"""Check rules (C.* and the numbered setup checks): they read facts and emit conflicts only. A conflict never
removes a fact; it makes `dcp check` fail (error, bug) or `dcp conflicts` list it (warn)."""
from __future__ import annotations

import re
from collections import defaultdict

from ..ledger.fact import Kind, Level, Severity, severity_of
from .engine import RuleContext, rule


@rule("C.overlap", version="2", ceiling=Level.proven, needs=("kind:symbol", "kind:region"))
def overlap(ctx: RuleContext):
    """Two symbol or region facts that overlap contradict each other (every byte has one owner). Severity
    from the two levels: proven against proven is a bug in a rule. Overlaps with an open fact are not
    reported (open is replaced, not contradicted), nor two facts that say the same thing (one interval, one
    symbol kind: a declaration the walk confirms)."""
    items = [f for f in ctx.facts(Kind.symbol) if f.level > Level.open] + list(ctx.facts(Kind.region))
    items.sort(key=lambda f: (f.lo, f.hi))
    active = []
    for f in items:
        active = [g for g in active if g.hi > f.lo]
        for g in active:
            if (g.lo, g.hi, g.kind, g.value.get("skind")) == (f.lo, f.hi, f.kind, f.value.get("skind")):
                continue
            if g.lo < f.hi and f.lo < g.hi:
                yield ctx.conflict(severity_of(f.level, g.level), "C.overlap", max(f.lo, g.lo), min(f.hi, g.hi),
                                   f"{g.kind.value} {g.value.get('skind', g.value.get('what', ''))} {g.lo:#x}..{g.hi:#x} overlaps "
                                   f"{f.kind.value} {f.value.get('skind', f.value.get('what', ''))} {f.lo:#x}..{f.hi:#x}", a=g.by, b=f.by)
        active.append(f)


@rule("C.ref.target", version="1", ceiling=Level.proven, needs=("S.codewalk", "S.crt.code", "S.thunk"))
def ref_target(ctx: RuleContext):
    """A direct call whose target lies strictly inside a function (not at its start) contradicts that function's
    extent or the call's decoding."""
    funcs = [(f.lo, f.hi, f) for f in ctx.facts(Kind.symbol) if f.value.get("skind") == "func" and f.level > Level.open]
    funcs.sort()
    starts = {f.lo for f in ctx.facts(Kind.start)}
    for _, _, f in funcs:
        starts.update(f.value.get("inner", ()))   # local subroutines of assembly-written code (walk.py W2)
    import bisect
    los = [a for a, _, _ in funcs]
    for r in ctx.facts(Kind.ref):
        if r.value["rkind"] != "call":
            continue
        t = r.value["to"]
        if t in starts:
            continue
        i = bisect.bisect_right(los, t) - 1
        if i >= 0:
            a, b, f = funcs[i]
            if a < t < b:
                yield ctx.conflict(severity_of(f.level, r.level), "C.ref.target", t, t + 1,
                                   f"call from {r.lo:#x} targets the inside of the function at {a:#x}..{b:#x}", a=f.by, b=r.by)


def declared_build(decl: str) -> int | None:
    """The build number a declaration names: its last run of digits ('cl 12.00.9044' -> 9044)."""
    m = re.search(r"(\d+)\D*$", decl or "")
    return int(m.group(1)) if m else None


@rule("C.toolchain", version="2", ceiling=Level.proven, needs=("S.rich",), inputs=("toolchain",), helpers=(declared_build,))
def toolchain(ctx: RuleContext):
    """The target's toolchain declaration ([[target]] compiler / linker / reason, or the [toolchain] defaults it
    inherits) against the Rich header's candidates (S.rich): a declaration without a reason is an error; when
    the Rich header lists compiler entries, the declared compiler must name the build of one of them (the last
    number of the declaration), and a missing compiler declaration is an error; the same for the linker and
    the linker entries."""
    decl = ctx.input("toolchain")
    img = ctx.image
    t = ctx.project.target_name
    by = f"decl:decompanion.toml:{t}"
    if not str(decl.get("reason", "")).strip():
        yield ctx.conflict(Severity.error, "C.toolchain", img.base, img.base + 1,
                           f"target {t}: the toolchain declaration has no reason", a=by)
    rich = next(iter(ctx.facts(Kind.toolchain)), None)
    if rich is None:
        return
    tc = ctx.project.toolchain
    for key, cands in (("compiler", rich.value.get("compilers") or []), ("linker", rich.value.get("linkers") or [])):
        if not cands:
            continue
        spelled = ", ".join(f"{tc.declare(c)} ({c['tool']} x{c['count']})" for c in cands)
        d = str(decl.get(key, "") or "")
        if not d:
            yield ctx.conflict(Severity.error, "C.toolchain", img.base, img.base + 1,
                               f"target {t}: no {key} declared; the Rich header's {key} candidates: {spelled}", a=by, b=rich.by)
            continue
        b = declared_build(d)
        if b not in {c["build"] for c in cands}:
            yield ctx.conflict(Severity.error, "C.toolchain", img.base, img.base + 1,
                               f"target {t}: declared {key} {d!r} names build {b}, no {key} entry of the Rich header has it "
                               f"(candidates: {spelled})", a=by, b=rich.by)


@rule("S2.rich.members", version="2", ceiling=Level.proven, needs=("S.rich", "S.crt.code"), inputs=("toolchain",),
      helpers=(declared_build,))
def rich_members(ctx: RuleContext):
    """The Rich header counts library objects: the compiler entries whose build is not the declared compiler's.
    The placed library members should account for them. Fewer placed members than counted objects is a
    warning (members whose code was not found, or libraries not configured). Without a compiler declaration
    nothing is counted."""
    rich = next(iter(ctx.facts(Kind.toolchain)), None)
    b = declared_build(str(ctx.input("toolchain").get("compiler", "") or ""))
    if rich is None or b is None:
        return
    members = {f.value["tu"] for f in ctx.facts(Kind.unit)}
    counted = sum(c["count"] for c in rich.value.get("compilers") or [] if c["build"] != b)
    if counted and len(members) < counted:
        yield ctx.conflict(Severity.warn, "S2", ctx.image.base, ctx.image.base + 1,
                           f"Rich header counts {counted} library objects (compiler entries of other builds than {b}), "
                           f"{len(members)} members placed")


@rule("S7.entry.section", version="1", ceiling=Level.proven, needs=("S.sections", "S.exports", "S.entry"))
def entry_section(ctx: RuleContext):
    """The entry point and every export must lie in a code section (Section.holds_code: marked as code or as
    executable)."""
    img = ctx.image
    secs = [(f.lo, f.hi) for f in ctx.facts(Kind.section)]
    for s in ctx.facts(Kind.start):
        sec = next((img.section_of(a) for a, b in secs if a <= s.lo < b), None)
        if sec is None or not sec.holds_code:
            yield ctx.conflict(Severity.error, "S7", s.lo, s.lo + 1, f"{s.value['how']} start outside an executable section")


@rule("S5.crt.gaps", version="1", ceiling=Level.proven, needs=("S.crt.code", "S.unknown", "S.fill"))
def crt_gaps(ctx: RuleContext):
    """Unknown code between the first and the last placed library section is library code no member explains
    (a member not in the configured archives, or a section too short or ambiguous to place)."""
    crt = [f for f in ctx.facts(Kind.symbol) if f.value.get("unit", "").startswith("lib:") and f.value.get("skind") == "func"]
    if not crt:
        return
    lo, hi = min(f.lo for f in crt), max(f.hi for f in crt)
    for f in ctx.facts(Kind.symbol, lo, hi):
        if f.value.get("skind") == "unknown.code":
            yield ctx.conflict(Severity.warn, "S5", max(f.lo, lo), min(f.hi, hi), f"{min(f.hi, hi) - max(f.lo, lo)} unknown bytes inside the library region")


@rule("S4.import.libs", version="1", ceiling=Level.proven, inputs=("libs",))
def import_libs(ctx: RuleContext):
    """Every DLL the image imports needs an import library for the full link: the toolchain's library archives
    or the target's archives must hold the import library the toolchain names for it
    (Toolchain.import_library_name, compared case-insensitively; VC6: <DLL name>.LIB in VC98/Lib); a missing
    one is a warning until the link milestone."""
    tc = ctx.project.toolchain
    have = {p.name.lower() for p in tc.library_archives()} | {p.name.lower() for p in ctx.input("libs")}
    for dll in sorted({i.dll for i in ctx.image.imports()}):
        if tc.import_library_name(dll).lower() not in have:
            yield ctx.conflict(Severity.warn, "S4", ctx.image.base, ctx.image.base + 1, f"no import library for {dll} in the toolchain")
