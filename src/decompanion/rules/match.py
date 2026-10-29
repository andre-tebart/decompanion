"""Match rules (M.*): what the compiled objects say about the original.

  M.compile   one `build` fact per translation unit of the target (the tu table of the last `dcp build`): ok,
              object, diagnostics; a failed or never compiled unit is a gate error; the object-vs-source
              cross-check (M.gen)
  M.match     R1 [proven]: a function whose bytes equal the original's with the relocated fields masked (plus
              the DLL aid and the tail check, match/compare.py) owns [address, address + size)
  M.draft     R2 [derived, at most declared]: a compiled function that differs owns its code walk
  M8.reloc    M8 / M9 / M10: what our relocations refer to against what the original's sites hold

The sources remain the state: the `source` facts of L.src (an address comment, declared) are candidates the
match rules verify; a verified one yields facts above the declared level. Objects come from the store's tu
table (input `objects`); the rules never compile (`dcp build` does).
"""
from __future__ import annotations

import bisect

from ..build import compile as build_compile
from ..ledger.fact import Kind, Level, Severity, min_level, severity_of
from ..match import compare as C
from ..objfmt.base import ABSOLUTE, RELATIVE
from .engine import RuleContext, rule

P, D, DE, O = Level.proven, Level.derived, Level.declared, Level.open

WALK = ("S.sections", "S.relocs", "S.codewalk", "S.crt.code", "S.thunk", "S.exports", "S.entry")


def starts_of(ctx) -> list[int]:
    """Every known function start (start facts and function / thunk symbols of the needed rules), and the end
    of every code section, sorted: the end of a function's slot is the next of them."""
    s = {f.lo for f in ctx.facts(Kind.start)}
    s |= {f.lo for f in ctx.facts(Kind.symbol) if f.value.get("skind") in ("func", "thunk") and f.level > O}
    s |= {sec.end for sec in ctx.image.sections if sec.holds_code}
    return sorted(s)


def compiled_functions(ctx, sources=None):
    """[(source fact, unit object, function symbol, FunctionCode, Compared)] for every function fragment of the
    current target whose unit compiled and whose object defines the fragment's function; plus a list of
    (source fact, why) for the fragments that have no compiled function."""
    p, img, tc = ctx.project, ctx.image, ctx.project.toolchain
    tus = ctx.input("objects")
    objs = C.objects(p, tus)
    index = {u: C.function_index(o, tc) for u, o in objs.items()}
    relocs = sorted(f.lo for f in ctx.facts(Kind.ref) if f.value["rkind"] == "reloc") or None
    if not img.relocations():
        relocs = None
    starts = starts_of(ctx)
    srcs = sources if sources is not None else [f for f in ctx.facts(Kind.source) if f.value.get("what") == "func" and f.run == "L.src"]
    out, missing = [], []
    for s in sorted(srcs, key=lambda f: f.lo):
        unit, name = s.value["unit"], s.value["symbol"]
        if unit not in objs:
            row = tus.get(unit)
            missing.append((s, "no object: the unit " + ("failed to compile" if row else "is not compiled (dcp build)")))
            continue
        sym = index[unit].get(name)
        if sym is None:
            missing.append((s, f"the object of unit {unit} defines no function {name}"))
            continue
        code = objs[unit].function_code(sym)
        i = bisect.bisect_right(starts, s.lo)
        nxt = starts[i] if i < len(starts) else img.end
        out.append((s, objs[unit], sym, code, C.compare(img, code, s.lo, relocs, nxt, tc.fill_forms)))
    return out, missing


# ------------------------------------------------------------------------------------------------ M.compile
@rule("M.compile", version="1", ceiling=P, outputs=("build",), inputs=("objects", "src", "targets", "config", "toolchain"),
      needs=("S.sections",), helpers=(build_compile.plan, build_compile.flags_for, build_compile.unit_overrides))
def compile_facts(ctx: RuleContext):
    """One `build` fact per translation unit of the current target (build/amalg.py: a unit with at least one
    fragment of the target), at its first fragment's address (the image base when it has none): tu, ok, the
    object's hash, the flags, its errors (the compiler's diagnostics, file and line in the fragment) and its
    warning count, and `stale` when the unit's text or flags changed since the compile the tu table records.
    Gate errors (check M.compile): a unit that failed to compile (the first errors), a unit never compiled
    (a warning when the toolchain is not installed: nothing can be compiled on this machine); a stale unit is a
    warning (`dcp build` compiles it; `dcp check` builds first). An override table
    ([[toolchain.unit]]) without a reason is an error. M.gen, the object-vs-source cross-check (the first
    attempt's gen.py): every function the unit's object defines has exactly one fragment of the unit, and every
    fragment's function is defined by the object; either side alone is an error."""
    p, img = ctx.project, ctx.image
    tus = ctx.input("objects")
    for o in build_compile.unit_overrides(p):
        if not str(o.get("reason", "")).strip():
            yield ctx.conflict(Severity.error, "M.compile", img.base, img.base + 1,
                               f"[[toolchain.unit]] glob={o.get('glob')!r}: an override without a reason")
    tc = p.toolchain
    for a in build_compile.plan(p):
        at = a.first_addr if a.first_addr is not None and img.in_image(a.first_addr) else img.base
        row = tus.get(a.unit)
        flags, _ = build_compile.flags_for(p, a.target, a.unit)
        if row is None:
            yield ctx.fact(at, at + 1, Kind.build, {"tu": a.unit, "ok": False, "stale": True, "errors": ["not compiled"],
                                                    "warnings": 0, "fragments": len(a.fragments)}, P)
            if tc.available():
                yield ctx.conflict(Severity.error, "M.compile", at, at + 1, f"unit {a.unit} is not compiled (dcp build)")
            else:
                yield ctx.conflict(Severity.warn, "M.compile", at, at + 1,
                                   f"unit {a.unit} is not compiled: the toolchain is not available (root {tc.root})")
            continue
        errors = [f"{f}({l}): {sev} {code}: {msg}" if f else f"{sev} {code}: {msg}" for f, l, sev, code, msg in row["diags"] if sev == "error"]
        warnings = sum(1 for d in row["diags"] if d[2] == "warning")
        stale = row["src_hash"] != a.src_hash or row["flags"] != flags
        v = {"tu": a.unit, "ok": row["ok"], "stale": stale, "flags": " ".join(row["flags"]), "warnings": warnings,
             "fragments": len(a.fragments), "amalg": a.path}
        if row["ok"]:
            v["obj"] = row["obj_hash"][:16]
        if errors:
            v["errors"] = errors[:20]
        yield ctx.fact(at, at + 1, Kind.build, v, P)
        if not row["ok"]:
            last = (row["log"].strip().splitlines() or ["no diagnostics"])[-1]
            yield ctx.conflict(Severity.error, "M.compile", at, at + 1, f"unit {a.unit} does not compile: " + ("; ".join(errors[:3]) or last))
        elif stale:
            yield ctx.conflict(Severity.warn, "M.compile", at, at + 1, f"unit {a.unit} changed since its compile (dcp build)")
        if not row["ok"]:
            continue
        obj = C.read_object(p, row["obj_hash"])
        if obj is None:
            continue
        defined = {}
        for s in obj.functions():
            defined.setdefault(tc.undecorate(s.name), s)
        frag = {}
        for m in a.fragments:
            if m.name:
                frag.setdefault(m.name, []).append(m)
        for name in sorted(set(defined) - set(frag)):
            yield ctx.conflict(Severity.error, "M.gen", at, at + 1,
                               f"unit {a.unit}: the object defines {name} ({defined[name].name}), no fragment of the unit does")
        for name, ms in sorted(frag.items()):
            where = ms[0].addr if ms[0].addr is not None and img.in_image(ms[0].addr) else at
            if len(ms) > 1:
                yield ctx.conflict(Severity.error, "M.gen", where, where + 1,
                                   f"unit {a.unit}: {name} is defined by {len(ms)} fragments: " + ", ".join(m.file for m in ms))
            if name not in defined:
                yield ctx.conflict(Severity.error, "M.gen", where, where + 1,
                                   f"{ms[0].file}: the object of unit {a.unit} defines no function {name} (dropped by the "
                                   f"compiler as an unreferenced static, or not parsed as the fragment's definition)")


# ------------------------------------------------------------------------------------------------ M.match / M.draft
@rule("M.match", version="1", ceiling=P, outputs=("symbol", "source"), needs=("L.src", *WALK), inputs=("objects",),
      helpers=(compiled_functions, starts_of, C))
def match(ctx: RuleContext):
    """R1. A function fragment of the current target (an L.src `source` fact: a candidate, its declared level
    does not propagate) whose unit's object defines its function is a byte match when (match/compare.py):
    every byte of the function's section (from its symbol to the next named symbol or the section end) equals
    the image's byte at the fragment's address, relocated fields masked; the original does not continue after
    our last byte (the bytes up to the next known start are toolchain fill, or none); and, when the image
    carries base relocations (a dll: the complete list of its absolute fields), every absolute relocation site
    of ours is a base-relocation site and the extent holds as many base relocations as we have absolute
    relocations (`relocs 7/7`). A match owns its bytes: a `symbol` func proven (value: name, unit, file,
    relocs) from its address to the end of its last instruction that is no alignment fill (CL pads a function's
    section with fill up to the next function's alignment: the fill keeps its own symbol), or to the first jump
    or index table the walk found for it inside the section (VC6 places a switch's tables in the function's
    section; the tables keep their own symbols); and a `source` fact (what: match) over the whole section,
    proven."""
    funcs, _ = compiled_functions(ctx)
    img, isa, tc = ctx.image, ctx.project.isa, ctx.project.toolchain
    tables = sorted((f.lo, f.value.get("fn")) for f in ctx.facts(Kind.symbol) if f.value.get("skind") in ("jumptable", "idxtable"))
    for s, obj, sym, code, c in funcs:
        if not c.matched:
            continue
        a, end = s.lo, s.lo + c.size
        code_end = next((lo for lo, fn in tables if fn == a and a < lo < end), end)
        lines = isa.listing(code.data[:code_end - a], a, code.mask[:code_end - a], (img.base, img.end), tc.fill_forms)
        while lines and lines[-1].fill:
            lines.pop()
        if lines:
            code_end = min(code_end, lines[-1].addr + lines[-1].size)
        v = {"skind": "func", "extent": "matched", "name": s.value["symbol"], "unit": s.value["unit"], "file": s.value["file"],
             "relocs": c.aid}
        yield ctx.fact(a, code_end, Kind.symbol, v, P)
        yield ctx.fact(a, end, Kind.source, {"file": s.value["file"], "unit": s.value["unit"], "symbol": s.value["symbol"],
                                            "what": "match", "relocs": c.aid}, P)


@rule("M.draft", version="1", ceiling=D, outputs=("source",), needs=("L.src", *WALK), inputs=("objects",),
      helpers=(compiled_functions, starts_of, C))
def draft(ctx: RuleContext):
    """R2. A function fragment of the current target whose compiled function is no byte match (M.match's
    criterion fails) owns the bytes the code walk gives its start: a `source` fact (what: draft) over the walk's
    function extent (S.codewalk, derived), with why it is no match (differing bytes, the original continuing,
    the relocation aid). Its level is the lower of the walk's and the address comment's (declared). A fragment
    whose start the walk does not know owns nothing."""
    funcs, _ = compiled_functions(ctx)
    walk = {f.lo: f for f in ctx.facts(Kind.symbol) if f.value.get("skind") == "func" and f.run == "S.codewalk"}
    for s, obj, sym, code, c in funcs:
        if c.matched:
            continue
        w = walk.get(s.lo)
        if w is None:
            continue
        yield ctx.fact(s.lo, w.hi, Kind.source, {"file": s.value["file"], "unit": s.value["unit"], "symbol": s.value["symbol"],
                                                 "what": "draft", "why": c.why()}, min_level(w.level, s.level, ceiling=D))


# ------------------------------------------------------------------------------------------------ M8 / M9 / M10
def name_registry(ctx) -> tuple[dict, dict]:
    """(C name -> {address: producer level}, address -> {C names}) from every name fact of the needed rules:
    library names (linker symbols, `a|b` for several) undecorated, imports `DLL!f` as f at their slot."""
    tc = ctx.project.toolchain
    by_name, by_addr = {}, {}
    for f in ctx.facts(Kind.name):
        raw = f.value["name"]
        for n in raw.split("|"):
            if f.value.get("origin") == "import":
                n = n.split("!", 1)[-1]
            elif f.value.get("origin") == "lib":
                n = tc.undecorate(n)
            by_name.setdefault(n, {})[f.lo] = max(by_name.get(n, {}).get(f.lo, Level.open), f.level)
            by_addr.setdefault(f.lo, set()).add(n)
    return by_name, by_addr


@rule("M8.reloc", version="1", ceiling=P, needs=("L.src", *WALK, "kind:name"), inputs=("objects",),
      helpers=(compiled_functions, starts_of, name_registry, C))
def reloc_checks(ctx: RuleContext):
    """For every compiled function whose relocation sites line up with the original's (a byte match, or bytes
    that differ while the DLL aid holds: every absolute site of ours is a base-relocation site and the counts
    agree), each absolute or relative relocation of ours is resolved against the image (the address the
    original's site refers to, Reloc.resolve with our addend):
    M8: the symbol we reference has a registered address (a name fact: export, import slot, library, source,
    declaration) and the original's site refers to another address: our object references X where the original
    holds the address registered to Y (severity from the two levels).
    M9: we reference a string literal and the original's bytes at the resolved address differ from our
    literal's bytes (text or terminator).
    M10: we reference a floating constant and the original's bytes there differ from its bits."""
    img, tc = ctx.image, ctx.project.toolchain
    funcs, _ = compiled_functions(ctx, [f for f in ctx.facts(Kind.source) if f.value.get("what") == "func" and f.run == "L.src"])
    by_name, by_addr = name_registry(ctx)
    for s, obj, sym, code, c in funcs:
        if not (c.matched or (c.abs_image is not None and c.aid_ok)):
            continue
        for off, r, target in code.relocs:
            if target is None or r.kind not in (ABSOLUTE, RELATIVE):
                continue
            site = s.lo + off
            to = r.resolve(site, img.read(site, r.width), code.section.addend(r))
            if to is None:
                continue
            k = target.constant
            if k in ("string", "float") and target.section is not None and target.section.data is not None:
                lit = bytes(target.section.data[target.value:])
                if k == "string":
                    z = lit.find(b"\0")
                    lit = lit[:z + 1] if z >= 0 else lit
                have = img.read(to, len(lit))
                if have != lit:
                    yield ctx.conflict(Severity.error, "M9" if k == "string" else "M10", site, site + r.width,
                                       f"{s.value['symbol']} at {s.lo:#x}: our {'literal' if k == 'string' else 'constant'} "
                                       f"{lit[:40]!r} differs from the original's bytes {have[:40]!r} at {to:#x}", a=s.by)
                continue
            if not target.named or k is not None:
                continue
            cname = tc.undecorate(target.imported if target.dllimport else target.name)
            regs = by_name.get(cname)
            if not regs or to in regs:
                continue
            (b, lvl), = sorted(regs.items())[:1]
            others = ", ".join(sorted(by_addr.get(to, ()))) or "nothing registered"
            yield ctx.conflict(severity_of(P, lvl), "M8", site, site + r.width,
                               f"{s.value['symbol']} at {s.lo:#x}: our object references {cname} (registered at {b:#x}) where the "
                               f"original's site refers to {to:#x} ({others})", a=s.by)


# ------------------------------------------------------------------------------------------------ M.flags.proven
from ..build import probe as probe_mod  # noqa: E402


@rule("M.flags.proven", version="1", ceiling=P, outputs=("toolchain",), inputs=("probe", "toolchain"),
      helpers=(probe_mod.analyse,))
def flags_proven(ctx: RuleContext):
    """From the last `dcp toolchain probe` (build/probe.py): one `toolchain` fact per flag group of the probe
    grid, over the image, naming the best combination's flag, the user anchors that distinguish it (they match
    under it and stop matching when only that group takes another value) and their units. Proven when the
    distinguishing anchors come from at least two units; else declared (the target's declaration stays what
    says it). A proven flag the target's declared cflags do not contain is an error (M.flags)."""
    res = ctx.input("probe")
    if not res:
        return
    img = ctx.image
    an = probe_mod.analyse(res)
    declared = {f.lower() for f in (ctx.input("toolchain").get("cflags") or [])}
    for g in an["groups"]:
        lvl = P if len(g["units"]) >= 2 else DE
        yield ctx.fact(img.base, img.end, Kind.toolchain, {"flag": g["flag"], "group": g["group"], "anchors": len(g["anchors"]),
                                                          "units": len(g["units"]), "crt_anchors": len(g["crt_anchors"])}, lvl)
        if lvl == P and g["flag"].lower() not in declared:
            yield ctx.conflict(Severity.error, "M.flags", img.base, img.base + 1,
                               f"the probe proves {g['flag']} ({g['group']}, {len(g['anchors'])} anchors from {len(g['units'])} units); "
                               f"the declared cflags do not hold it")


# ------------------------------------------------------------------------------------------------ M5 / M6 / M7
@rule("M.lint", version="1", ceiling=P, needs=("L.src",), inputs=("lint", "src"), helpers=(build_compile.plan,))
def lint_checks(ctx: RuleContext):
    """The last `dcp lint` (source/lint.py: clang as a C89 type checker with MS compatibility against the
    toolchain's headers; `@original why` / `@vc6 why` on a line exempt it): M6 an error inside one unit, M5 a
    declaration conflict across units (the all-declarations unit), both errors; M7 a call through a K&R
    declaration or without a declaration, a warning (readability rule Q7 counts it). Reported at the address
    of the fragment the diagnostic names (the image base when it names another file). A lint run whose units'
    texts differ from today's amalgamations is stale: a warning (`dcp lint`; `dcp check` lints first)."""
    res = ctx.input("lint")
    if not res:
        return
    img = ctx.image
    at = {f.value["file"]: f.lo for f in ctx.facts(Kind.source) if f.value.get("what") == "func"}
    def where(text):
        f = text.split(":", 1)[0]
        a = at.get(f, img.base)
        return a, a + 1
    for e in res.get("errors", []):
        yield ctx.conflict(Severity.error, "M6", *where(e), e)
    for e in res.get("cross", []):
        yield ctx.conflict(Severity.error, "M5", *where(e), e)
    for f, calls in res.get("calls", {}).items():
        a = at.get(f, img.base)
        for c in calls:
            yield ctx.conflict(Severity.warn, "M7", a, a + 1, f"{f}: call without a prototype: {c}")
    current = {a.unit: a.src_hash for a in build_compile.plan(ctx.project)}
    stale = sorted(u for u, h in current.items() if res.get("units", {}).get(u) != h)
    if stale:
        yield ctx.conflict(Severity.warn, "M.lint", img.base, img.base + 1, f"the last lint did not parse today's text of: {', '.join(stale)} (dcp lint)")
