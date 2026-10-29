"""Layout rules (L.*): where the translation units of the original lie, and what the typed state says about them.

Loaders turn typed state into declared facts (rules/engine.py `loader`):
  L.decl     decl/*.dcl (ledger/decl.py)
  L.src      the address comments of the sources (ledger/srcscan.py)
  L.analyzer the starts of the analyzer's drafts (ledger/drafts.py)
Computed:
  L.analyze      boundary evidence per function: literal first users (B-LIT), the fill before a start (B-FILL),
                 leaked source paths (B-LEAK)
  L.unit.extent  unit extents and status (R7 of the first attempt, adapted)
  M.bytes.declared  declared dead / foreign bytes inside a unit belong to it (R5)
Checks: L1 (a source start inside other code), L3 (literal order contradicts the unit order), L4 (a boundary
not at a start / inside fill), L5 (a placeholder name that spells no start), L6 (a declaration the facts now
contradict), L7 (extents overlap, a source outside its unit), L8 (two leaked paths in one unit), L9 (an
analyzer's function body spans one of our starts, warning), L10 (walked code inside a unit that no fragment, declaration
or other function explains, warning), L11 (address comment vs file name, in L.src), L13 (a data declaration at
a function's code), L14 (a fragment outside its unit's declared extent, in the library code), A1 (an image
address literal cast to a pointer in the sources). L2 (a function of a unit
without a source fragment, "undrafted") is informational: `dcp layout next` / `dcp layout units` report it, it
is no conflict.

The pure functions below (game_range, compute_units, lit_issues, boundary_issues, leak_issues) are shared by the
rules and by `dcp layout unit propose`, which runs them on the units as they would be with the proposal.
"""
from __future__ import annotations

import bisect
import re
from collections import defaultdict
from dataclasses import dataclass

from ..ledger import decl as decl_mod
from ..ledger import srcscan
from ..ledger.fact import Kind, Level, Severity, min_level
from .engine import RuleContext, rule

P, D, DE, O = Level.proven, Level.derived, Level.declared, Level.open


@dataclass(frozen=True)
class Issue:
    """A conflict before it is bound to a rule run (the pure functions return these)."""
    check: str
    lo: int
    hi: int
    message: str
    a: str = ""
    b: str = ""
    severity: str = "error"


def _emit(ctx, issues):
    for i in issues:
        yield ctx.conflict(Severity(i.severity), i.check, i.lo, i.hi, i.message, a=i.a, b=i.b)


def code_ranges(img) -> list[tuple[int, int]]:
    return sorted((s.va, s.va + max(s.vsize, 1)) for s in img.sections if s.holds_code)


def in_ranges(a: int, ranges) -> bool:
    return any(lo <= a < hi for lo, hi in ranges)


# ------------------------------------------------------------------------------------------------ the game code
def game_range(img, lib_starts) -> tuple[int, int, Level]:
    """(lo, hi, level of hi) of the game code: from the start of the first code section to the first byte of
    library code (a placed library member or an import thunk). Convention (LINK): the objects named on the
    command line are placed before every library member, so the first library byte ends the game code
    (derived). Without library code the game code runs to the end of the last code section (proven)."""
    rs = code_ranges(img)
    if not rs:
        return (img.base, img.base, P)
    lo = rs[0][0]
    libs = [a for a in lib_starts if in_ranges(a, rs)]
    if libs:
        return (lo, min(libs), D)
    return (lo, rs[-1][1], P)


def lib_starts_of(facts) -> list[int]:
    """Starts of library code among symbol facts: placed library members (unit lib:...) and import thunks."""
    return [f.lo for f in facts if f.value.get("skind") == "thunk"
            or (f.value.get("skind") == "func" and str(f.value.get("unit", "")).startswith("lib:"))]


# ------------------------------------------------------------------------------------------------ units
@dataclass
class UnitX:
    tu: str
    lo: int
    hi: int
    start_level: Level
    end_level: Level
    start_by: str
    end_by: str
    named_by: str | None = None

    @property
    def level(self) -> Level:
        return min_level(self.start_level, self.end_level, ceiling=DE)


@dataclass(frozen=True)
class Bound:
    """A declared boundary: side start|end of unit tu at addr."""
    addr: int
    side: str
    tu: str
    by: str
    named_by: str | None = None


@dataclass(frozen=True)
class SrcFn:
    addr: int
    unit: str
    name: str
    by: str


def compute_units(game: tuple[int, int, Level], bounds: list[Bound], srcs: list[SrcFn], func_starts: list[int]):
    """The units of the game code and the L7 issues. Criterion (R7 adapted):
    - a unit starts at its declared `boundary start`, else at its first function with a source fragment;
    - it ends at its declared `boundary end`, else at the next unit's start, else (the last unit) at the end of
      the game code. That last end is derived when every function start from the unit's start to the end of
      the game code has a fragment of this unit (nothing undrafted is left after it: LINK places library code
      after every object), else open (the unit may end anywhere before);
    - a boundary level is the level of what places it: declared for boundaries and fragments.
    L7: two start or end boundaries of one unit, two units starting at one address, an end beyond the next
    unit's start, a unit outside the game code, an empty extent, a fragment outside its unit's extent."""
    glo, ghi, glevel = game
    issues: list[Issue] = []
    starts: dict[str, tuple] = {}
    ends: dict[str, tuple] = {}
    for b in sorted(bounds, key=lambda b: (b.addr, b.side, b.tu)):
        table = starts if b.side == "start" else ends
        if b.tu in table:
            issues.append(Issue("L7", b.addr, b.addr + 1, f"unit {b.tu} has two {b.side} boundaries: {table[b.tu][0]:#x} and {b.addr:#x}",
                                a=table[b.tu][2], b=b.by))
            continue
        table[b.tu] = (b.addr, DE, b.by, b.named_by)
    first_src: dict[str, SrcFn] = {}
    for s in sorted(srcs, key=lambda s: s.addr):
        if glo <= s.addr < ghi and s.unit not in first_src:
            first_src[s.unit] = s
    for u, s in first_src.items():
        if u not in starts:
            starts[u] = (s.addr, DE, s.by, None)
    for tu, e in ends.items():
        if tu not in starts:
            issues.append(Issue("L7", e[0], e[0] + 1, f"end boundary of unit {tu}, which has no start boundary and no fragment", a=e[2]))
    order = sorted(starts.items(), key=lambda kv: (kv[1][0], kv[0]))
    srcs_by_unit = defaultdict(set)
    for s in srcs:
        srcs_by_unit[s.unit].add(s.addr)
    units: list[UnitX] = []
    seen_at: dict[int, str] = {}
    fs = sorted(func_starts)
    for i, (tu, (a, lvl, by, named)) in enumerate(order):
        if not (glo <= a < ghi):
            issues.append(Issue("L7", a, a + 1, f"unit {tu} starts at {a:#x}, outside the game code {glo:#x}..{ghi:#x}", a=by))
            continue
        if a in seen_at:
            issues.append(Issue("L7", a, a + 1, f"units {seen_at[a]} and {tu} start at the same address", a=by))
            continue
        seen_at[a] = tu
        nxt = next(((t, v) for t, v in order[i + 1:] if v[0] > a and glo <= v[0] < ghi), None)
        if tu in ends:
            hi, elvl, eby = ends[tu][0], DE, ends[tu][2]
            if nxt is not None and hi > nxt[1][0]:
                issues.append(Issue("L7", nxt[1][0], hi, f"unit {tu} ends at {hi:#x}, after unit {nxt[0]} starts at {nxt[1][0]:#x}",
                                    a=eby, b=nxt[1][2]))
        elif nxt is not None:
            hi, elvl, eby = nxt[1][0], nxt[1][1], f"start of {nxt[0]}"
        else:
            hi, eby = ghi, "end of the game code"
            k = bisect.bisect_left(fs, a)
            rest = [x for x in fs[k:] if x < ghi]
            elvl = min_level(glevel, ceiling=D) if all(x in srcs_by_unit[tu] for x in rest) else O
        if hi > ghi:
            issues.append(Issue("L7", ghi, hi, f"unit {tu} runs to {hi:#x}, into the library code at {ghi:#x}", a=ends.get(tu, (0, 0, ""))[2]))
            hi = ghi
        if hi <= a:
            issues.append(Issue("L7", a, a + 1, f"unit {tu} has an empty extent {a:#x}..{hi:#x}", a=by))
            continue
        units.append(UnitX(tu, a, hi, lvl, elvl, by, eby, named))
    los = [u.lo for u in units]
    for s in srcs:
        if not (glo <= s.addr < ghi):
            continue
        i = bisect.bisect_right(los, s.addr) - 1
        u = units[i] if i >= 0 and s.addr < units[i].hi else None
        if u is None:
            issues.append(Issue("L7", s.addr, s.addr + 1, f"fragment of unit {s.unit} ({s.name}) lies outside every unit extent", a=s.by))
        elif u.tu != s.unit:
            issues.append(Issue("L7", s.addr, s.addr + 1, f"fragment of unit {s.unit} ({s.name}) lies in unit {u.tu} {u.lo:#x}..{u.hi:#x}",
                                a=s.by, b=u.start_by))
    return units, issues


def unit_index(units: list[UnitX]):
    """addr -> index of the unit containing it, or None."""
    los = [u.lo for u in units]

    def at(a):
        i = bisect.bisect_right(los, a) - 1
        return i if i >= 0 and a < units[i].hi else None
    return at


# ------------------------------------------------------------------------------------------------ checks (pure)
@dataclass(frozen=True)
class Lit:
    lo: int
    hi: int
    first: int          # the first user: the lowest function start among the functions whose relocation sites reach it
    section: str
    data_refs: int      # relocation sites in data sections that reach it (a table: its first user is unknown)


def lit_issues(units: list[UnitX], lits: list[Lit]) -> list[Issue]:
    """L3 (B-LIT contradiction). Convention (VC6 /GF, LINK): a pooled literal is placed with the first object in
    link order that contains it, and objects are laid out in the same order in every section; so in one data
    section the literals, in address order, have first users whose units never go backwards. A string reached
    from a data section is skipped (a table in some unit is its first user, and no code site says which). Each
    literal whose first user's unit lies before the unit of an earlier literal's first user is an error."""
    at = unit_index(units)
    out = []
    by_sec = defaultdict(list)
    for l in lits:
        if l.data_refs == 0:
            by_sec[l.section].append(l)
    for sec, ls in by_sec.items():
        ls.sort(key=lambda l: l.lo)
        top, top_lit = None, None
        reported = set()
        for l in ls:
            i = at(l.first)
            if i is None:
                continue
            if top is not None and i < top and (i, top) not in reported:
                reported.add((i, top))
                out.append(Issue("L3", l.lo, l.hi,
                                 f"literal at {l.lo:#x} ({sec}) is first used by {l.first:#x} in unit {units[i].tu}, but the earlier "
                                 f"literal at {top_lit.lo:#x} is first used by {top_lit.first:#x} in the later unit {units[top].tu}",
                                 a=units[i].start_by, b=units[top].start_by))
            if top is None or i > top:
                top, top_lit = i, l
    return out


def boundary_issues(bounds: list[Bound], starts: set[int], funcs: list[tuple[int, int]], fills: list[tuple[int, int]],
                    game: tuple[int, int, Level]) -> list[Issue]:
    """L4: a declared boundary lies at a function start (a `start` fact of any producer, or the start of a
    function symbol), or, for an end boundary, at the end of the game code. A boundary inside alignment fill
    or strictly inside a function is an error (fill belongs to the unit before it: the next unit's code starts
    at its first function)."""
    out = []
    flos = [lo for lo, hi in funcs]
    for b in bounds:
        a = b.addr
        if b.side == "end" and a == game[1]:
            continue
        fill = next(((lo, hi) for lo, hi in fills if lo <= a < hi), None)
        if fill is not None:
            out.append(Issue("L4", a, a + 1, f"{b.side} boundary of {b.tu} inside fill {fill[0]:#x}..{fill[1]:#x} (the unit starts at the "
                                             f"function after it, {fill[1]:#x})", a=b.by))
            continue
        i = bisect.bisect_right(flos, a) - 1
        if i >= 0 and funcs[i][0] < a < funcs[i][1] and a not in starts:
            out.append(Issue("L4", a, a + 1, f"{b.side} boundary of {b.tu} inside the function {funcs[i][0]:#x}..{funcs[i][1]:#x}", a=b.by))
            continue
        if a not in starts and not (i >= 0 and funcs[i][0] == a):
            out.append(Issue("L4", a, a + 1, f"{b.side} boundary of {b.tu} at {a:#x}, where no function starts", a=b.by))
    return out


@dataclass(frozen=True)
class Leak:
    fn: int
    path: str
    stem: str
    header: bool
    string: int


def leak_issues(units: list[UnitX], leaks: list[Leak]) -> list[Issue]:
    """L8: the leaked .c / .cpp paths (B-LEAK) referenced by the functions of one unit name one file; two
    different file names in one unit extent are an error (two units, or a wrong boundary)."""
    at = unit_index(units)
    per = defaultdict(dict)
    for l in leaks:
        if l.header:
            continue
        i = at(l.fn)
        if i is not None:
            per[i].setdefault(l.stem, l)
    out = []
    for i, stems in per.items():
        if len(stems) > 1:
            ls = sorted(stems.values(), key=lambda l: l.fn)
            out.append(Issue("L8", units[i].lo, units[i].hi,
                             f"unit {units[i].tu} holds functions that leak {len(stems)} source files: "
                             + ", ".join(f"{l.path} ({l.fn:#x})" for l in ls), a=units[i].start_by))
    return out


# ------------------------------------------------------------------------------------------------ loaders
@rule("L.decl", version="3", ceiling=DE, outputs=("boundary", "symbol", "name"), inputs=("decl", "targets"),
      loader=True, helpers=(decl_mod,))
def load_decl(ctx: RuleContext):
    """Every line of decl/*.dcl that belongs to the current target becomes one declared fact, producer
    decl:<file>:<line>, reason = the text after `--` (grammar: ledger/decl.py). boundary -> boundary fact
    {side, tu, named_by}; bytes dead -> symbol dead; jumptable / idxtable fn= -> symbol of that kind; foreign
    kind= -> symbol foreign; fptr -> symbol fptr; name N -> name (origin decl); start: L.decl.start; file tu= path=
    -> checked only: the image holds the path, NUL-terminated, at the address, and one unit has one file name.
    Errors (check L.decl, severity error): a malformed line, an unknown kind or key, a missing reason, an
    unknown target prefix, an unsorted file, a duplicate key, an address outside the image or a range across
    sections, a text.dcl line outside a code section or a data.dcl line inside one. An error is reported in
    the store of the target its line names (a line whose target is unknown: the default target's)."""
    p, img = ctx.project, ctx.image
    targets = [t["name"] for t in ctx.input("targets")]
    decls, errors = decl_mod.load(ctx.input("decl"), p.root, targets)
    for e in errors:
        if (e.target or targets[0]) != p.target_name:
            continue
        lo = e.lo if e.lo is not None and img.in_image(e.lo) else img.base
        yield ctx.conflict(Severity.error, "L.decl", lo, lo + 1, f"{e.file}:{e.line}: {e.message}", a=f"decl:{e.file}:{e.line}")
    code = code_ranges(img)
    file_of: dict[str, str] = {}
    for d in decls:
        if (d.target or targets[0]) != p.target_name:
            continue
        s_lo, s_hi = img.section_of(d.lo), img.section_of(d.hi - 1)
        if s_lo is None or s_lo is not s_hi:
            yield ctx.conflict(Severity.error, "L.decl", d.lo if img.in_image(d.lo) else img.base, (d.lo if img.in_image(d.lo) else img.base) + 1,
                               f"{d.file}:{d.line}: {d.lo:#x}..{d.hi:#x} is not inside one section of the image", a=d.by)
            continue
        is_code = in_ranges(d.lo, code)
        name = d.file.rsplit("/", 1)[-1]
        if (name == "text.dcl" and not is_code) or (name == "data.dcl" and is_code):
            yield ctx.conflict(Severity.error, "L.decl", d.lo, d.lo + 1,
                               f"{d.file}:{d.line}: {d.lo:#x} lies in {s_lo.name}; text.dcl holds code sections, data.dcl the rest", a=d.by)
        k = d.kind
        if k == "boundary":
            v = {"side": d.words[0], "tu": d.keys["tu"]}
            if "by" in d.keys:
                v["named_by"] = d.keys["by"]
            yield ctx.declared(d.lo, d.lo + 1, Kind.boundary, v, d.by, d.reason)
        elif k == "bytes":
            yield ctx.declared(d.lo, d.hi, Kind.symbol, {"skind": "dead", "extent": "declared"}, d.by, d.reason)
        elif k in ("jumptable", "idxtable"):
            yield ctx.declared(d.lo, d.hi, Kind.symbol, {"skind": k, "fn": d.keys["fn"], "extent": "declared"}, d.by, d.reason)
        elif k == "foreign":
            yield ctx.declared(d.lo, d.hi, Kind.symbol, {"skind": "foreign", "what": d.keys["kind"], "extent": "declared"}, d.by, d.reason)
        elif k == "fptr":
            yield ctx.declared(d.lo, d.hi, Kind.symbol, {"skind": "fptr", "extent": "declared"}, d.by, d.reason)
        elif k == "name":
            yield ctx.declared(d.lo, d.lo + 1, Kind.name, {"name": d.words[0], "origin": "decl"}, d.by, d.reason)
        elif k == "file":
            want = d.keys["path"].encode("latin-1") + b"\0"
            have = img.read(d.lo, len(want))
            if have != want:
                yield ctx.conflict(Severity.error, "L.decl", d.lo, d.lo + 1,
                                   f"{d.file}:{d.line}: the image holds {have!r} at {d.lo:#x}, not the declared file name {want!r}", a=d.by)
            tu = d.keys["tu"]
            if tu in file_of:
                yield ctx.conflict(Severity.error, "L.decl", d.lo, d.lo + 1,
                                   f"{d.file}:{d.line}: unit {tu} already has the file name {file_of[tu]}", a=d.by)
            file_of.setdefault(tu, d.keys["path"])


@rule("L.decl.start", version="1", ceiling=DE, outputs=("start",), inputs=("decl", "targets"), loader=True, helpers=(decl_mod,))
def load_decl_starts(ctx: RuleContext):
    """The `start` lines of decl/*.dcl for the current target, inside a code section, as declared start facts
    (how decl). Its own loader so that the setup walk, which takes them as roots, reruns only when a start
    declaration changes, not on every boundary edit (the run key follows this rule's output). Malformed lines
    are L.decl's errors."""
    p, img = ctx.project, ctx.image
    targets = [t["name"] for t in ctx.input("targets")]
    decls, _ = decl_mod.load(ctx.input("decl"), p.root, targets)
    code = code_ranges(img)
    for d in decls:
        if d.kind == "start" and (d.target or targets[0]) == p.target_name and in_ranges(d.lo, code):
            yield ctx.declared(d.lo, d.lo + 1, Kind.start, {"skind": "func", "how": "decl"}, d.by, d.reason)


@rule("L.src", version="2", ceiling=DE, outputs=("source", "name", "start"), inputs=("src", "targets"),
      loader=True, helpers=(srcscan,))
def load_src(ctx: RuleContext):
    """The address comments of the sources (grammar: ledger/srcscan.py), for the current target: every function
    fragment with an address gives a `source` fact {file, line, unit, symbol, what: func, deep / stuck / rough
    tags}, a `name` fact (origin source) and a `start` fact (how source); every data definition with an address
    a `source` fact (what: data) and a `name`; every extern with an address a `name`. Producer
    src:<file>:<line>, reason = the comment's description. Errors: a parse error of the scan (L.src: a fragment
    without its address comment on line 1, a function outside a fragment, two definitions in a fragment, a
    stray file), L11 (the file name's address differs from the comment's first address), an unknown target
    prefix, an address outside the image, a function address outside a code section, two definitions at one
    address (L.src), one name at two addresses (N2; a `static` name is compared within its unit only, two
    units may each keep their own). Errors of the text itself (the scan's, an unknown target
    prefix) are reported in the default target's store; errors about an address in the store of its target.
    A function or datum whose comment lists another target's address only is no fact of this target."""
    p, img = ctx.project, ctx.image
    targets = [t["name"] for t in ctx.input("targets")]
    default, cur = targets[0], p.target_name
    sc = srcscan.scan(ctx.input("src"), p.input_hash("src"))
    base = img.base
    if cur == default:
        for e in sc.errors:
            yield ctx.conflict(Severity.error, e.check, base, base + 1, f"{e.file}:{e.line}: {e.message}", a=f"src:{e.file}:{e.line}")
    code = code_ranges(img)
    defs_at: dict[int, list[str]] = defaultdict(list)
    names_at: dict[tuple, dict[int, str]] = defaultdict(dict)    # (name, unit of a static or None) -> address -> by

    def unknown_prefix(addrs, by):
        if cur != default:
            return []
        bad = sorted({t for t, _ in addrs if t is not None and t not in targets})
        return [ctx.conflict(Severity.error, "L.src", base, base + 1, f"{by[4:]}: unknown target prefix {t}: (targets: {', '.join(targets)})", a=by)
                for t in bad]

    for f in sc.functions:
        by = f"src:{f.file}:{f.comment_line}"
        yield from unknown_prefix(f.addrs, by)
        a = srcscan.address_for(f.addrs, cur, default)
        if a is None:
            continue
        if not in_ranges(a, code):
            yield ctx.conflict(Severity.error, "L.src", a if img.in_image(a) else base, (a if img.in_image(a) else base) + 1,
                               f"{f.file}: function {f.name} at {a:#x}, outside every code section", a=by)
            continue
        v = {"file": f.file, "line": f.line, "unit": f.unit, "symbol": f.name, "what": "func"}
        if f.deep is not None:
            v["deep"] = f.deep
        if f.stuck is not None:
            v["stuck"] = f.stuck
        if f.rough:
            v["rough"] = True
        reason = f.what or "address comment"
        defs_at[a].append(by)
        names_at[(f.name, f.unit if f.static else None)][a] = by
        yield ctx.declared(a, a + 1, Kind.source, v, by, reason)
        yield ctx.declared(a, a + 1, Kind.name, {"name": f.name, "origin": "source"}, by, reason)
        yield ctx.declared(a, a + 1, Kind.start, {"skind": "func", "how": "source"}, by, reason)
    for d in sc.data:
        by = f"src:{d.file}:{d.line}"
        yield from unknown_prefix(d.addrs, by)
        a = srcscan.address_for(d.addrs, cur, default)
        if a is None:
            continue
        if not img.in_image(a):
            yield ctx.conflict(Severity.error, "L.src", base, base + 1, f"{d.file}:{d.line}: {d.name} at {a:#x}, outside the image", a=by)
            continue
        reason = f"data address comment ({d.kind})"
        names_at[(d.name, d.unit if d.static else None)][a] = by
        if d.kind == "def":
            defs_at[a].append(by)
            yield ctx.declared(a, a + 1, Kind.source, {"file": d.file, "line": d.line, "unit": d.unit, "symbol": d.name, "what": "data"}, by, reason)
        yield ctx.declared(a, a + 1, Kind.name, {"name": d.name, "origin": "source"}, by, reason)
    for a, bys in sorted(defs_at.items()):
        if len(bys) > 1:
            yield ctx.conflict(Severity.error, "L.src", a, a + 1, f"{len(bys)} definitions at {a:#x}: " + ", ".join(b[4:] for b in bys),
                               a=bys[0], b=bys[1])
    for (name, _), at in sorted(names_at.items(), key=lambda x: (x[0][0], x[0][1] or "")):
        if len(at) > 1:
            (a1, b1), (a2, b2) = sorted(at.items())[:2]
            yield ctx.conflict(Severity.error, "N2", a1, a1 + 1, f"{name} at {len(at)} addresses: " + ", ".join(f"{x:#x}" for x in sorted(at)),
                               a=b1, b=b2)


@rule("L.analyzer", version="3", ceiling=DE, outputs=("start",), inputs=("drafts",), loader=True)
def load_analyzer(ctx: RuleContext):
    """Every draft of the analyzer (`dcp setup` runs its export; analyzers/) whose entry lies in a code section is
    a declared function start (how = the analyzer's key, by decl:analyzer:<key>:<file>, reason "<key>
    analysis"; value: the analyzer's name and, when it reports ranges, its body's size in bytes): an external
    tool's function discovery is a claim, so it is a declaration, never a computed fact. A function the
    analyzer made at one of our own starts on our request (seeded: Ghidra's export creates one where it has
    none) is no claim of the analyzer's and gives no start fact."""
    code = code_ranges(ctx.image)
    for e in ctx.input("drafts"):
        if in_ranges(e.start, code) and not e.seeded:
            v = {"skind": "func", "how": e.analyzer}
            if e.name:
                v["name"] = e.name
            if e.size is not None:
                v["size"] = e.size
            yield ctx.declared(e.start, e.start + 1, Kind.start, v, f"decl:analyzer:{e.analyzer}:{e.source}", f"{e.analyzer} analysis")


# ------------------------------------------------------------------------------------------------ L.analyze
LEAK = re.compile(r"(?i)(?<![%\w])((?:[a-z]:)?[\w.\\/ -]*?([\w-]{2,})\.(cpp|c|h))(?![\w.])")


def functions_of(facts) -> list:
    """Function symbols above open, sorted: [(lo, hi, fact)]."""
    return sorted(((f.lo, f.hi, f) for f in facts if f.value.get("skind") == "func" and f.level > O), key=lambda t: (t[0], t[1]))


def container(funcs):
    los = [lo for lo, _, _ in funcs]

    def at(a):
        i = bisect.bisect_right(los, a) - 1
        return funcs[i] if i >= 0 and funcs[i][0] <= a < funcs[i][1] else None
    return at


@rule("L.analyze", version="1", ceiling=P, outputs=("evidence",),
      needs=("S.sections", "S.relocs", "S.codewalk", "S.crt.code", "S.thunk", "S.strings", "S.fill"))
def analyze(ctx: RuleContext):
    """Boundary evidence, computed once per image.
    lit (B-LIT): for every string symbol reached by a relocation site inside a function, its first user = the
    lowest start among those functions, the number of user functions, and the number of relocation sites in
    data sections that reach it (then a table, not a function, may be its first user). For a dll the
    relocations are the complete list of absolute operands, so the users are exact; the containing function
    rests on the walk (derived).
    fill (B-FILL): for every function start, what precedes it: a fill run as the toolchain names its form
    (Toolchain.fill_origin; VC6: `cc` a run of int3, padding the linker puts between section contributions;
    `nop` the compiler's alignment inside one object, proves nothing; `mixed`), `none` (the previous symbol
    ends right there) or `unknown` (open bytes).
    leak (B-LEAK): a string whose text holds a path with a .c / .cpp / .h suffix (an __FILE__ of assert or a
    log call), at every function that references it: the function was compiled from that file (.c / .cpp:
    names the unit; .h: an inline from a header, names nothing)."""
    img = ctx.image
    secs = {(f.lo, f.hi): f.value["name"] for f in ctx.facts(Kind.section)}
    code = code_ranges(img)
    syms = ctx.facts(Kind.symbol)
    funcs = functions_of(syms)
    at = container(funcs)
    strings = [f for f in syms if f.value.get("skind") == "string"]
    slos = [s.lo for s in strings]
    users = defaultdict(set)
    data_refs = defaultdict(int)
    for r in ctx.facts(Kind.ref):
        if r.value["rkind"] != "reloc":
            continue
        t = r.value["to"]
        i = bisect.bisect_right(slos, t) - 1
        if i < 0 or not (strings[i].lo <= t < strings[i].hi):
            continue
        s = strings[i]
        if in_ranges(r.lo, code):
            fn = at(r.lo)
            if fn is not None:
                users[s.lo].add(fn[0])
        else:
            data_refs[s.lo] += 1
    fn_at = {lo: (lo, hi, f) for lo, hi, f in funcs}
    for s in strings:
        us = [fn_at[a] for a in sorted(users.get(s.lo, ()))]
        if not us:
            continue
        first = us[0]
        lvl = min_level(s.level, *(u[2].level for u in us), ceiling=D)
        sec = next((n for (lo, hi), n in secs.items() if lo <= s.lo < hi), "")
        yield ctx.fact(s.lo, s.hi, Kind.evidence, {"ekind": "lit", "first": first[0], "users": len(us), "data_refs": data_refs[s.lo],
                                                   "section": sec}, lvl)
        text = img.cstr(s.lo).decode("latin-1")
        for m in LEAK.finditer(text):
            path, stem, ext = m.group(1).strip(), m.group(2), m.group(3).lower()
            for u in us:
                yield ctx.fact(u[0], u[0] + 1, Kind.evidence, {"ekind": "leak", "path": path, "stem": stem.lower(), "header": ext == "h",
                                                               "string": s.lo}, min_level(lvl, u[2].level, ceiling=P))
    ends = {}
    for f in syms:
        if f.level > O and f.value.get("skind") != "fill":
            ends.setdefault(f.hi, f)
    fills = {f.hi: f for f in syms if f.value.get("skind") == "fill"}
    opens = {f.hi for f in syms if f.level == O}
    for lo, hi, f in funcs:
        if not in_ranges(lo, code):
            continue
        if lo in fills:
            fl = fills[lo]
            pre = ctx.project.toolchain.fill_origin(img.read(fl.lo, fl.hi - fl.lo))
            v = {"ekind": "fill", "pre": pre, "run": fl.hi - fl.lo}
        elif lo in ends:
            v = {"ekind": "fill", "pre": "none", "run": 0}
        elif lo in opens:
            v = {"ekind": "fill", "pre": "unknown", "run": 0}
        else:
            continue
        yield ctx.fact(lo, lo + 1, Kind.evidence, v, min_level(f.level, ceiling=D))


# ------------------------------------------------------------------------------------------------ L.unit.extent
def bounds_of(facts) -> list[Bound]:
    return [Bound(f.lo, f.value["side"], f.value["tu"], f.by, f.value.get("named_by")) for f in facts]


def srcfns_of(facts) -> list[SrcFn]:
    return [SrcFn(f.lo, f.value["unit"], f.value["symbol"], f.by) for f in facts if f.value.get("what") == "func"]


def unit_status(start_level: Level, end_level: Level, open_bytes: int, walk_conflicts: int) -> str:
    """separated when both boundaries are at least declared, no open byte and no C.walk conflict lies inside the
    unit; else open."""
    return "separated" if start_level >= DE and end_level >= DE and not open_bytes and not walk_conflicts else "open"


@rule("L.unit.extent", version="2", ceiling=DE, outputs=("unit",),
      needs=("L.decl", "L.src", "S.sections", "S.crt.code", "S.thunk", "S.codewalk", "S.unknown"),
      helpers=(compute_units, game_range, lib_starts_of, unit_status))
def unit_extent(ctx: RuleContext):
    """The units of the game code (compute_units in rules/layout.py: a unit runs from its declared start
    boundary or first fragment to its declared end, the next unit's start or the end of the game code; the
    first library byte ends the game code). Each unit is a `unit` fact over its extent with its boundary
    levels and producers, the count of function starts inside, how many have a fragment, its open bytes
    (unknown code: no rule claims them), its declared dead / foreign bytes (`bytes dead`, `foreign`: explained,
    not open) and the C.walk conflicts inside it (a walk that runs into another function's bytes: one of the
    two starts is wrong). Status: separated when both boundaries are at least declared, no open byte and no
    C.walk conflict lies inside, else open. Level: the lower of the two boundary levels (at most declared).
    Issues of the computation are L7 conflicts."""
    img = ctx.image
    syms = ctx.facts(Kind.symbol)
    game = game_range(img, lib_starts_of(syms))
    funcs = [lo for lo, _, _ in functions_of(syms) if game[0] <= lo < game[1]]
    srcs = srcfns_of(ctx.facts(Kind.source))
    units, issues = compute_units(game, bounds_of(ctx.facts(Kind.boundary)), srcs, funcs)
    yield from _emit(ctx, issues)
    unknown = sorted((f.lo, f.hi) for f in syms if f.value.get("skind") == "unknown.code")
    dead = sorted((f.lo, f.hi) for f in syms if f.run == "L.decl" and f.value.get("skind") in ("dead", "foreign"))
    walks = sorted(c.lo for c in ctx.conflicts("C.walk"))
    sourced = {s.addr for s in srcs}

    def overlap(ranges, u):
        return sum(max(0, min(b, u.hi) - max(a, u.lo)) for a, b in ranges if a < u.hi and b > u.lo)

    for u in units:
        open_bytes = overlap(unknown, u)
        n_walk = bisect.bisect_left(walks, u.hi) - bisect.bisect_left(walks, u.lo)
        inside = [a for a in funcs if u.lo <= a < u.hi]
        extra = {s.addr for s in srcs if u.lo <= s.addr < u.hi} - set(inside)
        v = {"tu": u.tu, "status": unit_status(u.start_level, u.end_level, open_bytes, n_walk),
             "start_level": u.start_level.name, "end_level": u.end_level.name, "start_by": u.start_by, "end_by": u.end_by,
             "open_bytes": open_bytes, "dead_bytes": overlap(dead, u), "walk_conflicts": n_walk,
             "functions": len(inside) + len(extra), "sourced": sum(1 for a in inside if a in sourced) + len(extra)}
        if u.named_by:
            v["named_by"] = u.named_by
        yield ctx.fact(u.lo, u.hi, Kind.unit, v, u.level)


# ------------------------------------------------------------------------------------------------ checks
def game_units(facts) -> list[UnitX]:
    """The game units of L.unit.extent facts (library members have no status)."""
    out = []
    for f in facts:
        v = f.value
        if "status" in v:
            out.append(UnitX(v["tu"], f.lo, f.hi, Level[v["start_level"]], Level[v["end_level"]], v["start_by"], v["end_by"], v.get("named_by")))
    return sorted(out, key=lambda u: u.lo)


def lits_of(facts) -> list[Lit]:
    return [Lit(f.lo, f.hi, f.value["first"], f.value["section"], f.value["data_refs"]) for f in facts if f.value.get("ekind") == "lit"]


def leaks_of(facts) -> list[Leak]:
    return [Leak(f.lo, f.value["path"], f.value["stem"], f.value["header"], f.value["string"]) for f in facts if f.value.get("ekind") == "leak"]


@rule("L1.src.start", version="1", ceiling=P, needs=("L.src", "S.codewalk", "S.crt.code", "S.thunk", "S.fill", "S.sections"))
def src_start(ctx: RuleContext):
    """L1: the address of a function fragment is the start of a function: the start of a walked or placed
    function, or a byte of unknown code (an undrafted start the walk did not find). Strictly inside a function
    (not one of its inner labels), inside fill, an import thunk or a table it is an error: the walk crosses
    the fragment's start, one of the two is wrong."""
    syms = [f for f in ctx.facts(Kind.symbol) if f.level > O]
    los = sorted((f.lo, f.hi, f) for f in syms)
    keys = [x[0] for x in los]
    for s in ctx.facts(Kind.source):
        if s.value.get("what") != "func":
            continue
        a = s.lo
        i = bisect.bisect_right(keys, a) - 1
        hit = None
        for j in range(i, max(i - 8, -1), -1):     # symbols do not overlap (C.overlap): the nearest few suffice
            lo, hi, f = los[j]
            if lo <= a < hi:
                hit = f
                break
        if hit is None or hit.lo == a:
            continue
        sk = hit.value.get("skind")
        if sk == "func" and a in hit.value.get("inner", ()):
            continue
        yield ctx.conflict(Severity.error, "L1", a, a + 1,
                           f"fragment {s.value['file']} starts {s.value['symbol']} at {a:#x}, inside the {sk} {hit.lo:#x}..{hit.hi:#x}",
                           a=s.by, b=hit.by)


@rule("L3.lit.order", version="1", ceiling=D, needs=("L.analyze", "L.unit.extent"), helpers=(lit_issues, unit_index))
def lit_order(ctx: RuleContext):
    """L3, B-LIT contradiction (lit_issues in rules/layout.py): in each data section, the units of the literals'
    first users never go backwards in address order."""
    yield from _emit(ctx, lit_issues(game_units(ctx.facts(Kind.unit)), lits_of(ctx.facts(Kind.evidence))))


@rule("L4.boundary", version="1", ceiling=P, needs=("L.decl", "kind:start", "S.codewalk", "S.crt.code", "S.thunk", "S.fill"),
      helpers=(boundary_issues, game_range, lib_starts_of))
def boundary_at_start(ctx: RuleContext):
    """L4 (boundary_issues in rules/layout.py): a declared boundary lies at a function start (or an end
    boundary at the end of the game code), never inside fill or strictly inside a function."""
    syms = ctx.facts(Kind.symbol)
    funcs = [(lo, hi) for lo, hi, _ in functions_of(syms)]
    fills = sorted((f.lo, f.hi) for f in syms if f.value.get("skind") == "fill")
    starts = {f.lo for f in ctx.facts(Kind.start)}
    for f in syms:
        if f.value.get("skind") == "func":
            starts.update(f.value.get("inner", ()))
    game = game_range(ctx.image, lib_starts_of(syms))
    yield from _emit(ctx, boundary_issues(bounds_of(ctx.facts(Kind.boundary)), starts, funcs, fills, game))


def file_targets(sc, targets: list[str]) -> dict[str, set[str]]:
    """The targets each fragment belongs to: the targets its address comment lists (a bare address: the default
    target); a fragment without an address (unlinked) or a file that is no fragment (head.c, headers) belongs
    to every target."""
    out = {}
    for f in sc.functions:
        if f.addrs:
            out[f.file] = {t or targets[0] for t, _ in f.addrs}
    return out


@rule("L5.placeholder", version="2", ceiling=P, inputs=("src", "targets"), needs=("kind:start", "S.sections", "S.codewalk", "S.crt.code"),
      helpers=(srcscan, file_targets))
def placeholder(ctx: RuleContext):
    """L5: an identifier that spells an address (`Unk<hex>`, `FUN_<hex>`, `DAT_<hex>`, `<name>_<6-8 hex with a
    digit>`, in any .c / .h of src/ and include/) names a real address: in a file of the current target (a
    fragment of a function the target holds, or any file that is no fragment) a number inside a section of the
    target's image must, inside a code section, be a function start (a `start` fact of any producer, or an inner
    label). A number inside no section of any target the file belongs to is a dropped or extra digit, reported
    in the default target's store only (at the line that spells it)."""
    p, img = ctx.project, ctx.image
    names = [t["name"] for t in ctx.input("targets")]
    sc = srcscan.scan(ctx.input("src"), p.input_hash("src"))
    starts = {f.lo for f in ctx.facts(Kind.start)}
    for f in ctx.facts(Kind.symbol):
        if f.value.get("skind") == "func":
            starts.update(f.value.get("inner", ()))
    code = code_ranges(img)
    cur = p.target_name
    default = cur == names[0]
    owners = file_targets(sc, names)
    for ph in sc.placeholders:
        v = ph.value
        by = f"src:{ph.file}:{ph.line}"
        mine = owners.get(ph.file, set(names))
        if cur in mine and img.section_of(v) is not None:
            if in_ranges(v, code) and v not in starts:
                yield ctx.conflict(Severity.error, "L5", v, v + 1, f"{ph.file}:{ph.line}: {ph.ident}: no function starts at {v:#x}", a=by)
        elif default and not any(p.image_of(t).section_of(v) is not None for t in mine):
            yield ctx.conflict(Severity.error, "L5", img.base, img.base + 1,
                               f"{ph.file}:{ph.line}: {ph.ident}: {v:#x} is not an address of {', '.join(n for n in names if n in mine)} "
                               f"(a dropped or extra digit?)", a=by)


NAME_ORIGINS = ("source", "decl", "export", "entry")       # the origins a reader names an address by, preferred first


def what_is_at(a: int, names: dict, syms: list) -> str:
    """What the facts know at address a: its names (`name` facts at a, sources and declarations first), else the
    symbol above open that contains it (`func 0x5de460..0x5de480 (MSS_auto_cleanup) +0x10`), else `nothing known`.
    `names` maps an address to its name facts, `syms` is [(lo, hi, fact)] sorted (symbols do not overlap)."""
    def name_of(x):
        fs = sorted(names.get(x, ()), key=lambda f: (NAME_ORIGINS.index(f.value.get("origin")) if f.value.get("origin") in NAME_ORIGINS
                                                      else len(NAME_ORIGINS), f.value["name"]))
        return list(dict.fromkeys(f.value["name"] for f in fs))
    own = name_of(a)
    if own:
        return "the name " + " / ".join(own[:3])
    i = bisect.bisect_right([s[0] for s in syms], a) - 1
    for j in range(i, max(i - 8, -1), -1):
        lo, hi, f = syms[j]
        if lo <= a < hi:
            nm = name_of(lo)
            return (f"the {f.value.get('skind', f.kind.value)} {lo:#x}..{hi:#x}" + (f" ({nm[0]})" if nm else "")
                    + (f" +{a - lo:#x}" if a != lo else ""))
    return "nothing known"


@rule("A1.addr.cast", version="1", ceiling=P, inputs=("src", "targets"), needs=("kind:name", "kind:symbol"),
      helpers=(srcscan, file_targets, what_is_at))
def addr_cast(ctx: RuleContext):
    """A1: an integer literal cast to a pointer type in the sources (srcscan.PTR_CAST: `(void (*)(void))0x5de470`,
    `(char *)0x6f242c`, `(T *)(unsigned)0x...`; the cast's type spells its `*`, a typedef'd pointer name is not
    recognised; comments, strings and `#if 0` / `#else` text do not count, `#define` bodies do) whose value lies in
    the current target's image [base, end), in a file of the current target (file_targets: a fragment of a
    function the target holds, or any file that is no fragment). Such a pointer is the original's address
    frozen into the code: the relinked image places that object elsewhere, so the pointer goes wrong. An error;
    the message names what the facts know at the address (its name, else the symbol containing it, else nothing
    known) and asks for the symbol by name. The address of a symbol (`(unsigned)&x`, `(char *)&x`) is no literal
    and is not reported."""
    p, img = ctx.project, ctx.image
    names_t = [t["name"] for t in ctx.input("targets")]
    sc = srcscan.scan(ctx.input("src"), p.input_hash("src"))
    if not sc.ptrcasts:
        return
    owners = file_targets(sc, names_t)
    names = defaultdict(list)
    for f in ctx.facts(Kind.name):
        names[f.lo].append(f)
    syms = sorted(((f.lo, f.hi, f) for f in ctx.facts(Kind.symbol) if f.level > O), key=lambda t: (t[0], t[1]))
    for c in sc.ptrcasts:
        if p.target_name not in owners.get(c.file, set(names_t)) or not (img.base <= c.value < img.end):
            continue
        what = what_is_at(c.value, names, syms)
        hint = (f"reference {what[len('the name '):].split(' / ')[0]} by name" if what.startswith("the name ")
                else "declare the object at that address and reference it by name")
        yield ctx.conflict(Severity.error, "A1", c.value, c.value + 1,
                           f"{c.file}:{c.line}: `{c.text}` casts the image address {c.value:#x} to a pointer; the image has "
                           f"{what} there: {hint} (a relinked image places it elsewhere)", a=f"src:{c.file}:{c.line}")


TABLE_KINDS = ("jumptable", "idxtable", "fptr")            # data a code section legitimately holds


@rule("L13.data.code", version="1", ceiling=P, inputs=("src", "targets"),
      needs=("kind:name", "kind:start", "S.codewalk", "S.crt.code", "S.thunk", "M.match", "L.decl"),
      helpers=(srcscan, what_is_at))
def data_at_code(ctx: RuleContext):
    """L13: a data declaration of the sources (a definition or an `extern` with an address comment, srcscan Data)
    whose address, for the current target, is a known function start (a `start` fact above declared: the walk,
    the library placement, the entry, an export; or the start of a function symbol above declared) or lies inside
    a known function's extent (a `func` symbol above declared: walked, placed or byte-matched), unless a table
    symbol covers it (the walk's or a declared jumptable / idxtable, a declared fptr range: data a code section
    holds). The name declares data at code: whatever reads or calls it through that declaration, the relinked
    image gives it a data object instead of the function. An error naming the function there."""
    p = ctx.project
    targets = [t["name"] for t in ctx.input("targets")]
    sc = srcscan.scan(ctx.input("src"), p.input_hash("src"))
    syms = ctx.facts(Kind.symbol)
    funcs = sorted(((f.lo, f.hi, f) for f in syms if f.value.get("skind") == "func" and f.level > DE), key=lambda t: (t[0], t[1]))
    tables = sorted((f.lo, f.hi) for f in syms if f.value.get("skind") in TABLE_KINDS and f.level >= DE)
    starts = {f.lo for f in ctx.facts(Kind.start) if f.level > DE} | {lo for lo, _, _ in funcs}
    if not funcs and not starts:
        return
    at = container(funcs)
    data_names = {d.name for d in sc.data}
    names = defaultdict(list)
    for f in ctx.facts(Kind.name):
        if f.value["name"] not in data_names:       # name the function by its function names, not by the data views
            names[f.lo].append(f)
    for d in sc.data:
        a = srcscan.address_for(d.addrs, p.target_name, targets[0])
        if a is None:
            continue
        fn = at(a)
        if fn is None and a not in starts:
            continue
        if any(lo <= a < hi for lo, hi in tables):
            continue
        what = what_is_at(fn[0] if fn else a, names, funcs)
        where = "the start of" if fn is None or fn[0] == a else f"+{a - fn[0]:#x} inside"
        rng = f" {fn[0]:#x}..{fn[1]:#x}" if fn else ""
        yield ctx.conflict(Severity.error, "L13", a, a + 1,
                           f"{d.file}:{d.line}: data {'definition' if d.kind == 'def' else 'extern'} {d.name} at {a:#x} lies at {where} "
                           f"the function{rng} ({what}): declare it as a function (or fix the address)",
                           a=f"src:{d.file}:{d.line}", b=fn[2].by if fn else "")


def outside_unit_issues(units: list[UnitX], srcs: list[SrcFn], declared: set[str], game: tuple) -> list[Issue]:
    """L14: a function fragment of a unit whose extent rests on a declared boundary (`declared`: the units with a
    `boundary start` or `boundary end` line) lies outside that unit's extent. compute_units' L7 already reports
    the fragments inside the game code that lie outside their unit; L14 adds the ones outside the game code (in
    the library code after it), which L7 does not look at. A unit without a declared boundary, or without an
    extent, is not checked."""
    ext = {u.tu: u for u in units}
    out = []
    for s in srcs:
        u = ext.get(s.unit)
        if u is None or s.unit not in declared or u.lo <= s.addr < u.hi or game[0] <= s.addr < game[1]:
            continue
        out.append(Issue("L14", s.addr, s.addr + 1,
                         f"fragment of unit {s.unit} ({s.name}) at {s.addr:#x} lies outside the unit's declared extent "
                         f"{u.lo:#x}..{u.hi:#x}", a=s.by, b=u.start_by))
    return out


@rule("L14.unit.outside", version="1", ceiling=DE, needs=("L.unit.extent", "L.src", "L.decl", "S.crt.code", "S.thunk"),
      helpers=(outside_unit_issues, game_range, lib_starts_of))
def fragment_outside_unit(ctx: RuleContext):
    """L14 (outside_unit_issues in rules/layout.py): a function fragment outside the game code (in the library
    code after it) whose unit has a declared boundary (`boundary start|end tu=UNIT` in decl/text.dcl) and an
    extent: every fragment of such a unit lies inside the extent. Inside the game code L7 checks the same.
    An error: no unit owns library code, and a unit's amalgamation compiled with that fragment is not the
    unit's translation unit."""
    syms = ctx.facts(Kind.symbol)
    game = game_range(ctx.image, lib_starts_of(syms))
    declared = {f.value["tu"] for f in ctx.facts(Kind.boundary)}
    srcs = [s for s in srcfns_of(ctx.facts(Kind.source)) if s.by.startswith("src:")]
    yield from _emit(ctx, outside_unit_issues(game_units(ctx.facts(Kind.unit)), srcs, declared, game))


@rule("L6.declared", version="1", ceiling=P, needs=("L.decl", "S.codewalk", "S.crt.code", "S.thunk", "S.relocs", "S.sections"))
def declared_recheck(ctx: RuleContext):
    """L6: every declaration is re-checked against the computed facts at every run, never trusted.
    bytes dead / foreign: no walked or placed function covers a byte of the range, and no call, jump, tail call
    or code immediate reaches into it (such bytes are reachable code, not dead).
    jumptable / idxtable fn=F: F is a function start; the walk did not walk the range as code; a table the
    walk found overlapping the range has the same extent and function.
    fptr: every address-wide field of the range (Image.ptr_size) is a relocation site whose target lies in a
    code section.
    start: not strictly inside a walked or placed function (unless it is an inner label)."""
    img = ctx.image
    code = code_ranges(img)
    mine = [f for f in ctx.facts(Kind.symbol) if f.run == "L.decl"] + [f for f in ctx.facts(Kind.start) if f.run == "L.decl"]
    if not mine:
        return
    other =[f for f in ctx.facts(Kind.symbol) if f.run != "L.decl" and f.level > O]
    funcs = sorted((f.lo, f.hi, f) for f in other if f.value.get("skind") == "func")
    tables = [f for f in other if f.value.get("skind") in ("jumptable", "idxtable")]
    starts = {f.lo for f in ctx.facts(Kind.start) if f.run != "L.decl"}
    refs = [r for r in ctx.facts(Kind.ref) if r.value["rkind"] in ("call", "jmp", "tail", "immediate")]
    relocs = {r.lo: r.value["to"] for r in ctx.facts(Kind.ref) if r.value["rkind"] == "reloc"}

    def covering(lo, hi):
        return [f for a, b, f in funcs if a < hi and lo < b]

    for d in mine:
        sk = d.value.get("skind")
        if d.kind is Kind.start:
            hit = next((f for f in covering(d.lo, d.hi) if f.lo < d.lo and d.lo not in f.value.get("inner", ())), None)
            if hit is not None:
                yield ctx.conflict(Severity.error, "L6", d.lo, d.hi, f"declared start {d.lo:#x} lies inside the function {hit.lo:#x}..{hit.hi:#x}",
                                   a=d.by, b=hit.by)
            continue
        if sk in ("dead", "foreign"):
            for f in covering(d.lo, d.hi):
                yield ctx.conflict(Severity.error, "L6", max(d.lo, f.lo), min(d.hi, f.hi),
                                   f"declared {sk} bytes {d.lo:#x}..{d.hi:#x} are code of the function {f.lo:#x}..{f.hi:#x}", a=d.by, b=f.by)
            for r in refs:
                if d.lo <= r.value["to"] < d.hi:
                    yield ctx.conflict(Severity.error, "L6", r.value["to"], r.value["to"] + 1,
                                       f"declared {sk} bytes {d.lo:#x}..{d.hi:#x} are reached by the {r.value['rkind']} at {r.lo:#x}", a=d.by, b=r.by)
        elif sk in ("jumptable", "idxtable"):
            fn = d.value["fn"]
            if fn not in starts:
                yield ctx.conflict(Severity.error, "L6", d.lo, d.hi, f"declared {sk} {d.lo:#x}..{d.hi:#x}: no function starts at fn={fn:#x}", a=d.by)
            for f in covering(d.lo, d.hi):
                yield ctx.conflict(Severity.error, "L6", max(d.lo, f.lo), min(d.hi, f.hi),
                                   f"declared {sk} {d.lo:#x}..{d.hi:#x} lies inside the code of the function {f.lo:#x}..{f.hi:#x}", a=d.by, b=f.by)
            for t in tables:
                if t.lo < d.hi and d.lo < t.hi and (t.lo, t.hi, t.value.get("fn")) != (d.lo, d.hi, fn):
                    yield ctx.conflict(Severity.error, "L6", max(t.lo, d.lo), min(t.hi, d.hi),
                                       f"declared {sk} {d.lo:#x}..{d.hi:#x} fn={fn:#x}, the walk finds {t.value['skind']} {t.lo:#x}..{t.hi:#x} "
                                       f"fn={t.value.get('fn', 0):#x}", a=d.by, b=t.by)
        elif sk == "fptr":
            w = img.ptr_size
            for a in range(d.lo, d.hi - w + 1, w):
                if a not in relocs or not in_ranges(relocs[a], code):
                    yield ctx.conflict(Severity.error, "L6", a, a + w, f"declared fptr {d.lo:#x}..{d.hi:#x}: the dword at {a:#x} is not a "
                                                                      f"relocated code address", a=d.by)
                    break


@rule("L8.leak", version="1", ceiling=D, needs=("L.analyze", "L.unit.extent"), helpers=(leak_issues, unit_index))
def leak_unit(ctx: RuleContext):
    """L8 (leak_issues in rules/layout.py): one unit, one leaked source file."""
    yield from _emit(ctx, leak_issues(game_units(ctx.facts(Kind.unit)), leaks_of(ctx.facts(Kind.evidence))))


# ------------------------------------------------------------------------------------------------ L9 / L10 / R5
def our_starts(ctx) -> tuple[dict, set]:
    """({start: how} of every start fact of the needed rules and every function / thunk symbol above open,
    {inner labels of walked functions})."""
    ours = {f.lo: f.value.get("how", "") for f in ctx.facts(Kind.start)}
    inner = set()
    for f in ctx.facts(Kind.symbol):
        if f.value.get("skind") in ("func", "thunk") and f.level > O:
            ours.setdefault(f.lo, "symbol")
            inner.update(f.value.get("inner", ()))
    return ours, inner


@rule("L9.analyzer.span", version="2", ceiling=DE, inputs=("drafts",),
      needs=("L.decl", "L.src", "S.exports", "S.entry", "S.crt.code", "S.crt.refs", "S.codewalk", "S.thunk"),
      helpers=(our_starts, game_range, lib_starts_of))
def analyzer_span(ctx: RuleContext):
    """L9 (warning): an analyzer's function of the game code (its entry before the first library byte) whose
    body (its address ranges, when the analyzer reports them: Ghidra's export does) holds one of our function
    starts other than its own entry: a start fact of any producer but L.analyzer (export, entry, library, walk,
    declaration, fragment) or the start of a placed or walked function; inner labels of a walked function do
    not count. The analyzer merged two functions (typically across a call that does not return): its
    pseudocode holds both, and a draft from it must stop at our start. A warning, not an error: the body is an
    external tool's analysis (a declaration), our starts rest on the bytes and stated conventions. Library code
    is placed by its own members' bytes; the analyzer's view of it is no layout question and is not checked."""
    ours, inner = our_starts(ctx)
    keys = sorted(a for a in ours if a not in inner)
    glo, ghi, _ = game_range(ctx.image, lib_starts_of(ctx.facts(Kind.symbol)))
    for e in ctx.input("drafts"):
        if not (glo <= e.start < ghi):
            continue
        hits = []
        for lo, hi in e.ranges:
            i = bisect.bisect_left(keys, lo)
            while i < len(keys) and keys[i] < hi:
                if keys[i] != e.start:
                    hits.append(keys[i])
                i += 1
        if hits:
            hits.sort()
            yield ctx.conflict(Severity.warn, "L9", e.start, max(hi for _, hi in e.ranges),
                               f"{e.analyzer}'s function {e.start:#x} ({e.name or '-'}, {e.size} bytes) spans our start"
                               f"{'s' if len(hits) > 1 else ''} " + ", ".join(f"{a:#x} ({ours[a]})" for a in hits[:6])
                               + (f" (+{len(hits) - 6} more)" if len(hits) > 6 else "") + ": its draft holds more than one function",
                               a=f"decl:analyzer:{e.analyzer}:{e.source}")


@rule("L10.unexplained", version="1", ceiling=DE, needs=("L.unit.extent", "L.src", "M.match", "S.codewalk", "L.decl"))
def unexplained(ctx: RuleContext):
    """L10 (warning): code inside a game unit's extent that no fragment, no declaration and no other function
    explains, though a fragment claims it. Two cases:
    (a) a fragment whose start the walk does not know (a declared start in unknown code) and that does not
    byte-match owns no bytes (M.draft takes the walk's extent, there is none; M.match proves an extent only for
    a match): its code stays open (`open_bytes`) until it matches or a convention reaches its start;
    (b) a fragment that byte-matches (M.match: its compiled section, padding included, ends at m) while the walk
    gives its start a function extent [a, w) with w > m: the bytes [m, w), minus declared dead / foreign bytes,
    are code the walk reached that our function does not contain (a missed start, dead code to declare `bytes
    dead -- why`, or a table read as code). (R1's tail check makes (b) rare: a match already proves that only fill
    follows its end up to the next start.)
    A non-matching draft with a walked start owns the walk's extent (M.draft), and a walked function without a
    fragment is L2 (informational, `dcp layout next`): neither is L10."""
    units = game_units(ctx.facts(Kind.unit))
    at = unit_index(units)
    walk = {f.lo: f for f in ctx.facts(Kind.symbol) if f.run == "S.codewalk" and f.value.get("skind") == "func"}
    matched = {f.lo: f for f in ctx.facts(Kind.source) if f.value.get("what") == "match"}
    dead = sorted((f.lo, f.hi) for f in ctx.facts(Kind.symbol) if f.run == "L.decl" and f.value.get("skind") in ("dead", "foreign"))
    for s in ctx.facts(Kind.source):
        if s.run != "L.src" or s.value.get("what") != "func":
            continue
        i = at(s.lo)
        if i is None:
            continue
        w, m = walk.get(s.lo), matched.get(s.lo)
        if w is None and m is None:
            yield ctx.conflict(Severity.warn, "L10", s.lo, s.lo + 1,
                               f"unit {units[i].tu}: {s.value['file']} ({s.value['symbol']}) owns no bytes: the walk does not know its "
                               f"start and it does not byte-match, so its code stays open", a=s.by)
            continue
        if w is None or m is None or w.hi <= m.hi:
            continue
        left = w.hi - m.hi - sum(max(0, min(b, w.hi) - max(a, m.hi)) for a, b in dead if a < w.hi and b > m.hi)
        if left > 0:
            yield ctx.conflict(Severity.warn, "L10", m.hi, w.hi,
                               f"unit {units[i].tu}: the walk of {s.lo:#x} ({s.value['symbol']}) runs to {w.hi:#x}, its byte-matched "
                               f"compile ends at {m.hi:#x}: {left} bytes of walked code no fragment explains (a missed start, or "
                               f"dead code to declare `bytes dead`)", a=w.by, b=m.by)


@rule("M.bytes.declared", version="1", ceiling=DE, outputs=("source",), needs=("L.decl", "L.unit.extent"))
def bytes_declared(ctx: RuleContext):
    """R5: declared dead or foreign bytes (decl/*.dcl `bytes dead`, `foreign kind=`) inside a game unit's extent
    belong to that unit: a `source` fact {what: dead | foreign, unit} over the range, declared (the declaration
    is the premise), so the byte map gives those bytes the unit and its source, and the unit counts them as
    explained (L.unit.extent: dead_bytes), not open. A range that crosses a unit boundary is an error
    (M.bytes.declared); a range inside no unit is a warning (no unit owns it yet)."""
    units = game_units(ctx.facts(Kind.unit))
    at = unit_index(units)
    for f in ctx.facts(Kind.symbol):
        if f.run != "L.decl" or f.value.get("skind") not in ("dead", "foreign"):
            continue
        i, j = at(f.lo), at(f.hi - 1)
        if i is None and j is None:
            yield ctx.conflict(Severity.warn, "M.bytes.declared", f.lo, f.hi, f"declared {f.value['skind']} bytes {f.lo:#x}..{f.hi:#x} lie in no unit", a=f.by)
            continue
        if i != j:
            yield ctx.conflict(Severity.error, "M.bytes.declared", f.lo, f.hi,
                               f"declared {f.value['skind']} bytes {f.lo:#x}..{f.hi:#x} cross a unit boundary", a=f.by)
            continue
        v = {"what": f.value["skind"], "unit": units[i].tu, "decl": f.by}
        yield ctx.fact(f.lo, f.hi, Kind.source, v, min_level(f.level, ceiling=DE), f.reason)
