"""Layout rules (L.*): where the translation units of the original lie, and what the typed state says about them.

Loaders turn typed state into declared facts (rules/engine.py `loader`):
  L.decl     decl/*.dcl (ledger/decl.py)
  L.src      the address comments of the sources (ledger/srcscan.py)
  L.ghidra   the starts of imported Ghidra drafts (ledger/ghidra.py)
Computed:
  L.analyze      boundary evidence per function: literal first users (B-LIT), the fill before a start (B-FILL),
                 leaked source paths (B-LEAK)
  L.unit.extent  unit extents and status (R7 of the first attempt, adapted)
Checks: L1 (a source start inside other code), L3 (literal order contradicts the unit order), L4 (a boundary
not at a start / inside fill), L5 (a placeholder name that spells no start), L6 (a declaration the facts now
contradict), L7 (extents overlap, a source outside its unit), L8 (two leaked paths in one unit), L11 (address
comment vs file name, in L.src). L2 (a function of a unit without a source fragment, "undrafted") is
informational: `dcp layout next` / `dcp layout units` report it, it is no conflict.

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
@rule("L.decl", version="2", ceiling=DE, outputs=("boundary", "symbol", "name", "start"), inputs=("decl", "targets"),
      loader=True, helpers=(decl_mod,))
def load_decl(ctx: RuleContext):
    """Every line of decl/*.dcl that belongs to the current target becomes one declared fact, producer
    decl:<file>:<line>, reason = the text after `--` (grammar: ledger/decl.py). boundary -> boundary fact
    {side, tu, named_by}; bytes dead -> symbol dead; jumptable / idxtable fn= -> symbol of that kind; foreign
    kind= -> symbol foreign; fptr -> symbol fptr; name N -> name (origin decl); start -> start (how decl).
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
        elif k == "start":
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
    address (L.src), one name at two addresses (N2). Errors of the text itself (the scan's, an unknown target
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
    names_at: dict[str, dict[int, str]] = defaultdict(dict)

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
        names_at[f.name][a] = by
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
        names_at[d.name][a] = by
        if d.kind == "def":
            defs_at[a].append(by)
            yield ctx.declared(a, a + 1, Kind.source, {"file": d.file, "line": d.line, "unit": d.unit, "symbol": d.name, "what": "data"}, by, reason)
        yield ctx.declared(a, a + 1, Kind.name, {"name": d.name, "origin": "source"}, by, reason)
    for a, bys in sorted(defs_at.items()):
        if len(bys) > 1:
            yield ctx.conflict(Severity.error, "L.src", a, a + 1, f"{len(bys)} definitions at {a:#x}: " + ", ".join(b[4:] for b in bys),
                               a=bys[0], b=bys[1])
    for name, at in sorted(names_at.items()):
        if len(at) > 1:
            (a1, b1), (a2, b2) = sorted(at.items())[:2]
            yield ctx.conflict(Severity.error, "N2", a1, a1 + 1, f"{name} at {len(at)} addresses: " + ", ".join(f"{x:#x}" for x in sorted(at)),
                               a=b1, b=b2)


@rule("L.ghidra", version="1", ceiling=DE, outputs=("start",), inputs=("ghidra",), loader=True)
def load_ghidra(ctx: RuleContext):
    """Every imported Ghidra draft (`dcp ghidra import`) whose entry lies in a code section is a declared
    function start (how ghidra, reason "ghidra analysis"): Ghidra's function discovery is an external tool's
    claim, so it is a declaration, never a computed fact."""
    code = code_ranges(ctx.image)
    for e in ctx.input("ghidra"):
        if in_ranges(e.start, code):
            v = {"skind": "func", "how": "ghidra"}
            if e.name:
                v["name"] = e.name
            yield ctx.declared(e.start, e.start + 1, Kind.start, v, f"decl:ghidra:{e.source}", "ghidra analysis")


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


@rule("L.unit.extent", version="1", ceiling=DE, outputs=("unit",),
      needs=("L.decl", "L.src", "S.sections", "S.crt.code", "S.thunk", "S.codewalk", "S.unknown"),
      helpers=(compute_units, game_range, lib_starts_of))
def unit_extent(ctx: RuleContext):
    """The units of the game code (compute_units in rules/layout.py: a unit runs from its declared start
    boundary or first fragment to its declared end, the next unit's start or the end of the game code; the
    first library byte ends the game code). Each unit is a `unit` fact over its extent with its boundary
    levels and producers, the count of function starts inside, how many have a fragment, and its open bytes
    (unknown code: no rule claims them). Status: separated when both boundaries are at least declared and no
    open byte lies inside, else open. Level: the lower of the two boundary levels (at most declared). Issues of
    the computation are L7 conflicts."""
    img = ctx.image
    syms = ctx.facts(Kind.symbol)
    game = game_range(img, lib_starts_of(syms))
    funcs = [lo for lo, _, _ in functions_of(syms) if game[0] <= lo < game[1]]
    srcs = srcfns_of(ctx.facts(Kind.source))
    units, issues = compute_units(game, bounds_of(ctx.facts(Kind.boundary)), srcs, funcs)
    yield from _emit(ctx, issues)
    unknown = sorted((f.lo, f.hi) for f in syms if f.value.get("skind") == "unknown.code")
    sourced = {s.addr for s in srcs}
    for u in units:
        open_bytes = sum(max(0, min(b, u.hi) - max(a, u.lo)) for a, b in unknown if a < u.hi and b > u.lo)
        inside = [a for a in funcs if u.lo <= a < u.hi]
        extra = {s.addr for s in srcs if u.lo <= s.addr < u.hi} - set(inside)
        v = {"tu": u.tu, "status": "separated" if u.start_level >= DE and u.end_level >= DE and not open_bytes else "open",
             "start_level": u.start_level.name, "end_level": u.end_level.name, "start_by": u.start_by, "end_by": u.end_by,
             "open_bytes": open_bytes, "functions": len(inside) + len(extra), "sourced": sum(1 for a in inside if a in sourced) + len(extra)}
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
