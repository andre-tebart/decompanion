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
analyzer's function body spans one of our starts, warning), L10 (walked code inside a unit that no source,
declaration or other function explains, warning), L13 (a data declaration at a function's code), L14 (a source
outside its unit's declared extent, in the library code), L16 (a function's `#if` and its address comment
disagree on its targets, in L.src), A1 (an image address literal cast to a pointer in the sources). L2 (a
function of a unit without a source, "undrafted") is informational: `dcp layout next` / `dcp layout units` report it, it
is no conflict.

The pure functions below (game_range, compute_units, lit_issues, boundary_issues, leak_issues) are shared by the
rules and by `dcp layout unit propose`, which runs them on the units as they would be with the proposal.
"""
from __future__ import annotations

import bisect
import re
from collections import defaultdict
from dataclasses import dataclass

from .. import native
from ..build import tu as build_tu
from ..ledger import decl as decl_mod
from ..ledger import srcscan
from ..source import cparse
from ..ledger.fact import Level, Severity, min_level
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
    - a unit starts at its declared `boundary start`, else at its first function with a source;
    - it ends at its declared `boundary end`, else at the next unit's start, else (the last unit) at the end of
      the game code. That last end is derived when every function start from the unit's start to the end of
      the game code has a source of this unit (nothing undrafted is left after it: LINK places library code
      after every object), else open (the unit may end anywhere before);
    - a boundary level is the level of what places it: declared for boundaries and sources.
    L7: two start or end boundaries of one unit, two units starting at one address, an end beyond the next
    unit's start, a unit outside the game code, an empty extent, a source outside its unit's extent. Native:
    native/dcp_core/src/layout.rs (L.unit.extent's and `dcp layout unit propose`'s)."""
    units, issues = native.core().compute_units(
        (game[0], game[1], int(game[2])), [(b.addr, b.side, b.tu, b.by, b.named_by) for b in bounds],
        [(s.addr, s.unit, s.name, s.by) for s in srcs], list(func_starts))
    return ([UnitX(tu, lo, hi, Level(sl), Level(el), sb, eb, nb) for tu, lo, hi, sl, el, sb, eb, nb in units],
            [Issue(*i) for i in issues])


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
    at its first function). Native: native/dcp_core/src/layout.rs."""
    return [Issue(*i) for i in native.core().boundary_issues(
        [(b.addr, b.side, b.tu, b.by, b.named_by) for b in bounds], set(starts), list(funcs), list(fills), game[1])]


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


# ------------------------------------------------------------------------------------------------ L.unit.extent
def bounds_of(facts) -> list[Bound]:
    return [Bound(f.lo, f.value["side"], f.value["tu"], f.by, f.value.get("named_by")) for f in facts]


def srcfns_of(facts) -> list[SrcFn]:
    return [SrcFn(f.lo, f.value["unit"], f.value["symbol"], f.by) for f in facts if f.value.get("what") == "func"]


def unit_status(start_level: Level, end_level: Level, open_bytes: int, walk_conflicts: int) -> str:
    """separated when both boundaries are at least declared, no open byte and no C.walk conflict lies inside the
    unit; else open."""
    return "separated" if start_level >= DE and end_level >= DE and not open_bytes and not walk_conflicts else "open"


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


# ------------------------------------------------------------------------------------------------ L9 / L10 / R5