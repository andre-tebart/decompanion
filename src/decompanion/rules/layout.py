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
def decl_inputs(p) -> dict:
    """What the native rules that read decl/*.dcl get of the configuration: the targets (the default first), the
    current one (the core reads the declarations itself: native/dcp_core/src/decl.rs)."""
    return {"targets": [t["name"] for t in p.input("targets")], "target": p.target_name}


def toolchain_key(p) -> dict:
    return {"toolchain": p.toolchain.key}


@rule("L.decl", version="4", ceiling=DE, outputs=("boundary", "symbol", "name"), inputs=("decl", "targets", "src"),
      loader=True, helpers=(decl_mod, build_tu), native=True,
      native_inputs=decl_inputs)
def load_decl(ctx: RuleContext):
    """Every line of decl/*.dcl that belongs to the current target becomes one declared fact, producer
    decl:<file>:<line>, reason = the text after `--` (grammar: ledger/decl.py). boundary -> boundary fact
    {side, tu, named_by}; bytes dead -> symbol dead; jumptable / idxtable fn= -> symbol of that kind; foreign
    kind= -> symbol foreign; fptr -> symbol fptr; name N -> name (origin decl); start: L.decl.start; file tu= path=
    -> checked only: the image holds the path, NUL-terminated, at the address, one unit has one file name, and
    the unit's file src/<tu>.c names it in a `#line` directive (its `__FILE__`).
    Errors (check L.decl, severity error): a malformed line, an unknown kind or key, a missing reason, an
    unknown target prefix, an unsorted file, a duplicate key, an address outside the image or a range across
    sections, a text.dcl line outside a code section or a data.dcl line inside one. An error is reported in
    the store of the target its line names (a line whose target is unknown: the default target's)."""
    return ()                                      # native: native/dcp_core/src/decl.rs


@rule("L.decl.start", version="1", ceiling=DE, outputs=("start",), inputs=("decl", "targets"), loader=True, helpers=(decl_mod,), native=True,
      native_inputs=decl_inputs)
def load_decl_starts(ctx: RuleContext):
    """The `start` lines of decl/*.dcl for the current target, inside a code section, as declared start facts
    (how decl). Its own loader so that the setup walk, which takes them as roots, reruns only when a start
    declaration changes, not on every boundary edit (the run key follows this rule's output). Malformed lines
    are L.decl's errors."""
    return ()                                      # native: native/dcp_core/src/decl.rs


@rule("L.src", version="5", ceiling=DE, outputs=("source", "name", "start"), inputs=("scan", "targets"),
      loader=True, helpers=(srcscan, cparse), native=True, native_inputs=lambda p: scan_inputs(p))   # the front end decides what the scan sees
def load_src(ctx: RuleContext):
    """The address comments of the sources (grammar: ledger/srcscan.py), for the current target: every function
    with an address gives a `source` fact {file, line, comment (the address comment's line), end (the
    definition's last line), unit, symbol, what: func, deep / stuck / rough tags}, a `name` fact (origin source)
    and a `start` fact (how source); every data definition with an address a `source` fact (what: data) and a
    `name`; every extern with an address a `name`. Producer src:<file>:<line>, reason = the comment's
    description. Errors: a parse error of the scan (L.src: a function without its address comment directly
    above its definition, a function outside a unit file, a stray file), L16 (a function compiled into a target
    its comment does not list, or listed for one whose compile does not hold it), an unknown target prefix, an
    address outside the image, a function address outside a code section, two definitions at one address
    (L.src), one name at two addresses (N2; a `static` name is compared within its unit only, two units may each
    keep their own), L15 (a view's address is not its container's plus its offset, or its container has no data
    declaration with an address; a view gives a `name` fact {view: container}). Errors of the text itself (the
    scan's, an unknown target prefix) are reported in the default target's store; errors about an address in the
    store of its target.
    A function or datum whose comment lists another target's address only is no fact of this target. Native:
    native/dcp_core/src/layout.rs."""
    return ()


@rule("L.analyzer", version="3", ceiling=DE, outputs=("start",), inputs=("drafts",), loader=True, native=True)
def load_analyzer(ctx: RuleContext):
    """Every draft of the analyzer (`dcp setup` runs its export; analyzers/) whose entry lies in a code section is
    a declared function start (how = the analyzer's key, by decl:analyzer:<key>:<file>, reason "<key>
    analysis"; value: the analyzer's name and, when it reports ranges, its body's size in bytes): an external
    tool's function discovery is a claim, so it is a declaration, never a computed fact. A function the
    analyzer made at one of our own starts on our request (seeded: Ghidra's export creates one where it has
    none) is no claim of the analyzer's and gives no start fact."""
    return ()                                      # native: native/dcp_core/src/layout.rs


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
      needs=("S.sections", "S.relocs", "S.codewalk", "S.crt.code", "S.thunk", "S.strings", "S.fill"), native=True,
      native_inputs=toolchain_key)
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
    return ()                                      # native: native/dcp_core/src/layout.rs


# ------------------------------------------------------------------------------------------------ L.unit.extent
def bounds_of(facts) -> list[Bound]:
    return [Bound(f.lo, f.value["side"], f.value["tu"], f.by, f.value.get("named_by")) for f in facts]


def srcfns_of(facts) -> list[SrcFn]:
    return [SrcFn(f.lo, f.value["unit"], f.value["symbol"], f.by) for f in facts if f.value.get("what") == "func"]


def unit_status(start_level: Level, end_level: Level, open_bytes: int, walk_conflicts: int) -> str:
    """separated when both boundaries are at least declared, no open byte and no C.walk conflict lies inside the
    unit; else open."""
    return "separated" if start_level >= DE and end_level >= DE and not open_bytes and not walk_conflicts else "open"


@rule("L.unit.extent", version="3", ceiling=DE, outputs=("unit",),
      needs=("L.decl", "L.src", "S.sections", "S.crt.code", "S.thunk", "S.codewalk", "S.unknown"),
      inputs=("decl", "targets"), native=True, native_inputs=decl_inputs)
def unit_extent(ctx: RuleContext):
    """The units of the game code (compute_units in rules/layout.py: a unit runs from its declared start
    boundary or first source to its declared end, the next unit's start or the end of the game code; the
    first library byte ends the game code). Each unit is a `unit` fact over its extent with its boundary
    levels and producers, the count of function starts inside, how many have a source, its open bytes
    (unknown code: no rule claims them), its declared dead / foreign bytes (`bytes dead`, `foreign`: explained,
    not open) and the C.walk conflicts inside it (a walk that runs into another function's bytes: one of the
    two starts is wrong). Status: separated when both boundaries are at least declared, no open byte and no
    C.walk conflict lies inside, else open. Level: the lower of the two boundary levels (at most declared).
    Issues of the computation are L7 conflicts. A unit declared `libunit` (a library member compiled from source)
    is no game unit: its functions are left out (L14 checks them against the member's range). Native:
    native/dcp_core/src/layout.rs."""
    return ()


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


@rule("L1.src.start", version="1", ceiling=P, needs=("L.src", "S.codewalk", "S.crt.code", "S.thunk", "S.fill", "S.sections"),
      native=True)
def src_start(ctx: RuleContext):
    """L1: the address of a sourced function is the start of a function: the start of a walked or placed
    function, or a byte of unknown code (an undrafted start the walk did not find). Strictly inside a function
    (not one of its inner labels), inside fill, an import thunk or a table it is an error: the walk crosses
    the source's start, one of the two is wrong. Native:
    native/dcp_core/src/layout.rs."""
    return ()


@rule("L3.lit.order", version="1", ceiling=D, needs=("L.analyze", "L.unit.extent"), helpers=(lit_issues, unit_index), native=True)
def lit_order(ctx: RuleContext):
    """L3, B-LIT contradiction (lit_issues in rules/layout.py): in each data section, the units of the literals'
    first users never go backwards in address order."""
    return ()                                      # native: native/dcp_core/src/layout.rs


@rule("L4.boundary", version="1", ceiling=P, needs=("L.decl", "kind:start", "S.codewalk", "S.crt.code", "S.thunk", "S.fill"),
      native=True)
def boundary_at_start(ctx: RuleContext):
    """L4 (boundary_issues in rules/layout.py): a declared boundary lies at a function start (or an end
    boundary at the end of the game code), never inside fill or strictly inside a function. Native:
    native/dcp_core/src/layout.rs."""
    return ()


def scan_inputs(p) -> str:
    """What L5, A1 and L13 read that only Python computes, as JSON text: the targets (the default first), the
    current one, the targets' image files and the source scan's items (srcscan.native_view)."""
    import json
    head = json.dumps({"targets": [t.name for t in p.targets], "target": p.target_name,
                       "images": {t.name: str(t.path) for t in p.targets}})
    return head[:-1] + ',"scan":' + srcscan.native_view(srcscan.scan(p.root, p.input_hash("src"))) + "}"


@rule("L5.placeholder", version="3", ceiling=P, inputs=("scan", "targets"), needs=("kind:start", "S.sections", "S.codewalk", "S.crt.code"),
      helpers=(srcscan,), native=True, native_inputs=scan_inputs)
def placeholder(ctx: RuleContext):
    """L5: an identifier that spells an address (`Unk<hex>`, `FUN_<hex>`, `DAT_<hex>`, `<name>_<6-8 hex with a
    digit>`, in any .c / .h of src/ and include/) names a real address: on a line of the current target (inside
    a function the target holds, or outside every function with an address) a number inside a section of the
    target's image must, inside a code section, be a function start (a `start` fact of any producer, or an inner
    label). A number inside no section of any target the file belongs to is a dropped or extra digit, reported
    in the default target's store only (at the line that spells it). A function's span ends with its definition
    (line_targets). Native:
    native/dcp_core/src/layout.rs."""
    return ()


@rule("A1.addr.cast", version="1", ceiling=P, inputs=("scan", "targets"), needs=("kind:name", "kind:symbol"),
      helpers=(srcscan,), native=True, native_inputs=scan_inputs)
def addr_cast(ctx: RuleContext):
    """A1: an integer literal cast to a pointer type in the sources (srcscan's PtrCast: `(void (*)(void))0x5de470`,
    `(char *)0x6f242c`, `(T *)(unsigned)0x...`; the cast's type spells its `*`, a typedef'd pointer name is not
    recognised; comments, strings and `#if 0` / `#else` text do not count, `#define` bodies do) whose value lies in
    the current target's image [base, end), on a line of the current target (line_targets: inside a function
    the target holds, or outside every function with an address). Such a pointer is the original's address
    frozen into the code: the relinked image places that object elsewhere, so the pointer goes wrong. An error;
    the message names what the facts know at the address (its name, else the symbol containing it, else nothing
    known) and asks for the symbol by name. The address of a symbol (`(unsigned)&x`, `(char *)&x`) is no literal
    and is not reported. Native:
    native/dcp_core/src/layout.rs."""
    return ()


@rule("L13.data.code", version="1", ceiling=P, inputs=("scan", "targets"),
      needs=("kind:name", "kind:start", "S.codewalk", "S.crt.code", "S.thunk", "M.match", "L.decl"),
      helpers=(srcscan,), native=True, native_inputs=scan_inputs)
def data_at_code(ctx: RuleContext):
    """L13: a data declaration of the sources (a definition or an `extern` with an address comment, srcscan Data)
    whose address, for the current target, is a known function start (a `start` fact above declared: the walk,
    the library placement, the entry, an export; or the start of a function symbol above declared) or lies inside
    a known function's extent (a `func` symbol above declared: walked, placed or byte-matched), unless a table
    symbol covers it (the walk's or a declared jumptable / idxtable, a declared fptr range: data a code section
    holds). The name declares data at code: whatever reads or calls it through that declaration, the relinked
    image gives it a data object instead of the function. An error naming the function there. Native:
    native/dcp_core/src/layout.rs."""
    return ()


@rule("L14.unit.outside", version="2", ceiling=DE, needs=("L.unit.extent", "L.src", "L.decl", "S.crt.code", "S.thunk"),
      inputs=("decl", "targets"), native=True, native_inputs=decl_inputs)
def source_outside_unit(ctx: RuleContext):
    """L14 (outside_unit_issues in rules/layout.py): a sourced function outside the game code (in the library
    code after it) whose unit has a declared boundary (`boundary start|end tu=UNIT` in decl/text.dcl) and an
    extent: every function of such a unit lies inside the extent. Inside the game code L7 checks the same.
    An error: no game unit owns library code, and a unit compiled with that function is not the
    unit's translation unit. Library code with a source belongs to a library unit (`libunit` in decl/text.dcl):
    its functions lie inside the declared member range, which lies outside the game code. Native:
    native/dcp_core/src/layout.rs."""
    return ()


@rule("L6.declared", version="1", ceiling=P, needs=("L.decl", "S.codewalk", "S.crt.code", "S.thunk", "S.relocs", "S.sections"), native=True)
def declared_recheck(ctx: RuleContext):
    """L6: every declaration is re-checked against the computed facts at every run, never trusted.
    bytes dead / foreign: no walked or placed function covers a byte of the range, and no call, jump, tail call
    or code immediate reaches into it (such bytes are reachable code, not dead).
    jumptable / idxtable fn=F: F is a function start; the walk did not walk the range as code; a table the
    walk found overlapping the range has the same extent and function.
    fptr: every address-wide field of the range (Image.ptr_size) is a relocation site whose target lies in a
    code section.
    start: not strictly inside a walked or placed function (unless it is an inner label)."""
    return ()                                      # native: native/dcp_core/src/layout.rs


@rule("L8.leak", version="1", ceiling=D, needs=("L.analyze", "L.unit.extent"), helpers=(leak_issues, unit_index), native=True)
def leak_unit(ctx: RuleContext):
    """L8 (leak_issues in rules/layout.py): one unit, one leaked source file."""
    return ()                                      # native: native/dcp_core/src/layout.rs


# ------------------------------------------------------------------------------------------------ L9 / L10 / R5
@rule("L9.analyzer.span", version="2", ceiling=DE, inputs=("drafts",),
      needs=("L.decl", "L.src", "S.exports", "S.entry", "S.crt.code", "S.crt.refs", "S.codewalk", "S.thunk"),
      native=True)
def analyzer_span(ctx: RuleContext):
    """L9 (warning): an analyzer's function of the game code (its entry before the first library byte) whose
    body (its address ranges, when the analyzer reports them: Ghidra's export does) holds one of our function
    starts other than its own entry: a start fact of any producer but L.analyzer (export, entry, library, walk,
    declaration, source) or the start of a placed or walked function; inner labels of a walked function do
    not count. The analyzer merged two functions (typically across a call that does not return): its
    pseudocode holds both, and a draft from it must stop at our start. A warning, not an error: the body is an
    external tool's analysis (a declaration), our starts rest on the bytes and stated conventions. Library code
    is placed by its own members' bytes; the analyzer's view of it is no layout question and is not checked. Native:
    native/dcp_core/src/layout.rs."""
    return ()


@rule("L.src.extent", version="1", ceiling=DE, outputs=("symbol",),
      needs=("L.src", "L.decl", "L.decl.start", "S.sections", "S.codewalk", "S.crt.code", "S.thunk", "S.fill", "M.match",
             "S.exports", "S.entry"),
      native=True, native_inputs=lambda p: {"function_alignment": p.toolchain.function_alignment})
def src_extent(ctx: RuleContext):
    """A sourced function whose start no other function covers (the walk did not reach it: an image without base
    relocations hides most call-only and pointer-only functions; it does not byte-match) owns its code by the
    contiguity convention W1 of rules/walk.py: from its start up to the next stop (any known start, the start of
    any claimed symbol or region, a declared unit boundary, the end of the code section), less the alignment fill
    at the end (Toolchain fill forms, at most function_alignment - 1 bytes), as a `func` symbol {extent: source};
    the trailing fill as a `fill` symbol. Declared: the start is the address comment's (a premise), the extent a
    convention. Nothing is claimed when the range is only fill. After the end of any claimed code (a function,
    its jump or index table, a match's compared section), a gap of less than function_alignment bytes up to the
    next stop is claimed too: first a match's padding inside our compiled section (compared equal: `fill`
    {extent: matched}), then alignment fill (`fill` {extent: source}). S.fill cannot see these gaps: it claims
    fill that ends at a claimed byte, and the next function may be one only this rule claims. Native:
    native/dcp_core/src/layout.rs."""
    return ()


@rule("L10.unexplained", version="2", ceiling=DE, needs=("L.unit.extent", "L.src", "M.match", "S.codewalk", "L.decl", "L.src.extent"),
      native=True)
def unexplained(ctx: RuleContext):
    """L10 (warning): code inside a game unit's extent that no source, no declaration and no other function
    explains, though a source claims it. Two cases:
    (a) a source whose start the walk does not know (a declared start in unknown code) and that does not
    byte-match owns no bytes (M.draft takes the walk's extent, there is none; M.match proves an extent only for
    a match) and L.src.extent did not give it the bytes up to the next stop either (a claimed byte right at its
    start, or only fill): its code stays open (`open_bytes`) until it matches or a convention reaches its start;
    (b) a source that byte-matches (M.match: its compiled section, padding included, ends at m) while the walk
    gives its start a function extent [a, w) with w > m: the bytes [m, w), minus declared dead / foreign bytes,
    are code the walk reached that our function does not contain (a missed start, dead code to declare `bytes
    dead -- why`, or a table read as code). (R1's tail check makes (b) rare: a match already proves that only fill
    follows its end up to the next start.)
    A non-matching draft with a walked start owns the walk's extent (M.draft), and a walked function without a
    function is L2 (informational, `dcp layout next`): neither is L10. Native:
    native/dcp_core/src/layout.rs."""
    return ()


@rule("M.bytes.declared", version="1", ceiling=DE, outputs=("source",), needs=("L.decl", "L.unit.extent"), native=True)
def bytes_declared(ctx: RuleContext):
    """R5: declared dead or foreign bytes (decl/*.dcl `bytes dead`, `foreign kind=`) inside a game unit's extent
    belong to that unit: a `source` fact {what: dead | foreign, unit} over the range, declared (the declaration
    is the premise), so the byte map gives those bytes the unit and its source, and the unit counts them as
    explained (L.unit.extent: dead_bytes), not open. A range that crosses a unit boundary is an error
    (M.bytes.declared); a range inside no unit is a warning (no unit owns it yet)."""
    return ()                                      # native: native/dcp_core/src/layout.rs
