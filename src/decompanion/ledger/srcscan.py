"""The source scan: the sources are typed state, and this module reads it (a port of the address-comment parser
of the first attempt, rea/tools/gildegold/core/gen.py). No object file is needed: it reads text.

Layout of a target project's sources
  src/<unit>.c             one translation unit, in its TU order (CL compiles a caller differently once a callee
                           is defined above it, a declaration must precede its use): the head region (includes,
                           local types, prototypes, the dcp declaration block; everything before the first
                           function definition), then the functions with the file-scope data between them
  include/<unit>.h         public prototypes and extern declarations
  `__inline` helpers       not functions of the binary (no symbol, no address): a unit or a header may define
                           them where the TU needs them; the scan does not count them

Address comments
  function   the own-line comment directly above its definition:  /* 0x10001000, what it does */
             several targets:                  /* server:0x10001000, exe:0x4a3000, what it does */
             (a bare address is the default target's)
             not in the binary:                /* unlinked, why */
             tags inside it:                   @deep why   @stuck why   @rough
             a function of some targets only stands under `#if` on their DCP_TARGET_<name> macros (L16)
  data       after the definition / extern:    int x = 1;  /* 0x1002a000 */
             one address per declarator:       extern int a, b;  /* 0x1002a000, 0x1002a004 */
             a multi-line table:               the comment on the line above it
             (the same target prefixes; `/* unlinked, why */` for data the binary lacks)
  view       a name for part of a larger data object (the original packs its data: a name inside another
             object is a view of that storage, no object of its own), a one-line object-like macro with the
             address comment on its line, in one of three forms:
               #define NAME (*(T *)((char *)&CONTAINER + OFFSET))  /* 0x1002a010 */   (byte offset)
               #define NAME (*(T *)&CONTAINER)                     /* 0x1002a000 */
               #define NAME CONTAINER                              /* 0x1002a000 */   (an alias)
             `(char *)CONTAINER` without `&` for an array container. CONTAINER is a data declaration of the
             sources; the view's address is the container's plus OFFSET (check L15, rules/layout.py). A
             dereferencing cast macro with an address comment in any other form is an error (L15).
  placeholders  an identifier that spells an address (`Unk10001000`, `FUN_10001000`, `name_10001000`) must
             name a real start (check L5, rules/layout.py)

scan(root) returns every definition, data declaration, placeholder and parse error of the tree, for all
targets; the loader rule L.src (rules/layout.py) picks the current target's addresses and emits the facts.
Results are memoised per tree hash, so the loader and the checks parse once per process.

Everything C comes from the front end (docs/plan.md section 18; source/cparse.py, libclang): the comments and
literals (its tokens), the macro definitions, the function definitions and the file-scope data declarations,
over each unit file as a target's compile sees it (models: its DCP_TARGET_<name> defined); a header as the first unit that includes it sees it, a file no unit
holds parsed alone. So `#if` / `#ifdef` are evaluated (a declaration in a dead branch is no declaration), a macro
is expanded (zlib's `local` is `static`), and every declarator of `int a = 1, b = 2;` is one. The default
target's view gives everything; another target's adds the function definitions only it holds (L16 compares
the targets a function is live in with those its comment lists). A data statement's address comment is found by
its extent (on its first line, after its `;`, or the own-line comment above). A text that is no project file (a
test's, a single line) is parsed alone (model_alone). What the comments say (the address comments, the tags, the
descriptions) and what the macros' bodies hold (views, casts) the scan reads: per file in the native core
(native/dcp_core/src/srcscan.rs: scan_file). Source (TOKEN, its own lexer) serves the other readers of a text.
"""
from __future__ import annotations

import bisect
import os
import re
from dataclasses import dataclass
from pathlib import Path
from .. import fsmemo

NATIVE = True                 # the per-file scan is the native core's: a rule with this module as a helper hashes it
TOKEN = re.compile(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|//[^\n]*|/\*.*?\*/', re.S)
ADDR_ITEM = r"(?:[A-Za-z][A-Za-z0-9_-]*:)?0x[0-9a-fA-F]+"
LEAD_ADDRS = re.compile(r"^\s*(" + ADDR_ITEM + r")((?:\s*[,/]\s*" + ADDR_ITEM + r")*)")
ONE_ADDR = re.compile(r"(?:([A-Za-z][A-Za-z0-9_-]*):)?(0x[0-9a-fA-F]+)")
UNLINKED = re.compile(r"^\s*unlinked\b\s*,?\s*(.*)", re.S)
DEEP = re.compile(r"@deep\b[ \t]*(.*?)[ \t]*(?:\*/|\n|$)")
STUCK = re.compile(r"@stuck\b[ \t]*(.*?)[ \t]*(?:\*/|\n|$)")
ROUGH = re.compile(r"@rough\b")
FUNCPTR = re.compile(r"\(\s*(?:__cdecl|__stdcall|__fastcall|WINAPI|CALLBACK|APIENTRY|PASCAL)?\s*\*+\s*(?:const\s+)?([A-Za-z_]\w*)\s*\)")
# `Unk<hex>` takes hex digits of one case and may carry an upper-case view suffix (`ai_Unk7603a0B` is the view B
# of 0x7603a0, not 0x7603a0b); the lower-case reading is tried first, so `Unk430100B` is 0x430100 too
PLACEHOLDER_ADDR = re.compile(r"\b[A-Za-z_]\w*?Unk([0-9a-f]{5,8}|[0-9A-F]{5,8})(?:[A-Z][A-Za-z]*)?\b"
                              r"|\b[A-Za-z_]\w*?(?:FUN_|DAT_|PTR_|LAB_)([0-9a-fA-F]{5,8})\b"
                              r"|\b[A-Za-z_]\w*?_((?=[0-9a-fA-F]*\d)[0-9a-fA-F]{6,8})\b")


def placeholder_value(m: re.Match) -> int:
    """The address a PLACEHOLDER_ADDR match spells."""
    return int(next(g for g in m.groups() if g), 16)



@dataclass(frozen=True)
class Function:
    file: str                 # project-relative posix path
    line: int                 # line of the definition
    unit: str
    name: str
    addrs: tuple              # ((target or None, address), ...) in comment order
    unlinked: bool
    what: str                 # the description after the addresses
    deep: str | None = None
    stuck: str | None = None
    rough: bool = False
    comment_line: int = 1
    static: bool = False      # `static`: its name is the unit's own (N2 compares it within the unit only)
    end_line: int = 0         # the last line of the definition (0: the front end gave no end)
    targets: tuple = ()       # the targets whose compile holds the definition (its `#if` live), () unknown


@dataclass(frozen=True)
class Data:
    file: str
    line: int
    unit: str
    name: str
    kind: str                 # def | extern
    addrs: tuple              # ((target or None, address), ...) of this declarator
    unlinked: bool
    static: bool = False      # `static`: its name is the unit's own (N2 compares it within the unit only)


@dataclass(frozen=True)
class Placeholder:
    file: str
    line: int
    ident: str
    value: int


@dataclass(frozen=True)
class PtrCast:
    """An integer literal cast to a pointer type (the front end's in code, a pointer cast's spelling in a macro's
    body: native/dcp_core/src/srcscan.rs; check A1 in rules/layout.py)."""
    file: str
    line: int
    text: str                 # the cast and the literal as written (whitespace collapsed)
    value: int


@dataclass(frozen=True)
class View:
    """A view macro: a name for `offset` bytes into the data object `container` (L15 in rules/layout.py)."""
    file: str
    line: int
    unit: str
    name: str
    container: str
    offset: int
    addrs: tuple              # ((target or None, address), ...) of its address comment
    alias: bool = False       # `#define NAME CONTAINER`: a view only when CONTAINER is a data declaration


@dataclass(frozen=True)
class ScanError:
    file: str
    line: int
    check: str                # L.src | L15 | L16
    message: str


class Scan:
    """A scan: the core's (scan(): native/dcp_core/src/frontend.rs; its rows become the dataclasses above when read)
    or an accumulator of scan_file (a text's scan). functions, data, placeholders, errors (the files', then the
    scan's own), files, macros [(name, body)] of every function-like #define, described (addresses an address
    comment describes in words), ptrcasts, views, rawobj (object-like macros dereferencing a cast, no view),
    own_errors (L16), piece_ids (its files' pieces in the core)."""

    LISTS = ("functions", "data", "placeholders", "errors", "macros", "described", "ptrcasts", "views", "rawobj", "own_errors",
             "piece_ids")

    def __init__(self, core=None):
        self._x = core
        if core is None:
            for k in self.LISTS:
                setattr(self, k, [])
            self.files = 0

    def __getattr__(self, name):
        x = self.__dict__.get("_x")
        if x is None or name.startswith("__"):
            raise AttributeError(name)
        if name == "functions":
            v = [Function(*a[:4], tuple(a[4]), *a[5:], *b[:6], tuple(b[6])) for a, b in x.function_rows]
        elif name == "data":
            v = [Data(*d[:5], tuple(d[5]), *d[6:]) for d in x.data_rows]
        elif name == "placeholders":
            v = [Placeholder(*r) for r in x.placeholder_rows]
        elif name == "errors":
            v = [ScanError(*e) for e in x.error_rows]
        elif name == "own_errors":
            v = [ScanError(*e) for e in x.own_error_rows]
        elif name == "macros":
            v = [tuple(m) for m in x.macros]
        elif name == "ptrcasts":
            v = [PtrCast(*c) for c in x.ptrcast_rows]
        elif name == "views":
            v = [View(*r[:6], tuple(r[6]), r[7]) for r in x.view_rows]
        elif name in ("described", "rawobj", "piece_ids", "files"):
            v = getattr(x, name)
        elif name == "models":
            v = _Models(x)
        else:
            raise AttributeError(name)
        self.__dict__[name] = v
        return v

    def digest(self) -> str:
        """The hash of what the native rules read of the scan (its files' pieces, its own errors)."""
        return self._x.digest()


class _Models:
    """rel -> the default target's front end model of a file (dict form, made when read)."""

    def __init__(self, x):
        self._x = x

    def get(self, rel: str, default=None):
        return self._x.model(rel)


def lead_addrs(body: str) -> list[tuple[str | None, int]]:
    """The addresses a comment starts with: `0x10001000` / `server:0x10001000, exe:0x4a3000, what`."""
    m = LEAD_ADDRS.match(body)
    if not m:
        return []
    return [(t or None, int(a, 16)) for t, a in ONE_ADDR.findall(m.group(0))]


class Source:
    """One .c / .h file: its comments, its code with strings and comments blanked, its definitions and data."""

    def __init__(self, rel: str, text: str):
        self.rel = rel
        self.text = text
        self._line_starts = None
        self._own_line_ends = None
        self.comments = []            # (start, end, body)
        out = []
        pos = 0
        for m in TOKEN.finditer(text):
            out.append(text[pos:m.start()])
            tok = m.group(0)
            if tok.startswith("/*"):
                self.comments.append((m.start(), m.end(), tok[2:-2]))
            elif tok.startswith("//"):
                self.comments.append((m.start(), m.end(), tok[2:]))
            out.append("".join("\n" if c == "\n" else " " for c in tok))
            pos = m.end()
        out.append(text[pos:])
        self.code = "".join(out)

    def line_of(self, off: int) -> int:
        if self._line_starts is None:
            self._line_starts = [0] + [i + 1 for i, c in enumerate(self.text) if c == "\n"]
        return bisect.bisect_right(self._line_starts, off)

    def offset(self, line: int, col: int) -> int:
        """The offset of a (line, column) position, both from 1 (the front end's)."""
        self.line_of(0)
        return self._line_starts[min(line, len(self._line_starts)) - 1] + col - 1

    def end_before(self, off: int) -> int:
        text = self.text
        while off > 0 and text[off - 1].isspace():
            off -= 1
        return off

    def own_line_comment_ends(self) -> dict[int, int]:
        """end offset -> index of every comment that starts its line."""
        if self._own_line_ends is None:
            self._own_line_ends = {e: i for i, (s, e, b) in enumerate(self.comments)
                                   if not self.text[self.text.rfind("\n", 0, s) + 1:s].strip()}
        return self._own_line_ends

def live_code(S: Source, model: dict) -> str:
    """The file's code (comments and strings blanked) with its preprocessor lines and the ranges the preprocessor
    skipped (model["dead"]) blanked too; offsets unchanged."""
    lines = S.code.split("\n")
    dead = {n for a, b in model["dead"] for n in range(a, b + 1)}
    cont = False
    for n, ln in enumerate(lines, 1):
        directive = cont or ln.lstrip().startswith("#")
        cont = directive and ln.rstrip().endswith("\\")
        if directive or n in dead:
            lines[n - 1] = " " * len(ln)
    return "\n".join(lines)


def model_alone(rel: str, text: str, root: Path | None = None) -> dict:
    """The front end's model of one text parsed alone (no unit around it, no includes found unless they exist
    below root): a text that is no project file (a test's, a single line), as a file no unit holds is."""
    from .. import native
    return native.core().front_model_alone(str(Path(root) if root is not None else Path.cwd()), rel, text)


def model_of(root: Path, rel: str, text: str) -> dict | None:
    """The front end's model of a file when text is the file as it is on disk (the scan's), else None."""
    p = Path(root) / rel
    if not p.exists() or fsmemo.read_text(p) != text:
        return None
    tree = fsmemo.tree_hash([Path(root) / "src", Path(root) / "include"], ("*.c", "*.h"))
    return scan(Path(root), tree).models.get(rel, EMPTY)


@dataclass(frozen=True)
class Define:
    """A macro the preprocessor defined in a file: offsets in the file's text from its name to the end of its last
    token (a trailing comment is no part of it)."""
    name: str
    line: int
    start: int
    end: int
    flike: bool

    def rest(self, text: str) -> str:
        """What follows the name in `text` (the file's text or its code): `(params) body` or the body."""
        return text[self.start + len(self.name):self.end]


def defines(S: Source, model: dict, like: bool | None = None):
    """The live macro definitions of a file (the front end's: model["defines"]), the function-like or the
    object-like ones only when `like` says so."""
    for name, flike, line, col, eline, ecol in model["defines"]:
        if like is None or flike == like:
            yield Define(name, line, S.offset(line, col), S.offset(eline, ecol), flike)


def scan_file(rel: str, text: str, out: Scan, model: dict | None = None, views: dict | None = None):
    """One file's part of the scan (native/dcp_core/src/srcscan.rs): its address comments, function definitions,
    data declarations, macros, casts and placeholders from its text and the front end's model of the file
    (cparse.model's entry; the text parsed alone when none is given: model_alone). views: target -> that target's
    model of the file (model is the default target's): a function's `targets` are the views that hold its
    definition, and a definition only another target's view holds (under its `#if`) is a function too."""
    from .. import native
    model = model_alone(rel, text) if model is None else model
    macros, described, functions, data, ptrcasts, views_, rawobj, errors, placeholders, piece = \
        native.core().scan_file(rel, text, model, list(views.items()) if views else [])
    out.piece_ids.append(piece.id)
    out.__dict__.setdefault("_pieces", []).append(piece)
    out.macros += [tuple(x) for x in macros]
    out.described += described
    out.functions += [Function(*a[:4], tuple(a[4]), *a[5:], *b[:6], tuple(b[6])) for a, b in functions]
    out.data += [Data(*d[:5], tuple(d[5]), *d[6:]) for d in data]
    out.ptrcasts += [PtrCast(*c) for c in ptrcasts]
    out.views += [View(*v[:6], tuple(v[6]), v[7]) for v in views_]
    out.rawobj += rawobj
    out.errors += [ScanError(*e) for e in errors]
    out.placeholders += [Placeholder(*x) for x in placeholders]


EMPTY = {"defs": [], "vars": [], "macros": [], "defines": [], "comments": [], "strings": [], "casts": [], "decls": [], "types": [], "dead": []}


def target_macro(name: str) -> str:
    """The macro every compile of a target defines (a function of some targets only stands under `#if` on it)."""
    return "DCP_TARGET_" + re.sub(r"\W", "_", name)


def local_refs(root: Path, names: list[str]) -> dict[str, set[tuple[int, int]]]:
    """rel -> {(line, col)} of the occurrences of `names` the front end finds referring to a declaration not at
    file scope (cparse.refs: a local, a parameter, a field, a label), in every project file that holds one of
    the names (as the default target's compile sees it): what a rename of a file-scope symbol leaves alone.
    One parse per such file, not per unit that reads it: each unit file that holds a name, and for a header
    that holds one, the first unit that includes it; a unit's parse covers the headers it reads."""
    from .. import native
    from ..source import cparse
    root = Path(root)
    core = native.core()
    sysdirs, incdirs_, targets = core.front_of(str(root))
    defines = targets[0][1]
    tree = fsmemo.tree_hash([root / "src", root / "include"], ("*.c", "*.h"))
    scan(root, tree)                                      # every unit's dependencies (its last parse's)
    files = [(rel, p) for rel, p in fsmemo.walk(root / "src", ("*.c",))] if (root / "src").exists() else []
    pat = re.compile(r"\b(?:" + "|".join(map(re.escape, names)) + r")\b")
    holds = {}
    under = os.path.normcase(str(root.resolve())) + os.sep

    def norm(d: str) -> str:
        return os.path.normcase(os.path.abspath(d))

    def held(p) -> bool:
        if p not in holds:
            try:
                text = fsmemo.read_text(p)
                holds[p] = any(n in text for n in names) and bool(pat.search(text))
            except OSError:
                holds[p] = False
        return holds[p]

    units = []                                            # (unit file, it holds a name, the headers below root it reads that do)
    for rel, p in sorted(files, key=lambda t: t[0].lower()):
        if "/" not in rel:
            deps = {norm(d) for d in core.front_last_deps(str(Path(p)))}
            units.append((p, held(str(p)), {d for d in deps if d.startswith(under) and held(d)}))
    covered, pick = set(), set()
    for p, own, deps in units:
        if own:
            pick.add(p)
            covered |= deps
    for p, own, deps in units:
        if not own and deps - covered:
            pick.add(p)
            covered |= deps
    jobs = [(Path(p), root, [Path(d) for d in sysdirs], [Path(d) for d in incdirs_], fsmemo.read_text(p), list(defines), list(names), None)
            for p, _, _ in units if p in pick]
    out: dict[str, set] = {}
    for r in cparse.many(jobs, fn="refs"):
        for rel, xs in r.items():
            out.setdefault(rel, set()).update(xs)
    return out


def scan(root: Path, tree_hash: str | None = None) -> Scan:
    """Scan src/**/*.c, src/**/*.h and include/**/*.h of the project at root (memoised per tree hash), every
    file as each target's compile sees it (the core's: native/dcp_core/src/frontend.rs)."""
    from .. import native
    return Scan(native.core().front_scan(str(Path(root)), tree_hash))


class Spans:
    """(file, line) -> the function whose span holds the line: from its address comment to the last line of its
    definition (an end of 0: to the next span or the end of the file). items: (file, first, last, value)."""

    def __init__(self, items):
        by: dict[str, list] = {}
        for f, lo, hi, v in items:
            by.setdefault(f, []).append((lo, hi, v))
        self._by = {f: sorted(xs, key=lambda x: x[0]) for f, xs in by.items()}
        self._keys = {f: [x[0] for x in xs] for f, xs in self._by.items()}

    def at(self, file: str, line: int):
        xs = self._by.get(file)
        if not xs:
            return None
        k = bisect.bisect_right(self._keys[file], line) - 1
        if k < 0 or xs[k][1] and line > xs[k][1]:
            return None
        return xs[k][2]


def native_pieces(sc: Scan) -> tuple[list[int], list[tuple]]:
    """The scan as the native rules read it: its files' pieces in the core by id, the errors of the whole scan."""
    return list(sc.piece_ids), [(e.check, e.file, e.line, e.message) for e in sc.own_errors]


def function_spans(sc: Scan, target: str, default: str) -> Spans:
    """(file, line) -> the address of the target's function whose span holds the line."""
    return Spans((f.file, f.comment_line, f.end_line, a) for f in sc.functions
                 if (a := address_for(f.addrs, target, default)) is not None)


def address_for(addrs: tuple, target: str, default: str) -> int | None:
    """The address of a (target or None, address) list for one target (a bare address is the default's)."""
    for t, a in addrs:
        if (t or default) == target:
            return a
    return None
