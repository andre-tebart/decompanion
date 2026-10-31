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
import functools
import os
import re
from dataclasses import dataclass, field
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


@dataclass
class Scan:
    functions: list[Function] = field(default_factory=list)
    data: list[Data] = field(default_factory=list)
    placeholders: list[Placeholder] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)
    files: int = 0
    macros: list[tuple[str, str]] = field(default_factory=list)  # (name, body) of every function-like #define
    described: list[int] = field(default_factory=list)          # addresses an address comment describes in words
    ptrcasts: list[PtrCast] = field(default_factory=list)       # integer literals cast to a pointer type (A1)
    views: list[View] = field(default_factory=list)             # view macros (L15)
    rawobj: list[str] = field(default_factory=list)             # object-like macros dereferencing a cast, no view (Q4)
    models: dict = field(default_factory=dict)                  # file -> its front end model (cparse.model's entry)
    native: list = field(default_factory=list, repr=False, compare=False)  # its files' pieces in the core (ScanPiece)
    own_errors: list[ScanError] = field(default_factory=list)   # the errors of the whole scan (L16), after the files'


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
    from ..source import cparse
    root = Path(root) if root is not None else Path.cwd()
    if root.joinpath("decompanion.toml").exists():
        sysdirs = front_end(root)
    else:
        if cparse._loaded is None:
            lib = cparse.library(None)
            if lib is None:
                from ..source import lint as L
                raise RuntimeError(L.NOT_FOUND)
            cparse.load(lib)
        sysdirs = []
    m = cparse.model(root / rel, root, sysdirs, [root / "include"], text, [])
    return m["files"].get(Path(rel).as_posix(), EMPTY)


def model_of(root: Path, rel: str, text: str) -> dict | None:
    """The front end's model of a file when text is the file as it is on disk (the scan's), else None."""
    import hashlib
    p = Path(root) / rel
    if not p.exists() or fsmemo.read_text(p) != text:
        return None
    key = (str(root), fsmemo.epoch)                # the tree's digest once per file epoch (a write starts a new one)
    tree = _trees.get(key)
    if tree is None:
        tree = hashlib.sha256("\0".join(f"{r}={fsmemo.sha256(q)}" for r, q in project_files(Path(root))).encode()).hexdigest()
        _trees.clear()
        _trees[key] = tree
    return scan(Path(root), tree).models.get(rel, EMPTY)


_trees: dict[tuple, str] = {}


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
    out.native.append(piece)
    out.macros += [tuple(x) for x in macros]
    out.described += described
    out.functions += [Function(*a[:4], tuple(a[4]), *a[5:], *b[:6], tuple(b[6])) for a, b in functions]
    out.data += [Data(*d[:5], tuple(d[5]), *d[6:]) for d in data]
    out.ptrcasts += [PtrCast(*c) for c in ptrcasts]
    out.views += [View(*v[:6], tuple(v[6]), v[7]) for v in views_]
    out.rawobj += rawobj
    out.errors += [ScanError(*e) for e in errors]
    out.placeholders += [Placeholder(*x) for x in placeholders]


_cache: dict[tuple[str, str], Scan] = {}
_files: dict[tuple[str, str], tuple] = {}        # (path, sha256 of the text) -> (the models it was scanned with, its scan)
MODEL_VERSION = "18"                               # bump when the scan's translation units change
_models: dict[str, tuple] = {}                    # model key -> ([(dependency, sha256)], files)
_last_deps: dict[str, list[str]] = {}             # translation unit path -> what its last parse read
EMPTY = {"defs": [], "vars": [], "macros": [], "defines": [], "comments": [], "strings": [], "casts": [], "decls": [], "types": [], "dead": []}
UNIT_FILE = re.compile(r"^src/[^/]+\.c$")


def target_macro(name: str) -> str:
    """The macro every compile of a target defines (a function of some targets only stands under `#if` on it)."""
    return "DCP_TARGET_" + re.sub(r"\W", "_", name)


def target_defines(root: Path) -> list[tuple[str | None, list[str]]]:
    """(target, the macros its compile defines) of every target, the default first; [(None, [])] without a
    decompanion.toml."""
    if not (Path(root) / "decompanion.toml").exists():
        return [(None, [])]
    from ..config import Project
    return [(t.name, [target_macro(t.name)]) for t in Project(root).targets]


def incdirs(root: Path) -> list[Path]:
    """The include directories of a unit's parse (a quoted include also resolves beside the file, in src/)."""
    return [Path(root) / "include"]


def front_end(root: Path) -> list[Path]:
    """Load the project's libclang (cparse) and return its system include directories (none without a
    decompanion.toml)."""
    from ..source import cparse
    from ..source import lint as L
    if (root / "decompanion.toml").exists():
        from ..config import Project
        p = Project(root)
        L.setup(p)
        return L.sysdirs_of(p)
    lib = cparse.library(None)
    if lib is None:
        raise RuntimeError(L.NOT_FOUND)
    cparse.load(lib)
    return []


def _model_hit(root: Path, key: str):
    """A kept model whose dependencies (every file the parse read) are unchanged, else None."""
    import pickle
    hit = _models.get(key)
    path = root / "build" / "cache" / "cparse" / f"{key}.pickle"
    if hit is None and path.exists():
        try:
            hit = pickle.loads(path.read_bytes())
        except (OSError, ValueError, EOFError, pickle.UnpicklingError, TypeError, AttributeError, ImportError):
            hit = None
    if hit is None:
        return None
    try:
        if any(fsmemo.sha256(d) != h for d, h in hit[0]):
            return None
    except OSError:
        return None
    _models[key] = hit
    return hit[1]


def _model_keep(root: Path, key: str, m: dict):
    import pickle
    if m["missing"]:
        return
    try:
        hit = ([(d, fsmemo.sha256(d)) for d in m["deps"]], m["files"])
    except OSError:
        return
    _models[key] = hit
    if (root / "build").is_dir():
        path = root / "build" / "cache" / "cparse" / f"{key}.pickle"
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(pickle.dumps(hit))
            tmp.replace(path)
        except OSError:
            pass


def models(root: Path, files: list[tuple[str, str]], defines=()) -> dict[str, dict]:
    """rel -> the front end's model of that file (cparse.model: defs, vars) as a compile with `defines` sees it.
    Each unit file src/<unit>.c is one translation unit; a header takes the model of the first unit (by name)
    that includes it (as that unit's preprocessor sees it); a file no unit holds (a header no unit includes, a
    stray .c) is parsed alone. Each parse is kept by its text, arguments and libclang (build/cache/cparse/) as
    long as every file it read is unchanged."""
    from ..ledger.fact import canonical
    from ..ledger.store import sha256
    from ..source import cparse
    sysdirs = front_end(root)
    vc = cparse.version()
    dirs = incdirs(root)

    def tu(path: Path, rel: str):
        """(key, path): keyed by the file's content hash (no file is read for a kept model)."""
        key = sha256("srcscan.model", MODEL_VERSION, cparse.VERSION, vc, canonical(cparse.args(sysdirs, dirs, defines)),
                     str(path), f"{rel}={fsmemo.sha256(path)}")
        return key, path

    def run(tus) -> list[dict]:
        got, misses = {}, []
        for key, path in tus:
            hit = _model_hit(root, key)
            if hit is None:
                misses.append((key, path))
            else:
                got[key] = hit
                _last_deps[str(path)] = [d for d, _ in _models[key][0]]
        # a lone miss (the unit an edit changed) is parsed in process and stays live: the lint of the edit reads
        # the same parse, the next edit reparses it
        jobs = [(path, root, sysdirs, dirs, fsmemo.read_text(path), list(defines), True if len(misses) == 1 else None)
                for _, path in misses]
        for (key, path), m in zip(misses, cparse.many(jobs, fn="model")):
            _model_keep(root, key, m)
            _last_deps[str(path)] = m["deps"]
            got[key] = m["files"]
        return [got[t[0]] for t in tus]

    out: dict[str, dict] = {}
    for files_ in run([tu(Path(p), rel) for rel, p in files if UNIT_FILE.match(rel)]):
        for rel, m in files_.items():
            out.setdefault(rel, m)
    alone = [(rel, p) for rel, p in files if rel not in out]
    for (rel, _), files_ in zip(alone, run([tu(Path(p), rel) for rel, p in alone])):
        out[rel] = files_.get(rel, EMPTY)
    return out


def local_refs(root: Path, names: list[str]) -> dict[str, set[tuple[int, int]]]:
    """rel -> {(line, col)} of the occurrences of `names` the front end finds referring to a declaration not at
    file scope (cparse.refs: a local, a parameter, a field, a label), in every project file that holds one of
    the names (as the default target's compile sees it): what a rename of a file-scope symbol leaves alone.
    One parse per such file, not per unit that reads it: each unit file that holds a name, and for a header
    that holds one, the first unit that includes it (an occurrence in a header refers to the same declaration
    in every unit that includes it, as models() takes a header's model from its first unit); a unit's parse
    covers the headers it reads."""
    from ..source import cparse
    root = Path(root)
    files = project_files(root)
    sysdirs = front_end(root)
    defines = target_defines(root)[0][1]
    models(root, files, defines)                          # every unit's dependencies (_last_deps)
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
    for rel, p in files:
        if UNIT_FILE.match(rel):
            deps = {norm(d) for d in _last_deps.get(str(Path(p)), [])}
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
    jobs = [(Path(p), root, sysdirs, incdirs(root), fsmemo.read_text(p), list(defines), list(names), None)
            for p, _, _ in units if p in pick]
    out: dict[str, set] = {}
    for r in cparse.many(jobs, fn="refs"):
        for rel, xs in r.items():
            out.setdefault(rel, set()).update(xs)
    return out


def project_files(root: Path) -> list[tuple[str, str]]:
    """(path relative to root, full path) of src/**/*.c, src/**/*.h and include/**/*.h, in the scan's order."""
    files = []
    for d, pats in (("src", ("*.c", "*.h")), ("include", ("*.h",))):
        base = root / d
        if base.exists():
            files += sorted({(d + "/" + r, p) for r, p in fsmemo.walk(base, pats)}, key=lambda t: t[0].lower())
    return files


def scan(root: Path, tree_hash: str | None = None) -> Scan:
    """Scan src/**/*.c, src/**/*.h and include/**/*.h of the project at root (memoised per tree hash), every
    file as each target's compile sees it (models per target; L16). Each file's own scan is kept while its text
    and its models are the same (the models() objects: a model stands while its parse does), so an edit scans
    only the files it changed."""
    root = Path(root)
    if tree_hash is not None and (str(root), tree_hash) in _cache:
        return _cache[(str(root), tree_hash)]
    out = Scan()
    used = {}
    files = project_files(root)
    targets = target_defines(root)
    default = targets[0][0]
    from .. import timing
    with timing.phase("scan.models"):
        per_target = {t: models(root, files, d) for t, d in targets}
    ms = out.models = per_target[default]
    for rel, p in files:
        m = ms.get(rel, EMPTY)
        views = {t: per_target[t].get(rel, EMPTY) for t, _ in targets} if default is not None else None
        held = [m, *(views or {}).values()]
        key = (str(root), rel, fsmemo.sha256(p))
        hit = _files.get(key)
        if hit is not None and len(hit[0]) == len(held) and all(a is b for a, b in zip(hit[0], held)):
            piece = hit[1]
        else:
            piece = Scan()
            with timing.phase("scan.file"):
                scan_file(rel, fsmemo.read_text(p), piece, m, views)
        used[key] = (held, piece)
        out.files += 1
        out.functions += piece.functions
        out.data += piece.data
        out.placeholders += piece.placeholders
        out.errors += piece.errors
        out.macros += piece.macros
        out.described += piece.described
        out.ptrcasts += piece.ptrcasts
        out.views += piece.views
        out.rawobj += piece.rawobj
        out.native += piece.native
    for k in [k for k in _files if k[0] == str(root)]:
        del _files[k]
    _files.update(used)
    if default is not None:
        out.own_errors = guards(out.functions, [t for t, _ in targets])
        out.errors += out.own_errors
    if tree_hash is not None:
        if len(_cache) > 2:                       # a long-lived process (dcp serve) sees a new tree per edit
            _cache.clear()
        _cache[(str(root), tree_hash)] = out
    return out


def guards(functions: list[Function], targets: list[str]) -> list[ScanError]:
    """L16: a function compiled into a target its address comment does not list, or listed for a target whose
    compile does not hold it (its `#if` on the DCP_TARGET_<name> macros)."""
    out = []
    for f in functions:
        if f.unlinked or not f.targets or any(t is not None and t not in targets for t, _ in f.addrs):
            continue                                       # (an unknown target prefix is L.src's error)
        listed = [t for t in targets if address_for(f.addrs, t, targets[0]) is not None]
        extra = [t for t in f.targets if t not in listed]
        missing = [t for t in listed if t not in f.targets]
        if extra:
            out.append(ScanError(f.file, f.line, "L16", f"{f.name} is compiled into {', '.join(extra)}, its address comment "
                                                        f"lists no address there (guard it: #if on "
                                                        f"{', '.join(map(target_macro, listed))})"))
        if missing:
            out.append(ScanError(f.file, f.line, "L16", f"{f.name}: its address comment lists {', '.join(missing)}, whose "
                                                        f"compile does not hold it (its #if)"))
    return out


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


def native_view(sc: Scan) -> str:
    """The scan as the native rules read it (L.src, L5, A1, L13, G.grade in native/dcp_core/src), as JSON text: its
    files' pieces in the core by id (they hold every item the rules read: native/dcp_core/src/srcscan.rs Piece),
    the errors of the whole scan (L16). The scan holds its pieces, so they stand while it does."""
    import json
    return json.dumps({"pieces": [x.id for x in sc.native],
                       "errors": [(e.check, e.file, e.line, e.message) for e in sc.own_errors]}, separators=(",", ":"))


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
