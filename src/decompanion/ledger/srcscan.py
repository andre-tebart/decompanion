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

Two layers (docs/plan.md section 18). The comments (the address comments, the tags, the descriptions) are read
per file by a lexer of comments and strings (TOKEN). The function definitions and the file-scope data
declarations come from the front end (source/cparse.py, libclang) over each unit file as a target's compile sees
it (models: its DCP_TARGET_<name> defined); a header as the first unit that includes it sees it, a file no unit
holds parsed alone. So `#if` / `#ifdef` are evaluated (a declaration in a dead branch is no declaration), a macro
is expanded (zlib's `local` is `static`), and every declarator of `int a = 1, b = 2;` is one. The default
target's view gives everything; another target's adds the function definitions only it holds (L16 compares
the targets a function is live in with those its comment lists). A data statement's address comment is found by
its extent (on its first line, after its `;`, or the own-line comment above). A text that is no project file (a
test's, a single line) is parsed alone (model_alone).
"""
from __future__ import annotations

import bisect
import functools
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from .. import fsmemo

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
DEFINE = re.compile(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)\(([^)]*)\)[ \t]*((?:\\\n|[^\n])*)", re.M)
OBJ_DEFINE = re.compile(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)(?![\w(])[ \t]*([^\n]*)", re.M)
DEREF_OBJ = re.compile(r"\(\s*\*\s*\(\s*[A-Za-z_]")      # an object-like macro body that dereferences a cast: (*(T ...
_NUM = r"(0[xX][0-9a-fA-F]+|\d+)[uUlL]*"
_TYPEP = r"[^()]*(?:\([^()]*\)[^()]*)*"
VIEW_BYTE = re.compile(r"\(\s*\*\s*\(" + _TYPEP + r"\)\s*\(\s*\(\s*(?:unsigned\s+|signed\s+)?char\s*\*\s*\)\s*(&\s*)?([A-Za-z_]\w*)\s*\+\s*"
                       + _NUM + r"\s*\)\s*\)")
VIEW_WHOLE = re.compile(r"\(\s*\*\s*\(" + _TYPEP + r"\)\s*&\s*([A-Za-z_]\w*)\s*\)")
VIEW_ALIAS = re.compile(r"([A-Za-z_]\w*)")
DESCRIBED = re.compile(r"\s*(?:[A-Za-z][A-Za-z0-9_-]*:)?(0x[0-9a-fA-F]+)\b\s*(.*)", re.S)
# A1: an integer literal cast to a pointer type. The cast's type names a pointer explicitly: a declarator with
# `*` (`(char *)`, `(struct x **)`, `(void (__cdecl *)(int))`); a typedef'd pointer name (`(LPVOID)`) is not
# recognised (the scan has no types). Between the cast and the literal only parentheses and casts to a type
# without `*` may stand (`(char *)(unsigned)0x5de470`, `(void (*)(void))(0x5de470)`).
_TYPE = r"(?:(?:const|volatile|unsigned|signed|struct|union|enum)\s+)*[A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*"
_CC = r"(?:__cdecl|__stdcall|__fastcall|WINAPI|CALLBACK|APIENTRY|PASCAL)"
PTR_CAST = re.compile(
    r"\(\s*" + _TYPE + r"\s*(?:"
    r"(?:\*\s*(?:(?:const|volatile)\b\s*)?)+"                                    # (T *), (T * const *)
    r"|\**\s*\(\s*" + _CC + r"?\s*\*+\s*\)\s*\([^()]*\)\s*"                      # (T (cc *)(params))
    r")\)"
    r"((?:\s*\((?:\s*" + _TYPE + r"\s*\))?)*\s*)"                               # parentheses, casts without `*`
    r"(?<![\w.])(0[xX][0-9a-fA-F]+|\d+)[uUlL]*(?![\w.])")


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
    """An integer literal cast to a pointer type (PTR_CAST; check A1 in rules/layout.py)."""
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
    _native: str | None = field(default=None, repr=False, compare=False)  # native_view's text


def lead_addrs(body: str) -> list[tuple[str | None, int]]:
    """The addresses a comment starts with: `0x10001000` / `server:0x10001000, exe:0x4a3000, what`."""
    m = LEAD_ADDRS.match(body)
    if not m:
        return []
    return [(t or None, int(a, 16)) for t, a in ONE_ADDR.findall(m.group(0))]


def lead_end(body: str) -> int:
    m = LEAD_ADDRS.match(body)
    return m.end() if m else 0


class Source:
    """One .c / .h file: its comments, its code with strings and comments blanked, its definitions and data."""

    def __init__(self, rel: str, text: str):
        self.rel = rel
        self.text = text
        self._line_starts = None
        self._own_line_ends = None
        self._cstarts = None
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

    def _attach(self, code: str, s: int, i: int, n: int, skip: frozenset):
        """The address comment of the statement at s..i (i just after its `;`) split over its n declarators, and
        whether it says `unlinked`: a comment on the statement's first line or right after its `;`, else the
        own-line comment directly above it (never a comment of `skip`: the functions' address comments)."""
        if self._cstarts is None:
            self._cstarts = [c[0] for c in self.comments]
        cstarts = self._cstarts
        addrs: list = []
        unlinked = False
        eol = code.find("\n", s)
        after = i
        while after < len(self.text) and self.text[after] in " \t":
            after += 1
        for ci in range(bisect.bisect_left(cstarts, s), len(cstarts)):
            cs = cstarts[ci]
            on_first_line = cs < eol if eol >= 0 else True
            if not (on_first_line or i <= cs <= after):
                if cs > after:
                    break
                continue
            if ci in skip:
                continue
            if cs >= i and ";" in code[i:cs]:
                continue                          # behind a later statement of this line: that one's comment
            addrs = lead_addrs(self.comments[ci][2])
            unlinked = unlinked or bool(UNLINKED.match(self.comments[ci][2]))
            if addrs:
                break
        if not addrs:
            ends = self.own_line_comment_ends()
            e = self.end_before(s)
            if e in ends and ends[e] not in skip:
                addrs = lead_addrs(self.comments[ends[e]][2])
                unlinked = unlinked or bool(UNLINKED.match(self.comments[ends[e]][2]))
        return assign(addrs, n), unlinked

    def model_definitions(self, defs: list) -> list[tuple[int, str, bool]]:
        """[(offset, name, static)] of the front end's function definitions of this file (cparse.model)."""
        return [(self.offset(line, col), name, static) for line, col, name, static in defs]

    def model_data(self, decls: list, skip: frozenset = frozenset()) -> list[tuple]:
        """[(offset, name, kind, [(target, addr)], unlinked, static)] of the front end's file-scope data
        declarators of this file (cparse.model), each statement's address comment found as data() finds it."""
        code = self.code
        stmts: dict[tuple, list] = {}
        for d in decls:
            stmts.setdefault((d[0], d[1]), []).append(d)
        res = []
        for (line, col), ds in stmts.items():
            s = self.offset(line, col)
            e = max(self.offset(d[2], d[3]) for d in ds)
            j = e
            while j < len(code) and code[j].isspace():
                j += 1
            i = j + 1 if j < len(code) and code[j] == ";" else e
            per_decl, unlinked = self._attach(code, s, i, len(ds), skip)
            for k, d in enumerate(ds):
                res.append((s, d[4], d[5], per_decl[k], unlinked, d[6]))
        return res


def assign(addrs: list, n: int) -> list[tuple]:
    """Split a comment's addresses over n declarators: per target, either one address per declarator or (one
    declarator) all of them. A list that fits neither gives every declarator nothing."""
    if n == 1:
        return [tuple(addrs)]
    by_t: dict = {}
    for t, a in addrs:
        by_t.setdefault(t, []).append(a)
    if any(len(v) != n for v in by_t.values()):
        return [()] * n
    return [tuple((t, v[j]) for t, v in by_t.items()) for j in range(n)]


def unit_of(rel: str) -> str:
    """The unit of a source file: src/<unit>.c (a header: its stem)."""
    return Path(rel).stem


DEFINE_LINE = re.compile(r"^[ \t]*#[ \t]*define\b(?:\\\n|[^\n])*", re.M)


def literal_value(s: str) -> int | None:
    """The value of a C integer literal's digits (hex, octal with a leading 0, decimal); None when malformed."""
    try:
        return int(s, 16) if s[:2] in ("0x", "0X") else int(s, 8) if len(s) > 1 and s[0] == "0" else int(s, 10)
    except ValueError:
        return None


def ptr_casts(S: Source, out: Scan, model: dict):
    """Every integer literal cast to a pointer type in the code (the front end's: model["casts"], any pointer
    type, a typedef'd one too) and in the bodies of the live macros (PTR_CAST over a body: a macro has no syntax
    tree until it is used)."""
    def add(code, base=0):
        for m in PTR_CAST.finditer(code):
            v = literal_value(m.group(2))
            if v is not None:
                text = " ".join(m.group(0).split())
                text += ")" * (text.count("(") - text.count(")"))       # close what the match left open
                out.ptrcasts.append(PtrCast(S.rel, S.line_of(base + m.start()), text, v))
    for line, col, eline, ecol, lit in model["casts"]:
        v = literal_value(lit.rstrip("uUlL"))
        if v is not None:
            text = " ".join(S.text[S.offset(line, col):S.offset(eline, ecol)].split())
            out.ptrcasts.append(PtrCast(S.rel, line, text + ")" * (text.count("(") - text.count(")")), v))
    for m in live_defines(S, model, DEFINE_LINE):
        add(m.group(0), m.start())


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


def live_defines(S: Source, model: dict, pattern: re.Pattern, text: str | None = None, like: bool | None = None):
    """The matches of a `#define` pattern at the lines of the macros the preprocessor defined (model["macros"]),
    of the function-like ones or the object-like ones only when `like` says so."""
    text = S.code if text is None else text
    for line, name, flike in model["macros"]:
        if like is None or flike == like:
            m = pattern.match(text, S.offset(line, 1))
            if m is not None:
                yield m


def view_macros(S: Source, unit: str, out: Scan, model: dict):
    """The object-like one-line macros: a view (VIEW_BYTE / VIEW_WHOLE / VIEW_ALIAS with an address comment on
    its line) goes to out.views; one whose body dereferences a cast (DEREF_OBJ) and is no view to out.rawobj,
    and to out.errors (L15) when it has an address comment all the same. The live object-like macros of the
    front end's model only."""
    for m in live_defines(S, model, OBJ_DEFINE, like=False):
        name, body = m.group(1), m.group(2).strip()
        if not body or body.endswith("\\"):
            continue
        eol = S.text.find("\n", m.start())
        eol = len(S.text) if eol < 0 else eol
        addrs = next((lead_addrs(b) for s, e, b in S.comments if m.start() <= s < eol and lead_addrs(b)), [])
        line = S.line_of(m.start())
        v = VIEW_BYTE.fullmatch(body)
        if v:
            container, offset, alias = v.group(2), literal_value(v.group(3)), False
        elif (v := VIEW_WHOLE.fullmatch(body)) is not None:
            container, offset, alias = v.group(1), 0, False
        elif (v := VIEW_ALIAS.fullmatch(body)) is not None:
            container, offset, alias = v.group(1), 0, True
        else:
            container = None
        if container is not None and addrs and offset is not None:
            out.views.append(View(S.rel, line, unit, name, container, offset, tuple(addrs), alias))
        elif DEREF_OBJ.search(body):
            out.rawobj.append(name)
            if addrs:
                out.errors.append(ScanError(S.rel, line, "L15", f"{name} has an address comment but is no view: write it "
                                                                 f"(*(T *)((char *)&CONTAINER + OFFSET)) with a byte offset"))


def scan_file(rel: str, text: str, out: Scan, model: dict | None = None, views: dict | None = None):
    """One file's part of the scan: its comments read here, its function definitions, data declarations,
    macros and casts from the front end's model of the file (cparse.model's entry; the text parsed alone when
    none is given: model_alone). views: target -> that target's model of the file (model is the default
    target's): a function's `targets` are the views that hold its definition, and a definition only another
    target's view holds (under its `#if`) is a function too."""
    S = Source(rel, text)
    model = model_alone(rel, text) if model is None else model
    for m in live_defines(S, model, DEFINE, S.text, like=True):
        out.macros.append((m.group(1), m.group(3)))
    for s, e, body in S.comments:
        m = DESCRIBED.match(body)
        if m:
            rest = re.split(r"@(?:deep|stuck|rough)\b", m.group(2))[0]
            rest = re.sub(r"^(?:\s*[,/]\s*(?:[A-Za-z][A-Za-z0-9_-]*:)?0x[0-9a-fA-F]+)*", "", rest)
            if rest.strip(" \t\r\n,.-:;*/"):
                out.described.extend(a for _, a in lead_addrs(body))
    unit = unit_of(rel)
    in_src = rel.startswith("src/")
    is_unit = in_src and rel.endswith(".c") and "/" not in rel[4:]
    if in_src and rel.endswith(".c") and not is_unit:
        out.errors.append(ScanError(rel, 1, "L.src", f"unexpected source file {rel}: a unit is one file, src/<unit>.c"))
    # the definitions of every target's view of the file, with the targets that hold each
    defs: dict[tuple, list] = {}
    for t, m in (views or {None: model}).items():
        ends = {tuple(d[3]): d[5] for d in m["decls"] if d[0] == "f" and d[6] is not None}
        for line, col, fname, fstatic in m["defs"]:
            e = defs.setdefault((line, col), [fname, fstatic, ends.get((line, col)), []])
            if t is not None:
                e[3].append(t)
    own = S.own_line_comment_ends()
    skip = set()
    for (line, col), (fname, fstatic, end, ts) in sorted(defs.items()):
        if not is_unit:
            out.errors.append(ScanError(rel, line, "L.src", f"function {fname} defined outside a unit file (src/<unit>.c)"))
            continue
        k = own.get(S.end_before(S.offset(line, col)))
        body = S.comments[k][2] if k is not None else ""
        addrs, um = lead_addrs(body), UNLINKED.match(body)
        if not addrs and not um:
            out.errors.append(ScanError(rel, line, "L.src", f"function {fname}: no address comment (`/* 0x..., what */`, "
                                                            f"`/* unlinked, why */`) directly above its definition"))
            continue
        skip.add(k)
        what = (um.group(1) if um else body[lead_end(body):]).strip().lstrip(",").strip()
        what = re.sub(r"\s+", " ", re.split(r"@(?:deep|stuck|rough)\b", what)[0]).strip()
        dm, sm = DEEP.search(body), STUCK.search(body)
        out.functions.append(Function(rel, line, unit, fname, tuple(addrs), bool(um) and not addrs, what,
                                      dm.group(1).strip() if dm else None, sm.group(1).strip() if sm else None,
                                      bool(ROUGH.search(body)), comment_line=S.line_of(S.comments[k][0]), static=fstatic,
                                      end_line=end[0] if end else 0, targets=tuple(ts)))
    for off, dname, kind, addrs, unlinked, static in S.model_data(model["vars"], frozenset(skip)):
        out.data.append(Data(rel, S.line_of(off), unit, dname, kind, addrs, unlinked, static))
    ptr_casts(S, out, model)
    view_macros(S, unit, out, model)
    seen = set()
    for m in PLACEHOLDER_ADDR.finditer(S.code):
        ident = m.group(0)
        if ident in seen:
            continue
        seen.add(ident)
        out.placeholders.append(Placeholder(rel, S.line_of(m.start()), ident, placeholder_value(m)))


_cache: dict[tuple[str, str], Scan] = {}
_files: dict[tuple[str, str, str], Scan] = {}     # (path, sha256 of the text, model digest) -> that file's own scan
CACHE_VERSION = 10                                # bump when scan_file's results change
MODEL_VERSION = "16"                               # bump when the scan's translation units change
_models: dict[str, tuple] = {}                    # model key -> ([(dependency, sha256)], files)
_last_deps: dict[str, list[str]] = {}             # translation unit path -> what its last parse read
EMPTY = {"defs": [], "vars": [], "macros": [], "casts": [], "decls": [], "types": [], "dead": []}
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


def _file_cache(root: Path) -> tuple[Path | None, dict]:
    """The on-disk memo of per-file scans (build/cache/srcscan.pickle), {} when absent or of another version."""
    import pickle
    d = root / "build"
    if not d.is_dir():
        return None, {}
    path = d / "cache" / "srcscan.pickle"
    try:
        version, data = pickle.loads(path.read_bytes())
        return path, data if version == CACHE_VERSION else {}
    except (OSError, ValueError, EOFError, pickle.UnpicklingError, TypeError, AttributeError, ImportError):   # another version's classes
        return path, {}


_disk_done: set[str] = set()                      # roots whose on-disk memo this process read (and wrote)


def scan(root: Path, tree_hash: str | None = None) -> Scan:
    """Scan src/**/*.c, src/**/*.h and include/**/*.h of the project at root (memoised per tree hash), every
    file as each target's compile sees it (models per target; L16). Each file's own scan is memoised by its
    path, the hash of its text and of its models in the process, so an edit re-parses only the files it changed;
    a process's first scan of a root also reads and writes them in build/cache/srcscan.pickle (a later edit of
    a long-lived process, dcp serve, leaves the file alone: the next process rescans the few files changed)."""
    import hashlib
    import pickle
    root = Path(root)
    if tree_hash is not None and (str(root), tree_hash) in _cache:
        return _cache[(str(root), tree_hash)]
    out = Scan()
    path, disk = None, None                  # the on-disk memo, read on the first file this process has not scanned
    used, changed = {}, False
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
        key = (rel, fsmemo.sha256(p), hashlib.sha256(repr(views or m).encode()).hexdigest())
        piece = _files.get(key)
        if piece is None and str(root) not in _disk_done:
            if disk is None:
                path, disk = _file_cache(root)
            piece = disk.get(key)
        if piece is None:
            piece = Scan()
            with timing.phase("scan.file"):
                scan_file(rel, fsmemo.read_text(p), piece, m, views)
            changed = True
        _files[key] = used[key] = piece
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
    if disk is not None:
        _disk_done.add(str(root))
    if path is not None and (changed or len(used) != len(disk)):      # (nothing new to this process: no write)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(pickle.dumps((CACHE_VERSION, used)))
            tmp.replace(path)
        except OSError:
            pass
    if default is not None:
        out.errors += guards(out.functions, [t for t, _ in targets])
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
    """The items of a scan the native rules read (L5, A1, L13 in native/dcp_core/src/layout.rs), as JSON text:
    functions with addresses (file, comment line, end line, addrs), placeholders and pointer casts (file, line,
    text, value as hex: a placeholder may spell more digits than an integer type holds), data declarations
    (file, line, kind, name, addrs); every function, datum, view and error as L.src reads them; the function definitions of the front end's models (file -> name -> start
    line, column, end line, column: G.grade's readability, the last definition with a body). Made once per scan (a
    scan is made once per tree)."""
    if sc._native is None:
        import json
        sc._native = json.dumps({
            "functions": [(f.file, f.comment_line, f.end_line, f.addrs) for f in sc.functions if f.addrs],
            "placeholders": [(p.file, p.line, p.ident, format(p.value, "x")) for p in sc.placeholders],
            "ptrcasts": [(c.file, c.line, c.text, format(c.value, "x")) for c in sc.ptrcasts],
            "data": [(d.file, d.line, d.kind, d.name, d.addrs) for d in sc.data],
            "defs": {rel: {d[1]: (*d[3], *(d[5] or (None, None))) for d in m["decls"] if d[0] == "f" and d[6] is not None}
                     for rel, m in sc.models.items()},
            "fns": [(f.file, f.line, f.comment_line, f.end_line, f.unit, f.name, f.static, f.addrs, f.deep, f.stuck, f.rough, f.what)
                    for f in sc.functions],
            "datas": [(d.file, d.line, d.unit, d.name, d.kind, d.static, d.addrs) for d in sc.data],
            "views": [(v.file, v.line, v.unit, v.name, v.container, v.offset, v.alias, v.addrs) for v in sc.views],
            "errors": [(e.check, e.file, e.line, e.message) for e in sc.errors]}, separators=(",", ":"))
    return sc._native


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
