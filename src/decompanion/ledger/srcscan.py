"""The source scan: the sources are typed state, and this module reads it (a port of the address-comment parser
of the first attempt, rea/tools/gildegold/core/gen.py). No object file is needed: it reads text.

Layout of a target project's sources
  src/<unit>/head.c        includes, local types, prototypes, leading file-scope data; no function
  src/<unit>/f_<addr>.c    one function, plus the file-scope definitions that precede it in TU order
  src/<unit>/u_<name>.c    one function the binary does not contain (`/* unlinked, why */`)
  src/<unit>/order         optional: the unit's translation-unit order when it is not the address order (CL
                           compiles a caller differently once a callee is defined above it, and a declaration
                           must precede its use): `#` reason lines first, then every fragment file of the
                           unit (f_<addr>.c and u_<name>.c), one per line, in TU order (check L12)
  include/<unit>.h         public prototypes and extern declarations
  `__inline` helpers       not functions of the binary (no symbol, no address): head.c, any fragment or a
                           header may define them where the TU needs them; the scan does not count them

Address comments
  function   the FIRST line of its fragment:  /* 0x10001000, what it does */
             several targets:                  /* server:0x10001000, exe:0x4a3000, what it does */
             (a bare address is the default target's; the file name carries the first address listed)
             not in the binary:                /* unlinked, why */
             tags inside it:                   @deep why   @stuck why   @rough
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
per file by a lexer of comments and strings (TOKEN): the amalgamations are made of what they say, so they come
before any parse. The function definitions and the file-scope data declarations come from the front end
(source/cparse.py, libclang) over one translation unit per unit (models): head.c, the fragments of every target,
tail.c; a header as the first unit that includes it sees it, a file no unit holds parsed alone. So `#if` /
`#ifdef` are evaluated (a declaration in a dead branch is no declaration), a macro is expanded (zlib's `local` is
`static`), and every declarator of `int a = 1, b = 2;` is one. A data statement's address comment is found by
its extent as before (on its first line, after its `;`, or the own-line comment above). A text that is no
project file (a test's, a single line) is parsed alone (model_alone).
"""
from __future__ import annotations

import bisect
import functools
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
FRAGMENT = re.compile(r"^f_([0-9a-fA-F]+)\.c$")
UNLINKED_FRAGMENT = re.compile(r"^u_([A-Za-z_]\w*)\.c$")
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
    check: str                # L.src | L11 | L12 | L15
    message: str


@dataclass
class Scan:
    functions: list[Function] = field(default_factory=list)
    data: list[Data] = field(default_factory=list)
    placeholders: list[Placeholder] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)
    files: int = 0
    orders: dict[str, list[str]] = field(default_factory=dict)   # unit -> fragment file names in TU order
    macros: list[tuple[str, str]] = field(default_factory=list)  # (name, body) of every function-like #define
    described: list[int] = field(default_factory=list)          # addresses an address comment describes in words
    ptrcasts: list[PtrCast] = field(default_factory=list)       # integer literals cast to a pointer type (A1)
    views: list[View] = field(default_factory=list)             # view macros (L15)
    rawobj: list[str] = field(default_factory=list)             # object-like macros dereferencing a cast, no view (Q4)
    models: dict = field(default_factory=dict)                  # file -> its front end model (cparse.model's entry)


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

    def _attach(self, code: str, s: int, i: int, n: int, skip_comment: int | None):
        """The address comment of the statement at s..i (i just after its `;`) split over its n declarators, and
        whether it says `unlinked`: a comment on the statement's first line or right after its `;`, else the
        own-line comment directly above it (never comment `skip_comment`)."""
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
            if ci == skip_comment:
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
            if e in ends and ends[e] != skip_comment:
                addrs = lead_addrs(self.comments[ends[e]][2])
                unlinked = unlinked or bool(UNLINKED.match(self.comments[ends[e]][2]))
        return assign(addrs, n), unlinked

    def model_definitions(self, defs: list) -> list[tuple[int, str, bool]]:
        """[(offset, name, static)] of the front end's function definitions of this file (cparse.model)."""
        return [(self.offset(line, col), name, static) for line, col, name, static in defs]

    def model_data(self, decls: list, skip_comment: int | None = None) -> list[tuple]:
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
            per_decl, unlinked = self._attach(code, s, i, len(ds), skip_comment)
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
    parts = rel.split("/")
    if parts[0] == "src" and len(parts) >= 3:
        return parts[1]
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


def scan_file(rel: str, text: str, out: Scan, model: dict | None = None):
    """One file's part of the scan: its comments read here, its function definitions, data declarations,
    macros and casts from the front end's model of the file (cparse.model's entry; the text parsed alone when
    none is given: model_alone)."""
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
    name = Path(rel).name
    unit = unit_of(rel)
    in_src = rel.startswith("src/")
    is_fragment = in_src and bool(FRAGMENT.match(name) or UNLINKED_FRAGMENT.match(name))
    defs = S.model_definitions(model["defs"])
    skip = None
    if in_src and rel.endswith(".c") and not is_fragment and name not in ("head.c", "tail.c"):
        out.errors.append(ScanError(rel, 1, "L.src", f"unexpected source file {name}: a unit holds head.c, f_<addr>.c "
                                                     f"and u_<name>.c fragments, and tail.c"))
    if is_fragment:
        if len(defs) != 1:
            out.errors.append(ScanError(rel, 1, "L.src", f"a fragment defines exactly one function, this one {len(defs)}"))
        for line, fname, efile, eline in model.get("spills", []):
            out.errors.append(ScanError(rel, line, "L.src", f"the body of {fname} ends in {efile}:{eline}: a fragment holds "
                                                            f"its whole function (move the rest of the body here)"))
        first = S.comments[0] if S.comments else None
        if first is None or first[0] != 0 and text[:first[0]].strip():
            out.errors.append(ScanError(rel, 1, "L.src", "the first line is not the function's address comment"))
            first = None
        elif S.line_of(first[0]) != 1:
            out.errors.append(ScanError(rel, S.line_of(first[0]), "L.src", "the address comment is not on the first line"))
            first = None
        if first is not None and defs:
            skip = 0
            body = first[2]
            addrs = lead_addrs(body)
            um = UNLINKED.match(body)
            off, fname, fstatic = defs[-1]
            what = (um.group(1) if um else body[lead_end(body):]).strip().lstrip(",").strip()
            what = re.sub(r"\s+", " ", re.split(r"@(?:deep|stuck|rough)\b", what)[0]).strip()
            dm, sm = DEEP.search(body), STUCK.search(body)
            fm, um_name = FRAGMENT.match(name), UNLINKED_FRAGMENT.match(name)
            if not addrs and not um:
                out.errors.append(ScanError(rel, 1, "L.src", "the first comment holds neither an address nor `unlinked`"))
            elif addrs and fm and int(fm.group(1), 16) != addrs[0][1]:
                out.errors.append(ScanError(rel, 1, "L11", f"the file name says {int(fm.group(1), 16):#x}, the address comment "
                                                           f"{addrs[0][1]:#x}"))
            elif addrs and um_name:
                out.errors.append(ScanError(rel, 1, "L11", "an u_<name>.c fragment holds an unlinked function; this one has an address"))
            elif um and fm:
                out.errors.append(ScanError(rel, 1, "L11", "an unlinked function lives in u_<name>.c, not f_<addr>.c"))
            elif um and um_name and um_name.group(1) != fname:
                out.errors.append(ScanError(rel, 1, "L11", f"the file name says {um_name.group(1)}, the definition {fname}"))
            ends = [d[5] for d in model["decls"] if d[0] == "f" and d[1] == fname and d[6] is not None and d[5]]
            out.functions.append(Function(rel, S.line_of(off), unit, fname, tuple(addrs), bool(um) and not addrs, what,
                                          dm.group(1).strip() if dm else None, sm.group(1).strip() if sm else None,
                                          bool(ROUGH.search(body)), static=fstatic, end_line=ends[-1][0] if ends else 0))
    elif defs:
        for off, fname, _ in defs:
            out.errors.append(ScanError(rel, S.line_of(off), "L.src", f"function {fname} defined outside a fragment "
                                                                       f"(src/<unit>/f_<addr>.c)"))
    for off, dname, kind, addrs, unlinked, static in S.model_data(model["vars"], skip):
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
CACHE_VERSION = 9                                 # bump when scan_file's results change
MODEL_VERSION = "15"                               # bump when the scan's translation units change
_models: dict[str, tuple] = {}                    # model key -> ([(dependency, sha256)], files)
_last_deps: dict[str, list[str]] = {}             # translation unit path -> what its last parse read
EMPTY = {"defs": [], "vars": [], "macros": [], "casts": [], "decls": [], "types": [], "dead": [], "spills": []}


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


def models(root: Path, files: list[tuple[str, str]]) -> dict[str, dict]:
    """rel -> the front end's model of that file (cparse.model: defs, vars). Each unit is one translation unit of
    every target's fragments (the scan reads all targets): head.c, the fragments in address order (the file
    name's) or the unit's order file's, the unlinked ones by name, tail.c, each behind `#line 1 "<path>"` as in
    the amalgamation. A file takes the model of the first unit (by name) that holds it, a header too (as that
    unit's preprocessor sees it); a file no unit holds (a header no unit includes, a stray .c) is parsed alone.
    Each parse is kept by its text, arguments and libclang (build/cache/cparse/) as long as every file it read
    is unchanged."""
    from ..ledger.fact import canonical
    from ..ledger.store import sha256
    from ..source import cparse
    sysdirs = front_end(root)
    vc = cparse.version()

    def tu(path: Path, members: list[str], incdirs: list[Path], composed: bool):
        """(key, path, members, incdirs, composed): keyed by the members' content hashes (no file is read for a
        kept model); composed: the members go behind `#line 1 "<path>"` (a unit), else path alone is parsed."""
        key = sha256("srcscan.model", MODEL_VERSION, cparse.VERSION, vc, canonical(cparse.args(sysdirs, incdirs)),
                     str(path), *(f"{r}={fsmemo.sha256(root / r)}" for r in members))
        return key, path, members, incdirs, composed

    def live(path) -> str:
        try:
            return sha256("srcscan.live", *(f"{d}={fsmemo.sha256(d)}" for d in _last_deps.get(str(path), [])))
        except OSError:
            return "gone"

    def job(path, members, incdirs, composed, keep):
        if not composed:
            return path, root, sysdirs, incdirs, fsmemo.read_text(path), [], keep
        return path, root, sysdirs, incdirs, *compose_unit(root, members), keep

    def run(tus) -> list[dict]:
        got, misses = {}, []
        for key, *rest in tus:
            hit = _model_hit(root, key)
            if hit is None:
                misses.append((key, rest))
            else:
                got[key] = hit
                _last_deps[str(rest[0])] = [d for d, _ in _models[key][0]]
        # a lone miss (the unit an edit changed) is parsed in process and stays live: the next edit reparses it
        # while every file its last parse read is unchanged (keep: their hashes)
        jobs = [job(*rest, live(rest[0]) if len(misses) == 1 else None) for _, rest in misses]
        for (key, rest), m in zip(misses, cparse.many(jobs, fn="model")):
            _model_keep(root, key, m)
            _last_deps[str(rest[0])] = m["deps"]
            got[key] = m["files"]
        return [got[t[0]] for t in tus]

    tus = [tu(unit_path(root, unit), members, unit_incdirs(root, unit), True)
           for unit, members in unit_members(root, files)]
    out: dict[str, dict] = {}
    for files_ in run(tus):
        for rel, m in files_.items():
            out.setdefault(rel, m)
    alone = [(rel, p) for rel, p in files if rel not in out]
    tus = [tu(Path(p), [rel], ([root / "src" / rel.split("/")[1]] if rel.startswith("src/") else [])
              + [root / "include"], False) for rel, p in alone]
    for (rel, _), files_ in zip(alone, run(tus)):
        out[rel] = files_.get(rel, EMPTY)
    return out


def unit_members(root: Path, files: list[tuple[str, str]]) -> list[tuple[str, list[str]]]:
    """(unit, its files in the scan's translation unit order) per unit, by name: head.c, the fragments of every
    target in address order (the file name's) or the unit's order file's, the unlinked ones by name, tail.c."""
    by_unit: dict[str, dict[str, str]] = {}
    for rel, _ in files:
        parts = rel.split("/")
        if parts[0] == "src" and len(parts) == 3:
            by_unit.setdefault(parts[1], {})[parts[2]] = rel
    out = []
    for unit in sorted(by_unit):
        names = by_unit[unit]
        addressed = [(int(fm.group(1), 16), r) for n, r in names.items() if (fm := FRAGMENT.match(n))]
        frags = [r for _, r in sorted(addressed)]
        frags += sorted(r for n, r in names.items() if UNLINKED_FRAGMENT.match(n))
        op = root / "src" / unit / "order"
        if op.exists():
            listed = [ln.strip() for ln in fsmemo.read_text(op).split("\n") if ln.strip() and not ln.strip().startswith("#")]
            pos = {f"src/{unit}/{n}": k for k, n in enumerate(listed)}
            frags = sorted(frags, key=lambda r: pos.get(r, len(pos)))
        out.append((unit, [names[n] for n in ("head.c",) if n in names] + frags
                    + [names[n] for n in ("tail.c",) if n in names]))
    return out


def local_refs(root: Path, names: list[str]) -> dict[str, set[tuple[int, int]]]:
    """rel -> {(line, col)} of the occurrences of `names` the front end finds referring to a declaration not at
    file scope (cparse.refs: a local, a parameter, a field, a label), over every unit whose files or headers
    hold one of the names: what a rename of a file-scope symbol leaves alone."""
    from ..source import cparse
    root = Path(root)
    files = project_files(root)
    sysdirs = front_end(root)
    models(root, files)                                   # every unit's dependencies (_last_deps)
    pat = re.compile(r"\b(?:" + "|".join(map(re.escape, names)) + r")\b")
    holds = {}
    rootr = root.resolve()

    def held(p) -> bool:
        if p not in holds:
            try:
                holds[p] = bool(pat.search(fsmemo.read_text(p)))
            except OSError:
                holds[p] = False
        return holds[p]

    jobs = []
    for unit, members in unit_members(root, files):
        path = unit_path(root, unit)
        deps = [d for d in _last_deps.get(str(path), []) if Path(d).resolve().is_relative_to(rootr)]
        if any(held(str(root / r)) for r in members) or any(held(d) for d in deps):
            jobs.append((path, root, sysdirs, unit_incdirs(root, unit), *compose_unit(root, members), list(names), None))
    out: dict[str, set] = {}
    for r in cparse.many(jobs, fn="refs"):
        for rel, xs in r.items():
            out.setdefault(rel, set()).update(xs)
    return out


def unit_path(root: Path, unit: str) -> Path:
    """Where the scan's translation unit of a unit stands (never written: its text is handed to the parser)."""
    return root / "build" / "cache" / "cparse" / f"{unit}.c"


def unit_incdirs(root: Path, unit: str) -> list[Path]:
    return [root / "src" / unit, root / "include"]


def compose_unit(root: Path, members: list[str]) -> tuple[str, list[tuple[int, str]]]:
    """(text, parts) of a unit's translation unit: each member behind `#line 1 "<path>"`; parts: (the physical
    line of that directive, the path), what cparse.model maps by (a `#line` pin inside a part maps nothing)."""
    text, parts, n = "", [], 1
    for r in members:
        t = fsmemo.read_text(root / r)
        t += "\n" if t and not t.endswith("\n") else ""
        parts.append((n, r))
        text += f'#line 1 "{r}"\n' + t
        n += 1 + t.count("\n")
    return text, parts


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


def scan(root: Path, tree_hash: str | None = None) -> Scan:
    """Scan src/**/*.c, src/**/*.h and include/**/*.h of the project at root (memoised per tree hash). Each
    file's own scan is memoised by its path and the hash of its text, in the process and in
    build/cache/srcscan.pickle, so an edit re-parses only the files it changed."""
    import hashlib
    import pickle
    root = Path(root)
    if tree_hash is not None and (str(root), tree_hash) in _cache:
        return _cache[(str(root), tree_hash)]
    out = Scan()
    path, disk = None, None                  # the on-disk memo, read on the first file this process has not scanned
    used, changed = {}, False
    files = project_files(root)
    ms = out.models = models(root, files)
    for rel, p in files:
        m = ms.get(rel, EMPTY)
        key = (rel, fsmemo.sha256(p), hashlib.sha256(repr(m).encode()).hexdigest())
        piece = _files.get(key)
        if piece is None:
            if disk is None:
                path, disk = _file_cache(root)
            piece = disk.get(key)
        if piece is None:
            piece = Scan()
            scan_file(rel, fsmemo.read_text(p), piece, m)
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
    if path is not None and (changed or len(used) != len(disk)):      # (nothing new to this process: no write)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(pickle.dumps((CACHE_VERSION, used)))
            tmp.replace(path)
        except OSError:
            pass
    src = root / "src"
    if src.exists():
        for p in sorted(src.glob("*/order")):
            scan_order(p.relative_to(root).as_posix(), p.read_text(errors="replace"),
                       sorted(q.name for q in p.parent.glob("*.c")), out)
    if tree_hash is not None:
        if len(_cache) > 2:                       # a long-lived process (dcp serve) sees a new tree per edit
            _cache.clear()
        _cache[(str(root), tree_hash)] = out
    return out


def scan_order(rel: str, text: str, files: list[str], out: Scan):
    """src/<unit>/order: `#` reason lines, then each fragment file of the unit once, in TU order (L12)."""
    unit = unit_of(rel)
    names, seen, reason = [], set(), False
    for n, line in enumerate(text.split("\n"), 1):
        s = line.strip()
        if not s:
            continue
        if s.startswith("#"):
            reason = reason or bool(s.lstrip("#").strip())
            continue
        if not reason:
            out.errors.append(ScanError(rel, n, "L12", "an order file starts with its reason (`# why`)"))
            reason = True
        if not (FRAGMENT.match(s) or UNLINKED_FRAGMENT.match(s)):
            out.errors.append(ScanError(rel, n, "L12", f"{s} is no fragment file (f_<addr>.c, u_<name>.c)"))
        elif s not in files:
            out.errors.append(ScanError(rel, n, "L12", f"{s}: no such file in src/{unit}"))
        elif s in seen:
            out.errors.append(ScanError(rel, n, "L12", f"{s} listed twice"))
        else:
            seen.add(s)
            names.append(s)
    missing = [f for f in files if (FRAGMENT.match(f) or UNLINKED_FRAGMENT.match(f)) and f not in seen]
    if missing:
        out.errors.append(ScanError(rel, 1, "L12", f"the order leaves out {len(missing)} fragment(s): " + ", ".join(missing[:6])))
    out.orders[unit] = names


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
