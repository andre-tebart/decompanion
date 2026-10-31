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

Everything C comes from the front end (libclang, native/dcp_core/src/frontend.rs and srcscan.rs): the comments and
literals, the macro definitions, the function definitions and the file-scope data declarations, over each unit
file as a target's compile sees it. Source (TOKEN, its own lexer) serves the readers of a text that remain here.
"""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass
from pathlib import Path

TOKEN = re.compile(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|//[^\n]*|/\*.*?\*/', re.S)
ADDR_ITEM = r"(?:[A-Za-z][A-Za-z0-9_-]*:)?0x[0-9a-fA-F]+"
LEAD_ADDRS = re.compile(r"^\s*(" + ADDR_ITEM + r")((?:\s*[,/]\s*" + ADDR_ITEM + r")*)")
ONE_ADDR = re.compile(r"(?:([A-Za-z][A-Za-z0-9_-]*):)?(0x[0-9a-fA-F]+)")
UNLINKED = re.compile(r"^\s*unlinked\b\s*,?\s*(.*)", re.S)


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


def scan(root: Path, tree_hash: str | None = None) -> Scan:
    """Scan src/**/*.c, src/**/*.h and include/**/*.h of the project at root (memoised per tree hash), every
    file as each target's compile sees it (the core's: native/dcp_core/src/frontend.rs)."""
    from .. import native
    return Scan(native.core().front_scan(str(Path(root)), tree_hash))


def address_for(addrs: tuple, target: str, default: str) -> int | None:
    """The address of a (target or None, address) list for one target (a bare address is the default's)."""
    for t, a in addrs:
        if (t or default) == target:
            return a
    return None
