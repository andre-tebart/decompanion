"""Declarations: decl/*.dcl, the typed state a human writes about addresses that have no source (yet).

One fact per line, the file sorted by address:

    [TARGET:]ADDR[..END] KIND [WORD ...] [key=value ...] -- reason

- ADDR, END: hex (`0x10008cb0`); END is exclusive. A bare address belongs to the default target (the first
  [[target]] of decompanion.toml), `exe:0x4a3000` to the named one.
- KIND and its arguments come from a closed vocabulary (KINDS below); anything else is an error.
- The reason after ` -- ` is mandatory: a declaration is a human's claim, and the claim needs its why.
- `#` starts a comment line; blank lines are ignored.
- Every file is sorted by (target in config order, ADDR); two lines with one key (target, ADDR, KIND, first
  word) are a duplicate. Sorting by address is what keeps parallel branches in different hunks.

Kinds: boundary start|end tu= [by=leaked|tag|guess], ADDR..END bytes dead, ADDR..END jumptable / idxtable fn=ADDR,
ADDR..END foreign kind=IDENT, name IDENT, ADDR..END fptr, start, ADDR..END libunit tu= lib=PATH, file tu= path=PATH.
The grammar, the loader and the writer are the core's (native/dcp_core/src/decl.rs); this module is its face.

`text.dcl` holds declarations about code sections, `data.dcl` the rest (`dcp decl add` picks the file).
The loader rule L.decl (rules/layout.py) turns the lines of the current target into declared facts with
`by=decl:<file>:<line>`; every error of this module becomes a conflict of severity error (check L.decl), so
`dcp check` fails on a malformed, unsorted or duplicated line.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .. import fsmemo, native

UNIT = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]*$")       # a unit name (what `boundary tu=` takes)


class DeclError(ValueError):
    pass


@dataclass(frozen=True)
class Decl:
    lo: int
    hi: int
    kind: str
    words: tuple[str, ...]
    keys: dict
    reason: str
    target: str | None = None      # None: the default target
    file: str = ""                 # project-relative posix path
    line: int = 0

    @property
    def by(self) -> str:
        return f"decl:{self.file}:{self.line}"

    def key(self, default: str) -> tuple:
        return (self.target or default, self.lo, self.kind, self.words[0] if self.words else "")

    def text(self) -> str:
        """The canonical spelling (what `dcp decl add` writes)."""
        return native.core().decl_text(_row(self))


def _row(d: Decl) -> tuple:
    return (d.lo, d.hi, d.kind, list(d.words), list(d.keys.items()), d.reason, d.target, d.file, d.line)


def _decl(r) -> Decl:
    lo, hi, kind, words, keys, reason, target, file, line = r
    return Decl(lo, hi, kind, tuple(words), dict(keys), reason, target, file, line)


def parse_line(text: str, file: str = "", line: int = 0) -> Decl:
    """One declaration line (not a comment, not blank). Raises DeclError with the reason it is malformed."""
    try:
        return _decl(native.core().decl_parse_line(text, file, line))
    except ValueError as e:
        raise DeclError(str(e)) from None


@dataclass(frozen=True)
class LoadError:
    file: str
    line: int
    lo: int | None
    message: str
    target: str | None = None     # the target the line belongs to (None: unknown; the default target reports it)


def load(files: list[Path], root: Path, targets: list[str]) -> tuple[list[Decl], list[LoadError]]:
    """Every declaration of every file (all targets), and the errors: malformed lines, unknown targets, lines out
    of order, duplicate keys (across files too). `targets` lists the target names, the default first."""
    rows, errors = native.core().decl_load([str(f) for f in files], str(root), list(targets))
    return [_decl(r) for r in rows], [LoadError(*e) for e in errors]


def unit_files(decls: list[Decl], target: str, default: str) -> dict[str, str]:
    """unit -> its declared original file name (`file` declarations of one target; the first one per unit)."""
    out: dict[str, str] = {}
    for d in decls:
        if d.kind == "file" and (d.target or default) == target:
            out.setdefault(d.keys["tu"], d.keys["path"])
    return out


def lib_units(decls: list[Decl], target: str, default: str) -> dict[str, Decl]:
    """unit -> its `libunit` declaration (of one target; the first one per unit)."""
    out: dict[str, Decl] = {}
    for d in decls:
        if d.kind == "libunit" and (d.target or default) == target:
            out.setdefault(d.keys["tu"], d)
    return out


def insert(path: Path, d: Decl, targets: list[str]) -> int:
    """Insert the canonical line of d into the sorted file, after the last declaration whose sort key is not
    larger (before the first larger one when there is none; at the end of an empty file). Returns the new
    line's number. The caller has checked for duplicates."""
    n = native.core().decl_insert(str(path), _row(d), list(targets))
    fsmemo.wrote(path)
    return n
