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

`text.dcl` holds declarations about code sections, `data.dcl` the rest (`dcp decl add` picks the file).
The loader rule L.decl (rules/layout.py) turns the lines of the current target into declared facts with
`by=decl:<file>:<line>`; every error of this module becomes a conflict of severity error (check L.decl), so
`dcp check` fails on a malformed, unsorted or duplicated line.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .. import fsmemo

IDENT =re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
UNIT = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]*$")
HEX = re.compile(r"^0x[0-9a-fA-F]+$")
PATH = re.compile(r'^[^\s"]+$')
LINE = re.compile(r"^(?:(?P<target>[A-Za-z][A-Za-z0-9_-]*):)?(?P<lo>0x[0-9a-fA-F]+)(?:\.\.(?P<hi>0x[0-9a-fA-F]+))?"
                  r"(?:\s+(?P<body>.*?))?\s*$")


@dataclass(frozen=True)
class Spec:
    """The shape of one kind: its words (each position a tuple of allowed values, or IDENT / UNIT), its
    required and optional keys (a tuple of allowed values, "addr", "unit" or "ident"), range or point."""
    words: tuple = ()
    required: dict = field(default_factory=dict)
    optional: dict = field(default_factory=dict)
    range: bool = False
    doc: str = ""


KINDS: dict[str, Spec] = {
    "boundary": Spec(words=(("start", "end"),), required={"tu": "unit"}, optional={"by": ("leaked", "tag", "guess")},
                     doc="a unit boundary: `start` = the unit's first byte, `end` = the first byte after it; by = how the "
                         "unit got its name (leaked path, tag string, guess)"),
    "bytes": Spec(words=(("dead",),), range=True,
                  doc="bytes no function's code reaches and that are not fill (dead code we cannot reproduce)"),
    "jumptable": Spec(required={"fn": "addr"}, range=True, doc="a jump table of the function fn the walk does not find"),
    "idxtable": Spec(required={"fn": "addr"}, range=True, doc="a byte index table of the function fn"),
    "foreign": Spec(required={"kind": "ident"}, range=True, doc="a blob no compiler of the toolchain produced (asm, a resource ...)"),
    "name": Spec(words=("ident",), doc="a name for an address without source (a function or data symbol)"),
    "fptr": Spec(range=True, doc="function pointers stored in a code section (dwords, each a relocated code address)"),
    "start": Spec(doc="a function start the setup walk does not find (reached only through a computed jump or not at all); "
                      "the walk takes it as a root, and what it reaches from there stays declared"),
    "libunit": Spec(required={"tu": "unit", "lib": "path"}, range=True,
                    doc="a library member compiled from source: the unit's code is the member of archive `lib` the image "
                        "holds at the range (an import library's code member no installation has); the link puts the "
                        "unit's object into that archive instead of the object list, so LINK places it among the "
                        "library contributions as the original"),
    "file": Spec(required={"tu": "unit", "path": "path"},
                 doc="the original file name of a unit (its __FILE__), declared at the address of the string in the image "
                     "(data.dcl); the amalgamation compiles the unit under that name"),
}


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
        spec = KINDS[self.kind]
        s = (f"{self.target}:" if self.target else "") + f"{self.lo:#010x}"
        if spec.range:
            s += f"..{self.hi:#010x}"
        parts = [s, self.kind, *self.words]
        for k in sorted(self.keys):
            v = self.keys[k]
            parts.append(f"{k}={v:#010x}" if isinstance(v, int) else f"{k}={v}")
        return " ".join(parts) + " -- " + self.reason


def _value(kind: str, key: str, shape, v: str):
    if shape == "addr":
        if not HEX.match(v):
            raise DeclError(f"{kind}: {key}={v} is not a hex address")
        return int(v, 16)
    if shape == "unit":
        if not UNIT.match(v):
            raise DeclError(f"{kind}: {key}={v} is not a unit name ([A-Za-z_][A-Za-z0-9_.-]*)")
        return v
    if shape == "ident":
        if not IDENT.match(v):
            raise DeclError(f"{kind}: {key}={v} is not an identifier")
        return v
    if shape == "path":
        if not PATH.match(v):
            raise DeclError(f"{kind}: {key}={v} is not a path (no blanks, no quotes)")
        return v
    if v not in shape:
        raise DeclError(f"{kind}: {key}={v} is not one of {'|'.join(shape)}")
    return v


def parse_line(text: str, file: str = "", line: int = 0) -> Decl:
    """One declaration line (not a comment, not blank). Raises DeclError with the reason it is malformed."""
    head, sep, reason = text.partition(" -- ")
    if not sep:
        if text.rstrip().endswith(" --") or text.strip().endswith("--"):
            raise DeclError("missing reason after `--`")
        raise DeclError("missing reason (` -- why` ends every declaration)")
    reason = reason.strip()
    if not reason:
        raise DeclError("missing reason after `--`")
    m = LINE.match(head.strip())
    if not m:
        raise DeclError(f"cannot parse {head.strip()!r}: expected [TARGET:]ADDR[..END] KIND ...")
    lo = int(m.group("lo"), 16)
    hi_s = m.group("hi")
    body = (m.group("body") or "").split()
    if not body:
        raise DeclError("missing kind")
    kind, args = body[0], body[1:]
    spec = KINDS.get(kind)
    if spec is None:
        raise DeclError(f"unknown kind {kind!r} (known: {', '.join(sorted(KINDS))})")
    if spec.range:
        if hi_s is None:
            raise DeclError(f"{kind} declares a range: ADDR..END")
        hi = int(hi_s, 16)
        if hi <= lo:
            raise DeclError(f"empty range {lo:#x}..{hi:#x}")
    else:
        if hi_s is not None:
            raise DeclError(f"{kind} declares a point: ADDR, not a range")
        hi = lo + 1
    words, keys = [], {}
    for a in args:
        if "=" in a:
            k, _, v = a.partition("=")
            shape = spec.required.get(k, spec.optional.get(k))
            if shape is None:
                raise DeclError(f"{kind}: unknown key {k!r}")
            if k in keys:
                raise DeclError(f"{kind}: key {k!r} given twice")
            keys[k] = _value(kind, k, shape, v)
        else:
            words.append(a)
    if len(words) != len(spec.words):
        want = " ".join("|".join(w) if isinstance(w, tuple) else w.upper() for w in spec.words) or "no words"
        raise DeclError(f"{kind}: expects {want}, got {' '.join(words) or 'nothing'}")
    for w, shape in zip(words, spec.words):
        if shape == "ident":
            if not IDENT.match(w):
                raise DeclError(f"{kind}: {w!r} is not an identifier")
        elif w not in shape:
            raise DeclError(f"{kind}: {w!r} is not one of {'|'.join(shape)}")
    for k in spec.required:
        if k not in keys:
            raise DeclError(f"{kind}: missing {k}=")
    return Decl(lo, hi, kind, tuple(words), keys, reason, m.group("target"), file, line)


@dataclass(frozen=True)
class LoadError:
    file: str
    line: int
    lo: int | None
    message: str
    target: str | None = None     # the target the line belongs to (None: unknown; the default target reports it)


def sort_key(d: Decl, order: dict[str, int], default: str) -> tuple[int, int]:
    return (order.get(d.target or default, len(order)), d.lo)


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


def load(files: list[Path], root: Path, targets: list[str]) -> tuple[list[Decl], list[LoadError]]:
    """Every declaration of every file (all targets), and the errors: malformed lines, unknown targets, lines out
    of order, duplicate keys (across files too). `targets` lists the target names, the default first."""
    default = targets[0]
    order = {t: i for i, t in enumerate(targets)}
    out: list[Decl] = []
    errors: list[LoadError] = []
    seen: dict[tuple, str] = {}
    for path in sorted(files):
        rel = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix()
        prev: Decl | None = None
        for n, raw in enumerate(path.read_text().splitlines(), 1):
            s = raw.strip()
            if not s or s.startswith("#"):
                continue
            try:
                d = parse_line(s, rel, n)
            except DeclError as e:
                m = LINE.match(s.partition(" -- ")[0].strip())
                t = m.group("target") if m and m.group("target") in order else None
                errors.append(LoadError(rel, n, None, str(e), t))
                continue
            if d.target is not None and d.target not in order:
                errors.append(LoadError(rel, n, d.lo, f"unknown target {d.target!r} (targets: {', '.join(targets)})"))
                continue
            if prev is not None and sort_key(d, order, default) < sort_key(prev, order, default):
                errors.append(LoadError(rel, n, d.lo, f"out of order: {d.text().split(' ')[0]} after line {prev.line} "
                                                      f"({prev.text().split(' ')[0]}); the file is sorted by target, address",
                                        d.target or default))
            prev = d
            k = d.key(default)
            if k in seen:
                errors.append(LoadError(rel, n, d.lo, f"duplicate {' '.join((d.kind, *d.words))} at {d.lo:#x} (also {seen[k]})",
                                        d.target or default))
            else:
                seen[k] = f"{rel}:{n}"
            out.append(d)
    return out, errors


def insert(path: Path, d: Decl, targets: list[str]) -> int:
    """Insert the canonical line of d into the sorted file, after the last declaration whose sort key is not
    larger (before the first larger one when there is none; at the end of an empty file). Returns the new
    line's number. The caller has checked for duplicates."""
    default = targets[0]
    order = {t: i for i, t in enumerate(targets)}
    key = sort_key(d, order, default)
    lines = path.read_text().splitlines() if path.exists() else []
    after, before = None, None
    for i, raw in enumerate(lines):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        try:
            o = parse_line(s)
        except DeclError:
            continue
        if sort_key(o, order, default) <= key:
            after = i
        elif before is None:
            before = i
    at = after + 1 if after is not None else (before if before is not None else len(lines))
    lines.insert(at, d.text())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", newline="\n")
    fsmemo.wrote(path)
    return at + 1
