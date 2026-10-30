"""The amalgamation: one translation unit per (unit, target), generated from the unit's files.

    src/<unit>/head.c          includes, local types, prototypes, leading file-scope data
    src/<unit>/f_<addr>.c      one function each, in the target's address order
    src/<unit>/u_<name>.c      the functions the binary does not contain, in name order after them
    src/<unit>/tail.c          trailing file-scope data (optional)
    src/<unit>/order           optional: the fragments' TU order, replacing the two orders above (srcscan, L12)

Each part goes behind `#line 1 "<its path>"`, so the compiler sees one token stream (static data order and
literal pooling follow the address order of the fragments) and every diagnostic names the fragment. A fragment
belongs to the targets its address comment lists (a bare address: the default target; a prefixed one only
its own); a fragment without an address (`unlinked`) belongs to every target; head.c and tail.c to every
target that holds at least one fragment of the unit. A unit without a fragment of the target is no translation
unit of it. The result is written to build/amalg/<target>/<unit>.c (only when its text changed) and printed by
`dcp unit cat UNIT`.

A unit with a declared original file name (decl/data.dcl `file tu=UNIT path=...`, the unit's __FILE__) is
compiled under that name instead: every part goes behind `#line <n> "<that name>"`, the parts numbered one
after the other (part k starts at the line after the last line of part k-1), so __FILE__ is the original's
string and the reported line still tells the part. `segments` maps a reported line back to (part, line);
a `#line N` pin inside a part (the original's __LINE__ for an assert or a checked call) starts a segment of
its own, and a line two segments share is given to the first (a pinned line can collide with another
part's numbering; the message names both).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .. import fsmemo
from ..ledger import srcscan
from ..ledger.store import sha256

FRAGMENT = re.compile(r"^f_([0-9a-fA-F]+)\.c$")
UNLINKED = re.compile(r"^u_([A-Za-z_]\w*)\.c$")


@dataclass(frozen=True)
class Member:
    file: str               # project-relative posix path
    addr: int | None        # the target's address of the fragment's function (None: head, tail, unlinked)
    name: str | None        # the function the fragment defines (None: head, tail, unparsed)
    role: str               # head | fragment | unlinked | tail


@dataclass
class Amalg:
    """One amalgamation. Its text (and segments) is composed on first use; src_hash, the hash of the text, is
    memoised per (compose's code, file name, each part's path and content hash), so a build that compiles no
    unit reads no part file (fsmemo.derived)."""
    target: str
    unit: str
    members: list = field(default_factory=list)
    file_name: str | None = None                      # the declared original file name, else None
    root: Path | None = None                          # the project root the members are relative to
    _composed: tuple | None = field(default=None, repr=False, compare=False)
    _src_hash: str | None = field(default=None, repr=False, compare=False)

    def _compose(self) -> tuple[str, list]:
        if self._composed is None:
            self._composed = compose(self.root, self.members, self.file_name)
        return self._composed

    @property
    def text(self) -> str:
        return self._compose()[0]

    @property
    def segments(self) -> list:
        """(first reported line, n lines, part file, its first line) per segment (a declared file name only)."""
        return self._compose()[1]

    def locate(self, line: int) -> list[tuple[str, int]]:
        """The (part file, line) a reported line of the declared file name stands for (several when pinned lines
        collide), [] when no segment holds it."""
        return [(f, first + line - lo) for lo, n, f, first in self.segments if lo <= line < lo + n]

    @property
    def path(self) -> str:
        """Where the amalgamation is written, project-relative."""
        return f"build/amalg/{self.target}/{self.unit}.c"

    @property
    def src_hash(self) -> str:
        if self._src_hash is None:
            key = sha256("amalg.src_hash", _compose_code(), self.file_name or "",
                         *(f"{m.file}={fsmemo.sha256(Path(self.root) / m.file)}" for m in self.members))
            h = fsmemo.derived(key)
            if h is None:
                h = sha256(self.text)
                fsmemo.put_derived(key, h)
            self._src_hash = h
        return self._src_hash

    @property
    def fragments(self) -> list[Member]:
        return [m for m in self.members if m.role in ("fragment", "unlinked")]

    @property
    def first_addr(self) -> int | None:
        return next((m.addr for m in self.members if m.addr is not None), None)


def line_directive(rel: str) -> str:
    return f'#line 1 "{rel}"\n'


_compose_digest: str | None = None


def _compose_code() -> str:
    """The hash of compose's own code (a memoised src_hash is only valid for the code that composed it)."""
    global _compose_digest
    if _compose_digest is None:
        import inspect
        _compose_digest = sha256(inspect.getsource(compose), inspect.getsource(line_directive))
    return _compose_digest


PIN = re.compile(r"^[ \t]*#[ \t]*line[ \t]+(\d+)[ \t]*$")


def compose(root: Path, members: list[Member], file_name: str | None = None, read=None) -> tuple[str, list]:
    """The amalgamation's text, and its segments when it is compiled under a declared file name. `read`
    (rel -> text or None) supplies a part's text instead of the file (a trial of edits not written yet)."""
    out, segments, n = [], [], 1
    esc = file_name.replace("\\", "\\\\") if file_name else None
    for m in members:
        text = (read(m.file) if read else None)
        if text is None:
            text = fsmemo.read_text(Path(root) / m.file)
        if text and not text.endswith("\n"):
            text += "\n"
        if esc is None:
            out.append(line_directive(m.file) + text)
            continue
        out.append(f'#line {n} "{esc}"\n' + text)
        lines = text.split("\n")[:-1]
        start, first = n, 1
        for k, line in enumerate(lines, 1):
            pm = PIN.match(line)
            if pm:
                segments.append((start, k - first, m.file, first))
                start, first = int(pm.group(1)), k + 1
        segments.append((start, len(lines) + 1 - first, m.file, first))
        n += len(lines)
    return "".join(out), [s for s in segments if s[1] > 0]


def units(root: Path, scan: srcscan.Scan, target: str, default: str, file_names: dict | None = None) -> list[Amalg]:
    """The amalgamations of one target, in unit name order (see the module docstring for the rules)."""
    root = Path(root)
    by_file = {f.file: f for f in scan.functions}
    out = []
    src = root / "src"
    if not src.exists():
        return out
    for d in sorted(p for p in src.iterdir() if p.is_dir()):
        unit = d.name
        addressed, unlinked = [], []
        for p in sorted(d.glob("*.c")):
            rel = p.relative_to(root).as_posix()
            fm, um = FRAGMENT.match(p.name), UNLINKED.match(p.name)
            fn = by_file.get(rel)
            if fm:
                if fn is not None and fn.addrs:
                    a = srcscan.address_for(fn.addrs, target, default)
                    if a is None:
                        continue                            # a fragment of another target only
                elif fn is not None and fn.unlinked:
                    unlinked.append(Member(rel, None, fn.name, "unlinked"))
                    continue
                else:                                      # no parsed address comment: the file name's address,
                    if target != default:                  # the default target's (L.src reports the error)
                        continue
                    a = int(fm.group(1), 16)
                addressed.append(Member(rel, a, fn.name if fn else None, "fragment"))
            elif um:
                unlinked.append(Member(rel, None, fn.name if fn else um.group(1), "unlinked"))
        if not addressed and not unlinked:
            continue
        members = []
        if (d / "head.c").exists():
            members.append(Member((d / "head.c").relative_to(root).as_posix(), None, None, "head"))
        order = scan.orders.get(unit)
        if order:                                          # the declared TU order; anything it leaves out (L12)
            pos = {f"src/{unit}/{name}": k for k, name in enumerate(order)}   # follows in the default order
            default_order = sorted(addressed, key=lambda m: (m.addr, m.file)) + sorted(unlinked, key=lambda m: m.file)
            members += sorted(default_order, key=lambda m: pos.get(m.file, len(pos)))
        else:
            members += sorted(addressed, key=lambda m: (m.addr, m.file))
            members += sorted(unlinked, key=lambda m: m.file)
        if (d / "tail.c").exists():
            members.append(Member((d / "tail.c").relative_to(root).as_posix(), None, None, "tail"))
        out.append(Amalg(target, unit, members, file_name=(file_names or {}).get(unit), root=root))
    return out


def write(root: Path, a: Amalg) -> Path:
    """Write the amalgamation (only when its text differs from what is on disk); its absolute path."""
    p = Path(root) / a.path
    p.parent.mkdir(parents=True, exist_ok=True)
    data = a.text.encode()
    if not p.exists() or p.read_bytes() != data:
        p.write_bytes(data)
    return p
