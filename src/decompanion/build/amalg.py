"""The amalgamation: one translation unit per (unit, target), generated from the unit's files.

    src/<unit>/head.c          includes, local types, prototypes, leading file-scope data
    src/<unit>/f_<addr>.c      one function each, in the target's address order
    src/<unit>/u_<name>.c      the functions the binary does not contain, in name order after them
    src/<unit>/tail.c          trailing file-scope data (optional)

Each part goes behind `#line 1 "<its path>"`, so the compiler sees one token stream (static data order and
literal pooling follow the address order of the fragments) and every diagnostic names the fragment. A fragment
belongs to the targets its address comment lists (a bare address: the default target; a prefixed one only
its own); a fragment without an address (`unlinked`) belongs to every target; head.c and tail.c to every
target that holds at least one fragment of the unit. A unit without a fragment of the target is no translation
unit of it. The result is written to build/amalg/<target>/<unit>.c (only when its text changed) and printed by
`dcp unit cat UNIT`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

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
    target: str
    unit: str
    members: list = field(default_factory=list)
    text: str = ""

    @property
    def path(self) -> str:
        """Where the amalgamation is written, project-relative."""
        return f"build/amalg/{self.target}/{self.unit}.c"

    @property
    def src_hash(self) -> str:
        return sha256(self.text)

    @property
    def fragments(self) -> list[Member]:
        return [m for m in self.members if m.role in ("fragment", "unlinked")]

    @property
    def first_addr(self) -> int | None:
        return next((m.addr for m in self.members if m.addr is not None), None)


def line_directive(rel: str) -> str:
    return f'#line 1 "{rel}"\n'


def compose(root: Path, members: list[Member]) -> str:
    out = []
    for m in members:
        text = (Path(root) / m.file).read_text(errors="replace")
        if text and not text.endswith("\n"):
            text += "\n"
        out.append(line_directive(m.file) + text)
    return "".join(out)


def units(root: Path, scan: srcscan.Scan, target: str, default: str) -> list[Amalg]:
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
        members += sorted(addressed, key=lambda m: (m.addr, m.file))
        members += sorted(unlinked, key=lambda m: m.file)
        if (d / "tail.c").exists():
            members.append(Member((d / "tail.c").relative_to(root).as_posix(), None, None, "tail"))
        a = Amalg(target, unit, members)
        a.text = compose(root, members)
        out.append(a)
    return out


def write(root: Path, a: Amalg) -> Path:
    """Write the amalgamation (only when its text differs from what is on disk); its absolute path."""
    p = Path(root) / a.path
    p.parent.mkdir(parents=True, exist_ok=True)
    data = a.text.encode()
    if not p.exists() or p.read_bytes() != data:
        p.write_bytes(data)
    return p
