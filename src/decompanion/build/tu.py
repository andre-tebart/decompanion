"""A translation unit: one source file per unit, `src/<unit>.c`, compiled as it stands.

The file's text order is the TU order (static data order, literal pooling, a callee defined above its caller).
A unit is a translation unit of a target when it holds a function with an address of that target or an
unlinked function; a function of some targets only stands under `#if` on their `DCP_TARGET_<name>` macros,
which every target's compile defines (compile.defines; the scan parses each target's view, L16).

`__FILE__` and `__LINE__`: the file carries the original's `#line 1 "<path>"` and its `#line N` pins itself
(the unit's `file` declaration in decl/data.dcl names the path; L.decl checks it against the image and the
directive). The compiler reports a diagnostic at the name and line the directives give; `locate` maps it back
to the file's physical line.
"""
from __future__ import annotations

import functools
import re
from dataclasses import dataclass, field
from pathlib import Path

from .. import fsmemo
from ..ledger import srcscan

UNIT_FILE = re.compile(r"^src/([^/]+)\.c$")
LINE = re.compile(r'^[ \t]*#[ \t]*line[ \t]+(\d+)(?:[ \t]+"((?:\\.|[^"\\])*)")?', re.M)


@dataclass
class TU:
    target: str
    unit: str
    file: str                                         # src/<unit>.c, project-relative posix
    functions: list = field(default_factory=list)     # (address or None for an unlinked one, name) in text order
    file_name: str | None = None                      # the declared original file name, else None
    root: Path | None = None

    @property
    def path(self) -> str:
        """What the compiler reads, project-relative: the unit's file itself."""
        return self.file

    @property
    def text(self) -> str:
        return fsmemo.read_text(Path(self.root) / self.file)

    @property
    def src_hash(self) -> str:
        return fsmemo.sha256(Path(self.root) / self.file)

    @property
    def first_addr(self) -> int | None:
        """The least address of the target's functions in the unit (where its `build` fact stands)."""
        return min((a for a, _ in self.functions if a is not None), default=None)

    def locate(self, name: str, line: int) -> list[int]:
        """The physical lines of the file a compiler position (the name and line its `#line` directives give)
        stands for: several when pinned lines collide, [] when none does."""
        return locate(self.text, self.file, name, line)


def same_file(a: str, b: str) -> bool:
    na, nb = a.replace("\\", "/").lower(), b.replace("\\", "/").lower()
    return na == nb or na.endswith("/" + nb) or nb.endswith("/" + na)


@functools.lru_cache(maxsize=32)
def segments(text: str, rel: str) -> list[tuple[str, int, int, int]]:
    """(name, first reported line, n lines, first physical line) of every stretch of the text one `#line`
    directive numbers (the file's own name and line 1 before the first); once per text (a compile's
    diagnostics locate one by one in the same file)."""
    out, name, first, phys = [], rel, 1, 1
    lines = text.split("\n")
    for k, s in enumerate(lines, 1):
        m = LINE.match(s)
        if m:
            out.append((name, first, k - phys, phys))
            name = m.group(2).replace("\\\\", "\\") if m.group(2) is not None else name
            first, phys = int(m.group(1)), k + 1
    out.append((name, first, len(lines) + 1 - phys, phys))
    return [s for s in out if s[2] > 0]


def locate(text: str, rel: str, name: str, line: int) -> list[int]:
    return [phys + line - first for n, first, k, phys in segments(text, rel)
            if same_file(n, name) and first <= line < first + k]


def units(root: Path, scan: srcscan.Scan, target: str, default: str, file_names: dict | None = None) -> list[TU]:
    """The translation units of one target, in unit name order."""
    root = Path(root)
    by_file: dict[str, list] = {}
    for f in scan.functions:
        by_file.setdefault(f.file, []).append(f)
    out = []
    for rel in sorted(by_file):
        m = UNIT_FILE.match(rel)
        if not m:
            continue
        fns = []
        for f in sorted(by_file[rel], key=lambda f: f.line):
            a = srcscan.address_for(f.addrs, target, default)
            if a is not None or f.unlinked:
                fns.append((a, f.name))
        if fns:
            out.append(TU(target, m.group(1), rel, fns, (file_names or {}).get(m.group(1)), root))
    return out
