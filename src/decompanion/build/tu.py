"""A translation unit: one source file per unit, `src/<unit>.c`, compiled as it stands.

The file's text order is the TU order (static data order, literal pooling, a callee defined above its caller).
A unit is a translation unit of a target when it holds a function with an address of that target or an
unlinked function; a function of some targets only stands under `#if` on their `DCP_TARGET_<name>` macros,
which every target's compile defines (compile.defines; the scan parses each target's view, L16).

`__FILE__` and `__LINE__`: the file carries the original's `#line 1 "<path>"` and its `#line N` pins itself
(the unit's `file` declaration in decl/data.dcl names the path; L.decl checks it against the image and the
directive). The compiler reports a diagnostic at the name and line the directives give; `locate` maps it back
to the file's physical line.

The units, their flags and `locate` are the core's (native/dcp_core/src/plan.rs); this module is their face.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .. import fsmemo, native


@dataclass
class TU:
    target: str
    unit: str
    file: str                                         # src/<unit>.c, project-relative posix
    functions: list = field(default_factory=list)     # (address or None for an unlinked one, name) in text order
    file_name: str | None = None                      # the declared original file name, else None
    src_hash: str = ""                                # the sha256 of the unit's text
    root: Path | None = None

    @property
    def path(self) -> str:
        """What the compiler reads, project-relative: the unit's file itself."""
        return self.file

    @property
    def text(self) -> str:
        return fsmemo.read_text(Path(self.root) / self.file)

    @property
    def first_addr(self) -> int | None:
        """The least address of the target's functions in the unit (where its `build` fact stands)."""
        return min((a for a, _ in self.functions if a is not None), default=None)

    def locate(self, name: str, line: int) -> list[int]:
        """The physical lines of the file a compiler position (the name and line its `#line` directives give)
        stands for: several when pinned lines collide, [] when none does."""
        return locate(self.text, self.file, name, line)


def of_rows(root, rows) -> list[TU]:
    return [TU(t, u, f, list(fns), fn, h, Path(root)) for t, u, f, fns, fn, h in rows]


def same_file(a: str, b: str) -> bool:
    na, nb = a.replace("\\", "/").lower(), b.replace("\\", "/").lower()
    return na == nb or na.endswith("/" + nb) or nb.endswith("/" + na)


def locate(text: str, rel: str, name: str, line: int) -> list[int]:
    return native.core().plan_locate(text, rel, name, line)


def units(root: Path, scan, target: str, default: str, file_names: dict | None = None) -> list[TU]:
    """The translation units of one target of a scan, in unit name order."""
    return of_rows(root, native.core().plan_scan_units(str(root), scan._x, target, default, file_names or {}))
