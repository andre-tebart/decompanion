"""PE32 (i386) images: exe and dll. The reader is the core's (native/dcp_core/src/pe.rs, pyimage.rs); this class
is its face with the records of image/base.py.
"""
from __future__ import annotations

from functools import cached_property
from pathlib import Path

from .. import native
from . import register
from .base import DataDirectory, Export, Image, Import, Section

MACHINE_ISA = {0x14c: "x86"}        # IMAGE_FILE_MACHINE_I386


@register
class PE32(Image):
    key = "pe32"
    ptr_size = 4

    def __init__(self, path: Path):
        self.path = Path(path)
        self._x = native.core().pe_open(str(self.path))
        (self.base, self.entry, self.is_dll, self.machine, self.timestamp, self.linker_version, self.subsystem,
         self.headers_size, self.image_size, self.file_chars) = self._x.header()
        self.sections = [Section(*s) for s in self._x.sections()]
        self.directories = [DataDirectory(*d) for d in self._x.directories()]

    @cached_property
    def data(self) -> bytes:
        return self._x.data()

    @property
    def sha256(self) -> str:
        return self._x.sha256()

    def off(self, va: int) -> int | None:
        return self._x.off(va)

    def read(self, va: int, n: int) -> bytes:
        return self._x.read(va, n)

    def section_data(self, s: Section) -> bytes:
        return self._x.section_data(s.index)

    def cstr(self, va: int, limit: int = 4096) -> bytes:
        return self._x.cstr(va, limit)

    def directory(self, name: str) -> DataDirectory | None:
        return next((dd for dd in self.directories if dd.name == name and dd.va), None)

    @property
    def kind(self):
        """dll (the DLL characteristic), gui (subsystem 2, WINDOWS_GUI), console (3, WINDOWS_CUI), else exe."""
        return self._x.kind()

    @property
    def default_isa(self):
        return MACHINE_ISA.get(self.machine)

    def header_regions(self):
        return self._x.header_regions()

    def directory_regions(self):
        return self._x.directory_regions()

    def import_regions(self):
        return self._x.import_regions()

    def export_regions(self):
        return self._x.export_regions()

    def imports(self) -> list[Import]:
        return [Import(*i) for i in self._x.imports()]

    def import_descriptor_ranges(self) -> dict[str, list[tuple[int, int]]]:
        return self._x.import_ranges()

    def exports(self) -> list[Export]:
        return [Export(*e) for e in self._x.exports()]

    def export_ranges(self) -> dict[str, list[tuple[int, int]]]:
        return self._x.export_ranges()

    def relocations(self) -> list[int]:
        return self._x.relocations()

    def reloc_range(self) -> tuple[int, int] | None:
        return self._x.reloc_range()

    def rich(self) -> list[tuple[int, int, int]]:
        return self._x.rich()

    def rich_range(self) -> tuple[int, int] | None:
        return self._x.rich_range()
