"""The image format seam: what the rules need from the original binary, independent of the container.

PE32 is the only implementation (image/pe32.py). Everything is addressed by VA (image base + RVA), the
same numbers the sources and the declarations use.

What a format answers: the sections (Section: code / executable / writable / uninitialized from the format's
characteristics, holds_code), the entry point, imports (iat slots) and exports, the absolute relocation sites,
the Rich header entries, the byte ranges of its own machinery as (what, lo, hi) region triples in the format's
vocabulary (header_regions, directory_regions, import_regions, export_regions), the address width (ptr_size,
read_ptr) and the instruction set its machine type implies (default_isa).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Section:
    index: int
    name: str
    va: int             # VA of the first byte
    vsize: int          # virtual size (VirtualSize; 0 means raw size in some linkers)
    raw_off: int        # file offset of the raw data
    raw_size: int
    chars: int          # IMAGE_SCN_* characteristics

    @property
    def end(self):
        """VA one past the mapped bytes (the larger of virtual and raw size, section-aligned by the loader)."""
        return self.va + max(self.vsize, self.raw_size)

    @property
    def raw_end_va(self):
        return self.va + min(self.raw_size, max(self.vsize, self.raw_size))

    @property
    def code(self):
        return bool(self.chars & 0x20)

    @property
    def executable(self):
        return bool(self.chars & 0x20000000)

    @property
    def writable(self):
        return bool(self.chars & 0x80000000)

    @property
    def uninitialized(self):
        return bool(self.chars & 0x80)

    @property
    def holds_code(self):
        """A code section: marked as containing code or as executable."""
        return self.code or self.executable


@dataclass(frozen=True, slots=True)
class Import:
    dll: str
    name: str | None    # None when imported by ordinal
    ordinal: int | None
    slot: int           # VA of the IAT slot (the dword the thunk jumps through)

    @property
    def label(self):
        return f"{self.dll}!{self.name if self.name else '#%d' % self.ordinal}"


@dataclass(frozen=True, slots=True)
class Export:
    ordinal: int
    name: str | None
    va: int
    forwarder: str | None = None


@dataclass(frozen=True, slots=True)
class DataDirectory:
    index: int
    name: str
    va: int
    size: int


class Image:
    """Base class; subclasses fill the attributes in __init__ and implement the directory readers. The
    constructor raises ValueError for a file the format does not read."""

    key = "base"
    ptr_size = 4                     # bytes of an address stored in the image (an iat slot, a relocated field)
    byteorder = "little"
    path: Path
    data: bytes
    base: int
    entry: int                       # VA of the entry point (0 when none)
    sections: list[Section]
    is_dll: bool
    machine: int
    timestamp: int
    linker_version: tuple[int, int]
    subsystem: int
    headers_size: int                # SizeOfHeaders
    image_size: int                  # SizeOfImage
    directories: list[DataDirectory]

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    @property
    def end(self) -> int:
        return self.base + self.image_size

    # ------------------------------------------------------------------ addressing
    def section_of(self, va: int) -> Section | None:
        for s in self.sections:
            if s.va <= va < s.end:
                return s
        return None

    def off(self, va: int) -> int | None:
        """File offset of a VA, None when the byte is not backed by the file (bss, slack)."""
        s = self.section_of(va)
        if s is None:
            if self.base <= va < self.base + self.headers_size:
                return va - self.base
            return None
        o = va - s.va
        if o >= s.raw_size:
            return None
        return s.raw_off + o

    def read(self, va: int, n: int) -> bytes:
        """n bytes at va; bytes without file backing read as zero, like the loader maps them."""
        out = bytearray()
        while n > 0:
            o = self.off(va)
            if o is None:
                out.append(0)
                va += 1
                n -= 1
                continue
            s = self.section_of(va)
            avail = (s.raw_off + s.raw_size - o) if s else (self.headers_size - o)
            k = min(n, avail)
            out += self.data[o:o + k]
            va += k
            n -= k
        return bytes(out)

    def section_data(self, s: Section) -> bytes:
        """The file bytes of a section (its raw data, without the zero tail the loader adds)."""
        return self.data[s.raw_off:s.raw_off + s.raw_size]

    def u32(self, va: int) -> int:
        return int.from_bytes(self.read(va, 4), "little")

    def u16(self, va: int) -> int:
        return int.from_bytes(self.read(va, 2), "little")

    def read_ptr(self, va: int) -> int:
        """The address stored at va (ptr_size bytes in the image's byte order)."""
        return int.from_bytes(self.read(va, self.ptr_size), self.byteorder)

    def cstr(self, va: int, limit: int = 4096) -> bytes:
        o = self.off(va)
        if o is None:
            return b""
        e = self.data.find(b"\0", o, o + limit)
        return self.data[o:e if e >= 0 else o + limit]

    def in_image(self, va: int) -> bool:
        return self.base <= va < self.end

    # ------------------------------------------------------------------ implemented per format
    @property
    def default_isa(self) -> str | None:
        """The key of the instruction-set plugin the machine type implies (None: unknown machine)."""
        return None

    def header_regions(self) -> list[tuple[str, int, int]]:
        """(what, lo, hi) of the format's headers in front of the first section."""
        raise NotImplementedError

    def directory_regions(self) -> list[tuple[str, int, int]]:
        """(what, lo, hi) of the directories that are byte ranges of their own inside a section (relocations,
        resources, debug, ...); the import and export machinery is import_regions / export_regions."""
        raise NotImplementedError

    def import_regions(self) -> list[tuple[str, int, int]]:
        """(what, lo, hi) of the import machinery besides the address-table slots (descriptors, lookup tables,
        names, table terminators)."""
        raise NotImplementedError

    def export_regions(self) -> list[tuple[str, int, int]]:
        """(what, lo, hi) of the export machinery (directory, address / name / ordinal tables, names)."""
        raise NotImplementedError

    def imports(self) -> list[Import]:
        raise NotImplementedError

    def exports(self) -> list[Export]:
        raise NotImplementedError

    def relocations(self) -> list[int]:
        """VAs of every absolute (HIGHLOW) relocation site, sorted."""
        raise NotImplementedError

    def rich(self) -> list[tuple[int, int, int]]:
        """(product id, build, count) entries of the Rich header, in file order; [] when absent."""
        raise NotImplementedError
