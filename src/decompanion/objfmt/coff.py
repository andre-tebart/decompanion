"""COFF objects and archives (.obj, .lib), as VC6's CL and LIB write them. Ported from the first attempt's
link.py readers and reduced to what the ledger needs: sections with their relocations, symbols, and a
relocation mask per section for masked byte comparison.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

DIR32, DIR32NB, REL32 = 0x06, 0x07, 0x14
SCN_CODE, SCN_IDATA, SCN_UDATA, SCN_LNK_COMDAT = 0x20, 0x40, 0x80, 0x1000
SCN_LNK_INFO, SCN_LNK_REMOVE = 0x200, 0x800
# String literals and float constants are COMDATs that LINK merges program-wide only with /OPT:ICF; VC6's
# LINK keeps copies per object, so they resolve per object.
CONSTANT_PREFIXES = ("??_C@", "__real@")


@dataclass
class Reloc:
    offset: int
    symbol_index: int
    type: int


@dataclass
class Section:
    obj: "Obj"
    num: int
    name: str
    chars: int
    data: bytes | None          # None for .bss
    size: int
    relocs: list[Reloc]
    syms: list["Symbol"] = field(default_factory=list)

    @property
    def code(self):
        return bool(self.chars & SCN_CODE)

    @property
    def comdat(self):
        return bool(self.chars & SCN_LNK_COMDAT)

    @property
    def discard(self):
        return bool(self.chars & (SCN_LNK_INFO | SCN_LNK_REMOVE))

    def mask(self) -> bytes:
        """1 for every byte a relocation rewrites at link time (4 bytes per DIR32 / DIR32NB / REL32 site)."""
        m = bytearray(self.size)
        for r in self.relocs:
            if r.type in (DIR32, DIR32NB, REL32):
                for k in range(r.offset, min(r.offset + 4, self.size)):
                    m[k] = 1
        return bytes(m)

    def external_symbols(self):
        return [s for s in self.syms if s.external]

    def __repr__(self):
        return f"{self.obj.name}:{self.name}#{self.num}"


@dataclass
class Symbol:
    obj: "Obj"
    index: int
    name: str
    value: int
    secnum: int
    type: int
    cls: int
    section: Section | None = None

    @property
    def external(self):
        return self.cls == 2

    @property
    def defined(self):
        return self.secnum > 0

    @property
    def function(self):
        return (self.type >> 4) == 2

    @property
    def key(self):
        if self.external and not self.name.startswith(CONSTANT_PREFIXES):
            return self.name
        return f"{self.obj.name}:{self.name}"

    def __repr__(self):
        return self.key


class Obj:
    def __init__(self, name: str, data: bytes):
        self.name = name
        b = data
        self.machine, nsec, self.timestamp, symptr, nsym, optsz, self.chars = struct.unpack_from("<HHIIIHH", b, 0)
        strtab = symptr + 18 * nsym

        def sname(raw):
            if raw[:4] == b"\0\0\0\0":
                s = strtab + struct.unpack_from("<I", raw, 4)[0]
                return b[s:b.index(b"\0", s)].decode("latin-1")
            return raw.rstrip(b"\0").decode("latin-1")

        self.sections: list[Section | None] = [None]
        for k in range(nsec):
            h = 20 + optsz + 40 * k
            name = b[h:h + 8].rstrip(b"\0").decode("latin-1")
            if name.startswith("/") and name[1:].isdigit():
                s = strtab + int(name[1:])
                name = b[s:b.index(b"\0", s)].decode("latin-1")
            size, rawptr, relptr = struct.unpack_from("<III", b, h + 16)
            nrel = struct.unpack_from("<H", b, h + 32)[0]
            chars = struct.unpack_from("<I", b, h + 36)[0]
            sdata = None if chars & SCN_UDATA else b[rawptr:rawptr + size]
            relocs = [Reloc(*struct.unpack_from("<IIH", b, relptr + 10 * r)) for r in range(nrel)]
            self.sections.append(Section(self, k + 1, name, chars, sdata, size, relocs))
        self.symbols: dict[int, Symbol] = {}
        i = 0
        while i < nsym:
            o = symptr + 18 * i
            value, secnum, typ, cls, naux = struct.unpack_from("<IhHBB", b, o + 8)
            s = Symbol(self, i, sname(b[o:o + 8]), value, secnum, typ, cls)
            if secnum > 0:
                s.section = self.sections[secnum]
                if cls in (2, 3, 6) and not (cls == 3 and value == 0 and naux):
                    s.section.syms.append(s)
            self.symbols[i] = s
            i += 1 + naux
        for sec in self.sections[1:]:
            sec.syms.sort(key=lambda s: s.value)

    @property
    def code_sections(self):
        return [s for s in self.sections[1:] if s.code and s.data]

    @property
    def data_sections(self):
        return [s for s in self.sections[1:] if not s.code and not s.discard]

    def defined(self):
        return [s for s in self.symbols.values() if s.defined]

    def externals(self):
        """Symbols this object references but does not define."""
        return [s for s in self.symbols.values() if s.cls == 2 and s.secnum == 0]

    def __repr__(self):
        return f"Obj({self.name})"


def archive_members(path: Path) -> list[tuple[str, bytes]]:
    """(member name, bytes) of every object in a COFF archive, long names resolved, the linker members
    (`/`, `//`) skipped. Import-library members (`\\0\\0\\xff\\xff` short form) are returned too: the caller
    decides."""
    b = Path(path).read_bytes()
    if b[:8] != b"!<arch>\n":
        raise ValueError(f"{path}: not an archive")
    i, longnames, out = 8, b"", []
    while i + 60 <= len(b):
        name = b[i:i + 16].decode("latin-1").strip()
        size = int(b[i + 48:i + 58])
        d = b[i + 60:i + 60 + size]
        if name == "//":
            longnames = d
        elif name.startswith("/") and name[1:].isdigit():
            o = int(name[1:])
            out.append((longnames[o:longnames.index(b"\0", o)].decode("latin-1"), d))
        elif name != "/":
            out.append((name.rstrip("/"), d))
        i += 60 + size + (size & 1)
    return out


def is_import_member(data: bytes) -> bool:
    return data[:4] == b"\0\0\xff\xff"


def archive_objects(path: Path) -> list[Obj]:
    """Every real COFF object of an archive (import-library short members skipped)."""
    out = []
    for name, data in archive_members(path):
        if is_import_member(data) or len(data) < 20:
            continue
        out.append(Obj(Path(name).name, data))
    return out


def import_member_symbol(data: bytes) -> tuple[str, str] | None:
    """(symbol, dll) of an import-library short member."""
    if not is_import_member(data):
        return None
    strings = data[20:].split(b"\0")
    if len(strings) < 2:
        return None
    return strings[0].decode("latin-1"), strings[1].decode("latin-1")


def comp_ids(paths) -> dict[tuple[int, int], int]:
    """(Rich prodid, build) -> number of objects of the archives whose `@comp.id` symbol names it (the tool
    that built each object, as VC6-era compilers and assemblers stamp it)."""
    out: dict[tuple[int, int], int] = {}
    for path in paths:
        for o in archive_objects(path):
            for s in o.symbols.values():
                if s.name == "@comp.id":
                    k = (s.value >> 16, s.value & 0xffff)
                    out[k] = out.get(k, 0) + 1
                    break
    return out
