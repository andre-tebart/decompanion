"""COFF objects and archives (.obj, .lib), as VC6's CL and LIB write them (i386). Ported from the first
attempt's link.py readers and reduced to what the ledger needs: sections with their relocations, symbols, and
a relocation mask per section for masked byte comparison. The format-neutral view the rules use is described
in objfmt/base.py.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from . import register
from .base import ABSOLUTE, ABSOLUTE_RVA, RELATIVE, ObjectFormat

DIR32, DIR32NB, REL32 = 0x06, 0x07, 0x14
# IMAGE_REL_I386_* -> (kind, width): the relocations that rewrite bytes of the linked image
RELOC_KINDS = {DIR32: (ABSOLUTE, 4), DIR32NB: (ABSOLUTE_RVA, 4), REL32: (RELATIVE, 4)}
SCN_CODE, SCN_IDATA, SCN_UDATA, SCN_LNK_COMDAT = 0x20, 0x40, 0x80, 0x1000
SCN_LNK_INFO, SCN_LNK_REMOVE = 0x200, 0x800
SYM_EXTERNAL, SYM_STATIC = 2, 3              # IMAGE_SYM_CLASS_*
IMPORT_PREFIX = "__imp_"                      # the pointer symbol of a dllimport reference (its IAT slot)
COMP_ID = "@comp.id"                          # the absolute symbol MSVC-era tools stamp every object with
# String literals and float constants are COMDATs that LINK merges program-wide only with /OPT:ICF; VC6's
# LINK keeps copies per object, so they resolve per object.
CONSTANT_PREFIXES = ("??_C@", "__real@")


@dataclass
class Reloc:
    offset: int
    symbol_index: int
    type: int

    @property
    def kind(self) -> str | None:
        """ABSOLUTE (DIR32), ABSOLUTE_RVA (DIR32NB), RELATIVE (REL32); None for every other type."""
        k = RELOC_KINDS.get(self.type)
        return k[0] if k else None

    @property
    def width(self) -> int:
        """The bytes the relocation rewrites (0 for a type of no known kind)."""
        k = RELOC_KINDS.get(self.type)
        return k[1] if k else 0

    def resolve(self, site_va: int, site_bytes: bytes, addend: int) -> int | None:
        """The address the linked site refers to, from the bytes the image holds at the site and the addend the
        object holds there: ABSOLUTE: value - addend; RELATIVE: end of the field + value - addend (REL32 counts
        from the byte after the field). None for the other kinds."""
        kind, width = RELOC_KINDS.get(self.type, (None, 0))
        mask = (1 << (8 * width)) - 1
        v = int.from_bytes(site_bytes[:width], "little")
        if kind == ABSOLUTE:
            return (v - addend) & mask
        if kind == RELATIVE:
            return (site_va + width + v - addend) & mask
        return None


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
            w = r.width
            if w:
                for k in range(r.offset, min(r.offset + w, self.size)):
                    m[k] = 1
        return bytes(m)

    def addend(self, r: Reloc) -> int:
        """The addend of a relocation: COFF keeps it in place, in the bytes the relocation rewrites."""
        return struct.unpack_from("<I", self.data, r.offset)[0] if r.width == 4 else 0

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
        return self.cls == SYM_EXTERNAL

    @property
    def named(self):
        """External or file-static: a name the section defines (section and label symbols are not)."""
        return self.cls in (SYM_EXTERNAL, SYM_STATIC)

    @property
    def unresolved(self):
        """An external this object references and another defines."""
        return self.cls == SYM_EXTERNAL and self.secnum == 0

    @property
    def dllimport(self):
        """The pointer of a dllimport reference (`__imp_X`: X's import address-table slot)."""
        return self.name.startswith(IMPORT_PREFIX)

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
        return [s for s in self.symbols.values() if s.unresolved]

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


def comp_ids(paths) -> dict[int, int]:
    """raw `@comp.id` value -> number of objects of the archives that carry it (the tool that built each
    object, as MSVC-era compilers and assemblers stamp it; the toolchain decodes the value)."""
    out: dict[int, int] = {}
    for path in paths:
        for o in archive_objects(path):
            for s in o.symbols.values():
                if s.name == COMP_ID:
                    out[s.value] = out.get(s.value, 0) + 1
                    break
    return out


@register
class Coff(ObjectFormat):
    key = "coff"

    def archive_objects(self, path):
        return archive_objects(path)

    def tool_stamps(self, paths):
        return comp_ids(paths)
