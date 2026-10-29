"""The object-format seam: compiled objects and library archives, as the rules read them.

An object format plugin (objfmt/coff.py is the only one) reads an archive into objects. What the rules may use
of them, format-neutrally:
  Obj        name, sections (index 0 unused), code_sections, data_sections, symbols {index: Symbol}
  Section    num, name, data (None when uninitialised), size, relocs, syms (sorted by value), code, discard,
             mask() (1 for every byte a relocation rewrites), addend(reloc) (what the object holds at a site)
  Reloc      offset, symbol_index, kind (ABSOLUTE / RELATIVE / ABSOLUTE_RVA, None for any other), width,
             resolve(site_va, site_bytes, addend) -> the address the linked site refers to
  Symbol     name, value, section, defined, external, function, named (a defined name of its section: external
             or file-static), unresolved (referenced here, defined elsewhere), dllimport (a reference through an
             import address-table slot)
A relocation of a known kind rewrites `width` bytes at `offset`. ABSOLUTE: the site holds the target's address
plus the addend. RELATIVE: the site holds the target minus the end of the field (plus the addend). ABSOLUTE_RVA:
the target's address relative to the image base.
"""
from __future__ import annotations

from pathlib import Path

ABSOLUTE = "absolute"
RELATIVE = "relative"
ABSOLUTE_RVA = "absolute-rva"


class ObjectFormat:
    """Base class of an object-format plugin."""
    key = "base"

    def archive_objects(self, path: Path) -> list:
        """Every object of an archive (members that are no object, e.g. import-library short members, skipped)."""
        raise NotImplementedError

    def tool_stamps(self, paths) -> dict[int, int]:
        """raw tool stamp -> number of objects of the archives that carry it (the stamp of the tool that built
        each object; the toolchain decodes it, Toolchain.archive_tools)."""
        return {}
