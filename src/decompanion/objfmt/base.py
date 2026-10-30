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
             import address-table slot; `imported` the linker symbol it imports), constant ("string" / "float": a compiler-made literal the linker may
             pool, None for every other symbol), common (a tentative definition the linker allocates: its value is
             the size)
  Obj        functions() the defined function symbols of its code sections; function_code(symbol) -> FunctionCode
             (the bytes from the symbol to the next named symbol of its section or the section end, the
             relocation mask, the relocations inside with offsets relative to the symbol); data_symbols() the
             named data symbols with their section and size
A relocation of a known kind rewrites `width` bytes at `offset`. ABSOLUTE: the site holds the target's address
plus the addend. RELATIVE: the site holds the target minus the end of the field (plus the addend). ABSOLUTE_RVA:
the target's address relative to the image base.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

ABSOLUTE = "absolute"
RELATIVE = "relative"
ABSOLUTE_RVA = "absolute-rva"


@dataclass(frozen=True)
class FunctionCode:
    """One compiled function of an object: `data` its bytes (from the function symbol to the next named symbol
    of its section, or the section's end), `mask` 1 for every byte a relocation rewrites, `relocs` the
    relocations inside as (offset from the function start, Reloc, Symbol the relocation refers to), `section`
    the section, `start` the function's offset in it, `code_len` the bytes of instructions before the data the
    compiler puts after them in the same section (a switch's jump table), None when there is none. The byte
    compare takes `data` whole; instruction listings and code sizes take `code_data` / `code_mask`."""
    symbol: object
    section: object
    start: int
    data: bytes
    mask: bytes
    relocs: tuple
    code_len: int | None = None

    @property
    def size(self):
        return len(self.data)

    @property
    def code_data(self) -> bytes:
        return self.data if self.code_len is None else self.data[:self.code_len]

    @property
    def code_mask(self) -> bytes:
        return self.mask if self.code_len is None else self.mask[:self.code_len]


class ObjectFormat:
    """Base class of an object-format plugin."""
    key = "base"

    def read_object(self, path: Path):
        """One compiled object file (Obj)."""
        raise NotImplementedError

    def import_symbols(self, path: Path) -> dict[str, tuple[str, str]]:
        """symbol -> (dll, imported name or `#ordinal`) of an import library's import members."""
        return {}

    def alias_object(self, path: Path, aliases: list[tuple[str, str]]) -> None:
        """Write an object that makes each linker symbol `alias` resolve to the linker symbol `canonical` (the
        several typed names of one original symbol link as one address)."""
        raise NotImplementedError

    def archive_objects(self, path: Path) -> list:
        """Every object of an archive (members that are no object, e.g. import-library short members, skipped)."""
        raise NotImplementedError

    def tool_stamps(self, paths) -> dict[int, int]:
        """raw tool stamp -> number of objects of the archives that carry it (the stamp of the tool that built
        each object; the toolchain decodes it, Toolchain.archive_tools)."""
        return {}
