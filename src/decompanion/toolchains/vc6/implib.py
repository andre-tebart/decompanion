"""An import library from the image's own import directory (lifted from the first attempt's tools/make_mss32.py).

For a DLL whose import library no installation holds (GildeGold.exe's mss32.dll: the Miles SDK was commercial and
is not archived) the image's import directory names every function the program imports, so the library is
recoverable from it. LIB.EXE /DEF writes it; two things are patched in each short-format import member
afterwards (Microsoft PE/COFF: the import header, name type in bits 2..4 of the type word, hint at offset 16):

- the name type: LIB names a member `_name` with name type NOPREFIX (the import name drops the leading `_`).
  A DLL that exports a decorated stdcall name (`_AIL_startup@0`) needs name type NAME (import by the stored
  symbol exactly), so whenever the image's import name is the stored symbol itself the member gets NAME;
- the hint: the image's own hint, so a linked image's import table carries the original's hints.
"""
from __future__ import annotations

import struct
from pathlib import Path

NAME, NOPREFIX = 1, 2


def short_members(lib: bytes) -> list[int]:
    """The data offsets of the short-format import members (signature 0 / 0xffff) of an archive."""
    out, i = [], 8
    while i + 60 <= len(lib):
        size = int(lib[i + 48:i + 58])
        d = i + 60
        if lib[d:d + 4] == b"\0\0\xff\xff":
            out.append(d)
        i += 60 + size + (size & 1)
    return out


def make_import_library(tools, dll: str, imports: list, out: Path) -> str | None:
    named = [i for i in imports if i.name]
    if len(named) != len(imports):
        return "it imports by ordinal (not supported)"
    if not named:
        return "nothing is imported by name"
    out.parent.mkdir(parents=True, exist_ok=True)
    def_file = out.with_suffix(".def")
    # LIB prefixes `_`: an import name that has one is written without it, so the stored symbol is the name
    lines = [i.name[1:] if i.name.startswith("_") else i.name for i in named]
    def_file.write_text(f"; built by dcp link from the image's import directory\nLIBRARY {Path(dll).stem}\nEXPORTS\n"
                        + "".join(f"    {n}\n" for n in lines), newline="\n")
    r = tools.run("LIB.EXE", ["/NOLOGO", f"/DEF:{def_file.name}", f"/OUT:{out.name}", "/MACHINE:IX86"], out.parent)
    if r.returncode or not out.exists():
        return f"LIB.EXE failed: {(r.stdout + r.stderr).strip()[:300]}"
    lib = bytearray(out.read_bytes())
    by_symbol = {}
    for d in short_members(bytes(lib)):
        end = lib.index(b"\0", d + 20)
        by_symbol[lib[d + 20:end].decode("latin-1")] = d
    for i in named:
        stored = i.name if i.name.startswith("_") else "_" + i.name
        d = by_symbol.get(stored)
        if d is None:
            return f"LIB.EXE wrote no member for {i.name}"
        word = struct.unpack_from("<H", lib, d + 18)[0]
        if i.name == stored:                     # the DLL exports the decorated name itself
            word = (word & ~(0x7 << 2)) | (NAME << 2)
        struct.pack_into("<H", lib, d + 18, word)
        struct.pack_into("<H", lib, d + 16, i.hint or 0)
    out.write_bytes(bytes(lib))
    return None
