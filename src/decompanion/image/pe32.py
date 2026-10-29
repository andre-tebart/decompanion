"""PE32 (i386) images: exe and dll. Everything the setup rules read comes through this class; the rules never
touch file offsets themselves.
"""
from __future__ import annotations

import struct
from pathlib import Path

from . import register
from .base import DataDirectory, Export, Image, Import, Section

DIRECTORY_NAMES = ["export", "import", "resource", "exception", "security", "basereloc", "debug", "architecture",
                   "globalptr", "tls", "load_config", "bound_import", "iat", "delay_import", "com_descriptor", "reserved"]
# The directories S.imports / S.exports walk themselves (import, export, iat) or that lie outside the mapped image
# (security: a file offset, not an RVA).
NOT_REGIONS = ("import", "export", "iat", "security")
MACHINE_ISA = {0x14c: "x86"}        # IMAGE_FILE_MACHINE_I386


@register
class PE32(Image):
    key = "pe32"
    ptr_size = 4

    def __init__(self, path: Path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        d = self.data
        if d[:2] != b"MZ":
            raise ValueError(f"{path}: no MZ header")
        self.pe = pe = struct.unpack_from("<I", d, 0x3c)[0]
        if d[pe:pe + 4] != b"PE\0\0":
            raise ValueError(f"{path}: no PE signature at {pe:#x}")
        (self.machine, nsec, self.timestamp, _symptr, _nsym, optsz, self.file_chars) = struct.unpack_from("<HHIIIHH", d, pe + 4)
        opt = pe + 24
        magic = struct.unpack_from("<H", d, opt)[0]
        if magic != 0x10b:
            raise ValueError(f"{path}: optional header magic {magic:#x} is not PE32")
        self.linker_version = (d[opt + 2], d[opt + 3])
        (self.size_of_code, self.size_of_init, self.size_of_uninit, entry_rva, _base_code, _base_data, self.base,
         self.section_align, self.file_align) = struct.unpack_from("<IIIIIIIII", d, opt + 4)
        (self.image_size, self.headers_size) = struct.unpack_from("<II", d, opt + 56)
        self.checksum = struct.unpack_from("<I", d, opt + 64)[0]
        self.subsystem, self.dll_chars = struct.unpack_from("<HH", d, opt + 68)
        ndirs = struct.unpack_from("<I", d, opt + 92)[0]
        self.directories = []
        for i in range(min(ndirs, 16)):
            rva, size = struct.unpack_from("<II", d, opt + 96 + 8 * i)
            self.directories.append(DataDirectory(i, DIRECTORY_NAMES[i], self.base + rva if rva else 0, size))
        self.is_dll = bool(self.file_chars & 0x2000)
        self.entry = self.base + entry_rva if entry_rva else 0
        self.sections = []
        self.section_table = opt + optsz
        for k in range(nsec):
            h = self.section_table + 40 * k
            name = d[h:h + 8].rstrip(b"\0").decode("latin-1")
            vsize, va, rsize, roff = struct.unpack_from("<IIII", d, h + 8)
            chars = struct.unpack_from("<I", d, h + 36)[0]
            self.sections.append(Section(k, name, self.base + va, vsize, roff, rsize, chars))

    def directory(self, name: str) -> DataDirectory | None:
        for dd in self.directories:
            if dd.name == name and dd.va:
                return dd
        return None

    @property
    def kind(self):
        """dll (the DLL characteristic), gui (subsystem 2, WINDOWS_GUI), console (3, WINDOWS_CUI), else exe."""
        if self.is_dll:
            return "dll"
        return {2: "gui", 3: "console"}.get(self.subsystem, "exe")

    @property
    def default_isa(self):
        return MACHINE_ISA.get(self.machine)

    # ------------------------------------------------------------------ regions
    def header_regions(self):
        """The PE headers own [image base, image base + SizeOfHeaders): DOS header and stub, PE signature, file
        and optional headers, section table (pe.header), and the Rich header where the linker wrote one
        (pe.rich)."""
        lo, hi = self.base, self.base + self.headers_size
        rich = self.rich_range()
        if rich:
            return [("pe.header", a, b) for a, b in ((lo, rich[0]), (rich[1], hi)) if b > a] + [("pe.rich", rich[0], rich[1])]
        return [("pe.header", lo, hi)]

    def directory_regions(self):
        """pe.<directory name> for every data directory with an address and a size inside a section, except
        import / export / iat (their machinery is import_regions / export_regions) and security (a file
        offset)."""
        out = []
        for dd in self.directories:
            if not dd.va or not dd.size or dd.name in NOT_REGIONS:
                continue
            if self.section_of(dd.va) is None:
                continue
            out.append(("pe." + dd.name, dd.va, dd.va + dd.size))
        return out

    def import_regions(self):
        """pe.import_desc (descriptors), pe.ilt (lookup tables), pe.names (DLL names, hint/name strings), pe.iat
        (the terminating zero slot of each address table)."""
        r = self.import_descriptor_ranges()
        out = [("pe.import_desc", a, b) for a, b in r["pe.import_desc"]]
        out += [("pe.ilt", a, b) for a, b in r["pe.ilt"]]
        out += [("pe.names", a, b) for a, b in sorted(set(r["pe.names"]))]
        out += [("pe.iat", b - 4, b) for _, b in r["pe.iat"]]
        return out

    def export_regions(self):
        """pe.export_dir, pe.eat, pe.ent, pe.eot (the export directory and its address, name pointer and ordinal
        tables) and pe.names (the DLL name and the export names)."""
        r = self.export_ranges()
        out = [(what, a, b) for what in ("pe.export_dir", "pe.eat", "pe.ent", "pe.eot") for a, b in r[what]]
        out += [("pe.names", a, b) for a, b in sorted(set(r["pe.names"]))]
        return out

    # ------------------------------------------------------------------ imports
    def imports(self) -> list[Import]:
        dd = self.directory("import")
        if dd is None:
            return []
        out = []
        desc = dd.va
        while True:
            ilt_rva, _ts, _fwd, name_rva, iat_rva = struct.unpack_from("<IIIII", self.read(desc, 20))
            if name_rva == 0 and iat_rva == 0:
                break
            dll = self.cstr(self.base + name_rva).decode("latin-1")
            lookup = self.base + (ilt_rva or iat_rva)
            slot = self.base + iat_rva
            k = 0
            while True:
                e = self.u32(lookup + 4 * k)
                if e == 0:
                    break
                if e & 0x80000000:
                    out.append(Import(dll, None, e & 0xffff, slot + 4 * k))
                else:
                    out.append(Import(dll, self.cstr(self.base + e + 2).decode("latin-1"), None, slot + 4 * k))
                k += 1
            desc += 20
        return out

    def import_descriptor_ranges(self) -> dict[str, list[tuple[int, int]]]:
        """The byte ranges of the import machinery: descriptors, lookup tables, address tables, name strings."""
        dd = self.directory("import")
        out: dict[str, list[tuple[int, int]]] = {"pe.import_desc": [], "pe.ilt": [], "pe.iat": [], "pe.names": []}
        if dd is None:
            return out
        desc = dd.va
        n = 0
        while True:
            ilt_rva, _ts, _fwd, name_rva, iat_rva = struct.unpack_from("<IIIII", self.read(desc + 20 * n, 20))
            if name_rva == 0 and iat_rva == 0:
                break
            dll_name = self.base + name_rva
            out["pe.names"].append((dll_name, dll_name + len(self.cstr(dll_name)) + 1))
            for key, rva in (("pe.ilt", ilt_rva), ("pe.iat", iat_rva)):
                if not rva:
                    continue
                t = self.base + rva
                k = 0
                while self.u32(t + 4 * k):
                    e = self.u32(t + 4 * k)
                    if not e & 0x80000000 and key == "pe.ilt":
                        hn = self.base + e
                        out["pe.names"].append((hn, hn + 2 + len(self.cstr(hn + 2)) + 1))
                    k += 1
                out[key].append((t, t + 4 * (k + 1)))
            n += 1
        out["pe.import_desc"].append((desc, desc + 20 * (n + 1)))
        return out

    # ------------------------------------------------------------------ exports
    def exports(self) -> list[Export]:
        dd = self.directory("export")
        if dd is None:
            return []
        e = dd.va
        (_flags, _ts, _maj, _min, _name_rva, ordinal_base, nfunc, nnames, eat_rva, ent_rva, eot_rva) = \
            struct.unpack_from("<IIHHIIIIIII", self.read(e, 40))
        names = {}
        for i in range(nnames):
            nr = self.u32(self.base + ent_rva + 4 * i)
            oi = self.u16(self.base + eot_rva + 2 * i)
            names[oi] = self.cstr(self.base + nr).decode("latin-1")
        out = []
        for i in range(nfunc):
            rva = self.u32(self.base + eat_rva + 4 * i)
            if rva == 0:
                continue
            fwd = None
            if dd.va <= self.base + rva < dd.va + dd.size:
                fwd = self.cstr(self.base + rva).decode("latin-1")
            out.append(Export(ordinal_base + i, names.get(i), self.base + rva, fwd))
        return out

    def export_ranges(self) -> dict[str, list[tuple[int, int]]]:
        dd = self.directory("export")
        out: dict[str, list[tuple[int, int]]] = {"pe.export_dir": [], "pe.eat": [], "pe.ent": [], "pe.eot": [], "pe.names": []}
        if dd is None:
            return out
        e = dd.va
        (_flags, _ts, _maj, _min, name_rva, _ob, nfunc, nnames, eat_rva, ent_rva, eot_rva) = \
            struct.unpack_from("<IIHHIIIIIII", self.read(e, 40))
        out["pe.export_dir"].append((e, e + 40))
        out["pe.eat"].append((self.base + eat_rva, self.base + eat_rva + 4 * nfunc))
        if nnames:
            out["pe.ent"].append((self.base + ent_rva, self.base + ent_rva + 4 * nnames))
            out["pe.eot"].append((self.base + eot_rva, self.base + eot_rva + 2 * nnames))
        for va in [self.base + name_rva] + [self.base + self.u32(self.base + ent_rva + 4 * i) for i in range(nnames)]:
            out["pe.names"].append((va, va + len(self.cstr(va)) + 1))
        return out

    # ------------------------------------------------------------------ relocations
    def relocations(self) -> list[int]:
        dd = self.directory("basereloc")
        if dd is None:
            return []
        out = []
        p, end = dd.va, dd.va + dd.size
        while p + 8 <= end:
            page_rva, block = struct.unpack_from("<II", self.read(p, 8))
            if block < 8:
                break
            entries = self.read(p + 8, block - 8)
            for i in range(0, len(entries) - 1, 2):
                e = entries[i] | (entries[i + 1] << 8)
                typ, off = e >> 12, e & 0xfff
                if typ == 3:          # IMAGE_REL_BASED_HIGHLOW
                    out.append(self.base + page_rva + off)
            p += block
        out.sort()
        return out

    def reloc_range(self) -> tuple[int, int] | None:
        dd = self.directory("basereloc")
        return (dd.va, dd.va + dd.size) if dd else None

    # ------------------------------------------------------------------ rich header
    def rich(self) -> list[tuple[int, int, int]]:
        d = self.data[:self.pe]
        i = d.find(b"Rich")
        if i < 0 or i + 8 > len(d):
            return []
        key = struct.unpack_from("<I", d, i + 4)[0]
        # find DanS: the first dword (xor key) equal to "DanS" scanning back from "Rich"
        j = i - 4
        start = None
        while j >= 0:
            if struct.unpack_from("<I", d, j)[0] ^ key == 0x536e6144:
                start = j
                break
            j -= 4
        if start is None:
            return []
        out = []
        p = start + 16                      # DanS + 3 padding dwords
        while p + 8 <= i:
            a, b = struct.unpack_from("<II", d, p)
            a ^= key
            b ^= key
            out.append((a >> 16, a & 0xffff, b))
            p += 8
        return out

    def rich_range(self) -> tuple[int, int] | None:
        d = self.data[:self.pe]
        i = d.find(b"Rich")
        if i < 0:
            return None
        key = struct.unpack_from("<I", d, i + 4)[0]
        j = i - 4
        while j >= 0:
            if struct.unpack_from("<I", d, j)[0] ^ key == 0x536e6144:
                return (self.base + j, self.base + i + 8)
            j -= 4
        return None
