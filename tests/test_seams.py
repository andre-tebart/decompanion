"""The plugin seams: the registries, the format-neutral relocation view of objfmt, the toolchain's import stubs,
user entries and defaults, the instruction-set decoder the walk reads, and `dcp init` naming its plugins."""
import struct

import pytest

from conftest import build_pe, dcp

from decompanion import image, isa, objfmt, toolchains
from decompanion.config import ConfigError, Project
from decompanion.objfmt.base import ABSOLUTE, ABSOLUTE_RVA, RELATIVE
from decompanion.objfmt.coff import DIR32, DIR32NB, REL32, Reloc, Section


# ------------------------------------------------------------------------------------------------ registries
def test_registries():
    assert "pe32" in image.FORMATS and "vc6" in toolchains.TOOLCHAINS
    assert "coff" in objfmt.FORMATS and "x86" in isa.ISAS
    assert toolchains.default_key() == "vc6" and image.default_key() == "pe32"


def test_project_plugins(tiny):
    p = Project(tiny)
    assert p.image.key == "pe32" and p.image.default_isa == "x86"
    assert p.isa.key == "x86" and p.objfmt.key == "coff" and p.toolchain.key == "vc6"


def test_declared_isa(tiny):
    cfg = tiny / "decompanion.toml"
    cfg.write_text(cfg.read_text().replace('image = "pe32"\n', 'image = "pe32"\nisa = "x86"\n', 1), newline="\n")
    assert Project(tiny).isa.key == "x86"
    cfg.write_text(cfg.read_text().replace('isa = "x86"', 'isa = "z80"', 1), newline="\n")
    with pytest.raises(ConfigError, match="unknown instruction set 'z80'"):
        Project(tiny).isa


# ------------------------------------------------------------------------------------------------ objfmt
def test_reloc_view():
    assert (Reloc(0, 0, DIR32).kind, Reloc(0, 0, DIR32).width) == (ABSOLUTE, 4)
    assert (Reloc(0, 0, REL32).kind, Reloc(0, 0, DIR32NB).kind) == (RELATIVE, ABSOLUTE_RVA)
    assert (Reloc(0, 0, 0x0b).kind, Reloc(0, 0, 0x0b).width) == (None, 0)        # SECREL: no image bytes
    site = 0x401010
    # absolute: the image holds target + addend
    assert Reloc(0, 0, DIR32).resolve(site, struct.pack("<I", 0x405008), 8) == 0x405000
    # relative: the image holds target - (site + 4) + addend
    disp = (0x402000 - (site + 4)) & 0xffffffff
    assert Reloc(0, 0, REL32).resolve(site, struct.pack("<I", disp), 0) == 0x402000
    assert Reloc(0, 0, DIR32NB).resolve(site, b"\0\0\0\0", 0) is None


def test_section_mask_and_addend():
    data = b"\xe8" + struct.pack("<i", -4) + b"\xa1" + struct.pack("<I", 0x10) + b"\xc3"
    relocs = [Reloc(1, 0, REL32), Reloc(6, 0, DIR32), Reloc(0, 0, 0x0b)]
    sec = Section(None, 1, ".text", 0x60000020, data, len(data), relocs)
    assert sec.mask() == bytes([0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0])
    assert sec.addend(relocs[1]) == 0x10 and sec.addend(relocs[0]) == 0xfffffffc


# ------------------------------------------------------------------------------------------------ toolchain
def test_vc6_import_stubs():
    tc = toolchains.TOOLCHAINS["vc6"](None, {})
    data = b"\xcc" + b"\xff\x25" + struct.pack("<I", 0x10002000) + b"\xff\x25" + struct.pack("<I", 0x10002004) + b"\xff\x25\x00"
    assert list(tc.import_stubs(data)) == [(1, 0x10002000), (7, 0x10002004)]        # the truncated one is no stub
    assert tc.import_stub_size == 6 and tc.function_alignment == 16 and tc.stub_placement


def test_vc6_entries_and_defaults():
    tc = toolchains.TOOLCHAINS["vc6"](None, {})
    names = tc.user_entry_names()
    assert names == {"_DllMain@12": "DllMain", "_main": "main", "_WinMain@16": "WinMain", "_wmain": "wmain",
                     "_wWinMain@16": "wWinMain"}
    assert tc.crt_user_entry("__DllMainCRTStartup@12") == "_DllMain@12"
    assert tc.crt_user_entry("_wWinMainCRTStartup") == "_wWinMain@16"
    assert tc.wizard_cflags() == ["/O2", "/Gy"] and tc.archive_spec("libcmt") == "{toolchain.root}/VC98/Lib/LIBCMT.LIB"
    assert tc.archive_spec("C:/x/my.lib") == "C:/x/my.lib"
    assert tc.import_library_name("KERNEL32.dll") == "kernel32.lib"
    assert (tc.fill_origin(b"\xcc\xcc"), tc.fill_origin(b"\x90\x8b\xff"), tc.fill_origin(b"\x90\xcc")) == ("cc", "nop", "mixed")
    assert tc.archive_tools({(0x0a << 16) | 8047: 3, (0x30 << 16) | 9044: 1}) == {(0x0a, 8047): 3, (0x30, 9044): 1}


# ------------------------------------------------------------------------------------------------ isa
class Code:
    """A stand-in image holding code at 0x1000."""
    base, end = 0x1000, 0x3000

    def __init__(self, code):
        self.code = code

    def read(self, va, n):
        o = va - 0x1000
        return (self.code[o:o + n] + bytes(n))[:n]


# ------------------------------------------------------------------------------------------------ init
def test_init_names_plugins(tmp_path):
    pe = build_pe(tmp_path / "t.dll")
    from decompanion.cli import main
    assert main(["init", str(tmp_path / "proj"), str(pe)]) == 0
    text = (tmp_path / "proj" / "decompanion.toml").read_text()
    assert 'image = "pe32"\nisa = "x86"\n' in text          # computed from the file; nothing is declared
    p = Project(tmp_path / "proj")
    assert p.toolchain.key == "vc6"                         # the only registered plugin, without a [toolchain] table
    assert p.target().isa == "x86" and p.isa.key == "x86"
    code, out = dcp(tmp_path / "proj", "target", "list")
    assert "isa=x86" in out
