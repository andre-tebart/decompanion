"""server.dll and GildeGold.exe as two targets of one project (skipped when the GOG install is absent): the
declared toolchains pass C.toolchain on both, the exe comes clean, and its known landmarks hold
(game code to the dinput.lib tables at 0x5dd3e0, the CRT from 0x5de4a0, tail calls through the import table
inside functions)."""
from pathlib import Path

import pytest

from conftest import dcp, declare_vc6

GAME = Path("C:/Program Files/GOG Galaxy/Games/The Guild Gold")
SERVER, EXE = GAME / "server" / "server.dll", GAME / "GildeGold.exe"
TOOLCHAIN = Path("C:/Tools/MSVC600-SP5PP")

pytestmark = pytest.mark.skipif(not (SERVER.exists() and EXE.exists() and TOOLCHAIN.exists()),
                                reason="The Guild Gold or VC6 not installed")


@pytest.fixture(scope="module")
def guild(tmp_path_factory):
    from decompanion.init import init_project
    d = tmp_path_factory.mktemp("guild")
    init_project(d, SERVER, target_name="server")
    assert dcp(d, "target", "add", "exe", str(EXE))[0] == 0
    declare_vc6(d)
    declare_vc6(d, ("LIBC", "DINPUT"), target="exe", with_root=False)
    code, out = dcp(d, "setup", "--all-targets", "--no-analyzer")      # a Ghidra export of the exe takes minutes
    assert code == 0, out
    return d


def test_declarations_and_gate(guild):
    from decompanion.config import Project
    for name in ("server", "exe"):
        d = Project(guild, name).toolchain_decl
        assert (d["compiler"], d["linker"]) == ("cl 12.00.9044", "link 6.00.8447"), name
    code, out = dcp(guild, "check")
    assert code == 0, out
    code, out = dcp(guild, "toolchain")
    assert out.count("C.toolchain: ok") == 2 and "link 5.12.9049 (Linker512 - x3)" in out


def test_exe_landmarks(guild):
    from decompanion.config import Project
    from decompanion.ledger.fact import Kind
    p = Project(guild, "exe")
    syms = {f.lo: f for f in p.store.facts(Kind.symbol)}
    # `jmp [__imp_CoUninitialize]` ends the function at 0x422d90 (reached by fall-through and by its own je)
    assert syms[0x422d90].hi == 0x422dbc and syms[0x422d90].value["skind"] == "func"
    assert syms[0x42c3a0].value["skind"] == "func" and syms[0x42c3a0].hi == 0x42c3a6     # a whole function of 6 bytes
    assert syms[0x5de450].value["skind"] == "thunk"                                      # dinput.lib's, after its tables
    assert syms[0x5dd3e0].value["unit"] == "lib:DINPUT.LIB/dilib2.obj"
    assert syms[0x465e00].hi == 0x465e6d and 0x465e70 in syms                           # W5: zlib's _tr_init ends in a jmp
    assert syms[0x4eabd0].hi == 0x4eabd5 and 0x4eabe0 in syms                           # over fill into init_block; 0x4eabd0 is just a jmp
    assert syms[0x4276a0].hi == 0x4277b5                    # W5 needs an aligned target: `jmp; int 3` inside it
    assert syms[0x5de4a0].value["name"] == "_strrchr"
    code, out = dcp(guild, "--target", "exe", "layout", "units")
    assert "game=0x00401000..0x005dd3e0" in out


def test_declared_start_and_file(guild):
    """A declared start is a walk root (its function and what it reaches are declared, not derived); a declared
    file name must be the image's string at its address."""
    from decompanion.config import Project
    from decompanion.ledger.fact import Kind, Level
    p = Project(guild, "exe")
    syms = {f.lo: f for f in p.store.facts(Kind.symbol) if f.run == "S.codewalk"}
    assert 0x4eba80 not in syms and syms[0x4eb480].hi > 0x4eba80        # the walk swallows ahm_LoadDfn
    assert dcp(guild, "--target", "exe", "decl", "add", "0x4eba80 start -- called from 0x4eb4a3 (ahm_LoadPrototypes)")[0] == 0
    assert dcp(guild, "--target", "exe", "decl", "add",
               "0x5fbd94 file tu=d3_interface path=D:\\develop\\Units\\d3\\d3_interface.c -- __FILE__")[0] == 0
    assert dcp(guild, "--target", "exe", "decl", "add", "0x5fbd94 file tu=other path=D:\\wrong.c -- __FILE__")[0] != 0  # duplicate key
    code, out = dcp(guild, "--target", "exe", "setup", "--no-analyzer")
    assert code == 0, out
    p = Project(guild, "exe")
    syms = {f.lo: f for f in p.store.facts(Kind.symbol) if f.run == "S.codewalk"}
    assert syms[0x4eba80].level is Level.declared and syms[0x4eb480].hi <= 0x4eba80
    assert syms[0x4eb480].level is Level.derived
    assert not [c for c in p.store.conflicts() if c.check == "L.decl"]


def test_import_library_from_the_image(guild, tmp_path):
    """mss32.dll has no import library in any installation: one is built from the exe's import directory, its
    members import the decorated names exactly (name type NAME) with the exe's hints."""
    import struct
    from decompanion.config import Project
    from decompanion.toolchains.vc6.implib import short_members
    p = Project(guild, "exe")
    imports = [i for i in p.image.imports() if i.dll.lower() == "mss32.dll"]
    out = tmp_path / "mss32.lib"
    assert p.toolchain.make_import_library("mss32.dll", imports, out) is None
    lib = out.read_bytes()
    members = {lib[d + 20:lib.index(b"\0", d + 20)].decode(): d for d in short_members(lib)}
    assert len(imports) == 31 and set(members) == {i.name for i in imports}
    for i in imports:
        d = members[i.name]
        assert (struct.unpack_from("<H", lib, d + 18)[0] >> 2) & 7 == 1                  # IMPORT_NAME
        assert struct.unpack_from("<H", lib, d + 16)[0] == i.hint
    # a library unit's object joins the archive (decl `libunit`): its code member next to the import members
    src = tmp_path / "member.c"
    src.write_text("int MSS_auto_cleanup(void)\n{\n    return 0;\n}\n", newline="\n")
    res = p.toolchain.compile(src, tmp_path / "member.obj", ["/O2", "/Gy"], [], tmp_path)
    assert res.ok, res.log
    assert p.toolchain.add_library_members(out, [tmp_path / "member.obj"]) is None
    from decompanion.objfmt.coff import archive_members
    names = [n for n, _ in archive_members(out)]
    assert any(n.endswith("member.obj") for n in names)
    assert len(short_members(out.read_bytes())) == 31                                 # the import members stay
