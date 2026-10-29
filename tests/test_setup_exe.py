"""server.dll and GildeGold.exe as two targets of one project (skipped when the GOG install is absent): the
pre-filled toolchain declarations pass C.toolchain on both, the exe comes clean, and its known landmarks hold
(game code to the dinput.lib tables at 0x5dd3e0, the CRT from 0x5de4a0, tail calls through the import table
inside functions)."""
from pathlib import Path

import pytest

from conftest import dcp

GAME = Path("C:/Program Files/GOG Galaxy/Games/The Guild Gold")
SERVER, EXE = GAME / "server" / "server.dll", GAME / "GildeGold.exe"
TOOLCHAIN = Path("C:/Tools/MSVC600-SP5PP")

pytestmark = pytest.mark.skipif(not (SERVER.exists() and EXE.exists() and TOOLCHAIN.exists()),
                                reason="The Guild Gold or VC6 not installed")


@pytest.fixture(scope="module")
def guild(tmp_path_factory):
    from decompanion.init import init_project
    d = tmp_path_factory.mktemp("guild")
    init_project(d, SERVER, str(TOOLCHAIN), target_name="server")
    assert dcp(d, "target", "add", "exe", str(EXE))[0] == 0
    cfg = d / "decompanion.toml"
    text = cfg.read_text()
    text = text.replace('name = "exe"\n', 'name = "exe"\narchives = ["{toolchain.root}/VC98/Lib/LIBC.LIB", '
                                          '"{toolchain.root}/VC98/Lib/DINPUT.LIB"]\n', 1)
    cfg.write_text(text, newline="\n")
    code, out = dcp(d, "setup", "--all-targets")
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
    assert syms[0x5de4a0].value["name"] == "_strrchr"
    code, out = dcp(guild, "--target", "exe", "layout", "units")
    assert "game=0x00401000..0x005dd3e0" in out
