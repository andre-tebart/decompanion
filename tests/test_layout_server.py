"""Layout on server.dll (skipped when the GOG install is absent): Init's unit declared, a wrong boundary and a
dead-bytes declaration over walked code fail the gate."""
from pathlib import Path

import pytest

from conftest import dcp, declare_vc6

SERVER = Path("C:/Program Files/GOG Galaxy/Games/The Guild Gold/server/server.dll")
TOOLCHAIN = Path("C:/Tools/MSVC600-SP5PP")

pytestmark = pytest.mark.skipif(not (SERVER.exists() and TOOLCHAIN.exists()), reason="server.dll or VC6 not installed")


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    from decompanion.init import init_project
    d = tmp_path_factory.mktemp("guild-server")
    init_project(d, SERVER)
    declare_vc6(d)
    code, out = dcp(d, "setup", "--no-analyzer")      # the Ghidra export is test_layout_tools_server's (-m ghidra)
    assert code == 0
    return d


def set_decl(root, text):
    (root / "decl" / "text.dcl").write_text("# code\n" + text, newline="\n")


def test_init_unit(server):
    set_decl(server, "")
    code, out = dcp(server, "decl", "add", "0x10008cb0 boundary start tu=dllmain by=guess -- DllMain, Init and Exit: the entry points")
    assert code == 0, out
    code, out = dcp(server, "decl", "add", "0x10008d20 boundary end tu=dllmain -- the thread procedure Init starts begins the next unit")
    assert code == 0, out
    code, out = dcp(server, "layout", "units")
    line = next(l for l in out.splitlines() if l.startswith("unit=dllmain"))
    assert "range=0x10008cb0..0x10008d20" in line and "status=separated" in line and "functions=3" in line
    code, out = dcp(server, "check")
    assert code == 0, out
    code, out = dcp(server, "layout", "next", "--start", "0x10008cb0")
    assert "next=0x10008cb0" in out and "unit=dllmain" in out


def test_wrong_boundary_fails(server):
    set_decl(server, "0x10008cc5 boundary start tu=bad -- inside Init on purpose\n")
    code, out = dcp(server, "check")
    assert code == 1 and "L4" in out and "inside the function 0x10008cc0" in out


def test_dead_bytes_over_walked_code_fail(server):
    set_decl(server, "0x10008cd0..0x10008ce0 bytes dead -- the walk reaches these\n")
    code, out = dcp(server, "check")
    assert code == 1 and "L6" in out


def test_walk_crossing_a_source_fails(server):
    set_decl(server, "")
    src = server / "src" / "inside.c"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text("/* 0x10008cc5, a start inside Init */\nvoid f(void)\n{\n}\n", newline="\n")
    try:
        code, out = dcp(server, "check")
        assert code == 1 and "L1" in out and "src/inside.c:1: f starts at 0x10008cc5" in out, out
    finally:
        src.unlink()
    assert dcp(server, "check")[0] == 0
