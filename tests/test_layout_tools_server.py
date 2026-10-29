"""The layout tooling on server.dll (skipped when the GOG install is absent; the Ghidra export when Ghidra or its
JDK is absent): one project per module, exported once."""
from pathlib import Path

import pytest

from conftest import dcp

from decompanion.config import Project

SERVER = Path("C:/Program Files/GOG Galaxy/Games/The Guild Gold/server/server.dll")
TOOLCHAIN = Path("C:/Tools/MSVC600-SP5PP")
pytestmark = pytest.mark.skipif(not SERVER.exists(), reason="server.dll not installed")


def ghidra_ready() -> bool:
    try:
        from decompanion.build import ghidra as GX
        p = Project.__new__(Project)
        p.cfg = {}
        p.expand = lambda s: Path(s)
        GX.locate(p)
        return True
    except Exception:
        return False


@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    from decompanion.init import init_project
    root = tmp_path_factory.mktemp("srv") / "proj"
    init_project(root, SERVER, TOOLCHAIN.as_posix(), target_name="server")
    cfg = root / "decompanion.toml"
    text = cfg.read_text()
    text = text.replace('reason = "picked at init', 'archives = ["{toolchain.root}/VC98/Lib/LIBCMT.LIB"]\nreason = "picked at init', 1)
    cfg.write_text(text, newline="\n")
    assert dcp(root, "setup")[0] == 0
    return root


def test_reading_tools_on_server(srv):
    code, out = dcp(srv, "layout", "starts", "0x10008c00..0x10009000")
    assert code == 0 and "starts=6" in out
    assert "start=0x10008cc0  how=export" in out and "start=0x10008d20  how=immediate" in out
    code, out = dcp(srv, "layout", "literals", "0x10008c00..0x10009000")
    assert "fn=0x10008d20" in out and "first_used=10" in out and "text=GamePath" in out
    code, out = dcp(srv, "disasm", "Init")
    assert "push 0x10008d20" in out and "<_beginthread>" in out
    code, out = dcp(srv, "dump", "0x10027d08", "0x20", "--str")
    assert "text=General" in out and "text=GamePath" in out
    code, out = dcp(srv, "refs", "Init")
    assert "named=Init  origin=export" in out


@pytest.mark.skipif(not ghidra_ready(), reason="Ghidra or its JDK not found")
def test_ghidra_export_and_draft(srv):
    code, out = dcp(srv, "ghidra", "export")
    assert code == 0 and "exported=" in out and "failed=0" in out, out
    code, out = dcp(srv, "ghidra", "export")
    assert "export=up-to-date" in out                       # the same image, script and starts: nothing runs
    code, out = dcp(srv, "ghidra", "status")
    assert "game_functions=311" in out and "with_draft=311" in out and "ours_only=0" in out and "l9=0" in out, out
    code, out = dcp(srv, "ghidra", "show", "0x10008cc0")
    assert code == 0 and "FUN_10019af5(FUN_10008d20" in out    # Ghidra's own names
    assert dcp(srv, "unit", "new", "dllmain", "--range", "0x10008cb0..0x10008d20", "--by", "guess",
               "--why", "DllMain, Init and Exit")[0] == 0
    for a in ("0x10008cb0", "0x10008cc0", "0x10008cf0"):          # --next is the game code's first open function
        code, out = dcp(srv, "draft", a)
        assert code == 0 and "body=ghidra" in out, out
    init = (srv / "src/dllmain/f_10008cc0.c").read_text()
    # the export's name, the library member's name, the placeholder of a function in no unit yet
    assert init.startswith("/* 0x10008cc0, Init */") and "_beginthread(unk_10008d20,0,param_1)" in init
    head = (srv / "src/dllmain/head.c").read_text()
    assert "#include <process.h>" in head                   # _beginthread: the CRT header that declares it
