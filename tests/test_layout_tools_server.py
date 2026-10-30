"""The layout tooling on server.dll (skipped when the GOG install is absent; the Ghidra export when Ghidra or its
JDK is absent): one project per module, exported once (by dcp setup). The export test is marked `ghidra` and
deselected by default (pyproject addopts): `uv run pytest -m ghidra` runs it."""
from pathlib import Path

import pytest

from conftest import dcp, declare_vc6


SERVER = Path("C:/Program Files/GOG Galaxy/Games/The Guild Gold/server/server.dll")
TOOLCHAIN = Path("C:/Tools/MSVC600-SP5PP")
pytestmark = pytest.mark.skipif(not (SERVER.exists() and TOOLCHAIN.exists()), reason="server.dll or VC6 not installed")


def ghidra_ready() -> bool:
    from decompanion import analyzers
    return analyzers.get("ghidra")({}, None).available().ok


@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    from decompanion.init import init_project
    root = tmp_path_factory.mktemp("srv") / "proj"
    init_project(root, SERVER, target_name="server")
    declare_vc6(root, ("LIBCMT",))
    assert dcp(root, "setup", "--no-analyzer")[0] == 0
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


@pytest.mark.ghidra          # 30 s of Ghidra headless: deselected by default, `uv run pytest -m ghidra` runs it
@pytest.mark.skipif(not ghidra_ready(), reason="Ghidra or its JDK not found")
def test_ghidra_export_and_draft(srv):
    assert 'plugin = "ghidra"' in (srv / "decompanion.toml").read_text()      # dcp init found it
    code, out = dcp(srv, "setup")
    assert code == 0 and "analyzer=ghidra  exported=678  failed=0" in out, out
    code, out = dcp(srv, "setup")
    assert "exported=" not in out and "export=up-to-date" in out    # the same image, script and starts: nothing runs
    assert "game_functions=311" in out and "with_draft=311" in out and "ours_only=0" in out and "l9=0" in out, out
    code, out = dcp(srv, "draft", "0x10008cc0", "--show")
    assert code == 0 and "FUN_10019af5(FUN_10008d20" in out    # Ghidra's own names
    assert dcp(srv, "unit", "new", "dllmain", "--range", "0x10008cb0..0x10008d20", "--by", "guess",
               "--why", "DllMain, Init and Exit")[0] == 0
    for a in ("0x10008cb0", "0x10008cc0", "0x10008cf0"):          # --next is the game code's first open function
        code, out = dcp(srv, "draft", a)
        assert code == 0 and "body=ghidra" in out, out
    text = (srv / "src/dllmain.c").read_text()
    init = text[text.index("/* 0x10008cc0"):text.index("/* 0x10008cf0")]
    # the export's name, the library member's name, the placeholder of a function in no unit yet
    assert init.startswith("/* 0x10008cc0, Init */") and "_beginthread(unk_10008d20,0,param_1)" in init
    head = text[:text.index("/* 0x10008cb0")]
    assert "#include <process.h>" in head                   # _beginthread: the CRT header that declares it
