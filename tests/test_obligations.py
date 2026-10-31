"""The guided decisions (obligations.py): `dcp init` declares nothing, `dcp setup` and `dcp status` name the open
obligations in order, the declarations refuse a missing reason, the rules waiting on a declaration run once it
is made, and an open toolchain or libs obligation fails `dcp session start`. On the synthetic dll, and on
server.dll when it and VC6 are installed."""
import re
import subprocess
from pathlib import Path

import pytest

from conftest import RICH_TINY, VC6, build_lib, build_pe, dcp

from decompanion.config import Project

SERVER = Path("C:/Program Files/GOG Galaxy/Games/The Guild Gold/server/server.dll")
DECISION_KEYS = ("compiler", "linker", "cflags", "archives", "root", "reason")


def obligations(out: str) -> list[str]:
    """The ids of the numbered steps of the guided status view."""
    return [m.group(1) for l in out.splitlines() if (m := re.match(r"\s*\d+\.\s+(\S+)", l))]


def flat(out: str) -> str:
    """The output with every run of whitespace (wrapped lines included) collapsed to one space."""
    return " ".join(out.split())


@pytest.fixture
def fresh(tmp_path):
    """A project of the synthetic dll made by `dcp init` (nothing declared), set up without an analyzer."""
    pe = build_pe(tmp_path / "t.dll", rich=RICH_TINY)
    root = tmp_path / "proj"
    assert dcp(tmp_path, "init", str(root), str(pe))[0] == 0
    cfg = root / "decompanion.toml"
    cfg.write_text(cfg.read_text().replace('plugin = "ghidra"', 'plugin = "none"'), newline="\n")   # no Ghidra run in tests
    return root


def test_init_writes_no_decision(fresh):
    import tomllib
    cfg = tomllib.loads((fresh / "decompanion.toml").read_text())
    assert set(cfg) == {"target", "sources", "analyzer"}            # no [toolchain], no [libs]
    assert set(cfg["target"][0]) == {"name", "path", "sha256", "image", "isa"}     # computed from the file
    assert "reason" not in cfg["analyzer"]                          # the analyzer is computed, to be confirmed
    assert not set(cfg["target"][0]) & set(DECISION_KEYS)


def test_status_after_setup_lists_the_toolchain_obligations(fresh):
    code, out = dcp(fresh, "setup", "--no-analyzer")
    assert code == 0, out
    tail = out[out.index("dcp status: t"):]
    assert "phase  setup" in tail and "open   7 (6 to do now, 1 waiting)" in tail
    assert obligations(tail) == ["toolchain.compiler", "toolchain.linker", "toolchain.root", "toolchain.cflags", "libs.archives",
                                 "analyzer", "layout"]
    assert "Rich compilers cl 12.00.8047 x5, cl 12.00.9044 x3; built" in flat(tail)
    assert "5. libs.archives      target t" in tail and "wait  on toolchain.root: declare that first" in tail
    assert "next: dcp toolchain declare compiler=" in tail
    code, again = dcp(fresh, "status")
    assert code == 0 and obligations(again) == obligations(tail)
    code, rules = dcp(fresh, "rules", "-v")
    for r in ("S.crt.code", "S.crt.refs", "S.crt.data", "S4.import.libs"):
        assert any(l.startswith(r + " ") and " waiting " in l for l in rules.splitlines()), r
    assert "    waiting: libs.archives  (dcp status)" in rules and "    waiting: toolchain.compiler, toolchain.linker  (dcp status)" in rules


def test_status_json_keeps_the_records(fresh):
    """--json is the output contract (one record per line) for scripts; the guided view is the default."""
    import json
    assert dcp(fresh, "setup", "--no-analyzer")[0] == 0
    code, out = dcp(fresh, "status", "--json")
    assert code == 0
    rows = [json.loads(l) for l in out.splitlines()]
    assert rows[0] == {"status": "t", "phase": "setup", "open": 7}
    assert [r["obligation"] for r in rows[1:]] == obligations(dcp(fresh, "status")[1])
    assert rows[1]["resolve"] == 'dcp toolchain declare compiler="<one of the Rich compilers>" --why "..."'
    assert "waits" in rows[5] and rows[5]["obligation"] == "libs.archives"


def test_declare_refuses_a_missing_why(fresh):
    before = (fresh / "decompanion.toml").read_text()
    assert dcp(fresh, "toolchain", "declare", "compiler=cl 12.00.9044")[0] == 2
    assert dcp(fresh, "toolchain", "declare", "compiler=cl 12.00.9044", "--why", "  ")[0] == 2
    assert dcp(fresh, "libs", "declare", "LIBCMT")[0] == 2
    assert dcp(fresh, "analyzer", "declare", "none")[0] == 2
    assert (fresh / "decompanion.toml").read_text() == before


def test_declarations_end_the_waits(fresh, tmp_path):
    assert dcp(fresh, "setup", "--no-analyzer")[0] == 0
    vc = tmp_path / "vc"
    vc.mkdir()
    code, out = dcp(fresh, "toolchain", "declare", "compiler=cl 12.00.9044", "linker=link 6.00.8447", f"root={vc.as_posix()}",
                    "cflags=/O2 /Gy", "--why", "the Rich builds of the user's objects")
    assert code == 0, out
    assert "C.toolchain: ok" in out and obligations(out) == ["libs.archives", "analyzer", "layout"]
    assert "flags  '/O2' '/Gy'" in out                    # the flags as stored, one token each
    p = Project(fresh)
    d = p.toolchain_decl
    assert d["reasons"] == {"root": "the Rich builds of the user's objects", "compiler": "the Rich builds of the user's objects",
                            "linker": "the Rich builds of the user's objects", "cflags": "the Rich builds of the user's objects"}
    assert d["cflags"] == ["/O2", "/Gy"]
    lib = build_lib(tmp_path / "crt.lib", [(0x0a, 8047)] * 2)
    code, out = dcp(fresh, "libs", "declare", lib.as_posix(), "--why", "the CRT objects of the Rich header")
    assert code == 0, out
    assert obligations(out) == ["analyzer", "layout"]
    text = (fresh / "decompanion.toml").read_text()
    assert f'archives = ["{lib.as_posix()}"]\nreason.archives = "the CRT objects of the Rich header"' in text
    code, rules = dcp(fresh, "rules")
    assert "waiting" not in rules.split("\n", 1)[1] and "waiting=0" in rules
    rich = next(c for c in Project(fresh).store.facts("toolchain")[0].value["compilers"] if c["build"] == 8047)
    assert rich["archive_objects"] == 2                     # S.rich reads the declared archives now
    code, out = dcp(fresh, "analyzer", "declare", "none", "--why", "no drafts in a unit test")
    assert code == 0 and obligations(out) == ["layout"]
    assert dcp(fresh, "check")[0] == 0


def test_declare_prints_each_cflag_it_stored(fresh):
    """A shell that mangled the value is visible at once: the flags line shows the tokens as they were stored."""
    assert dcp(fresh, "setup", "--no-analyzer")[0] == 0
    code, out = dcp(fresh, "toolchain", "declare", "cflags=C:/Program Files/Git/O2 /Gy", "--why", "test: a mangled value")
    assert code == 0, out
    assert "flags  'C:/Program' 'Files/Git/O2' '/Gy'" in out


def test_session_start_fails_on_an_open_obligation(fresh):
    git = lambda *a: subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *a], cwd=fresh, check=True,  # noqa: E731
                                    capture_output=True)
    git("add", "-A")
    git("commit", "-q", "-m", "init")
    code, out = dcp(fresh, "session", "start")
    assert code == 1 and "gate: FAIL" in out
    assert "obligations=5  gate=FAIL" in out and "    obligation=toolchain.compiler  target=t" in out
    code, out = dcp(fresh, "check")
    assert code == 1 and "obligation=toolchain.root" in out


# ------------------------------------------------------------------------------------------------ server.dll
@pytest.fixture(scope="module")
def server(tmp_path_factory):
    if not (SERVER.exists() and VC6.exists()):
        pytest.skip("server.dll or VC6 not installed")
    from decompanion.init import init_project
    root = tmp_path_factory.mktemp("obl") / "proj"
    init_project(root, SERVER, target_name="server")
    assert dcp(root, "setup", "--no-analyzer")[0] == 0
    return root


@pytest.mark.e2e
def test_server_status_and_libs_candidates(server):
    code, out = dcp(server, "status")
    assert obligations(out)[:5] == ["toolchain.compiler", "toolchain.linker", "toolchain.root", "toolchain.cflags", "libs.archives"]
    assert "Rich compilers cl 12.00.8047 x125, cl 12.00.9044 x37, cl 12.00.8047 x1 C++" in flat(out)
    assert "C:/Tools/MSVC600-SP5PP (cl 12.00.8804 c2 13.00.9044 link 6.00.8447; makes a Rich compiler (9044) and a Rich linker (8447))" in flat(out)
    assert dcp(server, "libs", "candidates")[0] == 2        # no root declared yet
    code, out = dcp(server, "toolchain", "declare", f"root={VC6.as_posix()}", "--why", "test: makes the Rich builds 9044 and 8447")
    assert code == 0, out
    code, out = dcp(server, "libs", "candidates")
    assert code == 0, out
    rows = [l.strip() for l in out.splitlines() if l.strip().startswith("archive=")]
    assert rows[0].startswith("archive=LIBCMT.LIB  members=637  placed=109") and rows[1].startswith("archive=LIBC.LIB  members=637  placed=75")
    assert "conflict=LIBCMT.LIB,LIBC.LIB" in out
    code, again = dcp(server, "libs", "candidates")
    assert "cached=13" in again                             # per (image, archive) like a rule run
    code, out = dcp(server, "status")
    assert "dcp libs candidates: LIBCMT.LIB placed=109, LIBC.LIB placed=75" in flat(out)
