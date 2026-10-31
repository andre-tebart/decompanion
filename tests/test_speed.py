"""The speed machinery keeps every answer the same: the persisted file hashes (fsmemo), a rule run recorded again
with the same output, the plans memoised per process, and the daemon (`dcp serve`) against the in-process run."""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from conftest import dcp

from decompanion import fsmemo
from decompanion.ledger.fact import Conflict, Fact, Kind, Level, Severity
from decompanion.ledger.store import Store


def _age(path: Path, seconds: int):
    t = time.time() - seconds
    os.utime(path, (t, t))


def test_persisted_hash_trusted_only_for_an_old_unchanged_stamp(tmp_path, monkeypatch):
    monkeypatch.delenv("DCP_NO_STAMPS", raising=False)
    monkeypatch.delenv("DCP_NO_SHORTCUTS", raising=False)
    root = tmp_path / "proj"
    f = root / "src" / "a.c"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"int a;\n")
    _age(f, 60)
    fsmemo.attach(root)
    h1 = fsmemo.sha256(f)
    fsmemo.flush()
    # a new process: the memo is gone, the persisted hash answers without a read
    fsmemo.forget_all()
    fsmemo._disk_path = None
    fsmemo.attach(root)
    reads = []
    monkeypatch.setattr(fsmemo, "read_bytes", lambda p: reads.append(p) or Path(p).read_bytes())
    assert fsmemo.sha256(f) == h1 and not reads
    # same size, other content, other modification time: hashed again
    f.write_bytes(b"int b;\n")
    _age(f, 30)
    fsmemo.new_epoch()
    assert fsmemo.sha256(f) != h1 and reads


def test_racy_entry_is_hashed_again(tmp_path, monkeypatch):
    monkeypatch.delenv("DCP_NO_STAMPS", raising=False)
    monkeypatch.delenv("DCP_NO_SHORTCUTS", raising=False)
    root = tmp_path / "proj"
    f = root / "src" / "a.c"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"int a;\n")                     # modified just now: the stamp could hide a second write
    fsmemo._disk_path = None
    fsmemo.attach(root)
    fsmemo.sha256(f)
    fsmemo._sha.clear()
    fsmemo.new_epoch()
    reads = []
    monkeypatch.setattr(fsmemo, "read_bytes", lambda p: reads.append(p) or Path(p).read_bytes())
    fsmemo.sha256(f)
    assert reads


def test_walk_lists_like_rglob(tmp_path):
    for rel in ("b/z.c", "a/y.h", "a/x.c", "A2/w.C", "c.txt"):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x")
    got = [r for r, _ in fsmemo.walk(tmp_path, ("*.c", "*.h"))]
    assert got == ["a/x.c", "A2/w.C", "b/z.c", "a/y.h"]


def _facts(n=3, tag="x"):
    return [Fact(0x1000 + i, 0x1001 + i, Kind.symbol, {"skind": "func", "name": f"f{i}{tag}"}, Level.derived, "rule:T@1")
            for i in range(n)]


def _at(st, rule):
    return st.db.execute("SELECT at FROM run WHERE rule=? AND current=1", (rule,)).fetchone()[0]


def test_same_output_keeps_the_facts_and_their_ids(tmp_path):
    st = Store(tmp_path / "s.sqlite")
    rid = st.record_run("T", "1", "c", "in1", _facts(), [Conflict(Severity.warn, "X", 1, 2, "m", "a:1")], 5)
    ids, at = [f.id for f in st.facts(Kind.symbol)], _at(st, "T")
    time.sleep(0.01)
    rid2 = st.record_run("T", "1", "c", "in2", _facts(), [Conflict(Severity.warn, "X", 1, 2, "m", "a:2")], 7)
    assert rid2 == rid and _at(st, "T") == at and [f.id for f in st.facts(Kind.symbol)] == ids
    assert st.find_run("T", "in2") is not None and st.find_run("T", "in1") is None
    assert [c.a for c in st.conflicts()] == ["a:2"]                 # conflicts are written again (a / b)
    time.sleep(0.01)
    st.record_run("T", "1", "c", "in3", _facts(tag="y"), [], 1)
    # SQLite may give the new run the old id (the old row is deleted first): the run time tells them apart
    assert _at(st, "T") != at and [f.value["name"] for f in st.facts(Kind.symbol)] == ["f0y", "f1y", "f2y"]


def test_same_output_off_without_shortcuts(tmp_path, monkeypatch):
    monkeypatch.setenv("DCP_NO_SHORTCUTS", "1")
    st = Store(tmp_path / "s.sqlite")
    st.record_run("T", "1", "c", "in1", _facts(), [], 5)
    at = _at(st, "T")
    time.sleep(0.01)
    st.record_run("T", "1", "c", "in2", _facts(), [], 5)
    assert _at(st, "T") != at


def test_bytemap_names_current_facts_after_same_output_rerun(tiny):
    from decompanion.cli import open_project, refresh
    from decompanion.ledger import query
    assert dcp(tiny, "setup", "--no-analyzer")[0] == 0

    class A:
        root, target = str(tiny), None
    p, e = open_project(A())
    refresh(p, e, force=True)                       # every rule again, the same output
    query.ensure_bytemap(p.store)
    ids = {r[4] for r in p.store.bytemap_rows()}
    assert ids and all(p.store.fact(i) is not None for i in ids)


@pytest.mark.slow
def test_daemon_answers_like_the_process(tiny):
    assert dcp(tiny, "setup", "--no-analyzer")[0] == 0
    env = dict(os.environ)
    run = lambda *args: subprocess.run([sys.executable, "-m", "decompanion.client", "--root", str(tiny), *args],
                                       env=env, capture_output=True, text=True)
    no = run("map")
    assert no.returncode == 2 and "dcp serve" in no.stderr                    # no daemon: no command runs
    d = subprocess.Popen([sys.executable, "-m", "decompanion.daemon", str(tiny)], env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        info = tiny / "build" / "daemon.json"
        for _ in range(200):
            if info.exists():
                break
            time.sleep(0.05)
        assert info.exists()
        for args in (("why", "0x10001020"), ("facts", "0x10001000..0x10001060"), ("map",), ("nosuchcommand",)):
            a = run(*args)
            try:
                b = dcp(tiny, *args)
            except SystemExit as ex:                                          # argparse: the unknown command
                b = (ex.code, "")
            assert (a.returncode, a.stdout) == b, args
        st = subprocess.run([sys.executable, "-m", "decompanion.client", "serve", "--root", str(tiny), "--status"],
                            env=env, capture_output=True, text=True)
        assert "requests=4" in st.stdout
        stop = subprocess.run([sys.executable, "-m", "decompanion.client", "serve", "--root", str(tiny), "--stop"],
                              env=env, capture_output=True, text=True)
        assert stop.returncode == 0
        d.wait(timeout=20)
        assert not info.exists()
    finally:
        if d.poll() is None:
            d.kill()


@pytest.mark.slow
def test_serve_detaches_and_returns(tiny):
    """`dcp serve` returns once its daemon answers: the dcp script must not stay running (uv on Windows cannot
    replace a running .venv/Scripts/dcp.exe)."""
    assert dcp(tiny, "setup", "--no-analyzer")[0] == 0
    env = dict(os.environ)

    def serve(*args):
        return subprocess.run([sys.executable, "-m", "decompanion.client", "serve", "--root", str(tiny), *args],
                              env=env, capture_output=True, text=True, timeout=60)
    info = tiny / "build" / "daemon.json"
    try:
        start = serve()
        assert start.returncode == 0 and "started" in start.stdout, start.stderr
        assert info.exists()
        assert "pid=" in serve("--status").stdout
        assert serve().returncode == 1                       # one daemon per root
    finally:
        assert serve("--stop").returncode == 0
    for _ in range(200):
        if not info.exists():
            break
        time.sleep(0.05)
    assert not info.exists()
