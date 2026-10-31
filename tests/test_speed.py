"""The speed machinery keeps every answer the same: the byte map after a rerun with the same output, and the daemon
(`dcp serve`) against the in-process run. (A run recorded again with the same output and the persisted file hashes
are tested in the core: lib.rs, fsmemo.rs.)"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from conftest import dcp



def test_bytemap_names_current_facts_after_same_output_rerun(tiny):
    from decompanion.cli import open_project, refresh
    assert dcp(tiny, "setup", "--no-analyzer")[0] == 0

    class A:
        root, target = str(tiny), None
    p, e = open_project(A())
    refresh(p, e, force=True)                       # every rule again, the same output
    p.store.ensure_bytemap()
    ids = {r[4] for r in p.store.bytemap_rows()}
    assert ids and all(p.store.fact(i) is not None for i in ids)


@pytest.mark.e2e
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


@pytest.mark.e2e
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
