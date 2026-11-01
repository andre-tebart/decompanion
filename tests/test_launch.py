"""launch.py: a launch spec's steps, program and `after` steps (no project, no core: Python itself is the program)."""
import json
import sys

import pytest

from decompanion import launch

process = pytest.mark.e2e      # starts processes (pyproject: a process is end to end)


def spec(tmp_path, **kw):
    s = {"run": "play", "root": str(tmp_path), "dir": str(tmp_path), "exe": sys.executable, "args": [], "env": {},
         "seconds": 0, "steps": [], "after": [], "hook_env": {"DCP_RUN_DIR": str(tmp_path), "DCP_EXE": sys.executable}}
    s.update(kw)
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(s))
    return str(path)


def py(code):
    return [sys.executable, "-c", code]


@process
def test_steps_program_and_after(tmp_path):
    out = tmp_path / "log"
    step = py(f"import os; open(r'{out}', 'a').write('step ' + os.environ['DCP_RUN_DIR'] + '\\n')")
    prog = ["-c", f"import os, sys; open(r'{out}', 'a').write('prog ' + os.environ['START'] + ' ' + sys.argv[1] + '\\n'); sys.exit(3)", "x"]
    after = py(f"import os; open(r'{out}', 'a').write('after ' + os.environ['DCP_EXIT'] + '\\n')")
    rc = launch.launch(spec(tmp_path, steps=[step], args=prog, env={"START": "new"}, after=[after]))
    assert rc == 3
    assert out.read_text().splitlines() == [f"step {tmp_path}", "prog new x", "after 3"]


@process
def test_failing_step_stops_the_run(tmp_path):
    out = tmp_path / "log"
    prog = ["-c", f"open(r'{out}', 'w').write('started')"]
    assert launch.launch(spec(tmp_path, steps=[py("import sys; sys.exit(5)")], args=prog)) == 5
    assert not out.exists()


@process
def test_time_limit_terminates(tmp_path):
    rc = launch.launch(spec(tmp_path, args=["-c", "import time; time.sleep(30)"], seconds=0.3))
    assert rc == 0


def test_handoff(tmp_path, monkeypatch):
    target = tmp_path / "handoff.txt"
    monkeypatch.delenv(launch.HANDOFF, raising=False)
    assert not launch.handoff("x.json")
    monkeypatch.setenv(launch.HANDOFF, str(target))
    assert launch.handoff("x.json") and target.read_text() == "x.json"


def test_run_options_are_never_program_arguments():
    from decompanion.cli import parser
    a = parser().parse_args(["run", "play", "--prepare-only", "--seconds", "5"])
    assert (a.name, a.prepare_only, a.seconds, a.extra) == ("play", True, 5.0, [])
    a = parser().parse_args(["run", "play", "--no-build", "--", "-x", "--prepare-only"])
    assert (a.no_build, a.prepare_only, a.extra) == (True, False, ["-x", "--prepare-only"])
