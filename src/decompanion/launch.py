"""Launching a staged run (docs/run.md): the steps of the setup, the program, the `after` steps.

The core builds and stages and writes the launch spec build/run/<run>.json (run.rs); this module runs it in the
process the user typed `dcp` in (the daemon has no window to start a program in). Standard library only: the client
imports it without loading the core.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

HANDOFF = "DCP_LAUNCH"     # set by the client: the file `dcp run` in the daemon writes the spec's path into


def _env(spec: dict, extra: dict | None = None) -> dict:
    env = dict(os.environ)
    env.update(spec.get("hook_env") or {})
    env.update(extra or {})
    return env


def _step(cmd: list[str], spec: dict, env: dict, what: str) -> int:
    print(f"run {what}: {subprocess.list2cmdline(cmd)}", flush=True)
    try:
        return subprocess.run(cmd, cwd=spec["root"], env=env).returncode
    except OSError as ex:
        print(f"dcp run: {what} {cmd[0]}: {ex}", file=sys.stderr)
        return 127


def launch(spec_path: str) -> int:
    """Run a launch spec: each step (a failing one stops the run), the program in the run directory (terminated after
    `seconds` when > 0, or on Ctrl+C), then each `after` step with DCP_EXIT. The program's exit code."""
    with open(spec_path, encoding="utf-8") as fh:
        spec = json.load(fh)
    env = _env(spec)
    for i, cmd in enumerate(spec.get("steps") or []):
        rc = _step(cmd, spec, env, f"step {i + 1}")
        if rc != 0:
            print(f"dcp run: step {i + 1} exited with {rc}: the program is not started", file=sys.stderr)
            return rc or 1
    run_env = dict(env)
    run_env.update(spec.get("env") or {})
    argv = [spec["exe"], *(spec.get("args") or [])]
    seconds = float(spec.get("seconds") or 0)
    t0 = time.perf_counter()
    debug = bool(spec.get("debug"))
    print(f"run {spec['run']}: {subprocess.list2cmdline(argv)}  (in {spec['dir']}{', under the debugger' if debug else ''})", flush=True)
    crash = None
    if debug:
        try:
            code, stopped, crash = _debug(spec, argv, run_env, seconds, spec_path)
        except RuntimeError as ex:
            print(f"dcp run: {ex}", file=sys.stderr)
            return 127
    else:
        code, stopped = _plain(spec, argv, run_env, seconds)
        if code is None:
            return 127
    ms = int((time.perf_counter() - t0) * 1000)
    if crash:
        print(f"run {spec['run']}: crashed; report {os.path.join(crash, 'crash.txt')}", flush=True)
    after_env = _env(spec, {"DCP_EXIT": str(code), "DCP_CRASH": crash or ""})
    for i, cmd in enumerate(spec.get("after") or []):
        rc = _step(cmd, spec, after_env, f"after {i + 1}")
        if rc != 0:
            print(f"dcp run: after {i + 1} exited with {rc}", file=sys.stderr)
    print(f"run={spec['run']}  exit={code}  ms={ms}" + (f"  stopped={stopped}" if stopped else "")
          + (f"  crash={os.path.relpath(crash, spec['root'])}" if crash else ""))
    if crash:
        return 1
    return 0 if stopped == "time" else (code if code is not None else 1)


def _plain(spec, argv, env, seconds):
    """(exit code, stopped): the program as a plain child process; (None, '') when it cannot start."""
    try:
        proc = subprocess.Popen(argv, cwd=spec["dir"], env=env)
    except OSError as ex:
        print(f"dcp run: {spec['exe']}: {ex}", file=sys.stderr)
        return None, ""
    stopped = ""
    try:
        code = proc.wait(timeout=seconds if seconds > 0 else None)
    except subprocess.TimeoutExpired:
        stopped = "time"
    except KeyboardInterrupt:
        stopped = "interrupt"
    if stopped:
        proc.terminate()
        try:
            code = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            code = proc.wait()
    return code, stopped


def _debug(spec, argv, env, seconds, spec_path):
    """(exit code, stopped, crash folder): the program under the core's debugger (debugger.rs), on this thread (the
    debug loop must run on the thread that creates the process). The debug heap stays off: a program started under
    a debugger gets the NT debug heap otherwise, which moves heap bugs."""
    from . import native
    env = dict(env)
    env.setdefault("_NO_DEBUG_HEAP", "1")
    return native.core().debug_launch(spec["run"], spec["exe"], subprocess.list2cmdline(argv), spec["dir"], sorted(env.items()), seconds,
                                      spec.get("symbols") or "", spec.get("capstone") or "", spec["crash_root"],
                                      spec.get("dump") or "full", spec_path)


def handoff(spec_path: str) -> bool:
    """In the daemon: hand the spec to the client that asked (True), instead of launching here."""
    target = os.environ.get(HANDOFF)
    if not target:
        return False
    with open(target, "w", encoding="utf-8") as fh:
        fh.write(spec_path)
    return True
