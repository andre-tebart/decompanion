"""Where a command's time goes: named phases summed per process (per request under `dcp serve`).

DCP_TIMING=1 prints one line to stderr when the command ends: `timing: total=.. open=.. hash.src=.. ...` (ms per
phase, phases in first-seen order; nested phases count in both). DCP_TIMING=2 adds the per-rule lines the engine
records (`rule.<id>` run and `record.<id>` store time). DCP_PROFILE=1 runs the command under cProfile and writes
build/profile/<cmd>-<time>.prof (cli.main), printing the top functions by cumulative time.

Nothing here changes what a command computes; with neither variable set every call is a dict update.
"""
from __future__ import annotations

import os
import sys
import time
from contextlib import contextmanager

_ms: dict[str, float] = {}
_t0 = time.perf_counter()


def level() -> int:
    try:
        return int(os.environ.get("DCP_TIMING", "0") or 0)
    except ValueError:
        return 1


def reset():
    global _t0
    _ms.clear()
    _t0 = time.perf_counter()


def add(name: str, ms: float):
    _ms[name] = _ms.get(name, 0.0) + ms


@contextmanager
def phase(name: str):
    t = time.perf_counter()
    try:
        yield
    finally:
        add(name, (time.perf_counter() - t) * 1000)


def report(out=None):
    """Print the timing line (DCP_TIMING set); the per-rule entries only at level 2."""
    lv = level()
    if not lv:
        return
    total = (time.perf_counter() - _t0) * 1000
    items = [(k, v) for k, v in _ms.items() if lv >= 2 or not k.startswith(("rule.", "record."))]
    print("timing: " + "  ".join([f"total={total:.0f}"] + [f"{k}={v:.0f}" for k, v in items]), file=out or sys.stderr)
