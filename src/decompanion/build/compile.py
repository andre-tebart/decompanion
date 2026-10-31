"""The compile: every stale translation unit of a target through the toolchain, one compiler process per unit
in a thread pool, the objects content-addressed under build/obj/<sha256>.obj, the outcome in the store's `tu`
table.

A unit is stale iff one of three hashes differs from its tu row: the source hash (the text of src/<unit>.c),
the flags hash (the target's cflags plus the unit's override and the target's DCP_TARGET_<name> define), or the
include hash (the contents of every
file in the unit's actual include set). The include set comes from the preprocessor (Toolchain.includes) and
is cached in the store by (source hash, flags hash, listing hash of every include search directory): it can
only change when the unit's text, its flags, a file in the set, or a directory listing changes, and a changed
file in the set already makes the unit stale, after which the set is read again. So an edited header
recompiles exactly the units that include it (the header-edit trap of the first attempt, where a global
headers digest recompiled all units).

A failed unit keeps a row with ok=0, its log and diagnostics and its input hashes (it is not compiled again
until an input changes); M.compile turns it into a `build` fact with ok=false and a gate error. Nothing here
reads a modification time.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from .. import native


@dataclass
class Report:
    target: str
    units: int = 0
    compiled: list = field(default_factory=list)    # units compiled this run
    failed: list = field(default_factory=list)      # units whose compile failed this run
    removed: list = field(default_factory=list)     # tu rows of units that are gone
    preprocessed: int = 0
    ms: int = 0
    unavailable: bool = False                       # the toolchain is not installed: nothing compiled


def ensure(project, log=None, force: bool = False, jobs: int | None = None) -> Report:
    """Bring the objects of the current target up to date (the core's: native/dcp_core/src/compile.rs)."""
    target, units, compiled, failed, removed, pre, ms, unavailable, lines = native.core().compile_ensure(project.core, force, jobs)
    project.forget_input("objects")
    project.forget_input("src")
    project.forget_input("decl")
    if log:
        for line in lines:
            log(line)
    return Report(target, units, compiled, failed, removed, pre, ms, unavailable)
