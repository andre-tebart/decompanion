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
from pathlib import Path


from .. import native
from . import tu as T


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


def unit_overrides(project) -> list[dict]:
    """The [[toolchain.unit]] tables: glob (on the unit name), cflags, reason, optional targets."""
    return native.core().plan_unit_overrides(project.core)


def flags_for(project, target: str, unit: str) -> tuple[list[str], dict | None]:
    """(flags, the override table that applied or None): the core's (plan.rs flags_for)."""
    return native.core().plan_flags_for(project.core, target, unit)


def compile_flags(project, target: str, unit: str) -> list[str]:
    """The flags a unit compiles with: flags_for's and the target's define."""
    return native.core().plan_compile_flags(project.core, target, unit)


def include_dirs(unit: str) -> list[Path]:
    """The include directories of a unit, relative to the project root (a quoted include also resolves beside
    the unit's file, in src/)."""
    return [Path("include")]


def plan(project, scan=None) -> list[T.TU]:
    """The translation units of the project's current target (the core's: plan.rs, memoised by the hashes of what
    they depend on); of a given scan: tu.units."""
    if scan is not None:
        return T.units(project.root, scan, project.target_name, project.default_target)
    return T.of_rows(project.root, native.core().plan_units(project.core))


def obj_path(root: Path, obj_hash: str) -> Path:
    return Path(root) / "build" / "obj" / f"{obj_hash}.obj"


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
