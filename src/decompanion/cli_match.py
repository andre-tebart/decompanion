"""dcp: the match-phase commands (build is in cli.py): grade, next, asmdiff, diffclass, escalate, stuck,
promote, accept, link, toolchain probe, lint. Each builds or refreshes the target, then prints what the core
returns (native/dcp_core/src/matchcmd.rs). Same output contract as cli.py: one record per line, key=value tokens,
addresses 0x%08x, counts before lists.
"""
from __future__ import annotations

import sys
from pathlib import Path

from . import native
from .cli import build_target, open_project, refresh, target_names
from .config import Project

_core = native.core()


def report(cmd: str, lines, error=None, code: int = 0) -> int:
    for line in lines:
        print(line)
    if error:
        print(f"dcp {cmd}: {error}", file=sys.stderr)
    return code


def built(args):
    p, e, rep = build_target(args, getattr(args, "target", None), quiet=True)
    return p, e


# ------------------------------------------------------------------------------------------------ grade / next
def cmd_grade(args):
    """The grades: without an argument the matrix and the unit table; a unit: its functions with the failing
    rules; a function (name or address): its grades, the failing rules with evidence, the distance."""
    p, e = built(args)
    q7 = current_lint(p, e)
    return report("grade", *_core.grade_command(p.core, args.what, q7))


def cmd_next(args):
    """The next functions of a queue (base by default)."""
    p, e = built(args)
    current_lint(p, e)
    which = "deep" if args.deep else "names" if args.names else "base"
    return report("next", *_core.next_command(p.core, which, args.shard, args.unit, args.n))


# ------------------------------------------------------------------------------------------------ asmdiff / diffclass
def cmd_asmdiff(args):
    """The instruction diff of one function: ours ('-') against the original ('+'), both listed at the
    original address (numbers that are image addresses and our relocated fields read X; --symbols prints their names)."""
    from .rules.engine import capstone_dll
    p, e = built(args)
    return report("asmdiff", *_core.asmdiff_command(p.core, capstone_dll(), args.name, args.regs, bool(args.all), bool(args.symbols),
                                                       bool(args.plain)))


def cmd_diffclass(args):
    """The hunks of one function's instruction diff with their classes (diffclass.rs)."""
    from .rules.engine import capstone_dll
    p, e = built(args)
    return report("diffclass", *_core.diffclass_command(p.core, capstone_dll(), args.name, bool(args.all)))


# ------------------------------------------------------------------------------------------------ the level ladder
def cmd_level(args):
    """`dcp escalate` / `dcp stuck`: the level tag of a function's address comment (the core's queues.rs)."""
    from .rules.engine import capstone_dll
    p, e = open_project(args)
    refresh(p, e)
    lines, error, status = _core.level_command(p.core, args.level, args.name, bool(args.clear), args.why, capstone_dll(),
                                               getattr(args, "size_explained", None))
    return report("escalate" if error and error.startswith("refused") else args.level, lines, error, status)


# ------------------------------------------------------------------------------------------------ promote / accept
def in_worktree(args, cmd: str, what: str) -> bool:
    p0 = Project(Path(args.root) if args.root else None)
    if p0.main_build_dir() is not None:
        print(f"dcp {cmd}: refused in a worktree (the baseline is {what} on main only)", file=sys.stderr)
        return True
    return False


def cmd_promote(args):
    """Write ledger/grades.tsv from the current grades of every target (main checkout only)."""
    if in_worktree(args, "promote", "promoted"):
        return 1
    projects = [build_target(args, t.name, quiet=True)[0] for t in Project(Path(args.root) if args.root else None).targets]
    return report("promote", *_core.promote_command(str(projects[0].root), [p.core for p in projects], bool(getattr(args, "accept_falls", False))))


def cmd_accept(args):
    """Lower one function's entry of ledger/grades.tsv to the grade it fell to, with the reason (main checkout
    only): M1 then holds it there."""
    if in_worktree(args, "accept", "changed"):
        return 1
    if not " ".join((args.why or "").split()) or (not args.to and not args.readability):
        return report("accept", *_core.accept_command(None, args.name, args.to, args.readability, args.why))
    p, e = open_project(args)
    refresh(p, e)
    return report("accept", *_core.accept_command(p.core, args.name, args.to, args.readability, args.why))


# ------------------------------------------------------------------------------------------------ link / probe / lint
def cmd_link(args):
    failed = False
    for name in target_names(args):
        p, e, rep = build_target(args, name, quiet=True)
        lines, ok, _, _, _ = _core.link_command(p.core)
        report("link", lines)
        failed = failed or not ok
    return 1 if failed else 0


def cmd_probe(args):
    p, e = built(args)
    result, line = _core.probe_run(p.core)
    if args.verbose:
        print(line)
    p.forget_input("probe")
    refresh(p, e)
    return report("toolchain probe", _core.probe_report(p.core, result))


def current_lint(p, e) -> str:
    """Lint again when a unit changed since the last lint (only the changed units parse) so Q7 is current; the
    note on where Q7 comes from."""
    action, note = _core.lint_plan(p.core)
    if action == "lint":
        _core.lint_command(p.core)
        refresh(p, e)
    return note


def cmd_lint(args):
    """clang as the declaration checker of every unit of the target (the core's lintrun.rs): M6 errors, M5
    cross-unit conflicts, M7 calls without a prototype; exit 1 on M5 / M6."""
    failed = False
    for name in target_names(args):
        p, e, rep = build_target(args, name, quiet=True)
        if not _core.lint_available(p.core):
            return report("lint", [], _core.lint_not_found(), 2)
        lines, bad = _core.lint_command(p.core)
        refresh(p, e)
        report("lint", lines)
        failed = failed or bad
    return 1 if failed else 0
