"""dcp: the guided decisions (the core's decide.rs): `dcp status` (the phase, the gate and the numbered steps in
order, with the next command; --json for the records), the evidence views (`dcp toolchain`, `dcp libs candidates`)
and the declarations (`dcp toolchain declare`, `dcp libs declare`, `dcp analyzer declare`). A declaration always
carries a reason (`--why`, refused without one), lands in decompanion.toml as `key = value` with `reason.<key> =
"..."`, is level declared, and reruns the rules at once so the next obligation shows. The tool never declares
anything on its own. This module parses the arguments, reruns the rules and prints what the core returns.
"""
from __future__ import annotations

import sys
from pathlib import Path

from . import native
from .cli import open_project, refresh
from .config import Project

_core = native.core()


def report(cmd: str, lines, error, code: int) -> int:
    for line in lines:
        print(line)
    if error:
        print(f"dcp {cmd}: {error}", file=sys.stderr)
    return code


def project(args, name=None) -> Project:
    return Project(Path(args.root) if args.root else None, name or getattr(args, "target", None))


# ------------------------------------------------------------------------------------------------ status
def print_status(p, shown: list | None = None, work: bool = True, as_json: bool = False) -> list:
    """The status of one target (decide.rs); `shown`: the project-wide obligations already printed, returned
    extended."""
    lines, shown = _core.decide_status(p.core, shown or [], work, as_json)
    for line in lines:
        print(line)
    return shown


def cmd_status(args):
    """Per target (every target unless --target): the phase, the gate and the open obligations in order, each
    with what is missing, the evidence so far and the command that resolves it, plus the first step to take.
    --json prints the records instead. Exit 0."""
    shown: list = []
    names = [args.target] if getattr(args, "target", None) else [t.name for t in project(args).targets]
    for i, name in enumerate(names):
        if i:
            print()
        p, e = open_project(args, name)
        refresh(p, e)
        shown = print_status(p, shown, as_json=args.json)
    return 0


def status_tail(p, view=None, work: bool = True):
    """The tail other commands print (setup, session start)."""
    print()
    print_status(p, work=work)


def gate_failures(p) -> list[str]:
    """The open toolchain and libs obligations of the current target as records (the session and check gate)."""
    return _core.decide_gate(p.core)


# ------------------------------------------------------------------------------------------------ declarations
def rerun(args, name):
    """The rules again after a declaration, so the next obligation shows at once: (project, engine), or None
    before the first `dcp setup` of the target (no store yet: setup runs the rules the first time, a
    declaration made before it only writes)."""
    p = project(args, name)
    if not p.store_path().exists():
        print("rules: not run yet (no store): `dcp setup` runs them and prints the next obligations")
        return None
    p, e = open_project(args, name)
    refresh(p, e)
    return p, e


def cmd_toolchain_declare(args):
    """Declare any of compiler= linker= cflags= (the current target's table) root= plugin= ([toolchain]) with one
    reason (--why), stored per key; then rerun the rules and print C.toolchain and the status tail."""
    p = project(args)
    lines, error, code, root = _core.decide_toolchain_declare(p.core, args.pairs, args.why)
    if error or code:
        return report("toolchain declare", lines, error, code)
    report("toolchain declare", lines, None, 0)
    r = rerun(args, p.target_name)
    if r is None:
        return 0
    lines, code = _core.decide_toolchain_after(r[0].core, root)
    return report("toolchain declare", lines, None, code)


def cmd_libs_declare(args):
    """Declare the current target's static library archives (bare names are the toolchain's archives under the
    declared root) with a reason; rerun the rules (S.crt.code places the members) and print what was placed and
    the status tail."""
    p = project(args)
    code = report("libs declare", *_core.decide_libs_declare(p.core, args.archives, args.why))
    if code:
        return code
    r = rerun(args, p.target_name)
    if r is not None:
        report("libs declare", _core.decide_libs_after(r[0].core), None, 0)
    return 0


def cmd_libs_candidates(args):
    """Place every run-time archive of the declared toolchain root on its own (libcand.rs) and report per archive
    members, placed members and placed bytes (sorted by bytes) and the archive pairs that conflict."""
    p, e = open_project(args)
    if p.core.toolchain_root() is None:
        return report("libs candidates", [], 'no toolchain root declared: dcp toolchain declare root=DIR --why "..." first', 2)
    refresh(p, e)
    lines, log = _core.libs_candidates_lines(p.core, native.source_hash(), args.force)
    if args.verbose:
        for line in log:
            print(line, file=sys.stderr)
    return report("libs candidates", lines, None, 0)


def cmd_analyzer_declare(args):
    """Confirm or change the analyzer ([analyzer] plugin and its keys) with a reason."""
    p = project(args)
    code = report("analyzer declare", *_core.decide_analyzer_declare(p.core, args.plugin, args.pairs, args.why))
    if code:
        return code
    r = rerun(args, p.target_name)
    if r is not None:
        status_tail(r[0])
    return 0


# ------------------------------------------------------------------------------------------------ the evidence view
def cmd_toolchain(args):
    """Per target (every target unless --target): what is declared, the installs found on this machine, the Rich
    candidates, the PE linker version and time stamp, the CRT strings, the C.toolchain verdict, the archives and the
    members placed, the probe (decide.rs)."""
    names = [args.target] if getattr(args, "target", None) else [t.name for t in project(args).targets]
    for i, name in enumerate(names):
        if i:
            print()
        p, e = open_project(args, name)
        refresh(p, e)
        report("toolchain", _core.decide_toolchain_view(p.core), None, 0)


def register(sub, cmd):
    """The parsers: status, toolchain [probe | declare], libs candidates | declare, analyzer declare."""
    s = cmd(sub, "status", cmd_status, "the phase and the open obligations in order, with the next step (every target unless --target)")
    s.add_argument("--json", action="store_true", help="the records of the output contract instead of the guided view")
    s = cmd(sub, "toolchain", cmd_toolchain, "the toolchain evidence; `probe`: the flag probe; `declare`: a declaration")
    s.add_argument("-v", "--verbose", action="store_true")
    ts = s.add_subparsers(dest="sub")
    from .cli_match import cmd_probe
    s2 = cmd(ts, "probe", cmd_probe, "the flag grid over the byte-matched functions")
    s2.add_argument("-v", "--verbose", action="store_true")
    s2 = cmd(ts, "declare", cmd_toolchain_declare, "declare compiler= linker= root= cflags= (any subset) with --why")
    s2.add_argument("pairs", nargs="+", metavar="KEY=VALUE", help="keys: compiler, linker, root, cflags, plugin")
    s2.add_argument("--why", help="the reason (required): the evidence the declaration rests on")
    lb = sub.add_parser("libs", help="the static library archives").add_subparsers(dest="sub", required=True)
    s2 = cmd(lb, "candidates", cmd_libs_candidates, "place every run-time archive of the root on its own")
    s2.add_argument("--force", action="store_true", help="place again (ignore the cache)")
    s2.add_argument("-v", "--verbose", action="store_true")
    s2 = cmd(lb, "declare", cmd_libs_declare, "declare the target's archives with --why")
    s2.add_argument("archives", nargs="+", metavar="ARCHIVE", help="LIBCMT, LIBCMT.LIB or a path")
    s2.add_argument("--why", help="the reason (required)")
    az = sub.add_parser("analyzer", help="the third-party analyzer").add_subparsers(dest="sub", required=True)
    s2 = cmd(az, "declare", cmd_analyzer_declare, "confirm or change the analyzer with --why")
    s2.add_argument("plugin", metavar="PLUGIN", help="ghidra | none")
    s2.add_argument("pairs", nargs="*", metavar="KEY=VALUE", help="root= java_home= timeout=")
    s2.add_argument("--why", help="the reason (required)")
