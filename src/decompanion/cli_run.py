"""dcp run: build a run profile's variant, stage its setup's directory, run its steps and start the program
(docs/run.md). The core does the build and the staging (native/dcp_core/src/run.rs); launch.py starts the program in
the process the user typed `dcp` in.
"""
from __future__ import annotations

from . import launch, native
from .cli import build_target, open_project, report

_core = native.core()


def cmd_run(args):
    p, e = open_project(args)
    if args.list or not args.name:
        return report("run", _core.run_list(p.core))
    target = _core.run_target(p.core, args.name)
    if target is None:
        return report("run", *_core.run_prepare(p.core, args.name)[:2], 2)
    if args.no_build:
        p, e = open_project(args, target)
    else:
        p, e, rep = build_target(args, target, quiet=True)
    extra = list(args.extra or [])
    lines, error, spec = _core.run_prepare(p.core, args.name, bool(args.no_build), args.seconds, extra)
    report("run", lines, error)
    if error or spec is None:
        return 1
    if args.prepare_only or launch.handoff(spec):
        print(f"spec={spec}")
        return 0
    return launch.launch(spec)


def register(sub, cmd):
    s = cmd(sub, "run", cmd_run, "build a [[run]] profile, stage its directory, run its setup steps and start the program")
    s.add_argument("name", nargs="?", help="the [[run]] profile (none: list the profiles)")
    s.add_argument("--list", action="store_true", help="list the profiles")
    s.add_argument("--no-build", action="store_true", help="stage and start the last linked program")
    s.add_argument("--seconds", type=float, help="terminate the program after this many seconds (default: the profile's)")
    s.add_argument("--prepare-only", action="store_true", help="build and stage, write the launch spec, start nothing")
    # not argparse.REMAINDER: it would swallow an option given after the name (`run play --prepare-only` started the
    # program with --prepare-only as its argument); extra program arguments follow `--`
    s.add_argument("extra", nargs="*", help="extra program arguments, after --")
