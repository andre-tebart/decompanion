"""dcp data: the data tooling (the core's datafix.rs). Same output contract as cli.py: one record per line,
key=value tokens, addresses 0x%08x, counts before lists.

  dcp data map [UNIT]            a unit's data declarations in address order (or the per-unit summary)
  dcp data fix [--check D5,D1,D4] [--unit U] [--write]
                                 the rewrites that answer D5 / D1 / D4; without --write only listed; with
                                 --write each unit's edits are trial-compiled first (a group that breaks the
                                 unit's compile or one of its byte matches is rejected), the accepted ones
                                 are written, then one build and refresh confirms them
"""
from __future__ import annotations

from . import native
from .cli import open_project, refresh


def cmd_data_map(args):
    p, e = open_project(args, None)
    refresh(p, e)
    lines, status = native.core().data_map(p.core, args.unit, bool(args.externs))
    print("\n".join(lines))
    return status


def cmd_data_fix(args):
    """The rewrites that answer D5 / D1 / D4 (the core's: datafix.rs); `sync` builds and refreshes the store."""
    from .build import compile as B
    p, e = open_project(args, None)

    def sync():
        B.ensure(p)
        refresh(p, e)
    return native.core().data_fix(p.core, args.check, args.unit, bool(args.write), args.limit, bool(args.verbose), sync, print)


def register(sub, cmd):
    dp = sub.add_parser("data", help="the data tooling: map, fix").add_subparsers(dest="sub", required=True)
    s = cmd(dp, "map", cmd_data_map, "a unit's data declarations in address order (no unit: the per-unit summary)")
    s.add_argument("unit", nargs="?")
    s.add_argument("--externs", action="store_true", help="list the extern declarations too")
    s = cmd(dp, "fix", cmd_data_fix, "rewrite sources to answer D5 / D1 / D4 (dry run unless --write)")
    s.add_argument("--check", help="comma-separated subset of D5,D1,D4 (default: all, in that order)")
    s.add_argument("--unit", help="only this unit's fixes")
    s.add_argument("--write", action="store_true", help="apply, compile, keep only units that lose no byte match")
    s.add_argument("--limit", type=int, default=40, help="edits listed per check (default 40)")
    s.add_argument("-v", "--verbose", action="store_true", help="list every edit")
