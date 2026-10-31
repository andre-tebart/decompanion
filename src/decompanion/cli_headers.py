"""dcp headers: the include checks of a unit's head region (the core's headers.rs). Same output contract as cli.py: one
record per line, key=value tokens, addresses 0x%08x, counts before lists.

  dcp headers conflicts UNIT HEADER..   what including the headers into the unit's head region collides with, by a
                                        trial parse (clang, as dcp lint, and VC6's front end, CL /Zs): clash /
                                        header / supersedes / call / vc6 / other / prototyped / duplicate, the
                                        warnings (the declaration set changes; a dropped duplicate carries the
                                        only description of a function), then the functions to re-grade.
                                        --write inserts the includes and drops the duplicates (every name of a
                                        multi-name `extern a, b, c;`: the line goes, or keeps its other names),
                                        only when nothing else is left and the trial without them has no new
                                        error. The includes go after the unit's last include, or before the first
                                        statement that uses a name the headers declare when that comes first;
                                        --at LINE chooses the line.
"""
from __future__ import annotations

from . import native
from .cli import open_project, refresh


def cmd_headers_conflicts(args):
    from .rules.engine import capstone_dll
    p, e = open_project(args)
    refresh(p, e)
    lines, status = native.core().headers_conflicts(p.core, capstone_dll(), args.unit, list(args.headers), bool(args.write), args.at)
    print("\n".join(lines))
    return status


def register(sub, cmd):
    h = sub.add_parser("headers", help="the include checks of a unit's head region").add_subparsers(dest="sub", required=True)
    s = cmd(h, "conflicts", cmd_headers_conflicts,
            "what including headers into a unit's head region collides with (a trial parse; nothing is written without --write)")
    s.add_argument("unit")
    s.add_argument("headers", nargs="+", metavar="HEADER")
    s.add_argument("--write", action="store_true",
                   help="insert the includes and drop the head's duplicates when no other conflict is left")
    s.add_argument("--at", type=int, metavar="LINE",
                   help="insert the includes before the unit file's line LINE (default: after its last include, or before "
                        "the first statement using a name the headers declare when that comes first)")
