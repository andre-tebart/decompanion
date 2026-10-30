"""dcp headers: the include checks of a unit's head.c (source/headers.py). Same output contract as cli.py: one
record per line, key=value tokens, addresses 0x%08x, counts before lists.

  dcp headers conflicts UNIT HEADER..   what including the headers into the unit's head.c collides with, by a
                                        trial parse (clang, as dcp lint): supersedes / duplicate / clash / call /
                                        prototyped / other, then the functions to re-grade. --write inserts the
                                        includes and drops the duplicates, only when nothing else is left.
"""
from __future__ import annotations

from collections import Counter

from .cli import fmt_addr, open_project, record, refresh
from .source import headers as H
from .source import lint as L

ORDER = ("clash", "header", "supersedes", "call", "other", "prototyped", "duplicate")
BLOCKING = ("clash", "header", "supersedes", "call", "other")


def cmd_headers_conflicts(args):
    p, e = open_project(args)
    refresh(p, e)
    if L.clang_path(p) is None:
        print(record(error="clang not found ([lint] clang = ... in decompanion.toml, or clang on PATH)"))
        return 2
    hdrs = []
    for h in args.headers:
        r = H.resolve_header(p.root, args.unit, h)
        if r is None:
            print(record(unit=args.unit, header=h, error="no such header in the unit's include directories"))
            return 2
        hdrs.append(r)
    try:
        a, head, items = H.analyse(p, args.unit, hdrs)
    except LookupError as ex:
        print(record(unit=args.unit, error=str(ex)))
        return 2
    from .cli_match import find_function
    n = Counter(i.kind for i in items)
    print(record(unit=args.unit, headers=",".join(hdrs), **{k: n.get(k, 0) for k in ORDER}))
    regrade = {}
    for kind in ORDER:
        for i in (x for x in items if x.kind == kind):
            print("  " + record(kind=i.kind, name=i.name, at=i.at, **{"decl" if kind == "call" else "header": i.other},
                                exempt="@original" if i.exempt else None))
            if i.msg and kind != "duplicate":
                print(f"    {i.msg}")
            a_, b_ = ("first: ", "second:") if kind == "clash" else ("ours:  ", "decl:  " if kind == "call" else "header:")
            if i.ours:
                print(f"    {a_} {i.ours}")
            if i.theirs:
                print(f"    {b_} {i.theirs}")
            for ev in i.evidence:
                print(f"    {ev}")
            if i.sites:
                print(f"    sites: {', '.join(i.sites[:8])}" + (f" (+{len(i.sites) - 8})" if len(i.sites) > 8 else ""))
            for fn in ([i.fn] if i.fn is not None else []) + i.fns:
                if kind in ("supersedes", "call", "prototyped", "other"):
                    regrade.setdefault(fn, set()).add(kind)
    rows = []
    for fn in sorted(regrade):
        r = find_function(p, fmt_addr(fn))
        rows.append((fn, r))
    print(record(regrade=len(rows), unit_functions="all (the declaration set alone can move stack slots)"))
    for fn, r in rows:
        print("  " + record(fn=fn, name=r["name"] if r else None, code=r["code"] if r else None,
                            why=",".join(sorted(regrade[fn]))))
    if not args.write:
        return 0 if not any(n[k] for k in BLOCKING) else 1
    blocking = sum(n[k] for k in BLOCKING)
    if blocking:
        print(record(write="refused", why=f"{blocking} conflicts left; only includes and duplicates are written"))
        return 1
    drop = {int(i.at.rsplit(":", 1)[1]) for i in items if i.kind == "duplicate"}
    _, _, base, tri, new = H.trial(p, args.unit, hdrs, drop)
    seen = {H._key(g) for g in base}
    left = [g for g in tri if g[0]["kind"] == "error" and H._key(g) not in seen]
    if left:
        print(record(write="refused", why=f"without the duplicates the trial has {len(left)} new errors"))
        for g in left[:10]:
            print("  " + L.fmt_group(g))
        return 1
    (p.root / head).write_text(new.replace('   /* dcp headers conflicts: trial */', ''), newline="\n")
    print(record(write=head, included=",".join(hdrs), dropped=len(drop)) + "  (dcp build, then dcp check and re-grade the unit)")
    return 0


def register(sub, cmd):
    h = sub.add_parser("headers", help="the include checks of a unit's head.c").add_subparsers(dest="sub", required=True)
    s = cmd(h, "conflicts", cmd_headers_conflicts,
            "what including headers into a unit's head.c collides with (a trial parse; nothing is written without --write)")
    s.add_argument("unit")
    s.add_argument("headers", nargs="+", metavar="HEADER")
    s.add_argument("--write", action="store_true",
                   help="insert the includes and drop head.c's duplicates when no other conflict is left")
