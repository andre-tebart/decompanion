"""dcp headers: the include checks of a unit's head.c (source/headers.py). Same output contract as cli.py: one
record per line, key=value tokens, addresses 0x%08x, counts before lists.

  dcp headers conflicts UNIT HEADER..   what including the headers into the unit's head.c collides with, by a
                                        trial parse (clang, as dcp lint, and VC6's front end, CL /Zs): clash /
                                        header / supersedes / call / vc6 / other / prototyped / duplicate, the
                                        warnings (the declaration set changes; a dropped duplicate carries the
                                        only description of a function), then the functions to re-grade.
                                        --write inserts the includes and drops the duplicates (every name of a
                                        multi-name `extern a, b, c;`: the line goes, or keeps its other names),
                                        only when nothing else is left and the trial without them has no new
                                        error. The includes go after head.c's last include, or before the first
                                        statement that uses a name the headers declare when that comes first;
                                        --at LINE chooses the line.
"""
from __future__ import annotations

from collections import Counter

from .cli import fmt_addr, open_project, record, refresh
from .source import headers as H
from .source import lint as L

ORDER = ("clash", "header", "supersedes", "call", "vc6", "other", "prototyped", "duplicate")
BLOCKING = ("clash", "header", "supersedes", "call", "vc6", "other")


def cmd_headers_conflicts(args):
    p, e = open_project(args)
    refresh(p, e)
    if not L.available(p):
        print(record(error=L.NOT_FOUND))
        return 2
    hdrs = []
    for h in args.headers:
        r = H.resolve_header(p.root, args.unit, h)
        if r is None:
            print(record(unit=args.unit, header=h, error="no such header in the unit's include directories"))
            return 2
        hdrs.append(r)
    try:
        a, head, items, info = H.analyse(p, args.unit, hdrs, at=args.at)
    except LookupError as ex:
        print(record(unit=args.unit, error=str(ex)))
        return 2
    from .cli_match import find_function
    n = Counter(i.kind for i in items)
    print(record(unit=args.unit, headers=",".join(hdrs), **{k: n.get(k, 0) for k in ORDER},
                 **({} if info["vc6"] else {"vc6_trial": "unavailable"})))
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
                if kind in ("supersedes", "call", "vc6", "prototyped", "other"):
                    regrade.setdefault(fn, set()).add(kind)
    rows = []
    for fn in sorted(regrade):
        r = find_function(p, fmt_addr(fn))
        rows.append((fn, r))
    print(record(regrade=len(rows)))
    for fn, r in rows:
        print("  " + record(fn=fn, name=r["name"] if r else None, code=r["code"] if r else None,
                            why=",".join(sorted(regrade[fn]))))
    dropped = sum(1 for i in items if i.kind == "duplicate")
    added = info["declset"]["added"]
    if added or dropped:
        # VC6 /O2: the declaration set of a unit alone moves code generation (gildegold: removing uncalled
        # prototypes flipped byte matches to shape)
        fns = []
        for m in a.members:
            if m.role == "fragment" and m.name:
                r = find_function(p, m.name)
                fns.append((m.addr, m.name, r["code"] if r else None))
        fns.sort(key=lambda x: ({"byte": 0, "shape": 1}.get(x[2], 2), x[0] or 0))
        print(record(warning="declaration-set", added=added, **{"dropped" if args.write else "duplicates": dropped},
                     functions=len(fns), byte=sum(1 for f in fns if f[2] == "byte"),
                     shape=sum(1 for f in fns if f[2] == "shape"))
              + "  (the unit's declaration set changes: VC6 /O2 can move code by it alone; re-grade every function "
                "of the unit, byte ones first; the byte and shape ones follow)")
        for addr, name, code in fns:
            if code in ("byte", "shape"):
                print("  " + record(fn=addr, name=name, code=code))
    for it, addr in info["q6"]:
        print(record(warning="q6", name=it.name, at=it.at, addr=addr)
              + "  (the duplicate's comment is the only description of the function: Q6 fails when it is dropped; "
                "move the words to the function's address comment first)")
    if not args.write:
        return 0 if not any(n[k] for k in BLOCKING) else 1
    blocking = sum(n[k] for k in BLOCKING)
    if blocking:
        print(record(write="refused", why=f"{blocking} conflicts left; only includes and duplicates are written"))
        return 1
    drop = {}
    for i in items:
        if i.kind == "duplicate":
            drop.setdefault(int(i.at.rsplit(":", 1)[1]), set()).add(i.name)
    _, _, base, tri, new, vc6, pos = H.trial(p, args.unit, hdrs, drop, at=args.at)
    seen = {H._key(g) for g in base}
    left = [g for g in tri if g[0]["kind"] == "error" and H._key(g) not in seen]
    vleft = H.vc6_new(vc6)
    if left or vleft:
        print(record(write="refused", why=f"without the duplicates the trial has {len(left) + len(vleft)} new errors",
                     at=pos + 1) + "  (the includes went before head.c's line `at`; --at LINE puts them elsewhere)")
        for g in left[:10]:
            print("  " + L.fmt_group(g))
        for d in vleft[:10]:
            print(f"  vc6 {d['file']}:{d['line']}: {d['msg']}")
        return 1
    (p.root / head).write_text(new.replace('   /* dcp headers conflicts: trial */', ''), newline="\n")
    print(record(write=head, included=",".join(hdrs), at=pos + 1, dropped=sum(len(v) for v in drop.values()), lines=len(drop))
          + "  (dcp build, then dcp check and re-grade the unit)")
    return 0


def register(sub, cmd):
    h = sub.add_parser("headers", help="the include checks of a unit's head.c").add_subparsers(dest="sub", required=True)
    s = cmd(h, "conflicts", cmd_headers_conflicts,
            "what including headers into a unit's head.c collides with (a trial parse; nothing is written without --write)")
    s.add_argument("unit")
    s.add_argument("headers", nargs="+", metavar="HEADER")
    s.add_argument("--write", action="store_true",
                   help="insert the includes and drop head.c's duplicates when no other conflict is left")
    s.add_argument("--at", type=int, metavar="LINE",
                   help="insert the includes before head.c's line LINE (default: after its last include, or before "
                        "the first statement using a name the headers declare when that comes first)")
