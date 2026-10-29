"""dcp data: the data tooling (source/datafix.py). Same output contract as cli.py: one record per line,
key=value tokens, addresses 0x%08x, counts before lists.

  dcp data map [UNIT]            a unit's data declarations in address order (or the per-unit summary)
  dcp data fix [--check D5,D1,D4] [--unit U] [--write]
                                 the rewrites that answer D5 / D1 / D4; without --write only listed; with
                                 --write each unit's edits are trial-compiled first (a group that breaks the
                                 unit's compile or one of its byte matches is rejected), the accepted ones
                                 are written, then one build and refresh confirms them
"""
from __future__ import annotations

import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from .cli import open_project, record, refresh
from .source import datafix as DF


def cmd_data_map(args):
    p, e = open_project(args, None)
    refresh(p, e)
    model = DF.data_model(p)
    if not args.unit:
        per = {}
        for d in model:
            per.setdefault(d.unit, []).append(d)
        print(record(target=p.target_name, units=len(per), declarations=len(model),
                     conflicts=sum(len(d.conflicts) for d in model)))
        for u in sorted(per, key=lambda u: min(d.addr for d in per[u])):
            ds = per[u]
            secs = Counter(d.section for d in ds if d.kind == "def")
            lv = Counter(d.level for d in ds if d.kind == "def")
            checks = Counter(c for d in ds for c, _ in d.conflicts)
            print("  " + record(unit=u, defs=sum(secs.values()), externs=sum(1 for d in ds if d.kind == "extern"),
                                data=secs.get("data", 0), rdata=secs.get("rdata", 0), bss=secs.get("bss", 0),
                                common=secs.get("common", 0), proven=lv.get("proven", 0),
                                conflicts=",".join(f"{k}={v}" for k, v in sorted(checks.items())) or None))
        return 0
    ds = sorted((d for d in model if d.unit == args.unit and (d.kind == "def" or args.externs)), key=lambda d: (d.addr, d.file))
    if not ds:
        print(record(unit=args.unit, error="no data declarations with an address"))
        return 1
    print(record(unit=args.unit, declarations=len(ds)))
    for d in ds:
        room = d.next_start - d.addr if d.next_start is not None else None
        print("  " + record(at=d.addr, name=d.name, kind=d.kind if d.kind != "def" else None, section=d.section,
                            size=d.size, room=room, over=(d.size - room) if d.size and room is not None and d.size > room else None,
                            level=d.level, by=d.extent, static=d.static or None, src=f"{d.file}:{d.line}"))
        for c, m in d.conflicts:
            print(f"    {c}: {m}")
    return 0


def cmd_data_fix(args):
    from .build import compile as B
    checks = [c.strip().upper() for c in args.check.split(",")] if args.check else list(DF.CHECKS)
    bad = [c for c in checks if c not in DF.CHECKS]
    if bad:
        print(record(error=f"unknown check {','.join(bad)} (known: {','.join(DF.CHECKS)})"))
        return 2
    p, e = open_project(args, None)
    status = 0
    for check in checks:
        t0 = time.perf_counter()
        B.ensure(p)                       # the data checks read the objects: they must be the sources' own
        refresh(p, e)
        model = DF.data_model(p)
        files = DF.Files(p.root)
        if check == "D5":
            edits, manual = DF.d5_edits(files, model)
        elif check == "D1":
            edits, manual = DF.d1_edits(files, model)
        else:
            order = {a.unit: [m.file for m in a.members] for a in B.plan(p)}
            edits, manual = DF.d4_edits(files, model, order)
        if args.unit:
            edits = [x for x in edits if x.unit == args.unit]
            manual = [m for m in manual if f" src/{args.unit}/" in m]
        print(record(check=check, edits=len(edits), units=len({x.unit for x in edits}), manual=len(manual),
                     write=bool(args.write)))
        for x in edits[:args.limit] if not args.verbose else edits:
            if not x.why.endswith("moves"):
                print("  edit " + x.why + f"  {x.file}")
        for m in manual:
            print("  manual " + m)
        if not args.write or not edits:
            continue
        # trial compiles decide (source/datafix.py Trial); only accepted edits are written, then one build
        before = DF.byte_functions(p)
        trial = DF.Trial(p)
        units = sorted({x.unit for x in edits})
        with ThreadPoolExecutor(4) as pool:
            verdicts = dict(zip(units, pool.map(lambda u: trial.judge(files, u, [x for x in edits if x.unit == u]), units)))
        accepted = [x for u in units for x in verdicts[u][0]]
        for u in units:
            for why in verdicts[u][1]:
                print("  rejected " + record(unit=u) + "  " + why)
        t1 = time.perf_counter()
        new = DF.apply(files, accepted)
        for rel, text in new.items():
            (p.root / rel).write_text(text, newline="\n")
        B.ensure(p)
        refresh(p, e)
        failed = DF.failed_units(p)
        still = [a for a in before if a not in DF.byte_functions(p)]
        if still or failed - set(before.values()) and failed:
            for rel in new:                               # the trial missed something: the batch goes back
                (p.root / rel).write_text(files.text(rel), newline="\n")
            B.ensure(p)
            refresh(p, e)
            print("  reverted " + record(edits=len(accepted), why=f"after writing, {len(still)} byte match(es) lost, "
                                                                f"failed units: {','.join(sorted(failed)) or '-'}"))
            accepted, status = [], 1
        groups = len({x.group for x in accepted})
        print(record(check=check, applied=groups, rejected=sum(len(v[1]) for v in verdicts.values()),
                     byte_lost=len([a for a in before if a not in DF.byte_functions(p)]),
                     trial_ms=int((t1 - t0) * 1000), ms=int((time.perf_counter() - t0) * 1000)))
    return status


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
