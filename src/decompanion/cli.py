"""dcp: the command line. Every command refreshes the rule engine first (nothing changed: nothing runs), then
answers from the store. Output: one record per line, key=value tokens, addresses 0x%08x, intervals lo..hi
(hi exclusive), sorted by address, counts before lists; --json gives the same records as JSON lines.
Every command takes --target NAME (default: the first [[target]] of decompanion.toml).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

from . import rules  # noqa: F401  (registers every rule)
from .config import ConfigError, Project
from .ledger import query
from .ledger.fact import Kind, Level, canonical
from .rules.engine import Engine, RuleError


def fmt_addr(a):
    return f"{a:#010x}"


def fmt_range(lo, hi):
    return f"{lo:#010x}..{hi:#010x}" if hi > lo + 1 else f"{lo:#010x}"


def parse_addr(s: str) -> int:
    s = s.strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s, 0)


def parse_range(s: str) -> tuple[int, int]:
    if ".." in s:
        a, b = s.split("..", 1)
        return parse_addr(a), parse_addr(b)
    a = parse_addr(s)
    return a, a + 1


def tok(v):
    """A value as a key=value token."""
    if v is None:
        return "-"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, int):
        return fmt_addr(v) if v >= 0x100000 else str(v)      # an address, else a count or size (decimal)
    if isinstance(v, tuple) and len(v) == 2:
        return f"{fmt_addr(v[0])}..{fmt_addr(v[1])}"
    if isinstance(v, (list, tuple)):
        return ",".join(tok(x) for x in v) or "-"
    s = str(v)
    return repr(s) if (" " in s or not s) else s


def record(**kv) -> str:
    return "  ".join(f"{k}={tok(v)}" for k, v in kv.items())


def jsonable(v):
    if isinstance(v, dict):
        return {k: jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [jsonable(x) for x in v]
    return v


def open_project(args, target: str | None = None) -> tuple[Project, Engine]:
    p = Project(Path(args.root) if getattr(args, "root", None) else None, target or getattr(args, "target", None))
    e = Engine(p, p.store)
    return p, e


def refresh(p: Project, e: Engine, verbose=False, force=False, only=None):
    t0 = time.perf_counter()
    res = e.run(only, force=force, log=(lambda s: print(s, file=sys.stderr)) if verbose else None)
    ran = [r for r in res if r.ran]
    if verbose or ran:
        print(f"rules: {len(ran)} ran of {len(res)}, {int((time.perf_counter() - t0) * 1000)} ms (target {p.target_name})", file=sys.stderr)
    query.ensure_bytemap(p.store)
    return res


# ------------------------------------------------------------------------------------------------- setup and queries
def cmd_setup(args):
    p, e = open_project(args)
    refresh(p, e, verbose=args.verbose, force=args.force)
    cmd_report(args, p, e)


def cmd_report(args, p=None, e=None):
    if p is None:
        p, e = open_project(args)
        refresh(p, e)
    st = p.store
    img = p.image
    print(f"target={p.target_name}  file={p.image_path.name}  sha256={img.sha256[:16]}  base={fmt_addr(img.base)}  entry={fmt_addr(img.entry)}  "
          f"{'dll' if img.is_dll else 'exe'}  linker={img.linker_version[0]}.{img.linker_version[1]}  sections={len(img.sections)}")
    tcf = next(iter(st.facts(Kind.toolchain)), None)
    if tcf:
        v = tcf.value
        print(f"rich: compiler={v.get('compiler')} build={v.get('compiler_build')} objects={v.get('compiler_objects')} "
              f"language={v.get('language')} library_objects={v.get('library_objects')} linker={v.get('linker')} "
              f"build={v.get('linker_build')}  {tcf.level}  name={v.get('compiler_name', '')!r}")
    s = query.summary(st)
    for name in s["by_section"]:
        classes = "  ".join(f"{k}={v:#x}" for k, v in sorted(s["by_section"][name].items(), key=lambda kv: -kv[1]))
        levels = "  ".join(f"{k}={v:#x}" for k, v in sorted(s["by_level"][name].items(), key=lambda kv: -Level[kv[0]]))
        print(f"section {name}: {levels}")
        print(f"  {classes}")
    lib_units = [f for f in st.facts(Kind.unit) if "lib" in f.value]
    units = Counter(f.value["tu"] for f in lib_units)
    libs = Counter(f.value.get("lib", "") for f in lib_units)
    funcs = [f for f in st.facts(Kind.symbol) if f.value.get("skind") == "func"]
    print(f"functions: {len(funcs)} (proven {sum(1 for f in funcs if f.level == Level.proven)}, "
          f"derived {sum(1 for f in funcs if f.level == Level.derived)}); library members placed: {len(units)} "
          + "  ".join(f"{k}={v}" for k, v in libs.items()))
    names = [f for f in st.facts(Kind.name) if f.value.get("origin") in ("export", "entry")]
    for f in names:
        print(f"  {f.value['origin']} {f.value['name']} at {fmt_addr(f.lo)}")
    game = [f for f in st.facts(Kind.unit) if "status" in f.value]
    if game:
        c = Counter(f.value["status"] for f in game)
        print(f"units: {len(game)}  " + "  ".join(f"{k}={v}" for k, v in sorted(c.items())) + "  (dcp layout units)")
    conf = st.conflicts()
    c = Counter(x.severity.value for x in conf)
    print("conflicts: " + ("  ".join(f"{k}={v}" for k, v in sorted(c.items())) if conf else "0"))


def cmd_why(args):
    p, e = open_project(args)
    refresh(p, e)
    st = p.store
    for s in args.addr:
        a = parse_addr(s)
        w = query.why(st, a)
        row = w["row"]
        if row is None:
            print(f"addr={fmt_addr(a)}  target={p.target_name}  not in the image")
            continue
        lo, hi, cls, level, *_ = row
        sec = p.image.section_of(a)
        off = f"  section={sec.name}  off=+{a - sec.va:#x}" if sec else "  (headers)"
        print(f"addr={fmt_addr(a)}  target={p.target_name}{off}  cls={cls}  level={Level(level)}  owner={fmt_range(lo, hi)}")
        for f in w["facts"]:
            print("  " + f.line())
        if args.refs:
            for f in w["refs_to"]:
                print(f"  ref->  {f.value['rkind']} from={fmt_addr(f.lo)} to={fmt_addr(f.value['to'])}  by={f.by}")
            for f in w["refs_from"]:
                print(f"  ref<-  {f.value['rkind']} at={fmt_addr(f.lo)} to={fmt_addr(f.value['to'])}  by={f.by}")
        else:
            print(f"  refs: to={len(w['refs_to'])} from={len(w['refs_from'])}  (--refs lists them)")


def cmd_facts(args):
    p, e = open_project(args)
    refresh(p, e)
    lo, hi = parse_range(args.range)
    facts = p.store.facts(args.kind, lo, hi)
    if args.json:
        for f in facts:
            print(canonical({"lo": f.lo, "hi": f.hi, "kind": f.kind.value, "value": f.value, "level": f.level.name, "by": f.by, "reason": f.reason}))
        return
    print(f"facts={len(facts)}  range={fmt_range(lo, hi)}" + (f"  kind={args.kind}" if args.kind else ""))
    for f in facts:
        print(f.line())


def cmd_conflicts(args):
    p, e = open_project(args)
    refresh(p, e)
    conf = p.store.conflicts(args.severity)
    if args.json:
        for x in conf:
            print(canonical({"severity": x.severity.value, "check": x.check, "lo": x.lo, "hi": x.hi, "message": x.message, "a": x.a, "b": x.b}))
        return
    c = Counter(x.severity.value for x in conf)
    print("conflicts=" + str(len(conf)) + ("  " + "  ".join(f"{k}={v}" for k, v in sorted(c.items())) if conf else ""))
    for x in conf:
        print(x.line())


def cmd_check(args):
    """The gate: every rule of every target ran (the loaders included), no bug / error conflicts. Exit 1
    otherwise. --target checks one target only."""
    p0 = Project(Path(args.root) if args.root else None, getattr(args, "target", None))
    names = [args.target] if getattr(args, "target", None) else [t.name for t in p0.targets]
    failed = False
    for name in names:
        p, e = open_project(args, name)
        refresh(p, e)
        conf = p.store.conflicts()
        c = Counter(x.severity.value for x in conf)
        bad = [x for x in conf if x.severity.value in ("bug", "error")]
        print(f"check target={name}: " + ("  ".join(f"{k}={v}" for k, v in sorted(c.items())) if conf else "no conflicts"))
        for x in bad:
            print(x.line())
        if args.strict:
            for x in conf:
                if x.severity.value == "warn":
                    print(x.line())
        failed = failed or bool(bad) or (args.strict and bool(conf))
    return 1 if failed else 0


def cmd_rules(args):
    p, e = open_project(args)
    refresh(p, e)
    for r, cur, ms, n in e.status():
        print(f"{r.id:<18} v{r.version:<3} {r.ceiling.name:<9} {'current' if cur else 'missing':<8} {ms:>6} ms {n:>6} facts  "
              f"needs={','.join(e.resolve_needs(r)) or '-'}  inputs={','.join(r.inputs) or '-'}" + ("  loader" if r.loader else ""))
        if args.verbose:
            for line in r.doc.splitlines():
                print("    " + line)


def cmd_map(args):
    p, e = open_project(args)
    refresh(p, e)
    st = p.store
    lo, hi = parse_range(args.range) if args.range else (p.image.base, p.image.end)
    rows = st.bytemap_rows(lo, hi)
    print(f"rows={len(rows)}  range={fmt_range(lo, hi)}")
    for rlo, rhi, cls, level, sym, unit, src, sec in rows:
        f = st.fact(sym)
        name = f.value.get("name", "") if f else ""
        u = st.fact(unit) if unit else None
        extra = f"  text={f.value['text']!r}" if f and "text" in f.value else ""
        ut = f"  unit={u.value['tu']}" if u else ""
        print(f"{fmt_range(rlo, rhi)}  {rhi - rlo:>7}  {cls:<14} {Level(level).name:<9} {name}{ut}{extra}")


def cmd_toolchain(args):
    p, e = open_project(args)
    refresh(p, e)
    tcf = next(iter(p.store.facts(Kind.toolchain)), None)
    decl = p.toolchain_decl
    print(f"declared: plugin={decl.get('plugin')} compiler={decl.get('compiler')!r} linker={decl.get('linker')!r} "
          f"cflags={' '.join(decl.get('cflags', []))!r}  reason={decl.get('reason', '')!r}")
    if tcf:
        v = tcf.value
        print(f"rich ({tcf.level}): compiler={v.get('compiler')} build={v.get('compiler_build')} "
              f"objects={v.get('compiler_objects')} language={v.get('language')} linker={v.get('linker')} build={v.get('linker_build')}")
        for en in v["entries"]:
            print(f"  prodid={en['prodid']:#04x} {en['tool']:<16} family={en['family']:<9} build={en['build']:<5} count={en['count']}")
    members = Counter(f.value.get("lib", "") for f in p.store.facts(Kind.unit) if "lib" in f.value)
    print("libraries placed: " + ("  ".join(f"{k}={v}" for k, v in members.items()) or "none"))
    print("probe: not run (milestone 3): flags are declared only")


def cmd_init(args):
    from .init import init_project
    init_project(Path(args.dir), Path(args.target_path), args.toolchain_root, args.name, args.target_name)


# ------------------------------------------------------------------------------------------------- targets
def cmd_target_list(args):
    p = Project(Path(args.root) if args.root else None)
    rows = []
    for i, t in enumerate(p.targets):
        sp = p.store_path(t.name)
        rows.append({"target": t.name, "default": i == 0, "path": t.path.as_posix(), "sha256": t.sha256[:16], "image": t.image,
                     "exists": t.path.exists(), "store": sp.relative_to(p.root).as_posix(), "store_exists": sp.exists(),
                     "form": "legacy" if t.legacy else "list"})
    if args.json:
        for r in rows:
            print(canonical(r))
        return
    print(f"targets={len(rows)}  default={p.default_target}")
    for r in rows:
        print(record(**r))


def cmd_target_add(args):
    from .init import add_target
    p = Project(Path(args.root) if args.root else None)
    text = add_target(p.root, args.name, Path(args.path))
    print(f"added to {p.config_path.name}:")
    for line in text.splitlines():
        print("  " + line)
    p2 = Project(p.root, args.name)
    print(f"target={args.name}  store={p2.store_path().relative_to(p2.root).as_posix()}  (run `dcp setup --target {args.name}`)")


# ------------------------------------------------------------------------------------------------- declarations
def cmd_decl_add(args):
    from .ledger import decl as D
    p, e = open_project(args)
    targets = [t.name for t in p.targets]
    try:
        d = D.parse_line(args.line.strip())
    except D.DeclError as ex:
        print(f"dcp decl add: {ex}", file=sys.stderr)
        return 1
    if d.target is None and p.target_name != p.default_target:
        d = D.Decl(d.lo, d.hi, d.kind, d.words, d.keys, d.reason, p.target_name)
    tname = d.target or p.default_target
    if tname not in targets:
        print(f"dcp decl add: unknown target {tname!r} (targets: {', '.join(targets)})", file=sys.stderr)
        return 1
    tp = p if tname == p.target_name else Project(p.root, tname)
    img = tp.image
    sec = img.section_of(d.lo)
    if sec is None:
        print(f"dcp decl add: {d.lo:#x} is not in a section of {tname}", file=sys.stderr)
        return 1
    if d.target == p.default_target:
        d = D.Decl(d.lo, d.hi, d.kind, d.words, d.keys, d.reason, None)      # a bare address is the default target
    fname = "text.dcl" if (sec.code or sec.executable) else "data.dcl"
    path = p.root / "decl" / fname
    existing, errors = D.load(sorted((p.root / "decl").glob("*.dcl")) if (p.root / "decl").exists() else [], p.root, targets)
    k = d.key(p.default_target)
    dup = next((x for x in existing if x.key(p.default_target) == k), None)
    if dup is not None:
        print(f"dcp decl add: duplicate of {dup.file}:{dup.line}: {dup.text()}", file=sys.stderr)
        return 1
    n = D.insert(path, d, targets)
    rel = path.relative_to(p.root).as_posix()
    print(f"added {rel}:{n}  {d.text()}")
    tp, te = open_project(args, tname)
    refresh(tp, te)
    by = f"decl:{rel}:{n}"
    mine = [x for x in tp.store.conflicts() if by in (x.a, x.b)]
    for x in mine:
        print(x.line())
    return 1 if any(x.severity.value in ("bug", "error") for x in mine) else 0


# ------------------------------------------------------------------------------------------------- layout
def cmd_layout_next(args):
    from .ledger import layoutview as LV
    p, e = open_project(args)
    refresh(p, e)
    v = LV.View.load(p, p.store)
    recs = LV.next_records(v, args.n, parse_addr(args.start) if args.start else None)
    und = LV.undrafted(v)
    if args.json:
        for r in recs:
            print(json.dumps(jsonable(r)))
        return
    print(record(target=p.target_name, game=v.game[:2], units=len(v.units), undrafted_in_units=len(und), shown=len(recs)))
    if not recs:
        print("nothing open: every function of the game code has a source fragment")
        return
    for r in recs:
        print(record(next=r["addr"], kind=r["kind"], size=r["size"], next_start=r["next_start"], unit=r["unit"],
                     unit_status=r["unit_status"], ghidra=r["ghidra"]))
        for what, kv in r["lines"]:
            print("  " + what + "  " + record(**kv))


def cmd_layout_units(args):
    from .ledger import layoutview as LV
    p, e = open_project(args)
    refresh(p, e)
    v = LV.View.load(p, p.store)
    rows = LV.unit_rows(v)
    if args.json:
        for r in rows:
            print(json.dumps(jsonable(r)))
        return
    glo, ghi, glevel = v.game
    covered = sum(r["range"][1] - r["range"][0] for r in rows)
    c = Counter(r["status"] for r in rows)
    lib = len({f.value["tu"] for f in p.store.facts(Kind.unit) if "lib" in f.value})
    print(record(target=p.target_name, units=len(rows), separated=c.get("separated", 0), open=c.get("open", 0), game=(glo, ghi),
                 game_end=glevel.name, unassigned=(ghi - glo) - covered, library_members=lib))
    for r in rows:
        print(record(unit=r["unit"], range=r["range"], status=r["status"], start=r["start"], end=r["end"], named_by=r["named_by"],
                     open_bytes=r["open_bytes"], functions=r["functions"], sourced=r["sourced"], undrafted=r["undrafted"],
                     leaks=r["leaks"] or None))
        if args.verbose:
            print("  " + record(start_by=r["start_by"], end_by=r["end_by"]))


def cmd_layout_propose(args):
    from .ledger import decl as D
    from .ledger import layoutview as LV
    p, e = open_project(args)
    refresh(p, e)
    if ".." in args.range:
        lo, hi = parse_range(args.range)
    else:
        lo, hi = parse_addr(args.range), None
    if not D.UNIT.match(args.name):
        print(f"dcp layout unit propose: {args.name!r} is not a unit name", file=sys.stderr)
        return 1
    v = LV.View.load(p, p.store)
    have = next((b for b in v.bounds if b.tu == args.name and b.side == "start"), None)
    if have is not None:
        print(f"dcp layout unit propose: unit {args.name} already starts at {have.addr:#x} ({have.by})", file=sys.stderr)
        return 1
    pr = LV.propose(v, lo, hi, args.name)
    print(record(proposal=args.name, range=(pr.lo, pr.hi), functions=len(pr.table), drafted=sum(1 for t in pr.table if t["drafted"]),
                 new_issues=len(pr.new_issues), by=args.by, why=args.why))
    for t in pr.table:
        print("  " + record(fn=t["fn"], size=t["size"], fill=t["fill"], drafted=t["drafted"], literals=t["lits"], first_literal=t["first_lit"],
                            leaks=t["leaks"] or None))
    for i in pr.new_issues:
        print(f"  issue  {i.severity}  {i.check}  {fmt_range(i.lo, i.hi)}  {i.message}")
    errors = [i for i in pr.new_issues if i.severity in ("error", "bug")]
    if errors:
        print(f"refused: {len(errors)} error(s); nothing written")
        return 1
    if args.dry_run:
        print("dry run: nothing written")
        return 0
    targets = [t.name for t in p.targets]
    prefix = None if p.target_name == p.default_target else p.target_name
    path = p.root / "decl" / "text.dcl"
    for addr, side in pr.lines:
        keys = {"tu": args.name}
        if args.by and side == "start":
            keys["by"] = args.by
        d = D.Decl(addr, addr + 1, "boundary", (side,), keys, args.why, prefix)
        n = D.insert(path, d, targets)
        print(f"added {path.relative_to(p.root).as_posix()}:{n}  {d.text()}")
    p2, e2 = open_project(args)
    refresh(p2, e2)
    bad = [x for x in p2.store.conflicts() if x.severity.value in ("bug", "error")]
    print(f"check: {len(bad)} error(s) after the proposal" + ("" if not bad else " (dcp check lists them)"))
    return 1 if bad else 0


# ------------------------------------------------------------------------------------------------- ghidra
def cmd_ghidra_import(args):
    from .ledger import ghidra as G
    p, e = open_project(args)
    img_sha = p.image.sha256
    total = 0
    for path in args.json_files:
        digest, entries, failed = G.parse(Path(path))
        if digest and digest != img_sha:
            other = next((t.name for t in p.targets if t.sha256 == digest), None)
            hint = f" (that is target {other}: --target {other})" if other else ""
            print(f"dcp ghidra import: {path} analysed sha256 {digest[:16]}, target {p.target_name} is {img_sha[:16]}{hint}", file=sys.stderr)
            return 1
        n = G.store_entries(p.store, img_sha, entries)
        total += n
        print(record(file=Path(path).name, imported=n, failed=len(failed)))
        for f in failed:
            print("  failed  " + f)
    p.forget_input("ghidra")
    refresh(p, e)
    print(record(target=p.target_name, drafts=len(G.entries(p.store)), imported=total))


def cmd_ghidra_show(args):
    from .ledger import ghidra as G
    p, e = open_project(args)
    refresh(p, e)
    a = parse_addr(args.addr)
    d = G.draft(p.store, p.image.sha256, a)
    if d is None:
        f = next((f for f in p.store.facts(Kind.symbol, a, a + 1) if f.value.get("skind") == "func"), None)
        if f is not None:
            d = G.draft(p.store, p.image.sha256, f.lo)
    if d is None:
        print(f"no Ghidra draft at {fmt_addr(a)} (dcp ghidra import JSON...)")
        return 1
    print(f"/* Ghidra draft of {fmt_addr(d.start)} {d.name} (requested {fmt_addr(d.requested)}, from {d.source}) */")
    sys.stdout.write(d.text)


# ------------------------------------------------------------------------------------------------- worktrees
def cmd_wt_new(args):
    from .repo import wt
    p = Project(Path(args.root) if args.root else None)
    path = wt.new(p.root, args.name)
    print(record(worktree=args.name, path=path.as_posix(), branch=f"wt/{args.name}", overlay=(p.root / "build").as_posix()))


def cmd_wt_list(args):
    from .repo import wt
    p = Project(Path(args.root) if args.root else None)
    es = wt.entries(p.root)
    print(f"worktrees={len(es)}")
    for x in es:
        path = Path(x["worktree"])
        print(record(worktree=x["name"], path=path.as_posix(), head=x.get("HEAD", "")[:12], overlay=(path / ".dcp" / "main_store").exists()))


def cmd_wt_drop(args):
    from .repo import wt
    p = Project(Path(args.root) if args.root else None)
    for m in wt.drop(p.root, args.name, args.force):
        print(m)


def cmd_seed(args):
    from .repo import wt
    p = Project(Path(args.root) if args.root else None)
    dest = Path(args.path).resolve()
    copied = wt.seed(p.build_dir, dest)
    print(record(seeded=dest.as_posix(), stores=copied))


# ------------------------------------------------------------------------------------------------- parser
def main(argv=None):
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--target", default=argparse.SUPPRESS, help="the target to work on (default: the first [[target]])")
    common.add_argument("--root", default=argparse.SUPPRESS, help="the target project (default: the decompanion.toml above the cwd)")
    ap = argparse.ArgumentParser(prog="dcp", description=__doc__.split("\n")[0])
    ap.add_argument("--root", help="the target project (default: the decompanion.toml above the cwd)")
    ap.add_argument("--target", help="the target to work on (default: the first [[target]] of decompanion.toml)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def cmd(parent, name, fn, help_):
        s = parent.add_parser(name, help=help_, parents=[common])
        s.set_defaults(fn=fn)
        return s

    s = cmd(sub, "setup", cmd_setup, "run every rule and print the report")
    s.add_argument("-v", "--verbose", action="store_true")
    s.add_argument("--force", action="store_true", help="rerun every rule")
    cmd(sub, "report", cmd_report, "the setup report")
    s = cmd(sub, "why", cmd_why, "everything known about an address")
    s.add_argument("addr", nargs="+")
    s.add_argument("--refs", action="store_true")
    s = cmd(sub, "facts", cmd_facts, "facts intersecting a range")
    s.add_argument("range")
    s.add_argument("--kind")
    s.add_argument("--json", action="store_true")
    s = cmd(sub, "map", cmd_map, "the byte map rows of a range")
    s.add_argument("range", nargs="?")
    s = cmd(sub, "conflicts", cmd_conflicts, "contradictions between facts")
    s.add_argument("--severity", choices=("bug", "error", "warn"))
    s.add_argument("--json", action="store_true")
    s = cmd(sub, "check", cmd_check, "the gate: exit 1 on any bug or error conflict (every target unless --target)")
    s.add_argument("--strict", action="store_true", help="warnings fail too")
    s = cmd(sub, "rules", cmd_rules, "the rule graph and run status")
    s.add_argument("-v", "--verbose", action="store_true", help="print each rule's criterion")
    cmd(sub, "toolchain", cmd_toolchain, "the toolchain evidence")
    s = cmd(sub, "init", cmd_init, "create a target project")
    s.add_argument("dir")
    s.add_argument("target_path", metavar="TARGET")
    s.add_argument("--toolchain-root", default="C:/Tools/MSVC600-SP5PP")
    s.add_argument("--name", help="the project's name (default: the directory's)")
    s.add_argument("--target-name", help="the target's name (default: the binary's stem)")

    t = sub.add_parser("target", help="the binaries of the project").add_subparsers(dest="sub", required=True)
    s = cmd(t, "list", cmd_target_list, "list the targets")
    s.add_argument("--json", action="store_true")
    s = cmd(t, "add", cmd_target_add, "add a target")
    s.add_argument("name")
    s.add_argument("path")

    d = sub.add_parser("decl", help="declarations (decl/*.dcl)").add_subparsers(dest="sub", required=True)
    s = cmd(d, "add", cmd_decl_add, "insert a declaration line in address order")
    s.add_argument("line", help='e.g. "0x10008cb0 boundary start tu=dllmain by=guess -- DllMain, Init, Exit"')

    lay = sub.add_parser("layout", help="the layout phase").add_subparsers(dest="sub", required=True)
    s = cmd(lay, "next", cmd_layout_next, "the first open function of the game code with its evidence")
    s.add_argument("-n", type=int, default=1, help="show the first N")
    s.add_argument("--start", help="from this address on")
    s.add_argument("--json", action="store_true")
    s = cmd(lay, "units", cmd_layout_units, "the unit table")
    s.add_argument("-v", "--verbose", action="store_true")
    s.add_argument("--json", action="store_true")
    u = lay.add_parser("unit", help="unit commands").add_subparsers(dest="sub2", required=True)
    s = cmd(u, "propose", cmd_layout_propose, "check a unit proposal (L3/L4/L7/L8) and write its boundary lines")
    s.add_argument("range", help="0xSTART..0xEND (END exclusive) or 0xSTART")
    s.add_argument("--name", required=True)
    s.add_argument("--why", required=True)
    s.add_argument("--by", choices=("leaked", "tag", "guess"))
    s.add_argument("--dry-run", action="store_true")

    g = sub.add_parser("ghidra", help="Ghidra drafts").add_subparsers(dest="sub", required=True)
    s = cmd(g, "import", cmd_ghidra_import, "import saved REA batch_decompile results")
    s.add_argument("json_files", nargs="+", metavar="JSON")
    s = cmd(g, "show", cmd_ghidra_show, "print the Ghidra draft of a function")
    s.add_argument("addr")

    w = sub.add_parser("wt", help="worktrees with an overlay store").add_subparsers(dest="sub", required=True)
    s = cmd(w, "new", cmd_wt_new, "create ../<project>-wt/NAME on branch wt/NAME")
    s.add_argument("name")
    cmd(w, "list", cmd_wt_list, "list the worktrees")
    s = cmd(w, "drop", cmd_wt_drop, "remove a worktree (and its branch when merged)")
    s.add_argument("name")
    s.add_argument("--force", action="store_true")
    s = cmd(sub, "seed", cmd_seed, "copy this checkout's stores into another checkout (fallback for the overlay)")
    s.add_argument("path")

    args = ap.parse_args(argv)
    try:
        return args.fn(args) or 0
    except ConfigError as ex:
        print(f"dcp: {ex}", file=sys.stderr)
        return 2
    except RuleError as ex:
        print(f"dcp: {ex}", file=sys.stderr)
        return 2
    except Exception as ex:
        from .repo.wt import WtError
        if isinstance(ex, WtError):
            print(f"dcp: {ex}", file=sys.stderr)
            return 2
        raise


if __name__ == "__main__":
    sys.exit(main())
