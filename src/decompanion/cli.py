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
def target_names(args) -> list[str | None]:
    """The targets a command runs on: --all-targets: every target in config order; else the selected one."""
    if getattr(args, "all_targets", False):
        if getattr(args, "target", None):
            raise ConfigError("--all-targets and --target exclude each other")
        p = Project(Path(args.root) if getattr(args, "root", None) else None)
        return [t.name for t in p.targets]
    return [getattr(args, "target", None)]


def cmd_setup(args):
    """Run every rule (a rule whose input is not declared yet waits: rules/engine.py); then, unless --no-analyzer,
    the configured analyzer's export when its key is stale (or --analyzer-force) and the rules again (L.analyzer
    and what reads its facts); then the report and the status tail (the open obligations, obligations.py). A
    missing analyzer is a warning line, not a failure; a failed export exits 1 after the report."""
    failed = False
    for i, name in enumerate(target_names(args)):
        if i:
            print()
        p, e = open_project(args, name)
        refresh(p, e, verbose=args.verbose, force=args.force)
        if not args.no_analyzer:
            failed = not run_analyzer(p, e, args) or failed
        view = cmd_report(args, p, e)
        from .cli_decide import status_tail
        status_tail(p, view)
    return 1 if failed else 0


def run_analyzer(p, e, args) -> bool:
    """The analyzer step of `dcp setup` (build/analyzer.py); False when the export failed."""
    from .build import analyzer as AX
    o = AX.run(p, force=args.analyzer_force)
    if o.status == "unavailable":
        print(f"analyzer={o.analyzer} unavailable: {o.reason}", file=sys.stderr)
    elif o.status == "failed":
        print(f"analyzer={o.analyzer} failed: {o.reason}", file=sys.stderr)
        return False
    elif o.status == "exported":
        ex = o.export
        out = ex.out.relative_to(p.root).as_posix() if ex.out is not None and ex.out.is_relative_to(p.root) else None
        print(record(analyzer=o.analyzer, exported=o.stored, failed=len(ex.failed), skipped=len(ex.skipped) or None, ms=ex.ms,
                     where=o.where, out=out))
        for f in ex.failed[:20]:
            print("  failed  " + f)
        for f, digest in ex.skipped:
            other = next((t.name for t in p.targets if t.name != p.target_name and p.image_of(t.name).sha256 == digest), None)
            print("  " + record(skipped=f, sha256=digest[:16], target=other))
        refresh(p, e, verbose=args.verbose)
    if o.note:
        print(f"analyzer={o.analyzer}: {o.note}", file=sys.stderr)
    return True


def candidate_entry(tc, e) -> str:
    """One Rich candidate as `dcp toolchain` prints it."""
    extra = f", {e['archive_objects']} archive objects" if e.get("archive_objects") else ""
    return f"{tc.declare(e)} ({e['tool']} {e['language'] or '-'} x{e['count']}{extra})"


def cmd_report(args, p=None, e=None):
    if p is None:
        for i, name in enumerate(target_names(args)):
            if i:
                print()
            p, e = open_project(args, name)
            refresh(p, e)
            cmd_report(args, p, e)
        return
    st = p.store
    img = p.image
    print(f"target={p.target_name}  file={p.image_path.name}  sha256={img.sha256[:16]}  base={fmt_addr(img.base)}  entry={fmt_addr(img.entry)}  "
          f"{'dll' if img.is_dll else 'exe'}  linker={img.linker_version[0]}.{img.linker_version[1]}  sections={len(img.sections)}")
    decl = p.toolchain_decl
    tcf = next(iter(st.facts(Kind.toolchain, rules=("S.rich",))), None)
    rich = (f"  rich: compilers={len(tcf.value.get('compilers') or [])} linkers={len(tcf.value.get('linkers') or [])} "
            f"(dcp toolchain)") if tcf else "  rich: none"
    print(f"toolchain: compiler={decl.get('compiler') or '-'!r} linker={decl.get('linker') or '-'!r} "
          f"cflags={' '.join(decl.get('cflags') or []) or '-'!r} root={decl.get('root') or '-'!r}{rich}")
    s = query.summary(st)
    for name in s["by_section"]:
        classes = "  ".join(f"{k}={v:#x}" for k, v in sorted(s["by_section"][name].items(), key=lambda kv: -kv[1]))
        levels = "  ".join(f"{k}={v:#x}" for k, v in sorted(s["by_level"][name].items(), key=lambda kv: -Level[kv[0]]))
        print(f"section {name}: {levels}")
        print(f"  {classes}")
    lib_units = {(f.value.get("lib", ""), f.value["tu"]) for f in st.facts(Kind.unit) if "lib" in f.value}
    units = {tu for _, tu in lib_units}
    libs = Counter(lib for lib, _ in sorted(lib_units))
    funcs = [f for f in st.facts(Kind.symbol) if f.value.get("skind") == "func" and not f.run.startswith("M.")]
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
    from .cli_layout import print_analyzer
    view = print_analyzer(p, getattr(args, "verbose", False))
    waiting = {r.id: w for r in e.order() if (w := e.waiting(r))}
    if waiting:
        print(record(waiting=len(waiting), rules=",".join(sorted(waiting)),
                     on=",".join(dict.fromkeys(x for w in waiting.values() for x in w))) + "  (their facts are missing until declared)")
    conf = st.conflicts()
    c = Counter(x.severity.value for x in conf)
    print("conflicts: " + ("  ".join(f"{k}={v}" for k, v in sorted(c.items())) if conf else "0"))
    return view


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
        probed = [f for f in w["facts"] if f.kind is Kind.toolchain and "flag" in f.value]
        if probed:
            print(f"  {fmt_range(probed[0].lo, probed[0].hi)}  toolchain probe  "
                  + " ".join(f"{f.value['flag']}={f.level}" for f in sorted(probed, key=lambda f: f.value["group"]))
                  + f"  (dcp toolchain)  by={probed[0].by}")
        for f in w["facts"]:
            if f.kind is Kind.toolchain and "flag" in f.value:
                continue
            if f.kind is Kind.toolchain and "compilers" in f.value:   # spans the image: one line, `dcp toolchain` has the rest
                print(f"  {fmt_range(f.lo, f.hi)}  toolchain  compilers={len(f.value.get('compilers') or [])}  "
                      f"linkers={len(f.value.get('linkers') or [])}  (dcp toolchain)  {f.level}  by={f.by}")
                continue
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
    print(f"target={p.target_name}  facts={len(facts)}  range={fmt_range(lo, hi)}" + (f"  kind={args.kind}" if args.kind else ""))
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
    print(f"target={p.target_name}  conflicts={len(conf)}" + ("  " + "  ".join(f"{k}={v}" for k, v in sorted(c.items())) if conf else ""))
    for x in conf:
        print(x.line())


def cmd_check(args):
    """The gate, per target (every target unless --target): the stale units compile (dcp build), every rule
    ran (the loaders included), no bug / error conflicts (M.compile, M.gen, M1, M8.. among them), no open
    toolchain or libs obligation (obligations.py), and, once
    the target has a fragment, the full link resolves every external. --against REV: no function grade fell
    against ledger/grades.tsv at that git revision. Exit 1 otherwise."""
    from .build import link as L
    from .cli_match import print_link
    from .ledger import grades as G
    p0 = Project(Path(args.root) if args.root else None, getattr(args, "target", None))
    names = [args.target] if getattr(args, "target", None) else [t.name for t in p0.targets]
    failed = False
    against = G.baseline_at(p0.root, args.against) if getattr(args, "against", None) else None
    for name in names:
        p, e, rep = build_target(args, name, quiet=True)
        from .source import lint as LI
        if p.store.facts(Kind.build) and LI.clang_path(p) is not None:
            from .cli_match import lint_target
            lint_target(p, e)
        conf = p.store.conflicts()
        c = Counter(x.severity.value for x in conf)
        bad = [x for x in conf if x.severity.value in ("bug", "error")]
        print(f"check target={name}: " + ("  ".join(f"{k}={v}" for k, v in sorted(c.items())) if conf else "no conflicts"))
        for x in bad:
            print(x.line())
        from .obligations import gate_failures
        open_ = gate_failures(p)
        for o in open_:
            print(record(**o.fields()))
        failed = failed or bool(open_)
        if args.strict:
            for x in conf:
                if x.severity.value == "warn":
                    print(x.line())
        failed = failed or bool(bad) or (args.strict and bool(conf))
        if p.store.facts(Kind.build) and p.toolchain.available():
            lr = L.full_link(p)
            print_link(lr)
            failed = failed or not lr.ok
        elif p.store.facts(Kind.build):
            print(record(link=name, skipped="the toolchain is not available"))
        if against is not None:
            falls = G.regressions(p, against)
            print(record(against=args.against, target=name, falls=len(falls)))
            for line in falls:
                print("  fell: " + line)
            failed = failed or bool(falls)
    return 1 if failed else 0


def cmd_rules(args):
    p, e = open_project(args)
    refresh(p, e)
    rows = e.status()
    print(record(target=p.target_name, rules=len(rows), current=sum(1 for _, cur, _, _, w in rows if cur and not w),
                 waiting=sum(1 for *_, w in rows if w)))
    for r, cur, ms, n, waits in rows:
        state = "waiting" if waits else ("current" if cur else "missing")
        print(f"{r.id:<18} v{r.version:<3} {r.ceiling.name:<9} {state:<8} {ms:>6} ms {n:>6} facts  "
              f"needs={','.join(e.resolve_needs(r)) or '-'}  inputs={','.join(r.inputs) or '-'}" + ("  loader" if r.loader else ""))
        if waits:
            print(f"    waiting: {', '.join(waits)}  (dcp status)")
        if args.verbose:
            for line in r.doc.splitlines():
                print("    " + line)


def cmd_map(args):
    p, e = open_project(args)
    refresh(p, e)
    st = p.store
    lo, hi = parse_range(args.range) if args.range else (p.image.base, p.image.end)
    rows = st.bytemap_rows(lo, hi)
    print(f"target={p.target_name}  rows={len(rows)}  range={fmt_range(lo, hi)}")
    for rlo, rhi, cls, level, sym, unit, src, sec in rows:
        f = st.fact(sym)
        name = f.value.get("name", "") if f else ""
        u = st.fact(unit) if unit else None
        extra = f"  text={f.value['text']!r}" if f and "text" in f.value else ""
        ut = f"  unit={u.value['tu']}" if u else ""
        print(f"{fmt_range(rlo, rhi)}  {rhi - rlo:>7}  {cls:<14} {Level(level).name:<9} {name}{ut}{extra}")


# ------------------------------------------------------------------------------------------------- match phase
def build_target(args, name, quiet=False):
    """Compile the stale units of one target and refresh its rules: (project, engine, compile report)."""
    from .build import compile as B
    p, e = open_project(args, name)
    rep = B.ensure(p, log=None if quiet else print, force=getattr(args, "force", False))
    refresh(p, e)
    return p, e, rep


def cmd_build(args):
    """Compile every stale unit (one compiler process per unit, in a pool), then refresh the rules."""
    failed = False
    for i, name in enumerate(target_names(args)):
        if i:
            print()
        p, e, rep = build_target(args, name)
        builds = sorted(p.store.facts(Kind.build), key=lambda f: f.value["tu"])
        bad = [f for f in builds if not f.value["ok"]]
        print(record(target=p.target_name, units=rep.units, compiled=len(rep.compiled), failed=len(bad),
                     fresh=rep.units - len(rep.compiled), removed=len(rep.removed), ms=rep.ms))
        for f in builds:
            v = f.value
            print("  " + record(tu=v["tu"], at=f.lo, ok=v["ok"], obj=v.get("obj"), fragments=v.get("fragments"),
                                warnings=v.get("warnings", 0), errors=len(v.get("errors") or []), flags=v.get("flags")))
            for x in (v.get("errors") or [])[:10]:
                print("    " + x)
        failed = failed or bool(bad)
        from .ledger import grades as G
        rows = G.function_grades(p.store)
        if rows:
            c = Counter((r["code"], r["readability"]) for r in rows)
            print("  grades: " + "  ".join(f"{k[0]}+{k[1]}={v}" for k, v in sorted(c.items())))
        cleared = G.auto_clear(p, rows)
        for line in cleared:
            print("  " + line)
        if cleared:
            p, e, rep = build_target(args, name, quiet=True)
    return 1 if failed else 0


def cmd_unit_cat(args):
    """Print the amalgamation of a unit (head, fragments in address order, tail) as the compiler sees it."""
    from .build import compile as B
    p, e = open_project(args)
    a = next((a for a in B.plan(p) if a.unit == args.unit), None)
    if a is None:
        print(f"dcp unit cat: no unit {args.unit!r} with a fragment of target {p.target_name}", file=sys.stderr)
        return 1
    sys.stdout.write(a.text)


def cmd_init(args):
    """Create the project: the [[target]] computed from the binary, nothing declared (init.py)."""
    from .init import init_project
    init_project(Path(args.dir), Path(args.target_path), args.name, args.target_name)


# ------------------------------------------------------------------------------------------------- targets
def cmd_target_list(args):
    p = Project(Path(args.root) if args.root else None)
    rows = []

    def machine_isa(t):
        try:
            return f"{p.image_of(t.name).default_isa}(machine)"
        except ConfigError:                     # missing file or sha256 mismatch: the list still prints
            return "-"

    for i, t in enumerate(p.targets):
        sp = p.store_path(t.name)
        rows.append({"target": t.name, "default": i == 0, "path": t.path.as_posix(), "sha256": t.sha256[:16], "image": t.image,
                     "isa": t.isa or machine_isa(t), "exists": t.path.exists(), "store": sp.relative_to(p.root).as_posix(), "store_exists": sp.exists(),
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
                     unit_status=r["unit_status"], analyzed=r["analyzed"]))
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
    if args.verbose:
        from .ledger import srcscan
        und = LV.undrafted(v)
        conf = p.store.conflicts()
        sc = srcscan.scan(p.root, p.input_hash("src"))
    c = Counter(r["status"] for r in rows)
    lib = len({f.value["tu"] for f in p.store.facts(Kind.unit) if "lib" in f.value})
    print(record(target=p.target_name, units=len(rows), separated=c.get("separated", 0), open=c.get("open", 0), game=(glo, ghi),
                 game_end=glevel.name, unassigned=(ghi - glo) - covered, library_members=lib))
    for r in rows:
        print(record(unit=r["unit"], range=r["range"], status=r["status"], start=r["start"], end=r["end"], named_by=r["named_by"],
                     open_bytes=r["open_bytes"], functions=r["functions"], sourced=r["sourced"], undrafted=r["undrafted"],
                     leaks=r["leaks"] or None))
        if args.verbose:
            print("  " + record(start_by=r["start_by"], end_by=r["end_by"], dead_bytes=r["dead_bytes"], walk_conflicts=r["walk_conflicts"]))
            lo, hi = r["range"]
            mine = [a for a in und if lo <= a < hi]
            for a in mine[:8]:
                print("  " + record(undrafted=a) + "  (L2)")
            if len(mine) > 8:
                print(f"  ... {len(mine) - 8} more undrafted (L2): dcp layout next --start {mine[8]:#010x} -n N")
            for x in conf:
                if x.check in ("L10", "C.walk", "M.bytes.declared") and lo <= x.lo < hi:
                    print("  " + x.line())
            for f in sc.functions:
                if f.unlinked and f.unit == r["unit"]:
                    print("  " + record(unlinked=f.name, file=f.file, why=f.what or None))


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
    rel = path.relative_to(p.root).as_posix()
    bys = {f"decl:{rel}:{i}" for i, line in enumerate(path.read_text().splitlines(), 1) if f"tu={args.name} " in line + " "}
    bad = [x for x in p2.store.conflicts() if x.severity.value in ("bug", "error")]
    mine = [x for x in bad if x.a in bys or x.b in bys]
    print(f"check: {len(mine)} error(s) of the proposal's lines, {len(bad)} in all" + ("" if not bad else " (dcp check lists them)"))
    for x in mine:
        print(x.line())
    return 1 if mine else 0


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
    s.add_argument("--all-targets", action="store_true", help="every target in config order")
    s.add_argument("--no-analyzer", action="store_true", help="skip the analyzer's export")
    s.add_argument("--analyzer-force", action="store_true", help="export again although the export key is unchanged")
    s = cmd(sub, "report", cmd_report, "the setup report (with the analyzer's drafts)")
    s.add_argument("--all-targets", action="store_true", help="every target in config order")
    s.add_argument("-v", "--verbose", action="store_true", help="list every analyzer-only and ours-only start")
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
    s = cmd(sub, "check", cmd_check, "the gate: build, no bug or error conflict, the link resolves (every target unless --target)")
    s.add_argument("--strict", action="store_true", help="warnings fail too")
    s.add_argument("--against", metavar="REV", help="no grade fell against ledger/grades.tsv at this git revision")
    s = cmd(sub, "rules", cmd_rules, "the rule graph and run status")
    s.add_argument("-v", "--verbose", action="store_true", help="print each rule's criterion")
    from . import cli_decide as CD
    CD.register(sub, cmd)

    from . import cli_match as CM
    s = cmd(sub, "grade", CM.cmd_grade, "the grades: matrix and units, or one unit / function with the failing rules")
    s.add_argument("what", nargs="?", metavar="NAME|UNIT|ADDR")
    s = cmd(sub, "next", CM.cmd_next, "the next functions of the base (default), deep or names queue")
    s.add_argument("--base", action="store_true")
    s.add_argument("--deep", action="store_true")
    s.add_argument("--names", action="store_true")
    s.add_argument("-n", type=int, default=1)
    s.add_argument("--unit")
    s.add_argument("--shard", help="k/N (or off); default: the file .dcp/shard")
    s = cmd(sub, "asmdiff", CM.cmd_asmdiff, "the instruction diff of one function (ours '-', the original '+')")
    s.add_argument("name")
    s.add_argument("--regs", help="rename registers on our side: a=b,c=d")
    s.add_argument("--all", action="store_true", help="print every equal instruction")
    s = cmd(sub, "diffclass", CM.cmd_diffclass, "the hunk classes of one function's instruction diff")
    s.add_argument("name")
    for lvl, verb in (("deep", "escalate"), ("stuck", "stuck")):
        s = cmd(sub, verb, CM.cmd_level, f"write `@{lvl} why` into a function's address comment (--clear removes the tag)")
        s.add_argument("name")
        s.add_argument("why", nargs="?")
        s.add_argument("--clear", action="store_true")
        s.set_defaults(level=lvl)
    cmd(sub, "promote", CM.cmd_promote, "write the grade baseline ledger/grades.tsv (main checkout only)")
    s = cmd(sub, "link", CM.cmd_link, "the full link of a target with the unresolved externals classified")
    s.add_argument("--all-targets", action="store_true")
    s = cmd(sub, "lint", CM.cmd_lint, "clang as the declaration checker (M5 / M6 / M7, readability Q7)")
    s.add_argument("--all-targets", action="store_true")
    s = cmd(sub, "init", cmd_init, "create a target project (declares nothing: dcp setup, then dcp status)")
    s.add_argument("dir")
    s.add_argument("target_path", metavar="TARGET")
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
    from . import cli_read as CR
    s = cmd(lay, "literals", CR.cmd_layout_literals, "the literal-pool view of a unit or range: first users, blocks, interleaving (B-LIT)")
    s.add_argument("what", nargs="?", metavar="UNIT|LO..HI", help="default: the game code")
    s = cmd(lay, "starts", CR.cmd_layout_starts, "every function start in a range with its evidence")
    s.add_argument("range", nargs="?", metavar="LO..HI", help="default: the game code")
    u = lay.add_parser("unit", help="unit commands").add_subparsers(dest="sub2", required=True)
    s = cmd(u, "propose", cmd_layout_propose, "check a unit proposal (L3/L4/L7/L8) and write its boundary lines")
    s.add_argument("range", help="0xSTART..0xEND (END exclusive) or 0xSTART")
    s.add_argument("--name", required=True)
    s.add_argument("--why", required=True)
    s.add_argument("--by", choices=("leaked", "tag", "guess"))
    s.add_argument("--dry-run", action="store_true")

    s = cmd(sub, "build", cmd_build, "compile every stale unit, refresh the rules, print the build and grade summary")
    s.add_argument("--all-targets", action="store_true", help="every target in config order")
    s.add_argument("--force", action="store_true", help="compile every unit")
    un = sub.add_parser("unit", help="units").add_subparsers(dest="sub", required=True)
    s = cmd(un, "cat", cmd_unit_cat, "print a unit's amalgamation")
    s.add_argument("unit")
    from . import cli_layout as CLU
    CLU.register_unit(un, cmd)

    from . import cli_layout as CL
    CL.register(sub, cmd)

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
