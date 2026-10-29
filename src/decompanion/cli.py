"""dcp: the command line. Every command refreshes the rule engine first (nothing changed: nothing runs), then
answers from the store. Output: one record per line, key=value tokens, addresses 0x%08x, intervals lo..hi
(hi exclusive), sorted by address, counts before lists; --json gives the same records as JSON lines.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

from . import rules  # noqa: F401  (registers every rule)
from .config import ConfigError, Project
from .ledger.fact import Kind, Level, canonical
from .ledger import query
from .rules.engine import RULES, Engine, RuleError


def fmt_addr(a):
    return f"{a:#010x}"


def fmt_range(lo, hi):
    return f"{lo:#010x}..{hi:#010x}" if hi > lo + 1 else f"{lo:#010x}"


def parse_addr(s: str) -> int:
    return int(s, 16) if s.lower().startswith("0x") else int(s, 0)


def parse_range(s: str) -> tuple[int, int]:
    if ".." in s:
        a, b = s.split("..", 1)
        return parse_addr(a), parse_addr(b)
    a = parse_addr(s)
    return a, a + 1


def open_project(args) -> tuple[Project, Engine]:
    p = Project(Path(args.root) if getattr(args, "root", None) else None)
    e = Engine(p, p.store)
    return p, e


def refresh(p: Project, e: Engine, verbose=False, force=False, only=None):
    t0 = time.perf_counter()
    res = e.run(only, force=force, log=(lambda s: print(s, file=sys.stderr)) if verbose else None)
    ran = [r for r in res if r.ran]
    if verbose or ran:
        print(f"rules: {len(ran)} ran of {len(res)}, {int((time.perf_counter() - t0) * 1000)} ms", file=sys.stderr)
    query.ensure_bytemap(p.store)
    return res


# ------------------------------------------------------------------------------------------------- commands
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
    print(f"target={p.target.name}  sha256={img.sha256[:16]}  base={fmt_addr(img.base)}  entry={fmt_addr(img.entry)}  "
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
    units = Counter(f.value["tu"] for f in st.facts(Kind.unit))
    libs = Counter(f.value.get("lib", "") for f in st.facts(Kind.unit))
    funcs = [f for f in st.facts(Kind.symbol) if f.value.get("skind") == "func"]
    print(f"functions: {len(funcs)} (proven {sum(1 for f in funcs if f.level == Level.proven)}, "
          f"derived {sum(1 for f in funcs if f.level == Level.derived)}); library members placed: {len(units)} "
          + "  ".join(f"{k}={v}" for k, v in libs.items()))
    names = [f for f in st.facts(Kind.name) if f.value.get("origin") in ("export", "entry")]
    for f in names:
        print(f"  {f.value['origin']} {f.value['name']} at {fmt_addr(f.lo)}")
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
            print(f"addr={fmt_addr(a)}  not in the image")
            continue
        lo, hi, cls, level, *_ = row
        sec = p.image.section_of(a)
        off = f"  section={sec.name}  off=+{a - sec.va:#x}" if sec else "  (headers)"
        print(f"addr={fmt_addr(a)}{off}  cls={cls}  level={Level(level)}  owner={fmt_range(lo, hi)}")
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
    c = Counter(x.severity.value for x in conf)
    print("conflicts=" + str(len(conf)) + ("  " + "  ".join(f"{k}={v}" for k, v in sorted(c.items())) if conf else ""))
    for x in conf:
        print(x.line())


def cmd_check(args):
    """The gate: every rule ran, no bug / error conflicts. Exit 1 otherwise."""
    p, e = open_project(args)
    refresh(p, e)
    conf = p.store.conflicts()
    c = Counter(x.severity.value for x in conf)
    bad = [x for x in conf if x.severity.value in ("bug", "error")]
    print("check: " + ("  ".join(f"{k}={v}" for k, v in sorted(c.items())) if conf else "no conflicts"))
    for x in bad:
        print(x.line())
    if args.strict:
        for x in conf:
            if x.severity.value == "warn":
                print(x.line())
    return 1 if bad or (args.strict and conf) else 0


def cmd_rules(args):
    p, e = open_project(args)
    refresh(p, e)
    for r, cur, ms, n in e.status():
        print(f"{r.id:<18} v{r.version:<3} {r.ceiling.name:<9} {'current' if cur else 'missing':<8} {ms:>6} ms {n:>6} facts  "
              f"needs={','.join(e.resolve_needs(r)) or '-'}  inputs={','.join(r.inputs) or '-'}")
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
        extra = f"  text={f.value['text']!r}" if f and "text" in f.value else ""
        print(f"{fmt_range(rlo, rhi)}  {rhi - rlo:>7}  {cls:<14} {Level(level).name:<9} {name}{extra}")


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
    members = Counter(f.value.get("lib", "") for f in p.store.facts(Kind.unit))
    print("libraries placed: " + ("  ".join(f"{k}={v}" for k, v in members.items()) or "none"))
    print("probe: not run (milestone 3): flags are declared only")


def cmd_init(args):
    from .init import init_project
    init_project(Path(args.dir), Path(args.target), args.toolchain_root, args.name)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="dcp", description=__doc__.split("\n")[0])
    ap.add_argument("--root", help="the target project (default: the decompanion.toml above the cwd)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("setup", help="run the setup rules and print the report")
    s.add_argument("-v", "--verbose", action="store_true")
    s.add_argument("--force", action="store_true", help="rerun every rule")
    s.set_defaults(fn=cmd_setup)
    s = sub.add_parser("report", help="the setup report")
    s.set_defaults(fn=cmd_report)
    s = sub.add_parser("why", help="everything known about an address")
    s.add_argument("addr", nargs="+")
    s.add_argument("--refs", action="store_true")
    s.set_defaults(fn=cmd_why)
    s = sub.add_parser("facts", help="facts intersecting a range")
    s.add_argument("range")
    s.add_argument("--kind")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_facts)
    s = sub.add_parser("map", help="the byte map rows of a range")
    s.add_argument("range", nargs="?")
    s.set_defaults(fn=cmd_map)
    s = sub.add_parser("conflicts", help="contradictions between facts")
    s.add_argument("--severity", choices=("bug", "error", "warn"))
    s.set_defaults(fn=cmd_conflicts)
    s = sub.add_parser("check", help="the gate: exit 1 on any bug or error conflict")
    s.add_argument("--strict", action="store_true", help="warnings fail too")
    s.set_defaults(fn=cmd_check)
    s = sub.add_parser("rules", help="the rule graph and run status")
    s.add_argument("-v", "--verbose", action="store_true", help="print each rule's criterion")
    s.set_defaults(fn=cmd_rules)
    s = sub.add_parser("toolchain", help="the toolchain evidence")
    s.set_defaults(fn=cmd_toolchain)
    s = sub.add_parser("init", help="create a target project")
    s.add_argument("dir")
    s.add_argument("target")
    s.add_argument("--toolchain-root", default="C:/Tools/MSVC600-SP5PP")
    s.add_argument("--name")
    s.set_defaults(fn=cmd_init)
    args = ap.parse_args(argv)
    try:
        return args.fn(args) or 0
    except (ConfigError, RuleError) as ex:
        print(f"dcp: {ex}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
