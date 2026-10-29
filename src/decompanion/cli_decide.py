"""dcp: the guided decisions (obligations.py): `dcp status` (the phase and the open obligations in order), the
evidence views (`dcp toolchain`, `dcp libs candidates`) and the declarations (`dcp toolchain declare`, `dcp libs
declare`, `dcp analyzer declare`). A declaration always carries a reason (`--why`, refused without one), lands
in decompanion.toml as `key = value` with `reason.<key> = "..."`, is level declared, and reruns the rules at
once so the next obligation shows. The tool never declares anything on its own. Same output contract as cli.py.
"""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

from .cli import candidate_entry, open_project, record, refresh
from .config import Project
from .ledger.fact import Kind
from . import obligations as OB
from . import tomledit as TE


def err(cmd: str, msg: str, code: int = 1) -> int:
    print(f"dcp {cmd}: {msg}", file=sys.stderr)
    return code


# ------------------------------------------------------------------------------------------------ status
def print_status(p, view=None, shown: set | None = None, work: bool = True) -> list:
    """The status tail of one target: `status target= phase= open=` and one record per open obligation, in
    order. `shown`: ids of project-wide obligations already printed (multi-target output prints them once).
    Returns the obligations."""
    obls = OB.compute(p, view, work=work)
    shown = shown if shown is not None else set()
    rows = [o for o in obls if not (o.target is None and o.id in shown)]
    print(record(status=p.target_name, phase=OB.phase(obls), open=len(obls)))
    for o in rows:
        print(record(**o.fields()))
        if o.target is None:
            shown.add(o.id)
    if not obls:
        print("nothing open: every decision is declared and every function is byte + readable")
    return obls


def cmd_status(args):
    """Per target (every target unless --target): the phase and the open obligations in order, each with what is
    missing, the evidence so far and the command that resolves it (obligations.py). Exit 0."""
    shown: set = set()
    names = ([args.target] if getattr(args, "target", None)
             else [t.name for t in Project(Path(args.root) if args.root else None).targets])
    for i, name in enumerate(names):
        if i:
            print()
        p, e = open_project(args, name)
        refresh(p, e)
        print_status(p, shown=shown)
    return 0


def status_tail(p, view=None, work: bool = True):
    """The tail other commands print (setup, session start, the declarations)."""
    print("--- dcp status")
    print_status(p, view, work=work)


# ------------------------------------------------------------------------------------------------ declarations
def parse_pairs(cmd: str, pairs: list[str], known: tuple[str, ...]) -> dict | None:
    out = {}
    for s in pairs:
        if "=" not in s:
            err(cmd, f"{s!r} is not KEY=VALUE (keys: {', '.join(known)})")
            return None
        k, v = s.split("=", 1)
        k = k.strip()
        if k not in known:
            err(cmd, f"unknown key {k!r} (keys: {', '.join(known)})")
            return None
        out[k] = v.strip()
    return out


def target_table(p) -> tuple[str, int | None]:
    """The (table, index) of the current target in decompanion.toml for tomledit."""
    t = p.target()
    if t.legacy:
        return "target", None
    return "target", [x.name for x in p.targets].index(t.name)


def no_why(cmd: str, why) -> bool:
    if why is None or not str(why).strip():
        err(cmd, 'a declaration needs its reason: --why "..." (the evidence it rests on); nothing written')
        return True
    return False


def rerun(args, name):
    """The rules again after a declaration, so the next obligation shows at once: (project, engine), or None
    before the first `dcp setup` of the target (no store yet: setup runs the rules the first time, a
    declaration made before it only writes)."""
    p = Project(Path(args.root) if args.root else None, name)
    if not p.store_path().exists():
        print("rules: not run yet (no store): `dcp setup` runs them and prints the next obligations")
        return None
    p, e = open_project(args, name)
    refresh(p, e)
    return p, e


TOOLCHAIN_DECL_KEYS = ("compiler", "linker", "root", "cflags", "plugin")


def cmd_toolchain_declare(args):
    """Declare any of compiler= linker= cflags= (the current target's table) root= plugin= ([toolchain]) with one
    reason (--why), stored per key; then rerun the rules and print C.toolchain and the status tail."""
    cmd = "toolchain declare"
    if no_why(cmd, args.why):
        return 2
    kv = parse_pairs(cmd, args.pairs, TOOLCHAIN_DECL_KEYS)
    if kv is None:
        return 2
    if not kv:
        return err(cmd, f"nothing to declare (keys: {', '.join(TOOLCHAIN_DECL_KEYS)})", 2)
    p = Project(Path(args.root) if args.root else None, getattr(args, "target", None))
    why = args.why.strip()
    if "root" in kv:
        root = Path(kv["root"]).expanduser()
        if not root.is_dir():
            return err(cmd, f"root={kv['root']}: no such directory; nothing written", 2)
        kv["root"] = root.resolve().as_posix()
    if "plugin" in kv:
        from . import toolchains
        if kv["plugin"] not in toolchains.TOOLCHAINS:
            return err(cmd, f"plugin={kv['plugin']}: unknown (known: {', '.join(toolchains.TOOLCHAINS)}); nothing written", 2)
    path = p.config_path
    tgt = {k: (v.split() if k == "cflags" else v) for k, v in kv.items() if k in ("compiler", "linker", "cflags")}
    proj = {k: v for k, v in kv.items() if k in ("root", "plugin")}
    if tgt:
        table, index = target_table(p)
        TE.set_keys(path, table, {**tgt, **{f"reason.{k}": why for k in tgt}}, index,
                    covered=("compiler", "linker", "cflags", "archives"))
    if proj:
        TE.set_keys(path, "toolchain", {**proj, **{f"reason.{k}": why for k in proj}},
                    covered=("plugin", "root", "compiler", "linker", "cflags"))
    for k, v in {**tgt, **proj}.items():
        where = f"target {p.target_name}" if k in tgt else "[toolchain]"
        print(record(declared=k, value=" ".join(v) if isinstance(v, list) else v, level="declared", where=where, why=why))
    r = rerun(args, p.target_name)
    if r is None:
        return 0
    p, e = r
    if "root" in proj:
        inst = p.toolchain.install(Path(proj["root"]))
        print("  " + record(root=proj["root"], available=p.toolchain.available(), **inst.versions))
    bad = [x for x in p.store.conflicts() if x.check == "C.toolchain"]
    if not p.waiting("toolchain"):
        print("C.toolchain: " + ("ok" if not bad else f"{len(bad)} error(s)"))
        for x in bad:
            print("  " + x.message)
    status_tail(p)
    return 1 if bad else 0


def cmd_libs_declare(args):
    """Declare the current target's static library archives (bare names are the toolchain's archives under the
    declared root: Toolchain.archive_spec) with a reason; rerun the rules (S.crt.code places the members) and
    print what was placed and the status tail."""
    cmd = "libs declare"
    if no_why(cmd, args.why):
        return 2
    p = Project(Path(args.root) if args.root else None, getattr(args, "target", None))
    specs = [p.toolchain.archive_spec(a) for a in args.archives]
    if any("{toolchain.root}" in s for s in specs) and not p.toolchain_decl.get("root"):
        return err(cmd, "the archives are named under the toolchain root, which is not declared yet: "
                        'dcp toolchain declare root=DIR --why "..." first; nothing written', 2)
    missing = [s for s in specs if not p.expand(s).exists()]
    if missing:
        return err(cmd, "no such archive: " + ", ".join(p.expand(s).as_posix() for s in missing) + "; nothing written", 2)
    why = args.why.strip()
    table, index = target_table(p)
    TE.set_keys(p.config_path, table, {"archives": specs, "reason.archives": why}, index,
                covered=("compiler", "linker", "cflags", "archives"))
    print(record(declared="archives", value=",".join(Path(s).name for s in specs), level="declared",
                 where=f"target {p.target_name}", why=why))
    r = rerun(args, p.target_name)
    if r is None:
        return 0
    p, e = r
    units = {f.value["tu"]: f.value.get("lib", "") for f in p.store.facts(Kind.unit, rules=("S.crt.code",))}
    c = Counter(units.values())
    print("  placed: " + ("  ".join(f"{k}={v}" for k, v in sorted(c.items())) or "nothing") + "  (S.crt.code)")
    status_tail(p)
    return 0


def cmd_libs_candidates(args):
    """Place every run-time archive of the declared toolchain root on its own (build/libcand.py) and report per
    archive members, placed members and placed bytes (sorted by bytes) and the archive pairs that conflict."""
    from .build import libcand
    p, e = open_project(args)
    if not p.toolchain_decl.get("root"):
        return err("libs candidates", 'no toolchain root declared: dcp toolchain declare root=DIR --why "..." first', 2)
    refresh(p, e)
    s = libcand.candidates(p, force=args.force, log=(lambda m: print(m, file=sys.stderr)) if args.verbose else None)
    declared = {Path(a).name.upper() for a in (p.archives_decl_for()["archives"] or [])}
    print(record(target=p.target_name, root=s["root"], archives=len(s["archives"]), cached=s["cached"], ms=s["ms"]))
    for r in s["archives"]:
        print("  " + record(archive=r["archive"], members=r["members"], placed=r["placed"], bytes=r["bytes"],
                            declared="yes" if r["archive"].upper() in declared else None))
    for c in s["conflicts"]:
        print("  " + record(conflict=f"{c['a']},{c['b']}", overlaps=c["overlaps"], first=c["first"]))
    if not s["conflicts"]:
        print("  conflicts: none")
    print('resolve: dcp libs declare ARCHIVE... --why "..." (the evidence above)')
    return 0


def cmd_analyzer_declare(args):
    """Confirm or change the analyzer ([analyzer] plugin and its keys) with a reason."""
    from . import analyzers
    cmd = "analyzer declare"
    if no_why(cmd, args.why):
        return 2
    if args.plugin not in analyzers.ANALYZERS:
        return err(cmd, f"unknown analyzer {args.plugin!r} (known: {', '.join(analyzers.ANALYZERS)}); nothing written", 2)
    kv = parse_pairs(cmd, args.pairs, ("root", "java_home", "file", "timeout"))
    if kv is None:
        return 2
    vals: dict = {"plugin": args.plugin}
    for k, v in kv.items():
        vals[k] = int(v) if k == "timeout" else (Path(v).as_posix() if k in ("root", "java_home", "file") else v)
    vals["reason"] = args.why.strip()
    p = Project(Path(args.root) if args.root else None, getattr(args, "target", None))
    TE.set_keys(p.config_path, "analyzer", vals)
    p = Project(p.root, p.target_name)
    inst = p.analyzer.available()
    print(record(declared="analyzer", value=args.plugin, level="declared", where="[analyzer]", why=vals["reason"],
                 available=inst.ok, at=inst.where if inst.ok else None))
    if not inst.ok:
        print("  " + record(unavailable=inst.reason))
    r = rerun(args, p.target_name)
    if r is not None:
        status_tail(r[0])
    return 0


# ------------------------------------------------------------------------------------------------ the evidence view
def cmd_toolchain(args):
    """Per target (every target unless --target): what is declared (per key with its reason and level), the
    installs found on this machine with the versions they report, the Rich candidates with the plugin's build
    names, the PE linker version and time stamp, the CRT strings, the C.toolchain verdict, the archives and the
    members placed, the probe."""
    p0 = Project(Path(args.root) if args.root else None)
    names = [args.target] if getattr(args, "target", None) else [t.name for t in p0.targets]
    for i, name in enumerate(names):
        if i:
            print()
        p, e = open_project(args, name)
        refresh(p, e)
        tc, img = p.toolchain, p.image
        decl = p.toolchain_decl
        reasons = decl.get("reasons") or {}
        probed = [f for f in p.store.facts(Kind.toolchain) if f.run == "M.flags.proven"]
        proven = sorted(f.value["flag"] for f in probed if f.level.name == "proven")
        print(record(target=p.target_name, plugin=decl.get("plugin"), available=tc.available()))
        for k in ("compiler", "linker", "root", "cflags"):
            v = decl.get(k)
            v = " ".join(v) if isinstance(v, list) else v
            level = "open" if not v else ("declared" if reasons.get(k) else "declared-no-reason")
            if k == "cflags" and proven:
                level += ";proven:" + ",".join(proven)
            print("  " + record(key=k, value=v or None, level=level, source=decl["from"].get(k), why=reasons.get(k) or None))
        installs = tc.installs()
        print(f"  installs found={len(installs)}  (the {tc.key} plugin's places)")
        rich = OB.rich_fact(p)
        for inst in installs:
            print("    " + OB.install_text(inst, decl, rich))
        print("  " + record(pe_linker=f"{img.linker_version[0]}.{img.linker_version[1]:02d}", built=OB.built_at(img),
                            timestamp=f"{img.timestamp:#010x}"))
        crt = tc.crt_strings(img)
        print(f"  crt strings={len(crt)}" + "".join(f"\n    {a:#010x} {t!r}" for a, t in crt))
        if rich is None:
            print("  rich: no Rich header")
        else:
            v = rich.value
            for key in ("compilers", "linkers"):
                cands = v.get(key) or []
                print(f"  {key[:-1]} candidates={len(cands)}  ({rich.level}, {rich.by})")
                for c in cands:
                    bn = tc.build_name(c["family"], c["build"])
                    print("    " + candidate_entry(tc, c) + (f"  [{bn}]" if bn else ""))
            print(f"  rich entries={len(v.get('entries') or [])}")
            for en in v.get("entries") or []:
                print(f"    prodid={en['prodid']:#04x} {en['tool']:<16} family={en['family']:<9} build={en['build']:<5} "
                      f"count={en['count']:<4} archive_objects={en.get('archive_objects', 0)}")
        waits = p.waiting("toolchain")
        bad = [x for x in p.store.conflicts() if x.check == "C.toolchain"]
        print("  C.toolchain: " + (f"waiting: {', '.join(waits)}" if waits else ("ok" if not bad else f"{len(bad)} error(s)")))
        for x in bad:
            print("    " + x.message)
        ad = p.archives_decl_for()
        if ad["archives"] is None:
            print("  archives: open (dcp libs candidates, dcp libs declare)")
        else:
            print("  " + record(archives=",".join(Path(a).name for a in ad["archives"]) or "none", source=ad["from"],
                                why=ad["reason"] or None, waiting=",".join(p.waiting("libs")) or None))
        members = Counter(f.value.get("lib", "") for f in p.store.facts(Kind.unit, rules=("S.crt.code",)))
        print("  libraries placed: " + ("  ".join(f"{k}={v}" for k, v in members.items()) or "none"))
        if not probed:
            print("  probe: not run (dcp toolchain probe): flags are declared only")
        for f in probed:
            v = f.value
            print("  probe  " + record(flag=v["flag"], group=v["group"], anchors=v["anchors"], units=v["units"], level=f.level.name))


def register(sub, cmd):
    """The parsers: status, toolchain [probe | declare], libs candidates | declare, analyzer declare."""
    s = cmd(sub, "status", cmd_status, "the phase and the open obligations in order (every target unless --target)")
    s = cmd(sub, "toolchain", cmd_toolchain, "the toolchain evidence; `probe`: the flag probe; `declare`: a declaration")
    s.add_argument("-v", "--verbose", action="store_true")
    ts = s.add_subparsers(dest="sub")
    from .cli_match import cmd_probe
    s2 = cmd(ts, "probe", cmd_probe, "the flag grid over the byte-matched functions")
    s2.add_argument("-v", "--verbose", action="store_true")
    s2 = cmd(ts, "declare", cmd_toolchain_declare, "declare compiler= linker= root= cflags= (any subset) with --why")
    s2.add_argument("pairs", nargs="+", metavar="KEY=VALUE", help=f"keys: {', '.join(TOOLCHAIN_DECL_KEYS)}")
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
    s2.add_argument("plugin", metavar="PLUGIN", help="ghidra | rea | none")
    s2.add_argument("pairs", nargs="*", metavar="KEY=VALUE", help="root= java_home= file= timeout=")
    s2.add_argument("--why", help="the reason (required)")
