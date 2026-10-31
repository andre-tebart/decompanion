"""dcp: the command line. Every command refreshes the rule engine first (nothing changed: nothing runs), then
answers from the store. Output: one record per line, key=value tokens, addresses 0x%08x, intervals lo..hi
(hi exclusive), sorted by address, counts before lists; --json gives the same records as JSON lines.
Every command takes --target NAME (default: the first [[target]] of decompanion.toml). The answers are the core's
(native/dcp_core/src/clicmd.rs and the modules it names); this module parses the arguments, refreshes and prints.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from . import fsmemo, native, timing
from .config import ConfigError, Project
from .rules.engine import Engine, RuleError

_core = native.core()


def tok(v):
    """A value as a key=value token."""
    if v is None:
        return "-"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, int):
        return f"{v:#010x}" if v >= 0x100000 else str(v)      # an address, else a count or size (decimal)
    s = str(v)
    return repr(s) if (" " in s or not s) else s


def record(**kv) -> str:
    return "  ".join(f"{k}={tok(v)}" for k, v in kv.items())


def report(cmd: str, lines, error=None, code: int = 0) -> int:
    """Print a command's lines; its error to stderr as `dcp CMD: error`; the exit code."""
    for line in lines:
        print(line)
    if error:
        print(f"dcp {cmd}: {error}", file=sys.stderr)
    return code


def open_project(args, target: str | None = None) -> tuple[Project, Engine]:
    with timing.phase("open"):
        p = Project(Path(args.root) if getattr(args, "root", None) else None, target or getattr(args, "target", None))
        e = Engine(p, p.store)
    return p, e


def refresh(p: Project, e: Engine, verbose=False, force=False, only=None):
    t0 = time.perf_counter()
    fsmemo.new_epoch()
    if force:
        fsmemo.forget_all()                 # a forced refresh trusts no persisted hash
    for name in ("src", "decl"):          # a command may have written either since its last refresh (rename, draft,
        p.forget_input(name)              # data fix, escalate, decl add); the file memo keeps the rehash cheap
    with timing.phase("refresh"):
        res = e.run(only, force=force, log=(lambda s: print(s, file=sys.stderr)) if verbose else None)
    ran = [r for r in res if r.ran]
    if verbose or ran:
        print(f"rules: {len(ran)} ran of {len(res)}, {int((time.perf_counter() - t0) * 1000)} ms (target {p.target_name})", file=sys.stderr)
    return res


def refreshed(args, name=None) -> Project:
    p, e = open_project(args, name)
    refresh(p, e)
    return p


# ------------------------------------------------------------------------------------------------- setup and queries
def target_names(args) -> list[str | None]:
    """The targets a command runs on: --all-targets: every target in config order; else the selected one."""
    if getattr(args, "all_targets", False):
        if getattr(args, "target", None):
            raise ConfigError("--all-targets and --target exclude each other")
        p = Project(Path(args.root) if getattr(args, "root", None) else None)
        return [t.name for t in p.targets]
    return [getattr(args, "target", None)]


def every_target(args) -> list[str]:
    """--target NAME, else every target in config order."""
    if getattr(args, "target", None):
        return [args.target]
    return [t.name for t in Project(Path(args.root) if getattr(args, "root", None) else None).targets]


def cmd_setup(args):
    """Run every rule (a rule whose input is not declared yet waits: rules/engine.py); then, unless --no-analyzer,
    the configured analyzer's export when its key is stale (or --analyzer-force) and the rules again (L.analyzer
    and what reads its facts); then the report and the status tail (the open obligations, the core's decide.rs). A
    missing analyzer is a warning line, not a failure; a failed export exits 1 after the report."""
    failed = False
    for i, name in enumerate(target_names(args)):
        if i:
            print()
        p, e = open_project(args, name)
        refresh(p, e, verbose=args.verbose, force=args.force)
        if not args.no_analyzer:
            out, errs, ok, exported = _core.analyzer_step(p.core, bool(args.analyzer_force))
            report("setup", out)
            for line in errs:
                print(line, file=sys.stderr)
            if exported:
                refresh(p, e, verbose=args.verbose)
            failed = failed or not ok
        report("setup", _core.report_command(p.core, bool(args.verbose)))
        from .cli_decide import status_tail
        status_tail(p)
    return 1 if failed else 0


def cmd_report(args):
    for i, name in enumerate(target_names(args)):
        if i:
            print()
        report("report", _core.report_command(refreshed(args, name).core, bool(getattr(args, "verbose", False))))


def cmd_why(args):
    return report("why", *_core.why_command(refreshed(args).core, args.addr, bool(args.refs)))


def cmd_facts(args):
    report("facts", _core.facts_command(refreshed(args).core, args.range, args.kind, bool(args.json)))


def cmd_conflicts(args):
    report("conflicts", _core.conflicts_command(refreshed(args).core, args.severity, bool(args.json)))


def cmd_check(args):
    """The gate, per target (every target unless --target): the stale units compile (dcp build), every rule
    ran (the loaders included), no bug / error conflicts (M.compile, M.gen, M1, M8.. among them), no open
    toolchain or libs obligation (decide.rs), and, once the target has a source, the full link resolves every
    external. --against REV: no function grade fell against ledger/grades.tsv at that git revision. Each target ends
    with its verdict line (`gate=ok` or `gate=FAIL` and the failing parts), the same verdict `dcp session wrap`
    prints. Exit 1 otherwise."""
    p0 = Project(Path(args.root) if args.root else None, getattr(args, "target", None))
    failed = False
    against = _core.grades_baseline_at(str(p0.root), args.against) if getattr(args, "against", None) else None
    for name in every_target(args):
        p, e, rep = build_target(args, name, quiet=True)
        built = bool(p.store.facts("build"))
        if built and _core.lint_available(p.core):
            _core.lint_command(p.core)
            refresh(p, e)
        lines, reasons = _core.check_conflicts(p.core, bool(args.strict))
        report("check", lines)
        if built and p.core.toolchain_available():
            lines, ok, why, _, _ = _core.link_command(p.core)
            report("check", lines)
            if not ok:
                reasons.append(why)
        elif built:
            print(record(link=name, skipped="the toolchain is not available"))
        from .cli_decide import gate_failures
        open_ = gate_failures(p)            # after the link: libs.archives reads the link's `library` class
        report("check", open_)
        if open_:
            reasons.insert(0, f"obligations={len(open_)}")
        if against is not None:
            falls = _core.grades_regressions(p.target_name, str(p.store_path()), against)
            print(record(against=args.against, target=name, falls=len(falls)))
            report("check", ["  fell: " + line for line in falls])
            if falls:
                reasons.append(f"falls={len(falls)}")
        print(record(gate="FAIL" if reasons else "ok", target=name, **({"why": ";".join(reasons)} if reasons else {})))
        failed = failed or bool(reasons)
    return 1 if failed else 0


def cmd_rules(args):
    report("rules", _core.rules_command(refreshed(args).core, bool(args.verbose)))


def cmd_map(args):
    report("map", _core.map_command(refreshed(args).core, args.range))


# ------------------------------------------------------------------------------------------------- match phase
def build_target(args, name, quiet=False):
    """Compile the stale units of one target and refresh its rules: (project, engine, compile report)."""
    from .build import compile as B
    p, e = open_project(args, name)
    rep = B.ensure(p, log=None if quiet else print, force=getattr(args, "force", False))
    lint_built(p)
    refresh(p, e)
    return p, e, rep


def lint_built(p):
    """A project that lints (a `dcp lint` ran before, libclang is there): lint the units that changed since, before the
    refresh, so the one refresh of a build sees the objects and the lint together (grade / next find it current)."""
    if _core.lint_plan(p.core)[0] == "lint":
        with timing.phase("lint"):
            _core.lint_command(p.core)


def cmd_build(args):
    """Compile every stale unit (one compiler process per unit, in a pool), then refresh the rules. Prints the
    compiled units, the summary, the failed units with their errors and the grade counts; --units lists every
    unit's build row."""
    failed = False
    for i, name in enumerate(target_names(args)):
        if i:
            print()
        p, e, rep = build_target(args, name)
        lines, bad = _core.build_summary(p.core, (rep.units, len(rep.compiled), len(rep.removed), rep.ms), bool(getattr(args, "units", False)))
        report("build", lines)
        failed = failed or bad
        cleared = _core.grades_auto_clear(p.core)
        report("build", ["  " + line for line in cleared])
        if cleared:
            p, e, rep = build_target(args, name, quiet=True)
    return 1 if failed else 0


def cmd_fn(args):
    """Print one function of the sources: a record with its file and lines (its address comment to the end of
    its definition), then that text. KEY is a function name or an address of the target."""
    p, e = open_project(args)
    return report("fn", *_core.fn_command(p.core, args.key))


def cmd_init(args):
    """Create the project: the [[target]] computed from the binary, nothing declared (the core's init.rs)."""
    from .cli_session import DCP_ROOT
    lines, error = _core.init_project(args.dir, args.target_path, args.name, args.target_name, str(DCP_ROOT))
    if error:
        raise SystemExit(error)
    report("init", lines)


# ------------------------------------------------------------------------------------------------- targets
def cmd_target_list(args):
    report("target list", _core.target_list(Project(Path(args.root) if args.root else None).core, bool(args.json)))


def cmd_target_add(args):
    p = Project(Path(args.root) if args.root else None)
    lines, error = _core.target_add(str(p.root), args.name, args.path)
    if error:
        raise SystemExit(error)
    report("target add", lines)


# ------------------------------------------------------------------------------------------------- declarations
def cmd_decl_add(args):
    p, e = open_project(args)
    lines, error, code, made = _core.decl_add(p.core, args.line)
    report("decl add", lines, error)
    if made is None:
        return code
    target, by = made
    lines, code = _core.decl_conflicts(refreshed(args, target).core, by)
    return report("decl add", lines, None, code)


# ------------------------------------------------------------------------------------------------- layout
def cmd_layout_next(args):
    report("layout next", _core.layout_next(refreshed(args).core, args.n, args.start, bool(args.json)))


def cmd_layout_units(args):
    report("layout units", _core.layout_units(refreshed(args).core, bool(args.verbose), bool(args.json)))


def cmd_layout_propose(args):
    p = refreshed(args)
    lines, error, code, written = _core.propose_command(p.core, args.range, args.name, args.why, args.by, bool(args.dry_run))
    report("layout unit propose", lines, error)
    if not written:
        return code
    return report("layout unit propose", *_core.propose_verdict(refreshed(args).core, args.name))


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
_parser = None


def main(argv=None):
    global _parser
    if _parser is None:
        _parser = parser()
    args = _parser.parse_args(argv)
    try:
        return run_command(args)
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


def parser() -> argparse.ArgumentParser:
    """The command line (built once per process: main)."""
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
    s = cmd(sub, "why", cmd_why, "everything known about an address (or a function / data name)")
    s.add_argument("addr", nargs="+", metavar="ADDR|NAME")
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
    s = sub.add_parser("serve", help="run the project's daemon: every dcp command of the project runs in it (daemon.py)")
    s.add_argument("--stop", action="store_true", help="stop the running daemon")
    s.add_argument("--status", action="store_true", help="print the running daemon's state")
    s.add_argument("--foreground", action="store_true", help="run the supervisor in this process instead of detached")
    s.set_defaults(fn=cmd_serve)
    s = cmd(sub, "rules", cmd_rules, "the rule graph and run status")
    s.add_argument("-v", "--verbose", action="store_true", help="print each rule's criterion")
    from . import cli_decide as CD
    CD.register(sub, cmd)
    from . import cli_data as CDA
    CDA.register(sub, cmd)
    from . import cli_headers as CH
    CH.register(sub, cmd)

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
    s = cmd(sub, "promote", CM.cmd_promote, "raise the grade baseline ledger/grades.tsv to the current grades (main checkout "
                                            "only; a fall no dcp accept covers is refused)")
    s.add_argument("--accept-falls", action="store_true", help="write the falls too (each noted in the accepted column)")
    s = cmd(sub, "accept", CM.cmd_accept, "lower one function's baseline entry to the grade it fell to, with the reason "
                                          "(main checkout only)")
    s.add_argument("name", metavar="ADDR|NAME")
    s.add_argument("--to", choices=("shape", "draft"), help="the code grade the entry falls to")
    s.add_argument("--readability", choices=("draft",), help="the readability falls to draft too")
    s.add_argument("--why", required=True, help="the reason (kept in the accepted column)")
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
    s = cmd(lay, "fptrs", CR.cmd_layout_fptrs, "every function pointer in data (tables of functions) with its unit")
    s.add_argument("what", nargs="?", metavar="UNIT|LO..HI", help="a unit or code range: the functions pointed to; "
                   "a data range: the sites; default: all")
    s = cmd(lay, "starts", CR.cmd_layout_starts, "every function start in a range with its evidence")
    s.add_argument("range", nargs="*", metavar="LO..HI", help="LO..HI or LO HI; default: the game code")
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
    s.add_argument("--units", action="store_true", help="list every unit's build row, not only the failed ones")
    un = sub.add_parser("unit", help="units").add_subparsers(dest="sub", required=True)
    s = cmd(sub, "fn", cmd_fn, "print one function of the sources (its address comment to the end of its definition)")
    s.add_argument("key", help="a function name or an address")
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

    return ap


def cmd_serve(args):
    """`dcp serve` reached cli.main (the dcp script handles it in client.py first): the same."""
    from . import client
    return client.serve((["--root", args.root] if args.root else []) + (["--stop"] if args.stop else [])
                        + (["--status"] if args.status else []))


def run_command(args):
    """args.fn(args) with the timing line (DCP_TIMING) and the profile (DCP_PROFILE) around it."""
    import os
    from . import fsmemo
    timing.reset()
    fsmemo.new_epoch()
    try:
        if os.environ.get("DCP_PROFILE"):
            import cProfile
            import pstats
            prof = cProfile.Profile()
            try:
                return prof.runcall(args.fn, args) or 0
            finally:
                name = "-".join(x for x in (args.cmd, getattr(args, "sub", None)) if x)
                out = Path(getattr(args, "root", None) or ".").resolve() / "build" / "profile"
                out.mkdir(parents=True, exist_ok=True)
                path = out / f"{name}-{time.strftime('%Y%m%d-%H%M%S')}.prof"
                prof.dump_stats(path)
                print(f"profile: {path}", file=sys.stderr)
                pstats.Stats(prof, stream=sys.stderr).sort_stats("cumulative").print_stats(30)
        return args.fn(args) or 0
    finally:
        fsmemo.flush()
        timing.report()


if __name__ == "__main__":
    sys.exit(main())
