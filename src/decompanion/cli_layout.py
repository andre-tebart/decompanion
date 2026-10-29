"""dcp: the layout-tooling commands (milestone 4): ghidra export / status, disasm, dump, refs, layout literals /
starts, unit new / join / rename, draft, rename, session start / wrap, skills install. Same output contract as
cli.py: one record per line, key=value tokens, addresses 0x%08x, counts before lists.
"""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

from .cli import fmt_addr, open_project, parse_addr, parse_range, record, refresh
from .config import ConfigError, Project
from .ledger.fact import Kind, Level


def err(cmd: str, msg: str) -> int:
    print(f"dcp {cmd}: {msg}", file=sys.stderr)
    return 1


# ------------------------------------------------------------------------------------------------ ghidra
def cmd_ghidra_export(args):
    """Ghidra headless over the target's binary (build/ghidra.py), every function decompiled, then imported
    (ledger/ghidra.py). Nothing runs when the same image was exported with the same script (unless --force)."""
    from .build import ghidra as GX
    from .ledger import ghidra as G
    p, e = open_project(args)
    if GX.up_to_date(p) and not args.force:
        refresh(p, e)
        print(record(target=p.target_name, export="up-to-date", drafts=len(G.entries(p.store))) + "  (--force exports again)")
        return 0
    try:
        setup = GX.locate(p)
    except GX.GhidraMissing as ex:
        return err("ghidra export", str(ex))
    print(record(target=p.target_name, ghidra=setup.root.as_posix(), java_home=setup.java_home.as_posix() if setup.java_home else None,
                 project=GX.project_dir(p).relative_to(p.root).as_posix()), flush=True)
    run = GX.run_headless(p, setup)
    if not run.ok:
        return err("ghidra export", f"{run.message} (log: {run.log.relative_to(p.root).as_posix()})")
    digest, entries, failed = G.parse(run.json)
    if digest and digest != p.image.sha256:
        return err("ghidra export", f"Ghidra analysed sha256 {digest[:16]}, target {p.target_name} is {p.image.sha256[:16]}")
    n = G.store_entries(p.store, p.image.sha256, entries)
    p.store.set_meta(GX.META, GX.export_key(p))
    p.forget_input("ghidra")
    refresh(p, e)
    print(record(target=p.target_name, exported=n, failed=len(failed), ms=run.ms, json=run.json.relative_to(p.root).as_posix()))
    for f in failed[:20]:
        print("  failed  " + f)
    return 0


def ghidra_overview(p):
    """(drafts, ghidra-only starts [(addr, entry, where)], ours-only starts [(addr, how)], L9 conflicts) of the
    game code and the whole image."""
    from .ledger import ghidra as G
    from .ledger import layoutview as LV
    v = LV.View.load(p, p.store)
    ents = {e.start: e for e in G.entries(p.store)}
    glo, ghi, _ = v.game
    ours = {}
    for a, fs in v.starts.items():
        hows = [f.value["how"] for f in fs if f.value.get("how") != "ghidra"]
        if hows:
            ours[a] = hows[0]
    inner = set()
    for lo, hi, f in v.funcs:
        ours.setdefault(lo, "symbol")
        inner.update(f.value.get("inner", ()))
    ours = {a: h for a, h in ours.items() if a not in inner}
    at = LV.L.container(v.funcs)
    g_only = []
    for a, e in sorted(ents.items()):
        if a in ours or a in inner:
            continue
        fn = at(a)
        if fn is not None:
            where = f"inside {fn[0]:#x}"
        else:
            row = p.store.bytemap_at(a)
            where = row[2] if row else "-"
        g_only.append((a, e, where))
    o_only = [(a, h) for a, h in sorted(ours.items()) if glo <= a < ghi and a not in ents]
    l9 = [c for c in p.store.conflicts() if c.check == "L9"]
    return v, ents, g_only, o_only, l9


def cmd_ghidra_status(args):
    """How many functions have Ghidra drafts, the starts Ghidra has that we do not (and where they lie), the
    game-code starts we have that Ghidra does not, and L9 (a Ghidra function spanning one of our starts)."""
    from .build import ghidra as GX
    p, e = open_project(args)
    refresh(p, e)
    v, ents, g_only, o_only, l9 = ghidra_overview(p)
    glo, ghi, _ = v.game
    game_funcs = [lo for lo, _, _ in v.funcs if glo <= lo < ghi]
    with_draft = sum(1 for a in game_funcs if a in ents)
    export = "up-to-date" if GX.up_to_date(p) else ("none" if p.store.meta(GX.META) is None else "stale")
    print(record(target=p.target_name, drafts=len(ents), export=export, game_functions=len(game_funcs), with_draft=with_draft,
                 ghidra_only=len(g_only), ours_only=len(o_only), l9=len(l9)))
    where = Counter(w.split(" ")[0] for _, _, w in g_only)
    if where:
        print("  ghidra_only by place: " + "  ".join(f"{k}={n}" for k, n in sorted(where.items())))
    n = None if args.verbose else 20
    for a, en, w in g_only[:n]:
        print("  " + record(ghidra_only=a, name=en.name or None, size=en.size, where=w, game=glo <= a < ghi))
    for a, how in o_only[:n]:
        print("  " + record(ours_only=a, how=how))
    for c in l9[:n]:
        print("  " + c.line())
    if not args.verbose and max(len(g_only), len(o_only), len(l9)) > 20:
        print("  (-v lists all)")
    return 0


# ------------------------------------------------------------------------------------------------ parser
def register(sub, cmd):
    """Add the layout-tooling commands to the dcp parser (cli.main): the reading commands of cli_read.py and the
    drafting / session commands of this module. `layout literals|starts` go into the existing `layout` parser."""
    from . import cli_read as R
    s = cmd(sub, "disasm", R.cmd_disasm, "the original's instructions with the ledger's names (--ours NAME: our compiled function)")
    s.add_argument("addr", nargs="?", metavar="ADDR|NAME")
    s.add_argument("len", nargs="?", metavar="LEN|..END")
    s.add_argument("--ours", metavar="NAME", help="disassemble our compiled function from its unit's object")
    s = cmd(sub, "dump", R.cmd_dump, "the original's bytes: hex and latin-1, strings, dwords, floats, with the symbols of each row")
    s.add_argument("addr", metavar="ADDR|NAME")
    s.add_argument("len", nargs="?", metavar="LEN", help="bytes (default 0x40)")
    s.add_argument("--str", action="store_true", help="every NUL-terminated string starting in the range")
    s.add_argument("--dword", action="store_true", help="every aligned dword: unsigned, signed, float, name")
    s.add_argument("--float", action="store_true", help="every aligned float and double")
    s = cmd(sub, "refs", R.cmd_refs, "definition, facts, references to and from, and source lines of a name or address")
    s.add_argument("what", metavar="NAME|ADDR")
    from . import cli_draft as DR
    s = cmd(sub, "draft", DR.cmd_draft, "write the first fragment of a function (Ghidra's pseudocode, else a @rough skeleton)")
    s.add_argument("addr", nargs="?", metavar="ADDR|NAME")
    s.add_argument("--next", action="store_true", help="the function `dcp layout next` shows")
    s.add_argument("--unit", help="the unit (default: the unit whose extent holds the address)")
    s = cmd(sub, "rename", DR.cmd_rename, "rename one identifier over src/ and include/ (names.log)")
    s.add_argument("old")
    s.add_argument("new")
    s.add_argument("--why", required=True)
    from . import cli_session as SE
    ses = sub.add_parser("session", help="the session protocol").add_subparsers(dest="sub", required=True)
    cmd(ses, "start", SE.cmd_session_start, "the session gate (clean tree, built, checked, linked) and the overview")
    cmd(ses, "wrap", SE.cmd_session_wrap, "build, link, check, promote, and the computed session report")
    sk = sub.add_parser("skills", help="the agent skills").add_subparsers(dest="sub", required=True)
    s = cmd(sk, "install", SE.cmd_skills_install, "install the decompanion skills into .claude/skills/")
    s.add_argument("--force", action="store_true", help="overwrite every skill file")


def register_unit(un, cmd):
    """The `dcp unit new|join|rename` subcommands (cli.main's `unit` parser holds `cat`)."""
    from . import cli_draft as DR
    s = cmd(un, "new", DR.cmd_unit_new, "declare a unit (layout unit propose) and write its skeleton files")
    s.add_argument("name")
    s.add_argument("--range", required=True, help="0xSTART..0xEND (END exclusive) or 0xSTART")
    s.add_argument("--by", choices=("leaked", "tag", "guess"), required=True, help="how the unit got its name")
    s.add_argument("--why", required=True)
    s = cmd(un, "join", DR.cmd_unit_join, "join unit B (directly after A) into unit A")
    s.add_argument("a")
    s.add_argument("b")
    s.add_argument("--why", required=True)
    s = cmd(un, "rename", DR.cmd_unit_rename, "rename a unit (directory, header, includes, boundaries, placeholders)")
    s.add_argument("old")
    s.add_argument("new")
    s.add_argument("--why", required=True)
    s.add_argument("--by", choices=("leaked", "tag", "guess"), help="the new name's origin (the start boundary's by=)")
