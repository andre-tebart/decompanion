"""dcp: the layout-tooling commands (milestone 4): the analyzer lines of the report, disasm, dump, refs, layout
literals / starts, unit new / join / rename, draft, rename, session start / wrap, skills install. Same output
contract as cli.py: one record per line, key=value tokens, addresses 0x%08x, counts before lists.
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


# ------------------------------------------------------------------------------------------------ analyzer
def analyzer_overview(p):
    """(view, drafts {start: entry}, analyzer-only starts [(addr, entry, where)], ours-only game-code starts
    [(addr, how)], L9 conflicts)."""
    from .ledger import drafts as G
    from .ledger import layoutview as LV
    v = LV.View.load(p, p.store)
    ents = {e.start: e for e in G.entries(p.store)}
    glo, ghi, _ = v.game
    ours = {}
    for a, fs in v.starts.items():
        hows = [f.value["how"] for f in fs if f.run != "L.analyzer"]
        if hows:
            ours[a] = hows[0]
    inner = set()
    for lo, hi, f in v.funcs:
        ours.setdefault(lo, "symbol")
        inner.update(f.value.get("inner", ()))
    for f in v.syms:
        if f.value.get("skind") == "thunk":
            ours.setdefault(f.lo, "thunk")
    ours = {a: h for a, h in ours.items() if a not in inner}
    at = LV.L.container(v.funcs)
    a_only = []
    for a, en in sorted(ents.items()):
        if a in ours or a in inner:
            continue
        fn = at(a)
        if fn is not None:
            where = f"inside {fn[0]:#x}"
        else:
            row = p.store.bytemap_at(a)
            where = row[2] if row else "-"
        a_only.append((a, en, where))
    o_only = [(a, h) for a, h in sorted(ours.items()) if glo <= a < ghi and a not in ents]
    l9 = [c for c in p.store.conflicts() if c.check == "L9"]
    return v, ents, a_only, o_only, l9


def print_analyzer(p, verbose=False):
    """The analyzer lines of `dcp report`: how many functions have drafts, the export's state, the starts only the
    analyzer has (and where they lie), the game-code starts only we have, L9 (an analyzer's function spanning one
    of our starts). Returns the layout view it loaded (the status tail reuses it)."""
    from .build import analyzer as AX
    v, ents, a_only, o_only, l9 = analyzer_overview(p)
    glo, ghi, _ = v.game
    game_funcs = [lo for lo, _, _ in v.funcs if glo <= lo < ghi]
    print(record(analyzer=p.analyzer.key, drafts=len(ents), export=AX.state(p), game_functions=len(game_funcs),
                 with_draft=sum(1 for a in game_funcs if a in ents), analyzer_only=len(a_only), ours_only=len(o_only), l9=len(l9)))
    where = Counter(w.split(" ")[0] for _, _, w in a_only)
    if where:
        print("  analyzer_only by place: " + "  ".join(f"{k}={n}" for k, n in sorted(where.items())))
    if not ents:                       # no drafts at all: every start is ours only, a list says nothing
        o_only = []
    n = None if verbose else 20
    for a, en, w in a_only[:n]:
        print("  " + record(analyzer_only=a, name=en.name or None, size=en.size, where=w, game=glo <= a < ghi))
    for a, how in o_only[:n]:
        print("  " + record(ours_only=a, how=how))
    for c in l9[:n]:
        print("  " + c.line())
    if not verbose and max(len(a_only), len(o_only), len(l9)) > 20:
        print("  (-v lists all)")
    return v


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
    s = cmd(sub, "draft", DR.cmd_draft, "write the first fragment of a function (the analyzer's pseudocode, else a @rough skeleton)")
    s.add_argument("addr", nargs="?", metavar="ADDR|NAME")
    s.add_argument("--next", action="store_true", help="the function `dcp layout next` shows")
    s.add_argument("--show", action="store_true", help="print the analyzer's draft of ADDR, write nothing")
    s.add_argument("--unit", help="the unit (default: the unit whose extent holds the address)")
    s = cmd(sub, "rename", DR.cmd_rename, "rename one identifier over src/ and include/ (names.log)")
    s.add_argument("old", metavar="OLD", help="the identifier, or [TARGET:]0xADDR for the ledger's name of the address")
    s.add_argument("new")
    s.add_argument("--why", required=True)
    from . import cli_session as SE
    ses = sub.add_parser("session", help="the session protocol").add_subparsers(dest="sub", required=True)
    cmd(ses, "start", SE.cmd_session_start, "the session gate (clean tree, built, checked, linked) and the overview")
    cmd(ses, "wrap", SE.cmd_session_wrap, "build, link, check, promote, and the computed session report")
    s = cmd(ses, "status", SE.cmd_session_status, "the session clock: base, start time, minutes elapsed and left, over")
    s.add_argument("--minutes", type=int, default=30, help="the session length (default 30)")
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
