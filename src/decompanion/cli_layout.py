"""dcp: the layout-tooling commands' parsers (milestone 4): disasm, dump, refs, layout literals / starts, unit new /
join / rename, draft, rename, session start / wrap, skills install (cli_read.py, cli_draft.py, cli_session.py)."""
from __future__ import annotations


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
    s = cmd(sub, "draft", DR.cmd_draft, "write a function into its unit's file (the analyzer's pseudocode, else a @rough skeleton)")
    s.add_argument("addr", nargs="?", metavar="ADDR|NAME")
    s.add_argument("--next", action="store_true", help="the function `dcp layout next` shows")
    s.add_argument("--show", action="store_true", help="print the analyzer's draft of ADDR, write nothing")
    s.add_argument("--unit", help="the unit (default: the unit whose extent holds the address)")
    s = cmd(sub, "rename", DR.cmd_rename, "rename identifiers over src/ and include/ (names.log); several pairs in one call "
                                          "share one rebuild")
    s.add_argument("pairs", nargs="*", metavar="OLD NEW",
                   help="pairs of the identifier (or [TARGET:]0xADDR for the ledger's name of the address) and its new name")
    s.add_argument("--from", dest="from_file", metavar="FILE", help="more pairs, one `OLD NEW [why]` per line")
    s.add_argument("--why", help="the evidence (required unless every --from line carries its own)")
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
