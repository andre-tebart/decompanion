"""The layout tooling of milestone 4 on the synthetic dll: the reading commands (disasm, dump, refs, layout
literals / starts), drafting (unit new, draft, rename, unit rename, unit join, names.log), L9, L10, declared
dead bytes owned by their unit, the Ghidra status, the session gate and report, the skills."""
import json
import subprocess
from pathlib import Path

import pytest

from conftest import dcp, make_project

from decompanion.config import Project
from decompanion.ledger import query
from decompanion.ledger.fact import Kind

VC6 = Path("C:/Tools/MSVC600-SP5PP")
needs_vc6 = pytest.mark.skipif(not (VC6 / "VC98" / "Bin" / "CL.EXE").exists(), reason="VC6 not installed")


def write(root: Path, rel: str, text: str):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, newline="\n")


def errors(root) -> list:
    return [c for c in Project(root).store.conflicts() if c.severity.value in ("bug", "error")]


def ghidra(root: Path, tmp: Path, items: list) -> int:
    """Import a Ghidra JSON (the export's shape) with these items: (address, name, pseudocode, body ranges)."""
    sha = Project(root).image.sha256
    js = {"subject": {"digest": {"sha256": sha}}, "normalized_result": {"items": [
        {"address": f"{a:#010x}", "status": "ok", "procedure": {"address": f"{a:#010x}", "name": n}, "pseudocode": text,
         "body": {"start": f"{rs[0][0]:#010x}", "end": f"{rs[-1][1]:#010x}", "size": sum(b - x for x, b in rs),
                  "ranges": [[f"{x:#010x}", f"{b:#010x}"] for x, b in rs]}}
        for a, n, text, rs in items]}}
    f = tmp / "export.json"
    f.write_text(json.dumps(js), newline="\n")
    code, out = dcp(root, "ghidra", "import", str(f))
    assert code == 0, out
    return code


F1 = "\nvoid FUN_10001000(void)\n\n{\n  FUN_10001020();\n  FUN_10001030();\n  DAT_10002000 = 0;\n  return;\n}\n"
F2 = "\nundefined4\nFUN_10001020(void)\n\n{\n  return DAT_10002000;\n}\n"


# ------------------------------------------------------------------------------------------------ reading
def test_disasm_dump_refs(tiny):
    assert dcp(tiny, "decl", "add", "0x10001020 name GetCounter -- reads the counter (test)")[0] == 0
    code, out = dcp(tiny, "disasm", "0x10001000")
    assert code == 0, out
    assert "function=0x10001000..0x1000100f" in out and "-- 0x10001000" in out
    assert "call 0x10001020 <GetCounter>" in out
    code, out = dcp(tiny, "disasm", "GetCounter")
    assert "instructions=2" in out and "mov eax, dword ptr [0x10002000]" in out
    code, out = dcp(tiny, "dump", "0x10002000", "0x48", "--str", "--dword")
    assert code == 0 and "section=.data" in out
    assert "text=hello" in out and "text=world" in out and "text=c:\\src\\net\\net.c" in out
    assert "at=0x10002040  u32=0x10001050" in out
    assert "string@0x10002030" in out                       # the symbols starting in a row
    code, out = dcp(tiny, "refs", "GetCounter")
    assert code == 0, out
    assert "address=0x10001020" in out and "named=GetCounter  origin=decl" in out
    assert "ref_to=call  site=0x10001003" in out and "fn=0x10001000" in out
    assert "decl/text.dcl:" in out                           # the declaration line that names it


def test_layout_starts_and_literals(tiny):
    code, out = dcp(tiny, "layout", "starts")
    assert code == 0 and "starts=4" in out
    line = next(l for l in out.splitlines() if l.startswith("start=0x10001050"))
    assert "how=fptr" in line and "callers=1" in line and "drafted=no" in line
    assert "fill=nop" in next(l for l in out.splitlines() if l.startswith("start=0x10001020"))
    code, out = dcp(tiny, "layout", "literals", "0x10001000..0x10001060")
    assert code == 0, out
    lit = next(l for l in out.splitlines() if l.startswith("  lit=0x10002030"))
    assert "kind=string" in lit and "first=0x10001030" in lit and "text=hello" in lit
    assert "fn=0x10001030" in out and "fn=0x10001050" in out


# ------------------------------------------------------------------------------------------------ drafting
def test_unit_new_draft_rename(tiny, tmp_path):
    assert dcp(tiny, "setup")[0] == 0
    ghidra(tiny, tmp_path, [(0x10001000, "FUN_10001000", F1, [(0x10001000, 0x1000100f)]),
                            (0x10001020, "FUN_10001020", F2, [(0x10001020, 0x10001026)])])
    code, out = dcp(tiny, "unit", "new", "net", "--range", "0x10001000..0x10001060", "--by", "guess", "--why", "the whole test code")
    assert code == 0, out
    for f in ("src/net/head.c", "include/net.h", "src/net/open.md"):
        assert (tiny / f).exists(), f
    assert (tiny / "src/net/open.md").read_text().startswith("# net\n\n## Open work\n")
    assert "NET_H" in (tiny / "include/net.h").read_text()
    n_err = len(errors(tiny))
    # f1 from Ghidra: the callees spelled as placeholders of their unit, the data label kept, declarations added
    code, out = dcp(tiny, "draft", "--next")
    assert code == 0 and "drafted=0x10001000" in out and "body=ghidra" in out, out
    f1 = (tiny / "src/net/f_10001000.c").read_text()
    assert f1.startswith("/* 0x10001000, net_10001000 */\nvoid net_10001000(void)\n{")
    assert "net_10001020();" in f1 and "net_10001030();" in f1 and "DAT_10002000 = 0;" in f1
    head = (tiny / "src/net/head.c").read_text()
    assert head.index('#include "dcp_ghidra.h"') < head.index('#include "net.h"')
    assert "undefined4 net_10001020();" in head and "int net_10001030();" in head and "extern undefined4 DAT_10002000;" in head
    assert "void net_10001000(void);" in (tiny / "include/net.h").read_text()
    assert (tiny / "include/dcp_ghidra.h").exists()
    # f2: its K&R line leaves head.c, its prototype (one line) goes into the header
    code, out = dcp(tiny, "draft", "--next")
    assert "drafted=0x10001020" in out, out
    assert (tiny / "src/net/f_10001020.c").read_text().startswith("/* 0x10001020, net_10001020 */\nundefined4 net_10001020(void)\n")
    assert "net_10001020" not in (tiny / "src/net/head.c").read_text()
    assert "undefined4 net_10001020(void);" in (tiny / "include/net.h").read_text()
    # f3 without a Ghidra draft: the @rough skeleton with the disassembly
    code, out = dcp(tiny, "draft", "--next")
    assert "drafted=0x10001030" in out and "body=skeleton" in out, out
    f3 = (tiny / "src/net/f_10001030.c").read_text()
    assert f3.startswith("/* 0x10001030, net_10001030 @rough */\nvoid __cdecl net_10001030(void)") and "push 0x10002010" in f3
    assert "int net_10001030();" not in (tiny / "src/net/head.c").read_text()
    code, out = dcp(tiny, "draft", "0x10001030")
    assert code == 1                                          # drafted already
    assert len(errors(tiny)) == n_err, [c.line() for c in errors(tiny)]
    assert not [c for c in Project(tiny).store.conflicts() if c.check in ("L5", "L.src", "L1", "L7")]
    # rename: whole words, names.log, collision refused, the check count unchanged
    code, out = dcp(tiny, "rename", "net_10001020", "GetCounter", "--why", "returns the counter")
    assert code == 0, out
    assert "GetCounter();" in (tiny / "src/net/f_10001000.c").read_text()
    log = (tiny / "names.log").read_text().splitlines()
    assert log[-1].split(" ", 1)[1].startswith("0x10001020 func net_10001020 -> GetCounter by:main why:returns the counter")
    code, out = dcp(tiny, "rename", "net_10001030", "GetCounter", "--why", "x")
    assert code == 1
    assert len(errors(tiny)) == n_err
    # unit rename: directory, header, guard, includes, boundary lines, placeholders
    code, out = dcp(tiny, "unit", "rename", "net", "netcode", "--by", "tag", "--why", "the tag string 'net:'")
    assert code == 0, out
    assert not (tiny / "src/net").exists() and (tiny / "src/netcode/f_10001000.c").exists() and (tiny / "src/netcode/open.md").exists()
    hdr = (tiny / "include/netcode.h").read_text()
    assert "NETCODE_H" in hdr and "NET_H" not in hdr and not (tiny / "include/net.h").exists()
    assert '#include "netcode.h"' in (tiny / "src/netcode/head.c").read_text()
    assert "netcode_10001000" in (tiny / "src/netcode/f_10001000.c").read_text()
    text = (tiny / "decl/text.dcl").read_text()
    assert "boundary start by=tag tu=netcode" in text and "tu=net " not in text
    log = (tiny / "names.log").read_text()
    assert "- unit net -> netcode" in log and "0x10001000 func net_10001000 -> netcode_10001000" in log
    assert len(errors(tiny)) == n_err
    code, out = dcp(tiny, "layout", "units")
    assert "unit=netcode" in out and "named_by=tag" in out


def test_unit_join(tiny):
    assert dcp(tiny, "unit", "new", "a", "--range", "0x10001000..0x10001030", "--by", "guess", "--why", "first half")[0] == 0
    assert dcp(tiny, "unit", "new", "b", "--range", "0x10001030..0x10001060", "--by", "guess", "--why", "second half")[0] == 0
    for _ in range(4):
        assert dcp(tiny, "draft", "--next")[0] == 0
    assert (tiny / "src/b/f_10001050.c").exists()
    before = len(errors(tiny))
    code, out = dcp(tiny, "unit", "join", "b", "a", "--why", "x")
    assert code == 1                                          # the earlier unit first
    code, out = dcp(tiny, "unit", "join", "a", "b", "--why", "one literal block")
    assert code == 0, out
    assert not (tiny / "src/b").exists() and not (tiny / "include/b.h").exists()
    assert sorted(p.name for p in (tiny / "src/a").glob("f_*.c")) == ["f_10001000.c", "f_10001020.c", "f_10001030.c", "f_10001050.c"]
    assert "a_10001030" in (tiny / "src/a/f_10001030.c").read_text() and "a_10001050(void);" in (tiny / "include/a.h").read_text()
    decl = [l for l in (tiny / "decl/text.dcl").read_text().splitlines() if "boundary" in l]
    # b ran to the end of the game code without an end line: a's end at b's start goes, a runs on
    assert len(decl) == 1 and decl[0].startswith("0x10001000 boundary start by=guess tu=a")
    assert "joined from b" in (tiny / "src/a/open.md").read_text()
    assert "- unit b -> a by:main why:join: one literal block" in (tiny / "names.log").read_text()
    assert len(errors(tiny)) == before and "grades_changed=0" in out
    code, out = dcp(tiny, "layout", "units")
    assert "units=1" in out and "unit=a  range=0x10001000..0x10001060" in out


# ------------------------------------------------------------------------------------------------ checks
def test_l9_and_ghidra_status(tiny, tmp_path):
    assert dcp(tiny, "setup")[0] == 0
    ghidra(tiny, tmp_path, [(0x10001000, "FUN_10001000", F1, [(0x10001000, 0x10001040)]),
                            (0x10001058, "FUN_10001058", F2, [(0x10001058, 0x1000105b)])])
    l9 = [c for c in Project(tiny).store.conflicts() if c.check == "L9"]
    assert len(l9) == 1 and l9[0].severity.value == "warn" and "0x10001020" in l9[0].message and "0x10001030" in l9[0].message
    code, out = dcp(tiny, "ghidra", "status")
    assert code == 0 and "drafts=2" in out and "l9=1" in out and "ghidra_only=1" in out and "ours_only=3" in out, out
    assert "ghidra_only=0x10001058" in out
    code, out = dcp(tiny, "check", "--strict")
    assert code == 1 and "L9" in out


def patched(tmp_path) -> Path:
    """The synthetic dll with `xor eax, eax; ret` at 0x10001058 in the fill after f4: 0x10001057..0x10001060 is
    unknown code (no fill run any more)."""
    root = make_project(tmp_path / "dead")
    dll = root / "tiny.dll"
    data = bytearray(dll.read_bytes())
    data[0x400 + 0x58:0x400 + 0x5b] = b"\x33\xc0\xc3"
    dll.write_bytes(bytes(data))
    return root


def test_bytes_dead_owned_by_the_unit(tmp_path):
    root = patched(tmp_path)
    assert dcp(root, "unit", "new", "tail", "--range", "0x10001050..0x10001060", "--by", "guess", "--why", "f4")[0] == 0
    code, out = dcp(root, "layout", "units", "-v")
    line = next(l for l in out.splitlines() if l.startswith("unit=tail"))
    assert "status=open" in line and "open_bytes=9" in line          # the patch breaks the fill run: 0x10001057..0x10001060
    assert dcp(root, "decl", "add", "0x10001057..0x10001060 bytes dead -- unreachable return after f4")[0] == 0
    code, out = dcp(root, "layout", "units", "-v")
    line = next(l for l in out.splitlines() if l.startswith("unit=tail"))
    # explained now; the unit stays open only because f4, the last function of the game code, has no fragment
    assert "open_bytes=0" in line and "dead_bytes=9" in out and "end=open" in line
    p = Project(root)
    query.ensure_bytemap(p.store)
    lo, hi, cls, level, sym, unit, src, sec = p.store.bytemap_at(0x10001059)
    assert cls == "dead" and unit is not None and p.store.fact(unit).value["tu"] == "tail"
    assert p.store.fact(src).value == {"what": "dead", "unit": "tail", "decl": "decl:decl/text.dcl:3"}
    assert not errors(root)


def test_l10_fragment_without_bytes(tmp_path):
    root = patched(tmp_path)
    assert dcp(root, "decl", "add", "0x10001058 start -- a function only a table reaches (test)")[0] == 0
    assert dcp(root, "unit", "new", "tail", "--range", "0x10001050..0x10001060", "--by", "guess", "--why", "f4")[0] == 0
    code, out = dcp(root, "draft", "0x10001058")
    assert code == 0, out
    code, out = dcp(root, "layout", "units", "-v")
    assert "L10" in out
    l10 = [c for c in Project(root).store.conflicts() if c.check == "L10"]
    assert len(l10) == 1 and "owns no bytes" in l10[0].message and l10[0].severity.value == "warn"
    assert dcp(root, "check")[0] == 0                       # a warning, not an error
    assert dcp(root, "check", "--strict")[0] == 1


def test_unit_status_rule():
    """L.unit.extent's status: open bytes and C.walk conflicts inside a unit keep it open."""
    from decompanion.ledger.fact import Level
    from decompanion.rules import layout as L
    DE, O = Level.declared, Level.open
    assert L.unit_status(DE, DE, 0, 0) == "separated"
    assert L.unit_status(DE, DE, 3, 0) == "open"
    assert L.unit_status(DE, DE, 0, 1) == "open"
    assert L.unit_status(DE, O, 0, 0) == "open"


# ------------------------------------------------------------------------------------------------ unlinked helpers
@needs_vc6
def test_unlinked_helper_builds_without_a_grade(tiny):
    cfg = tiny / "decompanion.toml"
    cfg.write_text(cfg.read_text().replace('plugin = "vc6"\n', f'plugin = "vc6"\nroot = "{VC6.as_posix()}"\n', 1), newline="\n")
    write(tiny, "decl/text.dcl", "# code\n0x10001020 boundary start by=guess tu=net -- test\n0x10001030 boundary end tu=net -- test\n")
    write(tiny, "src/net/head.c", "int counter = 0x1234;  /* 0x10002000 */\nint twice(int x);\n")
    write(tiny, "src/net/f_10001020.c", "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return counter;\n}\n")
    write(tiny, "src/net/u_twice.c", "/* unlinked, inlined everywhere by /Ob1 */\nint twice(int x)\n{\n    return x + x;\n}\n")
    code, out = dcp(tiny, "build")
    assert code == 0 and "ok=yes" in out, out
    from decompanion.ledger import grades as G
    rows = G.function_grades(Project(tiny).store)
    assert [r["name"] for r in rows] == ["get"] and rows[0]["code"] == "byte"
    assert not [c for c in Project(tiny).store.conflicts() if c.check in ("M.gen", "M.compile")]
    code, out = dcp(tiny, "layout", "units", "-v")
    assert "unlinked=twice  file=src/net/u_twice.c" in out


# ------------------------------------------------------------------------------------------------ session and skills
def git(root, *args):
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=True)


def test_session_start_and_wrap(tiny):
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tiny, check=True)
    write(tiny, ".gitignore", "/build/\n.dcp/\n")
    git(tiny, "add", "-A")
    git(tiny, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "init")
    code, out = dcp(tiny, "session", "start")
    assert code == 0 and "gate: ok" in out and "next=0x10001000" in out, out
    assert (tiny / ".dcp/session.json").exists()
    assert dcp(tiny, "unit", "new", "net", "--range", "0x10001000..0x10001060", "--by", "guess", "--why", "all")[0] == 0
    code, out = dcp(tiny, "session", "start")
    assert code == 1 and "dirty" in out                      # the gate wants a clean tree
    for _ in range(2):
        assert dcp(tiny, "draft", "--next")[0] == 0
    assert dcp(tiny, "rename", "net_10001000", "Main", "--why", "the entry")[0] == 0
    code, out = dcp(tiny, "session", "wrap")
    assert "units: declared 1 (net)" in out and "functions drafted: 2" in out and "0x10001020" in out, out
    assert "renames: 1" in out and "net_10001000 -> Main" in out and "next: 0x10001030" in out
    assert (tiny / "build/session/report.md").exists()


def test_skills_install(tiny):
    code, out = dcp(tiny, "skills", "install")
    assert code == 0, out
    skill = tiny / ".claude/skills/dcp-layout/SKILL.md"
    assert skill.exists() and skill.read_text().startswith("---\nname: dcp-layout\n")
    assert "sleep 1800" in skill.read_text()
    code, out = dcp(tiny, "skills", "install")
    assert "skills=0" in out                                 # nothing changed


def test_ghidra_export_without_ghidra(tiny, capsys):
    cfg = tiny / "decompanion.toml"
    cfg.write_text(cfg.read_text() + '\n[ghidra]\nroot = "C:/nowhere/ghidra"\n', newline="\n")
    code, out = dcp(tiny, "ghidra", "export")
    assert code == 1
    assert "Ghidra not found ([ghidra] root = C:" in capsys.readouterr().err
    assert dcp(tiny, "layout", "next")[0] == 0               # nothing else breaks
