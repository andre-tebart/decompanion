"""The layout tooling of milestone 4 on the synthetic dll: the reading commands (disasm, dump, refs, layout
literals / starts), drafting (unit new, draft, rename, unit rename, unit join, names.log), L9, L10, declared
dead bytes owned by their unit, the analyzer lines of the report, the session gate and report, the skills."""
import json
import subprocess
from pathlib import Path

import pytest

from conftest import dcp, make_project, unit

from decompanion.config import Project
from decompanion.ledger.fact import Kind, Level

VC6 = Path("C:/Tools/MSVC600-SP5PP")
needs_vc6 = pytest.mark.skipif(not (VC6 / "VC98" / "Bin" / "CL.EXE").exists(), reason="VC6 not installed")


def write(root: Path, rel: str, text: str):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, newline="\n")


def errors(root) -> list:
    return [c for c in Project(root).store.conflicts() if c.severity.value in ("bug", "error")]


def analyze(root: Path, tmp: Path, items: list) -> int:
    """Drafts from a Ghidra export (a stand-in installation writes the batch_decompile file in dcp setup) with these
    items: (address, name, pseudocode, body ranges)."""
    from conftest import use_fake_ghidra
    sha = Project(root).image.sha256
    js = {"subject": {"digest": {"sha256": sha}}, "normalized_result": {"items": [
        {"address": f"{a:#010x}", "status": "ok", "procedure": {"address": f"{a:#010x}", "name": n}, "pseudocode": text,
         "body": {"start": f"{rs[0][0]:#010x}", "end": f"{rs[-1][1]:#010x}", "size": sum(b - x for x, b in rs),
                  "ranges": [[f"{x:#010x}", f"{b:#010x}"] for x, b in rs]}}
        for a, n, text, rs in items]}}
    f = tmp / "export.json"
    f.write_text(json.dumps(js), newline="\n")
    use_fake_ghidra(root, f)
    code, out = dcp(root, "setup")
    assert code == 0 and f"exported={len(items)}" in out, out
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
    code, out = dcp(tiny, "why", "GetCounter")               # why takes a name too (it crashed on int(name, 0))
    assert code == 0 and out.startswith("addr=0x10001020") and "cls=func" in out, out
    code, out = dcp(tiny, "why", "NoSuchName")
    assert code == 1 and "name=NoSuchName" in out and "unknown" in out, out
    code, out = dcp(tiny, "dump", "0x10002000", "0x48", "--str", "--dword")
    assert code == 0 and "section=.data" in out
    assert "text=hello" in out and "text=world" in out and "text=c:\\src\\net\\net.c" in out
    assert "at=0x10002040  u32=0x10001050" in out
    assert "string@0x10002030" in out                       # the symbols starting in a row
    code, out = dcp(tiny, "dump", "0x10002000", "8", "--float")
    assert code == 0 and "at=0x10002000  f32=" in out and "f64=" in out
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
    code, out2 = dcp(tiny, "layout", "starts", "0x10001000", "0x10001060")          # LO HI as two words
    assert code == 0 and out2.splitlines()[1:] == dcp(tiny, "layout", "starts", "0x10001000..0x10001060")[1].splitlines()[1:]
    # the table of pointers in .data: one function pointer, to f4
    code, out = dcp(tiny, "layout", "fptrs")
    assert code == 0 and "fptrs=1" in out, out
    row = next(l for l in out.splitlines() if l.startswith("  site="))
    assert "section=.data" in row and "to=0x10001050" in row and "delta=-" in row
    assert "fptrs=0" in dcp(tiny, "layout", "fptrs", "0x10001000..0x10001040")[1]
    code, out = dcp(tiny, "layout", "literals", "0x10001000..0x10001060")
    assert code == 0, out
    lit = next(l for l in out.splitlines() if l.startswith("  lit=0x10002030"))
    assert "kind=string" in lit and "first=0x10001030" in lit and "text=hello" in lit
    assert "fn=0x10001030" in out and "fn=0x10001050" in out


# ------------------------------------------------------------------------------------------------ drafting
def test_unit_new_draft_rename(tiny, tmp_path):
    assert dcp(tiny, "setup")[0] == 0
    analyze(tiny, tmp_path, [(0x10001000, "FUN_10001000", F1, [(0x10001000, 0x1000100f)]),
                            (0x10001020, "FUN_10001020", F2, [(0x10001020, 0x10001026)])])
    code, out = dcp(tiny, "unit", "new", "net", "--range", "0x10001000..0x10001060", "--by", "guess", "--why", "the whole test code")
    assert code == 0, out
    for f in ("src/net.c", "include/net.h", "notes/units/net.md"):
        assert (tiny / f).exists(), f
    assert (tiny / "notes/units/net.md").read_text().startswith("# net\n\n## Open work\n")
    assert "notes in notes/units/net.md */" in (tiny / "src/net.c").read_text()
    assert "NET_H" in (tiny / "include/net.h").read_text()
    n_err = len(errors(tiny))

    def unit_text():
        text = (tiny / "src/net.c").read_text()
        return text, text[:text.index("\n/* 0x1000")]               # the file and its head region
    # f1 from the analyzer (Ghidra's dialect): the callees spelled as placeholders of their unit, the data label kept, declarations added
    code, out = dcp(tiny, "draft", "--next")
    assert code == 0 and "drafted=0x10001000" in out and "body=ghidra" in out and "file=src/net.c" in out, out
    text, head = unit_text()
    f1 = text[text.index("/* 0x10001000"):]
    assert f1.startswith("/* 0x10001000, net_10001000 */\nvoid net_10001000(void)\n{")
    assert "net_10001020();" in f1 and "net_10001030();" in f1 and "DAT_10002000 = 0;" in f1
    assert head.index('#include "dcp_ghidra.h"') < head.index('#include "net.h"')
    assert "undefined4 net_10001020();" in head and "int net_10001030();" in head and "extern undefined4 DAT_10002000;" in head
    assert "void net_10001000(void);" in (tiny / "include/net.h").read_text()
    assert (tiny / "include/dcp_ghidra.h").exists()
    # f2: its K&R line leaves the head, its prototype (one line) goes into the header, its text after f1's
    code, out = dcp(tiny, "draft", "--next")
    assert "drafted=0x10001020" in out, out
    text, head = unit_text()
    assert "\n/* 0x10001020, net_10001020 */\nundefined4 net_10001020(void)\n" in text
    assert text.index("/* 0x10001000") < text.index("/* 0x10001020")
    assert "net_10001020" not in head
    assert "undefined4 net_10001020(void);" in (tiny / "include/net.h").read_text()
    # f3 without a draft: the @rough skeleton with the disassembly
    code, out = dcp(tiny, "draft", "--next")
    assert "drafted=0x10001030" in out and "body=skeleton" in out, out
    text, head = unit_text()
    f3 = text[text.index("/* 0x10001030"):]
    assert f3.startswith("/* 0x10001030, net_10001030 @rough */\nvoid __cdecl net_10001030(void)") and "push 0x10002010" in f3
    assert "int net_10001030();" not in head
    assert text.index("/* 0x10001020") < text.index("/* 0x10001030")
    code, out = dcp(tiny, "draft", "0x10001030")
    assert code == 1                                          # drafted already
    assert len(errors(tiny)) == n_err, errors(tiny)
    assert not [c for c in Project(tiny).store.conflicts() if c.check in ("L5", "L.src", "L1", "L7")]
    # rename: whole words, names.log, collision refused, the check count unchanged
    code, out = dcp(tiny, "rename", "net_10001020", "GetCounter", "--why", "returns the counter")
    assert code == 0, out
    assert "GetCounter();" in (tiny / "src/net.c").read_text()
    log = (tiny / "names.log").read_text().splitlines()
    assert log[-1].split(" ", 1)[1].startswith("0x10001020 func net_10001020 -> GetCounter by:main why:returns the counter")
    code, out = dcp(tiny, "rename", "net_10001030", "GetCounter", "--why", "x")
    assert code == 1
    assert len(errors(tiny)) == n_err
    # unit rename: its file and notes, header, guard, includes, boundary lines, placeholders
    code, out = dcp(tiny, "unit", "rename", "net", "netcode", "--by", "tag", "--why", "the tag string 'net:'")
    assert code == 0, out
    assert not (tiny / "src/net.c").exists() and (tiny / "src/netcode.c").exists() and (tiny / "notes/units/netcode.md").exists()
    hdr = (tiny / "include/netcode.h").read_text()
    assert "NETCODE_H" in hdr and "NET_H" not in hdr and not (tiny / "include/net.h").exists()
    text = (tiny / "src/netcode.c").read_text()
    assert text.startswith("/* netcode:") and "notes in notes/units/netcode.md */" in text
    assert '#include "netcode.h"' in text and "netcode_10001000" in text
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
    assert "/* 0x10001050, b_10001050" in (tiny / "src/b.c").read_text()
    before = len(errors(tiny))
    code, out = dcp(tiny, "unit", "join", "b", "a", "--why", "x")
    assert code == 1                                          # the earlier unit first
    code, out = dcp(tiny, "unit", "join", "a", "b", "--why", "one literal block")
    assert code == 0, out
    assert not (tiny / "src/b.c").exists() and not (tiny / "include/b.h").exists() and not (tiny / "notes/units/b.md").exists()
    text = (tiny / "src/a.c").read_text()
    at = [text.index(f"/* {a:#010x}") for a in (0x10001000, 0x10001020, 0x10001030, 0x10001050)]
    assert at == sorted(at) and text.count('#include "a.h"') == 1 and "/* b:" not in text, text
    assert "a_10001030" in text and "a_10001050(void);" in (tiny / "include/a.h").read_text()
    decl = [l for l in (tiny / "decl/text.dcl").read_text().splitlines() if "boundary" in l]
    # b ran to the end of the game code without an end line: a's end at b's start goes, a runs on
    assert len(decl) == 1 and decl[0].startswith("0x10001000 boundary start by=guess tu=a")
    assert "joined from b" in (tiny / "notes/units/a.md").read_text()
    assert "- unit b -> a by:main why:join: one literal block" in (tiny / "names.log").read_text()
    assert len(errors(tiny)) == before and "grades_changed=0" in out
    code, out = dcp(tiny, "layout", "units")
    assert "units=1" in out and "unit=a  range=0x10001000..0x10001060" in out


# ------------------------------------------------------------------------------------------------ checks
def test_l9_and_analyzer_report(tiny, tmp_path):
    assert dcp(tiny, "setup")[0] == 0
    analyze(tiny, tmp_path, [(0x10001000, "FUN_10001000", F1, [(0x10001000, 0x10001040)]),
                            (0x10001058, "FUN_10001058", F2, [(0x10001058, 0x1000105b)])])
    l9 = [c for c in Project(tiny).store.conflicts() if c.check == "L9"]
    assert len(l9) == 1 and l9[0].severity.value == "warn" and "0x10001020" in l9[0].message and "0x10001030" in l9[0].message
    code, out = dcp(tiny, "report")
    assert code == 0 and "analyzer=ghidra  drafts=2  export=up-to-date" in out, out
    assert "l9=1" in out and "analyzer_only=1" in out and "ours_only=3" in out, out
    assert "analyzer_only=0x10001058" in out
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
    # explained now; the unit stays open only because f4, the last function of the game code, has no source
    assert "open_bytes=0" in line and "dead_bytes=9" in out and "end=open" in line
    p = Project(root)
    p.store.ensure_bytemap()
    lo, hi, cls, level, sym, unit, src, sec = p.store.bytemap_at(0x10001059)
    assert cls == "dead" and unit is not None and p.store.fact(unit).value["tu"] == "tail"
    assert p.store.fact(src).value == {"what": "dead", "unit": "tail", "decl": "decl:decl/text.dcl:3"}
    assert not errors(root)


def test_declared_start_is_walked(tmp_path):
    root = patched(tmp_path)
    assert dcp(root, "decl", "add", "0x10001058 start -- a function only a table reaches (test)")[0] == 0
    assert dcp(root, "unit", "new", "tail", "--range", "0x10001050..0x10001060", "--by", "guess", "--why", "f4")[0] == 0
    code, out = dcp(root, "draft", "0x10001058")
    assert code == 0, out
    p = Project(root)
    walked = {f.lo: f for f in p.store.facts(Kind.symbol) if f.run == "S.codewalk"}
    assert walked[0x10001058].level is Level.declared and walked[0x10001058].hi == 0x1000105b   # xor eax,eax; ret
    assert not [c for c in p.store.conflicts() if c.check == "L10"]
    assert dcp(root, "check")[0] == 0


def test_source_only_start_owns_its_code(tmp_path):
    """A fragment whose start only the source names (the walk does not reach it, it does not byte-match) owns its
    code up to the next stop by the contiguity convention (L.src.extent), its trailing fill too; no L10."""
    root = patched(tmp_path)
    assert dcp(root, "unit", "new", "tail", "--range", "0x10001050..0x10001060", "--by", "guess", "--why", "f4")[0] == 0
    f = root / "src" / "tail.c"
    f.write_text(f.read_text() + "\n/* 0x10001058, only the source names this start */\nint f5(void)\n{\n    return 0;\n}\n",
                 newline="\n")
    code, out = dcp(root, "layout", "units", "-v")
    p = Project(root)
    own = [f for f in p.store.facts(Kind.symbol) if f.run == "L.src.extent"]
    funcs = [(f.lo, f.hi) for f in own if f.value["skind"] == "func"]
    assert funcs == [(0x10001058, 0x1000105b)]                         # xor eax,eax; ret
    assert all(f.level is Level.declared for f in own)
    assert not [c for c in p.store.conflicts() if c.check == "L10"]
    assert dcp(root, "check")[0] == 0


# ------------------------------------------------------------------------------------------------ unlinked helpers
@needs_vc6
def test_unlinked_helper_builds_without_a_grade(tiny):
    cfg = tiny / "decompanion.toml"
    cfg.write_text(cfg.read_text().replace('root = "C:/nowhere/vc6"\n', f'root = "{VC6.as_posix()}"\n', 1), newline="\n")
    write(tiny, "decl/text.dcl", "# code\n0x10001020 boundary start by=guess tu=net -- test\n0x10001030 boundary end tu=net -- test\n")
    unit(tiny, "net", "int counter = 0x1234;  /* 0x10002000 */\nint twice(int x);\n",
         "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return counter;\n}\n",
         "/* unlinked, inlined everywhere by /Ob1 */\nint twice(int x)\n{\n    return x + x;\n}\n")
    code, out = dcp(tiny, "build")
    assert code == 0 and "failed=0" in out and "ok=yes" not in out, out   # only failed units get a row
    code, out = dcp(tiny, "build", "--units")
    assert code == 0 and "tu=net" in out and "ok=yes" in out, out
    from decompanion import native
    rows = native.core().grades_function(str(Project(tiny).store_path()))
    assert [r["name"] for r in rows] == ["get"] and rows[0]["code"] == "byte"
    assert not [c for c in Project(tiny).store.conflicts() if c.check in ("M.gen", "M.compile")]
    code, out = dcp(tiny, "layout", "units", "-v")
    assert "unlinked=twice  file=src/net.c" in out
    code, out = dcp(tiny, "disasm", "--ours", "get")
    assert code == 0 and "ours=get" in out and "relocations=1" in out and "; reloc counter" in out, out


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
    code, out = dcp(tiny, "session", "status")
    assert code == 0 and "session=running" in out and "elapsed=0m" in out and "over=no" in out, out
    assert dcp(tiny, "layout", "next")[1].splitlines()[0].startswith("session=running")
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
    assert "dcp session status" in skill.read_text() and "sleep 1800" not in skill.read_text()
    code, out = dcp(tiny, "skills", "install")
    assert "skills=0" in out                                 # nothing changed


def test_setup_without_ghidra(tiny, capsys):
    """The configured analyzer is missing: one warning line, setup still exits 0, nothing else breaks."""
    cfg = tiny / "decompanion.toml"
    cfg.write_text(cfg.read_text().replace('plugin = "none"', 'plugin = "ghidra"\nroot = "C:/nowhere/ghidra"'), newline="\n")
    code, out = dcp(tiny, "setup")
    assert code == 0 and "analyzer=ghidra  drafts=0  export=none" in out, out
    err = [l for l in capsys.readouterr().err.splitlines() if l.startswith("analyzer=")]
    assert len(err) == 1 and err[0].startswith("analyzer=ghidra unavailable: Ghidra not found ([analyzer] root = C:/nowhere/ghidra)")
    assert dcp(tiny, "layout", "next")[0] == 0               # nothing else breaks
    code, out = dcp(tiny, "setup", "--no-analyzer")
    assert code == 0 and "unavailable" not in capsys.readouterr().err


def test_no_analyzer_drafts_rough_skeletons(tiny, capsys):
    """plugin = "none": setup exports nothing (one warning line), dcp draft writes a @rough skeleton from the
    disassembly."""
    code, out = dcp(tiny, "setup")
    assert code == 0 and "analyzer=none  drafts=0" in out, out
    err = [l for l in capsys.readouterr().err.splitlines() if l.startswith("analyzer=")]
    assert err == ["analyzer=none: no analyzer configured: no drafts, dcp draft writes @rough skeletons"]
    assert dcp(tiny, "unit", "new", "net", "--range", "0x10001000..0x10001060", "--by", "guess", "--why", "the whole test code")[0] == 0
    code, out = dcp(tiny, "draft", "--next")
    assert code == 0 and "drafted=0x10001000" in out and "body=skeleton" in out, out
    text = (tiny / "src/net.c").read_text()
    assert "\n/* 0x10001000, net_10001000 @rough */\nvoid __cdecl net_10001000(void)\n{\n    /* disassembly" in text
    assert not (tiny / "include/dcp_ghidra.h").exists()


def test_analyzer_registry():
    from decompanion import analyzers
    assert analyzers.ANALYZERS == ("ghidra", "none") and analyzers.DEFAULT == "ghidra"


def test_unknown_analyzer(tiny, capsys):
    cfg = tiny / "decompanion.toml"
    cfg.write_text(cfg.read_text().replace('plugin = "none"', 'plugin = "ida"'), newline="\n")
    assert dcp(tiny, "setup")[0] == 2
    assert "unknown analyzer plugin 'ida'" in capsys.readouterr().err


def test_rename_is_symbol_exact(tiny):
    """A symbol with an address is renamed where it is used, not where a parameter, a local or a struct field of
    the same name stands (comments still follow by word); a new name that is only a local elsewhere is no
    collision."""
    unit(tiny, "a", "struct S { int a_10001000; };\nint count;\n",
         "/* 0x10001000, a_10001000 */\nint a_10001000(int count)\n{\n"
         "    struct S s;\n    s.a_10001000 = count;\n    return s.a_10001000;\n}\n",
         "/* 0x10001020, a_10001020 */\nint a_10001020(void)\n{\n"
         "    int a_10001000 = 1;\n    int checksum = 2;\n    return a_10001000 + checksum + a_10001000;\n}\n")
    code, out = dcp(tiny, "rename", "a_10001000", "checksum", "--why", "what it computes")
    assert code == 0, out
    text = (tiny / "src/a.c").read_text()
    assert "/* 0x10001000, checksum */\nint checksum(int count)" in text
    assert "s.a_10001000 = count;" in text and "return s.a_10001000;" in text
    assert "int a_10001000 = 1;" in text and "return a_10001000 + checksum + a_10001000;" in text
    assert "struct S { int a_10001000; };" in text


def test_rename_collides_only_with_code(tiny):
    head = '/* adler32: the checksum */\n#include "adler32.h"\n'
    unit(tiny, "a", head, "/* 0x10001000, a_10001000 */\nint a_10001000(void)\n{\n    return 0;\n}\n")
    code, out = dcp(tiny, "rename", "a_10001000", "adler32", "--why", "zlib's name")
    assert code == 0, out
    assert "int adler32(void)" in (tiny / "src/a.c").read_text()
    # renamed by hand already (the placeholder is gone, adler32 is the ledger's name of 0x10001000): recorded only
    code, out = dcp(tiny, "rename", "a_10001000", "adler32", "--why", "written by hand")
    assert code == 0 and "recorded=a_10001000" in out, out
    assert (tiny / "names.log").read_text().splitlines()[-1].split(" ", 1)[1].startswith(
        "0x10001000 func a_10001000 -> adler32 by:main why:written by hand")
    assert dcp(tiny, "rename", "a_10001040", "crc32", "--why", "x")[0] == 1      # nowhere, and not the ledger's name
    f = tiny / "src/a.c"
    f.write_text(f.read_text() + "\n/* 0x10001020, a_10001020 */\nint a_10001020(void)\n{\n    return 1;\n}\n", newline="\n")
    assert dcp(tiny, "rename", "a_10001020", "adler32", "--why", "x")[0] == 1
    # the new name written by hand in part (a header prototype of the same address) while the placeholder is still
    # in the code: the rename completes it and records it
    write(tiny, "include/a.h", "int crc32(void);  /* 0x10001020 */\n")
    code, out = dcp(tiny, "rename", "a_10001020", "crc32", "--why", "the crc table")
    assert code == 0 and "completes it" in out, out
    assert "int crc32(void)" in (tiny / "src/a.c").read_text()
    assert (tiny / "names.log").read_text().splitlines()[-1].split(" ", 1)[1].startswith("0x10001020 func a_10001020 -> crc32")


def test_rename_reports_every_outcome(tiny, capsys):
    """Every refused rename prints an error record (stdout) and exits 1 without writing; every rename prints what
    it changed: the record, then one line per file with its replacements (a rename that silently did nothing
    was a match-base report: a name only inside a string literal counted as found)."""
    write(tiny, "include/a.h", "int a_HdrOnly(void);  /* 0x10001050 */\nextern int a_Unk10002000;  /* 0x10002000 */\n"
                               "#define a_Unk10002000B (*(short *)&a_Unk10002000)  /* 0x10002000 */\n")
    unit(tiny, "a", '#include "a.h"\n',
         "/* 0x10001000, a_10001000 */\nint a_10001000(void)\n{\n    return a_Unk10002000 + a_Unk10002000B;\n}\n",
         '/* 0x10001020, a_10001020 */\nint a_10001020(void)\n{\n    return (int)"a_InString";\n}\n')
    unit(tiny, "d", "int a_Unk10002000 = 0x1234;  /* 0x10002000 */\n")
    log = tiny / "names.log"
    kept = (".c", ".h", ".dcl", ".log")

    def refused(*args, says):
        before = {f: f.read_text() for f in tiny.rglob("*") if f.suffix in kept}
        code, out = dcp(tiny, "rename", *args, "--why", "x")
        assert code == 1 and "error=" in out and says in out, out
        assert says in capsys.readouterr().err
        assert {f: f.read_text() for f in tiny.rglob("*") if f.suffix in kept} == before

    # a name only in a header: renamed there, the file listed
    code, out = dcp(tiny, "rename", "a_HdrOnly", "a_Probe", "--why", "x")
    assert code == 0 and "files=1  replacements=1" in out and "  file=include/a.h  replacements=1" in out, out
    # a data name: every file listed; its view keeps its own name, a note says so
    code, out = dcp(tiny, "rename", "a_Unk10002000", "a_Counter", "--why", "the counter")
    assert code == 0 and "kind=data  at=0x10002000  files=3  replacements=4" in out, out
    assert "file=src/d.c  replacements=1" in out and "file=include/a.h  replacements=2" in out
    assert "the views of a_Unk10002000 keep their names: a_Unk10002000B" in out
    # the view by its own name
    code, out = dcp(tiny, "rename", "a_Unk10002000B", "a_CounterLo", "--why", "the low half")
    assert code == 0 and "kind=data  at=0x10002000  files=2" in out, out
    assert "#define a_CounterLo (*(short *)&a_Counter)" in (tiny / "include/a.h").read_text()
    # an address, plain and target-prefixed: the ledger's name of it
    code, out = dcp(tiny, "rename", "tiny:0x10001000", "a_Main", "--why", "the entry")
    assert code == 0 and "is a_10001000" in out and "renamed=a_10001000  to=a_Main  kind=func  at=0x10001000" in out, out
    code, out = dcp(tiny, "rename", "0x10001000", "a_Entry", "--why", "the entry")
    assert code == 0 and "renamed=a_Main  to=a_Entry" in out, out
    assert log.read_text().splitlines()[-1].split(" ", 1)[1].startswith("0x10001000 func a_Main -> a_Entry")
    # refusals: an error record each, nothing written
    refused("a_InString", "a_Other", says="only inside string literals")
    refused("a_10001020", "a_Counter", says="a_Counter exists already")
    refused("a_Nowhere", "a_Other", says="occurs nowhere")
    refused("nosuch:0x10001000", "a_Other", says="no target 'nosuch'")
    refused("0x10001040", "a_Other", says="knows no name of 0x10001040")
    refused("a_10001020", "9bad", says="no C identifier")
    refused("a-b", "a_Other", says="neither a C identifier nor an address")
    refused("a_Counter", "a_Counter", says="the same name")
    # a name declared only in decl/*.dcl: the declaration line is renamed
    write(tiny, "decl/data.dcl", "# data\n0x10002040 name a_Table -- the pointer table\n")
    code, out = dcp(tiny, "rename", "a_Table", "a_Handlers", "--why", "x")
    assert code == 0 and "decl=1" in out and "file=decl/data.dcl  replacements=1" in out, out
    assert "0x10002040 name a_Handlers -- the pointer table" in (tiny / "decl/data.dcl").read_text()


def test_rename_several_pairs(tiny, capsys):
    """Several OLD NEW pairs (and --from FILE) in one call: all are checked before anything is written (one
    refused pair refuses the call), then written in one pass, each with its record and its names.log event."""
    write(tiny, "include/a.h", "int a_10001000(void);  /* 0x10001000 */\nextern int a_Unk10002000;  /* 0x10002000 */\n")
    unit(tiny, "a", '#include "a.h"\n',
         "/* 0x10001000, a_10001000 */\nint a_10001000(void)\n{\n    return a_Unk10002000;\n}\n",
         "/* 0x10001020, a_10001020 */\nint a_10001020(void)\n{\n    return a_10001000() + a_Unk10002000;\n}\n")
    unit(tiny, "d", "int a_Unk10002000 = 0x1234;  /* 0x10002000 */\n")
    log = tiny / "names.log"
    kept = (".c", ".h", ".dcl", ".log")

    def snapshot():
        return {f: f.read_text() for f in tiny.rglob("*") if f.suffix in kept}

    # one refused pair: every refusal listed, nothing written
    before = snapshot()
    code, out = dcp(tiny, "rename", "a_10001000", "a_Main", "a_Nowhere", "a_Other", "--why", "x")
    assert code == 1 and "rename=a_Nowhere  to=a_Other  error=" in out and "nothing written" in out, out
    assert snapshot() == before
    # a chain and an odd word count are refused
    code, out = dcp(tiny, "rename", "a_10001000", "a_Main", "a_Main", "a_Entry", "--why", "x")
    assert code == 1 and "a chain" in out and snapshot() == before, out
    code, out = dcp(tiny, "rename", "a_10001000", "--why", "x")
    assert code == 1 and "pairs expected" in out, out
    capsys.readouterr()
    # two pairs on the command line and one from a file (its own why): one call, one record per pair
    write(tiny, "pairs.txt", "# the table\n0x10001020 a_Sum the sum of both\n")
    code, out = dcp(tiny, "rename", "a_10001000", "a_Main", "a_Unk10002000", "a_Counter", "--from", str(tiny / "pairs.txt"),
                    "--why", "the entry")
    assert code == 0, out
    assert "renamed=a_10001000  to=a_Main  kind=func  at=0x10001000  files=2  replacements=4" in out, out
    assert "renamed=a_Unk10002000  to=a_Counter  kind=data  at=0x10002000  files=3" in out, out
    assert "renamed=a_10001020  to=a_Sum  kind=func  at=0x10001020  files=1" in out, out
    a = (tiny / "src/a.c").read_text()
    assert "return a_Main() + a_Counter;" in a and "int a_Sum(void)" in a and "a_10001000" not in a
    events = [l.split(" ", 1)[1] for l in log.read_text().splitlines()[-3:]]
    assert events[0].startswith("0x10001000 func a_10001000 -> a_Main") and "why:the entry" in events[0]
    assert events[2].startswith("0x10001020 func a_10001020 -> a_Sum") and "why:the sum of both" in events[2]


def test_disasm_inside_an_instruction(tiny):
    """An address inside an instruction of a function lists from the next instruction boundary (decoded from the
    function's start), with a note, not as undecodable bytes (match-base feedback 2026-10-30)."""
    code, out = dcp(tiny, "disasm", "0x10001000")
    rows = [l.split() for l in out.splitlines() if l.startswith("   0x")]
    at = [int(r[0], 16) for r in rows]
    first, second = next((x, y) for x, y in zip(at, at[1:]) if y - x > 1)     # an instruction longer than a byte
    code, out = dcp(tiny, "disasm", hex(first + 1))
    assert code == 0 and "is inside an instruction" in out and f"disasm=0x{second:08x}.." in out, out
    assert "do not decode" not in out
    assert [l.split()[0] for l in out.splitlines() if l.startswith("   0x")][0] == f"0x{second:08x}"
