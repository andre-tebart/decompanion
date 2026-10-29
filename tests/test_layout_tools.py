"""The layout tooling of milestone 4 on the synthetic dll: the reading commands (disasm, dump, refs, layout
literals / starts), drafting (unit new, draft, rename, unit rename, unit join, names.log), L9, L10, declared
dead bytes owned by their unit, the analyzer lines of the report, the session gate and report, the skills."""
import json
import subprocess
from pathlib import Path

import pytest

from conftest import dcp, make_project

from decompanion.config import Project
from decompanion.ledger import query
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
    """Drafts from a batch_decompile file (the Ghidra export's shape, read by the `rea` analyzer in dcp setup) with
    these items: (address, name, pseudocode, body ranges)."""
    from conftest import use_rea
    sha = Project(root).image.sha256
    js = {"subject": {"digest": {"sha256": sha}}, "normalized_result": {"items": [
        {"address": f"{a:#010x}", "status": "ok", "procedure": {"address": f"{a:#010x}", "name": n}, "pseudocode": text,
         "body": {"start": f"{rs[0][0]:#010x}", "end": f"{rs[-1][1]:#010x}", "size": sum(b - x for x, b in rs),
                  "ranges": [[f"{x:#010x}", f"{b:#010x}"] for x, b in rs]}}
        for a, n, text, rs in items]}}
    f = tmp / "export.json"
    f.write_text(json.dumps(js), newline="\n")
    use_rea(root, f)
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
    for f in ("src/net/head.c", "include/net.h", "src/net/open.md"):
        assert (tiny / f).exists(), f
    assert (tiny / "src/net/open.md").read_text().startswith("# net\n\n## Open work\n")
    assert "NET_H" in (tiny / "include/net.h").read_text()
    n_err = len(errors(tiny))
    # f1 from the analyzer (Ghidra's dialect): the callees spelled as placeholders of their unit, the data label kept, declarations added
    code, out = dcp(tiny, "draft", "--next")
    assert code == 0 and "drafted=0x10001000" in out and "body=rea" in out, out
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
    # f3 without a draft: the @rough skeleton with the disassembly
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
def test_l9_and_analyzer_report(tiny, tmp_path):
    assert dcp(tiny, "setup")[0] == 0
    analyze(tiny, tmp_path, [(0x10001000, "FUN_10001000", F1, [(0x10001000, 0x10001040)]),
                            (0x10001058, "FUN_10001058", F2, [(0x10001058, 0x1000105b)])])
    l9 = [c for c in Project(tiny).store.conflicts() if c.check == "L9"]
    assert len(l9) == 1 and l9[0].severity.value == "warn" and "0x10001020" in l9[0].message and "0x10001030" in l9[0].message
    code, out = dcp(tiny, "report")
    assert code == 0 and "analyzer=rea  drafts=2  export=up-to-date" in out, out
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
    # explained now; the unit stays open only because f4, the last function of the game code, has no fragment
    assert "open_bytes=0" in line and "dead_bytes=9" in out and "end=open" in line
    p = Project(root)
    query.ensure_bytemap(p.store)
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
    (root / "src" / "tail" / "f_10001058.c").write_text("/* 0x10001058, only the source names this start */\n"
                                                        "int f5(void)\n{\n    return 0;\n}\n", newline="\n")
    code, out = dcp(root, "layout", "units", "-v")
    p = Project(root)
    own = [f for f in p.store.facts(Kind.symbol) if f.run == "L.src.extent"]
    funcs = [(f.lo, f.hi) for f in own if f.value["skind"] == "func"]
    assert funcs == [(0x10001058, 0x1000105b)]                         # xor eax,eax; ret
    assert all(f.level is Level.declared for f in own)
    assert not [c for c in p.store.conflicts() if c.check == "L10"]
    assert dcp(root, "check")[0] == 0


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
    cfg.write_text(cfg.read_text().replace('root = "C:/nowhere/vc6"\n', f'root = "{VC6.as_posix()}"\n', 1), newline="\n")
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
    f1 = (tiny / "src/net/f_10001000.c").read_text()
    assert f1.startswith("/* 0x10001000, net_10001000 @rough */\nvoid __cdecl net_10001000(void)\n{\n    /* disassembly")
    assert not (tiny / "include/dcp_ghidra.h").exists()


def test_analyzer_registry():
    from decompanion import analyzers
    from decompanion.analyzers.base import Analyzer
    assert {"ghidra", "rea", "none"} <= set(analyzers.ANALYZERS)
    assert analyzers.DEFAULT == "ghidra" and analyzers.get(None) is analyzers.ANALYZERS["ghidra"]
    assert analyzers.get("nothing") is None
    for key, cls in analyzers.ANALYZERS.items():
        assert issubclass(cls, Analyzer) and cls.key == key
    g = analyzers.dialect("ghidra")
    assert g.is_placeholder("FUN_10001000") and g.is_placeholder("thunk_FUN_10001000") and not g.is_placeholder("Init")
    assert g.data_labels("x = PTR_s_hello_10002030 + DAT_10002000;") == {0x10002030: "undefined *", 0x10002000: "undefined4"}
    assert analyzers.dialect("rea").types_header == g.types_header and analyzers.dialect("none").types_header is None
    assert analyzers.ANALYZERS["none"]({}, None).available().ok
    assert not analyzers.ANALYZERS["rea"]({}, None).available().ok      # no file named


def test_unknown_analyzer(tiny, capsys):
    cfg = tiny / "decompanion.toml"
    cfg.write_text(cfg.read_text().replace('plugin = "none"', 'plugin = "ida"'), newline="\n")
    assert dcp(tiny, "setup")[0] == 2
    assert "unknown analyzer plugin 'ida'" in capsys.readouterr().err


def test_rename_leaves_strings_and_includes():
    from decompanion.source import edit as E
    text = '/* net: f calls net */\n#include "net.h"\nchar *s = "net";\nint net(void);\nint f(void) { return net(); }\n'
    new, n = E.replace_words(text, {"net": "socket_net"})
    assert n == 4 and '#include "net.h"' in new and '"net"' in new and "int socket_net(void);" in new
    assert "/* socket_net: f calls socket_net */" in new


def test_draft_keeps_analyzer_comments_off_the_signature():
    from decompanion.source import draft as DR
    text = "\r\n/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */\r\n\r\nvoid f(int a)\r\n\r\n{\r\n  return;\r\n}\r\n"
    assert DR.split(text)[0] == "void f(int a)"
    assert DR.lead_comments(text) == ["/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */"]


def test_rename_collides_only_with_code(tiny):
    write(tiny, "src/a/head.c", '/* adler32: the checksum */\n#include "adler32.h"\n')
    write(tiny, "src/a/f_10001000.c", "/* 0x10001000, a_10001000 */\nint a_10001000(void)\n{\n    return 0;\n}\n")
    code, out = dcp(tiny, "rename", "a_10001000", "adler32", "--why", "zlib's name")
    assert code == 0, out
    assert "int adler32(void)" in (tiny / "src/a/f_10001000.c").read_text()
    # renamed by hand already (the placeholder is gone, adler32 is the ledger's name of 0x10001000): recorded only
    code, out = dcp(tiny, "rename", "a_10001000", "adler32", "--why", "written by hand")
    assert code == 0 and "recorded=a_10001000" in out, out
    assert (tiny / "names.log").read_text().splitlines()[-1].split(" ", 1)[1].startswith(
        "0x10001000 func a_10001000 -> adler32 by:main why:written by hand")
    assert dcp(tiny, "rename", "a_10001040", "crc32", "--why", "x")[0] == 1      # nowhere, and not the ledger's name
    write(tiny, "src/a/f_10001020.c", "/* 0x10001020, a_10001020 */\nint a_10001020(void)\n{\n    return 1;\n}\n")
    assert dcp(tiny, "rename", "a_10001020", "adler32", "--why", "x")[0] == 1
