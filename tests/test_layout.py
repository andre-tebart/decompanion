"""Layout rules on the synthetic dll: loaders, evidence, unit extents, the checks, propose, the analyzer's drafts."""
import json
from pathlib import Path

from conftest import dcp

from decompanion.config import Project
from decompanion.ledger.fact import Kind, Level
from decompanion.rules import layout as L


def write(root: Path, rel: str, text: str):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, newline="\n")


def facts(root, kind, target=None):
    p = Project(root, target)
    return p.store.facts(kind)


def conflicts(root, target=None):
    return Project(root, target).store.conflicts()


def test_evidence(tiny):
    assert dcp(tiny, "setup")[0] == 0
    ev = facts(tiny, Kind.evidence)
    leak = [f for f in ev if f.value["ekind"] == "leak"]
    assert [(f.lo, f.value["path"], f.value["stem"]) for f in leak] == [(0x10001030, "c:\\src\\net\\net.c", "net")]
    lits = {f.lo: f.value for f in ev if f.value["ekind"] == "lit"}
    assert lits[0x10002010]["first"] == 0x10001030 and lits[0x10002038]["first"] == 0x10001050
    fills = {f.lo: f.value["pre"] for f in ev if f.value["ekind"] == "fill"}
    assert fills[0x10001020] == "nop"
    assert not [c for c in conflicts(tiny) if c.severity.value != "warn"]


def test_units_from_decl_and_sources(tiny):
    write(tiny, "decl/text.dcl", "# code\n0x10001020 boundary start tu=net by=leaked -- c:\\src\\net\\net.c in f3's log string\n")
    write(tiny, "src/net/f_10001020.c", "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return counter;\n}\n")
    write(tiny, "src/net/head.c", "int counter = 0x1234;  /* 0x10002000 */\n")
    code, out = dcp(tiny, "check")
    assert code == 0, out
    code, out = dcp(tiny, "layout", "units")
    assert "units=1" in out
    line = next(l for l in out.splitlines() if l.startswith("unit=net"))
    # the last unit runs to the end of the game code; functions after it lack fragments, so its end is open
    assert "range=0x10001020..0x10001060" in line and "status=open" in line and "end=open" in line and "named_by=leaked" in line
    assert "functions=3" in line and "sourced=1" in line and "leaks=c:\\src\\net\\net.c" in line
    names = {f.value["name"]: f.lo for f in facts(tiny, Kind.name) if f.value.get("origin") == "source"}
    assert names == {"get": 0x10001020, "counter": 0x10002000}
    src = [f for f in facts(tiny, Kind.source)]
    assert all(f.level is Level.declared and f.by.startswith("src:") and f.reason for f in src)
    # an end boundary separates it
    code, out = dcp(tiny, "decl", "add", "0x10001050 boundary end tu=net -- f4 is reached only through data")
    assert code == 0, out
    code, out = dcp(tiny, "layout", "units")
    line = next(l for l in out.splitlines() if l.startswith("unit=net"))
    assert "range=0x10001020..0x10001050" in line and "status=separated" in line and "undrafted=1" in line
    code, out = dcp(tiny, "layout", "next")
    assert "next=0x10001000" in out
    code, out = dcp(tiny, "layout", "next", "--start", "0x10001020", "-n", "3")
    assert "next=0x10001030" in out and "literal" in out and "leak" in out and "next=0x10001050" in out


def test_l4_l6_l1_l5_l7(tiny):
    write(tiny, "decl/text.dcl", "# code\n"
                                 "0x10001024 boundary start tu=bad -- inside f2 on purpose\n"
                                 "0x10001028 boundary start tu=fill -- inside the fill after f2\n"
                                 "0x10001030..0x10001034 bytes dead -- the walk reaches these\n"
                                 "0x10001050 boundary start tu=x -- after its own fragment: L7\n")
    write(tiny, "src/x/f_10001031.c", "/* 0x10001031, inside f3 */\nvoid f(void)\n{\n    FUN_10001044();\n}\n")
    code, out = dcp(tiny, "check")
    assert code == 1
    checks = {c.check for c in conflicts(tiny)}
    assert {"L4", "L6", "L1", "L5", "L7"} <= checks, out
    msgs = [c.message for c in conflicts(tiny) if c.check == "L4"]
    assert any("inside the function 0x10001020" in m for m in msgs) and any("inside fill" in m for m in msgs)


def test_decl_errors_fail_check(tiny):
    write(tiny, "decl/text.dcl", "0x10001020 start -- b\n0x10001000 start -- a\n0x10001000 frob -- x\n0x10002000 start -- data address in text.dcl\n")
    code, out = dcp(tiny, "check")
    assert code == 1
    msgs = [c.message for c in conflicts(tiny) if c.check == "L.decl"]
    assert any("out of order" in m for m in msgs) and any("unknown kind" in m for m in msgs) and any("text.dcl holds code" in m for m in msgs)


def test_propose(tiny):
    assert dcp(tiny, "setup")[0] == 0
    code, out = dcp(tiny, "layout", "unit", "propose", "0x10001024..0x10001050", "--name", "bad", "--why", "x")
    assert code == 1 and "refused" in out and "L4" in out
    assert "bad" not in (tiny / "decl" / "text.dcl").read_text()
    code, out = dcp(tiny, "layout", "unit", "propose", "0x10001020..0x10001050", "--name", "net", "--why", "leaked path", "--by", "leaked")
    assert code == 0, out
    text = (tiny / "decl" / "text.dcl").read_text()
    assert "0x10001020 boundary start by=leaked tu=net -- leaked path" in text and "0x10001050 boundary end tu=net" in text
    code, out = dcp(tiny, "layout", "units")
    assert "unit=net" in out and "status=separated" in out


def test_rea_analyzer(tiny, tmp_path):
    """[analyzer] plugin = "rea": dcp setup reads the saved batch_decompile file (the export), L.analyzer declares
    its starts, a second setup is a no-op, an edited file is read again, a foreign digest is skipped."""
    from conftest import use_rea
    p = Project(tiny)
    j = {"subject": {"digest": {"sha256": p.image.sha256}},
         "normalized_result": {"items": [
             {"address": "0x10001055", "procedure": {"status": "resolved", "address": "0x10001050", "name": "FUN_10001050"},
              "status": "ok", "pseudocode": "\r\nint FUN_10001050(void)\r\n{\r\n  return 0;\r\n}\r\n"},
             {"address": "0x10001000", "status": "error", "error": "timeout"}]}}
    f = tmp_path / "batch.json"
    f.write_text(json.dumps(j), newline="\n")
    use_rea(tiny, f)
    code, out = dcp(tiny, "setup")
    assert code == 0 and "analyzer=rea  exported=1  failed=1" in out, out
    assert "analyzer=rea  drafts=1  export=up-to-date" in out
    starts = [s for s in facts(tiny, Kind.start) if s.value["how"] == "rea"]
    assert [(s.lo, s.level, s.reason, s.by) for s in starts] == [(0x10001050, Level.declared, "rea analysis", "decl:analyzer:rea:batch.json")]
    code, out = dcp(tiny, "setup")
    assert code == 0 and "exported=" not in out                 # the same image, file and starts: nothing runs
    code, out = dcp(tiny, "draft", "0x10001052", "--show")
    assert code == 0 and "int FUN_10001050(void)" in out and out.startswith("/* rea draft of 0x10001050")
    code, out = dcp(tiny, "layout", "next", "--start", "0x10001050")
    assert "analyzed=yes" in out
    j["normalized_result"]["items"][0]["procedure"]["name"] = "Answer"
    f.write_text(json.dumps(j), newline="\n")
    code, out = dcp(tiny, "setup")
    assert "analyzer=rea  exported=1" in out                    # the file changed: read again
    assert [s.value.get("name") for s in facts(tiny, Kind.start) if s.value["how"] == "rea"] == ["Answer"]
    code, out = dcp(tiny, "refs", "Answer")
    assert "origin=analyzer" in out
    j["subject"]["digest"]["sha256"] = "0" * 64
    f.write_text(json.dumps(j), newline="\n")
    code, out = dcp(tiny, "setup")
    assert code == 0 and "analyzer=rea  exported=0" in out and "skipped=batch.json" in out, out
    assert not [s for s in facts(tiny, Kind.start) if s.value["how"] == "rea"]


def test_lit_issues_pure():
    units = [L.UnitX("a", 0x1000, 0x1100, Level.declared, Level.declared, "decl:a", "x"),
             L.UnitX("b", 0x1100, 0x1200, Level.declared, Level.declared, "decl:b", "x")]
    ok = [L.Lit(0x2000, 0x2004, 0x1000, ".data", 0), L.Lit(0x2004, 0x2008, 0x1150, ".data", 0)]
    assert L.lit_issues(units, ok) == []
    bad = ok + [L.Lit(0x2008, 0x200c, 0x1010, ".data", 0)]
    issues = L.lit_issues(units, bad)
    assert [i.check for i in issues] == ["L3"] and "unit a" in issues[0].message
    table = ok + [L.Lit(0x2008, 0x200c, 0x1010, ".data", 2)]       # reached from data: no evidence
    assert L.lit_issues(units, table) == []


def test_leak_issues_pure():
    units = [L.UnitX("a", 0x1000, 0x1100, Level.declared, Level.declared, "decl:a", "x")]
    leaks = [L.Leak(0x1000, "a.c", "a", False, 0x2000), L.Leak(0x1050, "b.c", "b", False, 0x2010), L.Leak(0x1060, "a.h", "a", True, 0x2020)]
    issues = L.leak_issues(units, leaks)
    assert [i.check for i in issues] == ["L8"] and "2 source files" in issues[0].message
