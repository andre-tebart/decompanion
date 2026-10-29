"""Every command and rule per target and across targets, on the synthetic dll as two targets (tiny, other):
the toolchain declaration and the Rich candidates, library archives, the loaders' target prefixes, decl add,
layout, the analyzer, setup --all-targets, seed."""
import json
import shutil
import sys

import pytest

from conftest import build_lib, dcp

from decompanion.config import ConfigError, Project
from decompanion.ledger.fact import Kind


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, newline="\n")


def set_config(root, old, new):
    p = root / "decompanion.toml"
    text = p.read_text()
    assert old in text
    p.write_text(text.replace(old, new, 1), newline="\n")


def target_table(root, name, extra):
    """Append key lines to the [[target]] table of `name`."""
    set_config(root, f'name = "{name}"\n', f'name = "{name}"\n{extra}\n')


def conflicts(root, target=None, check=None):
    return [c for c in Project(root, target).store.conflicts() if check is None or c.check == check]


def facts(root, kind, target=None):
    return Project(root, target).store.facts(kind)


# ------------------------------------------------------------------------------------------------ toolchain
def test_rich_candidates_per_target(tiny2):
    assert dcp(tiny2, "setup", "--all-targets")[0] == 0
    t = facts(tiny2, Kind.toolchain)[0].value
    o = facts(tiny2, Kind.toolchain, "other")[0].value
    assert [(c["tool"], c["build"], c["count"]) for c in t["compilers"]] == [("Utc12_C", 8047, 5), ("Utc12_2_C", 9044, 3)]
    assert {c["build"] for c in o["compilers"]} == {9044, 8047, 9178} and {k["build"] for k in o["linkers"]} == {8447, 9049}
    assert "compiler_build" not in t                       # nothing is picked
    # both inherit the [toolchain] defaults cl 12.00.9044 / link 6.00.8447: candidates of both
    code, out = dcp(tiny2, "check")
    assert code == 0, out


def test_toolchain_declaration_per_target(tiny2):
    target_table(tiny2, "other", 'compiler = "cl 13.00.9178"\nreason = "the VC7 object, on purpose"')
    p = Project(tiny2, "other")
    d = p.toolchain_decl
    assert d["compiler"] == "cl 13.00.9178" and d["linker"] == "link 6.00.8447" and d["from"]["compiler"] == "target"
    assert d["from"]["linker"] == "toolchain" and d["cflags"] == ["/O2"]
    assert Project(tiny2).toolchain_decl["compiler"] == "cl 12.00.9044"
    assert dcp(tiny2, "check")[0] == 0                     # 9178 is a compiler candidate of other
    # the same declaration on tiny is wrong there only
    target_table(tiny2, "tiny", 'compiler = "cl 13.00.9178"\nreason = "wrong on purpose"')
    code, out = dcp(tiny2, "check")
    assert code == 1
    bad = conflicts(tiny2, "tiny", "C.toolchain")
    assert len(bad) == 1 and "names build 9178" in bad[0].message and "cl 12.00.9044 (Utc12_2_C x3)" in bad[0].message
    assert not conflicts(tiny2, "other", "C.toolchain")
    code, out = dcp(tiny2, "toolchain")
    assert "target=tiny" in out and "target=other" in out and "C.toolchain: 1 error(s)" in out and "C.toolchain: ok" in out
    assert "cl 13.00.9178 (Utc13_C C x1)" in out and "inherited from [toolchain]: cflags, linker" in out
    code, out = dcp(tiny2, "--target", "other", "toolchain")
    assert "target=tiny" not in out and "target=other" in out


def test_toolchain_missing_reason_and_compiler(tiny2):
    set_config(tiny2, 'reason = "test project"\n', "")
    set_config(tiny2, 'compiler = "cl 12.00.9044"\n', "")
    target_table(tiny2, "other", 'compiler = "cl 12.00.9044"\nreason = "declared"')
    code, out = dcp(tiny2, "check")
    assert code == 1
    msgs = [c.message for c in conflicts(tiny2, "tiny", "C.toolchain")]
    assert any("no reason" in m for m in msgs) and any("no compiler declared" in m for m in msgs)
    assert not conflicts(tiny2, "other", "C.toolchain")


def test_unknown_target_key(tiny2):
    target_table(tiny2, "other", 'compilr = "cl 12.00.9044"')
    with pytest.raises(ConfigError, match="unknown keys compilr"):
        Project(tiny2)


def test_archives_per_target(tiny2):
    lib = build_lib(tiny2 / "crt.lib", [(0x0a, 8047), (0x0a, 8047)])
    target_table(tiny2, "other", f'archives = ["{lib.as_posix()}"]')
    assert Project(tiny2).lib_archives == [] and Project(tiny2, "other").lib_archives == [lib]
    assert dcp(tiny2, "setup", "--all-targets")[0] == 0
    crt = lambda t: next(c for c in facts(tiny2, Kind.toolchain, t)[0].value["compilers"] if c["build"] == 8047)  # noqa: E731
    assert crt("tiny")["archive_objects"] == 0 and crt("other")["archive_objects"] == 2
    # a changed archive reruns the rules of the target that names it, not the other's
    build_lib(lib, [(0x0a, 8047)])
    from decompanion.rules.engine import Engine
    for name, reran in (("tiny", False), ("other", True)):
        p = Project(tiny2, name)
        res = Engine(p, p.store).run()
        assert any(r.ran for r in res) is reran, name
    assert crt("other")["archive_objects"] == 1
    code, out = dcp(tiny2, "--target", "other", "toolchain")
    assert "archives: crt.lib (own list)" in out


# ------------------------------------------------------------------------------------------------ setup, report, memo
def test_setup_all_targets_and_memo(tiny2, capsys):
    code, out = dcp(tiny2, "setup", "--all-targets")
    assert code == 0 and "target=tiny" in out and "target=other" in out and "toolchain: compiler='cl 12.00.9044'" in out
    capsys.readouterr()
    code, out = dcp(tiny2, "setup", "--all-targets")
    assert code == 0 and "rules:" not in capsys.readouterr().err        # a second setup runs no rule
    code, out = dcp(tiny2, "report", "--target", "other")
    assert "target=other" in out and "target=tiny" not in out
    assert dcp(tiny2, "setup", "--all-targets", "--target", "other") == (2, "")


# ------------------------------------------------------------------------------------------------ loaders
def test_src_prefixes(tiny2):
    write(tiny2, "src/net/f_10001020.c", "/* tiny:0x10001020, other:0x10001030, the helper in both */\nint get(void)\n{\n    return 1;\n}\n")
    write(tiny2, "src/net/f_10001050.c", "/* 0x10001050, the default target's only */\nint put(void)\n{\n    return 2;\n}\n")
    write(tiny2, "src/net/head.c", "int both;  /* tiny:0x10002000, other:0x10002004 */\nint mine;  /* 0x10002008 */\n")
    assert dcp(tiny2, "check")[0] == 0
    src = lambda t: {(f.lo, f.value["symbol"]) for f in facts(tiny2, Kind.source, t)}  # noqa: E731
    assert src("tiny") == {(0x10001020, "get"), (0x10001050, "put"), (0x10002000, "both"), (0x10002008, "mine")}
    assert src("other") == {(0x10001030, "get"), (0x10002004, "both")}
    starts = {f.lo for f in facts(tiny2, Kind.start, "other") if f.value["how"] == "source"}
    assert starts == {0x10001030}


def test_src_errors_reported_once(tiny2):
    write(tiny2, "src/net/f_10001020.c", "void g(void)\n{\n}\n")                 # no address comment
    write(tiny2, "src/net/f_10001030.c", "/* nope:0x10001030, unknown target */\nvoid h(void)\n{\n}\n")
    code, out = dcp(tiny2, "check")
    assert code == 1
    assert len(conflicts(tiny2, "tiny", "L.src")) == 2 and not conflicts(tiny2, "other", "L.src")


def test_placeholders_per_target(tiny2):
    write(tiny2, "src/net/f_10001020.c", "/* other:0x10001020, other's only */\nint g(void)\n{\n    return FUN_10001044();\n}\n")
    write(tiny2, "src/net/head.c", "int x;\nint y(void);\n#define Z FUN_20001000\n")
    code, out = dcp(tiny2, "check")
    assert code == 1
    l5 = lambda t: sorted(c.message for c in conflicts(tiny2, t, "L5"))  # noqa: E731
    assert [m for m in l5("other") if "FUN_10001044" in m]          # a fragment of other: checked in other
    assert not [m for m in l5("tiny") if "FUN_10001044" in m]       # not a file of tiny
    assert [m for m in l5("tiny") if "FUN_20001000" in m and "tiny, other" in m]
    assert not [m for m in l5("other") if "FUN_20001000" in m]      # reported once, by the default target


def test_decl_prefixes_and_add(tiny2):
    code, out = dcp(tiny2, "--target", "other", "decl", "add", "0x10001050 name Handler -- reached through data only")
    assert code == 0, out
    text = (tiny2 / "decl" / "text.dcl").read_text()
    assert "other:0x10001050 name Handler -- reached through data only" in text
    code, out = dcp(tiny2, "decl", "add", "0x10001050 name Fourth -- the default target's")
    assert code == 0, out
    names = lambda t: {f.value["name"] for f in facts(tiny2, Kind.name, t) if f.value.get("origin") == "decl"}  # noqa: E731
    assert names("tiny") == {"Fourth"} and names("other") == {"Handler"}
    lines = [l for l in (tiny2 / "decl" / "text.dcl").read_text().splitlines() if not l.startswith("#")]
    assert lines == ["0x10001050 name Fourth -- the default target's", "other:0x10001050 name Handler -- reached through data only"]
    # an error of an other: line is other's conflict only
    write(tiny2, "decl/text.dcl", "# code\nother:0x10001000 frob -- unknown kind\n")
    code, out = dcp(tiny2, "check")
    assert code == 1 and conflicts(tiny2, "other", "L.decl") and not conflicts(tiny2, "tiny", "L.decl")


# ------------------------------------------------------------------------------------------------ layout
def test_layout_per_target(tiny2):
    assert dcp(tiny2, "setup", "--all-targets")[0] == 0
    code, out = dcp(tiny2, "--target", "other", "layout", "unit", "propose", "0x10001020..0x10001050", "--name", "net", "--why", "leaked path")
    assert code == 0, out
    text = (tiny2 / "decl" / "text.dcl").read_text()
    assert "other:0x10001020 boundary start tu=net -- leaked path" in text and "other:0x10001050 boundary end tu=net" in text
    code, out = dcp(tiny2, "--target", "other", "layout", "units")
    assert "target=other" in out and "unit=net" in out and "status=separated" in out
    code, out = dcp(tiny2, "layout", "units")
    assert "target=tiny" in out and "units=0" in out
    code, out = dcp(tiny2, "--target", "other", "layout", "next", "--start", "0x10001020")
    assert "target=other" in out and "unit=net" in out


# ------------------------------------------------------------------------------------------------ analyzer
def test_analyzer_per_target(tiny2, tmp_path):
    """One rea file about the second target's binary: setup of the default target skips it (and names the target
    it is about), setup of `other` stores its draft."""
    from conftest import use_rea
    other_sha = Project(tiny2, "other").image.sha256
    j = {"subject": {"digest": {"sha256": other_sha}},
         "normalized_result": {"items": [{"address": "0x10001050", "status": "ok", "pseudocode": "int f(void)\n{\n  return 0;\n}\n",
                                          "procedure": {"address": "0x10001050", "name": "FUN_10001050"}}]}}
    f = tmp_path / "other.json"
    f.write_text(json.dumps(j), newline="\n")
    use_rea(tiny2, f)
    code, out = dcp(tiny2, "setup")
    assert code == 0 and "exported=0" in out and "skipped=other.json" in out and "target=other" in out, out
    code, out = dcp(tiny2, "--target", "other", "setup")
    assert code == 0 and "analyzer=rea  exported=1" in out and "target=other" in out
    assert dcp(tiny2, "--target", "other", "draft", "0x10001050", "--show")[0] == 0
    assert dcp(tiny2, "draft", "0x10001050", "--show")[0] == 1
    assert [s.lo for s in facts(tiny2, Kind.start, "other") if s.value["how"] == "rea"] == [0x10001050]
    assert not [s for s in facts(tiny2, Kind.start) if s.value["how"] == "rea"]


# ------------------------------------------------------------------------------------------------ queries and seed
def test_queries_name_the_target(tiny2):
    assert dcp(tiny2, "setup", "--all-targets")[0] == 0
    for cmd in (("facts", "0x10001000..0x10001010"), ("conflicts",), ("map", "0x10001000..0x10001040"), ("rules",)):
        code, out = dcp(tiny2, "--target", "other", *cmd)
        assert code == 0 and out.startswith("target=other"), (cmd, out[:80])
    code, out = dcp(tiny2, "--target", "other", "why", "0x10001020")
    assert "target=other" in out and "toolchain  compilers=3  linkers=2" in out


def test_seed_copies_every_store(tiny2, tmp_path):
    assert dcp(tiny2, "setup", "--all-targets")[0] == 0
    dest = tmp_path / "copy"
    shutil.copytree(tiny2, dest, ignore=shutil.ignore_patterns("build"))
    code, out = dcp(tiny2, "seed", str(dest))
    assert code == 0 and "other.sqlite" in out and "tiny.sqlite" in out
    from decompanion.rules.engine import Engine
    for name in ("tiny", "other"):
        p = Project(dest, name)
        assert not any(r.ran for r in Engine(p, p.store).run()), name
