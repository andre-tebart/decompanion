"""The .dcl grammar (ledger/decl.py): good lines, every error class, sorted insertion."""
import pytest

from decompanion.ledger import decl as D


@pytest.mark.parametrize("line, kind, lo, hi, words, keys, target", [
    ("0x10008cb0 boundary start tu=dllmain by=guess -- the dll's entry points", "boundary", 0x10008cb0, 0x10008cb1, ("start",),
     {"tu": "dllmain", "by": "guess"}, None),
    ("server:0x10008d20 boundary end tu=dllmain -- next unit", "boundary", 0x10008d20, 0x10008d21, ("end",), {"tu": "dllmain"}, "server"),
    ("0x10001000..0x10001010 bytes dead -- unreachable tail", "bytes", 0x10001000, 0x10001010, ("dead",), {}, None),
    ("0x10001000..0x10001010 jumptable fn=0x10000ff0 -- switch of f", "jumptable", 0x10001000, 0x10001010, (), {"fn": 0x10000ff0}, None),
    ("0x10001000..0x10001004 idxtable fn=0x10000ff0 -- byte index", "idxtable", 0x10001000, 0x10001004, (), {"fn": 0x10000ff0}, None),
    ("0x10001000..0x10001100 foreign kind=masm -- hand-written asm", "foreign", 0x10001000, 0x10001100, (), {"kind": "masm"}, None),
    ("0x10001000 name NetInit -- leaked by a log string", "name", 0x10001000, 0x10001001, ("NetInit",), {}, None),
    ("0x10001000..0x10001008 fptr -- two handlers", "fptr", 0x10001000, 0x10001008, (), {}, None),
    ("exe:0x401000 start -- reached through a computed jump", "start", 0x401000, 0x401001, (), {}, "exe"),
    ("0x5fbd94 file tu=d3_interface path=D:\\develop\\Units\\d3\\d3_interface.c -- its __FILE__", "file", 0x5fbd94, 0x5fbd95,
     (), {"tu": "d3_interface", "path": "D:\\develop\\Units\\d3\\d3_interface.c"}, None),
])
def test_good_lines(line, kind, lo, hi, words, keys, target):
    d = D.parse_line(line)
    assert (d.kind, d.lo, d.hi, d.words, d.keys, d.target) == (kind, lo, hi, words, keys, target)
    assert d.reason
    assert D.parse_line(d.text()) == d          # the canonical spelling parses back to the same declaration


@pytest.mark.parametrize("line, msg", [
    ("0x10001000 boundary start tu=x", "missing reason"),
    ("0x10001000 boundary start tu=x --", "missing reason"),
    ("0x10001000 boundary start tu=x --   ", "missing reason"),
    ("0x10001000 frob -- x", "unknown kind"),
    ("0x10001000 boundary middle tu=x -- x", "not one of"),
    ("0x10001000 boundary start -- x", "missing tu="),
    ("0x10001000 boundary start tu=x color=red -- x", "unknown key"),
    ("0x10001000 boundary start tu=x by=hunch -- x", "not one of"),
    ("0x10001000 bytes dead -- x", "range"),
    ("0x10001010..0x10001000 bytes dead -- x", "empty range"),
    ("0x10001000..0x10001010 name f -- x", "point"),
    ("0x10001000 name 9lives -- x", "identifier"),
    ("0x10001000..0x10001010 jumptable fn=zz -- x", "hex address"),
    ("10001000 start -- x", "cannot parse"),
    ("0x10001000 -- x", "missing kind"),
    ('0x10001000 file tu=x path="a.c" -- x', "not a path"),
    ("0x10001000 file path=a.c -- x", "missing tu="),
])
def test_bad_lines(line, msg):
    with pytest.raises(D.DeclError, match=msg):
        D.parse_line(line)


def test_load_errors(tmp_path):
    (tmp_path / "decl").mkdir()
    f = tmp_path / "decl" / "text.dcl"
    f.write_text("# comment\n\n"
                 "0x10002000 start -- b\n"
                 "0x10001000 start -- a: out of order\n"
                 "0x10002000 start -- again: duplicate\n"
                 "0x10003000 frob -- unknown kind\n"
                 "nope:0x10004000 start -- unknown target\n"
                 "other:0x10000000 start -- the second target sorts after the default\n"
                 "0x10005000 start -- a default-target line after another target's\n", newline="\n")
    decls, errors = D.load([f], tmp_path, ["tiny", "other"])
    msgs = [(e.line, e.message) for e in errors]
    assert any(l == 4 and "out of order" in m for l, m in msgs)
    assert any(l == 5 and "duplicate" in m for l, m in msgs)
    assert any(l == 6 and "unknown kind" in m for l, m in msgs)
    assert any(l == 7 and "unknown target" in m for l, m in msgs)
    assert any(l == 9 and "out of order" in m for l, m in msgs)
    assert not any(l == 8 for l, m in msgs)
    assert [d.line for d in decls] == [3, 4, 5, 8, 9]
    assert decls[0].by == "decl:decl/text.dcl:3"


def test_insert_sorted(tmp_path):
    f = tmp_path / "text.dcl"
    f.write_text("# header\n0x10001000 start -- a\n0x10003000 start -- c\nother:0x10000000 start -- o\n", newline="\n")
    t = ["tiny", "other"]
    assert D.insert(f, D.parse_line("0x10002000 start -- b"), t) == 3
    assert D.insert(f, D.parse_line("0x10000000 start -- first"), t) == 2
    assert D.insert(f, D.parse_line("other:0x20000000 start -- last"), t) == 7
    assert D.insert(f, D.parse_line("0x10003000 boundary start tu=u -- same address, after"), t) == 6
    lines = f.read_text().splitlines()
    assert lines == ["# header", "0x10000000 start -- first", "0x10001000 start -- a", "0x10002000 start -- b",
                     "0x10003000 start -- c", "0x10003000 boundary start tu=u -- same address, after",
                     "other:0x10000000 start -- o", "other:0x20000000 start -- last"]
    decls, errors = D.load([f], tmp_path, t)
    assert not errors
