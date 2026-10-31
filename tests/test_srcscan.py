"""The source scan (ledger/srcscan.py) on a temp source tree: one file per unit, the functions' address comments,
data comments, tags, placeholders, the spans; the `#line` mapping of a unit's compile (build/tu.py)."""
from pathlib import Path

from conftest import unit

from decompanion.build import tu
from decompanion.ledger import srcscan


def write(root: Path, rel: str, text: str):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, newline="\n")


def test_scan(tmp_path):
    unit(tmp_path, "net", '#include "net.h"\n\n'
                          "static int counter = 0;  /* 0x10002000 */\n"
                          "extern int a, b;  /* 0x10002004, 0x10002008 */\n"
                          "/* 0x10002010 */\n"
                          "static const char *names[] = {\n    \"x\",\n    \"y\",\n};\n"
                          "int both;  /* tiny:0x1000200c, other:0x1000300c */\n"
                          "static int local = 5;  /* 0x10002020 */\n",
         "/* 0x10001000, opens the socket @deep the jump table differs */\n"
         "int NetOpen(int port)\n{\n    return FUN_10001020(port) + local;\n}\n",
         "static __inline int sq(int x)\n{\n    return x * x;\n}\n",
         "/* tiny:0x10001020, other:0x10001120, a helper\n   on two lines @rough */\n"
         "int __stdcall helper(int x)\n{\n    return sq(x);\n}\n",
         "/* unlinked, dropped by /OPT:REF */\nvoid unused(void)\n{\n}\n",
         "/* a description, no address */\nvoid g(void)\n{\n}\n",
         "void h(void)\n{\n}\n")
    write(tmp_path, "src/net/extra.c", "int x;\n")
    write(tmp_path, "include/net.h", "int NetOpen(int port);  /* 0x10001000 */\nextern int counter2;  /* 0x10002030 */\n")
    sc = srcscan.scan(tmp_path)
    fns = {f.name: f for f in sc.functions}
    assert fns["NetOpen"].addrs == ((None, 0x10001000),) and fns["NetOpen"].unit == "net"
    assert (fns["NetOpen"].comment_line, fns["NetOpen"].line, fns["NetOpen"].end_line) == (13, 14, 17)
    assert fns["NetOpen"].what == "opens the socket" and fns["NetOpen"].deep == "the jump table differs"
    assert fns["helper"].addrs == (("tiny", 0x10001020), ("other", 0x10001120)) and fns["helper"].rough
    assert fns["helper"].what == "a helper on two lines" and fns["helper"].comment_line == 24
    assert "sq" not in fns                                                # an __inline helper is no function
    assert fns["unused"].unlinked and fns["unused"].addrs == ()
    assert set(fns) == {"NetOpen", "helper", "unused"}
    data = {(d.name, d.kind): d for d in sc.data}
    assert data[("counter", "def")].addrs == ((None, 0x10002000),)
    assert data[("a", "extern")].addrs == ((None, 0x10002004),) and data[("b", "extern")].addrs == ((None, 0x10002008),)
    assert data[("names", "def")].addrs == ((None, 0x10002010),)
    assert data[("both", "def")].addrs == (("tiny", 0x1000200c), ("other", 0x1000300c))
    assert data[("local", "def")].addrs == ((None, 0x10002020),)
    assert data[("local", "def")].static and data[("counter", "def")].static and not data[("both", "def")].static
    assert fns["unused"].static is False and fns["NetOpen"].static is False
    assert data[("counter2", "extern")].unit == "net"
    assert srcscan.address_for(fns["helper"].addrs, "other", "tiny") == 0x10001120
    assert srcscan.address_for(fns["NetOpen"].addrs, "tiny", "tiny") == 0x10001000
    assert srcscan.address_for(fns["NetOpen"].addrs, "other", "tiny") is None
    errs = sorted((e.file, e.line, e.check, e.message) for e in sc.errors)
    assert [(f, ln, c) for f, ln, c, _ in errs] == [("src/net.c", 37, "L.src"), ("src/net.c", 41, "L.src"),
                                                    ("src/net/extra.c", 1, "L.src")], errs
    assert "g: no address comment" in errs[0][3] and "h: no address comment" in errs[1][3]
    assert "unexpected source file src/net/extra.c" in errs[2][3]
    assert [p.ident for p in sc.placeholders] == ["FUN_10001020"]


def test_line_directives():
    """A unit with its original file name and a `__LINE__` pin: the compiler's positions (the name and line the
    directives give) map back to the file's physical lines."""
    text = 'int x;\n#line 1 "D:\\\\dev\\\\u.c"\nint a(void)\n{\n#line 200\n    return 1;\n}\n'
    assert tu.locate(text, "src/u.c", "src/u.c", 1) == [1]
    assert tu.locate(text, "src/u.c", "src\\u.c", 1) == [1]
    assert tu.locate(text, "src/u.c", "D:\\dev\\u.c", 1) == [3]                  # `int a(void)`
    assert tu.locate(text, "src/u.c", "d:/dev/U.C", 200) == [6]                  # after the pin
    assert tu.locate(text, "src/u.c", "D:\\dev\\u.c", 5) == []


def test_memo(tmp_path):
    unit(tmp_path, "u", "/* 0x10001000, x */\nvoid f(void)\n{\n}\n")
    a = srcscan.scan(tmp_path, "h1")
    assert srcscan.scan(tmp_path, "h1").piece_ids == a.piece_ids      # the same pieces: the core's memo
