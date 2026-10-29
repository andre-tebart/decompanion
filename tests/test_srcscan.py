"""The source scan (ledger/srcscan.py) on a temp source tree: fragments, data comments, tags, placeholders, L11."""
from pathlib import Path

from decompanion.ledger import srcscan


def write(root: Path, rel: str, text: str):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, newline="\n")


def test_scan(tmp_path):
    write(tmp_path, "src/net/head.c", '#include "net.h"\n\n'
                                      "static int counter = 0;  /* 0x10002000 */\n"
                                      "extern int a, b;  /* 0x10002004, 0x10002008 */\n"
                                      "/* 0x10002010 */\n"
                                      "static const char *names[] = {\n    \"x\",\n    \"y\",\n};\n"
                                      "int both;  /* tiny:0x1000200c, other:0x1000300c */\n")
    write(tmp_path, "src/net/f_10001000.c", "/* 0x10001000, opens the socket @deep the jump table differs */\n"
                                            "static int local = 5;  /* 0x10002020 */\n\n"
                                            "int NetOpen(int port)\n{\n    return FUN_10001020(port) + local;\n}\n")
    write(tmp_path, "src/net/f_10001020.c", "/* tiny:0x10001020, other:0x10001120, a helper\n   on two lines @rough */\n"
                                            "static __inline int sq(int x)\n{\n    return x * x;\n}\n"
                                            "int __stdcall helper(int x)\n{\n    return sq(x);\n}\n")
    write(tmp_path, "src/net/u_unused.c", "/* unlinked, dropped by /OPT:REF */\nvoid unused(void)\n{\n}\n")
    write(tmp_path, "src/net/f_10001040.c", "/* 0x10001050, wrong file name */\nvoid f(void)\n{\n}\n")
    write(tmp_path, "src/net/f_10001060.c", "void g(void)\n{\n}\n")
    write(tmp_path, "src/net/f_10001070.c", "/* 0x10001070, two */\nvoid h1(void)\n{\n}\nvoid h2(void)\n{\n}\n")
    write(tmp_path, "src/net/extra.c", "int x;\n")
    write(tmp_path, "include/net.h", "int NetOpen(int port);  /* 0x10001000 */\nextern int counter2;  /* 0x10002030 */\n")
    sc = srcscan.scan(tmp_path)
    fns = {f.name: f for f in sc.functions}
    assert fns["NetOpen"].addrs == ((None, 0x10001000),) and fns["NetOpen"].unit == "net" and fns["NetOpen"].line == 4
    assert fns["NetOpen"].what == "opens the socket" and fns["NetOpen"].deep == "the jump table differs"
    assert fns["helper"].addrs == (("tiny", 0x10001020), ("other", 0x10001120)) and fns["helper"].rough
    assert fns["helper"].what == "a helper on two lines"
    assert "sq" not in fns                                                # an __inline helper is no function
    assert fns["unused"].unlinked and fns["unused"].addrs == ()
    data = {(d.name, d.kind): d for d in sc.data}
    assert data[("counter", "def")].addrs == ((None, 0x10002000),)
    assert data[("a", "extern")].addrs == ((None, 0x10002004),) and data[("b", "extern")].addrs == ((None, 0x10002008),)
    assert data[("names", "def")].addrs == ((None, 0x10002010),)
    assert data[("both", "def")].addrs == (("tiny", 0x1000200c), ("other", 0x1000300c))
    assert data[("local", "def")].addrs == ((None, 0x10002020),)          # not the function's address comment
    assert data[("local", "def")].static and data[("counter", "def")].static and not data[("both", "def")].static
    assert fns["unused"].static is False and fns["NetOpen"].static is False
    assert data[("counter2", "extern")].unit == "net"
    assert srcscan.address_for(fns["helper"].addrs, "other", "tiny") == 0x10001120
    assert srcscan.address_for(fns["NetOpen"].addrs, "tiny", "tiny") == 0x10001000
    assert srcscan.address_for(fns["NetOpen"].addrs, "other", "tiny") is None
    errs = {(e.file.rsplit("/", 1)[-1], e.check): e.message for e in sc.errors}
    assert "the file name says 0x10001040" in errs[("f_10001040.c", "L11")]
    assert "address comment" in errs[("f_10001060.c", "L.src")]
    assert "exactly one function" in errs[("f_10001070.c", "L.src")]
    assert "unexpected source file" in errs[("extra.c", "L.src")]
    assert [p.ident for p in sc.placeholders] == ["FUN_10001020"]


def test_order(tmp_path):
    from decompanion.build import amalg
    write(tmp_path, "src/u/head.c", "int x;\n")
    write(tmp_path, "src/u/f_10001000.c", "/* 0x10001000, a */\nint a(void)\n{\n    return b();\n}\n")
    write(tmp_path, "src/u/f_10001020.c", "/* 0x10001020, b */\nint b(void)\n{\n    return 1;\n}\n")
    write(tmp_path, "src/u/u_c.c", "/* unlinked, c */\nint c(void)\n{\n    return 2;\n}\n")
    sc = srcscan.scan(tmp_path)
    files = [m.file.rsplit("/", 1)[-1] for m in amalg.units(tmp_path, sc, "t", "t")[0].members]
    assert files == ["head.c", "f_10001000.c", "f_10001020.c", "u_c.c"]           # address order, unlinked last
    write(tmp_path, "src/u/order", "# b is defined above its caller a\nu_c.c\nf_10001020.c\nf_10001000.c\n")
    sc = srcscan.scan(tmp_path)
    assert not sc.errors and sc.orders["u"] == ["u_c.c", "f_10001020.c", "f_10001000.c"]
    files = [m.file.rsplit("/", 1)[-1] for m in amalg.units(tmp_path, sc, "t", "t")[0].members]
    assert files == ["head.c", "u_c.c", "f_10001020.c", "f_10001000.c"]
    write(tmp_path, "src/u/order", "f_10001020.c\nf_10001020.c\nf_99.c\n")
    msgs = [e.message for e in srcscan.scan(tmp_path).errors if e.check == "L12"]
    assert any("reason" in m for m in msgs) and any("twice" in m for m in msgs)
    assert any("no such file" in m for m in msgs) and any("leaves out 2" in m for m in msgs)


def test_memo(tmp_path):
    write(tmp_path, "src/u/f_10001000.c", "/* 0x10001000, x */\nvoid f(void)\n{\n}\n")
    a = srcscan.scan(tmp_path, "h1")
    assert srcscan.scan(tmp_path, "h1") is a
