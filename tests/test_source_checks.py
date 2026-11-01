"""Checks that catch source decisions the link and the byte match let pass: A1 (an image address literal cast to a
pointer), L13 (a data declaration at a function's code), L14 (a function outside its unit's declared extent, in
the library code), and the link's `library` class (an unresolved name an undeclared archive defines) with its
libs.archives obligation."""
import json
import struct
from pathlib import Path

import pytest

from conftest import dcp, unit

from decompanion.cli_decide import gate_failures
from decompanion import native
from decompanion.config import Project
from decompanion.ledger.fact import Level
from decompanion import native

VC6 = Path("C:/Tools/MSVC600-SP5PP")
DX6 = Path("C:/Tools/DXSDK61/lib")


def write(root: Path, rel: str, text: str):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, newline="\n")


def errors(root, check):
    return [c for c in Project(root).store.conflicts() if c.check == check and c.severity.value == "error"]


# ------------------------------------------------------------------------------------------------ A1
def test_a1_addr_cast(tiny):
    assert dcp(tiny, "decl", "add", "0x10001050 name ShowWorld -- pushes world (test)")[0] == 0
    unit(tiny, "net", "int counter = 0x1234;  /* 0x10002000 */\nextern int atexit(void (*)(void));\n",
         "/* 0x10001030, logs hello */\nvoid log_hello(void)\n{\n"
          "    char *p = (char *)(unsigned)&counter;\n"                    # the address of a symbol: fine
          "    int n = (int)0x10001050;\n"                                 # no pointer: Q3's business, not A1's
          "    char *s = (char *)0x10002030;\n"
          "    char *z = (char *)0x20002030;\n"                            # outside the image
          "    atexit((void (*)(void))0x10001050);\n}\n")
    code, out = dcp(tiny, "check")
    assert code == 1 and "gate=FAIL" in out, out
    a1 = sorted(errors(tiny, "A1"), key=lambda c: c.lo, reverse=True)
    assert [c.lo for c in a1] == [0x10002030, 0x10001050], out
    assert "src/net.c:9: `(char *)0x10002030`" in a1[0].message and "the string 0x10002030" in a1[0].message
    assert "src/net.c:11: `(void (*)(void))0x10001050`" in a1[1].message
    assert "the name ShowWorld there: reference ShowWorld by name" in a1[1].message


# ------------------------------------------------------------------------------------------------ L13
def test_l13_data_at_code(tiny):
    get = "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return counter;\n}\n"
    unit(tiny, "net", "int counter = 0x1234;  /* 0x10002000 */\n"
                      "extern char stub[];  /* 0x10001020, a function's start */\n"
                      "extern char mid[];   /* 0x10001021, inside it */\n", get)
    code, out = dcp(tiny, "check")
    assert code == 1, out
    l13 = sorted(errors(tiny, "L13"), key=lambda c: c.lo)
    assert [c.lo for c in l13] == [0x10001020, 0x10001021], out
    assert "data extern stub at 0x10001020 lies at the start of the function 0x10001020..0x10001026 (the name get)" in l13[0].message
    assert "+0x1 inside the function 0x10001020..0x10001026" in l13[1].message
    unit(tiny, "net", "int counter = 0x1234;  /* 0x10002000 */\n", get)
    code, out = dcp(tiny, "check")
    assert code == 0 and not errors(tiny, "L13"), out


# ------------------------------------------------------------------------------------------------ L15 views
VIEWS_H = ("#define rec_Count (*(int *)((char *)&records + 0x4))  /* 0x10002004 */\n"
           "#define rec_Names (*(char (*)[2][8])((char *)table + 8))  /* 0x10002008 */\n"
           "#define rec_All (*(int (*)[4])&records)  /* 0x10002000 */\n"
           "#define rec_Alias records  /* 0x10002000 */\n"
           "#define rec_Bad (*(int *)((char *)&records + 0x8))  /* 0x1000200c */\n"
           "#define rec_Elem (*(int *)(table + 1))  /* 0x10002004 */\n"
           "#define LOCAL (*(int *)&p)\n"
           "#define SIZE 0x10  /* 0x10, the record size */\n")


def test_l15_views(tiny):
    write(tiny, "include/views.h", "extern int records[4];  /* 0x10002000 */\n" + VIEWS_H.replace(
        "#define rec_Elem (*(int *)(table + 1))  /* 0x10002004 */\n", ""))
    unit(tiny, "net", '#include "views.h"\n', "/* 0x10001020, reads the count */\nint get(void)\n{\n    return rec_Count;\n}\n")
    code, out = dcp(tiny, "check")
    assert code == 1, out
    l15 = sorted(errors(tiny, "L15"), key=lambda c: c.lo)
    assert [c.lo for c in l15] == [0x10002008, 0x1000200c], out
    assert "view rec_Names: its container table has no data declaration with an address" in l15[0].message
    assert "view rec_Bad at 0x1000200c, but records (0x10002000) + 0x8 is 0x10002008" in l15[1].message
    names = {f.value["name"]: f.lo for f in Project(tiny).store.facts("name") if f.value.get("view")}
    assert names == {"rec_Count": 0x10002004, "rec_All": 0x10002000, "rec_Alias": 0x10002000}


# ------------------------------------------------------------------------------------------------ the link's library class
def build_symlib(path: Path, symbols: list[str]) -> Path:
    """A COFF archive whose first linker member lists `symbols` (all at one dummy member)."""
    n = len(symbols)
    body = struct.pack(">I", n) + struct.pack(">I", 0) * n + b"".join(s.encode() + b"\0" for s in symbols)
    hdr = b"/".ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) + b"0".ljust(8) + str(len(body)).ljust(10).encode() + b"`\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"!<arch>\n" + hdr + body + (b"\n" if len(body) & 1 else b""))
    return path


def test_link_library_class(tiny):
    assert dcp(tiny, "setup")[0] == 0
    build_symlib(tiny / "libs" / "guids.lib", ["_IID_Foo"])
    p = Project(tiny)
    out = native.core().link_classify(p.core, ["_IID_Foo", "_nowhere"])
    assert out["library"] == [f"_IID_Foo  ->  {(tiny / 'libs' / 'guids.lib').as_posix()}  (undeclared: dcp libs declare "
                              f"<the declared archives> {(tiny / 'libs' / 'guids.lib').as_posix()} --why \"...\")"]
    assert out["other"] == ["_nowhere"]
    # the index is in the store, by content
    assert p.store.blobs("archive.symbols")
    # the obligation reads the last link's classes
    d = tiny / "build" / "link" / "tiny"
    d.mkdir(parents=True, exist_ok=True)
    (d / "link.json").write_text(json.dumps({"unresolved": out}), newline="\n")
    obl = [o for o in gate_failures(Project(tiny)) if "obligation=libs.archives" in o]
    assert len(obl) == 1 and "1 unresolved name(s)" in obl[0] and "guids.lib defines 1: _IID_Foo" in obl[0]


@pytest.mark.skipif(not (VC6 / "VC98" / "Lib").exists() or not (DX6 / "dxguid.lib").exists(), reason="VC6 or the DX 6.1 SDK not installed")
def test_link_library_class_dx6(tiny):
    """_IID_IDirectDraw4 is in the DX 6.1 SDK's dxguid.lib only (VC98's DXGUID.LIB is DX5)."""
    cfg = tiny / "decompanion.toml"
    text = cfg.read_text().replace('root = "C:/nowhere/vc6"\n', f'root = "{VC6.as_posix()}"\nlib_dirs = ["{DX6.as_posix()}"]\n')
    cfg.write_text(text, newline="\n")
    assert dcp(tiny, "setup")[0] == 0
    out = native.core().link_classify(Project(tiny).core, ["_IID_IDirectDraw4", "_GUID_SysMouse"])
    line = next(l for l in out["library"] if l.startswith("_IID_IDirectDraw4"))
    assert line.startswith(f"_IID_IDirectDraw4  ->  {(DX6 / 'dxguid.lib').as_posix()}  (")
    mouse = next(l for l in out["library"] if l.startswith("_GUID_SysMouse"))
    assert (DX6 / "dxguid.lib").as_posix() in mouse and "VC98/Lib/DXGUID.LIB" in mouse


# ------------------------------------------------------------------------------------------------ dcp headers conflicts
@pytest.mark.skipif(native.core().clang_library() is None, reason="libclang not installed")
def test_headers_conflicts(tiny):
    write(tiny, "include/net.h", "extern int counter;\nextern short width;\nint add2(int a, int b);\n")
    unit(tiny, "net", "extern int counter;  /* the same as net.h */\nextern char width;\n",
         "/* 0x10001030, logs hello */\nvoid log_hello(void)\n{\n    add2(1);\n    other(2);\n}\n")
    code, out = dcp(tiny, "headers", "conflicts", "net", "net")
    assert code == 1, out
    assert "supersedes=1  call=1" in out and "duplicate=1" in out, out
    assert "kind=supersedes  name=width  at=src/net.c:2  header=include/net.h:2" in out, out
    assert "kind=duplicate  name=counter  at=src/net.c:1" in out, out
    assert "kind=call  name=add2  at=src/net.c:7" in out and "too few arguments" in out, out
    assert "fn=0x10001030" in out, out                     # the function to re-grade
    code, out = dcp(tiny, "headers", "conflicts", "net", "net", "--write")
    assert code == 1 and "write=refused" in out, out
    assert "extern char width;" in (tiny / "src/net.c").read_text()

    fn = "/* 0x10001030, logs hello */\nvoid log_hello(void)\n{\n    add2(1, 2);\n}\n"
    unit(tiny, "net", "extern int counter;  /* the same as net.h */\n", fn)
    code, out = dcp(tiny, "headers", "conflicts", "net", "net.h", "--write")
    assert code == 0 and "dropped=1" in out, out
    text = (tiny / "src/net.c").read_text()
    assert text == '#include "net.h"\n\n' + fn, text


@pytest.mark.skipif(native.core().clang_library() is None, reason="libclang not installed")
def test_headers_conflicts_exempt_and_shifted(tiny):
    """A finding on a line with `@original` / `@vc6` (lint's exemption) is listed with its marker and blocks
    nothing; an error the unit had before is no finding, though the include shifts its line."""
    write(tiny, "include/net.h", "int add2(int a, int b);\n")
    unit(tiny, "net", "extern int counter;\n",
         "/* 0x10001030, logs hello */\nvoid log_hello(void)\n{\n"
         "    add2(1);  /* @original the original pushes one argument */\n    counter = nope;\n}\n")
    code, out = dcp(tiny, "headers", "conflicts", "net", "net")
    assert code == 0, out
    assert "call=0  vc6=0  other=0" in out, out
    assert "kind=call  name=add2  at=src/net.c:6  decl=include/net.h:1  exempt=@original" in out, out
    assert "nope" not in out, out
    code, out = dcp(tiny, "headers", "conflicts", "net", "net", "--write")
    assert code == 0 and "write=src/net.c" in out, out
    assert '#include "net.h"' in (tiny / "src/net.c").read_text()


@pytest.mark.skipif(native.core().clang_library() is None, reason="libclang not installed")
def test_headers_conflicts_warnings(tiny):
    """prototyped calls by argument class; the declaration-set warning."""
    write(tiny, "include/net.h", "int add2(int a, int b);  /* 0x10001020 */\nvoid setf(float f);\nint spare(void);\n")
    head = "int add2(int a, int b);  /* 0x10001020, adds two numbers */\n"
    add2 = "/* 0x10001020 */\nint add2(int a, int b)\n{\n    return a + b;\n}\n"
    unit(tiny, "net", head, add2, "/* 0x10001030, logs hello */\nvoid log_hello(int x)\n{\n"
                                  "    setf(1);\n    setf(x);\n    g(1, \"a\");\n}\n")
    code, out = dcp(tiny, "headers", "conflicts", "net", "net")
    assert "vc6_trial=unavailable" in out, out
    assert "kind=prototyped  name=setf" in out and "safe=0 (constant arguments" in out and "regrade=2" in out, out
    assert "src/net.c:12 (an integer constant to a floating parameter: re-grade)" in out, out
    assert "src/net.c:13 (expressions: re-grade)" in out, out
    assert "warning=declaration-set  added=2  duplicates=1  functions=2  byte=0  shape=0" in out, out      # setf, spare
    # a call with constant integer arguments to an int prototype is safe
    write(tiny, "include/net.h", "int add2(int a, int b);\nint add3(int a, char *s);\n")
    unit(tiny, "net", head, add2, "/* 0x10001030, logs hello */\nvoid log_hello(int x)\n{\n"
                                  "    add3(-1, (char *)\"a\");\n}\n")
    code, out = dcp(tiny, "headers", "conflicts", "net", "net")
    assert "kind=prototyped  name=add3" in out and "safe=1" in out and "regrade=0" in out, out
    assert "src/net.c:12 (constants: safe)" in out, out


@pytest.mark.skipif(native.core().clang_library() is None, reason="libclang not installed")
def test_headers_conflicts_multi_name_and_position(tiny):
    """Every name of a multi-name `extern a, b, c;` line is a duplicate (the line keeps its other names when
    written); the include goes before the first statement using a duplicate when that is above the last
    include (--at LINE chooses)."""
    write(tiny, "include/net.h", "extern int counter;\nextern int width;\nextern int height;\n")
    write(tiny, "include/late.h", "typedef int LATE;\n")
    write(tiny, "include/base.h", "typedef int BASE;\n")
    get = "/* 0x10001020, reads */\nint get(void)\n{\n    return counter + depth;\n}\n"
    unit(tiny, "net", '#include "base.h"\nextern int counter, width, depth;  /* 0x10002000, the counter */\n'
                      "extern int height;\nint *pw = &width;\n#include \"late.h\"\nLATE spare;\n", get)
    code, out = dcp(tiny, "headers", "conflicts", "net", "net")
    assert code == 0, out
    for n, ln in (("counter", 2), ("width", 2), ("height", 3)):
        assert f"kind=duplicate  name={n}  at=src/net.c:{ln}" in out, out
    assert "duplicate=3" in out, out
    code, out = dcp(tiny, "headers", "conflicts", "net", "net", "--write")
    assert code == 0 and "at=4" in out and "dropped=3  lines=2" in out, out
    text = (tiny / "src/net.c").read_text()
    assert text == ('#include "base.h"\nextern int depth;  /* 0x10002000, the counter */\n#include "net.h"\n'
                    'int *pw = &width;\n#include "late.h"\nLATE spare;\n\n' + get), text
    # --at: the includes go where the caller says (the trial still checks them)
    write(tiny, "include/net2.h", "extern int depth;\n")
    code, out = dcp(tiny, "headers", "conflicts", "net", "net2", "--write", "--at", "1")
    assert code == 0 and "at=1" in out, out
    assert (tiny / "src/net.c").read_text().startswith('#include "net2.h"\n#include "base.h"\n#include "net.h"\n')


VC6_ROOT = Path("C:/Tools/MSVC600-SP5PP")


@pytest.mark.skipif(native.core().clang_library() is None, reason="libclang not installed")
@pytest.mark.skipif(not (VC6_ROOT / "VC98" / "Bin" / "CL.EXE").exists(), reason="VC6 not installed")
def test_headers_conflicts_vc6(tiny):
    """clang accepts a struct parameter by value whose type the unit never completes; VC6 rejects it (C2079):
    the VC6 trial reports it as a blocking `vc6` item and --write refuses."""
    cfg = tiny / "decompanion.toml"
    cfg.write_text(cfg.read_text().replace('root = "C:/nowhere/vc6"\n', f'root = "{VC6_ROOT.as_posix()}"\n', 1), newline="\n")
    write(tiny, "include/net.h", "void paint(struct COLOR c);\n")
    unit(tiny, "net", "int counter = 1;  /* 0x10002000 */\n", "/* 0x10001020, reads */\nint get(void)\n{\n    return counter;\n}\n")
    code, out = dcp(tiny, "headers", "conflicts", "net", "net")
    assert code == 1 and "supersedes=0" in out and "vc6=1" in out, out
    assert "kind=vc6" in out and "C2079" in out and "COLOR" in out, out
    code, out = dcp(tiny, "headers", "conflicts", "net", "net", "--write")
    assert code == 1 and "write=refused" in out, out
