"""Checks that catch source decisions the link and the byte match let pass: A1 (an image address literal cast to a
pointer), L13 (a data declaration at a function's code), L14 (a fragment outside its unit's declared extent, in
the library code), and the link's `library` class (an unresolved name an undeclared archive defines) with its
libs.archives obligation."""
import json
import struct
from pathlib import Path

import pytest

from conftest import dcp

from decompanion import obligations
from decompanion.build import link as L
from decompanion.config import Project
from decompanion.ledger import srcscan
from decompanion.ledger.fact import Level
from decompanion.objfmt import coff
from decompanion.rules import layout as LY

VC6 = Path("C:/Tools/MSVC600-SP5PP")
DX6 = Path("C:/Tools/DXSDK61/lib")


def write(root: Path, rel: str, text: str):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, newline="\n")


def errors(root, check):
    return [c for c in Project(root).store.conflicts() if c.check == check and c.severity.value == "error"]


# ------------------------------------------------------------------------------------------------ A1
def test_ptr_cast_scan():
    text = ("/* 0x5de460, registers the exit callback */\n"
            "#define CB ((void (*)(void))0x5de471)\n"
            "#if 0\nchar *dead = (char *)0x401234;\n#endif\n"
            "int f(void)\n{\n"
            "    atexit((void (*)(void))0x5de470);\n"
            "    p = (char *)0x6f242c;\n"
            "    q = (struct foo **)(unsigned)(0x6f2430u);\n"
            "    r = (void (__cdecl *)(int))(0x401000);\n"
            "    s = U_I((unsigned)&full_data_6f242c);\n"
            "    t = (char *)(unsigned)&ai_OptionsFile;\n"
            "    u = (int)0x5de470;\n"
            "    w = \"(char *)0x5de470\";  /* (char *)0x5de470 */\n"
            "    return 0;\n}\n")
    sc = srcscan.Scan()
    srcscan.scan_file("src/sfx/f_5de460.c", text, sc)
    got = sorted((c.line, c.value, c.text) for c in sc.ptrcasts)
    assert got == [(2, 0x5de471, "(void (*)(void))0x5de471"),
                   (8, 0x5de470, "(void (*)(void))0x5de470"),
                   (9, 0x6f242c, "(char *)0x6f242c"),
                   (10, 0x6f2430, "(struct foo **)(unsigned)(0x6f2430u)"),
                   (11, 0x401000, "(void (__cdecl *)(int))(0x401000)")]


def test_a1_addr_cast(tiny):
    assert dcp(tiny, "decl", "add", "0x10001050 name ShowWorld -- pushes world (test)")[0] == 0
    write(tiny, "src/net/head.c", "int counter = 0x1234;  /* 0x10002000 */\nextern int atexit(void (*)(void));\n")
    write(tiny, "src/net/f_10001030.c",
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
    assert "f_10001030.c:6: `(char *)0x10002030`" in a1[0].message and "the string 0x10002030" in a1[0].message
    assert "f_10001030.c:8: `(void (*)(void))0x10001050`" in a1[1].message
    assert "the name ShowWorld there: reference ShowWorld by name" in a1[1].message


# ------------------------------------------------------------------------------------------------ L13
def test_l13_data_at_code(tiny):
    write(tiny, "src/net/head.c", "int counter = 0x1234;  /* 0x10002000 */\n"
                                  "extern char stub[];  /* 0x10001020, a function's start */\n"
                                  "extern char mid[];   /* 0x10001021, inside it */\n")
    write(tiny, "src/net/f_10001020.c", "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return counter;\n}\n")
    code, out = dcp(tiny, "check")
    assert code == 1, out
    l13 = sorted(errors(tiny, "L13"), key=lambda c: c.lo)
    assert [c.lo for c in l13] == [0x10001020, 0x10001021], out
    assert "data extern stub at 0x10001020 lies at the start of the function 0x10001020..0x10001026 (the name get)" in l13[0].message
    assert "+0x1 inside the function 0x10001020..0x10001026" in l13[1].message
    write(tiny, "src/net/head.c", "int counter = 0x1234;  /* 0x10002000 */\n")
    code, out = dcp(tiny, "check")
    assert code == 0 and not errors(tiny, "L13"), out


# ------------------------------------------------------------------------------------------------ L14
def test_l14_outside_unit_pure():
    units = [LY.UnitX("sfx", 0x42b720, 0x42c3b0, Level.declared, Level.declared, "decl:decl/text.dcl:47", "decl:decl/text.dcl:48"),
             LY.UnitX("open", 0x42c3b0, 0x42d000, Level.declared, Level.declared, "src:src/open/f_42c3b0.c:1", "start of x")]
    srcs = [LY.SrcFn(0x42b720, "sfx", "sfx_Open", "src:src/sfx/f_42b720.c:1"),
            LY.SrcFn(0x5de460, "sfx", "MSS_auto_cleanup", "src:src/sfx/f_5de460.c:1"),      # library code: L14
            LY.SrcFn(0x5de470, "open", "other", "src:src/open/f_5de470.c:1"),               # no declared boundary
            LY.SrcFn(0x42c400, "sfx", "inside", "src:src/sfx/f_42c400.c:1"),                # game code: L7's case
            LY.SrcFn(0x5de480, "lib", "x", "src:src/lib/f_5de480.c:1")]                     # no unit extent
    issues = LY.outside_unit_issues(units, srcs, {"sfx"}, (0x401000, 0x5dd3e0))
    assert [(i.check, i.lo) for i in issues] == [("L14", 0x5de460)]
    assert "fragment of unit sfx (MSS_auto_cleanup) at 0x5de460 lies outside the unit's declared extent 0x42b720..0x42c3b0" in issues[0].message
    assert issues[0].a == "src:src/sfx/f_5de460.c:1" and issues[0].b == "decl:decl/text.dcl:47"


# ------------------------------------------------------------------------------------------------ the link's library class
def build_symlib(path: Path, symbols: list[str]) -> Path:
    """A COFF archive whose first linker member lists `symbols` (all at one dummy member)."""
    n = len(symbols)
    body = struct.pack(">I", n) + struct.pack(">I", 0) * n + b"".join(s.encode() + b"\0" for s in symbols)
    hdr = b"/".ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) + b"0".ljust(8) + str(len(body)).ljust(10).encode() + b"`\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"!<arch>\n" + hdr + body + (b"\n" if len(body) & 1 else b""))
    return path


def test_archive_symbol_table(tmp_path):
    p = build_symlib(tmp_path / "x.lib", ["_IID_Foo", "_bar@4"])
    assert coff.archive_symbol_table(p.read_bytes()) == ["_IID_Foo", "_bar@4"]


def test_link_library_class(tiny):
    assert dcp(tiny, "setup")[0] == 0
    build_symlib(tiny / "libs" / "guids.lib", ["_IID_Foo"])
    p = Project(tiny)
    out = L.classify(p, ["_IID_Foo", "_nowhere"])
    assert out["library"] == [f"_IID_Foo  ->  {(tiny / 'libs' / 'guids.lib').as_posix()}  (undeclared: dcp libs declare "
                              f"<the declared archives> {(tiny / 'libs' / 'guids.lib').as_posix()} --why \"...\")"]
    assert out["other"] == ["_nowhere"]
    # the index is in the store, by content
    assert p.store.blobs("archive.symbols")
    # the obligation reads the last link's classes
    d = tiny / "build" / "link" / "tiny"
    d.mkdir(parents=True, exist_ok=True)
    (d / "link.json").write_text(json.dumps({"unresolved": out}), newline="\n")
    obl = [o for o in obligations.gate_failures(Project(tiny)) if o.id == "libs.archives"]
    assert len(obl) == 1 and "1 unresolved name(s)" in obl[0].missing and "guids.lib defines 1: _IID_Foo" in obl[0].evidence


@pytest.mark.skipif(not (VC6 / "VC98" / "Lib").exists() or not (DX6 / "dxguid.lib").exists(), reason="VC6 or the DX 6.1 SDK not installed")
def test_link_library_class_dx6(tiny):
    """_IID_IDirectDraw4 is in the DX 6.1 SDK's dxguid.lib only (VC98's DXGUID.LIB is DX5)."""
    cfg = tiny / "decompanion.toml"
    text = cfg.read_text().replace('root = "C:/nowhere/vc6"\n', f'root = "{VC6.as_posix()}"\nlib_dirs = ["{DX6.as_posix()}"]\n')
    cfg.write_text(text, newline="\n")
    assert dcp(tiny, "setup")[0] == 0
    out = L.classify(Project(tiny), ["_IID_IDirectDraw4", "_GUID_SysMouse"])
    line = next(l for l in out["library"] if l.startswith("_IID_IDirectDraw4"))
    assert line.startswith(f"_IID_IDirectDraw4  ->  {(DX6 / 'dxguid.lib').as_posix()}  (")
    mouse = next(l for l in out["library"] if l.startswith("_GUID_SysMouse"))
    assert (DX6 / "dxguid.lib").as_posix() in mouse and "VC98/Lib/DXGUID.LIB" in mouse
