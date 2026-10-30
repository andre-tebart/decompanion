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


# ------------------------------------------------------------------------------------------------ L15 views
VIEWS_H = ("#define rec_Count (*(int *)((char *)&records + 0x4))  /* 0x10002004 */\n"
           "#define rec_Names (*(char (*)[2][8])((char *)table + 8))  /* 0x10002008 */\n"
           "#define rec_All (*(int (*)[4])&records)  /* 0x10002000 */\n"
           "#define rec_Alias records  /* 0x10002000 */\n"
           "#define rec_Bad (*(int *)((char *)&records + 0x8))  /* 0x1000200c */\n"
           "#define rec_Elem (*(int *)(table + 1))  /* 0x10002004 */\n"
           "#define LOCAL (*(int *)&p)\n"
           "#define SIZE 0x10  /* 0x10, the record size */\n")


def test_view_scan():
    sc = srcscan.Scan()
    srcscan.scan_file("include/views.h", VIEWS_H, sc)
    got = [(v.name, v.container, v.offset, v.addrs, v.alias) for v in sc.views]
    assert got == [("rec_Count", "records", 4, ((None, 0x10002004),), False),
                   ("rec_Names", "table", 8, ((None, 0x10002008),), False),
                   ("rec_All", "records", 0, ((None, 0x10002000),), False),
                   ("rec_Alias", "records", 0, ((None, 0x10002000),), True),
                   ("rec_Bad", "records", 8, ((None, 0x1000200c),), False)]
    assert sc.rawobj == ["rec_Elem", "LOCAL"]
    assert [(e.check, e.line) for e in sc.errors] == [("L15", 6)]       # an address comment, but no byte offset


def test_l15_views(tiny):
    write(tiny, "include/views.h", "extern int records[4];  /* 0x10002000 */\n" + VIEWS_H.replace(
        "#define rec_Elem (*(int *)(table + 1))  /* 0x10002004 */\n", ""))
    write(tiny, "src/net/head.c", '#include "views.h"\n')
    write(tiny, "src/net/f_10001020.c", "/* 0x10001020, reads the count */\nint get(void)\n{\n    return rec_Count;\n}\n")
    code, out = dcp(tiny, "check")
    assert code == 1, out
    l15 = sorted(errors(tiny, "L15"), key=lambda c: c.lo)
    assert [c.lo for c in l15] == [0x10002008, 0x1000200c], out
    assert "view rec_Names: its container table has no data declaration with an address" in l15[0].message
    assert "view rec_Bad at 0x1000200c, but records (0x10002000) + 0x8 is 0x10002008" in l15[1].message
    names = {f.value["name"]: f.lo for f in Project(tiny).store.facts(LY.Kind.name) if f.value.get("view")}
    assert names == {"rec_Count": 0x10002004, "rec_All": 0x10002000, "rec_Alias": 0x10002000}


def test_q4_object_macros(tmp_path):
    from decompanion.rules import grade as GR
    write(tmp_path, "include/views.h", VIEWS_H)
    raw, _ = GR.context(str(tmp_path), "t1")
    assert {"rec_Elem", "LOCAL"} <= raw and not raw & {"rec_Count", "rec_Names", "rec_All", "rec_Alias", "rec_Bad", "SIZE"}


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


def test_l14_library_unit_pure():
    """A library unit (`libunit`) is checked against its member range, not a game unit's extent: inside it is
    fine, outside it is L14, and a member range inside the game code is L14 too."""
    from decompanion.ledger import decl as D
    lib = D.parse_line("0x5de460..0x5de480 libunit lib=mss32.lib tu=mss32lib -- the member", "decl/text.dcl", 188)
    srcs = [LY.SrcFn(0x5de460, "mss32lib", "MSS_auto_cleanup", "src:src/mss32lib/f_5de460.c:1"),
            LY.SrcFn(0x5de470, "mss32lib", "mss_AutoCleanupExit", "src:src/mss32lib/f_5de470.c:1"),
            LY.SrcFn(0x5de490, "mss32lib", "beyond", "src:src/mss32lib/f_5de490.c:1")]
    issues = LY.outside_unit_issues([], srcs, set(), (0x401000, 0x5dd3e0), {"mss32lib": lib})
    assert [(i.check, i.lo) for i in issues] == [("L14", 0x5de490)]
    assert "outside its declared member range 0x5de460..0x5de480" in issues[0].message
    inside = D.parse_line("0x401000..0x401010 libunit lib=x.lib tu=wrong -- inside the game code", "decl/text.dcl", 1)
    issues = LY.outside_unit_issues([], [], set(), (0x401000, 0x5dd3e0), {"wrong": inside})
    assert [i.check for i in issues] == ["L14"] and "inside the game code" in issues[0].message


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


def test_library_order_from_the_image():
    """The link orders libraries as the image shows: per section, the first contributions follow one another
    (placed members, import thunks, library units); unconstrained libraries keep their given place."""
    from types import SimpleNamespace as NS
    from decompanion.ledger.fact import Kind
    text, rdata = NS(name=".text"), NS(name=".rdata")
    units = [NS(lo=0x5de4a0, value={"tu": "lib:LIBC.LIB/a.obj", "lib": "LIBC.LIB"}),
             NS(lo=0x5dd3e0, value={"tu": "lib:DINPUT.LIB/b.obj", "lib": "DINPUT.LIB"}),
             NS(lo=0x5eef50, value={"tu": "lib:LIBC.LIB/c.obj", "lib": "LIBC.LIB"}),
             NS(lo=0x5eeee0, value={"tu": "lib:STRMIIDS.LIB/d.obj", "lib": "STRMIIDS.LIB"})]
    names = [NS(lo=0x5de486, value={"name": "thunk:DDRAW.dll!DirectDrawCreate", "origin": "import"})]
    store = NS(facts=lambda kind: units if kind is Kind.unit else names)
    image = NS(section_of=lambda a: text if a < 0x5eb000 else rdata)
    tc = NS(import_library_name=lambda dll: dll.lower().rsplit(".", 1)[0] + ".lib")
    lib = NS(lo=0x5de460, keys={"lib": "mss32.lib"})
    project = NS(store=store, image=image, toolchain=tc)
    libs = [Path("C:/x/LIBC.LIB"), Path("C:/x/DINPUT.LIB"), Path("C:/x/STRMIIDS.LIB"), Path("b/ddraw.lib"),
            Path("b/gdi32.lib"), Path("b/mss32.lib")]
    out, chains = L.library_order(project, libs, {"mss32lib": lib})
    assert [p.name.lower() for p in out] == ["dinput.lib", "strmiids.lib", "gdi32.lib", "mss32.lib", "ddraw.lib", "libc.lib"]
    assert ".text: dinput.lib < mss32.lib < ddraw.lib < libc.lib" in chains


# ------------------------------------------------------------------------------------------------ dcp headers conflicts
@pytest.mark.skipif(not Path("C:/Program Files/LLVM/bin/clang.exe").exists(), reason="clang not installed")
def test_headers_conflicts(tiny):
    write(tiny, "include/net.h", "extern int counter;\nextern short width;\nint add2(int a, int b);\n")
    write(tiny, "src/net/head.c", "extern int counter;  /* the same as net.h */\nextern char width;\n")
    write(tiny, "src/net/f_10001030.c",
          "/* 0x10001030, logs hello */\nvoid log_hello(void)\n{\n    add2(1);\n    other(2);\n}\n")
    code, out = dcp(tiny, "headers", "conflicts", "net", "net")
    assert code == 1, out
    assert "supersedes=1  call=1" in out and "duplicate=1" in out, out
    assert "kind=supersedes  name=width  at=src/net/head.c:2  header=include/net.h:2" in out, out
    assert "kind=duplicate  name=counter  at=src/net/head.c:1" in out, out
    assert "kind=call  name=add2  at=src/net/f_10001030.c:4" in out and "too few arguments" in out, out
    assert "fn=0x10001030" in out, out                     # the function to re-grade
    code, out = dcp(tiny, "headers", "conflicts", "net", "net", "--write")
    assert code == 1 and "write=refused" in out, out
    assert "extern char width;" in (tiny / "src/net/head.c").read_text()

    write(tiny, "src/net/head.c", "extern int counter;  /* the same as net.h */\n")
    write(tiny, "src/net/f_10001030.c", "/* 0x10001030, logs hello */\nvoid log_hello(void)\n{\n    add2(1, 2);\n}\n")
    code, out = dcp(tiny, "headers", "conflicts", "net", "net.h", "--write")
    assert code == 0 and "dropped=1" in out, out
    head = (tiny / "src/net/head.c").read_text()
    assert '#include "net.h"' in head and "extern int counter" not in head and "trial" not in head, head
