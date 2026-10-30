"""The match phase on the synthetic dll: the amalgamation, the compare, the hunk classes and the grade verdict
on hand-made instruction lists, the queues, the baseline (M1), the level ladder; with VC6 installed: compile
and byte match on the synthetic image, the include-set cache."""
import struct
from pathlib import Path

import pytest

from conftest import dcp

from decompanion import isa as isa_plugins
from decompanion.build import amalg as A
from decompanion.config import Project
from decompanion.isa.base import Line
from decompanion.ledger import grades as G
from decompanion.ledger import srcscan
from decompanion.ledger.fact import Fact, Kind, Level
from decompanion.ledger.store import Store
from decompanion.match import compare as C
from decompanion.match import diffclass as DC
from decompanion.objfmt.base import FunctionCode
from decompanion.objfmt.coff import DIR32, Reloc
from decompanion.rules.grade import falls, parse_baseline

VC6 = Path("C:/Tools/MSVC600-SP5PP")
needs_vc6 = pytest.mark.skipif(not (VC6 / "VC98" / "Bin" / "CL.EXE").exists(), reason="VC6 not installed")


def write(root: Path, rel: str, text: str):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, newline="\n")


def with_vc6(root: Path):
    cfg = root / "decompanion.toml"
    cfg.write_text(cfg.read_text().replace('root = "C:/nowhere/vc6"\n', f'root = "{VC6.as_posix()}"\n', 1), newline="\n")


# ------------------------------------------------------------------------------------------------ amalgamation
def test_amalgamation_order_and_lines(tiny):
    write(tiny, "src/net/head.c", "int counter = 1;  /* 0x10002000 */\n")
    write(tiny, "src/net/f_10001030.c", "/* 0x10001030, logs */\nvoid log3(void)\n{\n}\n")
    write(tiny, "src/net/f_10001020.c", "/* 0x10001020, reads */\nint get(void)\n{\n    return counter;\n}\n")
    write(tiny, "src/net/u_spare.c", "/* unlinked, dropped by /OPT:REF */\nvoid spare(void)\n{\n}\n")
    write(tiny, "src/net/tail.c", "int last = 2;\n")
    p = Project(tiny)
    sc = srcscan.scan(tiny)
    (a,) = A.units(tiny, sc, "tiny", "tiny")
    assert [m.file.rsplit("/", 1)[1] for m in a.members] == ["head.c", "f_10001020.c", "f_10001030.c", "u_spare.c", "tail.c"]
    assert [m.role for m in a.members] == ["head", "fragment", "fragment", "unlinked", "tail"]
    assert a.text.startswith('#line 1 "src/net/head.c"\nint counter = 1;')
    assert '#line 1 "src/net/f_10001020.c"\n/* 0x10001020, reads */' in a.text
    assert a.text.index("f_10001020.c") < a.text.index("f_10001030.c") < a.text.index("u_spare.c") < a.text.index("tail.c")
    assert a.first_addr == 0x10001020 and a.path == "build/amalg/tiny/net.c"
    assert dcp(tiny, "unit", "cat", "net")[1] == a.text
    assert not [e for e in sc.errors if "tail.c" in e.file]          # tail.c is a unit file


def test_amalgamation_targets(tiny2):
    write(tiny2, "src/net/f_10001020.c", "/* 0x10001020, other:0x10001020, both */\nint get(void)\n{\n    return 1;\n}\n")
    write(tiny2, "src/net/f_10001030.c", "/* other:0x10001030, only the second target */\nvoid only(void)\n{\n}\n")
    write(tiny2, "src/net/f_10001050.c", "/* 0x10001050, only the default target */\nvoid first(void)\n{\n}\n")
    write(tiny2, "src/lone/f_10001040.c", "/* other:0x10001040, a unit of the second target only */\nvoid lone(void)\n{\n}\n")
    sc = srcscan.scan(tiny2)
    t = {a.unit: [m.name for m in a.fragments] for a in A.units(tiny2, sc, "tiny", "tiny")}
    o = {a.unit: [m.name for m in a.fragments] for a in A.units(tiny2, sc, "other", "tiny")}
    assert t == {"net": ["get", "first"]}
    assert o == {"lone": ["lone"], "net": ["get", "only"]}


# ------------------------------------------------------------------------------------------------ compare
class Img:
    """A stand-in image: `code` at 0x1000, base relocations at `relocs`."""
    base, end = 0x1000, 0x3000

    def __init__(self, code, relocs=()):
        self.code, self._relocs = code, list(relocs)

    def read(self, va, n):
        o = va - 0x1000
        return (self.code[o:o + n] + bytes(n))[:n]

    def relocations(self):
        return self._relocs


def fcode(data, relocs=()):
    mask = bytearray(len(data))
    rs = []
    for off in relocs:
        for k in range(off, off + 4):
            mask[k] = 1
        rs.append((off, Reloc(off, 0, DIR32), None))
    return FunctionCode(None, None, 0, data, bytes(mask), tuple(rs))


FILL = (b"\x90", b"\xcc")


def test_compare_masked_and_aid():
    orig = b"\xa1\x00\x20\x00\x00\xc3" + b"\x90" * 10 + b"\x55"      # mov eax,[0x2000]; ret; fill; next function
    ours = fcode(b"\xa1\x00\x00\x00\x00\xc3", relocs=[1])
    c = C.compare(Img(orig, [0x1001]), ours, 0x1000, [0x1001], 0x1010, FILL)
    assert c.bytes_equal and c.tail_ok and c.aid == "1/1" and c.matched
    # a relocated field of ours where the original has a plain number: the aid fails
    c = C.compare(Img(orig, []), ours, 0x1000, [], 0x1010, FILL)
    assert c.bytes_equal and not c.aid_ok and c.aid == "1/0" and not c.matched and "no base relocation" in c.why()
    # the original continues after our end: no match although the prefix is equal
    c = C.compare(Img(b"\xa1\x00\x20\x00\x00\xc3\x40\xc3"), ours, 0x1000, None, 0x1010, FILL)
    assert c.bytes_equal and not c.tail_ok and not c.matched and c.aid == "-"
    # one differing byte
    c = C.compare(Img(orig, [0x1001]), fcode(b"\xa1\x00\x00\x00\x00\xc2", relocs=[1]), 0x1000, [0x1001], 0x1010, FILL)
    assert c.diffs == [5] and not c.matched


def test_aligned_sites():
    x86 = isa_plugins.get("x86")
    ours = b"\x55\x8b\xec\xe8\x00\x00\x00\x00\x5d\xc3"           # push ebp; mov ebp,esp; call f; pop ebp; ret
    mask = bytes([0, 0, 0, 0, 1, 1, 1, 1, 0, 0])
    site = [(4, 4)]

    def cmp(orig):
        c = C.Compared(0x1000, len(ours), ours, mask, orig)
        c.diffs = [k for k in range(len(ours)) if not mask[k] and ours[k] != orig[k]]
        return c

    # a draft whose call sits where the original's does: the site lines up although the function differs
    assert C.aligned_sites(x86, cmp(b"\x55\x8b\xec\xe8\x10\x00\x00\x00\x5e\xc3"), site) == {4}
    # one more instruction before the call (push ecx): the original's bytes at our site are no call target
    assert C.aligned_sites(x86, cmp(b"\x55\x8b\xec\x51\xe8\x10\x00\x00\x00\xc3"), site) == set()
    # the same size and offset but another instruction (mov eax, imm32): no line-up either
    assert C.aligned_sites(x86, cmp(b"\x55\x8b\xec\xb8\x10\x00\x00\x00\x5d\xc3"), site) == set()
    # a match lines up everywhere
    assert C.aligned_sites(x86, cmp(b"\x55\x8b\xec\xe8\x10\x00\x00\x00\x5d\xc3"), site) == {4}


# ------------------------------------------------------------------------------------------------ diffclass
def lines(*texts):
    return [Line(0x1000 + k, 1, t, t in ("nop", "int3")) for k, t in enumerate(texts)]


def test_hunk_classes():
    x86 = isa_plugins.get("x86")
    a = lines("push esi", "mov esi, dword ptr [esp + 8]", "mov eax, esi", "pop esi", "ret")
    b = lines("push edi", "mov edi, dword ptr [esp + 8]", "mov eax, edi", "pop edi", "ret")
    hs = DC.classify_hunks(a, b, x86)
    assert [h[4] for h in hs] == ["regs"] and "esi->edi" in hs[0][5]
    assert DC.verdict(a, b, x86).shape
    a = lines("mov eax, 1", "mov ecx, 2", "ret")
    b = lines("mov ecx, 2", "mov eax, 1", "ret")
    assert [h[4] for h in DC.classify_hunks(a, b, x86)] == ["order"]
    a = lines("mov eax, dword ptr [esp + 4]", "mov ecx, dword ptr [esp + 8]", "ret")
    b = lines("mov eax, dword ptr [esp + 8]", "mov ecx, dword ptr [esp + 4]", "ret")
    assert [h[4] for h in DC.classify_hunks(a, b, x86)] in (["slots"], ["regs"])
    a = lines("mov eax, dword ptr [ecx + edx + 4]", "mov ebx, dword ptr [ecx + esi]", "ret")
    b = lines("mov eax, dword ptr [edx + ecx + 4]", "mov ebx, dword ptr [esi + ecx]", "ret")
    assert [h[4] for h in DC.classify_hunks(a, b, x86)] == ["sib"]     # no one register renaming explains both
    a = lines("mov eax, 1", "ret")
    b = lines("mov eax, 2", "ret")
    v = DC.verdict(a, b, x86)
    assert [h[4] for h in DC.classify_hunks(a, b, x86)] == ["code"] and not v.shape and v.distance == 2
    a = lines("ret", "nop", "nop")
    b = lines("ret", "int3")
    assert DC.verdict(a, b, x86).hunks.get("fill") == 3


def test_listing_masks_relocated_fields():
    x86 = isa_plugins.get("x86")
    code = b"\xa1\x00\x00\x00\x00" + b"\xe8\x00\x00\x00\x00" + b"\xc3"        # mov eax,[reloc]; call reloc; ret
    mask = bytes([0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0])
    ours = x86.listing(code, 0x10001000, mask, (0x10000000, 0x10010000), FILL)
    orig = x86.listing(b"\xa1\x00\x20\x00\x10\xe8\x10\x00\x00\x00\xc3", 0x10001000, None, (0x10000000, 0x10010000), FILL)
    assert [l.text for l in ours] == [l.text for l in orig] == ["mov eax, dword ptr [X]", "call X", "ret"]


# ------------------------------------------------------------------------------------------------ queues
def grade_store(tmp_path, units, funcs):
    """A store holding unit facts (L.unit.extent) and function grade facts (G.grade)."""
    st = Store(tmp_path / "s.sqlite")
    uf = [Fact(lo, hi, Kind.unit, {"tu": tu, "status": status, "start_level": "declared", "end_level": "declared",
                                   "start_by": "x", "end_by": "y"}, Level.declared, "rule:L.unit.extent@1") for tu, lo, hi, status in units]
    gf = [Fact(a, a + 1, Kind.grade, {"of": "function", "name": n, "unit": u, "file": f"src/{u}/f_{a:x}.c", "code": code,
                                      "readability": q, "level": lvl, "failing": [], "dist": {"ins": d, "bytes": d, "size": 1, "orig": 1}},
               Level.declared, "rule:G.grade@1") for a, n, u, code, q, lvl, d in funcs]
    st.record_run("L.unit.extent", "1", "c", "i1", uf, [], 0)
    st.record_run("G.grade", "1", "c", "i2", gf, [], 0)
    return st


def test_queue_order(tmp_path):
    st = grade_store(tmp_path, [("a", 0x1000, 0x2000, "separated"), ("b", 0x2000, 0x3000, "separated"),
                                ("c", 0x3000, 0x4000, "separated"), ("open", 0x4000, 0x5000, "open")], [
        (0x1000, "a1", "a", "draft", "draft", "", 9), (0x1100, "a2", "a", "draft", "readable", "", 3),
        (0x1200, "a3", "a", "shape", "draft", "", 2),
        (0x2000, "b1", "b", "draft", "draft", "", 50), (0x2100, "b2", "b", "byte", "readable", "", 0),
        (0x3000, "c1", "c", "shape", "readable", "", 7), (0x3100, "c2", "c", "byte", "draft", "deep", 0),
        (0x3200, "c3", "c", "draft", "draft", "stuck", 4),
        (0x4000, "o1", "open", "draft", "draft", "", 1),
    ])
    base = [(r["name"], r["section"]) for r in G.queue(st, "base")]
    # every code draft first (unit b has 1 draft, a has 2), then the readability work; the open unit is left out
    assert base == [("b1", "draft"), ("a1", "draft"), ("a2", "draft"), ("a3", "read")]
    deep = [(r["name"], r["section"]) for r in G.queue(st, "deep")]
    # c has no base item left: its byte work (c1) first, the Q-only c2 waits, the stuck c3 last
    assert deep == [("c1", "deep"), ("c3", "stuck")]
    assert [r["name"] for r in G.queue(st, "names")] == ["c2"]
    owners = {G.shard_owner(lo, 2) for lo in (0x1000, 0x2000, 0x3000)}
    got = [r["name"] for k in range(2) for r in G.queue(st, "base", (k, 2))]
    assert sorted(got) == sorted(r["name"] for r in G.queue(st, "base")) and owners <= {0, 1}
    assert G.parse_shard("1/3") == (1, 3) and G.parse_shard("off") is None
    with pytest.raises(ValueError):
        G.parse_shard("3/3")


# ------------------------------------------------------------------------------------------------ baseline, ladder
def test_baseline_falls():
    text = G.HEADER + "\nt\t0x10001000\tf\tu\tbyte\treadable\t\nt\t0x10001010\tg\tu\tshape\tdraft\tdeep\n"
    b = parse_baseline(text)
    assert b[("t", 0x10001000)]["code"] == "byte" and b[("t", 0x10001010)]["level"] == "deep"
    assert falls(b[("t", 0x10001000)], {"code": "shape", "readability": "readable"}) == ["code byte -> shape"]
    assert falls(b[("t", 0x10001000)], {"code": "byte", "readability": "draft"}) == ["readability readable -> draft"]
    assert falls(b[("t", 0x10001010)], {"code": "byte", "readability": "draft"}) == []
    assert "no grade now" in falls(b[("t", 0x10001010)], None)[0]


def test_level_ladder(tmp_path):
    assert G.only_missing_statements("missing statements")
    assert G.only_missing_statements("the loop body is unwritten; two calls are missing")
    assert not G.only_missing_statements("register choice ebx/esi after the spell pass; missing statements")
    write(tmp_path, "src/u/f_10001000.c", "/* 0x10001000, does it */\nvoid f(void)\n{\n}\n")
    assert G.set_level(tmp_path, "src/u/f_10001000.c", "deep", "slot order after vargen") == "@deep added"
    assert (tmp_path / "src/u/f_10001000.c").read_text().startswith("/* 0x10001000, does it @deep slot order after vargen */\n")
    assert G.set_level(tmp_path, "src/u/f_10001000.c", "stuck", "every lead tried") == "@deep -> @stuck"
    fn = srcscan.scan(tmp_path).functions[0]
    assert fn.stuck == "every lead tried" and fn.deep is None and fn.what == "does it"
    assert G.set_level(tmp_path, "src/u/f_10001000.c", None, None) == "@stuck removed"
    assert (tmp_path / "src/u/f_10001000.c").read_text().startswith("/* 0x10001000, does it */\n")


# ------------------------------------------------------------------------------------------------ with VC6
@needs_vc6
def test_compile_and_byte_match(tiny):
    """f2 of the synthetic dll is `mov eax, [0x10002000]; ret`: `return counter;` compiles to it."""
    with_vc6(tiny)
    write(tiny, "decl/text.dcl", "# code\n0x10001020 boundary start tu=net by=tag -- f2 reads the counter\n"
                                 "0x10001030 boundary end tu=net -- f3 is another unit\n")
    write(tiny, "src/net/head.c", "int counter = 0x1234;  /* 0x10002000 */\n")
    write(tiny, "src/net/f_10001020.c", "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return counter;\n}\n")
    code, out = dcp(tiny, "build")
    assert code == 0, out
    assert "compiled=1" in out and "grades: byte+readable=1" in out
    sym = [f for f in Project(tiny).store.facts(Kind.symbol) if f.run == "M.match"]
    assert [(f.lo, f.hi, f.level, f.value["relocs"]) for f in sym] == [(0x10001020, 0x10001026, Level.proven, "1/1")]
    code, out = dcp(tiny, "build")                         # nothing changed: nothing compiles, no rule runs
    assert "compiled=0" in out
    code, out = dcp(tiny, "grade", "get")
    assert "code=byte" in out and "readability=readable" in out
    # a draft: another constant
    write(tiny, "src/net/f_10001020.c", "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return counter + 1;\n}\n")
    code, out = dcp(tiny, "grade", "get")
    assert "code=draft" in out and "B3 draft" in out
    code, out = dcp(tiny, "diffclass", "get")
    assert "code" in out
    # a compile error names the fragment and fails the gate
    write(tiny, "src/net/f_10001020.c", "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return nothing;\n}\n")
    code, out = dcp(tiny, "build")
    assert code == 1 and "src/net/f_10001020.c(4)" in out and "C2065" in out
    code, out = dcp(tiny, "check")
    assert code == 1 and "M.compile" in out


@needs_vc6
def test_header_edit_recompiles_only_includers(tiny):
    with_vc6(tiny)
    write(tiny, "include/net.h", "extern int counter;\n")
    write(tiny, "src/net/head.c", '#include "net.h"\nint counter = 0x1234;  /* 0x10002000 */\n')
    write(tiny, "src/net/f_10001020.c", "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return counter;\n}\n")
    write(tiny, "src/log/f_10001030.c", "/* 0x10001030, logs */\nvoid log3(void)\n{\n}\n")
    code, out = dcp(tiny, "build")
    assert "compiled=2" in out, out
    write(tiny, "include/net.h", "extern int counter;  /* edited */\n")
    code, out = dcp(tiny, "build")
    assert "compiled=1" in out and "ok   net" in out and "ok   log" not in out, out
    write(tiny, "src/net/head.c", '#include "net.h"\n/* a comment */\nint counter = 0x1234;  /* 0x10002000 */\n')
    code, out = dcp(tiny, "build")
    assert "compiled=1" in out and "ok   net" in out, out
    assert "compiled=0" in dcp(tiny, "build")[1]


CLANG = Path("C:/Program Files/LLVM/bin/clang.exe")


@needs_vc6
@pytest.mark.skipif(not CLANG.exists(), reason="clang not installed")
def test_lint_q7_and_exemption(tiny):
    with_vc6(tiny)
    write(tiny, "src/net/head.c", "int counter = 0x1234;  /* 0x10002000 */\nint helper();\n")
    write(tiny, "src/net/f_10001020.c", "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return counter + helper(1.5f);\n}\n")
    code, out = dcp(tiny, "lint")
    assert code == 0 and "m7=1" in out and "helper() at line 4" in out, out
    code, out = dcp(tiny, "grade", "get")
    assert "Q7 prototypes: helper() at line 4" in out and "readability=draft" in out
    write(tiny, "src/net/f_10001020.c", "/* 0x10001020, reads the counter */\nint get(void)\n{\n"
                                        "    return counter + helper(1.5f);  /* @original the original passes a double */\n}\n")
    code, out = dcp(tiny, "lint")
    assert "m7=0" in out, out
    # a conflict across units: two prototypes of one function
    write(tiny, "src/log/f_10001030.c", "/* 0x10001030, logs */\nlong helper(int x);\nvoid log3(void)\n{\n}\n")
    code, out = dcp(tiny, "lint")
    assert code == 1 and "m5=1" in out and "M5" in out, out


@needs_vc6
@pytest.mark.skipif(not CLANG.exists(), reason="clang not installed")
def test_lint_m5_between_headers(tiny):
    with_vc6(tiny)
    write(tiny, "include/a.h", "typedef struct BITS { int x; } BITS;\nint f(char *p);  /* @original a.c's spelling */\n")
    write(tiny, "include/b.h", "typedef struct BITS { short x; } BITS;\nint f(void *p);\n")
    code, out = dcp(tiny, "lint")
    assert code == 1, out
    m5 = [l for l in out.splitlines() if "M5" in l or "include/" in l]
    assert any("redefinition of 'BITS'" in l for l in m5), out                       # a tag two headers define
    assert any("conflicting types for 'f'" in l and "cannot be included together" in l for l in m5), out
    write(tiny, "include/b.h", "int g(void);\n")                                     # one definition, one spelling
    code, out = dcp(tiny, "lint")
    assert "m5=0" in out, out
    # a header private to one unit may define a tag another header defines too; another unit may not include it
    write(tiny, "include/a.h", "/* @private net */\ntypedef struct BITS { int x; } BITS;\n")
    write(tiny, "include/b.h", "typedef struct BITS { short x; } BITS;\n")
    write(tiny, "src/net/head.c", '#include "a.h"\nint counter = 0x1234;  /* 0x10002000 */\nint helper();\n')
    code, out = dcp(tiny, "lint")
    assert "m5=0" in out, out
    write(tiny, "src/log/head.c", '#include "a.h"\n')
    code, out = dcp(tiny, "lint")
    assert "m5=1" in out and "src/log/head.c:1: includes a.h, private to net" in out, out


@needs_vc6
@pytest.mark.skipif(not CLANG.exists(), reason="clang not installed")
def test_lint_m5_per_symbol(tiny):
    """M5 against the definition, one line per symbol: a.h comes first and disagrees, b.h agrees with the
    definition (clang alone would blame b.h); data from the sources too (a unit's GAPDATA view); a K&R
    definition does not swallow what follows it; a header that does not compile is its own M5."""
    with_vc6(tiny)
    write(tiny, "src/net/head.c", "int counter = 0x1234;  /* 0x10002000 */\n")
    write(tiny, "src/net/f_10001020.c", "/* 0x10001020, reads */\nint get(void)\n{\n    return counter;\n}\n")
    write(tiny, "src/log/f_10001030.c", "/* 0x10001030, logs */\nint log3(a)\nint a;\n{\n    return a;\n}\n")
    write(tiny, "src/log/head.c", "#define GAPDATA __declspec(align(1)) unsigned char\nextern GAPDATA counter[];\n"
                                  "int get();\nint log3(int a);\n")
    write(tiny, "include/a.h", "long get(void);\n")
    write(tiny, "include/b.h", "int get(void);\nextern int counter;\n")
    code, out = dcp(tiny, "lint")
    assert code == 1, out
    m5 = [l for l in out.splitlines() if l.startswith("  M5 ")]
    assert len(m5) == 2, out
    get = next(l for l in m5 if " get declared unlike its definition" in l)
    assert get.startswith("  M5 include/a.h:1: get declared unlike its definition src/net/f_10001020.c:2 (unit net) `int get(void)`"), get
    assert "disagree=1 `long get(void)` at include/a.h:1; agree=2 include/b.h:1, src/log/head.c:3" in get, get
    cnt = next(l for l in m5 if "counter" in l)
    assert "disagree=1 `GAPDATA counter[]` at src/log/head.c:2; agree=1 include/b.h:2" in cnt, cnt
    # the header spelling marked @original: the hint names the definition and the cast macro of a unit's view
    write(tiny, "include/a.h", "long get(void);  /* @original why */\n")
    code, out = dcp(tiny, "lint")
    assert "the @original spelling is in a header (include/a.h:1): a header repeats the definition's spelling " \
           "`int get(void);` (unit net); a unit's own view goes in its head.c as a cast macro: " \
           "`#define get_X ((long (*)(void))get) /* @original why */`" in out, out
    # in a unit's own declaration the exemption holds
    write(tiny, "include/a.h", "int get(void);\n")
    write(tiny, "src/log/head.c", "extern int counter;\nlong get(void);  /* @original why */\nint log3(int a);\n")
    code, out = dcp(tiny, "lint")
    assert "m5=0" in out, out
    # a K&R definition and the prototype after it: a disagreeing one is seen
    write(tiny, "src/log/head.c", "extern int counter;\nint log3(char *a);\n")
    code, out = dcp(tiny, "lint")
    assert "m5=1" in out and "log3 declared unlike its definition src/log/f_10001030.c:2" in out \
           and "`int log3(a) int a;` (as a prototype `int log3(int a)`)" in out, out
    # a header that does not compile in the all-declarations unit
    write(tiny, "src/log/head.c", "extern int counter;\n")
    write(tiny, "include/c.h", "NOSUCHTYPE *mk(void);\n")
    code, out = dcp(tiny, "lint")
    assert "m5=1" in out and "include/c.h:1: include/c.h does not compile in the all-declarations unit (1 errors, " \
                             "first: unknown type name 'NOSUCHTYPE')" in out, out
    # a rename macro (`#define get get_ag`) makes the header declare get_ag, not get
    write(tiny, "include/c.h", "#define get get_ag\nlong get(void);\n#undef get\n")
    code, out = dcp(tiny, "lint")
    assert "m5=0" in out, out


def test_lint_alldecls_scan():
    from decompanion.source import lint as L
    ds = L.file_scope_decls("src/u/head.c", "int a = 1, *b;\nstatic int c;\nextern struct S s[];\ntypedef int T;\n"
                            "static int f(void) { return 0; }\nint g(x) int x; { return x; }\nint h(void);\n"
                            "struct Q { int q; };\nchar *k(char *s)\n{\n    return s;\n}\n")
    assert [(d.kind, d.name, d.stmt) for d in ds] == [
        ("ddef", "a", "extern int a;"), ("ddef", "b", "extern int *b;"), ("extern", "s", "extern struct S s[];"),
        ("knr", "g", "int g(x) int x; {}"), ("proto", "h", "int h(void);"), ("fdef", "k", "char *k(char *s);")]
    assert all(d.stmt[d.at:d.at + len(d.name)] == d.name for d in ds)
    # a K&R definition compares as its default-promoted prototype (`int f()` and `int f(int, int)` agree with it)
    (d,) = L.file_scope_decls("src/u/f.c", "int f(x, y, p, q) short x; unsigned char y; float p; char *q;\n{\n}\n")
    assert d.kind == "knr" and d.proto == "int f(int x, int y, double p, char *q);"


@needs_vc6
def test_q4_view_forms(tiny):
    """Q4: `(*(T *)datum)` reads through the datum's value (raw), `(*(T *)&datum)` with its address comment is a
    view; the message states the accepted form."""
    with_vc6(tiny)
    write(tiny, "src/net/head.c", "char *counter = 0;  /* 0x10002000 */\n"
                                  "#define COUNT_RAW (*(int *)counter)\n#define COUNT (*(int *)&counter)  /* 0x10002000 */\n")
    write(tiny, "src/net/f_10001020.c", "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return COUNT_RAW;\n}\n")
    code, out = dcp(tiny, "grade", "get")
    assert "Q4 raw access: macro COUNT_RAW (" in out and "`#define NAME (*(T *)&datum)  /* 0xADDR */`" in out \
           and "`(*(T *)datum)` reads through the datum's value and stays raw" in out, out
    write(tiny, "src/net/f_10001020.c", "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return COUNT;\n}\n")
    code, out = dcp(tiny, "grade", "get")
    assert "Q4" not in out, out


@needs_vc6
def test_auto_clear_and_data_order(tiny):
    with_vc6(tiny)
    write(tiny, "src/net/head.c", "int pad = 7;  /* 0x10002004 */\nint counter = 0x1234;  /* 0x10002000 */\n")
    write(tiny, "src/net/f_10001020.c", "/* 0x10001020, reads the counter @deep register choice after the spell pass */\n"
                                        "int get(void)\n{\n    return counter;\n}\n")
    code, out = dcp(tiny, "build")
    assert "auto-clear src/net/f_10001020.c: get is byte + readable, @deep removed" in out, out
    assert (tiny / "src/net/f_10001020.c").read_text().startswith("/* 0x10001020, reads the counter */\n")
    code, out = dcp(tiny, "conflicts")
    assert "D4" in out and "counter (0x10002000) is defined after pad (0x10002004)" in out, out
    syms = {f.lo: f.value["extent"] for f in Project(tiny).store.facts(Kind.symbol) if f.run.startswith("M.data")}
    assert syms[0x10002000] == "site" and syms[0x10002004] == "draft"
