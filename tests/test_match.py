"""The match phase on the synthetic dll: the translation units, the compare, the hunk classes and the grade verdict
on hand-made instruction lists, the queues, the baseline (M1), the level ladder; with VC6 installed: compile
and byte match on the synthetic image, the include-set cache."""
import struct
from pathlib import Path

import pytest

from conftest import dcp, unit

from decompanion import isa as isa_plugins
from decompanion.build import tu as T
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
from decompanion.source import cparse

VC6 = Path("C:/Tools/MSVC600-SP5PP")
needs_vc6 = pytest.mark.skipif(not (VC6 / "VC98" / "Bin" / "CL.EXE").exists(), reason="VC6 not installed")


def write(root: Path, rel: str, text: str):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, newline="\n")


def with_vc6(root: Path):
    cfg = root / "decompanion.toml"
    cfg.write_text(cfg.read_text().replace('root = "C:/nowhere/vc6"\n', f'root = "{VC6.as_posix()}"\n', 1), newline="\n")


# ------------------------------------------------------------------------------------------------ translation units
def test_unit_file_order_and_fn(tiny):
    unit(tiny, "net", "int counter = 1;  /* 0x10002000 */\n",
         "/* 0x10001030, logs */\nvoid log3(void)\n{\n}\n",
         "/* 0x10001020, reads */\nint get(void)\n{\n    return counter;\n}\n",
         "/* unlinked, dropped by /OPT:REF */\nvoid spare(void)\n{\n}\n", "int last = 2;\n")
    sc = srcscan.scan(tiny)
    assert not sc.errors, sc.errors
    (a,) = T.units(tiny, sc, "tiny", "tiny")
    assert a.functions == [(0x10001030, "log3"), (0x10001020, "get"), (None, "spare")]      # the text's order
    assert a.first_addr == 0x10001020 and a.path == a.file == "src/net.c"
    get = next(f for f in sc.functions if f.name == "get")
    assert (get.comment_line, get.line, get.end_line) == (8, 9, 12)
    code, out = dcp(tiny, "fn", "0x10001020")
    assert code == 0 and "at=src/net.c:8-12" in out and out.endswith("/* 0x10001020, reads */\nint get(void)\n{\n    return counter;\n}\n"), out
    # a definition without its address comment directly above it
    unit(tiny, "net", "/* 0x10001020, reads */\nint x;\nint get(void)\n{\n    return 1;\n}\n")
    errs = [e for e in srcscan.scan(tiny).errors if e.check == "L.src"]
    assert len(errs) == 1 and "get: no address comment" in errs[0].message and errs[0].line == 3, errs
    unit(tiny, "net", "/* 0x10001020, reads */\nint get(void)\n{\n    return 1;\n}\n")
    (tiny / "src" / "old").mkdir()
    (tiny / "src" / "old" / "f_10001020.c").write_text("int y;\n")
    errs = [e for e in srcscan.scan(tiny).errors if e.check == "L.src"]
    assert len(errs) == 1 and "unexpected source file src/old/f_10001020.c" in errs[0].message, errs


def test_unit_targets(tiny2):
    unit(tiny2, "net", "/* 0x10001020, other:0x10001020, both */\nint get(void)\n{\n    return 1;\n}\n",
         "#if defined(DCP_TARGET_other)\n/* other:0x10001030, only the second target */\nvoid only(void)\n{\n}\n#endif\n",
         "#ifdef DCP_TARGET_tiny\n/* 0x10001050, only the default target */\nvoid first(void)\n{\n}\n#endif\n")
    unit(tiny2, "lone", "#ifdef DCP_TARGET_other\n/* other:0x10001040, a unit of the second target only */\n"
                        "void lone(void)\n{\n}\n#endif\n")
    sc = srcscan.scan(tiny2)
    assert not sc.errors, sc.errors
    t = {a.unit: [n for _, n in a.functions] for a in T.units(tiny2, sc, "tiny", "tiny")}
    o = {a.unit: [n for _, n in a.functions] for a in T.units(tiny2, sc, "other", "tiny")}
    assert t == {"net": ["get", "first"]}
    assert o == {"lone": ["lone"], "net": ["get", "only"]}
    # L16: a function the guard and the comment disagree on
    unit(tiny2, "lone", "/* other:0x10001040, unguarded */\nvoid lone(void)\n{\n}\n")
    errs = [e for e in srcscan.scan(tiny2).errors if e.check == "L16"]
    assert len(errs) == 1 and "lone is compiled into tiny" in errs[0].message and "DCP_TARGET_other" in errs[0].message, errs
    unit(tiny2, "lone", "#ifdef DCP_TARGET_tiny\n/* other:0x10001040, the wrong guard */\nvoid lone(void)\n{\n}\n#endif\n")
    msgs = sorted(e.message for e in srcscan.scan(tiny2).errors if e.check == "L16")
    assert len(msgs) == 2 and "lists other, whose compile does not hold it" in msgs[1], msgs


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
    """Native (native/dcp_core rules.rs aligned_sites, what M8.reloc reads)."""
    from decompanion import native
    from decompanion.rules.engine import capstone_dll
    ours = b"\x55\x8b\xec\xe8\x00\x00\x00\x00\x5d\xc3"           # push ebp; mov ebp,esp; call f; pop ebp; ret
    mask = bytes([0, 0, 0, 0, 1, 1, 1, 1, 0, 0])
    site = [(4, 4)]

    def aligned(orig):
        matched = all(mask[k] or ours[k] == orig[k] for k in range(len(ours)))
        return native.core().aligned_sites(capstone_dll(), ours, mask, orig, 0x1000, matched, site)

    # a draft whose call sits where the original's does: the site lines up although the function differs
    assert aligned(b"\x55\x8b\xec\xe8\x10\x00\x00\x00\x5e\xc3") == {4}
    # one more instruction before the call (push ecx): the original's bytes at our site are no call target
    assert aligned(b"\x55\x8b\xec\x51\xe8\x10\x00\x00\x00\xc3") == set()
    # the same size and offset but another instruction (mov eax, imm32): no line-up either
    assert aligned(b"\x55\x8b\xec\xb8\x10\x00\x00\x00\x5d\xc3") == set()
    # a match lines up everywhere
    assert aligned(b"\x55\x8b\xec\xe8\x10\x00\x00\x00\x5d\xc3") == {4}


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


def test_frame_class():
    """Frames of another size (one slot more or less) shift every stack offset above it: the frame-aligned diff
    classes those lines `frame` (by 0 or the frame delta, the frame sizes by exactly the delta) and leaves the
    real differences in hunks of their own; a function the plain diff explains keeps its verdict."""
    x86 = isa_plugins.get("x86")
    body = ["sub esp, {f}", "mov eax, dword ptr [esp + {arg}]", "mov dword ptr [esp + 0x10], eax", "mov ecx, 3",
            "mov edx, 4", "lea ecx, [esp + {loc}]", "push ecx", "call X", "{st}", "add esp, {f}", "ret"]

    def fn(f, arg, loc, st="mov dword ptr [esp + 0x14], ecx"):
        return lines(*(t.format(f=f, arg=arg, loc=loc, st=st) for t in body))
    a, b = fn("0xcc", "0xd0", "0x7c"), fn("0xc8", "0xcc", "0x78")
    assert not DC.judge(a, b, x86, DC.classify_hunks(a, b, x86)).shape        # the plain diff: code
    hs, v = DC.analyse(a, b, x86)
    assert v.shape and v.frame == [0xcc, 0xc8] and {h[4] for h in hs} == {"frame"}, hs
    assert "shifted by 0x4 (frame 0xcc vs 0xc8)" in hs[0][5] and "frame 0xcc vs 0xc8" in v.summary()
    # one real difference: a code hunk of its own, the shifted lines stay frame
    hs, v = DC.analyse(a, fn("0xc8", "0xcc", "0x78", st="mov dword ptr [esp + 0x14], 0"), x86)
    assert not v.shape and {h[4] for h in hs} == {"frame", "code"}
    assert [(h[0], h[1]) for h in hs if h[4] == "code"] == [(8, 9)]
    # a shift other than the frame delta is no frame
    hs, v = DC.analyse(a, fn("0xc8", "0xc4", "0x78"), x86)
    assert not v.shape and "code" in {h[4] for h in hs}
    # the same frame size: no frame-aligned diff (a plain slot renaming stays `slots`)
    hs, v = DC.analyse(fn("0xcc", "0xd0", "0x7c"), fn("0xcc", "0xd4", "0x7c"), x86)
    assert v.frame is None


def switch_fn(entries=(0x1010, 0x1016, 0x101C)):
    """A switch at 0x1000 of the stand-in image: three cases and a default, the 3-entry jump table at 0x1028
    after three bytes of fill, int3 up to the next function at 0x1040."""
    code = bytes.fromhex("8b442404" "83f802" "7719" "ff2485") + struct.pack("<I", 0x1028)
    code += bytes.fromhex("b801000000c3" "b802000000c3" "b803000000c3" "33c0c3")
    code += bytes.fromhex("90") * (0x28 - len(code))
    return code + b"".join(struct.pack("<I", e) for e in entries) + bytes.fromhex("cc") * 0xc


def switch_ours():
    """Our compiled switch: the same code, the table after the $L label at 0x28 (entries relocated to the
    section, the target offset as the addend in place)."""
    from decompanion.objfmt.coff import Section, Symbol
    data = bytearray(switch_fn()[:0x34])
    data[0x0c:0x10] = struct.pack("<I", 0x28)
    for k, off in enumerate((0x10, 0x16, 0x1c)):
        data[0x28 + 4 * k:0x2c + 4 * k] = struct.pack("<I", off)
    relocs = [Reloc(o, 0, DIR32) for o in (0x0c, 0x28, 0x2c, 0x30)]
    sec = Section(None, 1, ".text", 0x60000020, bytes(data), len(data), relocs)
    sym = Symbol(None, 0, ".text", 0, 1, 0, 3, sec)
    mask = sec.mask()
    return FunctionCode(None, sec, 0, bytes(data), mask, tuple((r.offset, r, sym) for r in relocs), 0x28)


def test_switch_tables_are_data():
    """The source extent of a function the walk does not reach holds its switch tables: the original's code ends
    at its first table (a walk of the slot finds it), and the tables compare as data, entry by the instruction
    it points to (a 37-byte tail read as instructions kept main_WindowProc draft with identical instructions)."""
    x86 = isa_plugins.get("x86")
    img = Img(switch_fn())
    o = DC.original(x86, img, 0x1000, 0x34, 0x40, FILL, 16)
    assert o.code == 0x25 and o.tables == [(0x1028, 0x1034, "jumptable")]
    assert DC.original(x86, img, 0x1000, 0x25, 0x40, FILL, 16).code == 0x25         # the walk's extent: no table inside
    A, B, o, tables = DC.compare_function(x86, img, switch_ours(), 0x1000, 0x34, 0x40, FILL, 16)
    assert [x.text for x in A] == [x.text for x in B] and B[-1].addr < 0x1025
    assert tables == {"entries": 3, "bytes": 0, "diffs": []}
    v = DC.verdict(A, B, x86, tables)
    assert v.shape and "switch tables equal (3 entries, 0 index bytes)" in v.summary()
    # two cases exchanged in the original's table: a table difference, no shape
    img = Img(switch_fn((0x1016, 0x1010, 0x101C)))
    A, B, o, tables = DC.compare_function(x86, img, switch_ours(), 0x1000, 0x34, 0x40, FILL, 16)
    assert len(tables["diffs"]) == 2 and "entry +0x0: ours to +0x10, the original's to +0x16" in tables["diffs"][0]
    v = DC.verdict(A, B, x86, tables)
    assert not v.shape and v.hunks == {"table": 2} and "switch tables differ" in v.summary()
    assert DC.Verdict.from_json(v.to_json()) == v


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
    gf = [Fact(a, a + 1, Kind.grade, {"of": "function", "name": n, "unit": u, "file": f"src/{u}.c", "code": code,
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


def test_baseline_accept_column():
    """The accepted column: an old 7-column file parses (empty), dcp accept lowers one entry and notes it, every
    other line stays; the note names the grade it fell from."""
    old = "target\taddress\tname\tunit\tcode\treadability\tlevel\nt\t0x10001000\tf\tu\tbyte\treadable\t\nt\t0x10001010\tg\tu\tshape\tdraft\tdeep\n"
    assert parse_baseline(old)[("t", 0x10001000)]["accepted"] == ""
    note = G.accept_note("byte+readable", "shape+readable", "abc1234", "a VC6\tdeclaration-set\ntie-break")
    assert note == "byte+readable -> shape+readable at abc1234: a VC6 declaration-set tie-break"
    assert G.note_from(note) == "byte+readable" and G.note_from("") is None
    new = G.accept(old, "t", 0x10001000, "shape", "readable", note)
    assert new == (G.HEADER + "\nt\t0x10001000\tf\tu\tshape\treadable\t\t" + note + "\nt\t0x10001010\tg\tu\tshape\tdraft\tdeep\t\n")
    b = parse_baseline(new)[("t", 0x10001000)]
    assert b["code"] == "shape" and b["accepted"] == note
    assert falls(b, {"code": "shape", "readability": "readable"}) == []          # M1 holds it at shape
    assert falls(b, {"code": "draft", "readability": "readable"}) == ["code shape -> draft"]
    assert G.at_least({"code": "byte", "readability": "readable"}, "byte+readable")
    assert not G.at_least({"code": "shape", "readability": "readable"}, "byte+readable")
    assert not G.at_least({"code": "byte", "readability": "draft"}, "shape+readable")


def test_level_ladder(tmp_path):
    assert G.only_missing_statements("missing statements")
    assert G.only_missing_statements("the loop body is unwritten; two calls are missing")
    assert not G.only_missing_statements("register choice ebx/esi after the spell pass; missing statements")
    unit(tmp_path, "u", "int x;  /* 0x10002000 */\n", "/* 0x10001000, does it */\nvoid f(void)\n{\n}\n")
    with pytest.raises(ValueError):
        G.set_level(tmp_path, "src/u.c", "deep", "the data comment", 1)
    assert G.set_level(tmp_path, "src/u.c", "deep", "slot order after vargen", 3) == "@deep added"
    assert "\n/* 0x10001000, does it @deep slot order after vargen */\n" in (tmp_path / "src/u.c").read_text()
    assert G.set_level(tmp_path, "src/u.c", "stuck", "every lead tried", 3) == "@deep -> @stuck"
    fn = srcscan.scan(tmp_path).functions[0]
    assert fn.stuck == "every lead tried" and fn.deep is None and fn.what == "does it" and fn.comment_line == 3
    assert G.set_level(tmp_path, "src/u.c", None, None, 3) == "@stuck removed"
    assert (tmp_path / "src/u.c").read_text() == "int x;  /* 0x10002000 */\n\n/* 0x10001000, does it */\nvoid f(void)\n{\n}\n"


# ------------------------------------------------------------------------------------------------ with VC6
@needs_vc6
def test_compile_and_byte_match(tiny):
    """f2 of the synthetic dll is `mov eax, [0x10002000]; ret`: `return counter;` compiles to it."""
    with_vc6(tiny)
    write(tiny, "decl/text.dcl", "# code\n0x10001020 boundary start tu=net by=tag -- f2 reads the counter\n"
                                 "0x10001030 boundary end tu=net -- f3 is another unit\n")
    head = "int counter = 0x1234;  /* 0x10002000 */\n"
    unit(tiny, "net", head, "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return counter;\n}\n")
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
    unit(tiny, "net", head, "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return counter + 1;\n}\n")
    code, out = dcp(tiny, "grade", "get")
    assert "code=draft" in out and "B3 draft" in out
    code, out = dcp(tiny, "diffclass", "get")
    assert "code" in out
    # a compile error names the unit's file and line and fails the gate
    unit(tiny, "net", head, "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return nothing;\n}\n")
    code, out = dcp(tiny, "build")
    assert code == 1 and "src/net.c(6)" in out and "C2065" in out, out
    code, out = dcp(tiny, "check")
    assert code == 1 and "M.compile" in out


@needs_vc6
def test_promote_raises_only_and_accept(tiny):
    """promote refuses a fall (nothing written); dcp accept lowers that one entry with its reason and M1 holds the
    function there; promote keeps the note while it stays below, clears it once the function is back; a fall
    passes promote with --accept-falls, noted."""
    with_vc6(tiny)
    write(tiny, "decl/text.dcl", "# code\n0x10001020 boundary start tu=net by=tag -- f2 reads the counter\n"
                                 "0x10001030 boundary end tu=net -- f3 is another unit\n")
    head = "int counter = 0x1234;  /* 0x10002000 */\n"
    good = head + "\n/* 0x10001020, reads the counter */\nint get(void)\n{\n    return counter;\n}\n"
    bad = good.replace("counter;\n}", "counter + 1;\n}")
    unit(tiny, "net", good)
    code, out = dcp(tiny, "promote")
    assert code == 0 and "functions=1" in out and "accepted=0" in out, out
    tsv = tiny / "ledger" / "grades.tsv"
    assert tsv.read_text() == G.HEADER + "\ntiny\t0x10001020\tget\tnet\tbyte\treadable\t\t\n"
    unit(tiny, "net", bad)
    before = tsv.read_text()
    code, out = dcp(tiny, "promote")
    assert code == 1 and "promote=refused  falls=1" in out and "fell: 0x10001020 get: code byte -> draft" in out, out
    assert tsv.read_text() == before
    assert dcp(tiny, "accept", "get", "--to", "shape", "--why", "x")[0] == 1          # it is draft now, below shape
    assert dcp(tiny, "accept", "get", "--readability", "draft", "--why", "x")[0] == 1  # still draft code
    code, out = dcp(tiny, "accept", "0x10001020", "--to", "draft", "--why", "a declaration-set tie-break")
    assert code == 0 and "accepted=0x10001020  name=get" in out and "was=byte+readable  now=draft+readable" in out, out
    line = tsv.read_text().splitlines()[1]
    assert line.startswith("tiny\t0x10001020\tget\tnet\tdraft\treadable\t\tbyte+readable -> draft+readable at "), line
    assert line.endswith(": a declaration-set tie-break"), line
    code, out = dcp(tiny, "conflicts")
    assert "M1" not in out, out
    code, out = dcp(tiny, "promote")                     # no fall against the lowered entry; the note stays
    assert code == 0 and "accepted=1" in out and tsv.read_text().splitlines()[1] == line, out
    unit(tiny, "net", good)
    code, out = dcp(tiny, "promote")                     # back at byte: raised, the note cleared
    assert code == 0 and "accepted=0" in out and tsv.read_text() == before, out
    unit(tiny, "net", bad)
    code, out = dcp(tiny, "promote", "--accept-falls")
    assert code == 0 and "fell (accepted): 0x10001020 get" in out and "accepted=1" in out, out
    assert "\tdraft\treadable\t\tbyte+readable -> draft+readable at " in tsv.read_text()
    assert tsv.read_text().rstrip().endswith(": promote --accept-falls")


@needs_vc6
def test_header_edit_recompiles_only_includers(tiny):
    with_vc6(tiny)
    write(tiny, "include/net.h", "extern int counter;\n")
    get = "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return counter;\n}\n"
    unit(tiny, "net", '#include "net.h"\nint counter = 0x1234;  /* 0x10002000 */\n', get)
    unit(tiny, "log", "/* 0x10001030, logs */\nvoid log3(void)\n{\n}\n")
    code, out = dcp(tiny, "build")
    assert "compiled=2" in out, out
    write(tiny, "include/net.h", "extern int counter;  /* edited */\n")
    code, out = dcp(tiny, "build")
    assert "compiled=1" in out and "ok   net" in out and "ok   log" not in out, out
    unit(tiny, "net", '#include "net.h"\n/* a comment */\nint counter = 0x1234;  /* 0x10002000 */\n', get)
    code, out = dcp(tiny, "build")
    assert "compiled=1" in out and "ok   net" in out, out
    assert "compiled=0" in dcp(tiny, "build")[1]


LIBCLANG = cparse.library(None)


@needs_vc6
@pytest.mark.skipif(LIBCLANG is None, reason="libclang not installed")
def test_lint_q7_and_exemption(tiny):
    with_vc6(tiny)
    head = "int counter = 0x1234;  /* 0x10002000 */\nint helper();\n"
    unit(tiny, "net", head, "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return counter + helper(1.5f);\n}\n")
    code, out = dcp(tiny, "lint")
    assert code == 0 and "m7=1" in out and "helper() at line 7" in out, out
    code, out = dcp(tiny, "grade", "get")
    assert "Q7 prototypes: helper() at line 7" in out and "readability=draft" in out
    unit(tiny, "net", head, "/* 0x10001020, reads the counter */\nint get(void)\n{\n"
                            "    return counter + helper(1.5f);  /* @original the original passes a double */\n}\n")
    code, out = dcp(tiny, "lint")
    assert "m7=0" in out, out
    # a conflict across units: two prototypes of one function
    unit(tiny, "log", "long helper(int x);\n", "/* 0x10001030, logs */\nvoid log3(void)\n{\n}\n")
    code, out = dcp(tiny, "lint")
    assert code == 1 and "m5=1" in out and "M5" in out, out


@needs_vc6
@pytest.mark.skipif(LIBCLANG is None, reason="libclang not installed")
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
    unit(tiny, "net", '#include "a.h"\nint counter = 0x1234;  /* 0x10002000 */\nint helper();\n')
    code, out = dcp(tiny, "lint")
    assert "m5=0" in out, out
    unit(tiny, "log", '#include "a.h"\n')
    code, out = dcp(tiny, "lint")
    assert "m5=1" in out and "src/log.c:1: includes a.h, private to net" in out, out


@needs_vc6
@pytest.mark.skipif(LIBCLANG is None, reason="libclang not installed")
def test_lint_m5_per_symbol(tiny):
    """M5 against the definition, one line per symbol: a.h comes first and disagrees, b.h agrees with the
    definition (clang alone would blame b.h); data from the sources too (a unit's GAPDATA view); a K&R
    definition does not swallow what follows it; a header that does not compile is its own M5."""
    with_vc6(tiny)
    unit(tiny, "net", "int counter = 0x1234;  /* 0x10002000 */\n", "/* 0x10001020, reads */\nint get(void)\n{\n    return counter;\n}\n")
    log3 = "/* 0x10001030, logs */\nint log3(a)\nint a;\n{\n    return a;\n}\n"
    unit(tiny, "log", "#define GAPDATA __declspec(align(1)) unsigned char\nextern GAPDATA counter[];\n"
                      "int get();\nint log3(int a);\n", log3)
    write(tiny, "include/a.h", "long get(void);\n")
    write(tiny, "include/b.h", "int get(void);\nextern int counter;\n")
    code, out = dcp(tiny, "lint")
    assert code == 1, out
    m5 = [l for l in out.splitlines() if l.startswith("  M5 ")]
    assert len(m5) == 2, out
    get = next(l for l in m5 if " get declared unlike its definition" in l)
    assert get.startswith("  M5 include/a.h:1: get declared unlike its definition src/net.c:4 (unit net) `int get(void)`"), get
    assert "disagree=1 `long get(void)` at include/a.h:1; agree=2 include/b.h:1, src/log.c:3" in get, get
    cnt = next(l for l in m5 if "counter" in l)
    assert "disagree=1 `GAPDATA counter[]` at src/log.c:2; agree=1 include/b.h:2" in cnt, cnt
    # the header spelling marked @original: the hint names the definition and the cast macro of a unit's view
    write(tiny, "include/a.h", "long get(void);  /* @original why */\n")
    code, out = dcp(tiny, "lint")
    assert "the @original spelling is in a header (include/a.h:1): a header repeats the definition's spelling " \
           "`int get(void);` (unit net); a unit's own view goes in its head region as a cast macro: " \
           "`#define get_X ((long (*)(void))get) /* @original why */`" in out, out
    # in a unit's own declaration the exemption holds
    write(tiny, "include/a.h", "int get(void);\n")
    unit(tiny, "log", "extern int counter;\nlong get(void);  /* @original why */\nint log3(int a);\n", log3)
    code, out = dcp(tiny, "lint")
    assert "m5=0" in out, out
    # a K&R definition and the prototype after it: a disagreeing one is seen
    unit(tiny, "log", "extern int counter;\nint log3(char *a);\n", log3)
    code, out = dcp(tiny, "lint")
    assert "m5=1" in out and "log3 declared unlike its definition src/log.c:5" in out \
           and "`int log3(a) int a;` (as a prototype `int log3(int a)`)" in out, out
    # a header that does not compile in the all-declarations unit
    unit(tiny, "log", "extern int counter;\n", log3)
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
    head = "char *counter = 0;  /* 0x10002000 */\n#define COUNT_RAW (*(int *)counter)\n#define COUNT (*(int *)&counter)  /* 0x10002000 */\n"
    unit(tiny, "net", head, "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return COUNT_RAW;\n}\n")
    code, out = dcp(tiny, "grade", "get")
    assert "Q4 raw access: macro COUNT_RAW (" in out and "`#define NAME (*(T *)&datum)  /* 0xADDR */`" in out \
           and "`(*(T *)datum)` reads through the datum's value and stays raw" in out, out
    unit(tiny, "net", head, "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return COUNT;\n}\n")
    code, out = dcp(tiny, "grade", "get")
    assert "Q4" not in out, out


@needs_vc6
def test_auto_clear_and_data_order(tiny):
    with_vc6(tiny)
    unit(tiny, "net", "int pad = 7;  /* 0x10002004 */\nint counter = 0x1234;  /* 0x10002000 */\n",
         "/* 0x10001020, reads the counter @deep register choice after the spell pass */\nint get(void)\n{\n    return counter;\n}\n")
    code, out = dcp(tiny, "build")
    assert "auto-clear src/net.c: get is byte + readable, @deep removed" in out, out
    assert "\n/* 0x10001020, reads the counter */\nint get(void)\n" in (tiny / "src/net.c").read_text()
    code, out = dcp(tiny, "conflicts")
    assert "D4" in out and "counter (0x10002000) is defined after pad (0x10002004)" in out, out
    syms = {f.lo: f.value["extent"] for f in Project(tiny).store.facts(Kind.symbol) if f.run.startswith("M.data")}
    assert syms[0x10002000] == "site" and syms[0x10002004] == "draft"


def test_branch_targets():
    """The listings read a jump's target as X: a jump to another block of the function is a `branch`
    difference that keeps it from shape; a jump to an identical copy of an epilogue is not."""
    x86 = isa_plugins.get("x86")

    def fn(*rows):
        return [Line(0x1000 + k, 1, t, False, None if g is None else 0x1000 + g) for k, (t, g) in enumerate(rows)]
    body = [("test eax, eax", None), ("je X", 4), ("mov eax, 1", None), ("jmp X", 5), ("xor eax, eax", None),
            ("pop esi", None), ("ret", None)]
    a = fn(*body)
    assert DC.verdict(a, fn(*body), x86).shape
    b = fn(*body[:1], ("je X", 2), *body[2:])                     # the same text, the jump goes elsewhere
    v = DC.verdict(a, b, x86)
    assert not v.shape and v.hunks == {"branch": 1} and "je at +0x1: ours to +0x4, the original's to +0x2" in v.branches[0]
    # register-renamed hunks keep their lines paired one to one: the targets still align
    assert DC.verdict(a, fn(*[(t.replace("eax", "ecx"), g) for t, g in body]), x86).shape
    # a jump to an identical copy of the epilogue: the same code
    dup = [("test eax, eax", None), ("je X", 6), ("mov eax, 1", None), ("pop esi", None), ("ret", None),
           ("int3", None), ("pop esi", None), ("ret", None)]
    ours = fn(*dup[:1], ("je X", 3), *dup[2:5])
    v = DC.verdict(ours, fn(*dup), x86)
    assert not v.branches, v.branches
    # an `order` hunk across a jump target: the target is the same instruction on both sides (gildegold's
    # ai_Unk49a5b0: `xor eax, eax` moved past the `pop edi` both jumps land on)
    o = [("test esi, esi", None), ("je X", 3), ("ret", None), ("xor eax, eax", None), ("pop edi", None),
         ("pop esi", None), ("ret", None)]
    ours = fn(*o[:1], ("je X", 3), o[2], o[4], o[5], o[3], o[6])
    assert DC.verdict(ours, fn(*o[:1], ("je X", 4), *o[2:]), x86).shape
    assert DC.verdict(ours, fn(*o), x86).shape                     # both enter the reordered hunk at its start
    assert not DC.verdict(ours, fn(*o[:1], ("je X", 5), *o[2:]), x86).shape    # the original's skips the pop edi
    # a block the compiler placed elsewhere: ours falls through to the join, the original's jumps back to it
    ours = fn(("cmp edx, 0xa", None), ("jg X", 4), ("mov edx, 1", None), ("jmp X", 5), ("mov edx, 0xa", None),
              ("push edi", None), ("ret", None))
    orig = fn(("cmp edx, 0xa", None), ("jg X", 5), ("mov edx, 1", None), ("push edi", None), ("ret", None),
              ("mov edx, 0xa", None), ("jmp X", 3))
    v = DC.verdict(ours, orig, x86)
    assert v.shape and not v.branches, v.summary()
    orig = fn(("cmp edx, 0xa", None), ("jg X", 5), ("mov edx, 1", None), ("push edi", None), ("ret", None),
              ("mov edx, 0xa", None), ("jmp X", 4))
    assert DC.verdict(ours, orig, x86).branches                    # the original's block jumps to the ret instead
    # a target inside our code against one outside the original's
    v = DC.verdict(a, fn(*body[:1], ("je X", 0x40), *body[2:]), x86)
    assert v.branches and "outside the code" in v.branches[0]
    assert DC.Verdict.from_json(v.to_json()).branches == v.branches
