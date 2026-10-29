"""The data rewrites (source/datafix.py) on files of a temp tree: statements and their blocks, declarators,
the D5 initialiser, the D4 order of insertions at one place and its type guard, the longest increasing run;
the padding-aware sizes of rules/match_data.py."""
from pathlib import Path

from decompanion.source import datafix as DF


def write(root: Path, rel: str, text: str):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, newline="\n")


def test_statement_block_and_declarators(tmp_path):
    write(tmp_path, "src/u/tail.c",
          "int a;  /* 0x600000, a comment that runs on\n"
          "           over a second line */\n"
          "/* 0x600010, the table */\n"
          "void (*handlers[4])(unsigned char *);\n"
          "int b = 5, c;  /* 0x600020, 0x600024 */\n")
    f = DF.Files(tmp_path)
    st = DF.statement_at(f, "src/u/tail.c", 1)
    text = f.text("src/u/tail.c")
    assert text[st.start:st.end] == "int a;  /* 0x600000, a comment that runs on\n           over a second line */\n"
    st2 = DF.statement_at(f, "src/u/tail.c", 4)
    assert text[st2.start:st2.end].startswith("/* 0x600010, the table */\nvoid (*handlers")    # the comment above moves too
    dc = DF.declarator(f, st2, "handlers")
    assert dc.dims == ["4"] and not dc.has_init and text[st2.s0:dc.end] == "void (*handlers[4])(unsigned char *)"
    st3 = DF.statement_at(f, "src/u/tail.c", 5)
    b, c = DF.declarator(f, st3, "b"), DF.declarator(f, st3, "c")
    assert b.has_init and not c.has_init and b.count == 2


def test_d5_initialisers(tmp_path):
    write(tmp_path, "src/u/tail.c", "int a;\nAIOBJ *p;\nAIOBJ o;\nchar s[8];\nvoid (*fp)(void);\n")
    f = DF.Files(tmp_path)
    model = []
    for line, name in enumerate(["a", "p", "o", "s", "fp"], 1):
        d = DF.DataDef("u", name, "src/u/tail.c", line, "def", 0x600000 + line, False)
        d.conflicts.append(("D5", "tentative"))
        model.append(d)
    edits, manual = DF.d5_edits(f, model)
    assert not manual
    new = DF.apply(f, edits)["src/u/tail.c"]
    assert new == "int a = 0;\nAIOBJ *p = 0;\nAIOBJ o = {0};\nchar s[8] = {0};\nvoid (*fp)(void) = 0;\n"


def test_insertions_at_one_place_keep_their_order(tmp_path):
    write(tmp_path, "a.c", "x\ny\n")
    f = DF.Files(tmp_path)
    edits = [DF.Edit("a.c", 2, 0, "1\n", "", "u"), DF.Edit("a.c", 2, 0, "2\n", "", "u"), DF.Edit("a.c", 0, 2, "", "", "u")]
    assert DF.apply(f, edits)["a.c"] == "1\n2\ny\n"


def test_d4_does_not_move_a_definition_above_its_type(tmp_path):
    """The init_PlayerProfile case: the definition sorts between two in head.c, but its typedef lives in its
    own fragment, between the two places: a manual case, no edit (the move would not compile)."""
    write(tmp_path, "src/u/head.c", "int a = 0;  /* 0x600000 */\nint b = 0;  /* 0x600020 */\nint e = 0;  /* 0x600028 */\n")
    write(tmp_path, "src/u/f_401000.c", "/* 0x401000, f */\ntypedef struct { int a; } INIT_PLAYER;\n"
                                        "INIT_PLAYER prof = {0};  /* 0x600010 */\nvoid f(void)\n{\n}\n")
    write(tmp_path, "src/u/f_401100.c", "/* 0x401100, g */\nint c = 0;  /* 0x600030 */\nint d = 0;  /* 0x600008 */\n"
                                        "void g(void)\n{\n}\n")
    f = DF.Files(tmp_path)

    def dd(name, rel, line, addr):
        x = DF.DataDef("u", name, rel, line, "def", addr, False, section="bss")
        x.conflicts.append(("D4", "order"))
        return x
    model = [dd("a", "src/u/head.c", 1, 0x600000), dd("b", "src/u/head.c", 2, 0x600020), dd("e", "src/u/head.c", 3, 0x600028),
             dd("prof", "src/u/f_401000.c", 3, 0x600010), dd("c", "src/u/f_401100.c", 2, 0x600030),
             dd("d", "src/u/f_401100.c", 3, 0x600008)]                  # the run a, b, e, c stays: prof and d move up
    order = {"u": ["src/u/head.c", "src/u/f_401000.c", "src/u/f_401100.c"]}
    edits, manual = DF.d4_edits(f, model, order)
    assert any(" prof " in m and "INIT_PLAYER" in m for m in manual), manual
    moved = {e.group for e in edits}
    assert "D4 prof" not in moved and "D4 d" in moved              # `int` needs nothing from in between


def test_lis():
    seq = [5, 1, 2, 9, 3, 4]
    keep = DF.lis(seq)
    assert [seq[i] for i in sorted(keep)] == [1, 2, 3, 4]


def test_least_size():
    """An object's size runs to the next symbol, padding included: the least size drops what the alignment of
    that end may have added (at most 7 bytes at an 8-aligned end)."""
    from types import SimpleNamespace
    from decompanion.rules.match_data import least_size
    assert least_size(SimpleNamespace(value=0x10), 8) == 1        # int x = 0; followed by an 8-aligned symbol
    assert least_size(SimpleNamespace(value=0x10), 6) == 5        # ends at 0x16: 2-aligned, at most 1 byte padding
    assert least_size(SimpleNamespace(value=0x11), 6) == 6        # ends at an odd offset: no padding
    assert least_size(None, 8) == 8


def test_content_masks_possible_padding():
    """M.data.content: `float x = 1.75f;` whose next symbol is 8-aligned has an object size of 8 (4 bytes of
    padding) and a least size of 1: every zero byte from byte 1 on may be padding and is masked, so the padded
    pattern (which occurs elsewhere) is no longer searched; too few certain bytes remain to prove anything."""
    from types import SimpleNamespace
    from decompanion.rules.match_data import least_size, padding_masked
    data = bytes.fromhex("0000e03f00000000")                 # 1.75f, then 4 zero bytes of padding
    mask = bytes(8)
    m = padding_masked(data, mask, least_size(SimpleNamespace(value=0x18), 8))
    assert m == bytes([0, 1, 0, 0, 1, 1, 1, 1])
    data2 = bytes.fromhex("0000e03f00000040")                 # a nonzero byte in the possible padding is the
    assert padding_masked(data2, mask, 1)[7] == 0              # symbol's own: compared
