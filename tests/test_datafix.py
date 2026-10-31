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
    write(tmp_path, "src/u.c",
          "int a;  /* 0x600000, a comment that runs on\n"
          "           over a second line */\n"
          "/* 0x600010, the table */\n"
          "void (*handlers[4])(unsigned char *);\n"
          "int b = 5, c;  /* 0x600020, 0x600024 */\n")
    f = DF.Files(tmp_path)
    st = DF.statement_at(f, "src/u.c", 1)
    text = f.text("src/u.c")
    assert text[st.start:st.end] == "int a;  /* 0x600000, a comment that runs on\n           over a second line */\n"
    st2 = DF.statement_at(f, "src/u.c", 4)
    assert text[st2.start:st2.end].startswith("/* 0x600010, the table */\nvoid (*handlers")    # the comment above moves too
    dc = DF.declarator(f, st2, "handlers")
    assert dc.dims == ["4"] and not dc.has_init and text[st2.s0:dc.end] == "void (*handlers[4])(unsigned char *)"
    st3 = DF.statement_at(f, "src/u.c", 5)
    b, c = DF.declarator(f, st3, "b"), DF.declarator(f, st3, "c")
    assert b.has_init and not c.has_init and b.count == 2


def test_d5_initialisers(tmp_path):
    write(tmp_path, "src/u.c", "int a;\nAIOBJ *p;\nAIOBJ o;\nchar s[8];\nvoid (*fp)(void);\n")
    f = DF.Files(tmp_path)
    model = []
    for line, name in enumerate(["a", "p", "o", "s", "fp"], 1):
        d = DF.DataDef("u", name, "src/u.c", line, "def", 0x600000 + line, False)
        d.conflicts.append(("D5", "tentative"))
        model.append(d)
    edits, manual = DF.d5_edits(f, model)
    assert not manual
    new = DF.apply(f, edits)["src/u.c"]
    assert new == "int a = 0;\nAIOBJ *p = 0;\nAIOBJ o = {0};\nchar s[8] = {0};\nvoid (*fp)(void) = 0;\n"


def test_insertions_at_one_place_keep_their_order(tmp_path):
    write(tmp_path, "a.c", "x\ny\n")
    f = DF.Files(tmp_path)
    edits = [DF.Edit("a.c", 2, 0, "1\n", "", "u"), DF.Edit("a.c", 2, 0, "2\n", "", "u"), DF.Edit("a.c", 0, 2, "", "", "u")]
    assert DF.apply(f, edits)["a.c"] == "1\n2\ny\n"


def test_d4_does_not_move_a_definition_above_its_type(tmp_path):
    """The init_PlayerProfile case: the definition sorts between two in the head, but its typedef stands further
    down, between the two places: a manual case, no edit (the move would not compile)."""
    write(tmp_path, "src/u.c", "int a = 0;  /* 0x600000 */\nint b = 0;  /* 0x600020 */\nint e = 0;  /* 0x600028 */\n"
                               "typedef struct { int a; } INIT_PLAYER;\nINIT_PLAYER prof = {0};  /* 0x600010 */\n"
                               "/* 0x401000, f */\nvoid f(void)\n{\n}\n"
                               "int c = 0;  /* 0x600030 */\nint d = 0;  /* 0x600008 */\n"
                               "/* 0x401100, g */\nvoid g(void)\n{\n}\n")
    f = DF.Files(tmp_path)

    def dd(name, rel, line, addr):
        x = DF.DataDef("u", name, rel, line, "def", addr, False, section="bss")
        x.conflicts.append(("D4", "order"))
        return x
    model = [dd("a", "src/u.c", 1, 0x600000), dd("b", "src/u.c", 2, 0x600020), dd("e", "src/u.c", 3, 0x600028),
             dd("prof", "src/u.c", 5, 0x600010), dd("c", "src/u.c", 10, 0x600030),
             dd("d", "src/u.c", 11, 0x600008)]                          # the run a, b, e, c stays: prof and d move up
    order = {"u": ["src/u.c"]}
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
    from decompanion import native
    least_size = native.core().least_size                        # native/dcp_core rules.rs least (the data rules')
    assert least_size(0x10, 8) == 1                               # int x = 0; followed by an 8-aligned symbol
    assert least_size(0x10, 6) == 5                               # ends at 0x16: 2-aligned, at most 1 byte padding
    assert least_size(0x11, 6) == 6                               # ends at an odd offset: no padding
    assert least_size(None, 8) == 8


def test_content_masks_possible_padding():
    """M.data.content: `float x = 1.75f;` whose next symbol is 8-aligned has an object size of 8 (4 bytes of
    padding) and a least size of 1: every zero byte from byte 1 on may be padding and is masked, so the padded
    pattern (which occurs elsewhere) is no longer searched; too few certain bytes remain to prove anything."""
    from decompanion import native
    least_size, padding_masked = native.core().least_size, native.core().padding_masked
    data = bytes.fromhex("0000e03f00000000")                 # 1.75f, then 4 zero bytes of padding
    mask = bytes(8)
    m = bytes(padding_masked(data, mask, least_size(0x18, 8)))
    assert m == bytes([0, 1, 0, 0, 1, 1, 1, 1])
    data2 = bytes.fromhex("0000e03f00000040")                 # a nonzero byte in the possible padding is the
    assert bytes(padding_masked(data2, mask, 1))[7] == 0       # symbol's own: compared
