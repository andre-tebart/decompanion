"""The match phase on the synthetic dll: the translation units, the compare, the hunk classes and the grade verdict
on hand-made instruction lists, the queues, the baseline (M1), the level ladder; with VC6 installed: compile
and byte match on the synthetic image, the include-set cache."""
from pathlib import Path

import pytest

from conftest import dcp, unit

from decompanion.config import Project
from decompanion.ledger.fact import Kind, Level
from decompanion import native

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
def scan(root):
    """The core's scan of a tree (frontend.rs)."""
    return native.core().front_scan(str(root), None)


def errors(sc, check):
    """(file, line, check, message) of the scan's errors of one check."""
    return [e for e in sc.error_rows if e[2] == check]


def units(root, sc, target, default="tiny"):
    """{unit: [(address or None, name)]} of one target's translation units (plan.rs)."""
    return {u: [tuple(f) for f in fns] for _, u, _, fns, _, _ in native.core().plan_scan_units(str(root), sc, target, default, {})}


def test_unit_file_order_and_fn(tiny):
    unit(tiny, "net", "int counter = 1;  /* 0x10002000 */\n",
         "/* 0x10001030, logs */\nvoid log3(void)\n{\n}\n",
         "/* 0x10001020, reads */\nint get(void)\n{\n    return counter;\n}\n",
         "/* unlinked, dropped by /OPT:REF */\nvoid spare(void)\n{\n}\n", "int last = 2;\n")
    sc = scan(tiny)
    assert not sc.error_rows, sc.error_rows
    assert units(tiny, sc, "tiny") == {"net": [(0x10001030, "log3"), (0x10001020, "get"), (None, "spare")]}   # the text's order
    get = next(f for f in sc.function_rows if f[0][3] == "get")
    assert (get[1][3], get[0][1], get[1][5]) == (8, 9, 12)
    code, out = dcp(tiny, "fn", "0x10001020")
    assert code == 0 and "at=src/net.c:8-12" in out and out.endswith("/* 0x10001020, reads */\nint get(void)\n{\n    return counter;\n}\n"), out
    # a definition without its address comment directly above it
    unit(tiny, "net", "/* 0x10001020, reads */\nint x;\nint get(void)\n{\n    return 1;\n}\n")
    errs = errors(scan(tiny), "L.src")
    assert len(errs) == 1 and "get: no address comment" in errs[0][3] and errs[0][1] == 3, errs
    unit(tiny, "net", "/* 0x10001020, reads */\nint get(void)\n{\n    return 1;\n}\n")
    (tiny / "src" / "old").mkdir()
    (tiny / "src" / "old" / "f_10001020.c").write_text("int y;\n")
    errs = errors(scan(tiny), "L.src")
    assert len(errs) == 1 and "unexpected source file src/old/f_10001020.c" in errs[0][3], errs


def test_q6_reads_a_functions_own_documentation(tiny):
    """Q6's described addresses: a function's definition comment and its declaration in its owner header
    include/<unit>.h; never a copy in another unit's header or source, nor a later address in another function's
    comment, nor a text that only names a file."""
    write(tiny, "include/net.h", "int get(void);  /* 0x10001020, reads the counter */\n"
                                 "void log3(void);  /* 0x10001030, logs three times */\n")
    write(tiny, "include/log.h", "void log3(void);  /* 0x10001030, net.h */\n")
    unit(tiny, "net", '#include "net.h"\nvoid log4(void);  /* 0x10001040, logs four times */\n',
         "/* 0x10001020 */\nint get(void)\n{\n    return 1;\n}\n",
         "/* 0x10001060, 0x10001030 on the record */\nvoid put(void)\n{\n}\n")      # 0x10001030 is log3's
    unit(tiny, "log", "int get(void);  /* 0x10001020, as in net.h */\n",
         "/* 0x10001030 */\nvoid log3(void)\n{\n}\n", "/* 0x10001040, defined in log.c */\nvoid log4(void)\n{\n}\n",
         "/* 0x10001050, logs five times */\nvoid log5(void)\n{\n}\n")
    assert scan(tiny).context()[1] == [0x10001020, 0x10001050, 0x10001060]


def test_unit_targets(tiny2):
    unit(tiny2, "net", "/* 0x10001020, other:0x10001020, both */\nint get(void)\n{\n    return 1;\n}\n",
         "#if defined(DCP_TARGET_other)\n/* other:0x10001030, only the second target */\nvoid only(void)\n{\n}\n#endif\n",
         "#ifdef DCP_TARGET_tiny\n/* 0x10001050, only the default target */\nvoid first(void)\n{\n}\n#endif\n")
    unit(tiny2, "lone", "#ifdef DCP_TARGET_other\n/* other:0x10001040, a unit of the second target only */\n"
                        "void lone(void)\n{\n}\n#endif\n")
    sc = scan(tiny2)
    assert not sc.error_rows, sc.error_rows
    assert {u: [n for _, n in fs] for u, fs in units(tiny2, sc, "tiny").items()} == {"net": ["get", "first"]}
    assert {u: [n for _, n in fs] for u, fs in units(tiny2, sc, "other").items()} == {"lone": ["lone"], "net": ["get", "only"]}
    # L16: a function the guard and the comment disagree on
    unit(tiny2, "lone", "/* other:0x10001040, unguarded */\nvoid lone(void)\n{\n}\n")
    errs = errors(scan(tiny2), "L16")
    assert len(errs) == 1 and "lone is compiled into tiny" in errs[0][3] and "DCP_TARGET_other" in errs[0][3], errs
    unit(tiny2, "lone", "#ifdef DCP_TARGET_tiny\n/* other:0x10001040, the wrong guard */\nvoid lone(void)\n{\n}\n#endif\n")
    msgs = sorted(e[3] for e in errors(scan(tiny2), "L16"))
    assert len(msgs) == 2 and "lists other, whose compile does not hold it" in msgs[1], msgs


# ------------------------------------------------------------------------------------------------ diffclass
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
    # a big code hunk: its first lines and how many more (every line with --all)
    calls = "".join(f"    put({k});\n" for k in range(1, 10))
    unit(tiny, "net", head + "void put(int x);\n", f"/* 0x10001020, reads the counter */\nint get(void)\n{{\n{calls}    return counter;\n}}\n")
    code, out = dcp(tiny, "diffclass", "get")
    assert "      - push 1" in out and "more of ours: --all, or dcp asmdiff)" in out, out
    code, out = dcp(tiny, "diffclass", "get", "--all")
    assert "more of ours" not in out and out.count("      - call X") == 9, out
    # a compile error names the unit's file and line and fails the gate
    unit(tiny, "net", head, "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return nothing;\n}\n")
    code, out = dcp(tiny, "build")
    assert code == 1 and "src/net.c(6)" in out and "C2065" in out, out
    code, out = dcp(tiny, "check")
    assert code == 1 and "M.compile" in out


@needs_vc6
def test_byte_match_with_a_differing_literal_is_no_byte(tiny):
    """f2 reads the dword at 0x10002000 (34 12 00 00): `return *(int *)"\\x34\\x12";` compiles to the same bytes,
    its literal held there, byte; another literal keeps the bytes (M.match) but the literal differs (M9): draft
    (a meaning difference), B1 failing with the M9 message, B3 naming the mismatch (a match-base report: grade said
    byte, only check caught it)."""
    with_vc6(tiny)
    write(tiny, "decl/text.dcl", "# code\n0x10001020 boundary start tu=net by=tag -- f2 reads the counter\n"
                                 "0x10001030 boundary end tu=net -- f3 is another unit\n")
    fn = "/* 0x10001020, reads the counter */\nint get(void)\n{{\n    return *(int *)\"{}\";\n}}\n"
    unit(tiny, "net", fn.format("\\x34\\x12"))
    code, out = dcp(tiny, "build")
    assert code == 0, out
    code, out = dcp(tiny, "grade", "get")
    assert "code=byte" in out, out
    code, out = dcp(tiny, "asmdiff", "get", "--symbols")            # the literal is the original's: one name
    assert "   0x10001020  mov eax, dword ptr [0x10002000]" in out and "\n!  " not in out, out
    unit(tiny, "net", fn.format("\\x34\\x13"))
    code, out = dcp(tiny, "build")
    assert [f.lo for f in Project(tiny).store.facts(Kind.symbol) if f.run == "M.match"] == [0x10001020]
    code, out = dcp(tiny, "grade", "get")
    assert "code=draft" in out and "B1 byte: M9" in out and "differs from the original's bytes" in out, out
    assert "B3 draft: 1 referenced literal(s) / constant(s) differ from the original's (M9)" in out, out
    code, out = dcp(tiny, "asmdiff", "get")                          # X on both sides: equal
    assert "differing=0" in out and "... " not in out and "   0x10001020  mov eax, dword ptr [X]" in out, out
    code, out = dcp(tiny, "asmdiff", "get", "--symbols")
    assert "differing=0" in out and '!  0x10001020  mov eax, dword ptr ["4\\x13"]   | mov eax, dword ptr [0x10002000]' in out, out


@needs_vc6
def test_rename_counts_the_errors_of_the_tree_as_from_before(tiny):
    """An M9 an edit brought (not built yet), then one the store holds under the old name: neither is the rename's
    (exit 0, `0 new error(s)`); an error the rename brings still fails it (a match-base report: the rename of a
    function whose unbuilt edit broke a literal exited 1 blaming itself)."""
    with_vc6(tiny)
    write(tiny, "decl/text.dcl", "# code\n0x10001020 boundary start tu=net by=tag -- f2 reads the counter\n"
                                 "0x10001030 boundary end tu=net -- f3 is another unit\n")
    fn = "/* 0x10001020, reads the counter */\nint {}(void)\n{{\n    return *(int *)\"{}\";\n}}\n"
    unit(tiny, "net", fn.format("get", "\\x34\\x12"))
    code, out = dcp(tiny, "build")
    assert code == 0, out
    unit(tiny, "net", fn.format("get", "\\x34\\x13"))                  # the edit, not built
    code, out = dcp(tiny, "rename", "get", "read_counter", "--why", "reads the counter")
    assert code == 0 and "renamed=get" in out and "check: 0 new error(s) after the rename, 1 from before" in out, out
    assert "build: 1 of 1 unit(s) that read the renamed files keep their objects" in out, out    # not compiled again
    import sqlite3
    h = sqlite3.connect(Project(tiny).store_path()).execute("SELECT obj_hash FROM tu WHERE unit='net'").fetchone()[0]
    assert b"_read_counter" in (tiny / "build" / "obj" / f"{h}.obj").read_bytes()
    code, out = dcp(tiny, "rename", "read_counter", "counter_value", "--why", "the store names read_counter")
    assert code == 0 and "check: 0 new error(s) after the rename, 1 from before" in out, out
    unit(tiny, "net", fn.format("counter_value", "\\x34\\x12"))
    code, out = dcp(tiny, "build")
    assert code == 0, out
    code, out = dcp(tiny, "rename", "counter_value", "FUN_10001021", "--why", "a placeholder of no start (L5)")
    assert code == 1 and "check: 1 new error(s) after the rename, 0 from before" in out and "L5" in out, out


@needs_vc6
def test_escalate_refuses_an_unexplained_size(tiny):
    """dcp escalate to deep refuses while the instruction count differs from the original's beyond what allocation
    explains (missing or wrong statements are base work); --size-explained takes it with the why in the reason."""
    with_vc6(tiny)
    write(tiny, "decl/text.dcl", "# code\n0x10001020 boundary start tu=net by=tag -- f2 reads the counter\n"
                                 "0x10001030 boundary end tu=net -- f3 is another unit\n")
    body = "".join(f"    n = n * {k} + *(int *)\"\\x34\\x12\";\n" for k in range(3, 9))
    unit(tiny, "net", "/* 0x10001020, reads the counter */\nint get(int n)\n{\n" + body + "    return n;\n}\n")
    assert dcp(tiny, "build")[0] == 0
    code, out = dcp(tiny, "escalate", "get", "register choice after the spell pass")
    assert code == 1 and "@deep" not in (tiny / "src/net.c").read_text(), out
    code, out = dcp(tiny, "escalate", "get", "register choice", "--size-explained", "the original keeps n in a register")
    assert code == 0 and "@deep register choice (size: " in (tiny / "src/net.c").read_text(), out
    assert "explained: the original keeps n in a register)" in (tiny / "src/net.c").read_text()


@needs_vc6
def test_headers_conflicts_trial_grades(tiny):
    """`dcp headers conflicts --trial` compiles the unit with the include and grades its functions: the one whose
    code would fall is listed (exit 1), nothing is written (a match-base report: only a real build showed that a
    header dropped a byte match to shape)."""
    with_vc6(tiny)
    write(tiny, "decl/text.dcl", "# code\n0x10001020 boundary start tu=net by=tag -- f2 reads the counter\n"
                                 "0x10001030 boundary end tu=net -- f3 is another unit\n")
    unit(tiny, "net", "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return *(int *)\"\\x34\\x12\";\n}\n")
    assert dcp(tiny, "build")[0] == 0
    write(tiny, "include/plain.h", "int spare(void);\n")
    write(tiny, "include/slow.h", "#pragma optimize(\"\", off)\n")
    before = (tiny / "src/net.c").read_text()
    code, out = dcp(tiny, "headers", "conflicts", "net", "plain", "--trial")
    assert code == 0 and "trial=compiled  functions=1  falls=0  rises=0  same=1" in out, out
    code, out = dcp(tiny, "headers", "conflicts", "net", "slow", "--trial")
    assert code == 1 and "falls=1" in out and "  fall=0x10001020  name=get  code=byte  trial=draft" in out, out
    assert (tiny / "src/net.c").read_text() == before and not list((tiny / "build" / "obj" / "trial").glob("*"))
    assert "code=byte" in dcp(tiny, "grade", "get")[1]


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
    assert tsv.read_text() == "target\taddress\tname\tunit\tcode\treadability\tlevel\taccepted\ntiny\t0x10001020\tget\tnet\tbyte\treadable\t\t\n"
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


LIBCLANG = native.core().clang_library()


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
    # an array's name is its address: (*(T *)(array + N)) is a view of its part (a match-base report: flagged)
    head = "char counter[8] = {0};  /* 0x10002000 */\n#define COUNT_HI (*(int *)(counter + 4))  /* 0x10002004 */\n"
    unit(tiny, "net", head, "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return COUNT_HI;\n}\n")
    code, out = dcp(tiny, "grade", "get")
    assert "Q4" not in out, out
    assert "L15" not in dcp(tiny, "conflicts")[1]


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


