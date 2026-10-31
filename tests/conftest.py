"""Fixtures: a tiny synthetic PE32 dll (no imports, no library code) and target projects around it.

Layout of the synthetic image (base 0x10000000):
  .text 0x10001000  f1 0x10001000: push ebp; mov ebp,esp; call f2; call f3; pop ebp; ret     (the entry point)
                    f2 0x10001020: mov eax,[0x10002000]; ret
                    f3 0x10001030: push "c:\\src\\net\\net.c"; push "hello"; add esp,8; ret
                    f4 0x10001050: push "world"; pop eax; ret                                 (called by nobody but f1's
                                                                                               table of pointers in .data)
  .data 0x10002000  a dword, then the strings, then a pointer to f4
  .reloc            the base relocations of every absolute operand
The headers carry a Rich header (RICH_TINY for the first target, RICH_OTHER for the second of `tiny2`);
build_lib writes a COFF archive of objects that carry only an @comp.id symbol.
"""
from __future__ import annotations

import struct
import time
from pathlib import Path

import pytest

BUDGET = 2.0                    # seconds: a default run (no `e2e`, no `ghidra`) that takes longer fails
DEFAULT_MARKS = "not ghidra and not e2e"
E2E_FIXTURES = {"server", "srv", "guild", "project"}     # the real binaries' projects


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(config, items):
    """Mark e2e (user decision: "e2e tests are not the way to go. most of the tests should be fast in memory tests")
    every test that runs a dcp command (its source, or a function of its module it calls, calls dcp()) or stands on
    a real binary's project; before the markers deselect."""
    import inspect
    import re
    calls_dcp: dict[object, set] = {}
    for item in items:
        mod = item.module
        if mod not in calls_dcp:
            funcs = {n: inspect.getsource(f) for n, f in vars(mod).items()
                     if inspect.isfunction(f) and f.__module__ == mod.__name__}
            hits = {n for n, s in funcs.items() if "dcp(" in s}
            while True:                                   # a helper that calls a helper that runs dcp
                more = {n for n, s in funcs.items() if n not in hits and any(re.search(rf"\b{h}\(", s) for h in hits)}
                if not more:
                    break
                hits |= more
            calls_dcp[mod] = hits
        fn = getattr(item, "function", None)
        src = inspect.getsource(fn) if fn is not None else ""
        if ("dcp(" in src or any(re.search(rf"\b{h}\(", src) for h in calls_dcp[mod])
                or E2E_FIXTURES & set(getattr(item, "fixturenames", ()))):
            item.add_marker(pytest.mark.e2e)


def pytest_sessionstart(session):
    from decompanion import native
    native.core()                   # a changed core builds before the clock starts (as cargo test's compile)
    session.config._dcp_started = time.perf_counter()


def pytest_sessionfinish(session, exitstatus):
    """The run's budget (user decision: "a full test run should run under 2s"): the default selection, from the
    session's start (collection and imports included), fails past BUDGET."""
    took = time.perf_counter() - session.config._dcp_started
    if session.config.option.markexpr == DEFAULT_MARKS and took > BUDGET:
        tr = session.config.pluginmanager.get_plugin("terminalreporter")
        msg = f"the test run took {took:.2f} s, over its budget of {BUDGET:.0f} s (tests/conftest.py BUDGET)"
        if tr is not None:
            tr.write_line(msg, red=True)
        if session.exitstatus == 0:
            session.exitstatus = 1

BASE = 0x10000000
TEXT, DATA, RELOC = 0x1000, 0x2000, 0x3000


# Rich headers of the two synthetic targets (prodid, build, count): the user's objects (Utc12_2_C 9044), static
# CRT objects (Utc12_C 8047), the linker; the second target adds a VC7 object (Utc13_C 9178) and an old linker.
RICH_TINY = [(0x30, 9044, 3), (0x0a, 8047, 5), (0x04, 8447, 1)]
RICH_OTHER = [(0x30, 9044, 2), (0x0a, 8047, 5), (0x1c, 9178, 1), (0x04, 8447, 2), (0x13, 9049, 1)]


def rich_header(entries, key=0x1234abcd) -> bytes:
    """A Rich header: DanS and three padding dwords, the (prodid << 16 | build, count) pairs, all xor key; then
    "Rich" and the key."""
    out = struct.pack("<IIII", 0x536e6144 ^ key, key, key, key)
    for prodid, build, count in entries:
        out += struct.pack("<II", ((prodid << 16) | build) ^ key, count ^ key)
    return out + b"Rich" + struct.pack("<I", key)


def build_lib(path: Path, comp_ids) -> Path:
    """A COFF archive of one object per (prodid, build): no sections, only the absolute `@comp.id` symbol."""
    members = b""
    for k, (prodid, build) in enumerate(comp_ids):
        sym = b"@comp.id" + struct.pack("<IhHBB", (prodid << 16) | build, -1, 0, 3, 0)
        obj = struct.pack("<HHIIIHH", 0x14c, 0, 0, 20, 1, 0, 0) + sym + struct.pack("<I", 4)
        name = f"o{k}.obj/".ljust(16).encode()
        hdr = name + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) + b"644".ljust(8) + str(len(obj)).ljust(10).encode() + b"`\n"
        members += hdr + obj + (b"\n" if len(obj) & 1 else b"")
    path.write_bytes(b"!<arch>\n" + members)
    return path


def build_pe(path: Path, variant: int = 0, rich=None) -> Path:
    """Write the synthetic dll; `variant` changes one data byte (another binary of the same codebase); `rich`
    adds a Rich header with these entries."""
    va = lambda rva: BASE + rva  # noqa: E731
    s_path, s_hello, s_world = va(DATA + 0x10), va(DATA + 0x30), va(DATA + 0x38)
    code = bytearray(b"\x90" * 0x60)
    relocs = []
    # f1 at +0x00
    f1 = b"\x55\x8b\xec" + b"\xe8" + struct.pack("<i", 0x20 - (0x03 + 5)) + b"\xe8" + struct.pack("<i", 0x30 - (0x08 + 5)) + b"\x5d\xc3"
    code[0:len(f1)] = f1
    # f2 at +0x20
    f2 = b"\xa1" + struct.pack("<I", va(DATA)) + b"\xc3"
    code[0x20:0x20 + len(f2)] = f2
    relocs.append(TEXT + 0x21)
    # f3 at +0x30
    f3 = b"\x68" + struct.pack("<I", s_path) + b"\x68" + struct.pack("<I", s_hello) + b"\x83\xc4\x08\xc3"
    code[0x30:0x30 + len(f3)] = f3
    relocs += [TEXT + 0x31, TEXT + 0x36]
    # f4 at +0x50
    f4 = b"\x68" + struct.pack("<I", s_world) + b"\x58\xc3"
    code[0x50:0x50 + len(f4)] = f4
    relocs.append(TEXT + 0x51)
    data = bytearray(0x50)
    struct.pack_into("<I", data, 0, 0x1234 + variant)
    data[0x10:0x10 + 17] = b"c:\\src\\net\\net.c\0"
    data[0x30:0x36] = b"hello\0"
    data[0x38:0x3e] = b"world\0"
    struct.pack_into("<I", data, 0x40, va(TEXT + 0x50))
    relocs.append(DATA + 0x40)
    # .reloc: one block per page
    blocks = b""
    for page in sorted({r & ~0xfff for r in relocs}):
        ents = [(3 << 12) | (r & 0xfff) for r in relocs if r & ~0xfff == page]
        if len(ents) % 2:
            ents.append(0)
        blocks += struct.pack("<II", page, 8 + 2 * len(ents)) + b"".join(struct.pack("<H", e) for e in ents)
    secs = [(b".text", TEXT, bytes(code), 0x60000020), (b".data", DATA, bytes(data), 0xC0000040), (b".reloc", RELOC, blocks, 0x42000040)]
    falign, hdr = 0x200, 0x400
    raw = []
    off = hdr
    for name, rva, body, ch in secs:
        rs = (len(body) + falign - 1) // falign * falign
        raw.append((name, rva, body, ch, off, rs))
        off += rs
    out = bytearray(off)
    out[0:2] = b"MZ"
    pe = 0x80
    if rich:
        r = rich_header(rich)
        out[0x80:0x80 + len(r)] = r
        pe = (0x80 + len(r) + 0xf) & ~0xf
    struct.pack_into("<I", out, 0x3c, pe)
    out[pe:pe + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", out, pe + 4, 0x14c, len(secs), 0x3f7a0000, 0, 0, 0xE0, 0x2102)
    opt = pe + 24
    size_image = RELOC + 0x1000
    struct.pack_into("<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII", out, opt,
                     0x10b, 6, 0, 0x200, 0x200, 0, TEXT, TEXT, DATA, BASE, 0x1000, falign, 4, 0, 0, 0, 4, 0, 0,
                     size_image, hdr, 0, 2, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    dd = opt + 96
    struct.pack_into("<II", out, dd + 8 * 5, RELOC, len(blocks))
    st = opt + 0xE0
    for k, (name, rva, body, ch, roff, rs) in enumerate(raw):
        struct.pack_into("<8sIIIIIIHHI", out, st + 40 * k, name, len(body), rva, rs, roff, 0, 0, 0, 0, ch)
        out[roff:roff + len(body)] = body
    path.write_bytes(bytes(out))
    return path


NO_VC6 = 'root = "C:/nowhere/vc6"\n'       # the toolchain root of the synthetic projects (tests needing VC6 replace it)
CONFIG = '''[[target]]
name = "{n1}"
path = "{p1}"
image = "pe32"
{second}
[toolchain]
plugin = "vc6"
root = "C:/nowhere/vc6"
compiler = "cl 12.00.9044"
linker = "link 6.00.8447"
cflags = ["/O2"]
reason = "test project"

[libs]
archives = []
reason = "test project: no static library"

[analyzer]
plugin = "none"
'''


FAKE_HEADLESS = """import shutil, sys
args = sys.argv[1:]
i = args.index("-postScript")
shutil.copyfile({export!r}, args[i + 2])
"""


def use_fake_ghidra(root: Path, export: Path):
    """Switch the project's analyzer to Ghidra, a stand-in installation beside the project whose analyzeHeadless
    writes the batch_decompile file `export` (the shape DcpExport.java writes) as the export."""
    import sys
    fake = root.parent / f"{root.name}-ghidra"
    (fake / "support").mkdir(parents=True, exist_ok=True)
    (fake / "jdk" / "bin").mkdir(parents=True, exist_ok=True)
    (fake / "headless.py").write_text(FAKE_HEADLESS.format(export=str(export)), newline="\n")
    (fake / "support" / "analyzeHeadless.bat").write_text(f'@"{sys.executable}" "{fake / "headless.py"}" %*\n', newline="\n")
    cfg = root / "decompanion.toml"
    text = cfg.read_text()
    assert '[analyzer]\nplugin = "none"\n' in text
    text = text.replace('[analyzer]\nplugin = "none"\n', f'[analyzer]\nplugin = "ghidra"\nroot = "{fake.as_posix()}"\n'
                                                          f'java_home = "{(fake / "jdk").as_posix()}"\n')
    cfg.write_text(text, newline="\n")


def make_project(d: Path, two: bool = False) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    p1 = build_pe(d / "tiny.dll", rich=RICH_TINY)
    second = ""
    if two:
        p2 = build_pe(d / "tiny2.dll", variant=1, rich=RICH_OTHER)
        second = f'\n[[target]]\nname = "other"\npath = "{p2.as_posix()}"\nimage = "pe32"\n'
    (d / "decompanion.toml").write_text(CONFIG.format(n1="tiny", p1=p1.as_posix(), second=second), newline="\n")
    (d / "decl").mkdir(exist_ok=True)
    (d / "decl" / "text.dcl").write_text("# code\n", newline="\n")
    (d / "decl" / "data.dcl").write_text("# data\n", newline="\n")
    return d


@pytest.fixture
def tiny(tmp_path):
    return make_project(tmp_path / "proj")


@pytest.fixture
def tiny2(tmp_path):
    return make_project(tmp_path / "proj2", two=True)


def unit(root: Path, name: str, *parts: str) -> Path:
    """Write src/<name>.c from its parts (the head region, then the functions, each with its address comment
    directly above its definition), a blank line between two parts; an empty part is left out."""
    p = Path(root) / "src" / f"{name}.c"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(x if x.endswith("\n") else x + "\n" for x in parts if x), newline="\n")
    return p


def dcp(root: Path, *args) -> tuple[int, str]:
    """Run the CLI in-process; (exit code, stdout)."""
    import contextlib
    import io

    from decompanion.cli import main
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = main(["--root", str(root), *args])
    return code, buf.getvalue()


VC6 = Path("C:/Tools/MSVC600-SP5PP")


def declare_vc6(root: Path, archives=("LIBC",), target: str | None = None, with_root: bool = True):
    """What a human declares for a project of The Guild Gold after `dcp init` (the real-binary tests): the VC6
    SP5 + PP builds, the root, the release flags, the static archives; each with a reason."""
    pre = ["--target", target] if target else []
    pairs = ["compiler=cl 12.00.9044", "linker=link 6.00.8447", "cflags=/O2 /Gy"] + ([f"root={VC6.as_posix()}"] if with_root else [])
    steps = [("toolchain", "declare", *pairs, "--why", "test: the Rich builds 9044 / 8447, VC6 SP5 + PP"),
             ("libs", "declare", *archives, "--why", "test: the static CRT the image links")]
    for step in (steps if with_root else steps[::-1]):     # the root declared: the archives first, one walk less
        code, out = dcp(root, *pre, *step)
        assert code == 0, out
