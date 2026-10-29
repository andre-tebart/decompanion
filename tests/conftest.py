"""Fixtures: a tiny synthetic PE32 dll (no imports, no library code) and target projects around it.

Layout of the synthetic image (base 0x10000000):
  .text 0x10001000  f1 0x10001000: push ebp; mov ebp,esp; call f2; call f3; pop ebp; ret     (the entry point)
                    f2 0x10001020: mov eax,[0x10002000]; ret
                    f3 0x10001030: push "c:\\src\\net\\net.c"; push "hello"; add esp,8; ret
                    f4 0x10001050: push "world"; pop eax; ret                                 (called by nobody but f1's
                                                                                               table of pointers in .data)
  .data 0x10002000  a dword, then the strings, then a pointer to f4
  .reloc            the base relocations of every absolute operand
"""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

BASE = 0x10000000
TEXT, DATA, RELOC = 0x1000, 0x2000, 0x3000


def build_pe(path: Path, variant: int = 0) -> Path:
    """Write the synthetic dll; `variant` changes one data byte (another binary of the same codebase)."""
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
    struct.pack_into("<I", out, 0x3c, 0x80)
    pe = 0x80
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


CONFIG = '''[[target]]
name = "{n1}"
path = "{p1}"
image = "pe32"
{second}
[toolchain]
plugin = "vc6"
compiler = "cl 12.00.9044"
linker = "link 6.00.8447"
cflags = ["/O2"]
reason = "test project"

[libs]
archives = []
'''


def make_project(d: Path, two: bool = False) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    p1 = build_pe(d / "tiny.dll")
    second = ""
    if two:
        p2 = build_pe(d / "tiny2.dll", variant=1)
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


def dcp(root: Path, *args) -> tuple[int, str]:
    """Run the CLI in-process; (exit code, stdout)."""
    import contextlib
    import io

    from decompanion.cli import main
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = main(["--root", str(root), *args])
    return code, buf.getvalue()
