"""Where Visual C++ 6 lives on this machine and which builds an installation holds (the evidence of the
obligation toolchain.root; `dcp toolchain`, `dcp status`).

The places searched, in order (each a root that holds VC98/Bin/CL.EXE):
  $VC6_ROOT
  C:/Tools/*                                          (the convention of this project's machines)
  <Program Files>/Microsoft Visual Studio, <Program Files (x86)>/Microsoft Visual Studio   (the VC6 installer's default)

The versions are read from the files' version resources (VS_FIXEDFILEINFO), not by running the tools: CL.EXE is
only the driver (12.00.8804 from SP3 on); the build the Rich header records for a C object is the back end's,
C2.DLL (VC6 SP5 + Processor Pack: 13.00.9044; SP6: 12.00.9782), and LINK.EXE's for the linker entry. A file's
contents are read, never its time stamps.
"""
from __future__ import annotations

import os
import struct
from pathlib import Path

FIXED_FILE_INFO = b"\xbd\x04\xef\xfe"           # VS_FIXEDFILEINFO.dwSignature
FILES = (("cl", "VC98/Bin/CL.EXE"), ("c1", "VC98/Bin/C1.DLL"), ("c2", "VC98/Bin/C2.DLL"), ("link", "VC98/Bin/LINK.EXE"))


def file_version(path: Path) -> str | None:
    """major.minor(2 digits).build of a PE file's version resource, None when it has none."""
    try:
        b = Path(path).read_bytes()
    except OSError:
        return None
    i = b.find(FIXED_FILE_INFO)
    if i < 0 or i + 16 > len(b):
        return None
    ms, ls = struct.unpack_from("<II", b, i + 8)
    return f"{ms >> 16}.{ms & 0xffff:02d}.{ls >> 16}"


def versions(root: Path) -> dict[str, str]:
    """{cl, c1, c2, link: version} of the files present under one root."""
    out = {}
    for key, rel in FILES:
        v = file_version(Path(root) / rel)
        if v is not None:
            out[key] = v
    return out


def candidates() -> list[Path]:
    """Every root of the documented places that holds VC98/Bin/CL.EXE, in the order of the places, once each."""
    roots: list[Path] = []
    env = os.environ.get("VC6_ROOT")
    if env:
        roots.append(Path(env))
    tools = Path("C:/Tools")
    if tools.is_dir():
        roots.extend(sorted(p for p in tools.iterdir() if p.is_dir()))
    for var, default in (("ProgramFiles", "C:/Program Files"), ("ProgramFiles(x86)", "C:/Program Files (x86)")):
        roots.append(Path(os.environ.get(var, default)) / "Microsoft Visual Studio")
    out, seen = [], set()
    for r in roots:
        key = str(r.resolve()).lower() if r.exists() else str(r).lower()
        if key in seen or not (r / "VC98" / "Bin" / "CL.EXE").is_file():
            continue
        seen.add(key)
        out.append(r)
    return out
