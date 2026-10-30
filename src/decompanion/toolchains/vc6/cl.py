"""CL.EXE and LINK.EXE of Visual C++ 6: the environment they run in, one process per translation unit, the
include set from the preprocessor's `#line` directives (VC6 has no /showIncludes), and the diagnostics.

The environment is lifted from the first attempt (rea core/build.py vc6_env): VC98/Bin and Common/MSDev98/Bin
(MSPDB60.DLL) on PATH, VC98/Include on INCLUDE, VC98/Lib on LIB; `[toolchain] include_dirs` / `lib_dirs`
(paths, `{toolchain.root}` expanded) are searched before them (an SDK newer than VC6's own headers).
"""
from __future__ import annotations

import functools
import os
import re
import subprocess
from pathlib import Path

from ..base import CompileResult, Diagnostic

# `file(line) : error C2065: 'x' : undeclared identifier`, `... : fatal error C1083: ...`, `... : warning C4013: ...`
SOURCE_DIAG = re.compile(r"^(.*?)\((\d+)\)\s*:\s*(fatal error|error|warning)\s+([A-Z]+\d+)\s*:\s*(.*)$")
# `Command line warning D4002 : ignoring unknown option '/G7'`, `cl : Command line error D2016 : ...`
COMMAND_DIAG = re.compile(r"^(?:\w+\s*:\s*)?Command line (fatal error|error|warning)\s+([A-Z]+\d+)\s*:\s*(.*)$")
# `foo.obj : error LNK2001: unresolved external symbol _x`, `LINK : fatal error LNK1181: ...`
LINK_DIAG = re.compile(r"^(.*?)\s*:\s*(fatal error|error|warning)\s+(LNK\d+)\s*:\s*(.*)$")
LINE_DIRECTIVE = re.compile(r'^#line\s+\d+\s+"((?:[^"\\]|\\.)*)"', re.M)
# Command-line diagnostics that mean a flag was not applied: unknown option, incompatible options.
REFUSED = {"D4002", "D2016", "D4024", "D2021"}
REFUSED_FLAG = re.compile(r"'(/[^']+)'")


def expand(root: Path | None, s: str) -> Path:
    return Path(s.replace("{toolchain.root}", str(root or "")))


class Tools:
    """The VC6 installation under `root` and the extra header / library directories of the configuration."""

    def __init__(self, root: Path | None, config: dict):
        self.root = Path(root) if root else None
        self.extra_include = [expand(root, s) for s in (config.get("include_dirs") or [])]
        self.extra_lib = [expand(root, s) for s in (config.get("lib_dirs") or [])]

    def available(self) -> bool:
        return self.root is not None and (self.root / "VC98" / "Bin" / "CL.EXE").exists()

    def require(self):
        if not self.available():
            raise RuntimeError(f"VC6 not found under the toolchain root {self.root} (VC98/Bin/CL.EXE)")

    @property
    def bindir(self) -> Path:
        return self.root / "VC98" / "Bin"

    @property
    def system_include(self) -> list[Path]:
        return [*self.extra_include, self.root / "VC98" / "Include"] if self.root else list(self.extra_include)

    @property
    def lib_path(self) -> list[Path]:
        return [*self.extra_lib, self.root / "VC98" / "Lib"] if self.root else list(self.extra_lib)

    @functools.cached_property
    def env(self) -> dict:
        self.require()
        path = os.pathsep.join([str(self.bindir), str(self.root / "Common" / "MSDev98" / "Bin"), os.environ.get("PATH", "")])
        return dict(os.environ, PATH=path, INCLUDE=";".join(str(p) for p in self.system_include),
                    LIB=";".join(str(p) for p in self.lib_path))

    def run(self, tool: str, args: list[str], cwd: Path) -> subprocess.CompletedProcess:
        return subprocess.run([str(self.bindir / tool), *args], cwd=cwd, env=self.env, capture_output=True, text=True,
                              errors="replace")


def diagnostics(text: str) -> tuple[list[Diagnostic], list[str]]:
    """(the diagnostics of a CL / LINK run, the flags the compiler refused)."""
    out, refused = [], []
    for line in text.splitlines():
        s = line.strip()
        m = SOURCE_DIAG.match(s)
        if m:
            sev = "warning" if m.group(3) == "warning" else "error"
            out.append(Diagnostic(m.group(1).strip(), int(m.group(2)), sev, m.group(4), m.group(5).strip()))
            continue
        m = COMMAND_DIAG.match(s)
        if m:
            sev = "warning" if m.group(1) == "warning" else "error"
            out.append(Diagnostic("", 0, sev, m.group(2), m.group(3).strip()))
            if m.group(2) in REFUSED:
                refused += REFUSED_FLAG.findall(m.group(3)) or [m.group(3).strip()]
            continue
        m = LINK_DIAG.match(s)
        if m:
            sev = "warning" if m.group(2) == "warning" else "error"
            out.append(Diagnostic(m.group(1).strip(), 0, sev, m.group(3), m.group(4).strip()))
    return out, refused


def include_args(include_dirs: list[Path]) -> list[str]:
    return [f"/I{p}" for p in include_dirs]


def compile_one(tools: Tools, src: Path, obj: Path, flags: list[str], include_dirs: list[Path], cwd: Path) -> CompileResult:
    """CL /nologo /c <flags> /I<dirs> /Fo<obj> <src>: one process, one unit."""
    if not tools.available():
        msg = f"VC6 not found under the toolchain root {tools.root} (VC98/Bin/CL.EXE)"
        return CompileResult(False, msg + "\n", [Diagnostic("", 0, "error", "toolchain", msg)])
    r = tools.run("CL.EXE", ["/nologo", "/c", *flags, *include_args(include_dirs), f"/Fo{obj}", str(src)], cwd)
    log = (r.stdout + r.stderr).replace("\r\n", "\n")
    diags, refused = diagnostics(log)
    ok = r.returncode == 0 and Path(cwd, obj).exists() and not refused
    return CompileResult(ok, log, diags, refused)


def syntax_check(tools: Tools, src: Path, flags: list[str], include_dirs: list[Path], cwd: Path) -> CompileResult:
    """CL /nologo /Zs <flags> /I<dirs> <src>: the syntax and type checks of the front end, no object."""
    if not tools.available():
        msg = f"VC6 not found under the toolchain root {tools.root} (VC98/Bin/CL.EXE)"
        return CompileResult(False, msg + "\n", [Diagnostic("", 0, "error", "toolchain", msg)])
    keep = [f for f in flags if f.upper() not in ("/C", "/ZS") and not f.upper().startswith(("/FO", "/FA", "/FD", "/FR"))]
    r = tools.run("CL.EXE", ["/nologo", "/Zs", *keep, *include_args(include_dirs), str(src)], cwd)
    log = (r.stdout + r.stderr).replace("\r\n", "\n")
    diags, refused = diagnostics(log)
    return CompileResult(r.returncode == 0 and not refused, log, diags, refused)


def preprocess_includes(tools: Tools, src: Path, flags: list[str], include_dirs: list[Path], cwd: Path) -> tuple[list[Path], str]:
    """The include set: CL /E (the /P listing on stdout) and every distinct path its `#line` directives name,
    resolved against cwd, without the unit itself."""
    if not tools.available():
        return [], f"VC6 not found under the toolchain root {tools.root}"
    keep = [f for f in flags if f[:2].upper() in ("/D", "/U", "/I") or f.upper() in ("/X", "/J", "/ZA", "/ZE")]
    r = tools.run("CL.EXE", ["/nologo", "/E", *keep, *include_args(include_dirs), str(src)], cwd)
    if r.returncode != 0:
        return [], (r.stderr or "").replace("\r\n", "\n")
    me = Path(cwd, src).resolve()
    seen, done = {}, set()
    for m in LINE_DIRECTIVE.finditer(r.stdout):
        if m.group(1) in done:                    # thousands of #line directives name a few hundred files
            continue
        done.add(m.group(1))
        raw = re.sub(r"\\(.)", r"\1", m.group(1))
        p = Path(raw)
        p = (p if p.is_absolute() else Path(cwd, p)).resolve()
        if p != me:
            seen.setdefault(str(p).lower(), p)
    return sorted(seen.values(), key=lambda p: str(p).lower()), ""
