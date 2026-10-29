"""LINK.EXE 6.00: the full link of a target (lifted from the first attempt's link/link.py full_link).

The arguments go into a response file: /NOLOGO /OUT /OPT:REF /OPT:ICF /MAP, /DLL /BASE:<image base> /DEF for a
dll, the subsystem, the objects in link order, one /INCLUDE per function symbol (so /OPT:REF keeps every
function and checks its references), then the libraries. Unresolved externals are read from the LNK2001 /
LNK2019 lines.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..base import LinkJob, LinkResult
from .cl import Tools, diagnostics

UNRESOLVED = re.compile(r"unresolved external symbol\s+(\S+)")


def link_args(job: LinkJob) -> list[str]:
    def rel(p):
        p = Path(p)
        try:
            return p.relative_to(job.cwd).as_posix() if p.is_absolute() else p.as_posix()
        except ValueError:
            return str(p)
    args = ["/NOLOGO", "/OUT:" + rel(job.out), "/OPT:REF", "/OPT:ICF", "/MAP:" + rel(job.map_file), "/MACHINE:IX86"]
    if job.dll:
        args += ["/DLL", f"/BASE:{job.base:#x}"]
        if job.def_file is not None:
            args.append("/DEF:" + rel(job.def_file))
    if job.subsystem:
        args.append("/SUBSYSTEM:" + {"gui": "WINDOWS", "console": "CONSOLE"}.get(job.subsystem, job.subsystem))
    if job.entry:
        args.append("/ENTRY:" + job.entry)
    args += [rel(o) for o in job.objects]
    args += [f"/INCLUDE:{s}" for s in job.includes]
    args += [rel(l) if (isinstance(l, Path) or "/" in str(l) or "\\" in str(l)) else str(l) for l in job.libraries]
    return args


def run_link(tools: Tools, job: LinkJob) -> LinkResult:
    args = link_args(job)
    rsp = job.rsp or Path(job.out).with_suffix(".rsp")
    rsp_abs = rsp if rsp.is_absolute() else Path(job.cwd, rsp)
    rsp_abs.parent.mkdir(parents=True, exist_ok=True)
    rsp_abs.write_text("\n".join(args) + "\n", newline="\n")
    try:
        rel_rsp = rsp_abs.relative_to(job.cwd).as_posix()
    except ValueError:
        rel_rsp = str(rsp_abs)
    r = tools.run("LINK.EXE", ["@" + rel_rsp], job.cwd)
    log = (r.stdout + r.stderr).replace("\r\n", "\n")
    unresolved = sorted({m.group(1) for m in UNRESOLVED.finditer(log)})
    diags, _ = diagnostics(log)
    errors = [d.text() for d in diags if d.severity == "error" and d.code not in ("LNK2001", "LNK2019", "LNK1120")]
    return LinkResult(r.returncode == 0, log, unresolved, errors, args)
