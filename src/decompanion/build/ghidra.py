"""`dcp ghidra export`: Ghidra headless over a target's binary, every function decompiled, imported as drafts.

Ghidra's analysis is a declaration ("ghidra analysis"), never a computed fact: its function starts become
declared `start` facts (L.ghidra), its pseudocode is draft text for `dcp draft`, its function bodies are
checked against our starts (L9). This module only runs the tool; ledger/ghidra.py stores what it wrote.

Where Ghidra and its JDK are (first hit wins):
  Ghidra   [ghidra] root = "..." in decompanion.toml, else $GHIDRA_INSTALL_DIR, else the newest
           C:/Tools/ghidra_* directory holding support/analyzeHeadless(.bat)
  JDK      [ghidra] java_home = "...", else $JAVA_HOME, else the newest
           C:/Program Files/Eclipse Adoptium/jdk-21* directory (Ghidra 12 needs JDK 21)
  [ghidra] timeout = 60   seconds per function for the decompiler

The run: `analyzeHeadless build/ghidra/<target> <target> -import <binary> -overwrite -scriptPath
<package>/data/ghidra -postScript DcpExport.java build/ghidra/<target>/export.json <timeout> starts.txt`; when the
project already holds the binary, `-process <binary name> -noanalysis` instead (the analysis is kept in the
project). starts.txt lists our function starts in the code sections (every start fact but Ghidra's own, every
walked or placed function; no inner label): where Ghidra has no function the script creates one, so every
function of ours gets a draft; those are marked `seeded` and give no Ghidra start fact. The script
(src/decompanion/data/ghidra/DcpExport.java) writes the REA batch_decompile shape plus each function's body
(start, end, size, address ranges). The headless log is build/ghidra/<target>/headless.log.

An export is keyed by (image sha256, script hash, our starts): a second export of the same image with the same
script and starts does nothing unless forced (store meta `ghidra.export`).
"""
from __future__ import annotations

import glob
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from ..ledger.store import file_hash, sha256

SCRIPT = Path(__file__).resolve().parents[1] / "data" / "ghidra" / "DcpExport.java"
META = "ghidra.export"


class GhidraMissing(RuntimeError):
    pass


@dataclass
class Setup:
    root: Path
    headless: Path
    java_home: Path | None
    timeout: int


def _newest(pattern: str, must: str | None = None) -> Path | None:
    hits = sorted((Path(p) for p in glob.glob(pattern)), key=lambda p: p.name)
    hits = [p for p in hits if p.is_dir() and (must is None or (p / must).exists())]
    return hits[-1] if hits else None


def locate(project) -> Setup:
    """Ghidra's installation and the JDK (module docstring); GhidraMissing with what was looked at."""
    cfg = project.cfg.get("ghidra") or {}
    exe = "analyzeHeadless.bat" if sys.platform == "win32" else "analyzeHeadless"
    tried = []
    root = None
    if cfg.get("root"):
        root = project.expand(cfg["root"])
        tried.append(f"[ghidra] root = {root}")
    elif os.environ.get("GHIDRA_INSTALL_DIR"):
        root = Path(os.environ["GHIDRA_INSTALL_DIR"])
        tried.append(f"$GHIDRA_INSTALL_DIR = {root}")
    else:
        root = _newest("C:/Tools/ghidra_*", f"support/{exe}")
        tried.append("C:/Tools/ghidra_*")
    if root is None or not (root / "support" / exe).exists():
        raise GhidraMissing("Ghidra not found (" + "; ".join(tried) + "): set [ghidra] root = \"...\" in decompanion.toml "
                            "or $GHIDRA_INSTALL_DIR to the installation (the folder that holds support/analyzeHeadless)")
    java = None
    if cfg.get("java_home"):
        java = project.expand(cfg["java_home"])
    elif os.environ.get("JAVA_HOME"):
        java = Path(os.environ["JAVA_HOME"])
    else:
        java = _newest("C:/Program Files/Eclipse Adoptium/jdk-21*", "bin")
    if java is not None and not (java / "bin").exists():
        raise GhidraMissing(f"the JDK {java} has no bin/ ([ghidra] java_home or $JAVA_HOME)")
    return Setup(root, root / "support" / exe, java, int(cfg.get("timeout", 60)))


def project_dir(project) -> Path:
    return project.build_dir / "ghidra" / project.target_name


def our_starts(project) -> list[int]:
    """Our function starts in the code sections (module docstring)."""
    from ..ledger.fact import Kind, Level
    st, img = project.store, project.image
    code = [(s.va, s.end) for s in img.sections if s.holds_code]
    out, inner = set(), set()
    for f in st.facts(Kind.start):
        if f.run != "L.ghidra":
            out.add(f.lo)
    for f in st.facts(Kind.symbol):
        if f.value.get("skind") == "func" and f.level > Level.open and not f.run.startswith("M."):
            out.add(f.lo)
            inner.update(f.value.get("inner", ()))
    return sorted(a for a in out - inner if any(lo <= a < hi for lo, hi in code))


def export_key(project) -> str:
    return sha256(project.image.sha256, file_hash(SCRIPT), ",".join(f"{a:x}" for a in our_starts(project)))


def up_to_date(project) -> bool:
    return project.store.meta(META) == export_key(project)


@dataclass
class Run:
    ok: bool
    json: Path
    log: Path
    ms: int
    message: str = ""


def run_headless(project, setup: Setup) -> Run:
    """Run analyzeHeadless with the export script (import and analyse, or reuse the project's analysis)."""
    d = project_dir(project)
    d.mkdir(parents=True, exist_ok=True)
    out = d / "export.json"
    log = d / "headless.log"
    if out.exists():
        out.unlink()
    name = project.target_name
    binary = project.image_path
    rep = d / f"{name}.rep"
    have = (d / f"{name}.gpr").exists() and (rep / "idata").exists() and any((rep / "idata").rglob("*.prp"))
    args = [str(setup.headless), str(d), name]
    if have:
        args += ["-process", binary.name, "-noanalysis"]
    else:
        args += ["-import", str(binary), "-overwrite"]
    starts = d / "starts.txt"
    starts.write_text("".join(f"{a:#010x}\n" for a in our_starts(project)), newline="\n")
    args += ["-scriptPath", str(SCRIPT.parent), "-postScript", SCRIPT.name, str(out), str(setup.timeout), str(starts)]
    env = dict(os.environ)
    if setup.java_home is not None:
        env["JAVA_HOME"] = str(setup.java_home)
    t0 = time.perf_counter()
    with open(log, "w", encoding="utf-8", errors="replace") as fh:
        r = subprocess.run(args, stdout=fh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=env, cwd=d)
    ms = int((time.perf_counter() - t0) * 1000)
    if have and not out.exists():                     # a stale or foreign project: import afresh, once
        import shutil
        (d / f"{name}.gpr").unlink(missing_ok=True)
        shutil.rmtree(rep, ignore_errors=True)
        again = run_headless(project, setup)
        again.ms += ms
        return again
    if not out.exists():
        lines = [l for l in log.read_text(errors="replace").splitlines() if "ERROR" in l or "Exception" in l]
        return Run(False, out, log, ms, (lines[-1].strip() if lines else f"analyzeHeadless exit {r.returncode}, no export written"))
    return Run(True, out, log, ms)
