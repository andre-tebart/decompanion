"""The Ghidra analyzer: Ghidra headless over a target's binary, every function decompiled (`dcp setup` runs it).

Where Ghidra and its JDK are (first hit wins):
  Ghidra   [analyzer] root = "..." in decompanion.toml, else $GHIDRA_INSTALL_DIR, else the newest
           C:/Tools/ghidra_* directory holding support/analyzeHeadless(.bat)
  JDK      [analyzer] java_home = "...", else $JAVA_HOME, else the newest
           C:/Program Files/Eclipse Adoptium/jdk-21* directory (Ghidra 12 needs JDK 21)
  [analyzer] timeout = 60   seconds per function for the decompiler

The run: `analyzeHeadless <out_dir> <name> -import <binary> -processor <language> -overwrite -scriptPath
<package>/data/ghidra -postScript DcpExport.java <out_dir>/export.json <timeout> starts.txt` (out_dir is
build/ghidra/<target>, name its last part); when the project already holds the binary, `-process <binary
name> -noanalysis` instead (the analysis is kept in the project). The language comes from our instruction set
(LANGUAGES). starts.txt lists our function starts: where Ghidra has no function the script creates one, so
every function of ours gets a draft; those are marked `seeded` (tag DCP_SEEDED in the Ghidra project) and are
no claim of Ghidra's. The script (src/decompanion/data/ghidra/DcpExport.java) writes the REA batch_decompile
shape (parse) plus each function's body (start, end, size, address ranges). The log is <out_dir>/headless.log.

Ghidra's dialect (GhidraDialect, shared with the REA plugin, whose files are Ghidra output):
  placeholders   FUN_<hex>, thunk_FUN_<hex>, LAB_, SUB_, DAT_, PTR_ + hex: Ghidra's names for what it does not know
  functions      FUN_<hex> / thunk_FUN_<hex>, or a name Ghidra gave an address
  data labels    DAT_<hex>, _DAT_<hex>, PTR_..._<hex>, s_..._<hex>, u_..._<hex>, BYTE_ / WORD_ / DWORD_ / QWORD_ /
                 FLOAT_ / DOUBLE_ / UNK_..._<hex>, typed by the prefix (DATA_TYPES; else undefined4)
  types          undefined1..8, uint, byte, CONCAT / SUB / ZEXT / SEXT ...: data/dcp_ghidra.h
"""
from __future__ import annotations

import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from ..ledger.store import file_hash
from . import register
from .base import Analyzer, AnalyzerError, Entry, Export, Install, Names

DATA = Path(__file__).resolve().parents[1] / "data"
SCRIPT = DATA / "ghidra" / "DcpExport.java"
HEADER = DATA / "dcp_ghidra.h"
LANGUAGES = {"x86": "x86:LE:32:default"}            # our isa key -> Ghidra's language id

PLACEHOLDER = re.compile(r"^(?:thunk_)?(?:FUN|LAB|SUB|DAT|PTR)_[0-9a-fA-F]+$")
FUN = re.compile(r"\b(?:thunk_)?FUN_([0-9a-fA-F]{8})\b")
LABEL = re.compile(r"\b(_?DAT|PTR|s|u|BYTE|WORD|DWORD|QWORD|FLOAT|DOUBLE|UNK)_\w*?([0-9a-fA-F]{8})\b")
DATA_TYPES = {"PTR": "undefined *", "s": "char []", "u": "char []", "BYTE": "undefined1", "WORD": "undefined2",
              "QWORD": "undefined8", "FLOAT": "float", "DOUBLE": "double"}


def parse(path: Path, key: str) -> tuple[str, list[Entry], list[str]]:
    """A file in the REA batch_decompile shape: (the analysed binary's sha256 or '', the ok entries, one message
    per item that failed). It holds `subject.digest.sha256` and `normalized_result.items`: per requested address
    its `status`, the `procedure` resolved (`address` = the function's entry, `name`), the `pseudocode`, and (our
    export only) the function's `body` (start, end exclusive, size in bytes, address ranges) and `seeded`."""
    d = json.loads(Path(path).read_text())
    digest = ((d.get("subject") or {}).get("digest") or {}).get("sha256", "")
    items = ((d.get("normalized_result") or {}).get("items")) or []
    out, failed = [], []
    for it in items:
        if it.get("status") != "ok" or "pseudocode" not in it:
            failed.append(f"{it.get('address')}: {it.get('status')} {it.get('error', '')}".strip())
            continue
        req = int(it["address"], 16)
        proc = it.get("procedure") or {}
        start = int(proc["address"], 16) if proc.get("address") else req
        text = it["pseudocode"].replace("\r\n", "\n").strip("\n") + "\n"
        body = it.get("body") or {}
        ranges = tuple((int(a, 16), int(b, 16)) for a, b in body.get("ranges") or ())
        end = int(body["end"], 16) if body.get("end") else None
        out.append(Entry(start, proc.get("name", ""), text, end, body.get("size"), ranges, bool(it.get("seeded")), req,
                         Path(path).name, key))
    return digest, out, failed


class GhidraDialect(Analyzer):
    """Reading Ghidra's output (module docstring); no run."""
    types_header = HEADER
    unknown_data_type = "undefined4"

    def is_placeholder(self, name: str) -> bool:
        return bool(PLACEHOLDER.match(name))

    def rewrite(self, body: str, own: tuple[str, str], names: Names, labels: dict[str, int]) -> str:
        theirs, ours = own
        out = body
        if theirs:
            out = re.sub(rf"\b{re.escape(theirs)}\b", ours, out)
        out = FUN.sub(lambda m: names.func(int(m.group(1), 16)), out)
        named = {n: a for n, a in labels.items() if not FUN.fullmatch(n) and n != theirs}
        if named:
            pat = re.compile(r"\b(" + "|".join(sorted(map(re.escape, named), key=len, reverse=True)) + r")\b")
            out = pat.sub(lambda m: names.func(named[m.group(1)]), out)
        return LABEL.sub(lambda m: names.data(int(m.group(2), 16)), out)

    def data_labels(self, body: str) -> dict[int, str]:
        types: dict[int, str] = {}
        for m in LABEL.finditer(body):
            types.setdefault(int(m.group(2), 16), DATA_TYPES.get(m.group(1), self.unknown_data_type))
        return types


def _newest(pattern: str, must: str | None = None) -> Path | None:
    hits = sorted((Path(p) for p in glob.glob(pattern)), key=lambda p: p.name)
    hits = [p for p in hits if p.is_dir() and (must is None or (p / must).exists())]
    return hits[-1] if hits else None


@register
class Ghidra(GhidraDialect):
    key = "ghidra"

    def available(self) -> Install:
        """Ghidra's installation and the JDK (module docstring), or what was looked at."""
        cfg = self.config
        exe = "analyzeHeadless.bat" if sys.platform == "win32" else "analyzeHeadless"
        if cfg.get("root"):
            root, tried = self.expand(cfg["root"]), f"[analyzer] root = {self.expand(cfg['root']).as_posix()}"
        elif os.environ.get("GHIDRA_INSTALL_DIR"):
            root = Path(os.environ["GHIDRA_INSTALL_DIR"])
            tried = f"$GHIDRA_INSTALL_DIR = {root.as_posix()}"
        else:
            root, tried = _newest("C:/Tools/ghidra_*", f"support/{exe}"), "C:/Tools/ghidra_*"
        if root is None or not (root / "support" / exe).exists():
            return Install(reason=f"Ghidra not found ({tried}): set [analyzer] root = \"...\" in decompanion.toml or "
                                  f"$GHIDRA_INSTALL_DIR to the installation (the folder that holds support/analyzeHeadless)")
        if cfg.get("java_home"):
            java = self.expand(cfg["java_home"])
        elif os.environ.get("JAVA_HOME"):
            java = Path(os.environ["JAVA_HOME"])
        else:
            java = _newest("C:/Program Files/Eclipse Adoptium/jdk-21*", "bin")
        if java is not None and not (java / "bin").exists():
            return Install(reason=f"the JDK {java.as_posix()} has no bin/ ([analyzer] java_home or $JAVA_HOME)")
        return Install(root.as_posix(), None, {"root": root, "headless": root / "support" / exe, "java_home": java,
                                               "timeout": int(cfg.get("timeout", 60))})

    def script_hash(self) -> str:
        return file_hash(SCRIPT)

    def export(self, install: Install, image, isa_key: str, starts: list[int], out_dir: Path) -> Export:
        """Run analyzeHeadless with the export script (import and analyse, or reuse the project's analysis)."""
        lang = LANGUAGES.get(isa_key)
        if lang is None:
            raise AnalyzerError(f"no Ghidra language for the instruction set {isa_key!r} (analyzers/ghidra.py LANGUAGES)")
        d = Path(out_dir)
        d.mkdir(parents=True, exist_ok=True)
        out, log = d / "export.json", d / "headless.log"
        name, binary = d.name, Path(image.path)
        rep = d / f"{name}.rep"
        t0 = time.perf_counter()
        for attempt in (0, 1):
            if out.exists():
                out.unlink()
            have = (d / f"{name}.gpr").exists() and (rep / "idata").exists() and any((rep / "idata").rglob("*.prp"))
            args = [str(install.detail["headless"]), str(d), name]
            args += ["-process", binary.name, "-noanalysis"] if have else ["-import", str(binary), "-processor", lang, "-overwrite"]
            st = d / "starts.txt"
            st.write_text("".join(f"{a:#010x}\n" for a in starts), newline="\n")
            args += ["-scriptPath", str(SCRIPT.parent), "-postScript", SCRIPT.name, str(out), str(install.detail["timeout"]), str(st)]
            env = dict(os.environ)
            if install.detail["java_home"] is not None:
                env["JAVA_HOME"] = str(install.detail["java_home"])
            with open(log, "w", encoding="utf-8", errors="replace") as fh:
                r = subprocess.run(args, stdout=fh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=env, cwd=d)
            if out.exists() or not have or attempt:
                break
            (d / f"{name}.gpr").unlink(missing_ok=True)       # a stale or foreign project: import afresh, once
            shutil.rmtree(rep, ignore_errors=True)
        ms = int((time.perf_counter() - t0) * 1000)
        if not out.exists():
            lines = [l for l in log.read_text(errors="replace").splitlines() if "ERROR" in l or "Exception" in l]
            raise AnalyzerError((lines[-1].strip() if lines else f"analyzeHeadless exit {r.returncode}, no export written")
                                + f" (log: {log.as_posix()})")
        digest, entries, failed = parse(out, self.key)
        return Export(entries, failed, digest, ms, out, log)
