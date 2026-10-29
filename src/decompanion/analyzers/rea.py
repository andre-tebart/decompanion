"""The REA analyzer: saved REA `batch_decompile` results instead of a tool run.

  [analyzer]
  plugin = "rea"
  file = "notes/rea/batch1.json"          (or a list of files; relative to the project)

`export` reads the files (the shape analyzers/ghidra.py `parse` reads: REA's decompiler is Ghidra, so the
dialect is Ghidra's and the plugin inherits it). A file whose digest names another binary is skipped for this
target (Export.skipped). The files' contents are the script hash: an edited file is read again by the next
`dcp setup`.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from . import register
from .base import AnalyzerError, Export, Install
from .ghidra import GhidraDialect, parse


@register
class Rea(GhidraDialect):
    key = "rea"

    def files(self) -> list[Path]:
        f = self.config.get("file")
        names = [f] if isinstance(f, str) else list(f or [])
        return [self.expand(n) for n in names]

    def available(self) -> Install:
        files = self.files()
        if not files:
            return Install(reason='no file: name the saved batch_decompile results with [analyzer] file = "..."')
        missing = [p.as_posix() for p in files if not p.exists()]
        if missing:
            return Install(reason="missing " + ", ".join(missing))
        return Install(", ".join(p.as_posix() for p in files), None, {"files": files})

    def script_hash(self) -> str:
        h = hashlib.sha256()
        for p in self.files():
            h.update(p.name.encode() + b"\0" + (p.read_bytes() if p.exists() else b"-") + b"\1")
        return h.hexdigest()

    def export(self, install: Install, image, isa_key: str, starts: list[int], out_dir: Path) -> Export:
        ex = Export()
        for p in install.detail["files"]:
            try:
                digest, entries, failed = parse(p, self.key)
            except (ValueError, KeyError) as e:
                raise AnalyzerError(f"{p.as_posix()}: not a batch_decompile result ({e})")
            if digest and digest != image.sha256:
                ex.skipped.append((p.name, digest))
                continue
            ex.entries += entries
            ex.failed += [f"{p.name}: {f}" for f in failed]
            ex.digest = ex.digest or digest
        return ex
