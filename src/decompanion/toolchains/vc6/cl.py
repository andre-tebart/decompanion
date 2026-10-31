"""The VC6 installation under the toolchain root: where its compiler is and which header directories it searches
(`[toolchain] include_dirs`, `{toolchain.root}` expanded, before VC98/Include). The core runs CL, LINK and LIB
(native/dcp_core/src/vc6.rs).
"""
from __future__ import annotations

from pathlib import Path


def expand(root: Path | None, s: str) -> Path:
    return Path(s.replace("{toolchain.root}", str(root or "")))


class Tools:
    """The VC6 installation under `root` and the extra header directories of the configuration."""

    def __init__(self, root: Path | None, config: dict):
        self.root = Path(root) if root else None
        self.extra_include = [expand(root, s) for s in (config.get("include_dirs") or [])]

    def available(self) -> bool:
        return self.root is not None and (self.root / "VC98" / "Bin" / "CL.EXE").exists()

    @property
    def system_include(self) -> list[Path]:
        return [*self.extra_include, self.root / "VC98" / "Include"] if self.root else list(self.extra_include)
