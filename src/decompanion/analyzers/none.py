"""No analyzer: nothing is exported, `dcp draft` writes `@rough` skeletons from the disassembly."""
from __future__ import annotations

from . import register
from .base import Analyzer, Install


@register
class NoAnalyzer(Analyzer):
    key = "none"

    def available(self) -> Install:
        return Install("none", note="no analyzer configured: no drafts, dcp draft writes @rough skeletons")
