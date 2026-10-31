"""x86-32: the instruction-set plugin. Everything it does is the core's (native/dcp_core/src: cs.rs capstone,
x86.rs the walk's decoder, the normalised listing and the hunk explanations); here it names the key and gives the
reading commands capstone's text.
"""
from __future__ import annotations

from .. import native
from . import register
from .base import Isa, Line


@register
class X86(Isa):
    key = "x86"

    def disasm(self, code, va, fill_forms=()):
        """capstone's Intel text, unchanged."""
        from ..rules.engine import capstone_dll
        rows = native.core().x86_disasm(capstone_dll(), bytes(code), va, [bytes(f) for f in fill_forms])
        return [Line(a, size, text, fill) for a, size, text, fill in rows]
