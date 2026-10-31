"""x86-32: the instruction-set plugin. Everything it does is the core's (native/dcp_core/src: cs.rs capstone,
x86.rs the walk's decoder, the normalised listing and the hunk explanations); here it names the key.
"""
from __future__ import annotations

from . import register
from .base import Isa


@register
class X86(Isa):
    key = "x86"
