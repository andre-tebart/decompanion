"""The instruction-set seam: a plugin names its key (a target's `isa`); the walk, the listings, the instruction diff
and its explanations are the core's (native/dcp_core/src/x86.rs)."""
from __future__ import annotations


class Isa:
    """Base class of an instruction-set plugin."""
    key = "base"
