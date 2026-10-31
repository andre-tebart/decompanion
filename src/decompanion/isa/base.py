"""The instruction-set seam: a plugin names its key and lists the original's instructions for the reading
commands (disasm, dump, draft skeletons); the walk, the listings of the instruction diff and its explanations are
the core's (native/dcp_core/src/x86.rs)."""
from __future__ import annotations

from dataclasses import dataclass


class Isa:
    """Base class of an instruction-set plugin."""
    key = "base"

    def disasm(self, code: bytes, va: int, fill_forms=()) -> list["Line"]:
        """The instructions of `code` placed at `va` as the tool spells them."""
        raise NotImplementedError


@dataclass(frozen=True)
class Line:
    """One instruction of a listing: address, size, the text, whether its bytes are a fill form."""
    addr: int
    size: int
    text: str
    fill: bool
    target: int | None = None
