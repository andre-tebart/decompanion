"""The instruction-set seam: what the code walk (rules/walk.py) needs from a decoder, independent of the
architecture and of the disassembler library.

The walk sees an instruction as a compact record (Ins): where it is, how long it is, how control leaves it
(its flow kind and direct target), the immediates and the memory displacements into the image it carries, the
table an indirect jump reads, and whether its bytes are one of the toolchain's alignment fill forms. Shapes the
walk needs beyond the record (the extent of a jump table, where an absolute address field may sit inside an
instruction) are asked from the decoder. x86-32 is the only implementation (isa/x86.py, capstone).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

# Flow kinds: how control leaves an instruction.
OTHER = 0       # control falls through to the next instruction
CALL = 1        # a call: `target` is the direct target, None for a call through a register or memory
JUMP = 2        # an unconditional jump to the direct `target`
CJUMP = 3       # a conditional (or otherwise falling-through) jump to the direct `target`
IJUMP = 4       # a jump through a register or memory, no target; `table` when it reads a table of code addresses
RET = 5         # a return
JUMPS = (JUMP, CJUMP, IJUMP)


class Ins:
    """One decoded instruction, reduced to what the walk reads: address, size, mnemonic (for the ISA's own shape
    readers), flow kind, the direct target of a call or jump (`target`), the memory operands whose displacement
    lies in the image (`mem`: (address, operand size)), every immediate operand (`imms`), the table an indirect
    jump reads (`table`), and whether the bytes are one alignment fill form of the toolchain (`fill`)."""
    __slots__ = ("addr", "size", "mn", "flow", "target", "mem", "imms", "table", "fill")

    def __init__(self, addr, size, mn, flow, target, mem, imms, table, fill):
        self.addr, self.size, self.mn, self.flow, self.target = addr, size, mn, flow, target
        self.mem, self.imms, self.table, self.fill = mem, imms, table, fill


@dataclass(frozen=True, slots=True)
class TableShape:
    """What the instructions before an indirect table jump say about its table: the width of one table entry
    (a code address), the number of entries the preceding bound check admits (None: no bound found), and the
    index table that selects the entry (a table of `index_size`-byte indices, None when there is none)."""
    entry_size: int
    bound: int | None
    index_table: int | None
    index_size: int = 1


class Decoder:
    """Decodes the code range [lo, hi) of an image into Ins records (memoised by address for one rule run).
    `code` holds the bytes of the range; `img` is the image."""
    img: object
    lo: int
    hi: int
    code: bytes

    def decode(self, addr: int) -> Iterator[Ins]:
        """Instructions from addr on, in address order, until the bytes stop decoding or the range ends."""
        raise NotImplementedError

    def table_shape(self, jump: Ins, recent: list[Ins]) -> TableShape:
        """The shape of the table the indirect jump `jump` reads (jump.table), from the instructions the walk
        executed before it in the same block (`recent`, oldest first, the jump itself last)."""
        raise NotImplementedError

    def field_starts(self, ins: Ins) -> range:
        """The addresses at which an absolute address field (a relocation site) may start inside the
        instruction: an immediate or displacement field, never the opcode."""
        raise NotImplementedError

    def read_entry(self, addr: int, size: int) -> int:
        """The unsigned `size`-byte value at addr inside the range (a table entry), in the ISA's byte order."""
        o = addr - self.lo
        return int.from_bytes(self.code[o:o + size], self.byteorder)

    byteorder = "little"


class Isa:
    """Base class of an instruction-set plugin."""
    key = "base"
    ptr_size = 4            # bytes of a code or data address
    byteorder = "little"

    def decoder(self, img, lo: int, hi: int, fill_forms) -> Decoder:
        """A decoder over the code range [lo, hi) of img; `fill_forms` are the toolchain's alignment fill byte
        forms (Toolchain.fill_forms), which the decoder marks on the records."""
        raise NotImplementedError

    # ------------------------------------------------------------------ the instruction diff (milestone 3)
    def listing(self, code: bytes, va: int, mask: bytes | None, image_range: tuple[int, int], fill_forms) -> list["Line"]:
        """The instructions of `code` placed at `va`, as normalised text for the instruction diff: every number
        that is an address of the image (inside image_range) and every value a masked (relocated) field holds
        reads `X`, so link-dependent values never differ. `mask` marks our relocated bytes (None: the
        original's bytes). Stops at the first byte that does not decode."""
        raise NotImplementedError

    def explain(self, xa: list[str], xb: list[str], context: list[str]) -> tuple[str, str] | None:
        """The ISA's explanation of one differing hunk (ours xa, the original's xb; `context` our whole
        function), as (class, note): `regs` equal after renaming general registers, `slots` after renaming
        stack slots (and registers), `order` the same instructions in another order after a register renaming,
        `sib` equal after exchanging base and index of scale-1 addressing modes, `fpu` only floating-point
        instructions differ. None: nothing explains it (a `code` hunk). The generic classes `fill` and `order`
        (the same multiset) are decided before this is asked."""
        return None

    def frame_delta(self, a: list[str], b: list[str]) -> tuple[int, int] | None:
        """(our frame size, the original's) when both listings (texts, ours a) allocate a stack frame of a
        constant size in their prologue and the sizes differ; None otherwise (no frame-aligned diff)."""
        return None

    def stack_mask(self, lines: list[str], frame: tuple[int, int]) -> list[str]:
        """The texts with every stack offset and the frame sizes of `frame` masked: the alignment key of the
        frame-aligned diff (match/diffclass.py)."""
        return list(lines)

    def frame_explain(self, xa: list[str], xb: list[str], frame: tuple[int, int]) -> str | None:
        """The note of a `frame` hunk: xa and xb (equal under stack_mask) differ in stack offsets only, each by 0
        or by the frame delta (our frame size minus the original's), the frame sizes by exactly the delta;
        None when they do not."""
        return None

    # ------------------------------------------------------------------ reading (milestone 4)
    def disasm(self, code: bytes, va: int, fill_forms=()) -> list["Line"]:
        """The instructions of `code` placed at `va` in the disassembler's own text (nothing normalised), for
        `dcp disasm`. Stops at the first byte that does not decode."""
        raise NotImplementedError

    def numbers(self, text: str) -> list[tuple[int, int, int]]:
        """(start, end, value) of every number in an instruction text of `disasm`: where `dcp disasm` puts a
        symbol name for an address."""
        return []

    def rename_registers(self, lines: list[str], mapping: dict[str, str]) -> list[str]:
        """The listing texts with registers renamed (`dcp asmdiff --regs a=b,...`)."""
        return list(lines)

    def one_renaming(self, a: list[str], b: list[str]) -> bool:
        """The whole function (ours a, the original's b) is equal under one bijective renaming of registers and
        stack slots applied everywhere."""
        return False


@dataclass(frozen=True, slots=True)
class Line:
    """One instruction of a listing: address, size, the normalised text, whether its bytes are a fill form, and
    the target of a direct branch (a jump with an immediate target no relocation of ours rewrites; the text
    reads it as X), else None."""
    addr: int
    size: int
    text: str
    fill: bool
    target: int | None = None
