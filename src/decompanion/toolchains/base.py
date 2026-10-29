"""The toolchain seam: everything the rules know about the compiler and linker that produced the image,
behind one class per toolchain family. VC6 is the only implementation (toolchains/vc6)."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RichProduct:
    prodid: int
    name: str           # the tool, in the usual Rich-header vocabulary (Utc12_2_C, Linker600, Masm613, ...)
    family: str         # compiler | linker | assembler | implib | import | cvtres | alias | unknown
    language: str = ""  # C | C++ | "" for non-compilers


class Toolchain:
    key = "base"

    def __init__(self, root: Path | None, config: dict):
        self.root = Path(root) if root else None
        self.config = config

    # -------------------------------------------------------------- facts about the output
    @property
    def fill_forms(self) -> tuple[bytes, ...]:
        """The byte forms the linker / compiler leave as alignment fill between functions."""
        raise NotImplementedError

    def rich_product(self, prodid: int) -> RichProduct:
        raise NotImplementedError

    def build_name(self, family: str, build: int) -> str:
        """A human name for a tool build, e.g. 9044 -> 'VC6 SP5 / Processor Pack'. '' when unknown."""
        return ""

    def crt_entry_symbols(self) -> dict[str, str]:
        """CRT entry symbols -> what they start: {'_DllMainCRTStartup@12': 'dll', '_WinMainCRTStartup': 'gui', ...}."""
        return {}

    def crt_user_entry(self, entry_symbol: str) -> str:
        """The user entry the CRT entry calls (DllMain, WinMain, main) or ''."""
        return ""

    # -------------------------------------------------------------- the toolchain on disk (later milestones)
    def library_archives(self) -> list[Path]:
        return []

    def compile(self, *a, **k):
        raise NotImplementedError

    def includes(self, *a, **k):
        raise NotImplementedError
