"""Visual C++ 6 (cl 12.00, link 6.00): the toolchain plugin."""
from __future__ import annotations

from pathlib import Path

from ..base import RichProduct, Toolchain
from . import rich

# The alignment fill VC6 / LINK leave between functions: nop, int3, mov edi,edi, lea ecx,[ecx+0]. Counted in
# GildeGold.exe (2026-10-23, the first attempt); one other instruction makes a run not fill.
FILL_FORMS = (b"\x90", b"\xcc", b"\x8b\xff", b"\x8d\x49\x00")

CRT_ENTRIES = {
    "__DllMainCRTStartup@12": "dll",
    "_DllMainCRTStartup@12": "dll",
    "_WinMainCRTStartup": "gui",
    "_mainCRTStartup": "console",
    "_wWinMainCRTStartup": "gui",
    "_wmainCRTStartup": "console",
}
USER_ENTRIES = {"dll": "_DllMain@12", "gui": "_WinMain@16", "console": "_main"}


class VC6(Toolchain):
    key = "vc6"

    @property
    def fill_forms(self):
        return FILL_FORMS

    def rich_product(self, prodid: int) -> RichProduct:
        return rich.product(prodid)

    def build_name(self, family: str, build: int) -> str:
        return rich.COMPILER_BUILDS.get(build, "")

    def crt_entry_symbols(self):
        return dict(CRT_ENTRIES)

    def crt_user_entry(self, entry_symbol: str) -> str:
        kind = CRT_ENTRIES.get(entry_symbol, "")
        return USER_ENTRIES.get(kind, "")

    def library_archives(self) -> list[Path]:
        if self.root is None:
            return []
        return sorted((self.root / "VC98" / "Lib").glob("*.LIB"))

    def lib_path(self, name: str) -> Path | None:
        if self.root is None:
            return None
        p = self.root / "VC98" / "Lib" / name
        return p if p.exists() else None
