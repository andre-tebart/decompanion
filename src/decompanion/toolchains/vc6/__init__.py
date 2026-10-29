"""Visual C++ 6 (cl 12.00, link 6.00): the toolchain plugin. The conventions of CL and LINK the rules rest on
are stated here, once, as data (docs/architecture.md lists them)."""
from __future__ import annotations

from pathlib import Path

from .. import register
from ..base import RichProduct, Toolchain
from . import rich

# The alignment fill VC6 / LINK leave between functions: nop, int3, mov edi,edi, lea ecx,[ecx+0]. Counted in
# GildeGold.exe (2026-10-23, the first attempt); one other instruction makes a run not fill.
FILL_FORMS = (b"\x90", b"\xcc", b"\x8b\xff", b"\x8d\x49\x00")
INT3 = 0xCC         # LINK pads between section contributions with int3; CL aligns inside one object with nops

# VC6 starts every compiled function at a 16-byte boundary (CL /O2 aligns function COMDATs to 16).
FUNCTION_ALIGNMENT = 16

# LINK's import stub: `jmp dword ptr [slot]` (FF 25 <slot VA>), 6 bytes. CL emits the same bytes for `return
# f(...)` of a dllimport f, so the bytes alone name a candidate only.
STUB_OPCODE = b"\xff\x25"
STUB_SIZE = 6
STUB_PLACEMENT = ("LINK places every library contribution (an import library's stubs included) after the "
                  "objects of the command line, and packs the stubs of one import library back to back")

# The CRT start-up symbols, what they start, the decorated user entry each calls and its C name.
ENTRIES = (
    ("__DllMainCRTStartup@12", "dll", "_DllMain@12", "DllMain"),
    ("_DllMainCRTStartup@12", "dll", "_DllMain@12", "DllMain"),
    ("_WinMainCRTStartup", "gui", "_WinMain@16", "WinMain"),
    ("_mainCRTStartup", "console", "_main", "main"),
    ("_wWinMainCRTStartup", "gui", "_wWinMain@16", "wWinMain"),
    ("_wmainCRTStartup", "console", "_wmain", "wmain"),
)
CRT_ENTRIES = {crt: kind for crt, kind, _, _ in ENTRIES}
USER_ENTRIES = {user: cname for _, _, user, cname in ENTRIES}

# The static CRT a new project's targets place members of (S.crt.code), under the toolchain root.
LIB_DIR = ("VC98", "Lib")
DEFAULT_ARCHIVES = ("LIBC.LIB",)
# The release flags of a VC6 project wizard (/O2: maximise speed; /Gy: function-level linking), assumed until
# `dcp toolchain probe` distinguishes them (milestone 3).
DEFAULT_CFLAGS = ("/O2", "/Gy")


@register
class VC6(Toolchain):
    key = "vc6"
    object_format = "coff"
    function_alignment = FUNCTION_ALIGNMENT
    import_stub_size = STUB_SIZE
    stub_placement = STUB_PLACEMENT

    @property
    def fill_forms(self):
        return FILL_FORMS

    def fill_origin(self, run: bytes) -> str:
        """`cc` (int3 only: LINK's padding between section contributions), `nop` (no int3: CL's alignment inside
        one object, proves nothing), `mixed`."""
        return "cc" if set(run) == {INT3} else ("nop" if INT3 not in run else "mixed")

    def import_stubs(self, data: bytes):
        p = data.find(STUB_OPCODE)
        while p >= 0:
            if p + STUB_SIZE <= len(data):
                yield p, int.from_bytes(data[p + len(STUB_OPCODE):p + STUB_SIZE], "little")
            p = data.find(STUB_OPCODE, p + 1)

    def archive_tools(self, stamps):
        """`@comp.id` holds prodid << 16 | build."""
        out: dict[tuple[int, int], int] = {}
        for v, n in stamps.items():
            k = (v >> 16, v & 0xffff)
            out[k] = out.get(k, 0) + n
        return out

    def rich_product(self, prodid: int) -> RichProduct:
        return rich.product(prodid)

    def build_name(self, family: str, build: int) -> str:
        return rich.COMPILER_BUILDS.get(build, "")

    def declare(self, entry: dict) -> str:
        """cl <major.minor>.<build> for a compiler entry, link <major.minor>.<build> for a linker entry."""
        tool = {"compiler": "cl", "linker": "link"}.get(entry["family"], entry["tool"])
        ver = rich.tool_version(entry["tool"])
        return f"{tool} {ver}.{entry['build']}" if ver else f"{tool} {entry['build']}"

    def crt_entry_symbols(self):
        return dict(CRT_ENTRIES)

    def crt_user_entry(self, entry_symbol: str) -> str:
        return next((user for crt, _, user, _ in ENTRIES if crt == entry_symbol), "")

    def user_entry_names(self):
        return dict(USER_ENTRIES)

    def library_archives(self) -> list[Path]:
        if self.root is None:
            return []
        return sorted(self.root.joinpath(*LIB_DIR).glob("*.LIB"))

    def lib_path(self, name: str) -> Path | None:
        if self.root is None:
            return None
        p = self.root.joinpath(*LIB_DIR, name)
        return p if p.exists() else None

    def default_archives(self) -> list[str]:
        return ["{toolchain.root}/" + "/".join(LIB_DIR) + "/" + a for a in DEFAULT_ARCHIVES]

    def default_cflags(self) -> list[str]:
        return list(DEFAULT_CFLAGS)

    def import_library_name(self, dll: str) -> str:
        """KERNEL32.dll -> kernel32.lib."""
        return dll.lower().rsplit(".", 1)[0] + ".lib"
