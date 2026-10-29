"""Visual C++ 6 (cl 12.00, link 6.00): the toolchain plugin. The conventions of CL and LINK the rules rest on
are stated here, once, as data (docs/architecture.md lists them)."""
from __future__ import annotations

from pathlib import Path

from .. import register
from ..base import CompileResult, LinkJob, LinkResult, RichProduct, Toolchain
from . import cl, rich
from .link import run_link

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

# `dcp toolchain probe`: the flags varied, one group at a time against the best combination. /Gy is fixed
# (function-level linking is what puts each function into a section of its own, the compare reads it). /GB
# ("blend", what CL targets without a /G option) joins the plan's /G3../G6: without it a declaration that names
# no /G option is not in the grid.
PROBE_GRID = (
    ("optimise", ("/O1", "/O2", "/Ox")),
    ("cpu", ("/G3", "/G4", "/G5", "/G6", "/GB")),
    ("frame", ("/Oy", "/Oy-")),
    ("comdat", ("/Gy",)),
    ("strings", ("/GF", "/Gf")),
    ("inline", ("/Ob0", "/Ob1", "/Ob2")),
)
# What CL does in each group when the command line names nothing of it under /O1 /O2 /Ox: /GB, frame
# pointer omission, read-only string pooling, /Ob1 (the probe's tie-break after the declared flags).
PROBE_DEFAULTS = ("/GB", "/Oy", "/GF", "/Ob1")

# The user entry each CRT start-up calls, as C, for the generated entry stub (entry_object): kind -> (C
# declaration of the entry with its call, parameters passed through).
ENTRY_STUBS = {
    "dll": ("#include <windows.h>\n{decl}\nBOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved)\n"
            "{{\n    return {user}(h, reason, reserved);\n}}\n",
            "BOOL WINAPI {user}(HINSTANCE h, DWORD reason, LPVOID reserved);"),
    "gui": ("#include <windows.h>\n{decl}\nint WINAPI WinMain(HINSTANCE h, HINSTANCE prev, LPSTR cmd, int show)\n"
            "{{\n    return {user}(h, prev, cmd, show);\n}}\n",
            "int WINAPI {user}(HINSTANCE h, HINSTANCE prev, LPSTR cmd, int show);"),
    "console": ("{decl}\nint main(int argc, char **argv)\n{{\n    return {user}(argc, argv);\n}}\n",
                "int {user}(int argc, char **argv);"),
}


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

    # -------------------------------------------------------------- the tools
    @property
    def tools(self) -> cl.Tools:
        t = self.__dict__.get("_tools")
        if t is None:
            t = self.__dict__["_tools"] = cl.Tools(self.root, self.config)
        return t

    def available(self) -> bool:
        """CL.EXE exists under VC98/Bin of the toolchain root."""
        return self.tools.available()

    def compile(self, src, obj, flags, include_dirs, cwd) -> CompileResult:
        """CL.EXE /nologo /c <flags> /I<dir>... /Fo<obj> <src> in cwd."""
        return cl.compile_one(self.tools, Path(src), Path(obj), list(flags), list(include_dirs), Path(cwd))

    def includes(self, src, flags, include_dirs, cwd):
        """CL.EXE /E (the /P listing on stdout): the paths of its `#line` directives."""
        return cl.preprocess_includes(self.tools, Path(src), list(flags), list(include_dirs), Path(cwd))

    def include_search_dirs(self, include_dirs):
        return [*include_dirs, *self.tools.system_include]

    def library_search_dirs(self) -> list[Path]:
        return self.tools.lib_path

    def undecorate(self, symbol: str) -> str:
        """`_f` (cdecl) and `_f@12` (stdcall) -> f, `@f@8` (fastcall) -> f; C++ names (`?f@@...`) stay."""
        if symbol.startswith("?"):
            return symbol
        s = symbol
        if s.startswith("@"):
            s = s[1:]
        elif s.startswith("_"):
            s = s[1:]
        at = s.rfind("@")
        if at > 0 and s[at + 1:].isdigit():
            s = s[:at]
        return s

    def data_symbol(self, cname: str) -> str:
        """`_` + the C name (C linkage)."""
        return "_" + cname

    def link(self, job: LinkJob) -> LinkResult:
        """LINK.EXE @<response file>: the arguments of toolchains/vc6/link.py link_args."""
        return run_link(self.tools, job)

    def default_libraries(self, kind: str) -> list[str]:
        """None beyond the target's archives (the static CRT, LIBC.LIB) and the import libraries of its
        imports: VC6's objects name their CRT by a /DEFAULTLIB directive, which the target's archives satisfy."""
        return []

    def entry_object(self, kind: str, out_dir: Path, user_entry: str | None = None):
        """The CRT start-up calls DllMain / WinMain / main. When the function at the user entry has another
        name in the sources (`user_entry`), a stub source with the expected entry calling it is written to
        out_dir/entry.c and compiled; None when no stub is needed."""
        expected = {"dll": "DllMain", "gui": "WinMain", "console": "main"}.get(kind)
        if expected is None or user_entry is None or user_entry == expected:
            return None
        body, decl = ENTRY_STUBS[kind]
        src = Path(out_dir) / "entry.c"
        src.write_text(body.format(decl=decl.format(user=user_entry), user=user_entry), newline="\n")
        r = self.compile(Path("entry.c"), Path("entry.obj"), ["/O2", "/Gy"], [], out_dir)
        if not r.ok:
            raise RuntimeError("the entry stub does not compile:\n" + r.log)
        return Path(out_dir) / "entry.obj"

    def module_definition(self, name: str, exports) -> str:
        """LIBRARY <name> / EXPORTS <name> @<ordinal> (NONAME for an export without a name)."""
        lines = [f"LIBRARY {name}", "EXPORTS"]
        for e in sorted(exports, key=lambda e: e.ordinal):
            lines.append(f"    {e.name} @{e.ordinal}" if e.name else f"    Ord{e.ordinal} @{e.ordinal} NONAME")
        return "\n".join(lines) + "\n"

    def probe_grid(self):
        return list(PROBE_GRID)

    def probe_defaults(self):
        return list(PROBE_DEFAULTS)
