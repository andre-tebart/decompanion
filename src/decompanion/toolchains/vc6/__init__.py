"""Visual C++ 6 (cl 12.00, link 6.00): the toolchain plugin. The conventions of CL and LINK the rules rest on
are stated here, once, as data (docs/architecture.md lists them)."""
from __future__ import annotations

from pathlib import Path

from .. import register
from ..base import Install, Toolchain
from . import cl
from . import install as places

C89_HEADERS = frozenset(("assert.h", "ctype.h", "errno.h", "float.h", "limits.h", "locale.h", "math.h", "setjmp.h", "signal.h",
                         "stdarg.h", "stddef.h", "stdio.h", "stdlib.h", "string.h", "time.h"))

# The libraries of an installation, under the toolchain root.
LIB_DIR = ("VC98", "Lib")
# The release flags of a VC6 project wizard (/O2: maximise speed; /Gy: function-level linking): evidence for the
# cflags obligation until `dcp toolchain probe` distinguishes them (milestone 3); never written by the tool.
WIZARD_CFLAGS = ("/O2", "/Gy")
# Strings of VC6's C run time (crt0msg.c, the heap selection of heapinit.c): their presence in an image is
# evidence that it links the static CRT.
CRT_STRINGS = (b"Microsoft Visual C++ Runtime Library", b"__MSVCRT_HEAP_SELECT", b"runtime error ")


@register
class VC6(Toolchain):
    key = "vc6"
    keywords = frozenset("__cdecl __stdcall __fastcall __thiscall __int64 __declspec __asm".split())
    default_convention = "__cdecl"                          # CL's default (/Gd)
    sized_conventions = ("__stdcall", "__fastcall", "__thiscall")   # `_f@12`, `@f@8`: the name needs the parameters

    # -------------------------------------------------------------- evidence for the guided decisions
    def installs(self) -> list[Install]:
        """The roots of places.candidates() ($VC6_ROOT, C:/Tools/*, Program Files/Microsoft Visual Studio)."""
        return [self.install(r) for r in places.candidates()]

    def install(self, root: Path) -> Install:
        """The versions of CL.EXE, C1.DLL, C2.DLL and LINK.EXE (version resources); the compiler build is C2's
        (the back end's build is what a Rich compiler entry records), the linker build LINK's."""
        v = places.versions(Path(root))
        build = lambda s: int(s.rsplit(".", 1)[1]) if s else None  # noqa: E731
        return Install(Path(root), v, build(v.get("c2")), build(v.get("link")), "cl" in v)

    def crt_strings(self, image) -> list[tuple[int, str]]:
        """Every occurrence of CRT_STRINGS in the raw data of the image's sections."""
        out = []
        for s in image.sections:
            raw = image.section_data(s)
            for needle in CRT_STRINGS:
                p = raw.find(needle)
                while p >= 0:
                    out.append((s.va + p, needle.decode("ascii")))
                    p = raw.find(needle, p + 1)
        return sorted(out)

    def archive_spec(self, name: str) -> str:
        """LIBCMT or LIBCMT.LIB -> {toolchain.root}/VC98/Lib/LIBCMT.LIB; a name with a slash is a path."""
        if "/" in name or "\\" in name:
            return Path(name).as_posix()
        n = name.upper() if name.upper().endswith(".LIB") else name.upper() + ".LIB"
        return "{toolchain.root}/" + "/".join(LIB_DIR) + "/" + n

    def wizard_cflags(self) -> list[str]:
        return list(WIZARD_CFLAGS)

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

    def declaring_header(self, name: str) -> str | None:
        """The first header of VC98/Include that declares `name` as a cdecl function in a C compile (the C
        library's: `_CRTIMP char * __cdecl strrchr(const char *, int);`), the C89 standard headers first, then
        alphabetical (memset: string.h, not memory.h): the front end's (source/cparse.function_headers, the
        project's libclang, else the default one), once per process."""
        idx = self.__dict__.get("_decls")
        if idx is None:
            from ...source import cparse
            dirs = [d for d in self.tools.system_include if d.exists()]
            headers = sorted({h.name for d in dirs for h in d.glob("*.h")},
                             key=lambda n: (n.lower() not in C89_HEADERS, n.lower()))
            if cparse._loaded is None and cparse.library(None) is not None:
                cparse.load(cparse.library(None))
            idx = cparse.function_headers(dirs, headers) if headers and cparse._loaded is not None else {}
            self.__dict__["_decls"] = idx
        return idx.get(name)

    def import_header(self, dll: str) -> str | None:
        """The Win32 API of every system DLL is declared through <windows.h> (it includes winsock.h and
        mmsystem.h unless WIN32_LEAN_AND_MEAN)."""
        return "windows.h"
