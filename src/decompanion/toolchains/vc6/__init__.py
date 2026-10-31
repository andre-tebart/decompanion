"""Visual C++ 6 (cl 12.00, link 6.00): the toolchain plugin. The conventions of CL and LINK the rules rest on
are stated here, once, as data (docs/architecture.md lists them)."""
from __future__ import annotations

from pathlib import Path

from .. import register
from ..base import Install, Toolchain
from . import install as places

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

    def available(self) -> bool:
        """CL.EXE exists under VC98/Bin of the toolchain root."""
        return self.root is not None and (self.root / "VC98" / "Bin" / "CL.EXE").exists()
