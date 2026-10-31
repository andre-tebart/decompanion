"""The toolchain seam: what the guided decisions and drafting ask about the compiler and linker that produced the
image, behind one class per toolchain family. VC6 is the only implementation (toolchains/vc6). The rules, the
build and the link read the core's toolchain (native/dcp_core/src/toolchain.rs, vc6.rs).

The guided decisions (obligations.py; the plugin hands over evidence, it never declares anything):
  installs()             the installations found on this machine (Install: root, versions, builds)
  install(root)          what one root holds (versions of its tools, the compiler / linker builds they make)
  crt_strings(image)     the run-time library's own strings found in the image (evidence of the CRT)
  archive_spec(name)     how `dcp libs declare NAME` spells an archive in decompanion.toml
  wizard_cflags()        the flags the toolchain's project wizard writes (evidence for toolchain.cflags)
  declare / build_name   the Rich header vocabulary (the core's)
  available()            the compiler and linker are installed
Drafting: declaring_header(name), import_header(dll), the language beyond standard C (keywords,
default_convention, sized_conventions) that `dcp draft` spells declarations with.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .. import native


@dataclass(frozen=True)
class Install:
    """One installation of a toolchain: its root, the versions of its tools ({tool: version}), the compiler and
    linker builds it makes (what a Rich entry and a declaration name; None when unknown), and whether the
    plugin can run it."""
    root: Path
    versions: dict
    compiler_build: int | None
    linker_build: int | None
    ok: bool


class Toolchain:
    key = "base"
    # the language the compiler reads beyond standard C (`dcp draft` spells declarations with them)
    keywords: frozenset = frozenset()       # the compiler's own keywords (calling conventions, extended types)
    default_convention = ""                 # the calling convention a skeleton prototype spells ('' : none)
    sized_conventions: tuple = ()           # conventions whose decorated name carries the parameters' size: a
                                            # declaration of such a function needs its full prototype

    def __init__(self, root: Path | None, config: dict):
        self.root = Path(root) if root else None
        self.config = config

    def build_name(self, family: str, build: int) -> str:
        """A human name for a tool build, e.g. 9044 -> 'VC6 SP5 / Processor Pack'. '' when unknown."""
        return native.core().tc_build_name(self.key, family, build)

    def declare(self, entry: dict) -> str:
        """The declaration spelling of a Rich compiler or linker entry ('cl 12.00.9044', 'link 6.00.8447')."""
        return native.core().tc_declare(self.key, entry["tool"], entry["family"], entry["build"])

    # -------------------------------------------------------------- evidence for the guided decisions
    def installs(self) -> list[Install]:
        """Every installation of the toolchain found on this machine (the plugin knows its usual places)."""
        return []

    def install(self, root: Path) -> Install:
        """What one installation root holds: the versions its tools report and the builds they make."""
        return Install(Path(root), {}, None, None, False)

    def crt_strings(self, image) -> list[tuple[int, str]]:
        """(address, text) of the run-time library's own strings found in the image's sections."""
        return []

    def archive_spec(self, name: str) -> str:
        """The decompanion.toml spelling of an archive a human names (`dcp libs declare NAME`): a path stays a
        path, a bare name is the toolchain's archive of that name under `{toolchain.root}`."""
        return name

    def wizard_cflags(self) -> list[str]:
        """The flags the toolchain's project wizard writes for a release build: evidence for the obligation
        toolchain.cflags, never written by the tool."""
        return []

    def available(self) -> bool:
        """The compiler and linker are installed (else nothing compiles: the match rules say so as warnings)."""
        return False

    # -------------------------------------------------------------- drafting
    def declaring_header(self, name: str) -> str | None:
        """The system header (as `#include <...>` names it) that declares the C library function `name`, None when
        no header of the toolchain does (`dcp draft` includes it instead of writing a declaration)."""
        return None

    def import_header(self, dll: str) -> str | None:
        """The system header that declares the functions an imported DLL exports, None when unknown."""
        return None
