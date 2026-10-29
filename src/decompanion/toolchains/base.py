"""The toolchain seam: everything the rules know about the compiler and linker that produced the image,
behind one class per toolchain family. VC6 is the only implementation (toolchains/vc6).

What a plugin answers (the rules ask, they never know the answers themselves):
  object_format          the objfmt plugin of its objects and archives ("coff")
  fill_forms             the byte forms of alignment fill between functions; fill_origin(bytes) names a run
  function_alignment     the boundary every compiled function starts at
  import_stubs(data)     the import stubs (linker-made `jump through an import slot` thunks) in a code section's
                         bytes, import_stub_size their size, stub_placement the linker's layout convention
  user_entry_names()     the decorated symbols of the user's entry functions -> their C names
  archive_tools(stamps)  the objects' tool stamps (objfmt tool_stamps) decoded to Rich (prodid, build)
  rich_product / rich_candidates / declare / prefill / build_name   the Rich header vocabulary
  default_archives()     the static library archives of a new project; default_cflags() its assumed flags
  import_library_name(dll)   the import library a DLL is linked through
"""
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
    object_format = ""              # the objfmt plugin key of the toolchain's objects and archives
    function_alignment = 1          # every compiled function starts at a multiple of this
    import_stub_size = 0            # bytes of one import stub (0: the toolchain makes none)
    stub_placement = ""             # the linker's placement convention for import stubs, as prose (S.thunk cites it)

    def __init__(self, root: Path | None, config: dict):
        self.root = Path(root) if root else None
        self.config = config

    # -------------------------------------------------------------- facts about the output
    @property
    def fill_forms(self) -> tuple[bytes, ...]:
        """The byte forms the linker / compiler leave as alignment fill between functions."""
        raise NotImplementedError

    def fill_origin(self, run: bytes) -> str:
        """What a fill run before a function start says about the boundary (L.analyze B-FILL): a short word
        naming the form, e.g. linker padding between contributions vs compiler alignment inside one object."""
        raise NotImplementedError

    def import_stubs(self, data: bytes):
        """(offset, slot) of every import stub in `data` (the raw bytes of a code section): the bytes of a stub
        whose jump goes through the import address-table slot `slot` (a VA). Candidates only: the same bytes
        may be compiled code; S.thunk decides by stub_placement."""
        return iter(())

    def rich_product(self, prodid: int) -> RichProduct:
        raise NotImplementedError

    def build_name(self, family: str, build: int) -> str:
        """A human name for a tool build, e.g. 9044 -> 'VC6 SP5 / Processor Pack'. '' when unknown."""
        return ""

    def declare(self, entry: dict) -> str:
        """The declaration spelling of a Rich compiler or linker entry ('cl 12.00.9044', 'link 6.00.8447')."""
        return f"{entry['tool']} {entry['build']}"

    def archive_tools(self, stamps: dict[int, int]) -> dict[tuple[int, int], int]:
        """(Rich prodid, build) -> objects, from the archives' tool stamps (ObjectFormat.tool_stamps: raw stamp
        value -> objects)."""
        return {}

    def rich_candidates(self, entries, comp_ids=None) -> dict:
        """The decoded Rich header: every entry with its tool, family, language, build, object count and the
        number of configured archive objects whose tool stamp (archive_tools) names the same (prodid, build);
        the compiler candidates (every compiler entry) and the linker candidates (every linker entry). Nothing
        is picked: which candidate built the user's objects is a declaration ([[target]] compiler / linker)."""
        comp_ids = comp_ids or {}
        decoded = []
        for prodid, build, count in entries:
            p = self.rich_product(prodid)
            decoded.append({"prodid": prodid, "tool": p.name, "family": p.family, "language": p.language,
                            "build": build, "count": count, "archive_objects": comp_ids.get((prodid, build), 0)})
        order = sorted(decoded, key=lambda e: (-e["count"], -e["build"], e["prodid"]))
        return {"entries": decoded,
                "compilers": [e for e in order if e["family"] == "compiler"],
                "linkers": [e for e in order if e["family"] == "linker"]}

    def prefill(self, cands: dict, when: str) -> tuple[str, str, str]:
        """(compiler, linker, reason) to write into a new target's declaration: the compiler entry with the most
        objects among those no configured archive object was built with (all compiler entries when every one
        is), the linker entry with the most objects. A pre-filled declaration, for a human to verify."""
        comps = cands.get("compilers") or []
        links = cands.get("linkers") or []
        own = [e for e in comps if not e["archive_objects"]]
        why = []
        compiler = linker = ""
        if comps:
            c = (own or comps)[0]
            compiler = self.declare(c)
            why.append(f"the compiler entry with the most objects{' no configured archive object was built with' if own else ''} "
                       f"({c['tool']} {c['build']} x{c['count']})")
        if links:
            k = links[0]
            linker = self.declare(k)
            why.append(f"the linker entry with the most objects ({k['tool']} {k['build']} x{k['count']})")
        if not why:
            return compiler, linker, f"declared at {when}: the image has no Rich header; verify"
        return compiler, linker, f"picked at {when} from the Rich header: " + ", ".join(why) + "; flags assumed; verify"

    def crt_entry_symbols(self) -> dict[str, str]:
        """CRT entry symbols -> what they start: {'_DllMainCRTStartup@12': 'dll', '_WinMainCRTStartup': 'gui', ...}."""
        return {}

    def crt_user_entry(self, entry_symbol: str) -> str:
        """The decorated user entry the CRT entry calls or ''."""
        return ""

    def user_entry_names(self) -> dict[str, str]:
        """The decorated symbols of the user's entry functions (what the CRT start-up calls) -> their C names."""
        return {}

    # -------------------------------------------------------------- the toolchain on disk
    def library_archives(self) -> list[Path]:
        """Every library archive of the toolchain installation."""
        return []

    def default_archives(self) -> list[str]:
        """The static library archives a new project places members of (S.crt.code), as config strings
        (`{toolchain.root}` stands for the toolchain root)."""
        return []

    def default_cflags(self) -> list[str]:
        """The compiler flags a new target's declaration assumes until they are probed (for a human to verify)."""
        return []

    def import_library_name(self, dll: str) -> str:
        """The file name (lower case) of the import library a DLL is linked through."""
        raise NotImplementedError

    def compile(self, *a, **k):
        raise NotImplementedError

    def includes(self, *a, **k):
        raise NotImplementedError
