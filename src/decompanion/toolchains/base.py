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

    def declare(self, entry: dict) -> str:
        """The declaration spelling of a Rich compiler or linker entry ('cl 12.00.9044', 'link 6.00.8447')."""
        return f"{entry['tool']} {entry['build']}"

    def rich_candidates(self, entries, comp_ids=None) -> dict:
        """The decoded Rich header: every entry with its tool, family, language, build, object count and the
        number of configured archive objects whose @comp.id names the same (prodid, build); the compiler
        candidates (every compiler entry) and the linker candidates (every linker entry). Nothing is picked:
        which candidate built the user's objects is a declaration ([[target]] compiler / linker)."""
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
        """The user entry the CRT entry calls (DllMain, WinMain, main) or ''."""
        return ""

    # -------------------------------------------------------------- the toolchain on disk (later milestones)
    def library_archives(self) -> list[Path]:
        return []

    def compile(self, *a, **k):
        raise NotImplementedError

    def includes(self, *a, **k):
        raise NotImplementedError
