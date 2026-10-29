"""The names the ledger knows for addresses, as the reading and drafting commands spell them (dcp disasm, dump,
refs, draft): one C name per address, chosen by a fixed order of origins, never guessed.

Order (the first origin that names an address wins):
  source   the definition in our sources (L.src: a fragment's function, a data definition or extern)
  decl     `ADDR name NAME` in decl/*.dcl
  export   the export table (proven)
  entry    the user entry the start-up code calls (S.entry.user: DllMain, WinMain, main)
  lib      a placed library member's symbol (S.crt.code / S.crt.refs / S.crt.data), undecorated by the
           toolchain (`_fclose` -> fclose); of `a|b` aliases the first in sorted order
  import   an import slot (`KERNEL32.dll!GetTickCount` -> GetTickCount) and the import thunk that jumps through
           it (`thunk:WS2_32.dll!#3`: by ordinal, no name)
  ghidra   the name Ghidra gave a function it found (`dcp ghidra export`), unless it is Ghidra's own placeholder
           (FUN_, thunk_FUN_, LAB_, SUB_)
A thunk or slot imported by ordinal takes Ghidra's name for it when there is one (Ghidra knows the ordinals of
the common system DLLs).
"""
from __future__ import annotations

import bisect
import re

from .fact import Kind

ORDER = ("source", "decl", "export", "entry", "lib", "import", "ghidra")
GHIDRA_PLACEHOLDER = re.compile(r"^(?:thunk_)?(?:FUN|LAB|SUB|DAT|PTR)_[0-9a-fA-F]+$")
IDENT = re.compile(r"^[A-Za-z_]\w*$")


class Names:
    """address -> (C name, origin), name -> addresses; data symbols and strings for operand annotation."""

    def __init__(self, project, store):
        from . import ghidra
        self.project = project
        self.store = store
        tc = project.toolchain
        cands: dict[int, list[tuple[int, str, str]]] = {}
        rank = {o: i for i, o in enumerate(ORDER)}
        for f in store.facts(Kind.name):
            origin = f.value.get("origin", "")
            raw = f.value["name"]
            if origin == "lib":
                names = sorted(tc.undecorate(n) for n in raw.split("|"))
                name = names[0]
            elif origin == "import":
                tail = raw.split("!", 1)[-1]
                name = tail if not tail.startswith("#") else None
                if raw.startswith("thunk:"):
                    origin = "import"
            else:
                name = raw
            if name and IDENT.match(name):
                cands.setdefault(f.lo, []).append((rank.get(origin, len(ORDER)), name, origin))
        for e in ghidra.entries(store):
            if e.name and not GHIDRA_PLACEHOLDER.match(e.name) and IDENT.match(e.name):
                cands.setdefault(e.start, []).append((rank["ghidra"], e.name, "ghidra"))
        self.at: dict[int, tuple[str, str]] = {}
        self.by_name: dict[str, list[int]] = {}
        for a, cs in cands.items():
            cs.sort()
            self.at[a] = (cs[0][1], cs[0][2])
            for _, n, _ in cs:
                lst = self.by_name.setdefault(n, [])
                if a not in lst:
                    lst.append(a)
        self.all_at = {a: sorted({(n, o) for _, n, o in cs}) for a, cs in cands.items()}
        syms = [f for f in store.facts(Kind.symbol) if not f.run.startswith("M.")]
        self.syms = sorted(((f.lo, f.hi, f) for f in syms), key=lambda t: (t[0], t[1]))
        self._los = [t[0] for t in self.syms]

    def name(self, a: int) -> str | None:
        n = self.at.get(a)
        return n[0] if n else None

    def origin(self, a: int) -> str | None:
        n = self.at.get(a)
        return n[1] if n else None

    def symbol(self, a: int):
        """The symbol fact (not the match phase's) covering a, or None."""
        i = bisect.bisect_right(self._los, a) - 1
        for j in range(i, max(i - 4, -1), -1):
            lo, hi, f = self.syms[j]
            if lo <= a < hi:
                return f
        return None

    def label(self, a: int) -> str | None:
        """How `dcp disasm` / `dcp dump` spell an address: its name, else `name+off` inside a named symbol (not an
        unknown run), else a string's text, else None."""
        n = self.name(a)
        if n:
            return n
        f = self.symbol(a)
        if f is None:
            return None
        sk = f.value.get("skind")
        if sk in ("unknown.code", "unknown.data"):         # no symbol: an offset from it would mean nothing
            return None
        base = self.name(f.lo)
        if base and a != f.lo:
            return f"{base}+{a - f.lo:#x}"
        if sk == "string" and a == f.lo:
            return '"' + self.project.image.cstr(a)[:40].decode("latin-1").replace("\n", "\\n") + '"'
        return None
