"""The names the ledger knows for addresses, as the reading and drafting commands spell them (dcp disasm, dump,
refs, draft): one C name per address, chosen by a fixed order of origins, never guessed.

Order (the first origin that names an address wins):
  source   the definition in our sources (L.src: a sourced function, a data definition or extern)
  decl     `ADDR name NAME` in decl/*.dcl
  export   the export table (proven)
  entry    the user entry the start-up code calls (S.entry.user: DllMain, WinMain, main)
  lib      a placed library member's symbol (S.crt.code / S.crt.refs / S.crt.data), undecorated by the
           toolchain (`_fclose` -> fclose); of `a|b` aliases the first in sorted order
  import   an import slot (`KERNEL32.dll!GetTickCount` -> GetTickCount) and the import thunk that jumps through
           it (`thunk:WS2_32.dll!#3`: by ordinal, no name)
  analyzer the name the analyzer gave a function it found (its drafts, `dcp setup`), unless the analyzer calls
           it one of its own placeholders (Analyzer.is_placeholder; Ghidra: FUN_, thunk_FUN_, LAB_, ...)
A thunk or slot imported by ordinal takes the analyzer's name for it when there is one (Ghidra knows the
ordinals of the common system DLLs).

The names are the core's (native/dcp_core/src/names.rs); this module is its face.
"""
from __future__ import annotations

from .. import native


def Names(project, store):
    """address -> (C name, origin), name -> addresses (by_name, all_at); the symbol covering an address and its
    label as the reading commands spell it."""
    return native.core().Names(store._p, store._main, str(project.image_path))
