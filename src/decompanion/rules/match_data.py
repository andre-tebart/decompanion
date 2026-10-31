"""Data rules (M.data.*, D*): where the data objects of the sources lie (lifted in part from the first attempt's
ledger/ledger_data.py and ledger/evidence.py; evidence kinds site and content; iat / lib and D2 / D3 / D7 /
D8 are later work).

A data object of the sources is a definition (or an `extern`) with an address comment (srcscan): the L.src
`source` facts (what: data) and `name` facts are its candidates. Its size and section kind come from the
object of its unit (ObjectFormat data_symbols: data / rdata / bss / common).

  M.data.site     [proven]   a byte-matched function's relocation refers to the data symbol and the original's
                             site holds exactly the declared address
  M.data.content  [proven]   the object's initialised bytes of the symbol (relocated fields masked) equal the
                             image's at the declared address and occur at no other address of the image's
                             initialised data
  M.data.draft    [declared] every other data definition with an address: it owns its declared extent
  D.data          D1 the declared extent overlaps the next symbol; D4 the definitions of one unit and section
                  kind are not in address order; D5 a tentative definition (common) declared in the original's
                  uninitialised data (it needs `= 0` to be placed with its unit); D6 a pointer-table entry of
                  ours refers to another address than the original's entry
"""
from __future__ import annotations

from ..ledger.fact import Level
from .engine import RuleContext, rule
from .match import WALK

P, D, DE, O = Level.proven, Level.derived, Level.declared, Level.open


@rule("M.data.site", version="2", ceiling=P, outputs=("symbol",), needs=("L.src", *WALK, "M.match"), inputs=("objects",), native=True)
def data_site(ctx: RuleContext):
    """A data definition with an address comment whose address a byte-matched function's absolute relocation
    to the same symbol confirms (the original's site holds exactly that address, Reloc.resolve with our
    addend) is placed: a `global` symbol proven over [address, address + the object's size of the symbol)
    {name, unit, extent: site}. Native:
    native/dcp_core/src/rules.rs."""
    return ()


@rule("M.data.content", version="3", ceiling=P, outputs=("symbol",), needs=("L.src", *WALK, "M.match"), inputs=("objects",), native=True)
def data_content(ctx: RuleContext):
    """A data definition with an address comment that M.data.site does not place, defined in an initialised
    section of its object with at least 4 bytes that are no relocated field, no possible alignment padding
    (padding_masked) and not all zero, whose bytes (relocated fields and possible padding masked) equal the image's at the declared address and occur at no other address of the
    image's initialised data sections: a `global` symbol proven {extent: content}. Found elsewhere only once
    and not at the declared address: an error (M.data.content): the declaration names another object's place. Native:
    native/dcp_core/src/rules.rs."""
    return ()


@rule("M.data.draft", version="2", ceiling=DE, outputs=("symbol",), needs=("L.src", "M.data.site", "M.data.content"),
      inputs=("objects",), native=True)
def data_draft(ctx: RuleContext):
    """Every data definition with an address comment that neither M.data.site nor M.data.content places owns
    its declared extent: a `global` symbol, declared, over [address, address + the object's size) (one byte
    when its unit has no object or the object lacks the symbol) {extent: draft}. Native:
    native/dcp_core/src/rules.rs."""
    return ()


@rule("D.data", version="5", ceiling=P, needs=("L.src", "M.data.site", "M.data.content", "M.data.draft", "S.crt.data",
                                              "S.strings", "S.imports", "S.relocs", "S.sections", "kind:name"),
      inputs=("objects", "src", "decl"), native=True)
def data_checks(ctx: RuleContext):
    """D1: a data definition's extent holds the start of another symbol (a data symbol of the sources, a CRT data
    block, a string, an import slot): an error when even its least size (least_size: the object's size without
    the alignment padding it may include) reaches it, a warning when only the padding may. D4: in one unit, the
    definitions of one section kind (data / rdata / bss) are not in increasing address order in the order the
    unit's file defines them (VC6 places a unit's definitions of a section in definition order). D5: a
    tentative definition (the object holds it as common: the linker allocates it apart from its unit) whose
    declared address lies in the image's uninitialised data (no file bytes): write it `= 0`. D6: an absolute
    relocation inside a definition of ours (a pointer-table entry) whose symbol has a registered address while
    the original's entry at the same offset holds another one. Native:
    native/dcp_core/src/rules.rs."""
    return ()
