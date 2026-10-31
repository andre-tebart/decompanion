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
from .match import WALK

P, D, DE, O = Level.proven, Level.derived, Level.declared, Level.open

