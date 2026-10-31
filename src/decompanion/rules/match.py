"""Match rules (M.*): what the compiled objects say about the original.

  M.compile   one `build` fact per translation unit of the target (the tu table of the last `dcp build`): ok,
              object, diagnostics; a failed or never compiled unit is a gate error; the object-vs-source
              cross-check (M.gen)
  M.match     R1 [proven]: a function whose bytes equal the original's with the relocated fields masked (plus
              the DLL aid and the tail check, match/compare.py) owns [address, address + size)
  M.draft     R2 [derived, at most declared]: a compiled function that differs owns its code walk
  M8.reloc    M8 / M9 / M10: what our relocations refer to against what the original's sites hold

The sources remain the state: the `source` facts of L.src (an address comment, declared) are candidates the
match rules verify; a verified one yields facts above the declared level. Objects come from the store's tu
table (input `objects`); the rules never compile (`dcp build` does).
"""
from __future__ import annotations

WALK = ("S.sections", "S.relocs", "S.codewalk", "S.crt.code", "S.thunk", "S.exports", "S.entry")
