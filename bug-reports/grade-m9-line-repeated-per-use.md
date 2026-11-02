# `dcp grade` prints the same M9 literal line once per use

- **Source:** match-base session 2026-11-02 (gildegold), worker 65
- **Severity:** minor (cosmetic)
- **What happened:** `dcp grade gm_SellBuilding` printed `B1 byte: M9 ... 'buy building' differs from 'buy_building'` twice, because the literal is used twice.
- **Expected:** one line with `x2` (and the use lines).
- **Repro:** `dcp grade gm_SellBuilding` (0x502fd0) with the draft's `"buy building"` (gildegold, before 68a0e3c).
- **Impact:** none.
