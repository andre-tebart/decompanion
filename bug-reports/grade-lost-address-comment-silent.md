# A function whose address comment is no longer recognised vanishes silently; grade reports a wrong extent for its neighbour

- **Source:** match-base session 2026-11-01 (gildegold), worker 10
- **Severity:** minor
- **What happened:** an edit swallowed the newline between two functions (`}/* 0x4ab2c0, ...`). The unit still compiled. `dcp grade ai_Unk4ab080` then said `size 570 vs 851` and "the original continues after our end: 0x4ab2c0..0x4ab3e0" (the original's extent jumped from 571 to 851), and `dcp fn ai_Unk4ab2c0` said "no function in the sources". The same slip in sv.c was caught by `dcp check` as M1 "no grade now (its source is gone?)", but grade/build give no hint.
- **Expected:** when a build loses an address comment the previous build had (function count drops), build and grade warn: `function 0x4ab2c0 lost its address comment (line N: comment not at line start?)`.
- **Repro:** join a function's closing `}` and the next address comment on one line, `uv run dcp build`, `uv run dcp grade <previous function>` (gildegold 6c8587c).
- **Impact:** ~4 minutes total, happened twice.
- **Related:** ../improvement-reports/scoped-function-body-edit.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 32)
- A block of `#define`s placed between `/* 0x494e70, ... */` and `int ai_LoadActionTable(void)` made `dcp grade ai_LoadActionTable` print "is neither a unit nor a graded function of target exe". Proposal: "src/am.c:3367 has an address comment for 0x494e70 but it is not directly above a definition (found `#define` on line N)". Cost: one build/grade round plus confusion.

## Also seen (match-base session 2026-11-02 (gildegold), worker 37)
- Third time: a `#define` between `/* 0x49eec0, ... */` and `int ai_DecideTakeCredit(` made `dcp grade ai_DecideTakeCredit` answer "is neither a unit nor a graded function". Proposal again: `address comment of 0x49eec0 not directly above its definition (line N)`. Cost: ~2 minutes.

## Also seen (match-base session 2026-11-02 (gildegold), worker 53)
- A `#define` placed between a function's address comment and its definition made `dcp grade NAME` answer "neither a unit nor a graded function", without saying why. Want: "address comment at line N is not directly above a definition (a #define intervenes)".

## Also seen (match-base session 2026-11-02 (gildegold), worker 60)
- Two `#define`s placed between the address comment and the function: `dcp grade unk_Unk4fdfd0` said "is neither a unit nor a graded function of target exe", `dcp diffclass` said "no graded function". Want "function at src/f3gm.c:N has no address comment directly above it (found a #define)". Cost: one round trip.

## Also seen (match-base session 2026-11-02 (gildegold), worker 62)
- Third time today: `#define` lines between `/* 0xADDR ... */` and the function made `dcp grade gm_UpdatePrices` say `is neither a unit nor a graded function`. Want "an address comment was found at line N but is not directly above the definition".
