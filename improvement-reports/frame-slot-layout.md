# `dcp frame NAME`: show the original's stack-slot layout with access sites

- **Source:** match-base session 2026-11-01 (gildegold), worker 5
- **Area:** new command
- **Problem:** frame-size gaps were closed twice by block-scoped locals (VC6 shares stack slots across disjoint scopes), found only by experiment.
- **Proposal:** `dcp frame NAME` lists the original's stack slots (offset, size, access sites/addresses) and ours, so variables sharing a slot are visible.
- **Repro:** e.g. `main_EndRound` at gildegold commit f47bfc6.
- **Cost of not having it:** moderate.
- **Related:** vc6-optimizer-hints.md (per-scope stack-slot packing)

## Also suggested (match-base session 2026-11-01 (gildegold), worker 12)
- sv_EaseCameraHeight (frame 0x10 vs 0x14) and sv_PlaceCamera (0x18 vs 0x1c) became byte once the position local was a padded D3VECTOR4. Hint wanted: when the frame differs by 4 and a 12-byte local sits at the frame edge, suggest the local may be 16 bytes (padded vector/array).

## Also seen (match-base session 2026-11-02 (gildegold), worker 29)
- gv_FindAccused: frame 0x200c vs 0x2010 and the two local arrays swapped, so every stack offset became `code` until the missing scalar was found; the fix was the order of the initialising assignments, not the declaration order. Hint wanted: "the original's frame has one more 4-byte slot (at esp+0x1c); arrays at 0xc20 / 0x20 vs ours 0x1c / 0xc1c".

## Also seen (match-base session 2026-11-02 (gildegold), worker 36)
- ai_DecideMayor (0x49d8d0): the original keeps two counters and two record pointers in the slots later used for the `AIARG s1`/`s2` structs (frame 0x58 vs our 0x6c), found by hand offset arithmetic (~10 minutes, still escalated). Proposal: diffclass's `frame: ours 0x6c, the original's 0x58` adds "the original's slot X+0x18 is used both as a dword counter and as a struct base: declare these in disjoint block scopes", and lists our locals with no slot of their own in the original. Repro: `uv run dcp diffclass ai_DecideMayor`.
