# EBP frames: diffclass applies a uniform frame shift, so moved local arrays come out as `code` / `fpu`

- **Source:** match-base session 2026-11-02 (gildegold), worker 38
- **Severity:** minor (only-slots function graded draft)
- **What happened:** ai_DecidePriceManipulation (0x49fc90), frames 0x55c (ours) vs 0x564 (original): the original keeps `hi32` in its own local at [ebp-0x58], ours in a parameter slot. The aligner shifts every offset by 8, but ebp-relative locals don't move with frame size, so real slot moves stay visible: `score[]` at -0x70 vs -0x78, `m[i].avg` at -0x4b4 vs -0x4bc. These came out as `code 2` (0x49fe75), `code 6` (0x49ff50) and `fpu 12 / 2 / 2` (0x49fee3 / 0x49ff7e / 0x49ffb0): B3 "unexplained code hunks", verdict draft.
- **Expected:** for EBP-based functions compare locals by order and extent, or class an offset change as `slots` when it is consistent for one object across the whole function.
- **Repro:** at gildegold commit "am: ai_DecidePriceManipulation -> deep (match-base)" (just before db06964), `uv run dcp diffclass ai_DecidePriceManipulation`, `uv run dcp asmdiff ai_DecidePriceManipulation`.
- **Impact:** ~10 minutes; escalation reason had to explain the hunks by hand.
- **Related:** diffclass-frame-shift-indexed-as-code.md, diffclass-slot-permutation-per-hunk.md
