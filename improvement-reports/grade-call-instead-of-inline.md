# grade / asmdiff: say when ours calls a helper where the original has its body expanded

- **Source:** match-base session 2026-11-02 (gildegold), worker 46
- **Area:** `dcp grade`, `dcp asmdiff`
- **Problem:** ai_AlchemistResearchWindow / ai_AlchemistWindow expand a ~45-line panel block twice. A `static __inline` helper was inlined, then silently became a call once its body grew past VC6's inline limit. The only hint was the instruction total falling ~100 short; a `calls differ:` line shows up in some outputs but not consistently.
- **Proposal:** when our side has a call to a function defined in the same unit and the original has no call there (or has more instructions at that point), print `ours calls ai_AlchemistPanel x1 where the original has it expanded`.
- **Repro:** unk_575860 at gildegold 8ce4a43 (`dcp asmdiff ai_AlchemistResearchWindow`).
- **Cost of not having it:** ~8 calls.
