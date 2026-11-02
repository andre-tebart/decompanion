# asmdiff header: `calls differ: ours none` reads as "no calls" instead of "no surplus calls"

- **Source:** match-base session 2026-11-03 (gildegold), worker 70
- **Severity:** minor
- **What happened:** for gm_CreateCharacter one run printed `calls differ: ours none | the original _ftol x2, gm_FindChar x2, ...`, a later one `calls differ: ours _ftol x1 | the original none`. "none" means no surplus calls on that side, but at a glance it says the original never calls `_ftol`.
- **Expected:** wording that states the surplus, e.g. `calls differ: +1 _ftol (ours)` or `ours has 1 more _ftol | the original has none more`.
- **Repro:** `dcp asmdiff gm_CreateCharacter` (gildegold, session ending befd916).
- **Impact:** ~1 minute of misreading.
- **Related:** diffclass-calls-differ-misses-original-call.md
