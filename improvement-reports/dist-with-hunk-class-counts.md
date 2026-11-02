# Show hunk-class counts next to `dist`, since `dist` alone can hide real progress

- **Source:** match-base session 2026-11-02 (gildegold), worker 60
- **Area:** `dcp grade` / `dcp build` / `dcp diffclass`
- **Problem:** `dist` sometimes stayed the same across real changes: gm_AddTime (0x4fe140) was 44 ins before and after an edit that removed a whole structural difference.
- **Proposal:** print a compact class count next to dist, e.g. `dist=44 (code 0, regs 30, slots 14)`, so a classification change is visible at a glance.
- **Cost of not having it:** extra diffclass runs; risk of reverting a good edit.
- **Related:** grade-object-unchanged.md
