# B1: separate bytes that differ in place from bytes only shifted

- **Source:** match-base session 2026-11-02 (gildegold), worker 60
- **Area:** `dcp grade` (B1)
- **Problem:** after the main fix gm_HomeObject (0x4fdc10) had one 3-instruction hunk, but B1 said "88 of 144 bytes differ": mostly the following code moved by that hunk.
- **Proposal:** report "N bytes differ in place, M by shift", or drop B1's count when `dist` is small.
- **Cost of not having it:** misjudging how far a function is from byte.
- **Related:** ../bug-reports/grade-b1-continues-after-end-confusing.md, ../bug-reports/grade-branch-shift-noise.md
