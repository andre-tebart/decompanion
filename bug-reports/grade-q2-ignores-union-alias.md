# Q2 flags a placeholder field that already has a readable alias in the same union

- **Source:** match-base session 2026-11-01 (gildegold), worker 9
- **Severity:** minor
- **What happened:** `dcp grade ai_Unk4a9a00` listed `Q2 identifiers: unkac, unkb0`, but AIJOB in `include/ai.h` has unions at 0xac / 0xb0 that already name these `partner1` / `partner2` (for pair events 0x41/0x6f/0x45). The message reads as if the field has no name; the fix is just to use the existing alias.
- **Expected:** for a flagged struct member with a non-placeholder alias at the same offset, say so: `unkac (alias at 0xac: partner1, partner2)`.
- **Repro:** use `j->unkac` on an `AIJOB *` and run `uv run dcp grade` on that function (gildegold 7ef405a).
- **Impact:** 2-3 minutes the first time; seen in 4 functions.
- **Related:** ../improvement-reports/grade-q2-full-list.md
