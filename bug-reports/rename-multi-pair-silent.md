# A multi-pair `dcp rename` printed nothing on success

- **Source:** match-base session 2026-11-02 (gildegold), worker 44
- **Severity:** minor
- **What happened:** `dcp rename ai_Unk578180 ai_TutorialStart ai_Unk578370 ai_TutorialStop ... --why "..."` (5 pairs, ~11:24) printed no output at all - no changed files or replacements as the skill describes. A single-pair rename at 11:18 printed its comment and rebuild notes. The worker grepped names.log to confirm.
- **Expected:** the same per-pair records and rebuild summary as a single rename.
- **Repro:** a 5-pair rename at gildegold before c5fa98f.
- **Impact:** 1-2 minutes.
- **Related:** ../improvement-reports/rename-summary-line-first.md
