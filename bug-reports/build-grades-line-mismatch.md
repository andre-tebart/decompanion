# `dcp build`'s `grades:` line disagrees with the per-function grade

- **Source:** match-base session 2026-11-02 (gildegold), worker 54
- **Severity:** minor
- **What happened:** right after ai_OpenCharTooltip (0x588c60) went to byte+readable (per `dcp grade`), the build summary still said `byte+readable=1749` (unchanged), while `shape+readable` went 150 -> 151 and `draft+draft` 1097 -> 1096. A second build printed the same line, so it is not a one-build lag. Earlier, ai_OpenUpgradeTooltip reaching shape did not visibly move the shape count either.
- **Expected:** the totals move with the graded function (here byte+readable +1, draft+draft -1), or the line says what it counts (e.g. baseline-promoted grades only).
- **Repro:** raise a function to byte, `dcp build | grep grades`, compare with `dcp grade NAME` (gildegold, before d8ce059).
- **Impact:** small; the worker stopped trusting the line and used `dcp check` / `dcp grade`.
- **Related:** ../improvement-reports/build-list-grade-changes.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 68)
- After commit "f3gm: gm_CureDisease byte + readable" (gildegold, session ending 7193051), `grades:` went shape+readable 214 -> 213 and draft+readable 354 -> 355; no M1, manual diff of `dcp grade f3gm` / `dcp grade unk_58bbd0` vs ledger/grades.tsv showed only the worker's raises, and wrap listed only those. Looked like an unflagged regression; ~4 calls.

## Also seen (match-base session 2026-11-02 (gildegold), worker 69)
- byte+readable flipped 1824 -> 1825 -> 1824 -> 1825 -> 1824 across builds while every edited function stayed draft/shape; no M1. Triggered around edits to include/gv.h (ORDCHAR fields w050/v194). ~3 extra `dcp check` runs. Related: ../improvement-reports/build-list-grade-changes.md

## Also seen (match-base session 2026-11-03 (gildegold), worker 70)
- gm_ItemPrice draft+draft -> byte+readable (confirmed by `dcp grade`), but the next build's `byte+readable=1826` did not move; draft+draft 936 -> 934, draft+readable 344 -> 345 (ai_TutorialInitChapter3 fell shape -> draft at the same moment, only one M1). Wrap was consistent (byte 2990 -> 2992). ~2 minutes; gildegold session ending befd916.
