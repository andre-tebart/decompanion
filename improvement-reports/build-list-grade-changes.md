# `dcp build`/`grade`: list functions whose grade changed in this build

- **Source:** match-base session 2026-11-01 (gildegold), worker 6
- **Area:** `dcp build`
- **Problem:** after changing ai_PokerStep's return type (`unsigned short`), the worker had to check by hand with `dcp grade ai_PokerGame` that the caller didn't fall. The build summary only shows totals, so a fall in another function can go unnoticed until `session wrap` / `check`.
- **Proposal:** `dcp build` prints an incremental "grades changed" list (like the wrap's) for functions whose grade moved in this build.
- **Repro:** change a prototype in include/unk_4a7140.h, `uv run dcp build` (gildegold 2fb619b).
- **Cost of not having it:** low, but an easy miss.

## Also seen (match-base session 2026-11-02 (gildegold), worker 18)
- After `dcp build` only totals like `byte+draft=1229 -> 1228` show; working out which function moved took ~2 minutes, 3-4 times this session.

## Also seen (match-base session 2026-11-02 (gildegold), worker 32)
- Changing `ai_AddNeedDelta(unsigned char k, ...)` to `int k` in include/am.h, include/cm.h, src/cm.c and src/f3gm.c: `dcp check` showed no M1, but the callee's own distance (draft either way) wasn't visible. Proposal addition: after a build, list functions whose distance changed (not only grade), covering recompiles caused by header edits.
