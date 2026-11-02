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

## Also seen (match-base session 2026-11-02 (gildegold), worker 48)
- In unk_575860 the `grades:` totals moved by ±1 several times after edits that should not touch any matched function (one was only a struct tag rename SHOTREC -> SHOTRESULT); `dcp check` showed no M1. The mover was ai_TutorialInitChapter2, a debt-held declaration-set tie-break that flips byte/shape on any declaration change. Want: the build line names the changed functions and says when a change is a debt item moving inside its allowance. Repro: add `typedef int X;` after `#include "d3s.h"` in src/unk_575860.c. Cost: ~4 extra check/grade rounds.

## Also seen (match-base session 2026-11-02 (gildegold), worker 50)
- Adding four const tables, and later one prototype to include/he.h, silently moved ai_TutorialInitChapter2 (0x578e40) byte -> shape; the build printed only aggregate counts. Found via `dcp check`, then a stash/bisect experiment. Want e.g. `fell: 0x578e40 ai_TutorialInitChapter2 byte -> shape (regs 2 hunks)` in the build output. Cost: two extra check cycles plus the bisect.

## Also seen (match-base session 2026-11-02 (gildegold), worker 51)
- After an include/ai.h edit (`AIMSG.graveWork`), build totals moved (shape+readable 148 -> 147, byte+readable +1, byte+draft +1) with no name; only `session wrap` showed d3_CloneObject shape -> byte (deep). Want `grade changed: NAME old -> new` lines in the build output, falls first.

## Also seen (match-base session 2026-11-02 (gildegold), worker 56)
- `byte+readable=1759 -> 1758` with no name; the M1 was found only via `dcp check | grep ^error`. Want `fell: 0xADDR name byte->shape` whenever a count drops below baseline. This is how gm_IncomeKind4 was first committed with an open M8 (see ../bug-reports/grade-byte-misses-swapped-relocations.md).

## Also seen (match-base session 2026-11-02 (gildegold), worker 59)
- A layout-neutral gv.h edit made ai_TutorialInitChapter2 (unrelated unit) fall byte -> shape; retyping `ORDBLD.object` to `struct D3OBJECT *` made one ord.c function fall shape -> draft. Both seen only in `dcp check`. Want `falls=N` with names on the `grades:` line. Cost: two extra check rounds plus a revert-and-rebuild.

## Also seen (match-base session 2026-11-02 (gildegold), worker 62)
- After header/typing changes `shape+readable` 163 -> 162 and `byte+readable` 1782 -> 1784 with no message; `dcp check` run each time to rule out an M1. Want `changed: gm_X shape->draft (experiment)` or a note that the counts are experiment-side and the baseline is unaffected.

## Also seen (match-base session 2026-11-02 (gildegold), worker 63)
- `shape+readable=163 -> 162`, `byte+readable 1789 -> 1788` with no mover named. Adding `inventory` to gv.h's ORDCHAR flipped ai_TutorialInitChapter2 in unk_575860, learned only from M1 after committing (so the debt needed its own commit). Want e.g. `header include/gv.h changed: 31 units recompiled, grade falls: 0x578e40 (unk_575860) byte->shape` in the build output.

## Also seen (match-base session 2026-11-02 (gildegold), worker 68)
- Wants `dcp grade --changed` or `dcp promote --dry-run`: every function whose grade differs from ledger/grades.tsv (up or down) mid-session. Would have resolved a puzzling totals move (see ../bug-reports/build-grades-line-mismatch.md) in one call.

## Also seen (match-base session 2026-11-02 (gildegold), worker 69)
- Same request after the byte+readable counter oscillated with no visible cause (see ../bug-reports/build-grades-line-mismatch.md): list address, name, old -> new for every function that moved in the build.
