# A rename rewrites a cast macro's target but leaves the macro's placeholder name and comment

- **Source:** match-base session 2026-11-02 (gildegold), worker 20
- **Severity:** minor
- **What happened:** gv.c had `#define ai_Unk5a9e40K ((int (*)())ai_DomizilMessage12)` after the rename: the target was rewritten, but the macro kept the `ai_Unk...` name and its now-wrong `@original` comment.
- **Expected:** rename also renames derived macro names (`OLDK`, `OLDF`, ...) or lists them for review.
- **Repro:** `uv run dcp rename ai_Unk5a9e40 ai_DomizilMessage12` at gildegold d67bf75^.
- **Impact:** minimal.
- **Related:** ../improvement-reports/rename-report-comment-rewrites.md, rename-kind-data-for-functions.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 62)
- After renaming ai_Unk61a686 -> gm_QueryKind, the view `ai_Unk61a688` in include/data_views.h kept its old name (expected per docs), but the rename output did not list the view; the skill says the note lists it. Possibly cut off in the tail of a long multi-pair output.

## Also seen (match-base session 2026-11-02 (gildegold), worker 67) - alias in another unit
- After `dcp rename gm_Unk5049e0 gm_ClassTreasury`, src/unk_58bbd0.c still declares 0x5049e0 under a different name, `ai_Unk5049e0`: a stale alias the rename did not reach (or did not report). Also, he.c calls 0x504840 (gm_DropRank) with no prototype at all. Want rename to find and report declarations of the same address under other names. Gildegold 96ddc48.
