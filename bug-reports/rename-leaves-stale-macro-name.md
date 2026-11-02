# A rename rewrites a cast macro's target but leaves the macro's placeholder name and comment

- **Source:** match-base session 2026-11-02 (gildegold), worker 20
- **Severity:** minor
- **What happened:** gv.c had `#define ai_Unk5a9e40K ((int (*)())ai_DomizilMessage12)` after the rename: the target was rewritten, but the macro kept the `ai_Unk...` name and its now-wrong `@original` comment.
- **Expected:** rename also renames derived macro names (`OLDK`, `OLDF`, ...) or lists them for review.
- **Repro:** `uv run dcp rename ai_Unk5a9e40 ai_DomizilMessage12` at gildegold d67bf75^.
- **Impact:** minimal.
- **Related:** ../improvement-reports/rename-report-comment-rewrites.md, rename-kind-data-for-functions.md
