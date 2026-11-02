# A readable-pending state for functions blocked only by a documented head conflict

- **Source:** match-base session 2026-11-01 (gildegold), worker 12
- **Area:** `dcp grade` / `dcp next`
- **Problem:** sv_OpenPlayerBar is byte but stays readability draft: its only open rule is Q7 (calls to d2_GetWinObj / d2_WinOpenPicStyled), and the fix (including d2.h) is the documented "Open: head:" conflict in sv.c's lead comment. It recurs for every widget function in sv and such items keep coming back to the queue.
- **Proposal:** recognise an "Open: head:" line (or a per-function marker) as readable-pending, or rank such items lower in `dcp next`.
- **Cost of not having it:** small per session, recurring.
- **Related:** skill-shape-vs-escalate-guidance.md, ../bug-reports/headers-conflicts-trial-silent-with-supersedes.md
