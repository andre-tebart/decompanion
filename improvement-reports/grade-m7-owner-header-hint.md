# M7 "undeclared": say which unit defines the callee and whether its owner header declares it

- **Source:** match-base session 2026-11-02 (gildegold), worker 15
- **Area:** `dcp grade` / `dcp lint` (M7)
- **Problem:** `d3sm_Pick` is defined in d3_sm.c but d3_sm.h did not declare it (only cm.h did). Finding that took greps.
- **Proposal:** for an undeclared call, print "callee defined in d3_sm.c; d3_sm.h lacks its prototype" (or "declared in cm.h, not included").
- **Cost of not having it:** ~5 minutes.
- **Related:** headers-signature-dry-run.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 54)
- `dcp grade` lists `d2_WinOpenPicStyled (undeclared) at line ...` four times and `sv_DrawBalanceBar (undeclared)` with no hint where the prototype lives. Want e.g. `owner=include/d2.h blocked: see dcp headers conflicts`. Cost: one grep each time.

## Also seen (match-base session 2026-11-02 (gildegold), worker 57)
- `M7 consistency: gm_BuildingSkill() at line 769` on byte+readable gm_HandOutMoney; cause was the K&R `int gm_BuildingSkill();` in gv.h and cm.h, full prototype in f3gm.h. Want the declaration in scope named (`gv.h:389 K&R`), the owner prototype, and whether M7 affects the grade. Cost: ~3 minutes.
