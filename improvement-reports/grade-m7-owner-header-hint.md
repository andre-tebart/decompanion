# M7 "undeclared": say which unit defines the callee and whether its owner header declares it

- **Source:** match-base session 2026-11-02 (gildegold), worker 15
- **Area:** `dcp grade` / `dcp lint` (M7)
- **Problem:** `d3sm_Pick` is defined in d3_sm.c but d3_sm.h did not declare it (only cm.h did). Finding that took greps.
- **Proposal:** for an undeclared call, print "callee defined in d3_sm.c; d3_sm.h lacks its prototype" (or "declared in cm.h, not included").
- **Cost of not having it:** ~5 minutes.
- **Related:** headers-signature-dry-run.md
