# D5 demands `= 0` for a datum whose tentative definition is the byte-identical form

- **Source:** match-base session 2026-11-02 (gildegold), worker 63
- **Severity:** minor (rule contradicts the original's bytes, or ownership is wrong)
- **What happened:** D5 makes `gm_KindObjCount` (0x76fdc4) an error unless written `= 0` ("so it is placed with its unit"). With `= 0`, VC6 does not keep it in a register in gm_BuildKindObjects (0x500b90), leaving one hunk; with a tentative definition (`unsigned short gm_KindObjCount;`) or no definition in f3gm.c, the function is byte-identical. The worker kept `= 0`, escalated, and added an `Open: data:` line to f3gm's lead comment.
- **Expected:** either D5 allows a tentative definition when the placement evidence still holds (or offers a placement form that does not change codegen), or dcp points out that 0x76fdc4 is probably owned by another TU.
- **Repro:** in src/f3gm.c switch `gm_KindObjCount` between `= 0` and tentative, `dcp build`, `dcp grade gm_BuildKindObjects`, `dcp check` (gildegold, session ending 9d14310).
- **Impact:** one function held at draft (deep) by a rule; the finding needed sed edits and backups (see ../improvement-reports/data-definition-form-trial.md).
