# `dcp build` / `dcp grade` miss a header-vs-definition mismatch that `dcp check` fails on (M5/M6)

- **Source:** match-base session 2026-11-02 (gildegold), worker 51
- **Severity:** minor (nearly committed a failing gate)
- **What happened:** after changing `ai_GypsyHelperWindow(char *b)` to `ai_GypsyHelperWindow(AIBLD *rec)` in src/unk_575860.c, include/unk_575860.h:95 still declared `char *b`. `dcp build` said ok (errors=0); `dcp grade ai_GypsyHelperWindow` showed only Q2/M7. `dcp check` then failed: `gate=FAIL errors=2`, M5 (declaration unlike definition) and M6 (conflicting types).
- **Expected:** `dcp grade NAME` reports M5/M6 for the function being graded, as it already reports M7; or `dcp build` flags it.
- **Repro:** change a parameter type in a definition but not its header prototype, then `dcp build`, `dcp grade NAME`, `dcp check` (gildegold, before 6853071).
- **Impact:** ~3 minutes; without a habitual pre-commit check the commit would have failed the gate.

## Also seen (match-base session 2026-11-02 (gildegold), worker 68)
- Rewrote gm_CatchMinorDisease (0x5054f0) as `int (ORDCHAR *)`; include/f3gm.h still said `unsigned gm_Unk5054f0(short *c)`. build ok, grade byte+readable "(consistency (M7) current)"; only `dcp check` showed M5. Same with gm_CureDisease's local prototype in src/unk_58bbd0.c. ~3 extra calls, twice.
