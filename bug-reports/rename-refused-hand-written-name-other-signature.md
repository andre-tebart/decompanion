# `dcp rename` refuses a hand-written new name when the header has another signature (skill says it completes)

- **Source:** match-base session 2026-11-01 (gildegold), worker 8
- **Severity:** minor
- **What happened:** for 0x4a91a0 the worker rewrote the definition as `int ai_DecideSuitor(int a, AICHAR *p, int c, int d, AIARG *m)` while `include/unk_4a7140.h` still declared `int ai_Unk4a91a0(int a, AIPER *p, int c, int d, unsigned char *m);` and the dispatch used `G10_CB(ai_Unk4a91a0)`. `dcp rename ai_Unk4a91a0 ai_DecideSuitor --why ...` printed "the rename brings 2 new error(s) (listed above; fix them first, e.g. a declaration of the new name with another type): nothing written". The errors were printed earlier and lost when the output was piped through tail.
- **Expected:** the skill says a name already written by hand is completed by the rename, not refused; in practice it is refused when the hand-written signature differs from the header (M5-style conflict). Either complete it, or (a) print the errors on/next to the refusal line and (b) make the skill say rename first whenever the signature also changes.
- **Repro:** at gildegold before 7ae5254: change a definition's name and parameter types by hand, leave the header, run `dcp rename OLD NEW`.
- **Impact:** about 3 tool calls, a few minutes.
- **Related:** ../improvement-reports/rename-summary-line-first.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 23)
- Hand-written `int *gv_RandomGrave` definition while the header still had `int unk_Unk4ef930(...)`: `dcp rename` refused with 56 cascading errors (M.compile plus M1 for every function in the unit); the one-line root cause was buried under 50+ M1 lines. Proposal: root error first, collapse consequent M1s ("unit gv does not compile -> 54 M1 suppressed"). Cost: ~2 minutes.

## Also seen (match-base session 2026-11-02 (gildegold), worker 29)
- Definition hand-edited to `int gv_CheckSentence(...)` while the gv.h prototype and callers still used `unk_Unk4f4420`: `error='the rename brings 2 new error(s) (listed above ...)'`, but nothing was listed above in the visible output. So the "name already written by hand is completed" rule doesn't cover the definition itself. Workaround: restore the old name, then rename. Cost: ~1 minute.
