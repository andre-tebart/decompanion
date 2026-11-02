# Flag local redeclarations that disagree with a changed definition right away

- **Source:** match-base session 2026-11-01 (gildegold), worker 13
- **Area:** `dcp build` / `dcp grade` / `dcp refs`
- **Problem:** twice the worker changed a definition and its sv.h prototype from `unsigned char *` to `struct AIBLD *` / `struct AIOBJ *`; a forgotten K&R-style local prototype later in sv.c (lines 3652, 3665) gave M5 / M6 only at `dcp check` after a full build.
- **Proposal:** build/grade flags a disagreeing redeclaration in the same unit immediately, or `dcp refs` marks declarations that disagree with the definition.
- **Cost of not having it:** ~2 extra build/check cycles each time.
- **Related:** headers-signature-dry-run.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 16)
- After restoring an old prototype to get a rename through, include/sv.h had `void sv_ShowBubble(int o, int b, char *name)` while sv.c defined `void sv_ShowBubble(CHARACTER *ch, int text, char *name)`. `dcp build` said `ok sv errors=0`; only `dcp check` gave `gate=FAIL errors=2` (M5, M6). Proposal: build (or grade) flags M5/M6 for the units it just built. Cost: ~3 tool calls.

## Also seen (match-base session 2026-11-02 (gildegold), worker 18)
- src/sv.c includes sv.h but repeats several of its prototypes locally (`void sv_Unk52f9f0(int *book);`, `int sv_Unk52f710(int *book, char dir);`); on a signature change these would conflict. Proposal: `dcp lint --dups UNIT` listing local copies of the unit's own header declarations. Cost: ~3 minutes of grepping.

## Also seen (match-base session 2026-11-02 (gildegold), worker 23)
- Other units' headers: cm.h carried `int gv_GrowGraveyard();`; giving the definition its real `GVYARD *` return type meant hand-editing cm.h:413, found only via `dcp refs`. Proposal: on a return-type change, grade/build points at every redeclaration (in any header) that now conflicts. Cost: ~3 minutes.

## Also seen (match-base session 2026-11-02 (gildegold), worker 32)
- src/f3gm.c:400 had its own `int ai_Unk4c3eb0(unsigned char k, float v);` disagreeing with the header after `ai_AddNeedDelta` became `int k`; found only by grep, nothing fired.

## Also seen (match-base session 2026-11-02 (gildegold), worker 35)
- include/am.h declares `ai_FindWantedItems` three times (lines 558, 845, 990); neither lint nor grade mentions it. Proposal: a duplicate-in-same-header note so dead copies get cleaned up. Cost: ~1 minute of confusion.

## Also seen (match-base session 2026-11-02 (gildegold), worker 68)
- f3gm.h prototypes of 4 functions edited by hand with sed after their definitions changed. Proposal: `dcp rename` mentions prototypes that disagree with the definition, or `dcp headers` offers to rewrite the owner header's prototype. Related: headers-signature-dry-run.md
