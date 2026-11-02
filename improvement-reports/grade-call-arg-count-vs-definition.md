# Check each call's pushed argument count against the callee's definition

- **Source:** match-base session 2026-11-02 (gildegold), worker 48
- **Area:** `dcp grade` (M7 output) / `dcp lint`
- **Problem:** in ai_CannonPanel, d2_SetObjValue takes a fifth argument (1) and ai_GetDefaultEffectScale takes none, but the unit's K&R declarations hid both. The tell was stray `push ebx`; the worker found it from `add esp` sums. `headers conflicts` already does this pushes-versus-definition reading for headers.
- **Proposal:** for every call, compare the original's pushed bytes with the definition's parameter size and flag mismatches, especially for K&R-declared callees.
- **Repro:** ai_CannonPanel (0x57f890) before 39f10ee.
- **Cost of not having it:** moderate.
- **Related:** detect-nested-call-in-arguments.md, headers-signature-dry-run.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 69)
- Proof said "a call differs (callee or arguments)" for gm_AssignBuilding (definition `unsigned short master`, callers push zero-extended ints); only grepping found f3init's `@original` comment. Want a note in grade/diffclass: "other callers' prototypes of this callee: f3init.c:454 (int, int) @original". ~5 minutes. See also refs-call-pushes.md.
