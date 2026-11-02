# `dcp rename` reports `kind=data` for some functions

- **Source:** match-base session 2026-11-01 (gildegold), worker 7
- **Severity:** minor
- **What happened:** renaming the function placeholders `ai_Unk4a8ad0`, `ai_Unk4a8c20` and `ai_Unk4a8f20` printed `kind=data`, and the wrap report's rename list shows "data" for them too. Other renames in the same unit (`ai_Unk4a7f50`, `ai_Unk4a8190`, `ai_Unk4a8760`, `ai_Unk4a58d0`, `ai_Unk4a63f0`) correctly printed `kind=func`. Worker's guess: these are decide/eval callbacks only referenced from a table, never called directly, so the ledger types the address as data.
- **Expected:** `kind=func` for any address that is a function in the ledger, whatever its references.
- **Repro:** `uv run dcp rename ai_Unk4a8c20 ai_EvalOwnTimeSlot --why "..."` gave `renamed=... kind=data at=0x004a8c20` (gildegold, before 37b970e; see names.log).
- **Impact:** none beyond confusion; may hint at a ledger typing issue elsewhere.

## Also seen (match-base session 2026-11-01 (gildegold), worker 8)
- names.log lines 352/353 at gildegold 7ae5254: `0x004a9080 data ai_Unk4a9080 -> ai_DecideAcquaintance`, `0x004a9150 data ai_Unk4a9150 -> ai_EvalOwnYearTurn`; the other 9 renames logged `func`. `dcp why 0x4a9080` says `cls=func level=proven` with a `what=func` source record.
- Not tied to multi-pair position: 0x4a9150 was a single-pair rename; 0x4a9030 was a second pair yet logged `func`. Worker's unverified guess: placeholders with no `named=` record (Ghidra "start" only) fall back to `data`.
- Repro: rename a placeholder such as `ai_Unk4a9a00` and check its names.log line.

## Related case: cast macros (match-base session 2026-11-01 (gildegold), worker 10)
- `dcp rename AI_505DF0 gm_FindPer` renamed `#define AI_505DF0(id) ((AIPER *)gm_FindChar(id))` in am.h but reported `kind=func at=0x00505df0` and logged `0x00505df0 func AI_505DF0 -> gm_FindPer`, which reads as if gm_FindChar (0x505df0) was renamed; `dcp why 0x505df0` confirmed it was not. Proposal: log macro/view names as `kind=macro` (or `view`), not under the wrapped function's address. Cost: ~2 minutes.

## Also seen (match-base session 2026-11-01 (gildegold), worker 11)
- `sv_Unk524770` / `sv_Unk524810` logged `data`. Pattern: no prototype in their own unit (sv.c) before the definition, and other units (he.c) declare them K&R style (`int sv_Unk524770();`). Functions declared in include/sv.h (`sv_Unk524100`, `sv_Unk524990`) reported `func`.
- Repro: `uv run dcp rename sv_Unk524810 sv_IsCartAtDoor --why x` (gildegold before 80355b6) prints `kind=data`.

## Also seen (match-base session 2026-11-01 (gildegold), worker 13)
- `sv_Unk528290 -> sv_ColourBannerCB` reported `kind=data` (a callback; consistent with the table-referenced/K&R-only pattern).

## Also seen (match-base session 2026-11-02 (gildegold), worker 21)
- names.log and the wrap report list unk_Unk4eeb00 (gv_StopEffect) and unk_Unk4eee00 (gv_StartShot) as `data` (gildegold 60a57e0).

## Also seen (match-base session 2026-11-02 (gildegold), worker 25)
- `gv_AddNewDead` and `gv_EntryHeldBy` logged as `kind=data` (gildegold db79813). Also: two names.log why texts contain placeholder addresses ("cm.c 0x4cxxxx", "he.c 0x56xxxx") written by mistake; there is no dcp way to correct a why text, and the rules forbid hand-editing names.log.

## Also seen (match-base session 2026-11-02 (gildegold), worker 28)
- `0x004f3b40 data unk_Unk4f3b40 -> gv_RetireCrimeIds` and 0x4f4080 (gv_HeldCrimeIdsOf) logged `data` (gildegold cc02898).

## Also seen (match-base session 2026-11-02 (gildegold), worker 29)
- Wrap report: `0x004f4420 data unk_Unk4f4420 -> gv_CheckSentence`, `0x004f4460 data unk_Unk4f4460 -> gv_PassSentence`. Both found by ghidra and source only (no `call` start); their only callers are unprototyped calls in cm.c. Consistent with the earlier guesses: the kind is taken from a source lacking a call-derived function record.

## Also seen (match-base session 2026-11-02 (gildegold), worker 30)
- 0x48f250, 0x48f500, 0x48f990, 0x48feb0 logged `data` (gildegold 5039a27).

## Also seen (match-base session 2026-11-02 (gildegold), worker 34)
- 0x498b80, 0x49a290, 0x553d60 logged `data` (gildegold 61cfc0d).

## Also seen (match-base session 2026-11-02 (gildegold), worker 37)
- 0x49e350, 0x49ec10, 0x4aaef0, 0x49ee20 logged `data` (gildegold d739c21).

## Also seen (match-base session 2026-11-02 (gildegold), worker 38)
- 0x49fb80, 0x4a0410, 0x4a4e30, 0x4a1640, 0x4c59b0 reported/logged `kind=data` (gildegold db06964).
