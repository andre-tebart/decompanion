# grade / asmdiff --symbols: print struct field names for `[reg + off]`

- **Source:** match-base session 2026-11-02 (gildegold), worker 17
- **Area:** `dcp asmdiff --symbols`, `dcp grade`
- **Problem:** the worker looked up D2VIEW, D2OBJ and D2WIN offsets with awk over d2_types.h several times per function.
- **Proposal:** when the base register's type is known (from our debug info / the source), annotate `[reg + 0x1a0]` as `D2VIEW.enabled`; at least a `dcp type D2VIEW 0x1a0` lookup.
- **Cost of not having it:** ~5 minutes per function.
- **Related:** datum-users-by-offset-and-type.md, types-duplicate-views-lint.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 59)
- Offsets like `[esi-0x1c6]` mapped to fields by hand, often with the base pointer not at the record start (c+2, c+0x1c8); the draft's wrong offsets in gm_PopulationStep (0x164/0x166/0x167 instead of 0x166/0x168/0x169) were found only by subtraction. Want `asmdiff --fields`: `[esi+0x164] {ORDCHAR.jobId}` when the pointer type is known, even ours only.

## Also seen (match-base session 2026-11-02 (gildegold), worker 66)
- `asmdiff --symbols` should show `ai_Chars+0x169 (ORDCHAR.job2)`: the old gm_PermissionBits draft read the character's second profession at +9 instead of +0x169, visible only as a raw `0x770ce9`.
