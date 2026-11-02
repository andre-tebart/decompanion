# `dcp data settle` / `dcp data merge`: settle gap data into typed objects in one step

- **Source:** match-base session 2026-11-01 (gildegold), worker 12
- **Area:** `dcp data`
- **Problem:** three objects settled by hand with Python regex across src/main.c, src/sv.c, include/sv.h, src/he.c, src/ls.c and include/data_views.h: sv_SkyFair / sv_SkyMedium; sv_Weather (merged five symbols and one gap, new include/sv_types.h); sv_DayTables (merged two symbols, dropped a data_views.h view).
- **Proposal:** `dcp data settle ADDR SIZE NAME TYPE --owner UNIT` and `dcp data merge A B --as NAME`: delete/split the full_data_ blocks, write the definition in the owner's data at the right place, add the header declaration, drop the extern GAPDATA lines, and rewrite or report the uses of old names.
- **Repro:** the three typing commits before gildegold 3b912d2.
- **Cost of not having it:** high, about 25% of the session.
- **Related:** data-literal-from-gap-block.md, data-size-vs-original-extent.md, datum-users-by-offset-and-type.md

## Also suggested (match-base session 2026-11-02 (gildegold), worker 15)
- Owner lookup: `dcp data map UNIT` could print the `full_data_*` gap blocks inline between the unit's definitions with their users. Seven data items were settled by combining `refs`, grep and `data map` by hand, ~2-3 minutes each.

## Also seen (match-base session 2026-11-02 (gildegold), worker 17)
- Splitting: typing `he_SlotConfirmed` (1 byte) in the 4-byte block `full_data_6f2630` meant writing the leftover `GAPDATA full_data_6f2631[3]` by hand. Merging: `sv_DisabledWidgets` covers `full_data_6f1c90` plus `full_data_6f1ce4`, sizes worked out by hand. Proposal form: `dcp data type ADDR NAME TYPE [--owner UNIT]`. Cost: ~10 minutes per data commit plus layout risk.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 18)
- `dcp data near 0xADDR`: nearest defined objects on each side with their units, so the owner decision for a gap datum (e.g. 0x6f23f0) is one command instead of reading `dcp data map sv`. Cost: ~4 minutes per gap datum, two this session.

## Also seen (match-base session 2026-11-02 (gildegold), worker 46)
- ai_ShotTable (0x6f9f60, 3 x 0x38) / ai_ShotDirty (0x6f2664) moved from main.c's gap block into unk_575860: edit main.c, split the remainder (`full_data_6fa008`), drop externs, retype users, then D1/D4/D8 by hand (~10 calls). Proposal: `dcp data adopt NAME UNIT --type T --size N`, atomic, splitting the remainder, ending with the `dcp check` result.
- Owner evidence for a bss address: `dcp layout literals` covers .data/.rdata only, so neighbours were found by grepping `src/*.c` (~4 calls). Proposal: `dcp data owner 0xADDR` - referencing functions grouped by unit plus the nearest named neighbours per unit (bss included). Same wish as `dcp data near` above.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 55)
- Moving `ai_Bookmarks[11]` (AIBOOKMARK, 0x6f5ec0..0x6f5f44) and `ai_ScreenshotCount` (0x6f2674) out of the gap: delete/split the GAPDATA line in main.c, delete the unit's `extern GAPDATA` lines, add the definition in address order, add the header declaration, rewrite uses. Want e.g. `dcp data adopt 0xADDR SIZE NAME "TYPE" --unit U` doing all but the uses.
- `dcp data map UNIT` lists only declared objects; deciding the owner needed `refs` on each neighbouring gap. Want an owner query: neighbours on both sides, their units and their users' units.
