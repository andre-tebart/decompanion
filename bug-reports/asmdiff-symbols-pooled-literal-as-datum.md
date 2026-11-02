# asmdiff --symbols names a pooled string literal after a data symbol

- **Source:** match-base session 2026-11-01 (gildegold), worker 11
- **Severity:** minor
- **What happened:** at 0x5239e9 the original pushes 0x5fe7d0, the pooled `"%i"` literal. The ledger names it `ai_Unk5fe7d0` (sv.c even had `extern int ai_Unk5fe7d0;`), so the push looked like a datum reference rather than a string literal.
- **Expected:** addresses in a string-literal range are shown as literals with their contents, like other literals.
- **Repro:** `uv run dcp asmdiff sv_UpdateCityPanel --symbols` around 0x5239e9 (gildegold 80355b6); `uv run dcp why 0x5fe7d0`.
- **Impact:** ~3 minutes detour on ownership.
- **Related:** asmdiff-symbols-wrong-library-callee.md, asmdiff-symbols-float-constant-value-missing.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 16)
- `char text[0x200] = "";` gives `!  mov al, byte ptr [??_C@_00A@?$AA@] | mov al, byte ptr [ch_EmptyName]`: VC6 string pooling merged the empty literal with `ch_EmptyName` in the original. diffclass rightly doesn't count it, but the `!` reads like a real error. Proposal: show a literal the original's pooling merged as an alias (`=`), or explain it in the legend.
