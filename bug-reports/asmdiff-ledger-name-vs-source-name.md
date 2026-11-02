# disasm / asmdiff --symbols show ledger names that exist nowhere in the source

- **Source:** match-base session 2026-11-02 (gildegold), worker 23
- **Severity:** minor
- **What happened:** the original side printed `0x7e3f94 <ai_PlayerCity>` and `0x770ae0 <NOWX>`, but in the source those are `ai_Unk7e3f94` (a data_views.h view) and `ai_Time` / the `gv_TimeT` view. The ledger names appear nowhere in src/ or include/, so the worker had to search.
- **Expected:** show the source name, or both (`<ai_PlayerCity = src ai_Unk7e3f94>`); or flag ledger/source name drift so one can be updated.
- **Repro:** `uv run dcp disasm 0x004f0490`, `uv run dcp asmdiff gv_BuryNewDead --symbols` (gildegold b0d1486).
- **Impact:** ~3 minutes.
- **Related:** asmdiff-symbols-reordered-load-marked-wrong.md (NOWX), check-unresolved-data-unnamed.md
