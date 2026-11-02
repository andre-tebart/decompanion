# An extern-only name standing in for another unit's defined object is not flagged

- **Source:** match-base session 2026-11-02 (gildegold), worker 26
- **Severity:** minor
- **What happened:** gv.h declares `extern char gv_Graveyard[]` (0x91f700) and `extern char unk_Tab91b6e0[]` (0x91b6e0); neither has a definition. They are second names for cm.c's defined `ai_Unk91f700` / `ai_Unk91b6e0` (now `ai_Crimes` / `ai_Evidence`); `gv_Graveyard` is also misnamed (crime records). Found only via `asmdiff --symbols` and `dcp why`. `C.name.alias` fired for 0x6f1b88 but not for these two.
- **Expected:** `dcp check --strict` / lint reports "extern-only name X at ADDR has no definition; the object at ADDR is defined as Y in unit U".
- **Repro:** `uv run dcp why 0x91f700` (owner `ai_Unk91f700` before the rename); grep gv.h for `gv_Graveyard` (gildegold before 43ee493).
- **Impact:** ~5 minutes; proper renaming left open in gv.c's lead comment.
- **Related:** ../improvement-reports/types-duplicate-views-lint.md, check-unresolved-data-unnamed.md
