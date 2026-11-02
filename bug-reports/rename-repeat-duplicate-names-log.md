# Repeating a `dcp rename` writes a duplicate names.log line ("renamed by hand already")

- **Source:** match-base session 2026-11-01 (gildegold), worker 10
- **Severity:** minor
- **What happened:** `uv run dcp rename unk_Unk4f4d30 gv_GetGraveInfo --why "..."` succeeded; the output was cut by `| Select-Object -First 2`, so the worker re-ran it. The second run printed `recorded=unk_Unk4f4d30 to=gv_GetGraveInfo kind=func at=0x004f4d30 files=0 (renamed by hand already: names.log only)` and appended an identical names.log line six seconds after the first.
- **Expected:** when no OLD remains in the source and names.log already has the same OLD -> NEW for that address, print `already renamed` and write nothing (exit 0). "Renamed by hand" is wrong: dcp did it.
- **Repro:** run any rename twice in a row (gildegold 6c8587c).
- **Impact:** ~3 minutes; manual names.log edit (discouraged by the rules); the wrap report would have listed the rename twice.
- **Related:** ../improvement-reports/rename-summary-line-first.md
