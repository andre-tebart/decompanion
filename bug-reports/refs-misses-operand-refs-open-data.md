# `dcp refs` reports 0 refs to an open-data address that `dcp why` counts 13 for

- **Source:** match-base session 2026-11-01 (gildegold), worker 14
- **Severity:** minor
- **What happened:** `dcp refs ai_FmtInt` (0x5fe7d0, the pooled "%i") printed `refs_to=0`, but sv_RefreshPanel's original pushes it (`push 0x5fe7d0` at 0x529f02) and `dcp why 0x5fe7d0` says `refs: to=13`.
- **Expected:** refs lists operand references into open/unknown data, consistent with `why`.
- **Repro:** `uv run dcp why 0x5fe7d0` vs `uv run dcp refs <name at 0x5fe7d0>` (gildegold 4dc46a1).
- **Impact:** ~5 minutes of confusion deciding the owner.
- **Related:** asmdiff-symbols-pooled-literal-as-datum.md
