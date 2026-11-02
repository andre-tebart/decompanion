# `dcp build` silently accepts the same function name defined in two units

- **Source:** match-base session 2026-11-02 (gildegold), worker 55
- **Severity:** minor (would break the link / mislead grading)
- **What happened:** the worker's edit script renamed 0x589bc0 to `ai_Screenshot` by hand; that name already exists at 0x5d7160 in unk_5d33b0. `dcp rename` correctly refused the name, but the next `dcp build` compiled both units without complaint while two units defined the same function. The link had not been run yet; fixed to `ai_SaveScreenshot` before commit (65f9a10).
- **Expected:** `dcp build` (or `dcp grade` / `dcp check` without a link) reports a duplicate external definition across units, naming both addresses.
- **Repro:** give a function in unk_575860 the name of an existing function in another unit by editing the source, then `dcp build`.
- **Impact:** small this time; a later link failure or a wrong-object grade otherwise.
- **Related:** ../improvement-reports/rename-collision-hint.md
