# `dcp grade`: "(consistency (M7) current)" printed beside a list of open M7 calls reads as "M7 is fine"

- **Source:** match-base session 2026-11-02 (gildegold), worker 51
- **Severity:** minor
- **What happened:** `dcp grade ai_GypsyHelperWindow` printed `M7 consistency: sv_CheckCharacterFlag() at line 8382, ...` followed by `(consistency (M7) current)`. Presumably "the M7 data is up to date", but it reads as a clean verdict.
- **Expected:** wording like `(M7 list up to date)`, or drop it.
- **Repro:** `dcp grade ai_GypsyHelperWindow` at gildegold 6853071.
- **Impact:** small.
- **Related:** ../improvement-reports/skill-m7-vs-readable.md
