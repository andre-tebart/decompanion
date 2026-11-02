# Q4 doesn't flag `(char *)&struct + OFF` raw offsets into a typed struct

- **Source:** match-base session 2026-11-02 (gildegold), worker 40
- **Severity:** minor (readable grade not earned)
- **What happened:** ai_ExecBuildBuilding passes `(char *)&m + 0x80`, `(char *)&m + 0x90` and `(char *)&m + 0x9c` (m is an AIMSG) to ai_ObjectPosition, ai_ObjectAngle and sprintf, yet reached readability=readable: Q4 only counts `*(T *)` casts.
- **Expected:** Q4 flags pointer arithmetic with constant offsets on the address of a typed object (suggesting the field at that offset).
- **Repro:** `uv run dcp grade ai_ExecBuildBuilding` at gildegold 6520924 (no Q4 listed).
- **Impact:** none in time; inflated readability counts.
- **Related:** ../improvement-reports/q4-indexed-view-macro.md, ../improvement-reports/asmdiff-field-names-for-offsets.md
