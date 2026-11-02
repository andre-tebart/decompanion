# `dcp grade` printed no M7 for an implicitly declared call (`d3if_ScreenBox` in sv.c)

- **Source:** match-base session 2026-11-02 (gildegold), worker 16
- **Severity:** minor
- **What happened:** sv.c called `d3if_ScreenBox` with no prototype in scope (the only declaration was in include/cm.h, which sv.c does not include), so it was implicitly `int`. Grade listed only `(consistency (M7) current)`. Found by grep; the worker then added the prototype to include/d3_interface.h (no grade change). Possibly because the calls were wrapped in a `(char)` cast.
- **Expected:** M7 flags every call without a prototype in scope, casts or not.
- **Repro:** `uv run dcp grade sv_DrawBubbles` at gildegold before the d3_interface.h typing commit (before e2a566e).
- **Impact:** ~4 calls.
- **Related:** grade-m7-indirect-call-unnamed.md, ../improvement-reports/grade-m7-owner-header-hint.md
