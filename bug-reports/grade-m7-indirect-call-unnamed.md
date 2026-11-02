# `dcp grade` reports `M7 consistency: ?() at line N` for calls through a function-pointer cast

- **Source:** match-base session 2026-11-02 (gildegold), worker 16
- **Severity:** minor
- **What happened:** `dcp grade sv_CameraFollow` on the old body, which called `((int (*)())*(int *)(n + 0x18c))(...)`, printed `M7 consistency: ?() at line N`. There is no symbol, and an indirect call through a K&R pointer cast is not a missing-prototype case.
- **Expected:** "indirect call through an unprototyped pointer type at line N".
- **Repro:** `uv run dcp grade sv_CameraFollow` on its pre-session body (gildegold 3e842a0).
- **Impact:** confusion only.
- **Related:** grade-m7-missed-implicit-call.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 20)
- gv's calls through `UNK_FR` (a cast macro of `ls_Read`) are listed as `?() at line 130`. Proposal: show the macro name or the function it casts.
