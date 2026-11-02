# One unit failing to compile floods `dcp check` with per-function M1 lines

- **Source:** match-base session 2026-11-02 (gildegold), worker 25
- **Severity:** minor (misleading)
- **What happened:** removing a duplicate prototype of 0x4c4ac0 from include/gv.h broke f3gm.c (its only early declaration came from that header; C2371). `dcp check` then listed ~80 separate `M1 ... byte -> draft` lines for f3gm functions, burying the single real cause `M.compile`. The worker first believed a float-signature change had broken 80 matches.
- **Expected:** list `M.compile` first, then one line like "N functions of unit f3gm counted as unbuilt".
- **Repro:** delete a header prototype another unit relies on, `uv run dcp build`, `uv run dcp check` (gildegold, before db79813).
- **Impact:** ~5 minutes plus a revert.
- **Related:** rename-refused-hand-written-name-other-signature.md (same cascade in rename), ../improvement-reports/check-summary-line.md
