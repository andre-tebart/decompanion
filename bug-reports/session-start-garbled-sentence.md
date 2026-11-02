# `dcp session start` prints a garbled sentence

- **Source:** match-base session 2026-11-02 (gildegold), worker 16
- **Severity:** minor (cosmetic)
- **What happened:** the output says "This is a match-base session is counted in functions".
- **Expected:** e.g. "This is a match-base session; it is counted in functions."
- **Repro:** `uv run dcp session start` for a match-base session (gildegold e2a566e).
- **Impact:** none.

## Also seen (match-base session 2026-11-02 (gildegold), worker 18)
- `uv run dcp session start --kind match-base`: "gate: ok. This is a match-base session is counted in functions...".

## Also seen (match-base session 2026-11-02 (gildegold), worker 23)
- Same garbled sentence; it also prints the layout status ("next: nothing open in the game code (layout complete ...)") in a match session.

## Also seen (match-base session 2026-11-02 (gildegold), worker 31)
- Still present at gildegold 28b8643.

## Also seen (match-base session 2026-11-02 (gildegold), worker 35)
- Still present.

## Related (match-base session 2026-11-02 (gildegold), worker 36)
- With `--kind match-base`, `dcp session start` first prints the full layout status of every unit (92 `unit=... status=separated` lines) before the match status and the gate line; the worker had to `tail` for `gate: ok`. Proposal: show gate and match phase first, collapse the layout listing to one summary line.
