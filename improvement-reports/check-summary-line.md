# `dcp check`: a short final verdict line (or `--summary`)

- **Source:** match-base session 2026-11-02 (gildegold), worker 22
- **Area:** `dcp check`
- **Problem:** after header edits the worker only wanted "any M1?", but `dcp check` prints a long report; it grepped for `gate=` and `M1`.
- **Proposal:** end with `M1=0 M1.debt=37 errors=0 gate=ok`, or a `--summary` flag.
- **Cost of not having it:** two extra commands each time.
- **Related:** data-check-one.md (check --name / --at)

## Also seen (match-base session 2026-11-02 (gildegold), worker 51) - output noise
- Every `dcp check` repeats the same link notes (`note import library mss32.lib...`, `note mss32.lib holds...`, `note library order from the image...`). Needed: `gate=` and any `error` lines; on a fail the worker grepped `^error`. Want notes only with `-v`, and error lines printed first on a fail.

## Also seen (match-base session 2026-11-02 (gildegold), worker 52)
- Same three link `note` lines (mss32.lib import library, library order) on every `dcp check`. Want them dropped when unchanged, or only with `-v`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 54)
- ~8+ lines per run (summary, `link=`, mss32 / library-order notes); always grepped `^error|gate=`. Want `gate=` plus errors by default, notes behind `-v` or only on change.

## Also seen (match-base session 2026-11-02 (gildegold), worker 55)
- Same 3 mss32/library-order notes, plus totals (`contradiction=3562 ... warn=3694`) that don't show what changed. Want the gate line plus findings new since the session base.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 56)
- `dcp check --errors` (or `-q`): only error lines and the gate line (worker always ran `dcp check | grep "^error"` against `warn=3693`).

## Also seen (match-base session 2026-11-02 (gildegold), worker 57)
- Counts, link notes and library-order notes every time; grepped for `M1` and `gate=`. Want a default printing M1 falls, new errors and `gate=`, `--verbose` for the rest.

## Also seen (match-base session 2026-11-02 (gildegold), worker 59)
- ~6 lines per run, 3-4 of them unchanging link notes; grepped for `gate=` / errors ~15 times this session.

## Also seen (match-base session 2026-11-02 (gildegold), worker 61)
- Long finding list; only M1/M5 and `gate=` needed. Want a short default (gate-relevant findings plus counts), `--all` for the full list.

## Also seen (match-base session 2026-11-02 (gildegold), worker 62)
- ~5 lines (fine), but finding the single M5 still took a grep; want `error=` lines first.

## Also seen (match-base session 2026-11-02 (gildegold), worker 63)
- The D5 line is long with its file reference at the end (`a=src:...`); want `file:line` first.

## Also seen (match-base session 2026-11-02 (gildegold), worker 65)
- 4-6 lines, ending every run with the same mss32 / library-order notes. Notes only on change or under `-v`.
