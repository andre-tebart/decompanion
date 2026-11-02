# `dcp build`: a terse summary while iterating on one function

- **Source:** match-base session 2026-11-02 (gildegold), worker 49
- **Area:** `dcp build` (output size)
- **Problem:** `dcp build` always prints the full grade histogram; while iterating the worker only needed to know whether the function being edited (or anything else) changed.
- **Proposal:** a `--fn NAME` / quiet mode: one line with that function's grade and distance, plus a count of other grade changes.
- **Cost of not having it:** context only (dozens of builds per session).
- **Related:** build-list-grade-changes.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 50)
- After a header edit, `dcp build` prints one `ok <unit> errors=0 warnings=NNN obj=...` line per recompiled unit (10+ lines). Want per-unit lines only on error or with `-v`; keep failures, the grade summary and falls (build-list-grade-changes.md).

## Also seen (match-base session 2026-11-02 (gildegold), worker 53)
- ~10 `ok <unit> errors=0 warnings=NNN obj=...` lines after a header edit; warning counts (100s-2000s per unit) are noise. Want failed units only, plus `changed: fn A draft->shape`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 54)
- 10-22 `ok <unit> ...` lines after a header edit plus `rules:` / `target=` lines. Want only failed units, `compiled=22 failed=0`, and `grades:`; per-unit lines behind `-v`. See also ../bug-reports/build-grades-line-mismatch.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 55)
- 10 `ok <unit> ... warnings=N` lines after a header edit plus `rules:`; piped through grep every time. Needed: errors and `grades:`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 57)
- 15-37 `ok UNIT ...` lines after gv.h / ch.h edits. Want `compiled=N failed=0` plus grades, per-unit lines only on failure.

## Also seen (match-base session 2026-11-02 (gildegold), worker 58)
- `rules: N ran of 60, ms` plus the full histogram on every call. Want `grades: +1 byte+readable, -1 shape+readable`, only when changed.

## Also seen (match-base session 2026-11-02 (gildegold), worker 59)
- 15 per-unit lines after the gv.h edit. Want `compiled=15 failed=0`, failed units only.

## Also seen (match-base session 2026-11-02 (gildegold), worker 60)
- ~33 lines after an f3gm_types.h edit (31 units). Want `compiled=31 failed=0` plus error lines, per-unit lines behind `-v`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 61)
- ~90 per-unit lines when gv.h changes. Want failed units only, `compiled=N failed=0`, grades line; `-v` for the rest.

## Also seen (match-base session 2026-11-02 (gildegold), worker 62)
- 15-31 `ok <unit> ...` lines per shared-header build (gv.h, f3gm_types.h), ~6 times this session (~30 lines each). Want `rebuilt=15 failed=0` plus failing or warning-count-changed units.

## Also seen (match-base session 2026-11-02 (gildegold), worker 63)
- ~95 lines: one `ok <unit> ...` line per unit even for reused units; grepped `grades` every time. Want only compiled/failed units, then the summary.

## Also seen (match-base session 2026-11-02 (gildegold), worker 64)
- 15-36 lines per shared-header edit; `| tail -1` every time. Want failed units, `compiled=36 failed=0`, and the changed functions.

## Also seen (match-base session 2026-11-02 (gildegold), worker 65)
- ~35 lines after a gv.h edit; want `compiled=35 failed=0` and failing units only.

## Also seen (match-base session 2026-11-02 (gildegold), worker 66)
- One `ok <unit> errors=0 warnings=2441 obj=...` line per unit; every build piped through `grep " error"`. Want only `FAIL` units with their errors, then one summary line.
