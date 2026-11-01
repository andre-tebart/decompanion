# The last line of a failed `dcp build` looks like a grade drop

- **Source:** match-base session 2026-11-01 (gildegold)
- **Severity:** minor (misleading output)
- **What happened:** an edit broke `rd.c`. With `| tail -1`, the only visible line was the grades summary, showing `byte+readable` falling from 1479 to 1463. Nothing on it said a unit had failed. The next `dcp diffclass` then said `unit rd has no object (dcp build)`.
- **Expected:** the last line of `dcp build` should say e.g. `FAILED units=rd` when a unit fails, or grades should only be printed after a clean build.
- **Impact:** about 3 minutes, and the worker briefly thought it had caused grade falls.
