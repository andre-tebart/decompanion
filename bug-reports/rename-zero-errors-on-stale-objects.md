# `dcp rename` reports "0 new error(s)" while the edited source doesn't compile

- **Source:** match-base session 2026-11-02 (gildegold), worker 20
- **Severity:** minor
- **What happened:** after `dcp rename full_data_6f25a8 main_DayEnding`, the result said "0 new error(s)", but `main_DayEnding = 1;` can't compile while the symbol is still a `GAPDATA` array. The check apparently ran on cached objects ("keep their objects").
- **Expected:** compile the units whose source changed, or note that post-rename compile errors aren't checked.
- **Repro:** `uv run dcp rename full_data_6f25a8 main_DayEnding` with a use that assigns an int (gildegold before 40f8c9b).
- **Impact:** small.
