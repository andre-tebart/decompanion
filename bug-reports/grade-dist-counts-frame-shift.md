# `dcp grade` `dist` and asmdiff `differing` move in opposite directions on one edit

- **Source:** match-base session 2026-11-01 (gildegold), worker 4
- **Severity:** minor (misleading; the skill says to revert when `dist` grows)
- **What happened:** after rewriting `D3FL_POS` in d3fl_Draw, the asmdiff head went from `differing=2703` to `2525` and code hunks from 2559 to 2545. Over the same edit `dcp grade` `dist` went from `2863 ins` to `3631 ins`, and the hunk line now shows `frame 206` where it showed `frame 92`. `dist` seems to count lines that differ only by the frame offset; asmdiff's aligned view does not.
- **Expected:** `dist` uses the frame-aligned comparison asmdiff uses, or the grade line prints both (`dist=... aligned=...`).
- **Repro:** `git checkout cb2e91b -- src/d3_fl.c`, then `uv run dcp grade d3fl_Draw; uv run dcp asmdiff d3fl_Draw | head -1`; repeat at 774a16d and compare.
- **Impact:** about 10 minutes of re-checking, plus an explanation in the commit message; pushes workers to revert real improvements.
