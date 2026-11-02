# Branch-target list repeats every jump shifted by one inserted/removed block

- **Source:** match-base session 2026-11-02 (gildegold), worker 33
- **Severity:** minor (misleading volume)
- **What happened:** for ai_ExecuteBuyBuilding (0x498470), `B3 draft: unexplained code hunks: code 5` came from a single early-return epilogue, but `branch targets differ` listed every jump that the resulting 4-byte shift moves (~12 lines), so the output looks much worse than the actual difference.
- **Expected:** collapse targets that differ only by one inserted/removed block into one line, e.g. "N targets shifted by +4 after 0x49847a".
- **Repro:** `uv run dcp grade ai_ExecuteBuyBuilding` at gildegold 2428e22.
- **Impact:** a few minutes per function.
- **Related:** grade-branch-targets-differ-same-target.md, ../improvement-reports/diffclass-tail-epilogue-class.md
