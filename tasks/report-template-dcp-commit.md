# Reports carry the dcp commit

- **Priority:** P1 · **Size:** S · **Root:** R13

## Problem

Many reports were filed against dcp builds older than the fixes they describe. Some sessions ran `uv run dcp`. Reports
cite the gildegold commit but not the dcp commit, so "is this still present?" could only be decided by re-running.

## Task

- `dcp --version` prints the dcp commit (and whether the tree was dirty).
- The report filing section of the skills (dcp-match-base-loop "Filing") requires a `dcp:` line with that output.
- Optionally, `dcp session start` prints the dcp commit in its first line.
