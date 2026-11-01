# `dcp check`: warn when one commit changes a unit's head and a function grade

- **Source:** match-base session 2026-11-01 (gildegold), worker 2
- **Area:** dcp check / dcp-match-base skill
- **Problem:** the skill's "commit the head on its own" rule is easy to miss mid-function. A `gfx.h` include went into a function commit.
- **Proposal:** `dcp check` warns when staged changes touch both a unit's head and a function's grade.
