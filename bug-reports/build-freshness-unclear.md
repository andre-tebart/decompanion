# `dcp build` gives no way to tell whether the latest edit reached the compiler

- **Source:** match-base session 2026-11-02 (gildegold), worker 58
- **Severity:** minor
- **What happened:** after edits, `dcp build` kept printing `compiled=0 fresh=93`, because `dcp grade` / `dcp rename` had already compiled. `build/amalg/exe/f3gm.c` was also stale (a new `goto world` was not in it). With several rewrites giving identical `dist`, the worker could not tell whether edits reached the compiler and checked by changing a constant on purpose.
- **Expected:** a note like `fresh=93 (compiled by grade 3s ago from hash X)`, and the amalgamated file kept in sync (or documented as not the compiled input).
- **Repro:** edit src/f3gm.c, `dcp grade NAME`, then `dcp build`; compare build/amalg/exe/f3gm.c (gildegold, before ca33582).
- **Impact:** ~4 tool calls, and doubt about every "no change" result.
- **Related:** ../improvement-reports/skill-build-compiles-pending-edits.md, ../improvement-reports/grade-object-unchanged.md
