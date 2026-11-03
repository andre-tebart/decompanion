# Re-measure performance after the Rust port

- **Priority:** P1 · **Size:** S

## Problem

peformance-reports/2026-11-01-match-base-gildegold.md was measured before the port (e225052). Two of its findings are
already solved:

- the 120 ms client floor: now `dcp fn` reports `daemon request=2` ms and about 30 ms wall time;
- `--time`: `DCP_TIMING=1` covers it.

Its other figures are stale, and several open questions remain against the AGENTS.md budget (reads under 10 ms warm,
builds under 1 s warm).

## Task

Measure with dcp-bench and DCP_TIMING on gildegold:

- a warm one-unit build against 1 s. VC6 alone takes about 0.7 s on main.c (compile.rs:295), then lint and refresh
  follow;
- a header fan-out build (parallel compile exists: `run_threads`, compile.rs:263-287);
- a cold `session start` after a daemon restart (55 s reported). Print its phases; the held verdicts and the prover are
  recomputed for everything (grade.rs:210-218);
- the 19.7 s single-unit build after `escalate`;
- `headers conflicts --trial` on f3gm (reported at 1-2 minutes), after trials-use-grade-verdict;
- the first-use cost of `dump` and `why`.

File a task for each result that misses the budget.

## Reports

- peformance-reports/2026-11-01-match-base-gildegold.md
- the headers-trial timing in the headers reports
