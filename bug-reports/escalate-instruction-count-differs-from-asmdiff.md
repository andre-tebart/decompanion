# `dcp escalate` size check quotes other instruction counts than the `asmdiff` head

- **Source:** match-base session 2026-11-02 (gildegold), worker 46
- **Severity:** minor
- **What happened:** for ai_AlchemistResearchWindow (0x57c690) the worker saw `asmdiff` report `ours=544 original=563`, while the `dcp escalate` size refusal (and `dcp grade`) implied other counts (559 vs 563). It could not tell which count the threshold uses and passed `--size-explained` blindly. (The counts may have come from builds minutes apart; unverified whether they disagree on one build.)
- **Expected:** escalate, grade, asmdiff and diffclass print the same `ours=` / `original=` for one build, and the escalate message names the limit it applied (`diff 19, limit 12`).
- **Repro:** `dcp asmdiff ai_AlchemistResearchWindow | head -1` vs `dcp escalate ai_AlchemistResearchWindow "..."` at gildegold 3e9915b (before the rework).
- **Impact:** low; an unjustified `--size-explained`. Related: improvement-reports/grade-show-instruction-counts.md
