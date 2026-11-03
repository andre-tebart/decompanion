# Trials use G.grade's verdict

- **Priority:** P0 · **Size:** S · **Root:** R1
- **Leads to:** trial-and-scoped-edit

## Problem

`headers conflicts --trial` reports "fall byte->draft" where the function was draft anyway. It can also report false
rises.

## Root cause

- `trial_grades` (headers.rs:1083-1090) grades byte by compare, otherwise by `FunctionCompare.verdict.shape`. It skips
  three things G.grade does:
  - the prover (binding through φ, equiv::bind);
  - the reference check (refcheck.rs: every relocated field against φ, literals by their bytes);
  - the code grade from both (`grade::code_grade`).
- A fall is measured against the current row's code (headers.rs:1214-1215), never against the baseline.
- `data fix` (datafix.rs:747) has its own byte-only trial.

## Task

- Write one verdict function, used by G.grade, the header trial and `data fix`.
- Per function, the trial prints `now=` and `baseline=`, and whether M1 would fire.
- Check that the `data fix` trial still guards what it should.

## Model

§4: an experiment must have one implementation.

## Reports

- headers-conflicts-trial-fall-against-current-grade
- fall-trigger-and-include-chain (part)
