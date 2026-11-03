# Trial and scoped edit primitive

- **Priority:** P1 · **Size:** M · **Root:** R11
- **Depends on:** trials-use-grade-verdict
- **Blocks:** exceptions-must-discriminate

## Problem

These are the two most frequent requests across all reports:

- Variant trials: about 22 sightings, often "the largest cost of the session". Workers edit, build, grade and revert by
  hand, for each variant.
- Scoped function edits: about 14 sightings. About 8 broken builds or corrupted files came from splicing by hand and
  from heredocs that destroy backslashes.

## Root cause

- Nothing writes or evaluates one function's text in place. `dcp fn` prints `at=` but cannot write.
- A trial compile-and-grade exists twice already: headers.rs:1026-1045 (`--trial`, build/obj/trial) and
  datafix.rs:747.

## Task

- `dcp fn NAME --replace FILE` swaps exactly the `at=` span (the address comment plus the definition, raw bytes, so
  backslashes are safe). It validates the result with the scan rules (see headers-write-keeps-phi).
- `dcp fn NAME --replace FILE... --trial` writes nothing. For each FILE it compiles the unit in build/obj/trial and
  prints one line: experiment, dist, proof, witness and differences. Worker 33's best-distance variant was semantically
  wrong, so distance alone is not enough.
- Factor the headers and datafix trials into one `trial(unit_text) -> verdicts`, used by all three.

## Rejected

- `--permute`.
- `--replace OLD NEW` pairs.
- A variant DSL. Generating variants stays the worker's script.

## Model

An experiment on a candidate H′ that leaves H unchanged (§4, §7).

## Reports

- dcp-try-variants-in-memory (about 22)
- scoped-function-body-edit (about 14)
- skill-edit-scripts-not-heredocs (tool part)
- fn-context (`--print`)
- headers-signature-dry-run
- data-definition-form-trial
