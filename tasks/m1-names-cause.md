# M1 names its cause candidates

- **Priority:** P1 · **Size:** S-M · **Root:** R5

## Problem

When a function falls after a header change, workers spend a long time finding which header and which include chain
caused it. This is the largest time sink in its report, with 8 sightings. The wrap cannot say why a grade changed either.

## Root cause

M1 says what fell, not which changed input in the unit's include set rebuilt it. The include sets are stored per unit
(compile.rs `include_set`), but nothing intersects them with the files changed since the witness.

## Task

- M1 names the files of the fallen unit's include set that changed since the witness commit, with the include chain.
- The wrap uses the same logic to attribute each grade change:
  - unit text unchanged, object changed: a header in its include closure changed (headers.rs `header_closure`);
  - object unchanged, grade changed: a rule or prover change, or another object's φ changed.

## Rejected

`fall-probe`, and a general `headers trial` command. Build plus check against the baseline is already a trial that
writes no baseline.

## Model

§8.5, §8.6: many small shifts share one cause, and a debt item names it.

## Reports

- fall-trigger-and-include-chain (8)
- wrap-grade-change-cause
