# Meaning differences are concrete differences

- **Priority:** P1 · **Size:** M · **Root:** R2
- **Depends on:** ref-check-in-object-experiment

## Problem

- An aligned pair of the same shape where only a non-address immediate differs is classed `code` and looks like
  allocation noise.
- The same goes for a pair where one side pushes a target as an address and the other loads from it. That one cost a
  worker an hour chasing a crash.
- Index-scale mismatches are likewise hidden in `code` hunks.

## Root cause

diffclass classes are fill / order / regs / slots / frame / tail / branch / code. `equiv::witness` (2843815) catches
only "a call or global store one side never refers to".

## Task

- For aligned pairs of the same shape, add two classes:
  - `const`: only a non-address immediate differs;
  - `addrval`: the same target is used as an address on one side and loaded on the other.
- Both are concrete differences: they keep a function from shape and are reported like the witness.

## Rejected

"Index scale" as a hint of its own.

## Reports

- address-vs-value-hunk-class
- asmdiff-index-scale-mismatch
