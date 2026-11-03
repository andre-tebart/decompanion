# Differential runtime trace

- **Priority:** P2 · **Size:** L

## Problem

When a built image behaves differently at runtime (a crash, wrong state), workers bisect by hand.

## Task

`dcp run --trace NAME` runs the original and ours under the debugger and reports the first diverging call: the callee
or the argument values. The debugger and the symbol mapping already exist.

## Model

A dynamic experiment against I.

## Rejected

runtime-data-guards-debug-variant, runtime canaries. Their real cause is a datum smaller than the original's extent:
data-extent-fallback and containment-check are done (a data owner is never one byte; M.contain, D7 by the declared size, D9).

## Reports

- differential-trace-against-original
- runtime-data-guards-debug-variant (declined)
