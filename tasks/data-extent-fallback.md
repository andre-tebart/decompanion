# Data extent fallback is never one byte

- **Priority:** P0 · **Size:** S-M · **Root:** R4

## Problem

- `dcp why` on named data shows `value=00` or `value=4c`: one byte of a float or a pointer.
- `dcp answers` shows 0x5ed1b0 (`G6CURSOR *const`, reproduced) as 1 byte, and 0x5ed1b1..bc as unknown.data. That is a
  wrong owner answer.

## Root cause

- `data_extent` falls back to one byte when our object gives no size (rules.rs:707-711).
- The why value line is cut at the end of the owner run (clicmd.rs:525-527, 599).

## Task

- Use our declared type size from the front end. Otherwise use the contiguity convention up to the next owner.
- The why value line reads independently of the owner run: up to 16 bytes, bounded by the next owner.
- Check `data_symbols` sizes for the same fallback.

## Model

- The owner question (§2).
- Layout totality (§7).

## Reports

- why-named-data-no-float-value
- also feeds runtime-data-guards-debug-variant
