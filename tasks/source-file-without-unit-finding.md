# A source file that yields no unit is ill-formed

- **Priority:** P0 · **Size:** S-M · **Root:** R7

## Problem

A `src/*.c` file that the scan cannot read sensibly (here, text inserted between every character) silently stops being
a unit. Then:

- grade says "no such function";
- M1 says "its source is gone?".

## Root cause

- `plan::units` makes a file a unit only if the scan finds an addressed function in it (plan.rs:64-74,
  `if !fns.is_empty()`).
- `compile::ensure` then deletes its `tu` row as removed (compile.rs:353-359).

## Task

- Plan units from the file list.
- A `src/*.c` file with no addressed function is an ill-formed finding: "src/gv.c: no addressed function found
  (scan: ...)".
- grade, fn and build say that the unit file failed to load, instead of "no such function".

## Rejected

- A "mass grade drop" warning. The named falls from output-convention cover it.

## Reports

- build-unit-silently-dropped
