# `dcp why`: owner first; ref answers for data

- **Priority:** P2 · **Size:** S + M

## Problem

- `dcp why` prints the section first. Workers wanted the owner.
- An aligned data dword that equals a known object's start is not shown as a reference, for example a const pointer.

## Root cause

- The questions print in `Question::ALL` order.
- `why` answers no `ref` question for data.

## Task

- Print the owner first. No `--brief` flag.
- Add a `ref` answer for an aligned data dword equal to the start of a known function, string or data object (§8.2
  strong tier, derived).

## Reports

- why-brief-output
- why-const-pointer-hint
