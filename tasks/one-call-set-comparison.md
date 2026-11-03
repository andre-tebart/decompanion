# One call-set comparison

- **Priority:** P0 · **Size:** S · **Root:** R1

## Problem

- `calls differ: ours _ftol, the original none`, although the original does call it (ours x2 against the original's
  x1).
- A tail `jmp sym` shifts the count onto another callee.
- `equiv::witness` has its own call set.

## Root cause

`unmatched_calls` (asmcmd.rs:70-98) prints only the surplus and counts only the `call` mnemonic (line 72).

## Task

- Write one function that computes the multiset of calls per side, tail `jmp` to a symbol included.
- Print counts on both sides, only for callees whose counts differ: `calls: _ftol ours x2, the original x1`.
- asmdiff, diffclass and `equiv::witness` all use it.

## Reports

- diffclass-calls-differ-misses-original-call
- asmdiff-calls-differ-none-wording
