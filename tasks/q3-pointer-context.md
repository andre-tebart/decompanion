# Q3 only in pointer context

- **Priority:** P1 · **Size:** S · **Root:** R8

## Problem

Q3 flags flag masks such as `0x1000000` as hard-coded addresses (3 sightings). Workers then rewrite the masks as
`(1 << 24)`, or fake `&sym + off` addresses, to silence it. (A fake `&sym + off` outside sym's declared size is now
an M.contain error, refcheck.rs `Outside`; the false Q3 that provokes it remains.)

## Root cause

Q3 flags any integer literal in [image base, image end) (readability.rs:363-373). Whether a number is an address is
the model's ref question. §8.2 calls it ambiguous, and §8.3 already answers it from the bytes through M.ref.missing and
A1.

## Task

- Q3 flags only literals in pointer context: cast to a pointer type, or dereferenced.
- The "hard-coded address where the original refers" case stays with M.ref.missing and A1.

## Rejected

An operator list for `&` and `|`.

## Model

- §8.2, §8.3: the ref question belongs to the model.
- §9 keeps readability apart from it.

## Reports

- grade-q3-flag-constant-as-address
