# A `similar:` line in grade

- **Priority:** P2 · **Size:** M

## Problem

Workers do not notice that a draft function is a twin of one already matched, so they solve the same spelling problems
twice.

## Task

`dcp grade NAME` prints a `similar:` line: the shape or byte functions whose callee and literal fingerprint matches the
original's. This is navigation only and produces no claim.

## Reports

- similar-function-hint
- twin-functions-together
