# Witness: a call to an H function with no counterpart in I

- **Priority:** P2 · **Size:** S-M

## Problem

Our code calls a same-unit static helper where the original has the code inline. The witness does not report it.

## Root cause

`equiv::witness` ignores calls to symbols without φ. Unbound relocations get placeholder addresses at 0xf0000000 and up
(`equiv::bind`), and are filtered out: in `witness`, and in `calls_differ` (the one call set asmdiff and diffclass print
as `calls:`), which only counts them as "calls to a symbol not placed".

## Task

A call from ours to an H function that has no address in the image is a concrete difference: "ours calls F, which has
no address in the image (expanded in the original?)". The `calls:` line names it too (ours x1, the original x0), by
our relocation's symbol.

## Reports

- grade-call-instead-of-inline
