# Witness: a call to an H function with no counterpart in I

- **Priority:** P2 · **Size:** S-M

## Problem

Our code calls a same-unit static helper where the original has the code inline. The witness does not report it.

## Root cause

`equiv::witness` ignores calls to symbols without φ. Unbound relocations get placeholder addresses at 0xf0000000 and up,
and are filtered out (equiv.rs:1988, 2345-2350).

## Task

A call from ours to an H function that has no address in the image is a concrete difference: "ours calls F, which has
no address in the image (expanded in the original?)".

## Reports

- grade-call-instead-of-inline
