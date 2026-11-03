# The datum object experiment

- **Priority:** P1 · **Size:** M · **Root:** R1

## Problem

A datum whose initializer bytes differ from the original at its declared address just stays declared. Nothing fails,
and M1 never sees a data fall.

## Root cause

The data rules only prove, never refute:

- `M.data.content` proves a datum only when its bytes match at the declared address and nowhere else, and errors only
  when the bytes are found elsewhere (registry.rs:357).
- A mismatch at the datum's own address stays `M.data.draft`.

## Task

- The datum's experiment is equal or not equal at the declared address, with relocated fields and padding masked, and
  the reference check (refcheck.rs: the sites at their offsets, as `sites_matched`, then `check` against φ) applied
  to relocated fields.
- Grade it, and let M1 see data falls.
- A datum whose unit has no object is *not run* (outcome `open`, `grade::NOT_RUN`), as for functions: M1 counts it in
  its per-unit line, not as a fall.

## Rejected

Making this a new D rule.

## Model

§4: an object experiment exists for data as well as for functions.

## Reports

- check-moved-datum-initializer-bytes
