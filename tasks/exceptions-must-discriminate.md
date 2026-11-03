# Exceptions must discriminate

- **Priority:** P1 · **Size:** M · **Root:** R8, R11
- **Depends on:** trial-and-scoped-edit

## Problem

An `@original` for a "six-argument call" turned out to have a different real cause: a nested call. The model itself
cites this case (§8.8). Nothing checks that an exception has evidence.

## Root cause

This is the open item in mental-model §10: `dcp exceptions` lists exceptions and counts the ones without a reason, but
never builds the variant without the exception.

## Task

- For each `@original`, trial-build the unit with the consistent spelling (using the trial primitive) and compare.
- If the bytes stay the same, flag the exception as having no evidence.
- Rerun when H changes, since exceptions go stale.
- Show the result in `dcp exceptions` and as a finding.
- frame-slot-annotation makes pending arguments across a call visible, which helps diagnose nested calls by hand.

## Rejected

A special "add esp right after the call" detector.

## Model

§8.8: an exception must discriminate, and exceptions go stale. This removes one row of §10's "not yet" table.

## Reports

- detect-nested-call-in-arguments
- skill-original-evidence-push-sequence
