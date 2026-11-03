# Not-found paths explain themselves

- **Priority:** P1 · **Size:** S · **Root:** R6

## Problem

After any of the following, `dcp grade X` says "X is neither a unit nor a graded function":

- a `#define` placed between the address comment and the definition;
- `}/* 0x...` ending up on one line;
- a unit that failed to build.

There are 6 sightings.

## Root cause

The findings that explain it already exist:

- L.src "no address comment directly above its definition" (srcscan.rs:460);
- M.gen "the object defines it, no comment" (mrules.rs:89-96);
- M.compile.

The not-found paths in grade, diffclass, escalate and asmdiff never consult them (matchcmd.rs:133-135).

## Task

When the name has no row, look up the ill-formed and compile findings for that name or its file, and print them. No
new state is needed.

## Rejected

Warning when the function count drops: that is history state, and output-convention's named falls cover it.

## Reports

- grade-lost-address-comment-silent (6)
- grade-failed-build-says-unknown-name
