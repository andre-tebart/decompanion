# Duplicate definitions across units; stray exception markers

- **Priority:** P2 · **Size:** S

## Task

- **One external name defined in two units** is ill-formed: H is no program. Today only the link at check or wrap
  catches it. Add a cheap check from the scan's definitions, so the build reports it.
- **An exception marker on a line with no diagnostic** is a finding. `@original` is read per line (lint.rs:34-39), so a
  misplaced marker silently does nothing. Don't widen the marker's scope: an exception names its site (§8.8). Exceptions
  go stale, and this catches misplaced markers too.

## Reports

- build-accepts-duplicate-function-name-across-units
- check-original-marker-line-only
