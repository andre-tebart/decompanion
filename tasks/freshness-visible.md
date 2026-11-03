# Freshness is visible

- **Priority:** P1 · **Size:** S · **Root:** R5

## Problem

- `dcp build` says `compiled=0 fresh=93`, or "compiling 1 of 93" after a header edit. Workers doubt that their edits
  reached the compiler, and change a constant on purpose to check.
- Several rewrites with the same `dist` cannot be told apart.

## Root cause

- Every match command first runs a quiet build that prints nothing: grade, next, asmdiff, diffclass
  (commands.rs:164-187), and rename and data fix (`glue::rebuilt`, `ensure(log=false)`). The next explicit build then
  truthfully reports that nothing is left to do.
- The staleness test itself is content-based and correct (compile.rs:271-283).
- `build/amalg/exe/*.c` is a leftover from the Python era. No Rust code reads or writes it, yet a worker compared
  against it.
- Hardening gap: the include files are hashed after the compile (compile.rs:296-334), so a header edited during a
  compile can record an old object as fresh.

## Task

- A quiet build prints one stderr line when it compiled something: `build: compiled f3gm, am (1.2 s)`.
- grade and build show a short hash of the function's compiled code and relocations on the function line. G.grade's
  `Key` already holds it (grade.rs:46, 54-70).
- `dcp setup` or `dcp build` removes the dead build/amalg.
- Hash the include files before, or at, the compile.

## Rejected

- "Compiled by grade 3s ago from hash X" as stored history.
- A session "was X" state.

## Model

Every read rebuilds, so an observation dcp prints is never stale (§5). The tool should show that.

## Reports

- build-freshness-unclear
- build-header-edit-rebuilt-one-unit
- grade-object-unchanged (5)
- dist-with-hunk-class-counts
- skill-build-compiles-pending-edits
