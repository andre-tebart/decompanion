# A unit's object stays stale after a header change

- **Priority:** P0 · **Size:** S-M (the repro decides)

## Problem

From bug-reports/stale-object-after-header-change.md (m7 session 3 and gapdata session 1, gildegold, 2026-11-08). After a
declaration-only header change (`include/main.h`: one new `extern int`; earlier `cm.h`), `dcp build` reported success
and left `src/he.c`'s old object. `dcp check` then reported a false M1 for `he_PostEvent67` (byte -> shape: `fild` +
`fmulp` where a clean build gives `fimul`), and `dcp headers probe he` refused because "the control compile does
not reproduce the build". `dcp build --force` fixed it. It happened twice, on the same function.

Every header edit of the M7, gapdata and exception passes (the bug-hunting passes before deep matching) can produce
a phantom fall. Disproving it costs a 4-minute forced rebuild. A worker that trusts it chases a regression that does
not exist, or accepts a witness against a wrong build.

## What the code does (compile.rs `ensure`)

- A unit is fresh when its source hash, flag hash and `include_hash` (the content hashes of its include set, Memo::set)
  equal the row's. The include set is keyed by (source hash, flags, the include directories' listing hash), so a
  header whose *content* changes keeps the key: the set is reused and only its content hashes are re-read.
- So the reported sequence should recompile he.c if he.c's include set contains main.h. Either it does not (the set
  is stale: a header that started or stopped including another one keeps the old set, since the key is unchanged),
  or the content hash is stale (the persisted stamps: fsmemo's racy-clean rule, the daemon's memo across epochs), or
  the object was right and the control compile differs for another reason (the parallel preprocess beside the compile).

## Task

1. Reproduce in a gildegold worktree (repro in the report: 44092cea~1, a declaration-only main.h edit, `dcp build`,
   `dcp check`) and find out which of the three it is.
2. Fix the cause. If the set itself can go stale: key the include set by the content hashes of the set's own
   files as well (the set's files are its inputs), or recompute the set whenever any file in it changed.
3. A test: a unit that includes a header through another header; edit the inner header (a declaration only); the
   build recompiles the unit.
4. Belt and braces: `dcp headers probe`, on "the control compile does not reproduce the build", recompiles the unit
   once and retries before refusing, and `dcp check` names the unit whose object the probe could not reproduce.

## Reports

- stale-object-after-header-change (bug)
