# headers conflicts: duplicates anywhere, superseded declarations in the trial

- **Priority:** P1 · **Size:** M

## Problem

- Mid-file and K&R redeclarations that a header makes redundant are not listed, and `--write` keeps one of them.
- The trial on a `supersedes` conflict fails to compile, and prints `trial=failed` among about 100 lines.

## Root cause

- Duplicates are taken only from the head region (`ln < end`, headers.rs:895-910).
- The documented resolution ("the local one goes") is never tried in the trial.

## Task

- List and drop duplicate and K&R redeclarations anywhere at file scope.
- The trial drops a superseded local declaration and grades.
- `--write` runs the trial and writes only when nothing falls. This merges `--trial --write`. (`--trial` and `--write`
  already refuse a text that detaches an address comment: `phi_breaks`.)
- The refusal message says what resolves each blocking kind. For `call`: an `@original` cast macro when the original's
  call site has the other arity.

## Model

§8.5: the declaration set is observable, and the trial is the experiment.

## Reports

- headers-conflicts-write-drops-one-duplicate
- headers-conflicts-trial-silent-with-supersedes
- headers-conflicts-preexisting-conflict-refuses-write (message part only; the refusal itself is right)
