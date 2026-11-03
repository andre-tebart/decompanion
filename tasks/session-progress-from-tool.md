# Session progress from the tool, not from commits

- **Priority:** P1 · **Size:** S · **Root:** R12

## Problem

The skill counts commits ("count the commits and stop at 8"). Workers bend the rules to make the count work:

- staging part of a change to give a typing change its own commit (about 15 minutes once);
- an `--allow-empty` commit for a grade the tool raised;
- guessing the commit form for data inside a unit's own block.

## Root cause

The tool already knows the session base and the grade changes against it (`session::grade_changes`, session.rs:275).
`dcp session status` prints only the clock.

## Task

- `dcp session status` and the wrap print `done=N/8` for match-base. N counts functions raised to shape or
  byte + readable, or newly tagged `@deep` or `@stuck`, against the base. Optionally exclude functions whose source span
  did not change.
- The wrap ends by repeating its summary line and pointing to build/session/report.md. A repeat at the same HEAD with
  no changes says "already wrapped, no changes".
- Run `grades_auto_clear` in the wrap's gate too, not only in `dcp build`, so a raise compiled implicitly by grade or
  rename doesn't keep a stale tag.
- Skill edits are in skills-sync-and-fixes.

## Rejected

`dcp commit --typing` and `dcp fn --stash`: git wrappers are outside dcp's scope.

## Reports

- skill-typing-commit-split
- skill-grade-change-without-source
- skill-data-commit-in-unit-block
- skill-deep-function-reaches-byte
- session-count
- session-report-readonly
