# One output convention: verdict, failures, named changes

- **Priority:** P1 · **Size:** M-L · **Root:** R5

## Problem

Report-style commands print their full state on every call, and workers pipe everything through grep or tail. This is
the largest group of reports (about 25 reports, 60+ sightings). Examples:

- One `ok <unit> errors= warnings= obj=` line per compiled unit: 10 to 90 lines after a header edit.
- The full `grades:` histogram. It never names which function moved, and it cannot show two moves that cancel out. That
  is all `build-grades-line-mismatch` is.
- check repeats the static link `note` lines and the category totals on every run.
- session start prints the layout overview and the full status block for every kind of session.
- The wrap prints names.log lines raw, each with its full reason: up to 12 KB.
- Rename lists every changed line and full comment rewrites. Its `renamed=`/`file=` records stay on a refusal, so they
  read as edits that were made.
- headers conflicts prints its regrade and declaration-set lists before the verdict.
- asmdiff prints legend lines and `=` alias lines; refs prints every claim and every full source line.
- The Q4 remedy is appended to every Q4 line. (M9 and the reference check's lines now print once per reference, at
  most 8 in grade's failing lines.)
- A finding line `severity category check` prints category `debt` for M1, so an undeclared fall reads like a declared
  debt item.

## Root cause

No command has a "changes since the previous observation" view, and there is no project-wide rule for what a default
view shows. Every command grew its own output.

## Task

Write the convention into AGENTS.md, then apply it to build, check, session start, wrap, rename, headers conflicts,
asmdiff, diffclass and refs:

- Line 1 is a stable verdict record (`compiled=N failed=0 ...`).
- Then the failing items: errors first, the gate line last.
- Then **named changes since the previous run**: `fell: 0x578e40 ai_X byte->shape`, `raised: ...`,
  `new error: M5 ...`, `gone: ...`.
- The full state goes behind `-v` or into the read commands (`grade`, `findings`, `why`).
- No legends in output. Guidance and remedies go to `-h` and the skills.
- Repeats are collapsed (`xN`), and a shared reason is printed once.
- Lines are truncated, with a pointer to where the full text is (for example names.log, build/session/report.md).
- A refusal prints the refusal and its reasons, and no planned edits.
- M1 prints `category=debt undeclared`.

The delta needs no cache. The engine already re-records a rule's run and writes only the facts that changed
(store.rs:264-282), so diffing the previous and current G.grade experiment claims and findings gives the moves. This
also makes in-session losses visible: M1 only compares with ledger/grades.tsv, which is written at wrap.

## Rejected

Per-command flags: `--fn`, `--summary`, `--errors`, `-q`, `--quiet`, `grade --changed`, `--hide-alias`, `--class`,
`--out`, `--callers/--from/--to/--claims/--decls`.

## Reports

- build-quiet-grade-summary (14 sightings)
- build-list-grade-changes
- build-grades-line-mismatch
- check-summary-line
- check-guard-session-gains
- check-m1-debt-label-before-debt-exists
- session-start-output-too-large
- session-report-readonly
- wrap-rename-shared-reason-once (15)
- rename-summary-line-first (11)
- rename-report-comment-rewrites
- rename-name-changed-units
- rename-refused-hand-written-name-other-signature (presentation)
- headers-conflicts-output (9)
- grade-q4-remedy-text-repeated
- grade-m9-line-repeated-per-use
- asmdiff-changed-only
- asmdiff-summary-flag
- asmdiff-segments-and-runs (output part)
- refs-default-output-too-large (12)
- refs-decl-sources (counts)
- diffclass-collapse-frame-shift-lines
