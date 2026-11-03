# Wrap and promote refuse on a dirty tree

- **Priority:** P0 · **Size:** S · **Root:** R9

## Problem

`dcp session wrap` promoted grades from uncommitted source.

## Root cause

- `session start` checks `session_dirty` (commands.rs:686-697).
- `Wrap` (commands.rs:719-740) and `promote_command` do not.

## Task

Refuse, not warn, when src/, include/ or decl/ are dirty. Reuse the `session_dirty` filter, which excludes
ledger/grades.tsv.

## Model

§8.6: a witness is an (H, φ) whose experiment passed, which means a commit. Promoting from a dirty tree records a
witness that is in no history.

## Reports

- session-wrap-accepts-uncommitted-source
- skill-windows-commit-message-file (the real defect behind it)
