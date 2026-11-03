# Switch tables compared per case

- **Priority:** P1 · **Size:** M · **Root:** R3

## Problem

One folded case prints `byte +0x44: 0x00 vs 0x48 ...` 12 times. The case-body order is not visible.

## Root cause

- `compare_tables` (diffclass.rs:786-870) compares the index table byte by byte at fixed positions.
- It judges entry targets with its own map, built from plain `Equal` opcodes, and accepts any pair "in the same hunk"
  (diffclass.rs:812-826).
- That is a third correspondence, more lenient than `branch_diffs`.

## Task

- Compare per case value: case → entry → target cut, with the target cuts mapped through the cut correspondence
  (`diffclass::Cuts::new` on the classified hunks, `Cuts::images`; `branch_diffs` shows the use). `compare_tables`
  then needs the classified hunks, so it runs after `classify_hunks` / `frame_hunks` in `analyse`.
- Report the entry counts and the differing cases: "case 0: ours to default, the original's to +0x..".
- Show the case-body order in the `tables=` output.

## Reports

- grade-switch-tables-differ-raw-bytes
- diffclass-switch-case-order
