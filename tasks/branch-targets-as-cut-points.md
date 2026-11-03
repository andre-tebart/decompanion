# Branch targets as cut points through the alignment

- **Priority:** P0 · **Size:** M · **Root:** R3
- **Blocks:** escalate-gates-on-verdict, switch-tables-per-case

## Problem

- `je at +0x49: ours to +0x62, the original's to +0x62` holds functions at draft and sends them to the deep queue.
  There were 7 sightings after 5469812, and gm_FreeStallCapacity reproduces it.
- One inserted epilogue gives about 12 "targets differ" lines.

## Root cause (diffclass.rs)

- A jump's text is `jX X`, because the target is in image range (x86.rs:122-127). Text equality therefore never sees
  targets, and `branch_diffs` is the only target check.
- Inside every hunk, `aligned()` pairs jumps by identical text (diffclass.rs:431-443). In code hunks that pairing is
  arbitrary.
- `same_code` (467-496) accepts a pair only if one of these holds:
  - the target instructions are paired by `m`;
  - they are a hunk start;
  - their texts are equal.
- So a target inside an order or FPU hunk whose instruction is paired with another one fails (`pop ebx` vs `pop edi`).
- `judge` turns any branch line into `shape=false` (563-567).

## Task

- Treat a jump target as a **cut point** between instructions. Map cut points through the shared alignment:
  - in equal runs, by position;
  - in order hunks, where the prefixes are equal multisets under the hunk's renaming;
  - in regs, slots and frame hunks of equal length, by index;
  - at hunk boundaries, always.
- Pair jumps only through the alignment, never by text inside hunks.
- When a pair's target cuts don't correspond:
  - if a cut lies in or on a code hunk, attribute it to that hunk as one grouped line ("N jumps into the code hunk at
    +X");
  - otherwise it is a real "branch targets differ" (structure), and the message names both target instructions.
- Never print a difference whose two offsets read the same without naming what differs.
- Print the branch list once. Today both diffclass.rs:334 and matchcmd.rs:452-454 print it.

## Rejected

- "Drop entries with equal offsets": equal offsets are not evidence.
- Collapsing by "+4 shift" text.

## Model

- §1: inside a function, φ is the alignment.
- One difference is reported once.

## Reports

- grade-branch-targets-differ-same-target
- grade-branch-shift-noise
- diffclass-branch-target-equal-offsets-reported-different (untracked)
