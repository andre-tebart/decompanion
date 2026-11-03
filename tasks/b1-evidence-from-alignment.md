# B1 evidence from the alignment

- **Priority:** P1 · **Size:** M · **Root:** R1

## Problem

- B1 says `136 of 784 bytes differ, the first at +0x27` where asmdiff shows equal lines.
- One 3-instruction hunk is counted as 88 bytes.
- A size off by one byte with equal instruction counts: no tool says where.
- "The original continues after our end" names a range past the original's extent.

## Root cause

- `Compared::why` (rules.rs:85-100) prints M.match's positional masked diff (compare.rs:45). That is the right pass/fail
  criterion, but useless as evidence once the lengths differ, and it is not the alignment asmdiff shows.
- Equal-text pairs can still differ in bytes: a jump displacement (targets read X, x86.rs:122) or an encoding length.
  Nothing reports them.
- One message covers two conditions (compare.rs:51-57, rules.rs:91):
  - `next_start > end`: the original continues;
  - `next_start < end`: *our* section (code, tables, fill) runs past the next start. sv_HandleRightClick is this case,
    printed with the first case's words.

## Task

- Keep the positional compare as the byte criterion.
- Build B1's evidence from the shared alignment:
  - the size in bytes *and* instructions, on both sides;
  - the bytes that differ in aligned pairs, kept apart from bytes inside hunks or only shifted;
  - the first aligned equal-text pair whose bytes differ, with both encodings ("je: other target", "encoding 3 vs 6
    bytes");
  - two distinct tail messages.
- This also gives "B1: branch targets only".
- asmdiff marks equal-text pairs whose bytes differ.

## Reports

- grade-b1-first-offset-equal-in-asmdiff
- grade-b1-shift-vs-in-place
- grade-size-diff-locate
- grade-b1-continues-after-end-confusing
- grade-show-instruction-counts
