# Tooling feedback from target sessions (open items)

Findings from running the skills on a target project, to be picked up as framework work. Each item: what was
observed, the cause (verified in the code, or suspected), a proposed change. Remove an item when it is done
(the commit that does it says so).

## match-base on gildegold, 2026-10-30 (session base ace7863d, unk_5d33b0, 8 functions)

Every `uv run dcp ...` call of one match-base session was timed (a wrapper around `uv run dcp`, wall clock,
warm store, Windows 11). The session took ~34 min (08:16 .. 08:50 by the commits); the dcp calls took 790 s of it
(39 %): 163 calls.

| command | calls | total s | mean s | min | max |
|---|---|---|---|---|---|
| build | 39 | 309.3 | 7.93 | 2.31 | 11.66 |
| grade | 22 | 145.5 | 6.61 | 2.28 | 11.42 |
| rename | 8 | 104.4 | 13.04 | 10.48 | 18.32 |
| asmdiff | 22 | 51.1 | 2.32 | 2.29 | 2.36 |
| check | 5 | 36.8 | 7.35 | 4.89 | 11.87 |
| next | 8 | 35.5 | 4.44 | 2.34 | 6.71 |
| diffclass | 14 | 34.0 | 2.43 | 2.28 | 2.92 |
| refs | 8 | 18.9 | 2.36 | 2.25 | 2.94 |
| disasm | 11 | 15.8 | 1.44 | 1.31 | 2.41 |
| dump | 8 | 10.1 | 1.26 | 1.23 | 1.29 |
| draft --show | 7 | 8.7 | 1.24 | 1.23 | 1.26 |
| session start / wrap | 2 | 11.7 | 5.86 | 5.18 | 6.54 |
| escalate | 5 | 5.3 | 1.06 | 1.04 | 1.08 |
| data map, why, -h | 4 | 3.4 | | 0.31 | 1.51 |

The work loop is edit -> `dcp build` -> `dcp diffclass` / `dcp asmdiff` (-> `dcp grade`): 10 .. 16 s per try. A
function that does not match at once takes 4 .. 6 tries, so this loop is most of the tool time.

### Speed

Items 2 (rename refreshes twice), 3 (grade / next lint), 4 (~1.2 s per call) and 5 (asmdiff / diffclass) are
done: `dcp serve`, the persisted file hashes, lint in `build`, per-function compare memos (docs/plan.md, the entry
of 2026-10-30). What is left of item 1:

1. **The refresh after a one-unit compile still costs ~1.1 s (warm daemon), ~2.7 s in-process.** Was ~4.5 s.
   Measured with tools/bench.py (S1, a one-line edit): build 1.8 .. 2.8 s in the daemon, of which CL ~0.55 s,
   the lint of the unit ~0.2 s, the refresh ~1.1 s. The rules still rerun whole: G.grade ~0.25 s, M.data.content
   ~0.13 s, M.lint ~0.12 s, M8.reloc ~0.09 s, M.data.site ~0.08 s, L13 / L5 / A1 (they read the whole `src`
   input), and a line move (an added line above a definition) still reruns the L.* chain (L.src's facts carry
   line numbers). In-process the same rules pay their memos cold (compare every function again), and the lint
   of the build costs ~1.1 s more (the all-declarations text parses every .c file; the daemon keeps them).
   Proposed: per-unit partitions of the M / G rules (`objects@unit`, `src@unit`), L5 / A1 / L13 reading the
   loader's facts instead of the tree, and run keys that leave the line numbers out of L.src's output.

Not a tool cost, but noted because it showed up as one: `dcp grade 0x5d3810` took 11.4 s because a header had
been edited without a build; `grade` compiles stale units first (`build_target`), so it was a build plus a grade.

### Usability

6. **`diffclass` calls operand-order differences `code`.** Hunks that are only the operand order of a commutative
   FPU op (`fld a; fadd b` vs `fld b; fadd a`), mixed with a register rotation or a moved load, are classed `code`
   ("a meaning difference until shown otherwise"). Examples from the session (gildegold, unk_5d33b0):
   ai_ShotHitsGround 0x5dcf00 hunk at 0x5dcfea (34 ins `code`: the walk's `p.y += d.y` / `t += step` with the two
   fadd operands swapped, the lea / push order of a call's arguments rotated); ai_InitShot 0x5dc240 (76 ins
   `code`: VC6 sank a call to a side-effect-free same-TU function to its first use, everything in between shifts);
   ai_StepShot 0x5dc4a0 (285 `code` of 311: the frame size 0x50 vs 0x98 changes every esp offset, plus the
   register swap ebx / ebp of the loop counters). This inflates `code`, keeps functions at `draft` whose meaning
   is complete, and makes the escalation boundary of the skill ("only regs / slots / order left") hard to apply:
   all five escalations of the session had to argue past `code` hunks.
   Proposed: a class for commutative operand swaps of fadd / fmul (same multiset of operands per FPU op), a
   frame-size-normalised slot comparison (esp offsets compared modulo the frame delta), and splitting mixed hunks
   into their explained and unexplained parts before classifying.

7. **`asmdiff` cannot print one side.** To read our code whole one has to filter `asmdiff --all` with
   `grep -v '^+'`. Proposed: `--ours` / `--original` (the original side is `dcp disasm`, ours has no command).

9. **`dcp escalate` writes the reason into the fragment's first comment as one line** (500 .. 900 characters in
   this session). The reason belongs there, but a long line makes the fragment hard to read. Proposed: wrap the
   `@deep` text at the comment's width.

10. **Static `.rdata` constants: D4 caught a declaration-order mistake only at `check`.** Adding
    `static const float` constants to a header after an existing one of a higher address builds fine and fails
    the gate later (`D4 ... is defined after ai_WindGain (0x5eee14) but lies before it`). Proposed: `dcp build`
    reports D4 for the units it compiled (cheap, the order is known then).
