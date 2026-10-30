# Tooling feedback from target sessions (open items)

Findings from running the skills on a target project, to be picked up as framework work. Each item: what was
observed, the cause (verified in the code, or suspected), a proposed change. Remove an item when it is done
(the commit that does it says so).

## match-base on gildegold, 2026-10-30, second session (191 calls, 612 s of tool time)

| command | calls | median | max | share |
|---|---|---|---|---|
| rename | 21 | 9.1 s | 31 s | 47 % |
| build | 27 | 7.1 s | 31.7 s | 41 % |
| check | 11 | 1.26 s | 1.6 s | 2 % |
| refs | 10 | 0.7 s | 5.1 s | 2 % |
| disasm, dump | 28 | 0.34 .. 0.37 s | | 2 % |
| grade, asmdiff, diffclass, next, fn, escalate, why | 81 | 0.15 .. 0.23 s | | ~3 % |

The reading tools, `headers conflicts` and `check` were reported fast and trusted. Done since (docs/plan.md, the
entry of 2026-10-31): rename takes several pairs in one call (one rebuild), rename's own work and the build's
compile, include scan, lint and G.grade got cheaper; a closed stdout pipe (`dcp refs X | head`) no longer reads as
a lost daemon; asmdiff prints its legend; disasm inside an instruction starts at the next one. Open:

11. **The rules that rerun whole after a compile or a line move (~1.2 .. 2 s of every build).** What was left of
    item 1. Measured with tools/bench.py on gildegold (2026-10-31): a body edit reruns 15 of 56 rules (~1.0 s:
    G.grade ~0.17, D.data ~0.15, M.data.content ~0.13, M8.reloc ~0.1, M.data.site ~0.09, record.L.src ~0.1, each
    rule calling compiled_functions and loading its facts again, ~0.1 s each); a line move (most real edits add or
    remove a line, and since one file per unit that moves every function below it) reruns 23 (~2 s: L.src's facts
    carry line numbers, so the L.* chain, L9.analyzer.span, L5, L13 and the byte map run again). Proposed: per-unit partitions of the M / G / D rules, and a position-free run key of L.src for the rules that
    read no line (their facts must not carry a source line then: `by=src:file:line`).
12. **A header edit parses the changed units twice with clang (~1 s plan + ~1 s lint).** The source scan's model
    (cparse.model, ~0.4 s for a 4000-line unit, the Python walk of the cursors) and the lint's diagnostics parse
    (~0.1 s) are separate parses, and the all-declarations unit (1.6 MB, ~0.76 s) is parsed again on every header
    edit. Proposed: start the lint's parses beside the compile (they need only the plan), and one parse per unit
    for model and diagnostics.
13. **No "meaning matches" verdict.** For 3 of 8 functions the worker diffed the calls and constants of both sides
    by hand to show the rest was register allocation; diffclass reports pure scheduling as `code` (62 hunks for
    one function). Proposed: a diffclass line `calls and immediates: identical | differ (...)` (the multiset of
    call targets and immediate operands per side, image addresses compared as relocated), which makes the
    escalation boundary of the skill mechanical; with item 6 below.
14. **gildegold, not the tool: header conflicts keep main from including cm.h, hmt.h and unk_575860.h** (void
    results assigned in main, the sb_PlaySample clash), so two of the session's functions had no prototypes (Q7).
    A project task: fix those callers once.

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
of 2026-10-30). What was left of item 1 is item 11 above.

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
