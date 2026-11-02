# `dcp try`: compile a variant in memory and print its distance

- **Source:** match-base session 2026-11-01 (gildegold), worker 3
- **Area:** new command
- **Problem:** the worker looped `cp backup; python edit; dcp build; dcp grade` many times: 6 DRAG macro forms, 4 `ai_MissionMode` forms, 3 strcpy forms.
- **Proposal:** `dcp try NAME --replace OLD NEW ...`, which compiles the variant without touching the file and prints the distance.
- **Cost of not having it:** roughly 10% of the session's tool calls.

## Also suggested (match-base session 2026-11-01 (gildegold), worker 5)
- Most of the session went into hand-scripted edit → build → grade → revert loops. Twice the script crashed mid-loop and left main.c modified; once a `replace(..., 1)` hit another function's `char c;`.
- Proposal variant: `dcp try NAME --patch a.diff --patch b.diff`, which compiles only that unit per patch and prints dist and code for each, without touching the working tree.
- Cost: large, plus one manual repair.

## Also suggested (match-base session 2026-11-01 (gildegold), worker 7)
- Same request (`dcp try NAME --replace 'old' 'new' [--replace ...]`, scratch copy, `dist` per variant). Useful for small meaning trials (signedness, operand order, loop form). Cost: about 10 minutes of throwaway scripting.

## Also suggested (match-base session 2026-11-01 (gildegold), worker 13)
- **Statement-order permutation:** sv_BorderCameraView went from draft (184 ins differing) to byte only after scripting all 24 orders of four independent assignments (`left`/`right`/`top`/`bottom`); exactly one matched. Proposal: `dcp try --permute LINES` grading each order. Cost: ~3 minutes scripting + 24 builds, very effective.

## Also suggested (match-base session 2026-11-01 (gildegold), worker 14)
- For sv_HoverPick three control-flow spellings gave identical code. The key signal for `dcp try` is "identical object" across variants; print object hashes per variant.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 16)
- sv_DrawBorderArrows went from 42 regs hunks to byte by reordering 4 `x = 0;` lines, found by a Python loop over orders. `--permute` should cover statement lines, not only declarations. Skill hint wanted: "regs-only around constant-zero registers: try the init order" (the worker only thought of it on the sixth function).

## Also suggested (match-base session 2026-11-02 (gildegold), worker 33)
- 0x497660: 7 control-flow variants by hand (backups in $TEMP); the best-scoring one (306 instructions) was semantically wrong, caught only by reading the disassembly. Any variant runner should also check semantics, at least that the set of call sites and return values is unchanged; instruction count alone rewarded the broken variant. Cost: ~25 minutes on one function.

## Also seen (match-base session 2026-11-02 (gildegold), worker 35)
- ~30 edit -> `dcp build` -> `dcp grade` rounds this session (~10 minutes of pure round trips).

## Also seen (match-base session 2026-11-02 (gildegold), worker 38)
- Store-order permutation turned two draft functions into byte: ai_ExecuteStammtisch (3-store request, 36 combinations) and ai_ExecuteStudy (6 message stores), via throwaway Python scripts rewriting src/am.c with one build per variant (slow; a crash would leave the file edited). Same `--permute FIRST-LAST` proposal, run in a scratch copy. Cost: ~15 minutes; two byte matches.
