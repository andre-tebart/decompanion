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

## Also suggested (match-base session 2026-11-02 (gildegold), worker 48)
- Three throw-away permutation scripts (expression order, statement placement, declaration order) each rebuilt unk_575860 and parsed diffclass; rebuilds were slow because header changes recompile ~10 units. Want `dcp try NAME --file variant.c` or `--replace OLD NEW`. Cost: moderate.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 49)
- A PowerShell loop (replace text, `dcp build`, `dcp grade`) for statement orders in three functions, ~30 builds; one round lost because shell variables don't persist between calls. Want `dcp try FN --variants FILE`: apply each alternative, build only that unit, one line per variant (dist / grade / size), restore the file. Cost: ~25 minutes, the largest of the session. See also build-daemon-holds-source-file-mapped.md.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 51)
- ai_GraveCare (message field assignment order, 5 variants) and ai_GypsyHelperWindow (order of `n` / `kinds[2]` / `gm_Query`, count tests) reached byte only by permuting statements; throwaway Python scripts copied a backup, applied a variant, built, graded, restored. Want `dcp try NAME --variants FILE` printing `variant -> grade dist`, tree untouched. Cost: ~10-15 minutes of scaffolding, the largest of the session.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 54)
- The worker wrote its own `try.py` (old/new text pairs applied to a copy, build, print dist and hunk classes, restore) and ran ~20 variants (init order, declaration order, expression forms, if-chain forms, float locals). Want `dcp try NAME --variants FILE.json`, always restoring the source. Cost: ~10 minutes plus the risk of leaving the file modified. (Fourth session today asking for this.)

## Also suggested (match-base session 2026-11-02 (gildegold), worker 58)
- 5-8 spellings per function (FPU constant fold, age store, copy loop, block order) via hand-written python/bash loops: ~25 tool calls; one search-and-replace hit a line in gm_DailyCharacters that had to be repaired. Want `dcp try NAME --variant FILE...` or `--line N "text"`, compiling in memory and writing nothing.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 59)
- 11 orders of the party-field stores (gm_PartnerStep), declaration orders, loop forms, `!(a<b)` vs `a>=b`: ~30 manual builds via a permutation script, the biggest cost of the session. Want a per-function trial like `headers --trial`: compile with the function's text from a file, report dist and diffclass summary, write nothing.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 60)
- gm_SetTime statement order (5 orders), declaration orders, local types via ad-hoc Python/shell loops copying src/f3gm.c: ~15 builds, the largest friction of the session. Want `dcp try NAME --body FILE1 FILE2 ...` printing `variant=1 experiment=byte dist=...` per variant.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 61)
- ~6 bash/python loops (substitute a line, build, `grade | grep dist`, restore); this is how gm_IsBuildingKind reached byte and gm_SyncMarket went from 52 to 22 differing instructions. Want `dcp try NAME --replace 'old' 'new'` or a variants file, built in a scratch copy. Cost: ~10-15 tool calls of plumbing.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 62)
- ~40 source variants this session via the worker's own repl.py + try.sh; "the main cost". Want `dcp try NAME FILE` (replace the body from a file, build only that unit, print dist and diffclass summary, restore unless `--keep`).

## Also suggested (match-base session 2026-11-02 (gildegold), worker 63)
- ~12 throwaway attempts (goto forms, branch order, chained assignments), each backup/edit/build/grade/restore: the biggest time cost of the session. Want `dcp build --trial` (scratch object, store untouched) or `dcp try FILE.patch NAME`.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 64)
- All 24 declaration orders of gm_CreateBuilding's four arrays via a script (rewrite, build, grade x24, restore). Want `dcp try NAME --variants DIR` on a scratch copy. Cost: ~3 minutes plus risk to the tree if the script dies mid-run.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 65)
- ~25 hand-scripted trial builds (gm_ShowSlotObjects ~15, gm_ListWorkers ~6, gm_GoodPicture 3, gm_AllocRaum 3): ~40% of the session's tool calls, and the scripts tripped over the backslash problem. Want `dcp try NAME --body FILE...` with one result line per variant.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 66)
- f3gm.c copied to the scratchpad ~6 times to roll back experiments. Want `dcp try NAME --file variant.c`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 69)
- Wrote ad-hoc Python loops for sum-term order in gm_RankPlayers and loop forms in gm_TakeOverCharacter. Wants `dcp try NAME --variant FILE...`: build each variant, print code / dist / proof per variant, restore. ~10 minutes.
