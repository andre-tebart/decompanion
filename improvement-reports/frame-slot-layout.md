# `dcp frame NAME`: show the original's stack-slot layout with access sites

- **Source:** match-base session 2026-11-01 (gildegold), worker 5
- **Area:** new command
- **Problem:** frame-size gaps were closed twice by block-scoped locals (VC6 shares stack slots across disjoint scopes), found only by experiment.
- **Proposal:** `dcp frame NAME` lists the original's stack slots (offset, size, access sites/addresses) and ours, so variables sharing a slot are visible.
- **Repro:** e.g. `main_EndRound` at gildegold commit f47bfc6.
- **Cost of not having it:** moderate.
- **Related:** vc6-optimizer-hints.md (per-scope stack-slot packing)

## Also suggested (match-base session 2026-11-01 (gildegold), worker 12)
- sv_EaseCameraHeight (frame 0x10 vs 0x14) and sv_PlaceCamera (0x18 vs 0x1c) became byte once the position local was a padded D3VECTOR4. Hint wanted: when the frame differs by 4 and a 12-byte local sits at the frame edge, suggest the local may be 16 bytes (padded vector/array).

## Also seen (match-base session 2026-11-02 (gildegold), worker 29)
- gv_FindAccused: frame 0x200c vs 0x2010 and the two local arrays swapped, so every stack offset became `code` until the missing scalar was found; the fix was the order of the initialising assignments, not the declaration order. Hint wanted: "the original's frame has one more 4-byte slot (at esp+0x1c); arrays at 0xc20 / 0x20 vs ours 0x1c / 0xc1c".

## Also seen (match-base session 2026-11-02 (gildegold), worker 36)
- ai_DecideMayor (0x49d8d0): the original keeps two counters and two record pointers in the slots later used for the `AIARG s1`/`s2` structs (frame 0x58 vs our 0x6c), found by hand offset arithmetic (~10 minutes, still escalated). Proposal: diffclass's `frame: ours 0x6c, the original's 0x58` adds "the original's slot X+0x18 is used both as a dword counter and as a struct base: declare these in disjoint block scopes", and lists our locals with no slot of their own in the original. Repro: `uv run dcp diffclass ai_DecideMayor`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 44)
- Inline-asm `AI_ZERO_AT` scopes: the original reuses `[ebp-8]` for the first block's size variable and then for `head` (matched without effort). In ai_TutorialProgressSlider a dead `mov [esp+8],0` plus one slot reused around fild/fidiv stayed unexplained (escalated).

## Also suggested (match-base session 2026-11-02 (gildegold), worker 48)
- Biggest cost of the session (est. 30-40%): resolving each `[esp+X]` by hand (minus pushes pending from deferred `add esp`, minus saved registers) for ai_CannonScene, ai_CannonCamera, ai_CannonPanel, ai_CannonSwitchAnim and ai_CannonExplosion, to find field offsets, parameter-slot reuse and temp sharing. Want `dcp frame NAME [--original]` resolving every stack access to a frame offset / parameter, on both sides.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 49)
- Annotate esp-based operands in `disasm` / `asmdiff` with a frame-relative slot, e.g. `(S+0x1c)` or `(arg2)`, accounting for outstanding pushes. ~10-15 minutes of hand counting; one parameter (`run` in ai_CannonBuildPanel) was found only this way.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 55)
- Rebuilding ai_BookmarkWindow (0x589670) meant counting outstanding pushes by hand to map `[esp+0x48]`, `[esp+0x2c]` onto locals, the most expensive part of the session. Want `--frame` on disasm/asmdiff rewriting `[esp+X]` as `[frame+Y]` with push depth applied.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 56)
- gm_CharacterWages and gm_UpdateWorthMood: `[esp+N]` mapped to locals by counting pushes, the most expensive reasoning of the session. Want `dcp disasm --frame` annotating `local+0x14` / `arg1` with push tracking.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 57)
- Remaining diffs were mostly VC6 spill / array-order effects (gm_HeadIconNumber's buf/icon/suffix order, gm_CharNameRecord's 8-byte spill). Want `dcp frame NAME`: ours vs original slots (offset, size, first use). Cost: ~15 minutes.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 59)
- Most per-function time in gm_PartnerStep, gm_PopulationStep and gm_FindHome went into slot/allocation guesswork where the original reuses one stack slot for several locals, and into mapping `[esp+0x24]` to locals by push depth (with mistakes). Want a diffclass hint naming which locals share a slot in the original, and esp operands annotated `[esp+0x24] {local+0x10}` / `{arg2}`. Cost: high, most reading time on big functions.

## Also seen (match-base session 2026-11-03 (gildegold), worker 70)
- Twice more: gm_InheritEstate (merge two variables) and gm_ForfeitEstate (declare reset locals inside `if (flag)`) closed 4/8-byte frame gaps. Proposal addition: a skill 2.2 note or a diffclass `frame:` hint: "frame larger by a few slots: try inner-block locals or reusing one variable". ~10 minutes.
