# asmdiff: hint when a call's argument shows another parameter type than our prototype

- **Source:** match-base session 2026-11-01 (gildegold), worker 11
- **Area:** `dcp asmdiff` / `dcp diffclass`
- **Problem:** four times the fix was "the original's call shows a different parameter type": `push -1` vs `push 0xff`; a byte-wide argument pushed as a dword load; 16-bit `add dx,di` feeding a short parameter; strength reduction suppressed by a short-parameter call. Each took 5-10 minutes to recognise; the worker then added `@original` cast macros (`d2_PutPixelRGBc`, `d2_CreatePicObjS`, `d2_WinOpenPicStyledS`, `ai_SwitchRoomI`, `cm_SendExSetHEI`).
- **Proposal:** annotate such hunks, e.g. "push 0xff vs push -1: parameter is unsigned char / int in the original", "16-bit arithmetic feeding the push: parameter likely short".
- **Repro:** sv_LoadGroundplan / sv_UpdateCityPanel drafts before gildegold 80355b6.
- **Cost of not having it:** 20-40 minutes this session.
- **Related:** headers-signature-dry-run.md, diffclass-idiom-hints.md

## Also suggested (match-base session 2026-11-02 (gildegold), worker 20)
- Parameter count: `ai_Unk5a9e40` was declared with 2 parameters but its code reads 3, learned only from an `@original` macro comment. A grade/asmdiff header line like "the definition takes 2, its callers push 3" would be faster (with the third added, ai_DomizilMessage12 also went to byte).

## Also suggested (match-base session 2026-11-02 (gildegold), worker 21)
- Float bits into an int parameter: `d3t_CreateSmoke` declared `int unused`, but both callers push float bits (0x428c0000 = 70.0f in gv, `50.0f` in cm), which had pushed gv into int literals and an `unk_fb` hack. Proposal: flag int parameters whose immediate arguments decode to plausible floats at every call site. Cost: ~5 minutes deciding whether the prototype change was safe.

## Also seen (match-base session 2026-11-02 (gildegold), worker 27)
- `ord_SubGridAmount(int, int kind)` masked `kind & 0xff`; the caller pushes edx after loading only dl from the record (ours `xor edx, edx; mov dl` vs a bare `mov dl`), so the parameter is `unsigned char`. Lint wanted: an argument push built from a byte/word load without widening while the prototype says int. Cost: ~3 minutes.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 31)
- `__int64` passed as two ints: `push 1; push 0xa07c43b4` next to a callee taking `__int64` was the key clue in two functions (ai_DecideGraveyardOwner1 now passes a `LARGE_INTEGER`). Proposal: asmdiff `--symbols` annotates pushes by parameter when the callee has a prototype ("args: p, a, mask.lo, mask.hi, c, f, out"). Cost: ~5 minutes.

## Also seen (match-base session 2026-11-02 (gildegold), worker 34)
- ai_DecideUseMilitaryObject: the original builds the `__int64` mask in registers (`mov eax,0x90010 / xor ecx,ecx / push ecx / push eax`), from a LARGE_INTEGER local; ours pushed immediates from an `__int64` literal. A LARGE_INTEGER local took it from draft to shape in one build (an `i64` literal made ai_DecideUpgradeBusiness worse). Hint: `mov reg, imm; push reg` pairs feeding an `__int64` parameter mean a local 64-bit variable, not a literal. Cost: 2 builds.
