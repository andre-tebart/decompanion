# asmdiff --symbols prints a bare `_real` for some float constants, hiding the value

- **Source:** match-base session 2026-11-01 (gildegold), worker 10
- **Severity:** minor
- **What happened:** on ai_Unk4ab6b0 (ai_ExecBlutrache), `! fmul dword ptr [_real] | fmul dword ptr [0x5ed1e4]` hid that our constant had a different value: VC6 folded the negation into +50.0 while the original multiplies by -50.0. In other functions asmdiff prints `_real@c2480000`, so the value suffix is dropped in some cases.
- **Expected:** always show both values, e.g. `_real@42480000 (50.0) | 0x5ed1e4 (-50.0)`.
- **Repro:** `uv run dcp asmdiff ai_ExecBlutrache --symbols` on its pre-session draft (gildegold 7ef405a).
- **Impact:** ~4 minutes working it out from the instruction sequence.
- **Related:** asmdiff-symbols-wrong-library-callee.md, asmdiff-symbols-reordered-load-marked-wrong.md

## Also suggested (match-base session 2026-11-01 (gildegold), worker 11)
- Constant folding: `x * 4.0 * (1/60.0)` folds into one constant in ours but stays two `fmul`s in the original; the fix was a `(float)` cast of the intermediate, and `(float)fmod(...)` to get `fmul dword`. Printing the decoded value of every `_real@`/constant operand on both sides (e.g. `7.6394 vs 48.0 * 0.159`) would make a folded product obvious.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 22)
- One-ulp float immediates: `dcp asmdiff gv_CannonScatter` showed only `mov [esp+8], 0x3c8b4396` vs `0x3c8b4395`; the worker decoded the bits in Python to get `0.0169999991f`. Proposal: print both values as decimals plus the shortest C literal producing the original's bits, e.g. `original 0x3c8b4395 = 0.0169999991f (ours 0.017f, 1 ulp)`.
