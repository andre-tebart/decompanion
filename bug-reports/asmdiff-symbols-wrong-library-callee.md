# asmdiff --symbols names the wrong library callee (fopen vs _wfopen), leaves atoi unnamed

- **Source:** match-base session 2026-11-01 (gildegold), worker 5
- **Severity:** minor
- **What happened:** in main_GameLoop, `asmdiff --symbols` shows `! call fopen | call _wfopen` at 0x5deca8, but the argument is a narrow `sprintf` path, so the original's callee is evidently `fopen` and `_wfopen` is a mislabel. The `!` marker reports a callee mismatch that isn't there. `atoi` appears only as an unnamed `call 0x5df681`.
- **Expected:** library callees in the original are named correctly (CRT signature/symbol matching); no `!` when both sides call the same function.
- **Repro:** `uv run dcp asmdiff main_GameLoop --symbols` at gildegold commit f47bfc6.
- **Impact:** a few minutes checking a phantom wrong-callee.
- **Related:** asmdiff-symbols-image-base-immediate.md
