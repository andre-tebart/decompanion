# `dcp rename`: print the outcome line first (and errors next to a refusal)

- **Source:** match-base session 2026-11-01 (gildegold), worker 8
- **Area:** `dcp rename`
- **Problem:** when a rename prints many replacement lines, the final status (kept / refused) is last, and an `error=` record can scroll by or be cut when piping through head/tail.
- **Proposal:** a one-line summary first (`renamed=N files=M` or `error=...`), and on refusal repeat the compiler errors right next to the refusal line.
- **Cost of not having it:** small; contributed to rename-refused-hand-written-name-other-signature.md.
- **Related:** ../bug-reports/rename-refused-hand-written-name-other-signature.md, rename-report-comment-rewrites.md

## Also seen (match-base session 2026-11-01 (gildegold), worker 10)
- PowerShell has no `tail`; `Select-Object -First N` cut off rename's result line, which led to a repeated rename (../bug-reports/rename-repeat-duplicate-names-log.md). Proposal addition: `--quiet` / `--summary` on rename and build printing only result records.

## Also seen (match-base session 2026-11-02 (gildegold), worker 24)
- A refused batch rename printed seven `file=<path> replacements=N` lines (src/am.c, src/gv.c, src/unk_575860.c, include/cm.h, src/cm.c, ...) before `check: 3 new error(s) after the rename`, the M5/M6 lines, one `error=` per pair and finally `nothing written`; the `file=` lines read like edits already made. Repro: edit include/gv.h:302 to `void gv_OrderMoveGrave(int *c, int to, char *o, int from, int entry, int price);`, then `uv run dcp rename unk_Unk4f0e80 gv_OrderMoveGrave ai_Unk4c60f0 cm_SendGraveMove unk_Unk4f0e80I gv_OrderMoveGraveI --why "..."` (gildegold before b9e651c). Proposal: on refusal print the refusal first and label planned edits `would_change=` (or omit them). Cost: ~2 calls (git status, revert, rerun).
