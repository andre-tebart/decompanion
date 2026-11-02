# rename: list comment and lead-comment rewrites separately

- **Source:** match-base session 2026-11-01 (gildegold), worker 1
- **Area:** dcp rename
- **Problem:** the rename rewrote `unk_Unk51f080` to `ls_ReadPlayerSlots` in `src/ls.c`'s lead-comment `Open:` line (correct whole-word replacement). A later scripted rewrite of that line then silently did not match; fixed in gildegold b29293e.
- **Proposal:** rename output lists comment replacements separately, e.g. `comment: src/ls.c:2 Open: ...`.
- **Cost of not having it:** about 3 minutes and one extra commit.
- **Related:** rename-name-changed-units.md

## Also seen (match-base session 2026-11-01 (gildegold), worker 5)
- Renaming main_Unk53b840 also rewrote a field comment the worker had just written in the head region. The worker's next scripted replace then didn't match and one build failed ("FAILED units=main"). The rename output does mention comment lines, but that note is easy to miss in a batched `rename --from`.
- Proposal addition: in `--from` batches, print a summary count of comment rewrites per file at the end, or add a `--no-comments` option.

## Also seen (match-base session 2026-11-01 (gildegold), worker 14)
- After renaming ai_Unk6f2338 and related names, comment-only names stayed (`/* ai_Unkf8f128: view of d2_Wins */`) and prose citing only the address (0x6f22e8) still says "ai_Unk6f22e8 ..." in cm.c. Rename did list them under "comments: ... review them". Negligible cost.
