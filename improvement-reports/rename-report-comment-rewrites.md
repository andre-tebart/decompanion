# rename: list comment and lead-comment rewrites separately

- **Source:** match-base session 2026-11-01 (gildegold), worker 1
- **Area:** dcp rename
- **Problem:** the rename rewrote `unk_Unk51f080` to `ls_ReadPlayerSlots` in `src/ls.c`'s lead-comment `Open:` line (correct whole-word replacement). A later scripted rewrite of that line then silently did not match; fixed in gildegold b29293e.
- **Proposal:** rename output lists comment replacements separately, e.g. `comment: src/ls.c:2 Open: ...`.
- **Cost of not having it:** about 3 minutes and one extra commit.
- **Related:** rename-name-changed-units.md
