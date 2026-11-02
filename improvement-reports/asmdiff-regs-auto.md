# asmdiff: detect a consistent register rotation across a whole function (`--regs auto`)

- **Source:** match-base session 2026-11-01 (gildegold)
- **Area:** asmdiff, diffclass
- **Problem:** for `surf_Up16` / `surf_Up24` / `surf_Up32`, diffclass reported 500–700 `code` hunks. Most were one consistent register rotation (for example `src` in ebp against ecx, masks in registers against reloads). The per-hunk `regs` class does not catch it once other differences fall in the same hunk.
- **Proposal:** `asmdiff --regs auto`, which infers the best overall register mapping and applies it before diffing, so the real `code` hunks stand out.
- **Cost of not having it:** medium. The worker checked the structure by reading three disassemblies by hand.

## Also seen (match-base session 2026-11-01 (gildegold), worker 12)
- sv_FillDayPhases: diffclass reports one `code 78` hunk; with a hand-built `uv run dcp asmdiff sv_FillDayPhases --regs esi=ecx,edi=esi,ecx=edi,cl=bl` only push/pop ebx and one value register remain. Proposal: diffclass searches the permutation itself and reports "regs + saved-register difference". Related: diffclass-spill-alloc-class.md
