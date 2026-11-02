# Suggest a struct when adjacent declarations are touched as one block

- **Source:** match-base session 2026-11-02 (gildegold), worker 20
- **Area:** `dcp data` / lint
- **Problem:** `memset(&x, 0, 0x20)` and a 14-byte struct copy showed that six char arrays were one object, found only by reading code (gv_LastTime became a plain `AITIME`, the 0x925100 cannon state one `GVCANNON gv_Cannon`). ~20 minutes.
- **Proposal:** detect block copies, memsets and `rep stos`/`movs` spanning several adjacent declarations in the original and suggest one struct of that size.
- **Cost of not having it:** ~20 minutes this session.
- **Related:** data-settle-command.md, types-duplicate-views-lint.md
