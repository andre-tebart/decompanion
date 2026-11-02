# Show the order of switch case bodies, ours against the original

- **Source:** match-base session 2026-11-02 (gildegold), worker 66
- **Area:** `dcp diffclass` / `dcp asmdiff`
- **Problem:** on gm_PermissionBits (0x503530) the original's case order had to be worked out by hand from the jump table and block addresses; ~6 block-placement experiments followed.
- **Proposal:** for each switch, a line like `case order: ours 1,2,4,5.. / original 0x21,2,9,4..` (case value per body in address order), plus merged / dropped labels.
- **Cost of not having it:** ~6 experiments on one function.
- **Related:** ../bug-reports/disasm-decodes-jump-tables.md, vc6-optimizer-hints.md
