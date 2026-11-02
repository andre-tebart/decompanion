# Flag a data symbol whose second half is reached only through its own indexed operand

- **Source:** match-base session 2026-11-02 (gildegold), worker 25
- **Area:** `dcp data map` / `dcp check`
- **Problem:** `gv_SaleShares` was declared as 8 floats, but the last 4 are a separate table at 0x5ee044 (now `gv_GraveWear`); found only because 0x4f1de0 indexes `0x5ee044 + size*4`.
- **Proposal:** flag symbols whose tail is reached only by code operands at `sym+off` with their own index and never through the base: usually two objects.
- **Cost of not having it:** ~3 minutes, easy to miss entirely.
- **Related:** data-struct-from-block-ops.md, data-settle-command.md
