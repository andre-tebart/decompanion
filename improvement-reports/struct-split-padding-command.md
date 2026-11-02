# `dcp struct suggest TYPE OFFSET TYPE NAME`: split padding into a field and check the size

- **Source:** match-base session 2026-11-02 (gildegold), worker 63
- **Area:** new command (types)
- **Problem:** splitting e.g. `pad29[0x24]` into `pad29[0x20]` plus `float priceFactor` at 0x49 is a mechanical, error-prone edit; done three times this session (ORDCHAR.inventory, ORDBLD.priceFactor, ORDBLD.masterId).
- **Proposal:** `dcp struct suggest ORDBLD 0x49 float priceFactor` splitting the covering padding member and verifying the size assert (and printing the diff, `--write` to apply).
- **Cost of not having it:** small per edit, but easy to get wrong.
- **Related:** rename-struct-field.md

## Also suggested (match-base session 2026-11-02 (gildegold), worker 64)
- `dcp struct ORDBLD --offsets`: each member's offset, noting where another header's struct of the same object (ai.h `AIBLD`) disagrees. ORDBLD was checked against AIBLD by hand, offset by offset, to add fields.
