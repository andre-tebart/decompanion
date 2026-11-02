# `dcp data check NAME`: one-line confirmation that a typed datum sits at its address

- **Source:** match-base session 2026-11-02 (gildegold), worker 17
- **Area:** `dcp data`
- **Problem:** after typing or moving data, confirming placement means reading the full `dcp check` output for D1/D4/D8.
- **Proposal:** `dcp data check NAME` printing e.g. "placed at 0x6f262c, M.data.site ok, size 4" (plus initializer bytes match, see check-moved-datum-initializer-bytes.md).
- **Cost of not having it:** small, every data commit.
- **Related:** data-settle-command.md

## Also suggested (match-base session 2026-11-02 (gildegold), worker 19)
- `dcp check --name NAME` / `--at 0xADDR`: after each gap-data move (sv_ChatRecipients, sv_Advancing) the worker grepped the full check output for the address to confirm no D1/D4/D8. ~1 minute per move.
