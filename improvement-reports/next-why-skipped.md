# `dcp next --why-skipped`: show why items were passed over

- **Source:** match-base session 2026-11-01 (gildegold), worker 14
- **Area:** `dcp next`
- **Problem:** after sv_RefreshPanel, `dcp next` jumped past sv_Unk529fb0 (0x529fb0) without saying why (presumably its grade is outside the base queue).
- **Proposal:** `--why-skipped` listing skipped items between the last and the next item with their reasons.
- **Cost of not having it:** negligible.
- **Related:** next-bare-name.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 17)
- After 0x52d940 the queue went to 0x52e0c0, skipping `sv_Unk52e050` (0x52e050) silently; looked like a hole in the queue.
