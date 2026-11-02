# `dcp rename`: on a name collision, say what the existing symbol is and suggest a free name

- **Source:** match-base session 2026-11-02 (gildegold), worker 55
- **Area:** `dcp rename`
- **Problem:** the refusal of `ai_Screenshot` (already at 0x5d7160 in unk_5d33b0) was correct but cost a round trip to find out what the existing symbol is and to pick another name.
- **Proposal:** print the existing symbol's address, unit and address comment, and suggest a free variant (e.g. `ai_SaveScreenshot`).
- **Cost of not having it:** one round trip.
- **Related:** ../bug-reports/build-accepts-duplicate-function-name-across-units.md
