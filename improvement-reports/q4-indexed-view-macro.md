# Q4: accept indexed view macros, or suggest the struct-array view pattern

- **Source:** match-base session 2026-11-02 (gildegold), worker 23
- **Area:** `dcp grade` Q4
- **Problem:** Q4 rejects `#define gv_SlotCurrency(i) (*(unsigned short *)&ai_PlayerSlots[(i)*2][0x54])`, so the worker defined a local GVPLAYERREC struct plus an array view (`gv_PlayerRecs`).
- **Proposal:** accept a parameterised view form, or make the Q4 message suggest "struct + `(*(T (*)[N])&datum)`" for indexed records.
- **Cost of not having it:** ~2 minutes.
