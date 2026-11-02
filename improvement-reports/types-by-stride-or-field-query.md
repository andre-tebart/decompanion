# `dcp types --stride N` / `--field OFF:SIZE`: find the view type for a record

- **Source:** match-base session 2026-11-02 (gildegold), worker 65
- **Area:** new query (types)
- **Problem:** headers grepped ~8 times to find ORDCHAR / ORDBLD / ORDOBJ / GMSTOCK / AIJOB / CHARACTER offsets, e.g. which type has a 14-byte field at 0x52, or which views exist for the 0x21c-byte character record.
- **Proposal:** `dcp types --stride 0x21c` (or `--for ai_Chars`) listing the view types and their headers, noting which are includable in the current unit (e.g. ORDCHAR in gv.h vs AICHAR in ai.h, not includable here); `dcp types --field 0x52:14`.
- **Cost of not having it:** ~10 minutes per session.
- **Related:** struct-split-padding-command.md, datum-users-by-offset-and-type.md
