# `dcp text ID`: show what a game text id says

- **Source:** match-base session 2026-11-02 (gildegold), worker 49
- **Area:** new command
- **Problem:** there is no way to read texts like 0x4024 or 0x401e, so names for the cabinet windows stayed reasoned guesses (ai_CabinetSpyByMoney, ai_CabinetIntrigueWindow).
- **Proposal:** `dcp text 0x4024` printing the text (from the game's text files, if the project has or can extract them); optionally show it next to `txt_Ptrs[...]` in `dcp why` / asmdiff.
- **Cost of not having it:** names left as guesses.
- **Related:** txt-views-index-spelling.md, name-hint-from-strings.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 57)
- Wanted text id 0x19a7 (printed by he_Unk542590 with gm_HandOutMoney's results). Without it the name came from the money direction alone and was wrong once (gm_CollectLevy, corrected to gm_HandOutMoney).
