# `dcp rename`: a separate why per pair on the command line, or print a shared why once

- **Source:** match-base session 2026-11-01 (gildegold), worker 6
- **Area:** `dcp rename`, `dcp session wrap`
- **Problem:** renaming 10 callees in one call with one shared `--why` makes names.log and the wrap's renames section repeat the long why 10 times. `--from FILE` exists but means writing a file for a one-off.
- **Proposal:** accept `OLD NEW:why` pairs on the command line, and/or have the wrap group renames that share a why and print it once.
- **Repro:** `uv run dcp rename ai_Unk4a8520 ai_PokerDealThree ai_Unk4a8590 ai_PokerDealFourth ... --why "..."`, then `uv run dcp session wrap` (gildegold 2fb619b).
- **Cost of not having it:** low; report noise.
- **Related:** rename-from-help-example.md, session-report-readonly.md

## Also seen (match-base session 2026-11-01 (gildegold), worker 7)
- `dcp rename ai_Unk4a63f0 X ai_Unk4a8db0 Y --why "..."` stored the same combined why for both in names.log and the wrap report. Same proposal: `OLD NEW:why` on the CLI.
