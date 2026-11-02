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

## Also seen (match-base session 2026-11-02 (gildegold), worker 52)
- `dcp rename A B --why "..." C D --why "..."` failed with only `For more information, try '--help'` visible. The working form `A B C D --why "..."` wrote one combined why for the gv_SeanceChance and he_SetLifeByAge pairs into names.log, mixing two explanations. Want either `--why` once per pair, or an error naming the problem ("--why given twice; use --from FILE for one why per pair"). Cost: one retry and mixed names.log entries.

## Also seen (match-base session 2026-11-02 (gildegold), worker 54)
- `dcp rename A B C D ... --why X` stored the same long why for 5 pairs; the wrap printed it 5 times (d8ce059).

## Also seen (match-base session 2026-11-02 (gildegold), worker 56)
- A two-pair call logged gm_NetMsgCount's reason for gm_IncomeKind4 too; the worker corrected names.log by hand. Besides per-pair reasons, want a warning when one `--why` covers pairs of different kinds (data + function).

## Also seen (match-base session 2026-11-02 (gildegold), worker 59)
- `dcp rename A B C D --why "..."` stored ~600 characters for each pair; names.log and the wrap show it three times, each entry mentioning functions it is not about. Want per-pair whys or docs pointing to `--from FILE`.
