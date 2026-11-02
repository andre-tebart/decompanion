# `dcp grade`: show the full Q2 list (`--all`) and say what counts

- **Source:** match-base session 2026-11-01 (gildegold), worker 5
- **Area:** `dcp grade` (Q2 readability rule)
- **Problem:** Q2 truncates its list with "(+17 more)" and `dcp grade` has no `--all`. Only by trial did the worker learn that struct field names such as `unk190` or `unk14` count too.
- **Proposal:** `dcp grade NAME --all` (or `--q2`) lists every flagged name with its kind (local, global, function, struct field); document in the skill which names Q2 counts.
- **Repro:** `uv run dcp grade main_SettleRound` at gildegold commit f47bfc6.
- **Cost of not having it:** guesswork on every large function.

## Also seen (match-base session 2026-11-02 (gildegold), worker 20)
- sv_RunFrame had 49 placeholder names; grade showed 8 and `(+N more)`, the rest found by grep (~3 minutes). Proposal: `--all` or a `q2=` list.
