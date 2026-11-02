# Skill: say whether "rewrite the lead comment of every touched unit" applies when nothing unit-level changed

- **Source:** match-base session 2026-11-01 (gildegold), worker 6
- **Area:** dcp-match-base skill, wrap step
- **Problem:** the worker touched unk_5d33b0 for one declaration, and unk_4a7140's Open: lines were still accurate; it left both lead comments unchanged. The skill reads as if a rewrite is always required.
- **Proposal:** state that the lead comment needs updating only when its content (Open:, status, notes) is out of date.
- **Cost of not having it:** negligible.
