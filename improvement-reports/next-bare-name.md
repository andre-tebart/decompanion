# `dcp next --name`: print only the bare name of the next item

- **Source:** match-base session 2026-11-01 (gildegold), worker 8
- **Area:** `dcp next`
- **Problem:** every item needed `N=$(uv run dcp next | grep -o "name=[^ ]*" | cut -d= -f2)`.
- **Proposal:** `dcp next --name` (or `--field name|addr|unit`) printing just the value.
- **Cost of not having it:** small, repeated 8 times per session.
