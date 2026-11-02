# `dcp fn NAME --context`: registration line, callers and grade gate in one record

- **Source:** match-base session 2026-11-02 (gildegold), worker 34
- **Area:** `dcp fn`
- **Problem:** per function the worker ran `dcp fn` + `dcp grade` + `dcp disasm` + `grep act.decide`.
- **Proposal:** `dcp fn NAME --context` adding callers or the registration line, and the grade's gate line.
- **Cost of not having it:** ~2 calls per function, ~16 per session.
- **Related:** name-hint-from-strings.md, twin-functions-together.md

## Also suggested (match-base session 2026-11-02 (gildegold), worker 39)
- Most wanted form: `dcp fn NAME --print`, printing the source including the address comment above the definition (the worker repeatedly turned `dcp fn NAME | head -1` into a sed range).

## Also suggested (match-base session 2026-11-02 (gildegold), worker 52) - output size
- `dcp fn` prints the whole body; often the asmdiff said more. Optional `--head` printing only location and address comment.
