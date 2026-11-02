# `dcp check`: a short final verdict line (or `--summary`)

- **Source:** match-base session 2026-11-02 (gildegold), worker 22
- **Area:** `dcp check`
- **Problem:** after header edits the worker only wanted "any M1?", but `dcp check` prints a long report; it grepped for `gate=` and `M1`.
- **Proposal:** end with `M1=0 M1.debt=37 errors=0 gate=ok`, or a `--summary` flag.
- **Cost of not having it:** two extra commands each time.
- **Related:** data-check-one.md (check --name / --at)
