# Skill: explain build/rename rebuild counts after header edits

- **Source:** match-base session 2026-11-02 (gildegold), worker 51
- **Area:** dcp-match-base skill / `dcp build` output
- **Problem:** a `dcp rename`'s rebuild also compiles other pending edits, so the next `dcp build` reported "compiling 1 of 93" after header edits, which looked like the header change had not been picked up.
- **Proposal:** a skill line saying that rename rebuilds include pending edits; or `dcp build` says "up to date: N units already rebuilt by rename".
- **Cost of not having it:** a moment of doubt.
