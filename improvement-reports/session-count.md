# `dcp session count`: raised + escalated so far

- **Source:** match-base session 2026-11-02 (gildegold), worker 17
- **Area:** sessions
- **Problem:** typing / data commits that don't count toward the 8 interleave with the counted ones in `git log`, making it awkward to track progress.
- **Proposal:** `dcp session count` printing raised / escalated / remaining for the current session.
- **Cost of not having it:** small.
- **Related:** session-report-readonly.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 27)
- The worker did 9 instead of 8: the typing commit (not counted) made the hand tally easy to lose. Proposal form: `dcp next` / `dcp session status` printing "session: N of 8 raised/escalated", excluding `(typing)` commits.
