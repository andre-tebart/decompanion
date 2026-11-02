# Skill: say whether M7 (undeclared call) blocks readable

- **Source:** match-base session 2026-11-02 (gildegold), worker 15
- **Area:** dcp-match-base skill, 2.3 Readability
- **Problem:** the skill lists M7 under readability, but `dcp grade` reported `readability=readable` while M7 "undeclared" calls remained (sv.c can't include cm.h yet).
- **Proposal:** state explicitly whether M7 blocks readable or is only reported.
- **Cost of not having it:** a moment of doubt per function.
- **Related:** grade-readable-blocked-by-head.md
