# Skill: say whether M7 (undeclared call) blocks readable

- **Source:** match-base session 2026-11-02 (gildegold), worker 15
- **Area:** dcp-match-base skill, 2.3 Readability
- **Problem:** the skill lists M7 under readability, but `dcp grade` reported `readability=readable` while M7 "undeclared" calls remained (sv.c can't include cm.h yet).
- **Proposal:** state explicitly whether M7 blocks readable or is only reported.
- **Cost of not having it:** a moment of doubt per function.
- **Related:** grade-readable-blocked-by-head.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 50)
- ai_GraveList showed `readability=readable` with an open `M7 consistency:` line; the skill's 2.3 lists M7 next to the Q rules, so the worker added a he.h prototype assuming it was needed. ~10 minutes, and that prototype triggered the ai_TutorialInitChapter2 tie-break fall.

## Also seen (match-base session 2026-11-02 (gildegold), worker 53)
- `M7 consistency: ai_OpenTransport() ...` with `readability=readable`; skill 2.3 calls M7 "a contradiction" without saying whether it gates. Want one skill line or a `(not a gate)` tag in grade output. Related: ../bug-reports/grade-m7-current-wording.md
