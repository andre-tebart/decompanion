# Skill: remind workers to add the attribution trailer to commits

- **Source:** match-base session 2026-11-02 (gildegold), worker 69
- **Area:** dcp-match-base skill (commit step)
- **Problem:** the skill's commit format `git commit -m "<unit>: <name> shape + readable (match-base)"` doesn't mention the session's Co-Authored-By / Claude-Session trailer; the worker left it off the first three commits (gm_Shuffled, gm_RandomAge, gm_CharLevel).
- **Proposal:** one line in the skill ("end the message with the attribution lines from the session reminder"), or a `dcp commit` helper that adds them.
- **Cost of not having it:** 3 commits without attribution.
- **Related:** skill-windows-commit-message-file.md
