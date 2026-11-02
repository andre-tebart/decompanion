# A per-session scratch directory from dcp (`dcp scratch`)

- **Source:** match-base session 2026-11-02 (gildegold), worker 16
- **Area:** sessions / skill
- **Problem:** the worker used Git Bash `$TMP` for temporary copies instead of the session scratchpad.
- **Proposal:** `dcp scratch` printing (and creating) a per-session temp directory, and the skill pointing edit scripts and variant copies there.
- **Cost of not having it:** none directly; hygiene.
- **Related:** skill-edit-scripts-not-heredocs.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 20)
- Git Bash `/tmp` is not Python's `/tmp`: scripts writing to `/tmp` couldn't be found from bash (~3 minutes). A skill line to use the scratchpad for helper scripts would avoid it.
