# An unrelated function's @deep tag silently deleted, probably by `dcp escalate`

- **Source:** match-base session 2026-11-02 (gildegold), worker 48
- **Severity:** minor
- **What happened:** in commit dc3851d (ai_CannonSwitchAnim -> deep), the @deep reason in ai_TutorialInitChapter3's address comment, ~3000 lines away in src/unk_575860.c, was deleted. The worker's own edits in that commit were scripted replacements scoped to the SwitchAnim function, so `dcp escalate ai_CannonSwitchAnim` is the likely cause (not confirmed). Only the wrap's `grades changed` line (`draft+readable deep -> draft+readable`) revealed it; the worker restored the tag from 83fdff3 before the final wrap.
- **Expected:** escalate edits only the named function's address comment; `dcp check` flags a lost @deep tag on a function nobody touched.
- **Repro:** `git show dc3851d -- src/unk_575860.c` (gildegold), look for ai_TutorialInitChapter3 (0x579570).
- **Impact:** a silent deep -> base demotion that a less careful wrap review would have committed.
- **Related:** grade-lost-address-comment-silent.md
