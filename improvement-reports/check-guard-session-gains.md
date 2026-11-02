# Warn when a function falls below its grade at the session's previous commit

- **Source:** match-base session 2026-11-02 (gildegold), worker 45
- **Area:** `dcp check` / `dcp build`
- **Problem:** ai_TutorialInitChapter2 had become byte earlier in the session (baseline still shape); a later header edit dropped it back to shape (declaration-set tie-break) and `dcp check` stayed silent because it compares against the baseline. Noticed only because the byte+readable total in the `grades:` line went down by one; finding which function moved took a stash, rebuild, `dcp grade unk_575860` on both sides and a diff. A gain that would have been promoted at wrap was lost.
- **Proposal:** warn when a function falls below its grade at the previous commit of the session (or the last build), even if still above the baseline; name it.
- **Cost of not having it:** ~4 minutes plus a lost gain.
- **Related:** build-list-grade-changes.md, fall-trigger-and-include-chain.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 61)
- After a header edit (`GMSTOCK.marketKind`) the build's byte+readable went 1784 -> 1782; `dcp check` showed no M1 (only the session-start baseline counts), and finding the two functions would have meant `dcp grade UNIT` over every unit. The wrap showed only net changes. Want `dcp grade --changed` / `dcp session diff`: functions whose grade differs from the baseline and from the last build. Cost: ~4 calls and doubt. Related: build-list-grade-changes.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 63)
- byte+readable moved 1789 -> 1788 at one build while `dcp check` showed no M1; a fall of a function raised earlier in the same session would go unflagged (wrap: `falls_against_old=0`). Not pinned down despite several greps and grades.

## Also seen (match-base session 2026-11-02 (gildegold), worker 64)
- `grades:` went `byte+readable=1793 shape+readable=162` -> `1792 / 163` and back after gv.h struct edits (pad removal, `unsigned char` -> `char`); no M1, so a function above its baseline was flipping. Want `changed: 0x... name byte->shape`. Cost: an extra `dcp check` each time.
