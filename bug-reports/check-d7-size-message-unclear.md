# D7 message gives a size that isn't the declared size

- **Source:** match-base session 2026-11-02 (gildegold), worker 20
- **Severity:** minor
- **What happened:** moving `sv_InMissionComplete` into sv.c's bss made check D7 say "ai_GameState (2 bytes)", while `dcp data map sv` shows `size=1 room=4`. The 2 seems to come from the relinked layout, so it was unclear which number to fix.
- **Expected:** "in the relinked image the next object (NAME) follows at +2", naming that object.
- **Repro:** at gildegold fcdc649, move the `sv_InMissionComplete` definition from main.c's gap block into sv.c's bss right after `sv_BookPhase`, `uv run dcp check`.
- **Impact:** ~10 minutes bisecting with `git stash`.
- **Related:** data-view-past-object-end-unflagged.md, check-d1-stale-extent-after-split.md
