# `headers conflicts --write` refuses over a conflict the unit already had

- **Source:** match-base session 2026-11-02 (gildegold), worker 20
- **Severity:** minor
- **What happened:** the `kind=call` lines for `d2_PlaceMainWindow` showed `decl=src/sv.c:6915`, sv.c's own K&R declaration, so the conflict predates the include. The skill says "an error the unit already had is no finding", yet `--write` printed `refused: 2 conflicts left` while `--trial` compiled with `falls=0`.
- **Expected:** pre-existing conflicts are reported but don't block `--write` (or are marked `preexisting`).
- **Repro:** `uv run dcp headers conflicts sv include/unk_5d33b0.h --write` at gildegold 9bc6a23^ without the `d2_PlaceMainWindowF` edit.
- **Impact:** ~5 minutes.
- **Related:** headers-conflicts-write-splits-address-comment.md, ../improvement-reports/headers-conflicts-output.md
