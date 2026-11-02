# A d3.h edit rebuilt only 1 of 93 units (possible stale objects)

- **Source:** match-base session 2026-11-01 (gildegold), worker 13
- **Severity:** minor (unconfirmed impact)
- **What happened:** commit 655a904 split `char pad09c[0xf0]` in `struct D3OBJECT` (include/d3.h) into a `views[10]` struct array and wrapped `unk05c` / `unk090` in unions. The next `dcp build` printed `compiling 1 of 93 units ... fresh=92`, although d3.h is included by many units whose preprocessed text changed. A later ai.h edit correctly recompiled 22 units. Layout was identical, so it may be harmless, but dependency tracking should be checked.
- **Expected:** every unit whose preprocessed text changes is recompiled (or the build says why it was skipped).
- **Repro:** `git checkout 3b912d2`, apply the d3.h hunk of 655a904, `uv run dcp build`.
- **Impact:** none noticed; potential stale grades.

## Also seen (match-base session 2026-11-02 (gildegold), worker 35) - second sighting
- Commit 15bbe02 edited src/unk_4a7140.c (removed the `ai_PickPartnerChainF` macro use, changing its preprocessed text) and include/unk_4a7140.h together with include/am.h and src/am.c. The next `dcp build` printed `compiling 1 of 93 units` and only `ok am`; unk_4a7140 apparently wasn't recompiled (unless quietly elsewhere). `dcp check` was `gate=ok`. Repro: change a call in src/unk_4a7140.c, delete a macro from include/unk_4a7140.h, change include/am.h, `uv run dcp build`, count compiled units. Two independent sightings now; the stale-object risk deserves a look.
