# `dcp headers conflicts --write` drops only one of several identical superseded declarations

- **Source:** match-base session 2026-11-02 (gildegold), worker 57
- **Severity:** minor
- **What happened:** `dcp headers conflicts f3gm d3_engine.h --write` reported `dropped=1`; src/f3gm.c still had two identical `extern D3SCENE d3_Scenes[];` lines, which d3.h now declares.
- **Expected:** drop every exact duplicate the header supersedes.
- **Repro:** the command above at gildegold before "f3gm: head includes d3_engine.h (typing)" (pre-728c0d8).
- **Impact:** small; removed by hand and rebuilt.
- **Related:** headers-conflicts-write-splits-address-comment.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 64) - K&R declarations missed
- After adding `int ai_UnlistPlayerBuilding(int id);` to include/unk_58bbd0.h, `dcp headers conflicts f3gm unk_58bbd0.h --trial` printed `supersedes=0 duplicate=0` though src/f3gm.c still held two local K&R `int ai_UnlistPlayerBuilding();` (lines 3620, 5102). Want them listed as supersedes/duplicates and dropped by `--write`. The command seems to look only at the include line, not at what the header makes redundant.
