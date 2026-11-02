# `dcp headers conflicts --trial` reports a "fall" against the current grade, not the baseline

- **Source:** match-base session 2026-11-02 (gildegold), worker 48
- **Severity:** minor
- **What happened:** `--trial` printed `fall=0x00579570 name=ai_TutorialInitChapter3 code=byte trial=draft`. Its baseline in ledger/grades.tsv is draft (tagged deep), so against the baseline it is no fall; `code=byte` was the current unpromoted grade. The worker prepared a `dcp debt` entry that wasn't needed.
- **Expected:** print the baseline grade next to the current one and call it a fall only against the baseline.
- **Repro:** `dcp headers conflicts unk_575860 unk_5d33b0.h --trial` at gildegold e9e1301^.
- **Impact:** ~10 minutes.
- **Related:** headers-conflicts-trial-silent-with-supersedes.md
