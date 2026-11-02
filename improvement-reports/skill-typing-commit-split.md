# Skill / helper: typing changes discovered mid-function vs "typing commits first"

- **Source:** match-base session 2026-11-01 (gildegold), worker 14
- **Area:** dcp-match-base skill, commits
- **Problem:** the skill wants head/typing changes in their own commit first. When the header change (e.g. a prototype into f3gm.h / unk_58bbd0.h) is found while fixing the function, splitting needs partial staging, and `git add -i` is unavailable. The worker combined them twice and said so in the commit messages.
- **Proposal:** allow a combined commit when the typing change is small, or a `dcp commit --typing FILES` helper that stages and commits only those files.
- **Cost of not having it:** small; rule-bending twice.

## Also seen (match-base session 2026-11-02 (gildegold), worker 20)
- Three times the WIP function already used new names, so the worker saved the file, put HEAD's body back (renames applied), built, committed the typing change, then restored the WIP: ~15 minutes total. Proposal: `dcp fn NAME --stash` / `--restore`, or `dcp commit --typing --exclude-fn NAME`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 24)
- The byte+draft sender 0x4f0c20 (now gv_OrderAdjustEntry) was renamed in the same commit as its handler gv_AdjustEntry. Section 2.4 ("one function, one commit") doesn't say whether a function renamed alongside may share the commit or needs its own (uncounted) one.
