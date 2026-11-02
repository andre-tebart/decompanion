# `dcp data trial NAME --form tentative|init|extern`: try a datum's definition form

- **Source:** match-base session 2026-11-02 (gildegold), worker 63
- **Area:** `dcp data`
- **Problem:** the gm_KindObjCount finding (see ../bug-reports/check-d5-requires-init-but-tentative-matches.md) came from deleting a line by hand with sed, building, and restoring from a backup.
- **Proposal:** compile the unit with the datum's definition changed, list grade changes, and say whether D5 / D4 would complain; write nothing.
- **Cost of not having it:** ~10 minutes and the risk of leaving the file changed.
