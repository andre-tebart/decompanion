# `dcp grade` on a unit that failed to build says the name is unknown

- **Source:** match-base session 2026-11-02 (gildegold), worker 59
- **Severity:** minor
- **What happened:** after src/f3gm.c was accidentally emptied, `dcp grade gm_DailyCharacters` said "gm_DailyCharacters is neither a unit nor a graded function of target exe", which reads like a wrong name rather than a broken build.
- **Expected:** "unit f3gm failed to build (dcp build lists the errors); grade unavailable", consistent with the `dist=-` shown elsewhere for failed builds.
- **Repro:** empty or break src/f3gm.c, then `dcp grade gm_DailyCharacters` (gildegold).
- **Impact:** one call working out what went wrong.
- **Related:** grade-lost-address-comment-silent.md, check-compile-failure-floods-m1.md
