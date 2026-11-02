# `dcp rename` reports an M5 error just caused by an uncommitted edit as "1 from before"; build/grade don't show it

- **Source:** match-base session 2026-11-02 (gildegold), worker 28
- **Severity:** minor (nearly committed a gate failure)
- **What happened:** from ffcc056 the worker changed `unk_Unk4f4080`'s parameter to `unsigned short t` in include/gv.h and src/gv.c, then ran `dcp rename unk_Unk4f4080 gv_HeldCrimeIdsOf --why "..."`, which printed `check: 0 new error(s) after the rename, 1 from before`. "Before" meant before the rename, not the committed state, so the error read as old debt. It was M5: src/he.c:7377 and src/unk_58bbd0.c:20104 declare `int gv_HeldCrimeIdsOf();`, incompatible with a promoted parameter. `dcp build` and `dcp grade` (byte + readable, "consistency (M7) current") didn't show it; only `dcp check` did (`gate=FAIL why=errors=1`).
- **Expected:** count "from before" against HEAD / session base (or split "from uncommitted edits" vs "committed"); build/grade warn when a changed unit or header brings a new M5/M6; the M5 message names the cause ("unprototyped `int f();` in he.c / unk_58bbd0.c is incompatible with a promoted parameter (unsigned short); include gv.h or keep an int-sized type").
- **Repro:** `git checkout ffcc056`, make the parameter change (header + definition), run the rename above, then `uv run dcp build`, `uv run dcp grade gv_HeldCrimeIdsOf`, `uv run dcp check`.
- **Impact:** ~3 calls; caught only because the worker ran `dcp check` before committing.
- **Related:** ../improvement-reports/stale-local-prototype-flag.md, rename-refused-hand-written-name-other-signature.md
