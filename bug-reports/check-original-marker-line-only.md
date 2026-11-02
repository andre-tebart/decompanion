# `@original` only exempts an M6 call when on the call's own line; grade/build don't show the M6

- **Source:** match-base session 2026-11-02 (gildegold), worker 42
- **Severity:** minor
- **What happened:** an intentional 3-argument call to the 1-argument 0x55ea60 (`he_FigureContact`, now prototyped in include/he.h) had its `@original` marker in a comment on the line above. `dcp build` passed and `dcp grade` showed byte + readable ("consistency (M7) current"), but `dcp check` failed the gate: `error ill-formed M6 0x00577110 src/unk_575860.c:1700: too many arguments to function call, expected single argument 'p', have 3 arguments / note include/he.h:10: ...`, without mentioning the marker. Moving the marker onto the call line fixed it.
- **Expected:** accept a marker in a comment ending directly above the flagged line, or say in the M6 message that `@original` / `@vc6` on the flagged line exempts it; and report M6 in grade/build so it surfaces before the wrap.
- **Repro:** prototype `int f(int p);` in a header; in another unit write `/* @original: 3 args to the 1-arg f */` above `if (!f(a, &x, &y))`; `uv run dcp build` (ok), `uv run dcp check` (gate=FAIL, M6). Same comment on the call line -> gate=ok.
- **Impact:** ~3 calls, 2 minutes (grepped he.c to see how it got away with the same call).
- **Related:** rename-from-before-counts-uncommitted-errors.md (M5 also only at check), ../improvement-reports/stale-local-prototype-flag.md
