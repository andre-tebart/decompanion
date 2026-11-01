# `dcp headers conflicts` blocked units on errors the unit already had and on exempt lines — FIXED

- **Source:** gildegold header cleanup, 2026-11-01 (coordinator survey: 6945 of 6945 findings printed `exempt=-`)
- **Severity:** major (whole units blocked for every header: cm 42 pairs, he 40 pairs)
- **What happened:** `dcp headers conflicts cm am.h` reported src/cm.c:14151
  `AI_ZERO_AT(offset ai_Unk92c600, 0x480);  /* @vc6 ... */` as two `kind=other` errors, and `he am.h` reported
  src/he.c:12450 (`/* @original: 3 args ... */`) as `kind=other`. Both lines are exempt for `dcp lint` / `dcp check`
  and both errors exist without the include.
- **Root cause:** two bugs.
  - The trial's new errors were found by comparing (file, line, message) with the base compile. The trial include
    shifts every later line of the unit, so every error the unit already had below the include looked new.
  - The exemption markers were checked only for `clash` findings, and the column printed `@original` whatever the
    marker was. No other kind was ever exempt, and exempt findings still counted as blockers.
- **Fix:**
  - A group of diagnostics is compared by its files, messages and lines, and a line of the unit's file by its text
    (`Trial::new_errors`). An error the unit already had is no finding, either in the analysis or in the `--write`
    check.
  - Every finding is checked with lint's own `lint::exemption`: any line of its diagnostic group with
    `@original` / `@vc6`, the rule M6 uses. It is listed as `exempt=@vc6` / `exempt=@original` and left out of the
    summary counts, the exit code and the `--write` refusal.
  - headers.rs no longer has its own copy of the marker regex.
- **Effect:** the cm and he findings above are gone (they are pre-existing). What `cm am.h` / `he am.h` still report is
  new with the include (calls am.h's prototypes reject, ai.h's `ai_Time`).
- **Test:** `test_headers_conflicts_exempt_and_shifted` (tests/test_source_checks.py).
