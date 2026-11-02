# `dcp disasm 0xADDR` silently prints a fixed 0x400 window for functions without a codewalk extent

- **Source:** match-base session 2026-11-02 (gildegold), worker 44
- **Severity:** minor (silent truncation; misleads scripts)
- **What happened:** at gildegold c5fa98f (also 3fe91b0), `dcp disasm 0x578570` prints `disasm=0x00578570..0x00578970 function=- name=-` and ends with "0x0057896e (2 bytes do not decode)"; the function runs to 0x578e3e (2254 bytes). `--no-daemon` gives the same; so does `dcp disasm 0x576490`. At 9d868d9 the same command printed the whole function (`name=ai_Unk578570 instructions=549`); 9d868d9 already includes 57567a3 (function-pointer table moved out of main.c into a typed array), so the trigger is 3fe91b0 itself: the function became byte-matched and was renamed ai_TutorialInitChapter1. `dcp why 0x578570` / `0x576490` show no S.codewalk extent, only source/ghidra start claims (0x578570 also `refs: to=0`).
- **Likely shared root cause with ../bug-reports/rename-kind-data-for-functions.md:** in the same wrap, 0x576490, 0x5768a0, 0x576a80, 0x5765e0 were logged `data`. Functions reached only through data pointers or immediate stores seem to lack a call/codewalk-derived function record, so disasm loses the extent and rename falls back to `data`.
- **Expected:** use the matched owner / source extent from the ledger when codewalk has none; never fall back silently - print a warning when the window is a guess.
- **Workaround:** explicit range, `dcp disasm 0x578570 ..0x578e3e`.
- **Impact:** ~10 minutes; a generator script produced 5 of 11 records with no warning.
