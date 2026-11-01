# Differential trace: compare a function's calls between the original exe and ours

- **Source:** play debugging session 2026-11-01 (gildegold)
- **Area:** dcp run --debug (a new mode)
- **Problem:** finding where the save load went wrong took an offline parse of Tutorial.cty, hand-computed
  reader offsets, and finally a temporary `fprintf` trace in `src/ls.c` logging the gz stream position after
  each reader, which had to be added, built, run and removed again. The trace showed the position at once:
  0xe209 before `LS_RD(ai_UpdateStart, 0x18)` and still 0xe20d after it.
- **Proposal:** `dcp run PROFILE --trace NAME` runs the original exe and ours under the debugger with a
  breakpoint on the same function (by name, mapped to each image's address), logs its arguments (and
  return value) for the first N calls, and prints the first call where the two traces diverge, e.g.
  `ls_Read call 23: original (0xf89580, 0x18, 1, h) ret 1 / ours (0x0, 0x18, 1, h) ret 1`. The run
  infrastructure already has the debugger, the setups and the symbol mapping for crash reports. Any
  deserializer (saves, .cty maps, ini readers) and any input-driven path benefits.
- **Repro:** gildegold commit 258ff9e, `REA_START=tutorial dcp run play`; the target would be
  `--trace ls_Read`.
- **Cost of not having it:** about an hour of manual offset arithmetic and a throwaway source edit (which
  also touched the byte-matched unit and needed a careful revert).
