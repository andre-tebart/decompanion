# Hint when the original reloads a global with no store/call between (volatile)

- **Source:** match-base session 2026-11-02 (gildegold), worker 41
- **Area:** `dcp diffclass` / `dcp asmdiff` / lint
- **Problem:** ai_TutorialTick (0x575860) was stuck at ~105 differing instructions. In state 4 the original reads `ai_ClockMs` for a compare, then reloads it for the store with nothing in between (`mov edi,[clock]; cmp; jbe; mov edx,[clock]; mov [eax+8],edx`); VC6 kept our single load. A guessed `(*(volatile int *)&ai_ClockMs)` view made it byte-identical at once. The owner declares it plain int, so the unit-local view is now an `Open:` line.
- **Proposal:** flag "the original loads [sym] twice with no store or call between, ours once: sym may be volatile"; group such hunks per symbol ("12 hunks: an extra `mov reg,[ai_ClockMs]` on the original's side"); a lint / `dcp why` claim that the owner header should declare it volatile.
- **Repro:** ai_TutorialTick before gildegold 904e84b.
- **Cost of not having it:** ~10 minutes of guessing; would otherwise have been escalated wrongly.
