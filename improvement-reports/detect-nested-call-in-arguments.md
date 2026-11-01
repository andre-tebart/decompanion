# Detect a call nested inside another call's arguments

- **Source:** match-base session 2026-11-01 (gildegold), worker 3
- **Area:** dcp grade / headers conflicts / diffclass
- **Problem:** `ai_FilePickWindow` had a "six-argument `d2_GetViewWin`" with an `@original` excuse. In fact the original nests `d2_GetViewWin(win, 1)` inside the 8-argument `sv_CreateFormSlider` call. Four other `@deep` functions in `unk_5d33b0` (`ai_SaveOptionWindow`, `ai_SaveNameWindow`, `ai_LoadGameWindow`, `ai_JoinGameWindow`) blame a "cleanup split" for what is very likely the same pattern.
- **Proposal:** when a call's pushed arguments are popped early (`add esp, 8` right after it) and another call follows, point out "a nested call inside the next call's arguments".
- **Cost of not having it:** real base work hidden behind four `@deep` tags.
