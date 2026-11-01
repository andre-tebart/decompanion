# `dcp try`: compile a variant in memory and print its distance

- **Source:** match-base session 2026-11-01 (gildegold), worker 3
- **Area:** new command
- **Problem:** the worker looped `cp backup; python edit; dcp build; dcp grade` many times: 6 DRAG macro forms, 4 `ai_MissionMode` forms, 3 strcpy forms.
- **Proposal:** `dcp try NAME --replace OLD NEW ...`, which compiles the variant without touching the file and prints the distance.
- **Cost of not having it:** roughly 10% of the session's tool calls.
