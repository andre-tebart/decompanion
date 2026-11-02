# `dcp data map`: list referenced-but-undeclared addresses inside a unit's block

- **Source:** match-base session 2026-11-02 (gildegold), worker 48
- **Area:** `dcp data map`
- **Problem:** ai_Tutorial showed `room=272`, which hid that 0x5eec64..0x5eed70 held about a dozen undeclared constants with users.
- **Proposal:** under each room, list the addresses inside it that the original's code references, with user counts.
- **Repro:** `dcp data map` for unk_575860 at gildegold 83fdff3.
- **Cost of not having it:** moderate (found by reading FPU code).
