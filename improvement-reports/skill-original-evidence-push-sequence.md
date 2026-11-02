# match-base skill: does the original's push sequence alone justify an `@original` spelling?

- **Source:** match-base session 2026-11-02 (gildegold), worker 49
- **Area:** dcp-match-base skill
- **Problem:** the skill wants a byte-matched caller as evidence for an `@original` spelling. The short y argument of `d2_CreatePicObj` is shown directly by the original's bytes (`sub cx` then an unextended `push ecx`) in ai_CannonBuildPanel, but no caller is byte-matched. The worker added a unit-local cast macro `d2_CreatePicObjS` without clear guidance.
- **Proposal:** state whether instruction-level evidence in the original (argument width at the push) counts, and how to cite it.
- **Cost of not having it:** small; uncertainty about a typing decision.
