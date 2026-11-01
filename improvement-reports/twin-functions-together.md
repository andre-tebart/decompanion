# Handle twin functions together

- **Source:** match-base session 2026-11-01 (gildegold), worker 3
- **Area:** dcp next / dcp-match-base skill
- **Problem:** `ai_StepShot` and `ai_StepShotSlow` are the same instructions apart from four operands, but they are two separate queue items, each needing a full read.
- **Proposal:** the skill allows, or `dcp next` offers, handling a twin pair together (one commit, two raises or escalations). Diffing the two disassemblies would replace the second full read.
