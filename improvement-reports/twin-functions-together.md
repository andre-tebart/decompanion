# Handle twin functions together

- **Source:** match-base session 2026-11-01 (gildegold), worker 3
- **Area:** dcp next / dcp-match-base skill
- **Problem:** `ai_StepShot` and `ai_StepShotSlow` are the same instructions apart from four operands, but they are two separate queue items, each needing a full read.
- **Proposal:** the skill allows, or `dcp next` offers, handling a twin pair together (one commit, two raises or escalations). Diffing the two disassemblies would replace the second full read.

## Also seen (match-base session 2026-11-02 (gildegold), worker 23)
- The graveyard order senders and handlers (types 0-6 of message 0x60) interleave in address order: sender, handler, sender, handler. Typing GVORDER once paid off across 3 functions, but the dispatcher (cm.c 0x4cce10) had to be found by hand. Proposal: `dcp next` / `dcp refs` note "sibling pattern: N functions call cm_SendGraveOrder / are dispatched from 0x4cce10". Cost: ~3 minutes.
