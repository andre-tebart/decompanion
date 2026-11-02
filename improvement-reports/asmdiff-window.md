# `dcp asmdiff NAME --at ADDR --context N`: an aligned window showing both sides in full

- **Source:** match-base session 2026-11-02 (gildegold), worker 33
- **Area:** `dcp asmdiff` / `dcp disasm --ours`
- **Problem:** comparing ours and the original around one hunk meant piping through sed/awk over address strings; once it gave empty output because our addresses differ from the original's.
- **Proposal:** `dcp asmdiff NAME --at 0x4977f0 --context 20` showing both sides including collapsed equal lines; `dcp disasm --ours NAME` with an address range or `--around ADDR`.
- **Cost of not having it:** ~5 minutes over the session.
- **Related:** disasm-compact-view.md, asmdiff-changed-only.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 38)
- Reading our object's block layout needed `dcp asmdiff NAME --all --plain | grep -v "^+"` (alignment-interleaved). Proposal: `dcp disasm --ours NAME` or `asmdiff --side ours`. Cost: ~10 minutes across ai_DecideUpgradeGuild and ai_DecidePriceManipulation.
