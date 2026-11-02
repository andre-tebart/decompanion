# diffclass: a slot class for a local moved between a dead argument slot and the frame

- **Source:** match-base session 2026-11-01 (gildegold), worker 9
- **Area:** `dcp diffclass`
- **Problem:** in ai_TrustedOfTwo (0x4aab90) every instruction matches (142 vs 142) except where locals live: ours puts x1/x2 into the dead argument slots of b/c with a 4-byte frame (`push ecx`/`pop ecx`); the original keeps them in an 8-byte frame (`sub esp, 8`/`add esp, 8`). diffclass says `code 16`, `verdict=draft`, so the function can't reach shape and was escalated.
- **Proposal:** a slot class for a local moved from an argument home slot to a frame slot (or back), together with the matching prologue/epilogue frame-size change, so an otherwise identical function grades shape.
- **Repro:** `uv run dcp diffclass ai_TrustedOfTwo` at gildegold 0bf3e2d.
- **Cost of not having it:** ~5 minutes ruling out a real difference; function stays draft.
- **Related:** diffclass-spill-alloc-class.md (different pattern: arg home-slot reuse, not a spill), frame-slot-layout.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 21)
- gv_CannonKind: writing the clamped value back into parameter `n` left 28 `code` lines; a new local (`kind = ...`) dropped it to shape with only `slots`. Hint wanted while still `code`: "the original stores into a different (dead) parameter slot: use a new variable".

## Also seen (match-base session 2026-11-02 (gildegold), worker 22)
- Parameter as loop cursor: in gv_FindEntry the only difference was that the original uses the parameter `after` itself as the cursor (`add esi, 0x14`) where ours had a separate `cur` (`lea edi, [eax+0x14]`); even with `--regs` it stayed `code 194`. Using `after` directly matched byte for byte. Hint wanted: "a parameter loaded into a local's register which is then incremented: reuse the parameter". Cost: 2 iterations.

## Also seen (match-base session 2026-11-02 (gildegold), worker 37)
- ai_DecideMasterBuilder (gildegold 592d206): `code 32` from a slot swap involving a dead parameter's slot: the original keeps `o` in dead parameter `a`'s slot ([esp+0x60]) and `money` in a local ([esp+0x10]); ours the reverse, which reorders the s2 setup stores before the call. Frame 0x4c vs 0x44. Function held at draft. Cost: ~5 minutes.
