# Flag "original loads a const datum from the unit's rdata where ours uses a `_real@` literal"

- **Source:** match-base session 2026-11-02 (gildegold), worker 48
- **Area:** `dcp diffclass` / `dcp asmdiff`
- **Problem:** the key finding in ai_CannonCamera, ai_CannonAim and ai_CannonSwitchAnim was that the original loads const globals from the unit's own .rdata block (0x5eec6c: ai_CannonPitchMax/Min, ai_CameraPitchMin/Max/Zero, ai_WimpelPos). Tells: two copies of 0.7853982 at different addresses, `fdiv [mem]` where a literal would become a multiply, `(max - min)` computed at run time. The `=` alias marking hides exactly this.
- **Proposal:** when the original's operand is in the unit's rdata block and ours is a pooled `_real@`/literal, mark it "const datum, not literal" with the datum's address and value.
- **Repro:** ai_CannonCamera before 33f1640 (gildegold).
- **Cost of not having it:** large.
