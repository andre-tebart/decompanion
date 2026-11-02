# Flag an index scale that differs from the original's multiply chain

- **Source:** match-base session 2026-11-02 (gildegold), worker 23
- **Area:** `dcp asmdiff` / `dcp grade`
- **Problem:** the view `ai_Unk7e3f94` (`char (*)[100]` at `ai_PlayerSlots+0x54`) was indexed as `ai_OwnPlayer * 0x5e8`; the original uses stride 0x2f4. No D7/D8 or hint said the index arithmetic disagrees; fixing it got gv_ReserveGrave to byte. gv.c's later order handlers still use 0x5e8 (an `Open:` line now).
- **Proposal:** when a site's computed scale differs from the original's (imul/shift/lea chain), note "index scale ours 0x5e8, original 0x2f4"; optionally scan a unit for other sites using the same view with that scale.
- **Repro:** gv_ReserveGrave before gildegold b0d1486.
- **Cost of not having it:** small here, but a silent meaning bug in draft code.
