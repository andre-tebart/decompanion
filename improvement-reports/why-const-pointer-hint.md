# `dcp why` / grade: hint when an unowned .rdata dword holds a relocated address (a `T *const`)

- **Source:** match-base session 2026-11-02 (gildegold), worker 39
- **Area:** `dcp why`, `dcp grade`
- **Problem:** ai_NextNearRingEntry's original does `mov esi, [0x5ed1b0]`, loading a pointer stored in .rdata that points to a .data object. `dcp why 0x5ed1b0` shows `u32=0x0060034c` and owner `unknown.data`, but doesn't say "this is a `T *const` initialised with &sym 0x60034c"; the worker worked it out from the dump (now `G6CURSOR *const ai_NearRingCursor`). A less careful reader might reach for a raw address.
- **Proposal:** when an unowned .rdata dword holds a relocated address of a known symbol, hint "looks like `T *const = &ai_Unk60034c`".
- **Repro:** `uv run dcp why 0x5ed1b0` at gildegold before 3be9fb1.
- **Cost of not having it:** ~5 minutes.
