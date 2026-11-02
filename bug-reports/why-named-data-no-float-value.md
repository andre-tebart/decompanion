# `dcp why` prints no f32/f64 value for named rdata constants

- **Source:** match-base session 2026-11-02 (gildegold), worker 48
- **Severity:** minor
- **What happened:** for named constants (0x5eb988 ai_Unk5eb988, 0x5eb780, 0x5eb788, 0x5ebb74) the `dcp why` record has no `f32=` field; it appears only for unknown.data. Decoding FPU code needed `dcp dump` and hand conversion.
- **Expected:** always print u32/f32 (and f64 for 8 bytes) for 4/8-byte data.
- **Repro:** `dcp why 0x5eb988` at gildegold 39f10ee.
- **Impact:** small.
- **Related:** asmdiff-symbols-float-constant-value-missing.md
