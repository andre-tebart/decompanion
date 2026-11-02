# `dcp why --brief`: just the owner

- **Source:** match-base session 2026-11-02 (gildegold), worker 63
- **Area:** `dcp why` (output size)
- **Problem:** ~10 lines (section, toolchain, phi records) when only the owner was needed. Size is fine otherwise.
- **Proposal:** `--brief` printing owner unit, name, type and size on one line.
- **Cost of not having it:** context only.

## Also seen (match-base session 2026-11-02 (gildegold), worker 67)
- `dcp why 0x504790` leads with the section answer (`chars=0x60000020 code=yes raw_hi=...`) before the owner line. Want owner first, or `--q owner`.
