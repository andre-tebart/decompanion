# `dcp dump --as f32|f64 ADDR...`: typed values for several addresses in one call

- **Source:** match-base session 2026-11-02 (gildegold), worker 57
- **Area:** `dcp dump`
- **Problem:** the worker looped `dcp dump` 11 times to read float constants (0.0125f, 0.8, 160.0f, ...) for float-heavy f3gm functions.
- **Proposal:** `dcp dump --as f32|f64|u32 ADDR...` printing one typed value per address.
- **Cost of not having it:** several calls per float-heavy function.
- **Related:** ../bug-reports/why-named-data-no-float-value.md

## Also suggested (match-base session 2026-11-02 (gildegold), worker 62) - strings
- `dcp dump 0x61aaac 24`: the `|....|` column showed fragments of neighbouring strings (`|----->Ob|`, `|EN..arbe|`); re-dumped 0x90 bytes to find the real strings. Want `--string` printing the NUL-terminated string at the address. Cost: 2 extra calls.

## Also seen (match-base session 2026-11-02 (gildegold), worker 65)
- `dcp dump 0x5ecedc 4` should print f32 / u32 (f64 for 8 bytes) next to the hex, as `dcp why` does (`f32=0.02380952`); `why` was run only to read the float.

## Also seen (match-base session 2026-11-02 (gildegold), worker 67)
- `dcp dump 0x5eb79c 4` prints only `00 00 80 3e`; 9 constants decoded mentally while `asmdiff --symbols` already shows `(0.25)`. Want `--as float|double|int`, or auto-decode when the address is a float operand.
