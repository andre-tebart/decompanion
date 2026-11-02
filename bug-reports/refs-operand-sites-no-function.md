# `dcp refs` shows `fn=- fn_name=-` for operand sites inside drafted functions

- **Source:** match-base session 2026-11-02 (gildegold), worker 65
- **Severity:** minor
- **What happened:** `dcp refs 0x5ecedc` (a pooled float) printed 28 sites such as 0x490e4d and 0x49100d, all with `fn=- fn_name=-`, although those addresses appear to lie inside drafted functions.
- **Expected:** the containing function's address and name for each site.
- **Repro:** `dcp refs 0x5ecedc` at gildegold 68a0e3c.
- **Impact:** small this time; makes "who uses this constant" hard to answer.
- **Related:** refs-misses-operand-refs-open-data.md
