# Lint: check that a C string literal's bytes match the original

- **Source:** match-base session 2026-11-01 (gildegold), worker 2
- **Area:** check / D-rules, typing commits
- **Problem:** moving `full_data_62aa8c` out of the gap block produced the C literal `"menu\netlobby"`. C reads `\n` as a newline, so the string changed meaning (wrong form opened). Nothing flagged it; `asmdiff --symbols` showed the same symbol name.
- **Proposal:** a D-rule or lint that compares a literal's bytes with the original bytes at that address, or a `dcp dump`-style check after a gap-to-literal move.
- **Repro:** `src/unk_589f10.c` at gildegold commit bacc0fc, line 187.
- **Cost of not having it:** a real meaning bug, found only by chance with `dcp dump 0x62aa8c`.
