# `dcp data literal ADDR`: turn a gap-block string into a C literal

- **Source:** match-base session 2026-11-01 (gildegold), worker 3
- **Area:** new command / dcp-match-base skill
- **Problem:** the string "%s: %d" (0x62aaa4) was a `GAPDATA` block in `main.c`. Turning it into a C literal meant deleting the main.c definition and the extern by hand.
- **Proposal:** `dcp data literal 0x62aaa4`, which does this with D1/D4 checks (and the byte check from lint-string-literal-bytes-vs-original.md).
- **Skill:** the "data from the gap block (typing)" rule is written for named objects and doesn't say whether a plain literal needs its own commit.

## Also seen (match-base session 2026-11-01 (gildegold), worker 5)
- `"Beamed home"` at 0x6253b0 sits in a `full_data` gap block; the right handling is to leave the gap as is and have the code write the literal. The worker found that precedent (`"127.0.0.1"`) only by grepping. Proposal: one line in the match-base skill saying so. Cost: about 5 minutes.
