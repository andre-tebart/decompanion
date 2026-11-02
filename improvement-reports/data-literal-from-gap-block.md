# `dcp data literal ADDR`: turn a gap-block string into a C literal

- **Source:** match-base session 2026-11-01 (gildegold), worker 3
- **Area:** new command / dcp-match-base skill
- **Problem:** the string "%s: %d" (0x62aaa4) was a `GAPDATA` block in `main.c`. Turning it into a C literal meant deleting the main.c definition and the extern by hand.
- **Proposal:** `dcp data literal 0x62aaa4`, which does this with D1/D4 checks (and the byte check from lint-string-literal-bytes-vs-original.md).
- **Skill:** the "data from the gap block (typing)" rule is written for named objects and doesn't say whether a plain literal needs its own commit.

## Also seen (match-base session 2026-11-01 (gildegold), worker 5)
- `"Beamed home"` at 0x6253b0 sits in a `full_data` gap block; the right handling is to leave the gap as is and have the code write the literal. The worker found that precedent (`"127.0.0.1"`) only by grepping. Proposal: one line in the match-base skill saying so. Cost: about 5 minutes.

## Also seen (match-base session 2026-11-02 (gildegold), worker 44)
- `full_data_629xxx` blocks are the unit's string literals. Writing `"tutorial\\aux_form"` inline matches via M9's content compare, but the gap block keeps the bytes and unused `extern GAPDATA` lines remain. Proposal: a `dcp check` note "gap block X is a literal of unit U, used as a literal, not referenced", saying whether to delete or keep it.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 45)
- `dcp dump --strings 0x629990 0x500` printing one line per string (`0x629e1c "CHAPTER_3_INTRO"`), and resolving `full_data_X + N` references to the string at that address. The worker scripted the hex-dump parse and replaced ~70 `(unsigned)&full_data_629xxx` references with literals across three builders (~5 minutes).

## Also seen (match-base session 2026-11-02 (gildegold), worker 50)
- `full_data_62a4bc` ("contact_KANONE") was replaced by a string literal in unk_575860; the GAPDATA definition in main.c and the unit's `extern GAPDATA` stayed behind and nothing reported it. Want a warning such as `gap block 0x62a4bc now unreferenced / covered by a literal of unk_575860` (or the `dcp data literal` command here). Cost: none yet, but stale gap blocks pile up.

## Also seen (match-base session 2026-11-02 (gildegold), worker 54)
- After writing literals inline (`"locations\\friedhof\\gespraeche.esc"`, the roman numerals, ToolTip form names), the unit's `extern GAPDATA full_data_62a8xx[];` lines stayed unused; found by grep and deleted by hand (~3 greps/seds per function). Want a lint warning for an `extern GAPDATA` with no remaining use in its unit.
- Skill 2.5 says to settle every gap object in a "(typing)" commit, but for string literals sibling code just writes the literal inline and leaves the gap block. Want one skill line, or a `kind=literal` hint from `dcp why` / `dcp refs` on a `full_data_` block that is just a string.
