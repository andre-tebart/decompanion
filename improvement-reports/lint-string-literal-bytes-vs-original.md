# Lint: check that a C string literal's bytes match the original

- **Source:** match-base session 2026-11-01 (gildegold), worker 2
- **Area:** check / D-rules, typing commits
- **Problem:** moving `full_data_62aa8c` out of the gap block produced the C literal `"menu\netlobby"`. C reads `\n` as a newline, so the string changed meaning (wrong form opened). Nothing flagged it; `asmdiff --symbols` showed the same symbol name.
- **Proposal:** a D-rule or lint that compares a literal's bytes with the original bytes at that address, or a `dcp dump`-style check after a gap-to-literal move.
- **Repro:** `src/unk_589f10.c` at gildegold commit bacc0fc, line 187.
- **Cost of not having it:** a real meaning bug, found only by chance with `dcp dump 0x62aa8c`.

## Also seen (match-base session 2026-11-01 (gildegold), worker 1)
- `main_OpenEngine` had `"Misc\Loading_main"` and `"%s\include_sfx.ini"` written with a single backslash; VC6 drops the unknown escape (C4129) and the strings come out wrong. Only `asmdiff --symbols` showed it (`!` lines); `grade` showed only generic code hunks. Proposal: turn C4129 into a meaning warning on that line, or have the B3 note say "string literal differs: ours ... vs ...". Repro at gildegold acf823a: `uv run dcp grade main_OpenEngine` vs `uv run dcp asmdiff main_OpenEngine --symbols`. Found by luck.

## Also seen (match-base session 2026-11-01 (gildegold), worker 5)
- main_BeginPlayerRound: a Python edit run from a Bash heredoc turned `"Runden\\Spielerrunde_Beginn_NEU"` into `"Runden\Spielerrunde..."`; `\S` compiled to `S`. Dist and grade did not change; only `asmdiff --symbols` showed it, as `!` on a string push. Found by chance. Proposal: a Q or B rule "string literal content differs from the original". See also skill-edit-scripts-not-heredocs.md.

## Also seen (match-base session 2026-11-02 (gildegold), worker 17)
- sv_RegisterNamePlate's old draft had "Too many Objects: %s" (original: no space). M9 fired only once the rewrite reached 0 differing instructions (surprise `gate=FAIL errors=1`). Proposal: report literal mismatches in `dcp grade` on draft functions too.

## Also seen (match-base session 2026-11-02 (gildegold), worker 40)
- A scripted edit turned `f\xfcr` into a real UTF-8 `ü` (2 bytes) in an error-message literal of ai_ExecBuildBuilding; `dcp build` / `dcp grade` reported the same distance (65 ins / 411 bytes) before and after, no warning. Noticed only because grep printed the umlaut. Proposal addition: lint for non-ASCII bytes in C string literals under src/ (VC6 source is Latin-1), or compare the .rdata string with the original. Cost: ~3 minutes.

## Also seen (match-base session 2026-11-02 (gildegold), worker 44)
- `dcp grade NAME | head -4` hid an M9 literal mismatch further down; one function (ai_TutorialStepForm) was escalated with wrong literals (`"tutorial\left_form"` lost its backslash in a heredoc) and needed a fix commit. Proposal: M9 is a meaning error - put it first or in the summary line.
- `dcp asmdiff` without `--symbols` folds a push of a wrong string literal into "... N equal instructions ...". Plain mode should mark differing literals with `!` instead of folding them.

## Also seen (match-base session 2026-11-02 (gildegold), worker 46)
- `"Locations\Domizil\Alchemistry2"` was written through a heredoc / Python and landed with single backslashes; `\D`, `\s` compile as unknown escapes that drop the backslash, so the form name was silently wrong. `dcp build` / `dcp grade` said nothing; `asmdiff --symbols` showed `LocationsDomizilAlchemistry2` with `!`, read as the usual literal-vs-address mark. Proposal: `dcp lint` reports unknown escape sequences (clang `-Wunknown-escape-sequence`), and asmdiff says "literal text differs" on such a `!`. Repro: unk_575860 at gildegold 80c1371 (fix commit acec15d). Cost: ~6 calls and a fix commit.
