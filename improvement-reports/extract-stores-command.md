# `dcp extract stores 0xADDR [--struct T]`: initializer-style functions as typed store records

- **Source:** match-base session 2026-11-02 (gildegold), worker 44
- **Area:** new command / `dcp draft`
- **Problem:** the tutorial chapter builders (0x578570, 0x578e40, 0x579570, 0x57aa80, 0x57aeb0, ...) are long regular sequences: alloc, `AI_ZERO_AT`, then ~20 field stores per record. The worker wrote an ~80-line script that walks `dcp disasm`, tracks registers holding zero or immediates (incl. `mov eax, imm` / `[reg+off], eax` reuse), reads string literals with `dcp dump`, and emits typed C in store order: byte match for chapter 1 and shape for chapter 2 on the first try.
- **Proposal:** `dcp extract stores 0xADDR [--struct TUTRUN]` printing per-block `offset=value` records (immediates, resolved symbols, literal text, register-held constants) in store order with field names from the header struct; better, `dcp draft --stores` for initializer functions.
- **Cost of not having it:** ~30 minutes per builder, plus hand-transcription errors (and see ../bug-reports/disasm-truncates-function-without-codewalk.md, which silently truncated the script's input).
