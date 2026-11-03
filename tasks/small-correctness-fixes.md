# Small correctness fixes

- **Priority:** P1 · **Size:** S (each)

Each item is verified at e42b189:

1. **refs `comment=` is line 1 of the file** (7 sightings). cliread.rs:478 reads
   `read_text_locale(&path).split('\n').next()`. Take the address comment above `definition=` from the srcscan spans
   instead. Check that Q6 (readability.rs) doesn't read the comment the same way.
2. **`disasm ... --symbols` fails silently or with a Python-style message.** args.rs:315 has
   `allow_hyphen_values = true` on LEN, so `--symbols` is taken as LEN, and cliread.rs:84 prints
   `invalid literal for int(): '--symbols'`. Remove `allow_hyphen_values` so clap reports the unknown option. Replace
   the "invalid literal for int()" messages at cliread.rs:84, clicmd.rs:45 and analyzers.rs:231.
3. **Garbled session-start sentence.** In commands.rs:668-672 the template `"gate: ok. This is {functions}."` gets a
   `functions` value that already reads "a match-base session is counted in…".
4. **Pasted fragment in src/client.rs:1.** The module doc reads `//! Th    c.spawn().map_err(...) \`dcp\` command: ...`.
5. **disasm decodes jump tables as code.** In the listing range, runs owned by a jumptable, an idxtable or any other
   non-code owner print their entries (labelled targets or indices). Uses readers-use-answer-table's owner lookup.
6. **Invariant test for asmdiff `diff_lines`:** every line of each side is printed or counted exactly once, including
   frame-folded runs. That decides asmdiff-default-drops-our-instruction (gm_SetTime), which cannot be reproduced
   without the repro.

## Reports

- refs-comment-is-unit-lead
- disasm-symbols-flag-silent-empty
- session-start-garbled-sentence
- disasm-decodes-jump-tables
- asmdiff-default-drops-our-instruction
