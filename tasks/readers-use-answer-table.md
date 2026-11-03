# Readers use the answer table; φ ranking

- **Priority:** P1 · **Size:** M · **Root:** R4

## Problem

- disasm truncates a byte-matched function at a guessed end.
- refs gives `fn=-` for operand sites, and counts 0 references where why counts 13.
- Rename logs `kind=data` for functions (about 20 sightings), and `func` for cast macros.
- Labels use the view macro (`NOWX`) instead of the datum (`ai_Time`), and `d3s_ShadowBits` instead of `dd_Surface`.
- Addresses inside known objects show bare instead of as `owner+off`.

## Root cause

Each reader re-derives "the object covering an address" with its own filter:

- `Reader::walk_func` (cliread.rs:186) skips `M.*` rules and needs a func or thunk symbol. A byte-matched function
  whose extent rests on M.match has no extent, and disasm falls back to the next start capped at `a + 0x400`
  (cliread.rs:267), silently.
- refs counts refs_to with `to == a`, or inside the symbol only when it starts at a (cliread.rs:498). why counts inside
  whichever symbol covers a.
- `Names::symbol_at` (names.rs:131-143) looks back at most 4 claims; rename's kind (rename.rs:265-275) and `label_of`
  (names.rs:176) use it.
- `placeholder_whole` takes a spelling as the address (rename.rs:266).
- `Phi::ranked` (phi.rs:163-167) sorts by (origin, folded, name), which is alphabetical within an origin. Views are not
  ranked below the definition.

answers.rs holds the owner at its highest support, but almost no read command uses it.

## Task

- disasm extent, refs `fn=`, the refs and why counts, asmcmd's extent fallback (asmcmd.rs:329-342), `label_of` and the
  rename kind all read `answers::at` / `rows`.
- Remove `walk_func`'s `M.*` exclusion and the silent 0x400 cap. When nothing is known, the header says the extent is a
  guess.
- φ ranking: the defining object first, then declarations, then views. Never alphabetical.
- A name whose address comes only from its spelling (a cast macro, a view) is logged as such, never as `func ADDR`.

## Rejected

Flagging drift between ledger names and source names: names are outside the model (§8.1).

## Model

§5: one answer per (byte, question), used by every reader.

## Reports

- disasm-truncates-function-without-codewalk
- refs-operand-sites-no-function
- refs-misses-operand-refs-open-data
- rename-kind-data-for-functions
- asmdiff-ledger-name-vs-source-name
- disasm-names-view-macro-not-datum
- asmdiff-symbols-original-side-new-object-unresolved
- asmdiff-symbols-reordered-load-marked-wrong (naming)
- asmdiff-symbols-array-minus-one-named-previous
- txt-views-index-spelling (offset labels)
