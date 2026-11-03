# D-rule messages name their sizes and alternatives

- **Priority:** P1 · **Size:** S

## Problem

- D1 and D7 messages don't say which size they mean.
- An "8-byte extent after a split" looks stale: the datum had become the last symbol of its section, so its slot ran to
  the padded section end.
- D5 demands `= 0` where the function's byte match wants the tentative or extern form.

## Root cause

- D1 uses `DataObj::size()`, the `coff::data_symbols` distance to the next symbol or the section end, padding
  included (coff.rs:360-387, rules.rs:644). D7 now reads the declared size (`declared_size`), the COFF size only
  without one; its message still says neither which nor the padding.
- `data map` instead shows the type size (`least`) and the room in the original.
- The declared type size (sizeof, the front end's) is on the L.src claim of each addressed data definition (`size`,
  rules.rs `declared_size`): the messages can name it instead of `least`.
- The messages (rules.rs:1000-1007, 1049-1052) name neither.
- D5 (rules.rs:1011-1017) applies the COMMON convention, a derived claim, while the byte match with the tentative form
  is reproduced.

## Task

- Each D1 and D7 message states its sizes: "in our object the next symbol of unit U's section is NAME at +N (padding)"
  or "the section ends at +N", next to the type size and the original's room.
- D5's message offers the alternative: define the datum `= 0` in the unit that φ or the data layout gives the address
  to, and declare it extern here. Where an experiment discriminates, name it.

## Model

A claim states its support and its reason (§3).

## Reports

- check-d1-size-evidence-unclear
- check-d1-stale-extent-after-split
- check-d7-size-message-unclear
- check-d5-requires-init-but-tentative-matches
