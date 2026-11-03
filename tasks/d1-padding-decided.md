# D1 decides alignment padding instead of warning

- **Priority:** P0 · **Size:** S-M · **Root:** R7

## Problem

D1's warning "X at ADDR: the object gives it N bytes, the symbol at B leaves R; fine if the last K are alignment
padding" leaves the decision to the reader. gildegold has 38 of them (`cm_SpeedTicks`, `gv_GraveTotals`,
`ai_Unk5ebc1c`, ...). Either the extra bytes are padding our toolchain adds, and nothing is wrong, or the declaration
is larger than the original's object, and our definition reaches into the next one.

## Root cause

- `d_data` (rules.rs:850-862) compares the object's size with the room before the next start and the type's least
  size; when least <= room < size it does not look at what the extra bytes are.

## Task

- Decide it from our object: the extra bytes are padding when the definition's own size (its type's size, from the
  front end: the L.src claim's `size`, rules.rs `declared_size`; or the symbol) fits the room and the rest is the section's alignment fill up to the next symbol's
  alignment. Then there is no finding.
- Otherwise it is an error (the declaration is too large: it overlaps the next object).
- Count the effect on gildegold before landing.

- D9 (rules.rs `room_refs`) already reads the padding the same way: our object's bytes past the declared size. A
  padding the original's code reads is D9's error, not D1's.

## Model

- §1: the toolchain is part of H; its alignment is a convention that explains the padding (derived), or it does not.
- §5: a finding states something; "fine if" is no finding.

## Reports

- found by the C.name.alias cleanup of gildegold (decompanion ecaaa9d): the warn-level findings that should gate
