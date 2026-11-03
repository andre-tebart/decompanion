# One object of the original split into several of ours is an error

- **Priority:** P0 · **Size:** S · **Root:** R7

## Problem

D8 reports the original's code using a range as one object (a block copy, a loop, an access through its address)
while our sources define several objects there. When the pieces are all of one unit, in order and without a hole, it
is a `warn` ("it links as the original's, declare it as one"), so the gate passes. gildegold has 12, for example:

- `gm_DefaultStock` (48 bytes) with `ai_Unk6178f8` at +0x30, where the original copies 0x6178c8..0x61a348 in one block.
- `full_data_6f4f60` and seven more `full_data_` pieces at +0x4 .. +0x34.

## Root cause

- `d8` (rules.rs:821-829) picks the severity from `tiled`: equal bytes after the link stand in for one object.

## Task

- D8 is an error in the tiled case too. The message keeps the remedy: declare one object of the proven extent, with
  the pieces as its fields (or views of it where a unit needs another spelling, with `@original`).
- `dcp data fix` offers the merge for a tiled run (see gap-data-through-data-fix).
- Count the effect on gildegold before landing.

## Model

- §8.3: equal bytes at one layout are not the criterion; the pieces link the same, but the owner answer differs.
- §8.7: one object of I, several objects of H, with no reason the toolchain gives, is no valid φ (like
  C.name.alias).
- The derived extent (S.extent) outranks the declared split (§3).

## Reports

- found by the C.name.alias cleanup of gildegold (decompanion ecaaa9d): the warn-level findings that should gate
