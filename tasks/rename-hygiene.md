# Rename hygiene

- **Priority:** P2 · **Size:** S (field renames M)

Names are outside the model (§8.1), so this is tool ergonomics.

## Task

- **Repeat writes nothing.** Today the "recorded" path (rename.rs:282-287, 449-463) appends to names.log without looking
  at it, and says "renamed by hand". A repeat should say "already recorded, nothing written".
- **The address form after a hand rename.** It resolves OLD to the ledger name, which is already NEW, and is refused
  (rename.rs:262-264). The error should point to the name form `dcp rename ai_Unk498b80 NEW`, which already records the
  hand rename.
- **Reasons per pair.** One `--why` is shared by all pairs (rename.rs:146). Make `--why` repeatable per pair, or give a
  clear error that names `--from`. Document the `--from` format in `-h`.
- **Collisions.** On a collision, name the existing object's unit and comment (the suggest-a-name part is declined).
- **Struct fields.** `dcp rename TYPE.field NEW` uses clang member references, inside the existing command. Today a
  field is renamed "by its words" (rename.rs:19-20), which hits unrelated structs.
- **Globals into one object's fields.** `dcp rename ai_UpdateStart ai_Update.start` is refused ("no C identifier"), so
  merging the pieces of one object (D8) into a record is a hand rewrite plus hand-written names.log lines
  (gildegold e09ed0f5). Accept `OLD OBJ.field` when OBJ's type has the field at OLD's address, and log it.

## Rejected

- `--log-only`.
- Completing a hand rename despite a type conflict: the header with OLD and a definition with NEW would give M6, an H
  that is no program.

## Reports

- rename-repeat-duplicate-names-log
- rename-same-name-after-hand-rename
- rename-per-pair-why (6)
- rename-from-help-example
- rename-collision-hint
- rename-struct-field (3)
- rename-multi-pair-silent (not reproducible from the code; covered by output-convention)
