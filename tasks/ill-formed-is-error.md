# Ill-formed findings are errors; C.name.alias covers every name

- **Priority:** P0 · **Size:** S-M · **Root:** R7

## Problem

Two of our names at one address pass the gate. Examples: `ai_Unk5049e0` next to `gm_Unk5049e0`, and extern-only
aliases.

## Root cause

- `C.name.alias` (setup.rs:231-249) groups only source names whose reason starts with "data address comment".
- It is emitted at `warn`, although registry.rs:90 files it as ill-formed.
- Category and severity are set independently.

## Task

- C.name.alias covers every name of H at one address: functions, data, extern-only names, placeholder spellings.
- It is an error unless an alias is declared or the toolchain explains the fold (§8.7).
- An extern-only name in an unowned run is a gap finding.
- In `registry::CHECKS`, an ill-formed id cannot be emitted below error. Sweep every ill-formed id emitted at warn.
- Count the effect on gildegold before landing: it may surface many errors at once.
- Rename lists the other names at OLD's address.

## Model

- §8.7: two of our definitions at one address without a toolchain reason are ill-formed φ.
- §5: the gate fails on errors.

## Reports

- check-extern-only-alias-unflagged
- rename-leaves-stale-macro-name
- data-view-past-object-end-unflagged (the alias part)
- check-unresolved-data-unnamed (the build part)
