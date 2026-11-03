# Prover stop reasons name the real effect pair

- **Priority:** P0 · **Size:** S · **Root:** R10

## Problem

The prover prints `proof: unknown: a store against a call` where the blocks' `Escape` effects differ:

- sv_UpdateGroundplan: `Escape([(0,186)])` vs `Escape([(0,190)])`;
- ai_CannonExplosion.

The skill calls this line "the first place to read", so workers look for a moved store that does not exist.

## Root cause

The `_ =>` arm in equiv.rs:2095-2099 also covers Escape, Fill and Copy pairs.

## Task

- Add Escape, Fill and Copy cases, with "an escaped frame laid out otherwise" as its own reason.
- Print the two differing effects in source terms (slot, offset, value, callee) instead of a category.

## Model

- §4: the experiment says where H differs.
- A wrong label is a rule that reports wrongly.

## Reports

This explains most still-draft functions in the diffclass-* class reports: sv_UpdateGroundplan, ai_CannonExplosion,
ai_DecidePriceManipulation and ls_ReadSceneRecords.
