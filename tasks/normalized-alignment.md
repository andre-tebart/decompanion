# Align on normalized keys

- **Priority:** P1 · **Size:** L · **Root:** R3
- **Related:** branch-targets-as-cut-points

## Problem

- Repeated blocks pair one copy apart: ai_FillNearRing is one copy apart, and ai_CannonScene has its calls off by one.
  This is the residual after 87cebdd.
- `regs=none` is shown while diffclass shows a hunk-local eax<->ecx.
- After a layout shift, every branch is `!`.

## Root cause

- The primary alignment (`difflib::opcodes` on `texts(la)` / `texts(lb)`, diffclass.rs:249, and asmdiff's
  `diff_lines`) runs on texts that still contain registers, stack slots and internal branch targets.
- Blocks that differ only in slots never match exactly, so Myers' shortest edit script can pair repeated copies one
  apart at equal cost.
- The register-masked alignment exists only for voting (`shape::voted_renaming`, shape.rs:569). It is global, so a
  renaming that holds in only one hunk loses the vote.

## Task

- Align with registers and stack offsets masked (`x86::shape_keys` / `mask_regs`).
- Map internal branch targets through the alignment before comparing.
- Then classify each pair exactly; the per-hunk renaming falls out.
- This changes grade's distance and verdicts. Measure on gildegold as 87cebdd did, and keep the speed budget.

## Rejected

`--pair 0xA,0xB`, `--segments`, `--runs`, `--non-regs`.

## Model

§1: φ inside a function is the alignment.

## Reports

- asmdiff-misaligns-repeated-cases (residual)
- asmdiff-regs-auto (residual)
- asmdiff-segments-and-runs
- diffclass-rotation-with-reorder-as-code (possibly)
