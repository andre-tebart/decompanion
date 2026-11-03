# A pooled toolchain literal is a derived owner

- **Priority:** P2 · **Size:** M

## Problem

An H global (`float ai_Unk5eb788`) is mapped by φ onto bytes that are really the toolchain's pooled `__real@`
literal. Q2 then flags it as a placeholder, and asmdiff names it as a datum.

## Root cause

The owner question has no answer "toolchain literal". A pooled constant the compiler emits is not an object of our
source.

The reference check (refcheck.rs) meets the same gap from the other side: our literal whose bytes the original's field
refers to, at an address φ gives one of our data objects, is `State::Datum`. Which declaration is wrong cannot be
decided today, so it is open (listed as `open:` in grade, asmdiff and diffclass), and `equiv::bind` does not bind
the literal there. On gildegold 05bbe07:

- `ai_FloatOne` (`float ai_FloatOne = 1.0f; /* 0x5eb780 */` in cm.c) on the pooled `__real@3f800000`: about 125
  functions use `1.0f`, 21 lines `ai_FloatOne`. As failing it took 101 byte and 24 shape functions to draft.
- `ch_EmptyName` at 0x631090 on the `""` VC6 puts in .bss (8 byte functions), `cm_TextNewline` ("$A").
- A real datum among them: `ch_StepSample` (`char ch_StepSample[] = "normal_s"`, written by
  SetCharacterStepSample), which ch_WalkSound reads where ours pushes the literal: a meaning difference left open.
- Not binding the literal cost two proofs (ahm_SendSetShare, ai_SolveCannonAim: shape to draft).

## Task

- Derive the owner "toolchain literal (`__real@...`)" for pooled constants under the VC6 convention.
- An H global φ-mapped onto such bytes contradicts it on the owner question.
- Then `State::Datum` is decidable: on a derived literal it is the datum's declaration that is wrong (the reference
  is the same: bind it); on a real datum the literal user fails (a concrete difference, draft).

## Model

§8.7: folding that the toolchain explains.

## Reports

- grade-q2-pooled-literal-placeholder
- asmdiff-symbols-pooled-literal-as-datum (remainder)
