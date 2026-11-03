# A pooled toolchain literal is a derived owner

- **Priority:** P2 · **Size:** M · **Depends on:** ref-check-in-object-experiment

## Problem

An H global (`float ai_Unk5eb788`) is mapped by φ onto bytes that are really the toolchain's pooled `__real@`
literal. Q2 then flags it as a placeholder, and asmdiff names it as a datum.

## Root cause

The owner question has no answer "toolchain literal". A pooled constant the compiler emits is not an object of our
source.

## Task

- Derive the owner "toolchain literal (`__real@...`)" for pooled constants under the VC6 convention.
- An H global φ-mapped onto such bytes contradicts it on the owner question.

## Model

§8.7: folding that the toolchain explains.

## Reports

- grade-q2-pooled-literal-placeholder
- asmdiff-symbols-pooled-literal-as-datum (remainder)
