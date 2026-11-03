# Name evidence from `"ident():"` strings

- **Priority:** P2 · **Size:** S

## Problem

Functions that reference a string such as `"gm_SpawnCharacter():"` (a diagnostic naming the function) keep their
placeholder names, although the image itself holds the name.

## Task

When a function references a string of the form `"<ident>():"`, show `<ident>` as name evidence in grade Q1 and in
refs.

## Model

§8.1: a name reaches the claim system only when the image holds it, and then it is part of what an analysis of I reads.

## Reports

- name-hint-from-strings
