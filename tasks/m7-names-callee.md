# M7 names the callee and the declaration in scope

- **Priority:** P2 · **Size:** S-M

## Problem

- M7 prints `?` for the callee of a call through a cast or a cast macro.
- It doesn't name the declaration in scope or the owner header.
- One implicit call was reportedly missed.

## Root cause

- The callee prints as `?` when clang's diagnostic has no name (lint.rs:1008).
- M7 comes only from `-Wimplicit-function-declaration` and `-Wdeprecated-non-prototype`. A K&R declaration brought in
  scope by another header would hide the call.

## Task

- Name the callee expression or macro.
- Name the declaration in scope (file:line, and whether it is K&R) and the header that owns the callee.
- Point to `dcp headers conflicts` rather than duplicating its logic.
- Find a repro for the missed implicit call.

## Reports

- grade-m7-indirect-call-unnamed
- grade-m7-owner-header-hint
- grade-m7-missed-implicit-call
