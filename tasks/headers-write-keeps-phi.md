# `headers conflicts --write` keeps φ well-formed

- **Priority:** P0 · **Size:** S · **Root:** R7

## Problem

- The include lands between `/* 0xADDR ... */` and the definition. `dcp check` then shows L.src, M.gen and a false M1
  ("its source is gone?").
- A header the unit already includes is included again.

There are 5 sightings.

## Root cause

- `include_pos` (headers.rs:348-386) walks back from the first use to the nearest statement start. The definition
  line counts as a legal insertion point because:
  - a one-line comment isn't "inside" a comment (the range on line 368 is empty);
  - `live_code` blanks the comment.
- Nothing compares the headers with the unit's existing INCLUDE_LINEs.
- The trial never runs the source scan, so `falls=0` says nothing about φ.

## Task

- Insert only in the head region, never between a comment block and the line it is attached to.
- Skip a header the unit already includes, and report it.
- Before writing, run the source scan on the new text and refuse on any new L.src or M.gen finding.
- General rule for every command that writes H (headers, data fix, rename): validate the result with the scan rules,
  not only by compiling.

## Model

§5 ill-formed: the tool must not put φ into a state where the model cannot be applied.

## Reports

- headers-conflicts-write-splits-address-comment
