# Library member placement checks reference targets

- **Priority:** P0 · **Size:** M · **Root:** R2

## Problem

- `fopen` is placed where `_wfopen` is. The two have the same code but different callees (`__openfile` /
  `__wopenfile`).
- `atoi` stays unnamed. The reference check lists it open in 51 functions on gildegold 05bbe07 (`srand` 6,
  `stricmp` 5): their references are not checked until the member is placed.

Placed-member claims carry **reproduced** support. By the model, a wrong one is a rule bug.

## Root cause

- `place_members` (crt.rs:107-208) groups members by (masked bytes, mask). It places them by masked equality, without
  resolving their relocations.
- Members with fewer than 8 compared bytes are skipped (crt.rs:124). That is likely the atoi case.

## Task

- Resolve each member's relocations against the image. Accept a placement only when its targets agree with the other
  placed members, the imports and φ.
- Split groups with equal masked bytes by their resolved targets.
- Allow short members once their targets confirm them.
- Members that stay indistinguishable leave φ open between them. Do not pick one.

## Model

§4: the object experiment tests the bytes *and* the targets of references, and a placed member is such an experiment.

## Reports

- asmdiff-symbols-wrong-library-callee
