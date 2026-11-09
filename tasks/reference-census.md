# Reference census: the objects each side refers to, whatever the alignment

- **Priority:** P0 · **Size:** M · **Root:** R1, R2

## Problem

- M8 compares a reference of ours with the original's field at the instruction the alignment pairs it with. Where
  the alignment pairs reordered code crosswise, M8 names a "difference" that is none: gildegold `cm_WaitTicks`
  (`cm_ShowPartyTexts` | `cm_UpdateDamagePops`, both called by both sides) and `d3_CornerCB` (`dd_Width` |
  `dd_Height`). A proof then raises the function to shape and the M8 line stays printed as `B2 shape: M8 at ...`.
  A reader (a worker, or a scan over `dcp grade`) cannot tell such a line from a wrong object: a scan of gildegold
  at f5f47ae9 found 451 concrete M8 lines in 202 functions (20 of them shape) and most are this crossing.
- The opposite case is not caught at all where the alignment does not pair the instruction: a reference of ours to
  an object the original never touches (or the original's to one we never touch) inside an unaligned `code` hunk is
  no M8 line. In a draft function it hides among the allocation hunks.
- `equiv::witness` already has the idea (a callee or a stored global one side never refers to), but only for calls
  and stores, only the first one, with a 0x1000 address window instead of the object's extent, and only in
  `dcp asmdiff` / `escalate`: G.grade never runs it.

## Task

- One census per function, from the prover's bound code (equiv::bind, so the same binding as the proof):
  - **ours only:** a relocation of ours to a named object O (φ: start, declared size) where no 4-byte field of the
    original's function (displacement, immediate, branch target) lies in O's extent (one past the end and the
    compiler's small negative bias `[O-4+ecx*4]` included). A function O: its start only.
  - **theirs only:** a 4-byte field of the original's equal to the start φ gives a named object of ours (a
    function, a datum; not a placeholder) that none of our relocations refers into; checked only when every one of
    our relocations is bound (as witness: an unbound one could be that object). The function's own extent is no
    reference.
- G.grade: a function that is no byte match gets one line per census difference (`M.census: ours refers to
  dd_Width (0x1463598) at +0x1b2; the original never refers into it`) after its M8 lines, and a finding
  `M.census` at **warn** (gildegold's gate must stay as it is until the census is measured there; then decide
  whether it is a concrete difference that keeps a function from shape).
- An M8 line of a function whose census is empty says so: `(crossed: both sides refer to both)`. That separates
  the alignment's crossing from a wrong object without a reader opening asmdiff.
- The original's field set and our bound references are held with the rest of the function's results (they depend
  on the key); the φ lookups run per refresh (φ of other objects is not in the key).

## Rejected

- Counting references (multiplicity): the compiler duplicates and merges loads and tails; presence per object is
  what carries the meaning.
- Raising the census to an error now: first measure it on gildegold (false positives from pooled literals, imports
  without φ, jump tables).

## Model

The object experiment's reference check (§4) without the alignment: a reference is part of the function's meaning,
not of an instruction's.

## Reports

- this task came from a review of gildegold's deep queue (2026-11-09), not from a report
- related: `equiv::witness` (2843815), diffclass-meaning-classes, escalate-gates-on-verdict

## Literals (2026-11-09)

The census also takes our literals (strings, floating constants): one whose bytes no field of the original's
function refers to anywhere is listed (`our literal 0.6 (__real@...); the original's function refers to no such
bytes`). With the census empty, every M8 / M9 / M10 line of the function says `(crossed ...)`: a literal paired
with another field inside a mismatched hunk is no difference. gildegold 0ce9dab4: 24 literal findings in 14
functions; the deep queue's `concrete` class fell from 24 to 16 (err_ExceptionFilter, ai_CommandExecution, ... were
pairing artifacts).
