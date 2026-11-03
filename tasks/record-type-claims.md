# Record types as claims: one type per record

- **Priority:** P2 · **Size:** L · **Depends on:** model-decisions (item 3), signature-claims-from-call-sites
- **Related:** consistency-at-uses (the cast rule is its cheap first step)

## Problem

Two struct types of H can describe the same records of I and nothing fails. The gildegold C.name.alias cleanup
(decompanion ecaaa9d) merged such types only where a global object carried each type at one address (`D3IFLEVEL` /
`D3IOSET` / `D3LIGHTSET`, `D3IOANIMDATA` / `D3ANIMDATA`, `D3DDEVINFO` / `D3DCARD`). Where the records are reached
only through pointers, the duplicates stay: `D3OPS`, `D3IOSTOCK` and `D3MESHSRC` describe the stock records of
`D3BGF`; `D3FLMAP`, `D3TERRAIN`, the `D3STERR` views and `INIT_TERRAIN` describe the terrain records of
`d3_Terrain`.

## Root cause

- Types are no question in the code (mental-model §10, "Types are questions": `M.lint` reports clang's M5 / M6 / M7;
  types are no claims of their own).
- A struct type owns no bytes of I. φ and C.name.alias see names at addresses; a record reached through a pointer has
  no address in the image, so two readings of it never meet at one byte.
- The conversions between the two types are explicit casts (`D3_OPS(x)`, `(D3IOSTOCK *)p`), which clang does not
  report.

## Task

- A record question: "the record a pointer designates has, at offset k, a field of type t". Its subject is not a byte
  of I but a record: an allocation site, a list (its head and links), a table, or an object of I whose field holds the
  pointer.
- Claims from H (declared): every typed access `p->f` / `p[i].f` in our sources gives (record of p, offset of f, type of
  f), the record found from where p comes from (a global, a field of a known record, a list link, an allocator's
  result).
- Claims from I (derived): the original's accesses `[reg + disp]` with their widths (`mov ax, word ptr [eax+0x12]`),
  through the matched alignment, where the register's record is known.
- Findings:
  - contradiction: two struct types of H claimed for one record (the stock list read as D3BGF in one unit and as
    D3OPS in another), or a field type of H against the width the original's access shows;
  - the remedy names the record, both types, and the fields they agree and disagree on.
- Where it fits in `store::Question` and its support levels: model-decisions item 3 (with the signature claims).

## Model

- §2: the type of an object is a question; types are partly observable (a width the bytes show, a layout the
  accesses fix).
- §8.8: the consistency convention: the original had one declaration per object, so one record type per record.
- §10: the step from "types are no claims" to "types are questions".

## Reports

- found by the C.name.alias cleanup of gildegold: the struct merges the agents left open (D3OPS / D3IOSTOCK /
  D3MESHSRC against D3BGF; the four terrain types)
