# Tie-break probes inside the declaration set, not only before it

- **Priority:** P0 (header changes interrupt the typing work) · **Size:** M

## Problem

- The probe (tiebreak.rs, `dcp headers probe`) puts unused typedefs before the unit's text. On gildegold
  (2026-11-04) that catches ai_TutorialInitChapter2 (shape, byte under three typedefs) and ai_TutorialInitChapter3,
  but not d3_CloneObject (any change to d3_fl.h or d3.h's D3PARTSYS) nor ai_Unk483a60 (two independent member
  splits of AIJOB swap two stack slots). Their bytes stay the same under every typedef before the unit.
- Their tie-breaks follow the declarations' place in the set (a typedef after a header's guard, as in the first
  sighting) or a struct's member list, not the count before the unit. A fall of theirs after a header change still
  reads as an M1 fall and asks for a debt item.

## Task

- More probe positions: the typedefs after each header guard of the unit's include closure (cause.rs's chain gives
  the headers), and one after the unit's last include. One compile each; the number of headers bounds the cost, so
  probe the headers of the closure that changed since the baseline first, and the rest only in the batch
  (`dcp headers probe UNIT --deep` or similar).
- A member-level probe: an unused member split (`char a[N]` -> `char a[k]; char b[N-k]`) of each struct the unit
  uses, layout unchanged. Ask first whether it is one: VC6 numbers the members, not the bytes.
- The witness names each probe by its place (`after include/ai_types.h`), so M1's line says where the tie-break
  lives.
- First check: d3_CloneObject and ai_Unk483a60 sensitive, and the probes leave the d3_engine functions that stay
  the same alone.
