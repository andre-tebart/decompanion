# Lint: flag `&sym + large_offset` that lands outside every object as a likely immediate

- **Source:** match-base session 2026-11-01 (gildegold), worker 7
- **Area:** lint / Q3
- **Problem:** earlier drafts held `flags = ((unsigned)&cm_SendRing + 0x4973c2) - ...` and `((unsigned)&cm_SendRing + 0x4973c0)`: really the immediates 0xf00502 and 0xf00500, misread as a relocated symbol plus offset. Q3 flagged them, but only as a bare address, so the worker had to read the disassembly to see they were plain constants.
- **Proposal:** a lint/Q3 note for `&sym + offset` whose sum falls outside every known object: "likely an immediate 0x...".
- **Repro:** ai_DecidePartnerOtherSex / unk_4a7140 drafts before gildegold 37b970e.
- **Cost of not having it:** about 5 minutes.
- **Related:** address-vs-value-hunk-class.md, ../bug-reports/asmdiff-symbols-image-base-immediate.md

## Also seen (match-base session 2026-11-01 (gildegold), worker 8)
- 0x4a91a0 (ai_DecideSuitor): `((unsigned)&cm_SendRing + 0x1982ca)` was the flags constant 0xc0140a; `asmdiff --symbols` showed `mov edx, cm_SendRing+0x1982ca`. Proposal: A1 / Q3 flag `&sym + offset` landing outside the symbol's extent (fake relocation), not only literal casts.
- Still present at gildegold 7ae5254: unk_58bbd0.c:18979 (`+ 0x19c2ca`) and `flags = ((unsigned)&cm_SendRing + 0x4973c0)` in am.c and unk_4a7140.c.

## Also seen (match-base session 2026-11-02 (gildegold), worker 30)
- Two more in am.c (ai_DecideUseAlchemyItems, ai_DecideGraveyardOwner0): `(unsigned)&cm_SendRing + 0x4973c0` = 0xf00500, relocated in ours, absolute in the original; asmdiff showed equal (see ../bug-reports/asmdiff-reloc-vs-immediate-equal.md). A third copy near src/am.c:5442 was already a plain constant. The worker wrote the mask as `(0xf << 20) | (5 << 8)` to get past Q3 (see ../bug-reports/grade-q3-flag-constant-as-address.md).

## Also seen (match-base session 2026-11-02 (gildegold), worker 35)
- The root of the hack: `dcp why 0xf00500` lists the partner-flag bitmask 0xf00500 as a site-reproduced reference into `cm_SendRing` (refs to=5), though ai_PickPartnerChain tests it bit by bit. These false refs in `why`/`refs` and the data-site evidence are what led an earlier session to write `(unsigned)&cm_SendRing + 0x4973c0`. The worker added `AI_CHAIN_USEREPUTATION` / `AI_CHAIN_MEAN` defines. Cost: ~3 minutes.

## Also seen (match-base session 2026-11-02 (gildegold), worker 37)
- ai_DecideTakeCredit: building-kind mask 0x7d4390 written as `&ai_Unk770d8c + 0x63604` (now `AI_CREDIT_KINDS`). Another remains at src/am.c:4658 (`(unsigned)&ai_Unk770d8c + 0x53628`), probably more; a repo-wide scan would be worthwhile.

## Also seen (match-base session 2026-11-02 (gildegold), worker 53)
- Draft of 0x586610 wrote the flag 0x800000 as `((unsigned)&ai_Relations + 0x1aca0)` and ai_GraveNames as `(unsigned)&sv_PhaseMinutes + 0x218`. Want a draft lint for `&sym + off` landing inside another known symbol or past `sym`'s end (D7-like on drafts). Also: the 0x5871c0 address comment said GRAB_MIETEN, but the dispatcher calls it for LIEGEPLAN (draft comment claims unchecked). Cost: one disasm read each.

## Also seen (match-base session 2026-11-02 (gildegold), worker 58)
- The same 0x800000 mask again, this time in f3gm's draft of 0x4fbe90: hidden as `(unsigned)&ai_Relations + 0x1aca0`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 68)
- Draft of 0x505230 had `w & ((unsigned)&he_Events + 0x54c0)` for `test eax, 0x700000` (fixed in f3gm). Still present at gildegold 7193051: `grep -rn "&he_Events + 0x54c0" src` finds 3 in src/he.c and src/unk_58bbd0.c. Proposal addition: treat immediates used as AND/TEST/XOR operands with a contiguous bit run as masks before symbolizing; lint `&sym + off` as an operand of `&`.
