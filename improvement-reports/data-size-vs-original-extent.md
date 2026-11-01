# Check a data declaration's size against the extent the original's code proves: what is left

- **Source:** play debugging session 2026-11-01 (gildegold), two of three crashes
- **Done:** D7 (a view past its container's object size), S.extent (the ranges the original's code proves one
  object: field accesses through a register, loop bounds, block copies, addresses passed to functions whose
  summary reaches through that argument, seeded by the library's copiers and `writes ptr=aK size=EXPR`
  declarations) and D8 (a declaration smaller than such an object, or several declarations sharing one; a warning
  when they are pieces of one unit that tile it). On gildegold 1d4b4f6 with `0x430bd0 writes ptr=a0 size=a1*a2`
  (vfs_fread) declared, S.extent proves the save header 0x76f920..0x76fa1c (through ls_ReadSaveHeader and
  ls_Read), the clock 0x75e130..0x75e13e (gm_AddTime) and the record table 0x60c7c0..0x60cb00 (the scan's last
  record). By D8's criterion the declarations of those crashes were errors: a 4-byte int whose fields were drafted
  in another unit, a 4-byte int with the other fields in ls.c, and 748 bytes followed by undeclared bytes. This was
  not rerun on the old commits. `d2_ShpLightTable` on the 4-byte `d2_ClipTop` is D7.
- **Open:**
  1. S.extent reads the functions S.codewalk walked. A function only a pointer reaches (on gildegold more than
     half of them) proves nothing until the walk reaches it. Reading L.src.extent's functions too would make
     S.extent depend on the sources and rerun on every build (~250 ms), so it was left out. One way: a second rule
     that reads only the unwalked sourced functions, with the walked ones' summaries from S.extent as its seeds.
  2. The adjacency variant (gildegold 7181939): source that uses symbol B's address as A's end
     (`INIT_CHARACTERS_END` was `&gm_PlayerRecords`, the original's one-past-the-end of `ai_Chars`). D8 sees the
     original's loop stop at 0x7d5f80, which `ai_Chars` holds. But our source's bound is another symbol whose place
     only the link decides. Proposal as before: when a source expression bounds a walk over A by `&B` and the
     original's A + size(A) == B, check that the link keeps B right after A, or flag it and suggest `A + size`.
     The `one-past-end-address-named-after-next-symbol.md` report is the naming side of the same problem.
