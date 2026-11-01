# A view of a datum's or parameter's users by offset and type

- **Source:** match-base session 2026-11-01 (gildegold), worker 2
- **Area:** dcp refs / typing
- **Problem:** overlapping view types keep coming up. The original stores ints into a `float *out` record. A struct layout for one function ripples through the other users and their byte matches, so the worker fell back to `((int *)out)[7]`. Q4 does not flag this, though it is no truer than the old raw access.
- **Proposal:** a `dcp refs`-style view listing the users of a datum or parameter by offset and access type, to decide whether a typed record is affordable.
- **Cost of not having it:** judgement calls on two functions.

## Also seen (match-base session 2026-11-01 (gildegold), worker 1)
- Typing `D3OBJECT.pad200` as `owner` broke `src/ch.c` (`D3OBJ_UNK200` macro in `include/ch.h`) and `src/d3_interface.c` (`*(int *)obj->pad200`), found only through build errors. Wants `dcp refs STRUCT.field` listing every use of a member, pads included, before retyping. Change is in gildegold 52c6fec. Cost: about 3 minutes and one failed 24-unit build.
