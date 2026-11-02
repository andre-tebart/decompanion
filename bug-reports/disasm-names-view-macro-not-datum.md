# `dcp disasm` names a view `#define` instead of the datum

- **Source:** match-base session 2026-11-02 (gildegold), worker 51
- **Severity:** minor
- **What happened:** 0x770ae0 is shown as `<NOWX>` (a view `#define` in am.h), not `ai_Time`. `asmdiff --symbols` then shows `ai_Time` against `NOWX`, which looks like two different objects at first glance.
- **Expected:** the datum's name first, views as aliases (e.g. `<ai_Time (NOWX)>`), and the same name on both asmdiff sides.
- **Repro:** `dcp disasm` of a function reading 0x770ae0 in unk_575860 at gildegold 6853071.
- **Impact:** small.

## Also seen (match-base session 2026-11-02 (gildegold), worker 55) - more labelling gaps
- `mov eax, [0x14673a0]` had no label though it is `dm_L.rup` (`dm_L` + 0x20, di_input.h): struct-member addresses inside a known object are not labelled.
- 0x1463590 shown as `<d3s_ShadowBits>` while dd_vesa.h names it `dd_Surface` (the needed name): alias choice looks arbitrary.
- txt_Ptrs slots shown as `full_data_1442334` / bare `0x1442368`; indices (`txt_Ptrs[0x205d]` etc.) computed by hand four times (see ../improvement-reports/txt-views-index-spelling.md).
- Cost: ~5 extra greps plus risk of picking the wrong name.

## Also seen (match-base session 2026-11-02 (gildegold), worker 57)
- 0x770ae0 still `<NOWX>` (sources/gv.h: `ai_TimeYear`, ai_Time's first int). 0x7d5f82 labelled `<gm_PlayerRecordBytes>` though it is the end of ai_Chars (ai_Chars+0x65402); asmdiff gets it right with `(or ai_Chars+...)`. Want the source name, or `sym+off` for a one-past-the-end loop bound. Related: asmdiff-symbols-array-minus-one-named-previous.md
