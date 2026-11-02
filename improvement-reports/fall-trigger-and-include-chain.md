# Explain a grade fall: include chain, triggering headers, and a tie-break probe

- **Source:** match-base session 2026-11-01 (gildegold), worker 13
- **Area:** `dcp check` (M1), `dcp accept`, new commands
- **Problem:** after an ai.h change (AIBLD/AIJOB pad splits, gildegold ba38c66), `d3_CloneObject` (d3_engine) fell byte -> shape. grep found no `#include "ai.h"` in d3_engine.c's chain, yet the unit recompiles on ai.h edits. The worker bisected by hand (revert sv.h, ai.h, each struct hunk), then proved a declaration-set tie-break: an unused `typedef int AIDUMMYX;` at line 30 of HEAD's ai.h drops it to draft. Only then could it `dcp accept`.
- **Proposal:**
  - `dcp unit includes UNIT`: the header chain (how ai.h reaches d3_engine.c);
  - M1 lines name the changed headers that rebuilt the unit;
  - optional `dcp fall-probe FN`: compile the unit at HEAD with one unrelated dummy declaration to test the tie-break hypothesis, which is exactly the evidence `dcp accept` asks for.
- **Cost of not having it:** ~12 tool calls, 15 minutes; the largest time sink of the session.

## Also seen (match-base session 2026-11-02 (gildegold), worker 15)
- Adding the `d3sm_Pick` prototype to include/d3_sm.h flipped `d3_CloneObject` (d3_engine, which never calls it) byte -> shape again: 4 swapped instructions wherever the prototype goes; accepted as debt item 40. Found only via `dcp check` after a full build, then bisected by hand (~8 minutes, three builds). Proposal addition: `dcp headers trial include/x.h` recompiling every includer and listing falls before committing.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 27)
- Moving a typedef between headers (`CRIME` from cm.h to cm_types.h so gv.h can use it) was a Python edit plus `dcp check`. Proposal: `dcp headers move-type CRIME include/cm_types.h --trial` listing includers whose declaration set changes and any grade falls.

## Also seen (match-base session 2026-11-02 (gildegold), worker 38)
- `d3_CloneObject` fell byte -> shape again when `AIBTYPE` got `maxLevel` (recorded with `dcp debt add`), then returned to byte after a later ai.h edit (study message view). `dcp session wrap` promoted it silently; `dcp debt list` no longer showed it and the wrap report didn't mention it (net change zero). Proposal: a wrap line `debt resolved: d3_CloneObject shape -> byte (witness ...)`. Cost: ~2 minutes.
