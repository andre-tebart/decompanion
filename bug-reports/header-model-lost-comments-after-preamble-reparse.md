# A header's comments vanished from the scan when its first includer was reparsed — FIXED

- **Source:** gildegold include driver, 2026-11-01 (on top of 399f0a8)
- **Severity:** major (Q6 of functions in unrelated units changed with another unit's includes)
- **What happened:** after `#include "err.h"` was added to src/cm.c (line 53) and `dcp build` ran, reg_OpenKey
  (0x4103a0, unit di_input) fell to readability=draft on Q6. Its description is in its owner header
  include/di_input.h:43. The same happened to reg_GetString and others, to surf_* when d3_d3d gained includes, and
  to amt_ClearOffices* when am gained d3_tools.h.
- **Root cause:** the scan takes a header's model (comments, literals) from the first unit, in file order, that
  includes it. cm is the first includer of di_input.h, d3_quad.h and unk_5d33b0_types.h. After the edit, the live
  libclang unit of cm was reparsed over its precompiled preamble (`with_parse`, the speed path for lint), and
  `clang_tokenize` returns no tokens for headers held in the preamble. The model of those headers had 0 comments,
  so Q6 lost the owner header's description. That model was also written to build/cache/cparse. 399f0a8 made this
  visible: before it, Q6 also counted copies of the comment in other units.
- **Fix:** `parse_model` takes a model only from a whole parse (`with_parse_as(.., whole)`). A live unit that was
  reparsed over its preamble, or would need to be, is parsed again from scratch. Lint's diagnostics still reuse
  the live unit. MODEL_VERSION 21 drops the cached models from such reparses.
- **Cost:** a model of an edited unit is a whole parse (gildegold cm: about 0.5 s) instead of a preamble reparse.
- **Test:** `frontend::tests::a_model_comes_from_a_whole_parse` (Rust). A small tree did not reproduce libclang's
  empty tokenization, so the test checks that a model never uses a unit reparsed over its preamble. Verified on
  gildegold: with cm.c + err.h, reg_OpenKey stays readable; surf_Down32 with d3_d3d + err.h too.
