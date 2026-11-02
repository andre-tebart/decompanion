# `dcp check`: compare a moved datum's initializer bytes with the image

- **Source:** match-base session 2026-11-01 (gildegold), worker 14
- **Area:** `dcp check` (D rules)
- **Problem:** a settle script anchored on the first `float sv_DayPhaseFrac`, an extern in the head, so `sv_PickX/Y` landed in the head region with initial value 0 instead of the gap's 0xff x 4. `dcp check` did not catch the changed initializer; the worker caught it by hand.
- **Proposal:** a D rule comparing each defined datum's initializer bytes with the original image (at least for data moved out of a gap block).
- **Cost of not having it:** ~10 minutes plus a near-miss on wrong data.
- **Related:** data-settle-command.md
