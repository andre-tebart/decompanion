# Suggest names from `<identifier>():` strings used inside a function

- **Source:** match-base session 2026-11-02 (gildegold), worker 30
- **Area:** `dcp grade` (Q1) / `dcp refs`
- **Problem:** 0x4a5320's own error text `"amt_ExecGebaeudeBauen(): Keine Group ..."` gives its original name; the worker found it only by reading the C.
- **Proposal:** list strings of the form `<identifier>():` used in the function as candidate names, flagging a unit prefix that differs from the file (`amt_` in am.c).
- **Repro:** `uv run dcp grade ai_ExecBuildBuilding` (0x4a5320) at gildegold 5039a27.
- **Cost of not having it:** none this time; easy to miss.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 34)
- Registration records: for ~7 of 8 functions the name evidence came from grepping am.c for `act.decide = NAME` / `act.exec = NAME` and the `strcpy(act.name, "...")` two lines above (registered at 0x4a16f0). Proposal: grade/refs show `registered: act.id=0x11 name="Wohnsitz bauen" role=decide` when a function is stored into a record next to a string literal. Cost: ~8 greps.
