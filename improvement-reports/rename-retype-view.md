# Renaming a `full_data_*` view should offer to retype it

- **Source:** match-base session 2026-11-02 (gildegold), worker 19
- **Area:** `dcp rename`, Q2/Q4
- **Problem:** `full_data_14414c8`, a txt_views.h view typed `unsigned char (*)[8]`, was renamed `txt_ChatConsoleSlider` but kept the gap type, though its only use reads an int; the worker retyped the macro by hand.
- **Proposal:** `dcp rename ... --type T` (or a note) for `full_data_*` views; Q2/Q4 flag a named view whose declared type differs from how it is read.
- **Cost of not having it:** small, easy to miss.
- **Related:** txt-views-index-spelling.md
