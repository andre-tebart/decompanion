# Gap blocks inside a defined object's extent go unflagged

- **Source:** match-base session 2026-11-02 (gildegold), worker 51
- **Severity:** minor
- **What happened:** `full_data_144a620`, `full_data_144a624`, `full_data_144a638`, `full_data_144a63c` and `full_data_144a40c` are separate gap symbols inside txt_Ptrs (0x143a1c0..0x144c1b9). asmdiff marks them `=` (alias) against `txt_Ptrs+0x...`, and no check reports the overlap.
- **Expected:** a check flags a gap block that overlaps a defined object and suggests the `txt_Ptrs[index]` spelling.
- **Repro:** `dcp refs 0x144a620` / `dcp why 0x144a620` at gildegold 6853071.
- **Impact:** ~3 minutes over 3 functions; stale aliases accumulate.
- **Related:** ../improvement-reports/txt-views-index-spelling.md, data-view-past-object-end-unflagged.md
