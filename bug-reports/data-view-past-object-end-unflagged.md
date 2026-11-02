# A data view reading one byte past a 1-byte object is not reported (d3d_ZEnabled over d3_MipSkip)

- **Source:** match-base session 2026-11-02 (gildegold), worker 18
- **Severity:** minor (unconfirmed whether a D7 finding exists)
- **What happened:** include/data_views.h defines `d3d_ZEnabled` as `(*(char *)((char *)&d3_MipSkip + 1))`, but `d3_MipSkip` is a 1-byte `unsigned char` in src/ts_texture.c, so the view reads past its container. The only finding seen was `dcp check --strict` warning `C.name.alias` on 0x63342c (`d3_MipSkip` / `d3d_TexShift`); the worker did not run `dcp data map` on d3_d3d / ts_texture. In code, VC6 emits `mov ax, word ptr [d3_MipSkip]; test ah, ah` where the original has `mov al, byte ptr [0x63342d]`, so sv_OpenBook misses shape and was escalated though its own code can't fix it.
- **Expected:** a D rule (or view lint) flags views whose offset lies outside the base object's size.
- **Repro:** `uv run dcp check --strict`, `uv run dcp data map ts_texture` (gildegold 92add7d); `uv run dcp asmdiff sv_OpenBook`.
- **Impact:** ~10 minutes tracing, plus one unfixable escalation.
- **Related:** ../improvement-reports/escalate-blocked-by-data.md
