# diffclass counts a frame shift in base+index*scale+disp addressing as `code`, not `frame`

- **Source:** match-base session 2026-11-02 (gildegold), worker 15
- **Severity:** minor
- **What happened:** with a frame of 0x21c vs the original's 0x218 in sv_RunLocationScripts, `dcp diffclass` showed `frame 114, code 12`. The 12 `code` lines were `mov dword ptr [esp + eax*4 + 0x10c], 0` vs `[esp + eax*4 + 0x108]` (and the same on `esi*4`): the same 4-byte shift in indexed form. asmdiff marks them `-`/`+`, not `~`.
- **Expected:** apply the frame-offset normalisation to esp/ebp-based indexed operands too.
- **Repro:** at gildegold b6266a3^, give sv_RunLocationScripts `char name[0x60]` with two `VFSDIR *` outs (`found`, `found0`), then `uv run dcp diffclass sv_RunLocationScripts`.
- **Impact:** small here, but with a lasting frame difference these lines count as unexplained code and can block shape or mislead an escalation.
