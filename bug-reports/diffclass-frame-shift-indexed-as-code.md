# diffclass counts a frame shift in base+index*scale+disp addressing as `code`, not `frame`

- **Source:** match-base session 2026-11-02 (gildegold), worker 15
- **Severity:** minor
- **What happened:** with a frame of 0x21c vs the original's 0x218 in sv_RunLocationScripts, `dcp diffclass` showed `frame 114, code 12`. The 12 `code` lines were `mov dword ptr [esp + eax*4 + 0x10c], 0` vs `[esp + eax*4 + 0x108]` (and the same on `esi*4`): the same 4-byte shift in indexed form. asmdiff marks them `-`/`+`, not `~`.
- **Expected:** apply the frame-offset normalisation to esp/ebp-based indexed operands too.
- **Repro:** at gildegold b6266a3^, give sv_RunLocationScripts `char name[0x60]` with two `VFSDIR *` outs (`found`, `found0`), then `uv run dcp diffclass sv_RunLocationScripts`.
- **Impact:** small here, but with a lasting frame difference these lines count as unexplained code and can block shape or mislead an escalation.

## Also seen (match-base session 2026-11-02 (gildegold), worker 39)
- ai_PickBuildSite (0x4a4e70), frames 0x470 vs 0x478: plain `[esp+0x10]` aligned as `frame`, but `mov eax, dword ptr [esp + esi*4 + 0x80]` vs `[esp + esi*4 + 0x88]` is `code`: six `code 2` hunks at 0x4a4f37, 0x4a4fc0, 0x4a502a, 0x4a50b3, 0x4a50f3, 0x4a5129. Repro: `uv run dcp diffclass ai_PickBuildSite` (gildegold 3be9fb1). Cost: ~5 minutes; inflates the escalation code count.

## Also seen (match-base session 2026-11-02 (gildegold), worker 49)
- ai_CabinetSpyOnCharacter: `mov eax, [esp + ebx*4 + 0x38]` vs the original's `+0x34` (local array cost[] placed 4 bytes higher) classed `code` while the surrounding plain accesses were `slots`. Kept the function at draft and cost one extra escalation (later reached shape by block-scoping the pick variable).
