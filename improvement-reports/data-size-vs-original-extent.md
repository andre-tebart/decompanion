# Check a data declaration's size against the extent the original's code proves

- **Source:** play debugging session 2026-11-01 (gildegold), two of three crashes
- **Area:** dcp check (D1, L15; native/dcp_core/src/rules.rs `d_data`, layout.rs)
- **Problem:** a global declared smaller than the original uses it links cleanly and passes the gate, then
  corrupts its neighbours at run time. D1 compares only our compiled object with the next symbol's address
  (`least_size` comes from our COFF symbol), and L15 checks only that a view's address is the container's
  plus the offset. Neither asks how many bytes the *original* touches. Two crashes came from this:
  - `ai_Unk76f920` (0x76f920, the save header) was `int ai_Unk76f920[1]`. The original's
    `ls_ReadSaveHeader` (0x51cee0) writes up to +0xfc (its `ls_Read` calls take `[ebx+0x9c]`, size 0x60).
    In our link that overwrote about 30 unrelated globals (`sv_FrameDepth`, `sv_FrameBase`, `sv_ViewRect*`, ...).
    The header's fields +4 / +0x70 / +0x74 / +0x98 / +0x9c had been drafted as five separate globals, two of
    them in another unit (`full_data_76f990` / `full_data_76f994` in main.c). D1 fired only after the fix
    enlarged the object ("249 bytes at least overlaps the symbol at 0x76f990"), never against the bug itself.
  - `d2_ShpLightTable` (0x6f0460) was a view `(char *)&d2_ClipTop + 4`, but `d2_ClipTop` is a 4-byte `int`,
    so the view pointed at whatever the linker put next (`d2_PaletteDepth`). L15 accepted it: the address is
    right, but the view lies wholly outside its container.
- **Proposal:**
  1. L15: error when a view's offset + size exceeds its container's declared size ("view d2_ShpLightTable
     +4..+8 lies outside d2_ClipTop (4 bytes)"). Cheap: both sizes are already known to the source scan.
  2. A new D rule: for each data symbol, the proven extent from the original's refs — the highest
     `operand` offset + size, plus `immediate` address refs whose base register is then indexed
     (`lea ecx,[ebx+0x9c]`) and, where recognizable, the size argument passed to a known reader/copier
     (`ls_Read`, `vfs_fread`, `memcpy`, `memset`). Error when the declaration is smaller than that extent,
     and name the other declared symbols inside the extent as candidate views.
- **Repro:** gildegold commit 258ff9e: `include/ls.h` (`ai_Unk76f920[1]`), `include/data_views.h`
  (`d2_ShpLightTable` on `d2_ClipTop`); `dcp check` passes; `dcp run play`, hover a main-menu item (crash
  in `d2_ShpBlit16ClipY`, `eax = 1`).
- **Cost of not having it:** two run-time crashes, each found only by reading a minidump and the link map;
  the second hid behind a third bug (ai-updatestart, see `address-vs-value-hunk-class.md`).
  Related: `runtime-data-guards-debug-variant.md`.
