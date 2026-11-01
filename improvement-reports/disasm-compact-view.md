# A compact `dcp disasm` view

- **Source:** match-base session 2026-11-01 (gildegold)
- **Area:** dcp disasm
- **Problem:** raw bytes take up a wide column, so the worker cut columns with `cut` to read functions of 300–700 instructions.
- **Proposal:** `--no-bytes` / `--compact`, and perhaps `--range +0x200..+0x400` to show only part of a function.
- **Cost of not having it:** small each time, but it came up on every large function.

## Also seen (match-base session 2026-11-01 (gildegold), worker 3)
- Again stripped the hex bytes with sed every time. In addition to `--no-bytes` and `--range LO..HI`: an option to compress inline strcpy/strlen loops (`repne scasb` and the like) into one line, which would roughly halve big functions like `io_CharacterName`.
