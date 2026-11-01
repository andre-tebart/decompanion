# Point out a similar sibling function in `dcp next` / `dcp grade`

- **Source:** match-base session 2026-11-01 (gildegold), worker 4
- **Area:** dcp next / dcp grade
- **Problem:** txt_Format is a near copy of io_PrintText (0x515960, already deep). Rebuilding it from io_PrintText's C was the key step, but only an old lead comment said so.
- **Proposal:** note when a function's instruction profile or string/callee set closely matches a function at shape or deep, e.g. "similar: io_PrintText 0x515960, 92% callee/literal overlap". Related: twin-functions-together.md
- **Cost of not having it:** about 10 minutes of comparing disassembly by hand.
