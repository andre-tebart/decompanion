# Point out a similar sibling function in `dcp next` / `dcp grade`

- **Source:** match-base session 2026-11-01 (gildegold), worker 4
- **Area:** dcp next / dcp grade
- **Problem:** txt_Format is a near copy of io_PrintText (0x515960, already deep). Rebuilding it from io_PrintText's C was the key step, but only an old lead comment said so.
- **Proposal:** note when a function's instruction profile or string/callee set closely matches a function at shape or deep, e.g. "similar: io_PrintText 0x515960, 92% callee/literal overlap". Related: twin-functions-together.md
- **Cost of not having it:** about 10 minutes of comparing disassembly by hand.

## Also seen (match-base session 2026-11-01 (gildegold), worker 9)
- ai_DecideVisitAction (0x4aa120) is ai_DecideLeisureAction (0x4a9a00) with a different table; ai_CheckVisitAction mirrors ai_CheckLeisureAction. The worker copied fixes across after recognising it. Proposal addition: once one of a pair is raised/escalated, `dcp next` / `grade` points to its commit so the twin starts from that fix. Related: twin-functions-together.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 35)
- Seven of eight functions were near-identical "UseObject" decide callbacks in am; once one was shape the same C skeleton (nested ifs ending in one `return 0`, `G9REC`, flags assigned per branch) fixed the next in one edit. A pointer from `dcp next` / `dcp grade` to an already-shape sibling with the same call sequence would have saved ~15 minutes.

## Also seen (match-base session 2026-11-02 (gildegold), worker 37)
- The fix taking 0x49def0 to byte (ternary order `lvl < 0x42 ? 30 : 10`, compare order, separate exit blocks, o2 store order) applied unchanged to 0x49e350. The same ternary appears 5 times in am.c (lines 7634, 8004, 9047 among them). Proposal addition: point out that a nearby function got this exact source change in a recent commit, so it can be carried over.
