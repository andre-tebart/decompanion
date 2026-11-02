# `dcp refs FUNC`: default output too large (every callee, datum and string)

- **Source:** match-base session 2026-11-02 (gildegold), worker 49
- **Area:** `dcp refs` (output size)
- **Problem:** `dcp refs ai_CannonBuildPanel` printed ~95 lines; the worker needed only the one caller and where the function is declared in the source.
- **Proposal:** default to the definition, callers and source declarations; put the outgoing `ref_from` list (callees, data, strings) behind `--from`.
- **Cost of not having it:** context only.
- **Related:** refs-decl-sources.md

## Also seen (match-base session 2026-11-02 (gildegold), worker 50)
- ~8-15 lines per `dcp refs NAME`, with claim lines (`named=`, `start=`, `analyzer=`, `support=`) before the refs; grepped every time for `ref_to=call` and source lines. Want refs and source lines first, claim lines behind `--claims` (`dcp why` already covers them).

## Also seen (match-base session 2026-11-02 (gildegold), worker 51)
- `dcp refs d2_Objs` printed hundreds of lines, one `named=` per declaration site, many from one file (unk_5d33b0.c lines 75..104); cut to the first 15. Needed: definition and type. Want the definition line, per-file declaration counts (`unk_5d33b0.c x12`), full list with `--all`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 52)
- The worker avoided `dcp refs ai_Unk5eb780` (486 refs) and used `grep -c ref_to`. Want a default summary (`refs_to=486 in 37 functions / 12 units`), `--all` for the list.

## Also suggested (match-base session 2026-11-02 (gildegold), worker 53)
- `dcp refs NAME --callers`: one line per call site with the calling function's name (the worker grepped `ref_to` lines every time).

## Also seen (match-base session 2026-11-02 (gildegold), worker 55)
- `dcp refs ai_Unk5890c0`: ~50 lines, 43 of them `ref_from` calls; needed callers and source lines. Want `--to` / `--callers`, or `ref_from` collapsed into one line of callees with counts.

## Also seen (match-base session 2026-11-02 (gildegold), worker 56)
- 15-25 lines (`named=`/`start=`/`analyzer=` claims, every `ref_from` callee and operand). Want `--callers` (`ref_to` + source lines only) or claims behind `-v`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 57)
- ~30 lines for a function with 29 `ref_from` entries; wanted callers and source declaration sites (`--callers`, or ref_to/source first).

## Also seen (match-base session 2026-11-02 (gildegold), worker 58)
- ~30 lines including full source lines of every textual mention: ch.c's `@deep` comment (~2 KB on one line) because it mentions 0x4fbb80; 0x4fbe90's address comment lines ~900 characters each. Want comment-only matches truncated to ~120 characters or counted ("+3 comment mentions"), `ref_from` behind a flag.

## Also seen (match-base session 2026-11-02 (gildegold), worker 59)
- ~60 `ref_from` lines for unk_Unk4fd120. Want callers and declarations by default, callees behind `--from` or as `refs_from=54`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 60)
- 10-20 lines, mostly `start=` / `named=` / `support=` claims; grepped `ref_to=call` / `fn_name=` every time. Want `--callers`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 61)
- Every source line in full, including 1-3 KB address comments, repeated per hit: ~5 KB for gm_Unk4ff8c0 (the same 600-character comments twice), hst.c's whole @deep paragraph for ai_Unk4c56d0. Want lines truncated to ~160 characters and comment lines folded into `comment-mention at file:line`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 64)
- The lead-comment line plus 4-6 `start=`/`named=` claim lines; needed definition, declarations, callers (`ref_to=call`). Claims behind `--claims`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 65) - worst offender this session
- 15-40 lines, many wrapped address comments of 5-12 lines: `dcp refs ai_Unk5fb5b0` printed six long `@deep` comments from anm.c; `dcp refs ai_ProdSetting` the whole 0x501580 comment; `dcp refs gm_ListBuildingsOfType` the full 0x5020e0 comment. Want `file:line  kind  first 80 chars`, full comments behind an option.

## Also seen (match-base session 2026-11-02 (gildegold), worker 67)
- `dcp refs ai_Chars` lists dozens of `named=... by=src:include/x.h:N` declarations before any use; cut with `Select-Object -First 8`. Want a summary head: `definition=... type=char[768][0x21c] declarations=23 views=ORD_CHARS(gv.h),...`, `--all` for the list.
