# Triage of bug-reports/, improvement-reports/, peformance-reports/ (2026-11-03)

216 reports: 83 bugs, 133 improvements, 1 performance report, plus one untracked bug report. They were filed by match-base and
layout workers on gildegold. I checked each one against the code at e42b189. Many were filed against dcp builds older than
931a652, 02237fa, 1e1a783, 87cebdd, 2e3148d, e504789, 4a5fae6, e8ae4d7, 3b4d6a9 and 4dfe5f3/4aae6cc. Those reports are
marked fixed below.

Most of the requests are the same few problems, each seen from a different command. The reports ask for about
40 new flags, commands, classes and hints. Almost none of them should be built as asked. They point at about a dozen root
problems, and most of those are places where the code departs from docs/mental-model.md.

---

## Part 1: Root problems

### R1. The object experiment exists several times, and the copies disagree (§4)

The model has one object experiment per object. The code has several implementations of it, and each has its own
idea of which instruction corresponds to which:

| Where | Correspondence / verdict |
|---|---|
| `M.match`, B1 text (compare.rs:45) | positional masked compare |
| M8 `aligned_sites` (rules.rs:1298) | "same instruction at the same offset" |
| `FunctionCompare` (grade, asmdiff, diffclass, equiv) | difflib alignment and hunk classes |
| `compare_tables` (diffclass.rs:812) | its own plain-Equal map, any pair "in the same hunk" |
| header trial `trial_grades` (headers.rs:1083) | byte or `verdict.shape`, without the prover, literals or binding |
| `data fix` trial (datafix.rs:747) | byte only |
| "calls differ" | `asmcmd::unmatched_calls` vs `equiv::witness`, two call sets |

Every commit that sharpens the verdict (prover, literals, name binding) leaves the copies behind. The reports find the
places where they diverge:

- B1 says bytes differ where asmdiff shows `=`.
- The header trial reports false falls.
- M8 fails where grade says byte.
- "calls differ: the original none" appears where the original makes the call.

**Root fix:** one in-function correspondence (φ inside the function is the alignment, §1) and one verdict function.
Everything else reads them: grade, asmdiff, diffclass, escalate, the trials and the M8 findings view. The positional
compare stays only as the byte pass/fail criterion.

### R2. Fields are masked without checking where they point (§4, §8.3, §8.4)

§4 allows masking a relocated field's value only together with the check that the field points to φ(target). The
code masks everywhere and checks only in places:

- asmdiff compares `X` texts. The identity check runs only with `--symbols` (asmcmd.rs:349), and `differing=` ignores
  it.
- M8 runs only for byte-matched or DLL-aid functions (rules.rs:464, verified). Its result never reaches G.grade.
  Two swapped `v1a4`/`v1a0` loads therefore grade `byte`.
- `equiv::bind` *learns* a symbol's address from the original's aligned site and falls back to φ only for unbound
  symbols (equiv.rs:2299-2340). That is the reverse of §8.4.
- Library member placement groups by masked bytes and never resolves member relocations (crt.rs:107-208). That
  is how `fopen` and `_wfopen` get confused, and these claims sit at the **reproduced** level. By the model that is
  a rule bug.
- No containment check: `&cm_SendRing + 0x4973c0` is accepted as an "alias", and D7 measures against the COFF
  distance, padding included.
- Literals are checked only for shape and proved functions (grade.rs:155). Drafts hide them.

**Root fix:** one reference check inside the object experiment, run for every compiled function:

- For each of our relocations whose site lines up, compare the original's target with φ(our symbol).
  - Equal: reproduced.
  - Different: failing.
  - φ undefined: *open*, listed, never learned.
- Literals are the same check, with the bytes as the target.
- Containment: sym+addend lies inside sym's declared C size, else ill-formed.
- The CRT placement checks member targets the same way.

### R3. The alignment runs on exact texts, and branch targets are compared as offsets

- The difflib alignment keys still contain registers, slots and raw internal jump targets. Repeated blocks then pair
  one copy apart, and one inserted instruction makes every later branch "differ".
- Inside hunks, jumps are paired by identical text (`jX X`, diffclass.rs:431-443), which is arbitrary.
- `same_code` compares raw text when the order-hunk pairing misses.

That produces `je at +0x49: ours to +0x62, the original's to +0x62` and the 12-line shift noise. Both hold functions at
draft and send them to the deep queue.

**Root fix:**

- Align on normalized keys (registers and slots masked).
- Treat a jump target as a *cut point*, and map cut points through the alignment (by position in equal runs, by
  multiset prefix in order hunks, at hunk boundaries).
- Attribute jumps into a code hunk to that hunk.
- Switch tables per case go through the same cut correspondence.

### R4. Each reader re-derives "what owns this address" (§5 answer)

`answers.rs` holds the owner answer, but the read commands bypass it, each with its own filter:

- `walk_func` excludes `M.*`, so a byte-matched function loses its extent and disasm silently caps the listing at 0x400.
- `symbol_at` looks back at most 4 claims (rename kind, `label_of`).
- refs and why count references with different predicates (0 vs 13).
- The data extent falls back to **1 byte** when our object gives no size (rules.rs:707-711). That is a wrong owner
  answer for the other bytes, not just a display issue (`value=4c` for a pointer).
- φ ranks alphabetically within an origin (phi.rs:163-167, verified), so `NOWX` beats `ai_Time`.

**Root fix:**

- Every reader asks the answer table (owner at its highest support).
- Fix the extent fallback: type size, or contiguity up to the next owner.
- φ ranking: the definition first, then declarations, then views.

### R5. Findings are computed but not shown, and nothing reports what changed

- `dcp build` already lints changed units and stores M5/M6/D findings, but prints only compile errors and a grade
  histogram.
- `grade NAME` attaches only M7.
- Rename counts "N from before" without naming them.
- Only `dcp check` shows the gate, so workers learn it at commit time.
- Separately, every report-style command prints full state:
  - one `ok <unit>` line per unit (10 to 90 lines after a header edit);
  - the full histogram, which cannot show two moves that cancel out (that is all `build-grades-line-mismatch` is);
  - static link notes, legends, and 12 KB of repeated rename reasons in the wrap.

This is the single largest group (about 25 reports, 60+ sightings). Workers pipe everything through grep or tail.

**Root fix:** one output convention, not per-command flags:

- line 1 is the verdict record;
- then failing items;
- then **named changes since the previous run** (fell / raised / new error / gone error);
- full state behind `-v` or in the read commands (`grade`, `findings`, `why`);
- no legends, guidance in `-h`, repeats collapsed (`xN`), a shared reason printed once.

The store already re-records rule runs and writes only the facts that changed (store.rs:264-282), so the delta is a
diff of two runs' claims and findings. It needs no cache.

### R6. "Not observed" is treated as "failed", and consequences are not tied to their cause

- A unit that fails to compile turns all its functions into `draft` (rules.rs:186-193, verified). M1 then prints
  about 80 falls that bury the one `M.compile` cause.
- A broken address comment shows as M1 "its source is gone?".
- grade, diffclass and escalate say "neither a unit nor a graded function", although L.src, M.gen or M.compile already
  says why.

In the model, an experiment that cannot run is *open*, not a fall.

**Root fix:**

- An unbuilt function's experiment is *not run*.
- M1 skips functions whose premise is missing and emits one finding per unit.
- Not-found paths print the ill-formed or compile findings for the name or file.

### R7. Ill-formed H and φ are not enforced, and commands that write H can break φ (§5, §8.7)

- `C.name.alias` is filed as ill-formed but emitted at `warn` (setup.rs, verified). It covers only data address
  comments, so two of our names at one address pass the gate.
- `headers conflicts --write` inserts an include between an address comment and its definition (headers.rs:348-386).
  It can also add a header the unit already includes.
- A `src/*.c` file in which the scan finds no addressed function silently stops being a unit, and its `tu` row is
  deleted.
- One external name defined in two units is caught only at link.
- `placeholder_whole` treats a *spelling* of an address as φ (rename kind and names.log for cast macros).

**Root fix:**

- Every ill-formed id is error severity: the category sets a floor for severity.
- Every command that writes H validates the result with the scan rules (L.src, M.gen, φ) before writing, as rename
  already does.
- A source file that yields no unit is a finding.
- A spelling is not an address comment.

### R8. The consistency convention (§8.8) is checked only for errors

- clang runs with `-Wno-everything` plus two warnings (frontend.rs:26-28, verified). C89 int-conversion and
  pointer-type disagreements at uses are invisible. That covers `char *` for `AIBLD *`, an int for a pointer, a cast
  around a `void` prototype, and cast macros left after a prototype fix.
- Exceptions are text markers with no link to a symbol, so a stale `@original` (its cast now equals the declaration)
  cannot be detected.
- M7 is a `warn` in category contradiction. The model says warnings are outside it and only errors gate, so M7's
  status is undefined. The skill files it under readability while calling it "the experiment's side".

**Root fix:**

- The type-agreement diagnostics are consistency findings at their site.
- An unmarked function-type cast is an inconsistent use.
- An exception whose cast equals the declaration is stale.
- M5/M6/M7 are all attached to the function in grade.
- **A model decision is needed on M7's severity** (see Part 4).

### R9. A witness can point to a commit that does not exist (§8.6)

`session wrap` and `promote` do not check for a dirty tree, although `session start` does (commands.rs:686 vs
719-740). The ledger then records a witness (H, φ) that is in no commit.

### R10. The prover is the general mechanism, but its stop reason is mislabelled

- About 20 reports each ask for one more diffclass class (rotation, slot permutation, ivbias, induction base, moved
  block, shrink-wrap, sched+copy, tail, commute, ...). They are all "same dataflow, other allocation or schedule".
- Since 3b4d6a9 the prover decides shape, and most of the named functions now grade shape.
- The remaining drafts stop in the prover. Its `_ =>` arm prints "a store against a call" for Escape, Fill and Copy
  differences (equiv.rs:2099, verified), so workers look for a moved store that does not exist. The skill calls this
  line "the first place to read".

**Root fix:**

- Freeze the class set: it stays a fast path and a navigation view.
- Name the real effect pair in the stop reason.
- Rank prover coverage by a stop-reason tally over the corpus.

### R11. No primitive for "try H′ without changing H"

The two most frequent requests across all slices:

- variant trials (about 22 sightings, "the largest cost of the session");
- scoped function edits (about 14 sightings, about 8 builds broken or files corrupted by hand splicing and heredocs).

Trial compile-and-grade exists twice already (headers, datafix).

**Root fix:** one `trial(unit_text) -> verdicts` (R1's verdict) and one scoped write of a function's `at=` span. The
header trial, `data fix` and the exception discrimination check (§8.8 / §10 open item) all use the same trial.

### R12. The skills drift from the tool and the model

- gildegold runs an older copy in `.claude/skills/`, and nothing detects it.
- skills/dcp-match-base/SKILL.md contradicts itself:
  - :96 "grade does not read the proof", stale since 3b4d6a9;
  - :255 calls the explained classes unexplained;
  - :270 "stale @deep at shape" disagrees with M2's byte+readable;
  - :140-142 claims a pointer walk where `jl` against an address means a signed int index loop.
- The skill uses commits as the session counter, which forces odd commit splits and `--allow-empty`.

Several skill rules exist only to work around tool behaviour (run check before committing, avoid confusion from quiet
builds). Those go away with R5.

### R13. The reports do not say which dcp binary they ran

Many residuals could not be dated, and some sessions ran `uv run dcp`. The report template should include the dcp
commit.

---

## Part 2: Tasks

Priority: **P0** = wrong answer or misleading verdict, broken H or φ, a witness lie. **P1** = frequent workflow cost.
**P2** = nice to have. Size: S / M / L.

### P0

| # | Task | Root | Size | Resolves |
|---|---|---|---|---|
| 1 | **One reference check in the object experiment.** For every compiled function, each aligned relocation's original target is compared with φ(symbol); a literal by its bytes. Mismatch: failing (draft). φ undefined: open and listed. `bind` checks against φ instead of learning. Grade, asmdiff (default view, counted in the header), diffclass and escalate read it, and M8.reloc becomes its findings view. | R2, R1 | M | grade-byte-misses-swapped-relocations, grade-m9-hidden-while-other-hunks, asmdiff-reloc-vs-immediate-equal, asmdiff-symbols-float-constant-value-missing (residual), txt-views-index-spelling (worker 53), lint-string-literal-bytes-vs-original, const-datum-vs-literal-hint |
| 2 | **Containment.** An H reference or view at sym+off outside sym's declared C size (sizeof from the front end, not the COFF distance) is ill-formed. A near-certain ref of I into bytes H calls padding or room is an owner contradiction. Also check `site_confirmed`, so that an *immediate* equal to a relocated field is not counted as reference evidence. | R2 | M | asmdiff-reloc-vs-immediate-equal (part 2), lint-symbol-plus-offset-immediate, data-view-past-object-end-unflagged, data-map-undeclared-refs-in-room, data-size-vs-original-extent |
| 3 | **Library placement checks member targets.** Split groups with equal masked bytes by their resolved targets; let short members be confirmed by their targets; leave φ open when members stay indistinguishable. | R2 | M | asmdiff-symbols-wrong-library-callee |
| 4 | **Branch targets as cut points through the alignment.** Pair jumps only via the alignment; cut correspondence in equal runs, order hunks and hunk boundaries; jumps into code hunks are grouped under the hunk; a real difference names both target instructions. | R3 | M | grade-branch-targets-differ-same-target, grade-branch-shift-noise, diffclass-branch-target-equal-offsets-reported-different (untracked) |
| 5 | **Prover stop reasons name the real effect pair** (Escape, Fill and Copy cases; source terms; "escaped frame laid out otherwise"). | R10 | S | explains most still-draft functions in the diffclass-* reports |
| 6 | **One call-set comparison**, counts on both sides, tail `jmp` included, shared by asmdiff and `equiv::witness`. | R1 | S | diffclass-calls-differ-misses-original-call, asmdiff-calls-differ-none-wording |
| 7 | **Data extent fallback.** Use our type size or contiguity, never 1 byte (rules.rs:707-711). The `why` value line no longer depends on the owner run. | R4 | S-M | why-named-data-no-float-value |
| 8 | **An unbuilt function is "not run" (open).** M1 emits one finding per failed unit; drop the `FAILED units=` patch line. | R6 | M | check-compile-failure-floods-m1, build-unit-silently-dropped (M1 part) |
| 9 | **Ill-formed means error.** C.name.alias covers every name of H at one address (functions, extern-only, placeholder spellings) at error severity unless an alias is declared. Sweep every ill-formed id emitted at warn. Count the effect on gildegold first. | R7 | S-M | check-extern-only-alias-unflagged, rename-leaves-stale-macro-name, data-view-past-object-end (alias part) |
| 10 | **`headers conflicts --write` keeps φ well-formed.** Insert only in the head region; skip a header already included; before writing, run the scan and refuse on new L.src or M.gen. | R7 | S | headers-conflicts-write-splits-address-comment |
| 11 | **A `src/*.c` file that yields no unit is ill-formed.** Plan units from the file list; grade and fn say why the unit is missing. | R7 | S-M | build-unit-silently-dropped |
| 12 | **Wrap and promote refuse on a dirty src/include/decl** (reuse `session_dirty`). | R9 | S | session-wrap-accepts-uncommitted-source |
| 13 | **The header trial (and `data fix`) use G.grade's verdict.** Print `now=` and `baseline=`, and whether M1 would fire. Precursor to task 22. | R1 | S | headers-conflicts-trial-fall-against-current-grade |

### P1

| # | Task | Root | Size | Resolves |
|---|---|---|---|---|
| 14 | **Output convention** for build, check, session start, wrap, rename, headers conflicts and asmdiff: verdict line, failures, named delta since the previous run; per-unit `ok` lines, histograms, static notes and legends behind `-v` or `-h`; `xN` dedupe; a shared reason printed once. Write the convention in AGENTS.md so new commands follow it. | R5 | M-L | build-quiet-grade-summary (14 sightings), build-list-grade-changes, build-grades-line-mismatch, check-summary-line, check-guard-session-gains, check-m1-debt-label-before-debt-exists, session-start-output-too-large, session-report-readonly, wrap-rename-shared-reason-once (15), rename-summary-line-first (11), rename-report-comment-rewrites, headers-conflicts-output (9), grade-q4-remedy-text-repeated, grade-m9-line-repeated-per-use, asmdiff-changed-only, asmdiff-summary-flag, refs-default-output-too-large (12), diffclass-collapse-frame-shift-lines |
| 15 | **Show the findings that are already computed.** Build prints new and gone error findings (part of the delta in task 14). `grade NAME` lists the error findings in its span and attaches M5/M6 next to M7. Rename names its existing errors, not just a count. | R5, R8 | S | build-grade-miss-header-definition-mismatch, rename-from-before-counts-uncommitted-errors (7), rename-zero-errors-on-stale-objects, stale-local-prototype-flag, skill-m5-only-in-check, grade-m7-current-wording |
| 16 | **Not-found paths explain themselves**: grade, diffclass, escalate, asmdiff and fn print the L.src / M.gen / M.compile finding for the name or file. | R6 | S | grade-lost-address-comment-silent (6), grade-failed-build-says-unknown-name |
| 17 | **Freshness is visible.** A quiet build prints one stderr line when it compiled units; grade and build show a short hash of the function's compiled code and relocations; delete the dead `build/amalg`; hash the include files before the compile, not after. | R5 | S | build-freshness-unclear, build-header-edit-rebuilt-one-unit, grade-object-unchanged (5), dist-with-hunk-class-counts, skill-build-compiles-pending-edits |
| 18 | **Readers use the answer table.** disasm extent (and a stated guess, never the silent 0x400 cap), refs `fn=`, refs and why counts, `label_of`, the rename kind. Fix φ ranking (definition, then declaration, then view). | R4 | M | disasm-truncates-function-without-codewalk, refs-operand-sites-no-function, refs-misses-operand-refs-open-data, rename-kind-data-for-functions (about 20), asmdiff-ledger-name-vs-source-name, disasm-names-view-macro-not-datum, asmdiff-symbols-original-side-new-object-unresolved, asmdiff-symbols-array-minus-one-named-previous |
| 19 | **Alignment on normalized keys** (registers and slots masked, internal targets through the alignment); per-hunk renaming falls out. It changes distances and verdicts, so measure on gildegold. | R3 | L | asmdiff-misaligns-repeated-cases (residual), asmdiff-regs-auto (residual), asmdiff-segments-and-runs |
| 20 | **B1 evidence from the alignment**: bytes and instructions on both sides; in-place vs shifted; the first equal-text pair whose bytes differ; two distinct tail messages ("the original continues" vs "ours runs past the next start"). | R1 | M | grade-b1-first-offset-equal-in-asmdiff, grade-b1-shift-vs-in-place, grade-size-diff-locate, grade-b1-continues-after-end-confusing, grade-show-instruction-counts |
| 21 | **Escalate gates on the verdict, not on prose.** Refuse on a witness, branches (after task 4), literals (after task 1) or table entries; print the diffclass summary and the raw counts with the tail adjustment. Reason from a file. | R1 | S | escalate-refuse-branch-targets-differ (8), escalate-instruction-count-differs-from-asmdiff, escalate-list-forbidden-phrases, escalate-why-file, skill-shape-vs-escalate-guidance (tool part) |
| 22 | **Trial and scoped edit primitive.** `dcp fn NAME --replace FILE...` writes exactly the `at=` span; with `--trial`, nothing is written, and each FILE gets one line (experiment, dist, proof, witness). The header and datafix trials share it. | R11 | M | dcp-try-variants-in-memory (about 22), scoped-function-body-edit (about 14), skill-edit-scripts-not-heredocs (tool part), fn-context `--print`, headers-signature-dry-run, data-definition-form-trial |
| 23 | **Prover coverage**, ordered by the stop-reason tally (mutant control kept at zero). Candidates: escaped frame layout, affine induction variables plus sym+addend binding, x87 stack across blocks, disjoint-store commute, duplicated test or jump threading. The diffclass class set is frozen. | R10 | L (each M) | every diffclass-*-class and *-as-code report, prover-downcount-loop-vs-end-compare |
| 24 | **Consistency at uses (§8.8).** Enable `-Wint-conversion`, `-Wincompatible-pointer-types` and `-Wincompatible-function-pointer-types` as consistency findings with `@original`/`@vc6` exemptions; an unmarked function-type cast is an inconsistent use; an exception whose cast equals the declaration is stale (in `dcp exceptions`). | R8 | M | cast-hides-pointer-warnings, cast-views-on-prototype-change, lint-void-callee-result-used, lint-placeholder-cast-macros, rename-retype-view |
| 25 | **Exceptions must discriminate** (§10 open item): trial-build the unit without each `@original` (task 22) and flag the ones whose bytes do not change. | R8, R11 | M | detect-nested-call-in-arguments, skill-original-evidence-push-sequence |
| 26 | **The datum object experiment** (§4): equal or not at the declared address, masked; graded; visible to M1. | R1 | M | check-moved-datum-initializer-bytes |
| 27 | **Frame-slot annotation in disasm and asmdiff** (`{S-0x10}`, `{arg2}`, read-never-written, arguments pending across a call), from the prover's sp tracking. No new command. | | M | frame-slot-layout (about 12), uninitialized-frame-read-hint, diffclass-arg-slot-reuse-class (diagnosis) |
| 28 | **Meaning classes in diffclass**: `const` (only a non-address immediate differs) and `addrval` (address on one side, load on the other) as concrete differences, like the witness. | R2 | M | address-vs-value-hunk-class, asmdiff-index-scale-mismatch |
| 29 | **headers conflicts scope.** File-scope and K&R duplicates anywhere; the trial drops a superseded local declaration and grades. | | M | headers-conflicts-write-drops-one-duplicate, headers-conflicts-trial-silent-with-supersedes |
| 30 | **M1 names its cause candidates**: files of the unit's include set changed since the witness, with the include chain. This also answers "why did the grade change" in the wrap. | R5 | S-M | fall-trigger-and-include-chain (8), wrap-grade-change-cause |
| 31 | **Switch tables per case** through the cut correspondence of task 4. | R3 | M | grade-switch-tables-differ-raw-bytes, diffclass-switch-case-order |
| 32 | **Gap data through `data fix`**: split a GAPDATA block around a typed definition from any unit; drop unused `extern GAPDATA`; a gap block covered by a literal is a two-owner finding. | R7 | M-L | data-settle-command (7), data-literal-from-gap-block (7), data-struct-from-block-ops |
| 33 | **D-rule messages name their sizes** (type size, our object's slot and the symbol bounding it, the original's room); D5 offers "extern here, defined in the owner unit". | | S | check-d1-size-evidence-unclear, check-d1-stale-extent-after-split, check-d7-size-message-unclear, check-d5-requires-init-but-tentative-matches |
| 34 | **Q3 only in pointer context** (cast to a pointer, dereferenced); address-ness is left to M.ref.missing and A1. | R8 | S | grade-q3-flag-constant-as-address |
| 35 | **The file lock**: confirm with handle.exe on the daemon, then pass every project file to libclang as an unsaved buffer from fsmemo. | | S then M | build-daemon-holds-source-file-mapped |
| 36 | **Small correctness fixes**: refs `comment=` reads the address comment, not line 1 of the file (cliread.rs:478, verified); `disasm` drops `allow_hyphen_values` so unknown options error; replace the Python-style "invalid literal for int()" messages; fix the garbled session-start sentence; fix the pasted fragment in src/client.rs:1; disasm prints jump and index tables as data. | | S | refs-comment-is-unit-lead (7), disasm-symbols-flag-silent-empty, session-start-garbled-sentence, disasm-decodes-jump-tables |
| 37 | **Skill sync and fixes.** `dcp session start` warns when the project's `.claude/skills` differ from the installed dcp's. In the skills: fix :96, :255, :270 and :140-142; move M7 out of readability (after the decision on M7 in Part 4); one rule: C text only through the file-editing tool; a VC6 spellings reference instead of idiom hints; the queue order; counting by the tool, not by commits. | R12 | S-M | all skill-* reports, diffclass-idiom-hints, vc6-optimizer-hints, diffclass-volatile-reload-hint, next-why-skipped, next-bare-name |
| 38 | **Session progress from the tool**: `session status` and the wrap print `done=N/8` from `grade_changes` against the base. | R12 | S | skill-typing-commit-split, skill-grade-change-without-source, skill-data-commit-in-unit-block, session-count |
| 39 | **Re-measure performance** after the port: a warm one-unit build against 1 s, a header fan-out, a cold `session start` after a restart (print its phases), the escalate outlier, `headers conflicts --trial` (reported at 1 to 2 minutes). | | S | peformance-reports/2026-11-01, the headers trial timing |
| 40 | **The report template carries the dcp commit.** | R13 | S | |

### P2

| # | Task | Resolves |
|---|---|---|
| 41 | Signature claims from I per call site (argument count, widths, `__int64` pairs, a `void` callee whose eax is used) as derived claims, a contradiction against H's prototype, shown in refs and grade. This is the §10 "types are questions" step. | refs-call-pushes, asmdiff-param-type-mismatch-hint, grade-call-arg-count-vs-definition, lint-void-callee-result-used (part 1) |
| 42 | M7 names the callee expression or macro and the declaration in scope; repro the missed implicit call. | grade-m7-indirect-call-unnamed, grade-m7-owner-header-hint, grade-m7-missed-implicit-call |
| 43 | Function source order vs address order within a unit (the first piece of the unit experiment, §4). | lint-function-out-of-address-order |
| 44 | A pooled toolchain literal as a derived owner; an H global mapped onto it is a contradiction (§8.7). | grade-q2-pooled-literal-placeholder, asmdiff-symbols-pooled-literal-as-datum (remainder) |
| 45 | Witness: a call to an H function without φ (a same-unit helper) is a concrete difference. | grade-call-instead-of-inline |
| 46 | Readability: the full Q2 list with kinds in single-function grade; Q4 `(char *)&obj + N`; lint hints (tautological compare, unknown escape, duplicate address comment). | grade-q2-full-list, grade-q2-ignores-union-alias, grade-q4-misses-struct-plus-offset, q4-indexed-view-macro, lint-always-false-compare, lint-duplicate-address-comment |
| 47 | `why`: owner first; a `ref` answer for aligned data dwords equal to a known start (§8.2 strong tier). | why-brief-output, why-const-pointer-hint |
| 48 | Name evidence from `"ident():"` strings (§8.1: a name the image holds). | name-hint-from-strings |
| 49 | Rename hygiene: a repeat writes nothing; the error points at the name form; a repeatable `--why`; `TYPE.field` renames via clang member references. | rename-repeat-duplicate-names-log, rename-same-name-after-hand-rename, rename-per-pair-why, rename-from-help-example, rename-struct-field |
| 50 | One type-layout read query (struct types by size or field offset, a member's uses). | types-by-stride-or-field-query, types-duplicate-views-lint, struct-split-padding-command, datum-users-by-offset-and-type |
| 51 | A `similar:` line in grade (callee and literal fingerprint). | similar-function-hint, twin-functions-together |
| 52 | Differential runtime trace (first diverging call). | differential-trace-against-original |
| 53 | Ill-formed: one external name defined in two units, from the scan; an exception marker on a line without a diagnostic. | build-accepts-duplicate-function-name-across-units, check-original-marker-line-only |
| 54 | Compile diagnostics as individual M.compile findings (all of them, listed once). | build-all-errors |

**Order:** start with tasks 1 and 4: everything that compares depends on them. Then 21 and 31 (they need 4),
then 13, 22 and 25 (one trial path). Task 14 is independent and removes the most friction per hour of work.

---

## Part 3: Declined, already fixed, or merged

**Already fixed:**

- asmdiff-symbols-image-base-immediate, -internal-jump-named-other-function, -pooled-literal-as-datum (mostly),
  asmdiff-jumptable-label-marked-differ, asmdiff-wrong-callee-unmarked-when-unaligned, and the naming part of the
  float constant (931a652);
- disasm-compact-view, asmdiff-window (02237fa);
- asmdiff-regs-auto (1e1a783);
- asmdiff-header-return-count;
- grade-readable-blocked-by-head (89a180d);
- check-unresolved-data-unnamed (Rust port);
- diffclass regs-map-fixed-across-redefinition, slot-permutation-per-hunk, frame-shift-indexed, the tail cases
  (2e3148d, e504789, 4a5fae6, e8ae4d7);
- most functions in the class-request reports now grade shape through the prover (3b4d6a9).

**Declined:**

| Report | Reason |
|---|---|
| Every new diffclass class | Covered by the prover (task 23). |
| `dcp hint`, idiom hints | Toolchain knowledge goes in the skill (task 37). |
| text-id-lookup, dcp-msg-command | Project-specific; scripts, not dcp. |
| extract-stores-command | Draft generation or a project script. |
| dump-multiple-typed-values | The flags exist; document them. |
| asmdiff-side-markers-confusing | It is patch notation; document it. |
| asmdiff-summary-flag, `--hide-alias`, `--class`, `--out`, `--pair`, `--segments` | Task 14 / 19 instead. |
| asmdiff-field-names-for-offsets | Readability. |
| next-bare-name, next-why-skipped, next-placeholder-callees | Document the queue order; merged into Q2. |
| fn-context `--context` / `--head` | Already printed. |
| runtime-data-guards-debug-variant | The extent question (tasks 2, 7). |
| escalate-blocked-by-data (`@blocked`) | Masking belongs to the datum's experiment; use debt's `--waits-for`. |
| escalate-list-reasons, `--amend` | Re-escalate already replaces the reason. |
| escalate-drops-deep-tag-elsewhere-in-unit | Cannot happen from `set_level`; probably the worker's script. |
| headers-conflicts-preexisting-conflict-refuses-write | The refusal is right; message part goes to task 14. |
| data settle / merge / adopt / literal / near / check-one | `data fix` and `why NAME` (task 32). |
| rename-collision-hint ("suggest a name") | Names are outside the model (§8.1). |
| rename-multi-pair-silent | Not reproducible from the code. |
| Completing a hand rename despite a type conflict | It would create M6: no program. |
| `--quiet` / `-v` / `--fn` / `--summary` / `--errors` per command | Task 14 instead. |
| `--all-errors`, `--errors-file` | Task 54. |
| dcp-scratch-dir | The harness provides one. |
| skill-shell-git-bash, skill-commit-attribution-trailer, skill-windows-commit-message-file | Environment, not dcp. |
| check-warn-head-and-function-in-one-commit | Commit hygiene; resolved by counting via the tool (task 38). |
| check-gap-block-inside-known-object | Containment is legal; readability at most. |
| peformance-reports/2026-11-01 | Measured before the port; replaced by task 39. |
| wrap-review-open-lines | Readability; borderline. |

---

## Part 4: Decisions for the model (docs/mental-model.md)

1. **M7 has no defined status.** It is a contradiction-category finding at warn severity, but the model says
   warnings are outside it and only errors gate. Either M7 gates (an error, possibly behind a `[gate]` setting), or the
   model admits severity within a category. The skill currently gives it a third meaning.
2. **The `@original` evidence in §8.8 is too narrow.** "The matched caller" should become "evidence that the
   consistent spelling changes the bytes", for example the original's unextended push at the call site. Task 25 makes
   it checkable.
3. **Signature claims (task 41)** are the first concrete step on "types are questions" (§10). They need a place in
   `store::Question`.
4. **The held-verdict cache in grade.rs** (`HELD`, needed a key fix in b49c0ea) is the kind of special-invalidation
   cache AGENTS.md accepts only as a last resort. Once task 1 has unified the verdict, check whether it is still
   needed.
