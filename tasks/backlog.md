# Backlog

The tasks in priority order. The order within a priority follows the dependencies, then the value per effort. The
reasoning and the full report mapping are in docs/report-triage.md, and each task file lists the reports it resolves.

The reports themselves were deleted once these tasks were written. To read one, use
`git show e42b189:bug-reports/<name>.md` (likewise improvement-reports/ and peformance-reports/). For
diffclass-branch-target-equal-offsets-reported-different.md, use 31ffbb6 instead of e42b189.

- **P0:** a wrong answer or misleading verdict, broken H or φ, or a witness that lies.
- **P1:** a frequent workflow cost.
- **P2:** nice to have.
- Size: S / M / L.

## P0

| # | Task | Size | Depends on |
|---|---|---|---|
| 11 | [data-extent-fallback](data-extent-fallback.md): no one-byte data owners | S-M | |
| 12 | [containment-check](containment-check.md): references and views stay inside their object | M | |
| 13 | [library-placement-checks-targets](library-placement-checks-targets.md): library placement checks member targets | M | |
| 56 | [d8-split-object-is-error](d8-split-object-is-error.md): one object of the original split into several of ours is an error | S | |
| 57 | [d1-padding-decided](d1-padding-decided.md): D1 decides alignment padding instead of warning | S-M | |

## P1

| # | Task | Size | Depends on |
|---|---|---|---|
| 14 | [model-decisions](model-decisions.md): M7's status, `@original` evidence, signature claims, the held-verdict cache | S | |
| 15 | [output-convention](output-convention.md): verdict, failures and named changes by default; full state behind `-v` | M-L | |
| 16 | [show-computed-findings](show-computed-findings.md): build, grade and rename show the findings they computed | S | 15 (the delta) |
| 17 | [small-correctness-fixes](small-correctness-fixes.md): refs `comment=`, disasm args, garbled sentence, client.rs:1, tables in disasm | S | |
| 18 | [not-found-explains](not-found-explains.md): "unknown name" prints the ill-formed or compile cause | S | |
| 19 | [freshness-visible](freshness-visible.md): quiet builds say what they compiled; code hash on grade | S | |
| 20 | [escalate-gates-on-verdict](escalate-gates-on-verdict.md): escalate refuses on concrete differences, not prose | S | |
| 21 | [trial-and-scoped-edit](trial-and-scoped-edit.md): `dcp fn NAME --replace FILE [--trial]` | M | |
| 22 | [readers-use-answer-table](readers-use-answer-table.md): one owner lookup for every reader; φ ranking | M | |
| 23 | [b1-evidence-from-alignment](b1-evidence-from-alignment.md): B1 evidence from the alignment, two tail messages | M | |
| 24 | [switch-tables-per-case](switch-tables-per-case.md): switch tables per case through the cut correspondence | M | |
| 25 | [prover-coverage](prover-coverage.md): extend the prover by stop-reason tally; freeze the class set | L | |
| 26 | [skills-sync-and-fixes](skills-sync-and-fixes.md): skill drift check, contradictions, VC6 spellings reference | S-M | 14 |
| 27 | [session-progress-from-tool](session-progress-from-tool.md): `done=N/8` from the tool, not from commits | S | |
| 28 | [consistency-at-uses](consistency-at-uses.md): type agreement at uses; stale casts and exceptions | M | 14 |
| 29 | [exceptions-must-discriminate](exceptions-must-discriminate.md): trial-build without each `@original` | M | 21 |
| 30 | [m1-names-cause](m1-names-cause.md): M1 and the wrap name the changed headers and include chain | S-M | |
| 31 | [frame-slot-annotation](frame-slot-annotation.md): entry-relative slots and arguments in disasm and asmdiff | M | |
| 32 | [diffclass-meaning-classes](diffclass-meaning-classes.md): `const` and `addrval` as concrete differences | M | |
| 33 | [datum-experiment](datum-experiment.md): the datum object experiment, graded, seen by M1 | M | |
| 34 | [normalized-alignment](normalized-alignment.md): align on keys with registers and slots masked | L | |
| 35 | [gap-data-through-data-fix](gap-data-through-data-fix.md): `data fix` splits gap blocks and drops unused externs | M-L | |
| 36 | [headers-conflicts-scope](headers-conflicts-scope.md): duplicates anywhere; the trial drops superseded declarations | M | |
| 37 | [d-rule-messages-sizes](d-rule-messages-sizes.md): D1/D7/D5 messages name their sizes and alternatives | S | |
| 38 | [q3-pointer-context](q3-pointer-context.md): Q3 only for literals in pointer context | S | |
| 39 | [daemon-file-lock](daemon-file-lock.md): confirm and remove the libclang file mapping | S then M | |
| 40 | [remeasure-performance](remeasure-performance.md): re-measure against the warm budgets after the port | S | |
| 41 | [report-template-dcp-commit](report-template-dcp-commit.md): reports carry the dcp commit | S | |

## P2

| # | Task | Size | Depends on |
|---|---|---|---|
| 42 | [signature-claims-from-call-sites](signature-claims-from-call-sites.md): derived signature claims from I's call sites | M-L | 14 |
| 58 | [record-type-claims](record-type-claims.md): record types as claims: one struct type per record | L | 14, 42 |
| 43 | [m7-names-callee](m7-names-callee.md): M7 names the callee and the declaration in scope | S-M | |
| 44 | [function-order-check](function-order-check.md): function source order against address order | S | |
| 45 | [pooled-literal-owner](pooled-literal-owner.md): pooled toolchain literals as a derived owner | M | |
| 46 | [witness-unmapped-callee](witness-unmapped-callee.md): a call to an H function without φ is a concrete difference | S-M | |
| 47 | [duplicate-definitions-and-stray-markers](duplicate-definitions-and-stray-markers.md): one name in two units; stray markers | S | |
| 48 | [compile-diagnostics-as-findings](compile-diagnostics-as-findings.md): every compile diagnostic as a finding | M | 15 |
| 49 | [why-owner-first-and-data-refs](why-owner-first-and-data-refs.md): `why` prints the owner first and answers ref for data | S+M | |
| 50 | [readability-coverage](readability-coverage.md): Q2 full list, Q4 `&obj + N`, lint hints | S-M | 28 |
| 51 | [rename-hygiene](rename-hygiene.md): names.log repeats, per-pair `--why`, `TYPE.field` renames | S-M | |
| 52 | [name-evidence-from-strings](name-evidence-from-strings.md): names from `"ident():"` strings | S | |
| 53 | [type-layout-query](type-layout-query.md): structs by size, stride and field offset | M | |
| 54 | [similar-function-line](similar-function-line.md): a `similar:` line in grade | M | |
| 55 | [differential-trace](differential-trace.md): first diverging call between the original and ours at runtime | L | |
