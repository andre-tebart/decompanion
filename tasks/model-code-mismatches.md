# The code departs from the model

- **Priority:** P1 · **Size:** L (many S items; some need a model decision first)
- **Model:** docs/mental-model.md is the authority (AGENTS.md: the code uses its names; a new concept goes into it
  first). Every place below is where the code says something the model does not.

Collected on 2026-11-04 from the rewrite of the model document and an audit of src/ against it. Line numbers are of
that day's working tree; items marked *likely* were not fully verified. Where a task already covers an item, it is
named and this list only points to it.

Where the model itself is unclear, the item says **decide**: settle it in the model first, then change the code.

## 1. The alignment is not one thing (§4 "The alignment": one per function)

- Several readers align the two listings themselves, each with its own pairing:
  `refcheck::sites_aligned` (refcheck.rs:260: equal lines, same-mnemonic lines of equal-length hunks by position),
  `diffclass::compare_tables` (diffclass.rs:968: a map of the equal runs only), asmdiff's `diff_lines`
  (matchcmd.rs:230: frame-masked), `diffclass::Cuts` (diffclass.rs:414: by position in regs / sib / frame / slots
  hunks), `shape::voted_renaming` (shape.rs:569: register-masked, for voting). The reference check and the branch
  check can pair one instruction differently.
- **Decide:** the one convention for pairing inside a hunk, and name it in §4.
- **Fix:** one module for the alignment, computed once per function (held by `FunctionCompare`); every reader above
  reads its pairs and cuts; the distances count from it. Then tasks/normalized-alignment.md changes the alignment
  itself in that one place. Measure grades and verdicts on gildegold before and after.

## 2. Rows that are not claims are called claims (§2, §3: a claim answers a question about I)

- `store::Claim` and the `claim` table hold every row: claims, φ entries (`name`), experiment results, readability,
  H's build (`build`), intermediate evidence (`evidence`). `store::role` sorts them out afterwards.
- The code already says "fact" in many places (setup.rs:150 `facts()`, `st_facts`, "a run's facts by kind", the
  registry docs: "symbol or region facts", "`unit` fact"), so "claim" and "fact" are used for the same rows.
- **Decide:** "fact" as the model's word for a stored row at an address of I, with claim as the facts that answer a
  question. Place it in §3 and §10.
- **Fix:** rename the row type to `Fact`, keep `Claim` for the facts whose role is a claim.

## 3. Open is stored (§3: "No claim at all means open")

- `S.unknown` writes `symbol` rows at support `Open` (setup.rs:351, :356; ceiling `OPEN`, registry.rs:495).
  `L.unit.extent` can give a boundary the level `OPEN` (layout.rs:739). The readers then filter `support > OPEN`
  (layout.rs:181, :570, :981; asmcmd.rs:288), and C.overlap's doc says "open is replaced, not contradicted": open is
  treated as a claim that loses.
- **Fix:** drop `Support::Open` as a stored level. Bytes without a claim are open; a reader that needs the open runs
  computes them as the gaps between claims (or the answer table holds them as no answer).

## 4. Support is used as a strength scale, not as the source (§3 table)

Support names where a claim comes from: our word (declared), analysis of I (derived), the format (observed), an
experiment (reproduced).

- A function experiment below byte is stored at `DECLARED` (grade.rs:500: "anything less rests on the address
  comment"); the unit experiment is capped at `DECLARED` (grade.rs:519). An experiment is neither our word nor an
  analysis.
- A toolchain flag probe from one unit is `DECLARED`, from two units `REPRODUCED` (mrules.rs:196). The model says the
  toolchain probe is reproduced.
- The tie-break probe records are `DERIVED` (`M.tiebreak`, registry.rs:272; tiebreak.rs:197), though they come from
  compiles. (Uncommitted work at the time of writing.)
- Registry ceilings that do not fit the source: `L.analyze` (an analysis of I) and the finding-only rules L1 / L4 /
  L5 / L6 / L13 / A1 declare `REPRODUCED`. L.analyze caps its claims at `DERIVED` in code (layout.rs:1690, :1702), so
  the ceiling is never reached, but it says the wrong thing. *likely* for the finding-only rules.
- **Decide:** what a shape experiment reproduces. §8.5 says a shape pass "still supports the extent and the control
  flow", and §4 says a passing experiment yields reproduced claims in the aspects the bytes discriminate. Then the
  experiment row of a shape function is reproduced for extent and control flow, and a draft yields nothing.
- **Fix:** every rule's support and ceiling from its source; strength within a level stays in the row's value.

## 5. Reproduced claims that the experiment cannot support (§4: an experiment supports only what could have failed it)

- **Shape yields no reproduced claims** (§8.5). Only `M.match` emits reproduced extents, and only on a byte match
  (rules.rs:298, :311).
- **M.match reproduces without the reference check** (§4: a relocated field is masked only together with the check
  of its target). `M.match` emits `REPRODUCED` `symbol` / `source` claims (rules.rs:311-314) from
  `Compared::matched()` (rules.rs:81), which is the masked compare (compare.rs:45) plus a count of relocation sites,
  never refcheck. R2 (docs/report-triage.md) fixed the grade and M8, not these claims.
- **One object's experiment reproduces another's extent** (§8.4: each experiment tests its own object). `M.data.site`
  gives a datum a `REPRODUCED` owner claim over its whole `data_extent` (rules.rs:641-649) because a byte-matched
  function's relocation lands on its address. That function's experiment cannot fail on the datum's size or kind:
  it supports the datum's start (a reference target), not its extent.

## 6. "Bug" decided from one side (§5: top against top is a bug)

- D6 emits `bug` when φ's support for the target is top (rules.rs:1093), whatever the support of H's own entry,
  which is declared unless the datum matched. setup.rs:165 does it right: both sides top.

## 7. Debt that is not a declared regression of an experiment (§5, §8.6)

- **A readability fall is debt.** M1 counts "readability readable -> draft" as a fall and emits an error of category
  Debt (layout.rs:887-889, :915). §5: debt is a regression of an experiment; §9: readability never overrides the
  model. Readability's fall is readability's own finding.
- **A regression accepted without a declaration.** `M1.tiebreak` treats a code fall of a tie-break sensitive
  function whose own text is unchanged as "no fall, no debt" (layout.rs:903-920): a warning with no witness,
  nothing it waits for, not counted against `max_debt`, yet filed under category Debt (registry.rs:116). §8.6: a
  regression is allowed only when declared; an unexplained one fails the gate. (Uncommitted work at the time of
  writing.)
- **A debt item without what it waits for** is only a warning (layout.rs:925); §8.6 requires it. *likely*

## 8. Tie-breaks and probes are not in the model (AGENTS.md: a new concept goes into the model first)

- G.grade stores `proven`, the best grade under the probes (grade.rs:477-486); the queues swap it in as the
  function's `code` (queues.rs:182-190), so a probed H′ moves work out of the base and deep queues
  (queues.rs:230-231). The model's grade is the experiment on the current H (§4), and the queues are a view of C
  (§7).
- **Decide:** place the declaration-set probe in the model: an experiment on a variant H′ (what it tests, what it
  masks, what it reproduces), and how a result on H′ may count for H. tasks/exceptions-must-discriminate.md and
  tasks/trial-and-scoped-edit.md (R11: "try H′ without changing H") need the same concept.

## 9. Readability holds what the bytes decide (§9: could the original's bytes ever decide it?)

- Q8 "complete" compares our size with the original's (grade.rs:455-460). The bytes decide it: it is the
  experiment's.
- Q3 flags any literal inside the image's range (readability.rs:391-400). Whether such a literal is a reference is
  the model's question (§8.2 ambiguous tier, §8.3). *likely*

## 10. Queues do not match §7

- The names queue holds "Q-only deep functions": `@deep` / `@stuck` tags, byte, failing any Q rule (queues.rs:19,
  :117), not "the names".
- The deep queue adds below-byte functions only once the unit's base is empty (queues.rs:232); §7 says every
  function below byte.
- `below_byte` also counts readability (queues.rs:113).
- **Decide:** whether §7 describes the queues as they are meant (then fix the code) or the code's rules are right
  (then rewrite §7). *likely* for all three.

## 11. The model's names are not the code's names (AGENTS.md)

- "proven" / "source-proven" (grade.rs:484, queues.rs:181, mrules.rs:177, layout.rs:236, crt.rs:78) against §3
  "Nothing is proven": the model's word is reproduced.
- "level" means support (clicmd.rs:33 `level()`, "boundary levels") and also the `@deep` / `@stuck` / `@hard` tags
  (queues.rs:121, `set_level`).
- `store::derived` (queues.rs:177) is a memo named after a support level.
- "claim" / "fact": item 2.
- "question" for the kind of a claim (§2: a claim has a kind; §5: contradictions come from consistency rules, of which
  "one value per byte" is one): `store::Question` and `Question::kinds` (store.rs:124: "the structural questions of
  §2"), `dcp claims --question`, `dcp why` grouped by question, `role` "a claim answering a question". Rename to the
  kind of a claim, with a flag for the kinds that have one value per byte.
- The contradiction checks are the model's consistency rules (§5). Each should name its rule and its claims; today a
  finding names the producers (`a=`, `b=`). Give the checks of category contradiction the rule names of §5's table
  (one value per byte, a call goes to a start, a unit edge is between objects, a reference lands on an object), and
  place any check that fits none of them in the model.

## 12. The model's "not yet" (§10)

Recorded in §10 and in their own tasks; listed here so this task is complete:

| Model | Task |
|---|---|
| One answer per (byte, question): `ref`, `start`, `toolchain` are answered on demand, not kept | readers-use-answer-table |
| Every contradiction names its two claims: cross-kind checks name producers, not rows | none yet |
| Unit and image experiments | function-order-check (the first piece), datum-experiment (the datum object experiment) |
| Types are questions | signature-claims-from-call-sites, record-type-claims |
| An exception must discriminate | exceptions-must-discriminate |
| Warnings outside the model, yet M7 is a warn-level contradiction | model-decisions (item 1) |

## Fixed in the model while collecting this

- §1 said φ is "always our word"; φ also holds the image's own names (observed) and placed library members
  (reproduced). §1 now says so.
- §8.2 listed the base relocations as derived; §3 and the code (`S.relocs`, registry.rs:445) say observed. §8.2 now
  gives them their own row, observed.

## Order

1. The decisions (items 1, 2, 4, 8, 10) in the model, one commit.
2. The names (items 2, 11): mechanical, no behaviour change.
3. Support from the source (items 3, 4, 6): changes stored rows; check `dcp why` and the answer table.
4. The experiment's reach (item 5) and debt (item 7): change gate results; measure on gildegold.
5. The one alignment (item 1): changes grades; measure on gildegold.
