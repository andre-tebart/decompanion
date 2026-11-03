# Decisions for the mental model

- **Priority:** P1 · **Size:** S (decisions, then a doc edit)
- **Blocks:** skills-sync-and-fixes (M7 wording), consistency-at-uses (severity), signature-claims-from-call-sites

These are decisions for docs/mental-model.md that the triage surfaced. The code and the skills disagree on them today.

1. **M7's status.** M7 is a finding of category contradiction at `warn` severity (rules.rs:605, registry.rs:72). The
   model says warnings are outside it (§10, last row) and that only errors gate (§5), so a contradiction that cannot
   gate is undefined. The skill gives it a third meaning: it files M7 under readability but calls it "the experiment's
   side". Choose one:
   - M7 gates (an error, possibly behind a `[gate]` setting); or
   - the model admits severity within a category, and says what a warn-level contradiction means.
2. **`@original` evidence (§8.8).** "The matched caller" is narrower than the model's own rule, "the consistent spelling
   changes the bytes". Instruction-level evidence at the call site qualifies, for example the original's unextended
   `push ecx` against our `movsx`. Reword §8.8. exceptions-must-discriminate makes it checkable.
3. **Signature claims.** signature-claims-from-call-sites would be the first concrete step on "types are questions"
   (§10). Decide its place in `store::Question` and its support level (derived).
4. **The held-verdict cache** in grade.rs (`HELD`) needed a key fix in b49c0ea. It is the kind of special-invalidation
   cache AGENTS.md accepts only as a last resort. Its key now also holds φ's addresses of every relocation's object
   (the prover binds through φ); the reference check runs on every run, outside it. The verdict is unified now
   (grade::decide, grade::Grader for the header and data fix trials, which hold nothing): check whether it is
   still needed.
