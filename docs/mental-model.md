# The mental model

decompanion answers one question for every address of the target: *what is here?* This document describes the model
behind that answer: what we observe, what we write, how the two are connected, what we claim about the original,
and how evidence moves claims.

It is the refined model. The last section maps it to the code and the command line, and says what the code does not
do yet.

## 1. The four things

| Thing | What it is | Known how? |
|---|---|---|
| **I**, the image | The original's bytes. | Observed. |
| **H**, the source | Everything we write that builds an image: the C code, the headers, the declarations, and the complete toolchain with its configuration (compiler and linker versions, flags, link order, libraries). | Completely: we have it and we build it. |
| **φ**, the correspondence | Which of H's objects is which part of I: "our `UpdateViews` is the original's bytes at 0x401230". | Written by us. |
| **C**, the claims | Statements about the original: "at byte b, the answer to question q is v", each with a support level. | Derived from the other three. |

**H is a program, not a set of claims.** Building H gives our own image I_H, and everything about I_H is known with
certainty: every function, unit, type, reference and boundary (the linker map, the relocations, the symbols).

**φ is the link between H and I.** The address comment above a function is φ for that function. The unit boundary
lines in `decl/*.dcl` are φ for units. `bytes dead` and `foreign` lines say "these bytes of I have no counterpart in
H's code yet, and this is why". Inside a function, φ extends by aligning the two instruction streams (what `asmdiff`
does); where the alignment breaks, φ says nothing.

**C comes from carrying things over.** Through φ, H's structure becomes claims about I: "the call at 0x401250
goes to `d2_MoveObj`", "these bytes are unit `net`". Analysis of I and experiments add claims of their own.

### The toolchain is part of H

I_H is H's sources built by H's toolchain. The toolchain is a choice like the code: an experiment tests both at once,
and a wrong compiler version or flag fails experiments just like wrong code. A toolchain error usually shows as many
functions failing the same way, not as one bad function.

Derived claims rest on toolchain conventions (VC6 fill bytes, LINK places objects in order), so they are only as
good as H's toolchain. Evidence in the image supports that choice (the Rich header, the library code the toolchain
ships), and every passing experiment supports it further.

## 2. Questions

A claim answers one **question** about a byte range. The questions are structural: about how the image was made,
not about how we like to read it.

- section of the byte
- owner of the byte (which function, global, string, table, fill, ...)
- does a function start here?
- which unit produces the byte?
- is the field at this address a reference, and to what?
- what is the type of an object, or the signature of a function (parameters, return type, calling convention)?

Every question has at most one answer per byte. When something looks multi-valued, the multiplicity goes into the
question ("the ref target of the field at b", not "the refs of b").

Types are **partly observable**: some type choices change the bytes (`short` against `int` parameters, an argument
more or less), others do not.

Names and comments are **not** questions. The bytes usually do not decide them (8.1). They are part of H, and this
model says nothing about them (section 9).

## 3. Claims and support

A claim is `(range, question, answer, support, why)`. Support depends on where it comes from:

| Source | How | Support |
|---|---|---|
| **H through φ** | H's structure carried over to I. Nothing but our word supports it. An external analyzer's output (Ghidra's function starts) is the same: someone's word. | declared |
| **Analysis of I** | A rule over the bytes and other claims under a named convention: a toolchain convention (VC6 fill, LINK order), an encoding rule (an absolute memory operand is an address), a convention about how the original was written (it was consistent C, 8.8). Independent of H. | derived |
| **Reading I's format** | The image read under its format's specification: the section table, the base relocations, the export and import tables, the headers. | observed |
| **Experiment** | I_H compared with I through φ, passing. H's structure there is confirmed in the aspects the bytes discriminate (section 4). A placed library member is one too: the toolchain's archives are part of H, and the member's bytes are compared with I. So is the toolchain probe: a flag whose anchors stop matching under any other value. | reproduced |

The order `declared < derived < observed = reproduced` ranks **how hard a claim is to overturn**, not how true it
is:

- Overturning a declared claim takes a better reason.
- Overturning a derived claim takes a place where the convention does not hold (an exception, section 5).
- Overturning an observed claim takes a rule that misreads the format: a bug.
- Overturning a reproduced claim takes a *different* H that also reproduces the bytes, or a rule that compares
  wrongly: a bug.

Observed and reproduced share the top rank: two top claims that disagree are a bug in a rule, whichever they are.

**Nothing is proven.** A finished decompilation does not show what the original source was; it shows that a source
exists that rebuilds the image byte for byte. That is a complete and honest result, and it is all the bytes can give.

No claim at all means *open*: nothing is known.

**A rule's support** is the min of its ceiling and the support of each premise: a conclusion is no stronger than its
weakest input.

**Claims stack, they are not upgraded.** The address comment's claim stays declared forever. When the function
matches, the experiment adds a reproduced claim that agrees with it. If the match is lost later, the reproduced claim
goes and the declared one is still there.

## 4. Experiments

An experiment compares I_H with I through φ over one object and observes *equal* or *not equal*. It is an
observation, not a claim. A passing experiment yields reproduced claims; a failing one shows where H is wrong.

**An experiment only supports what would have made it fail if it were wrong.**

- A function 10 bytes too long breaks the match, so a passing match supports the function's extent.
- `0x4a1230` and `g_foo` give the same bytes, so a passing byte comparison says nothing about whether that field is
  a reference, unless the experiment checks references as well (8.3).

**Each experiment tests exactly one thing and masks whatever belongs to something else.** A relocated field's
value is the address of another object, so it is masked; instead the experiment checks that the field refers to the
same thing on both sides: the field in I points to φ(the target the field has in I_H).

Experiments form a hierarchy:

| Experiment | Tests | Masks |
|---|---|---|
| **Object** (function, datum) | its bytes and the targets of its references | the values of relocated fields |
| **Unit** | the order of its functions, its data, its literals, its boundaries | the objects' own bytes (tested above) |
| **Image** | the order of the units and libraries, the fill between them | everything inside a unit |

## 5. Answers and contradictions

| Concept | Definition |
|---|---|
| **Answer** for (byte, question) | The value the covering claims agree on, at their highest support. Open if no claim covers it. |
| **Confirmation** | Two claims on the same (byte, question) with the same answer. |
| **Contradiction** | Two claims on the same (byte, question) with different answers. |
| **Resolution** | Revise or drop the claim with less support, which usually means changing H or φ. With equal support: declared against declared is ours to decide (two of our statements disagree); derived against derived means one convention does not hold there and needs an exception. |
| **Exception** | A declared statement that a convention does not hold at one site, with a reason. It removes the convention's premise there; it does not outvote it. |
| **Bug** | top against top (observed or reproduced on both sides): one H cannot give two answers, and the format reads one way, so a rule is wrong. |

Every contradiction has the same shape: two claims giving different answers to the same question about the same
byte. In practice it is almost always H through φ against an analysis of I, or two analyses against each other.

### Findings

Not everything the tool reports is a contradiction. A **finding** is one of five things:

| Category | What it says | Examples |
|---|---|---|
| **contradiction** | Two answers to one question about one byte. | two owners of a byte, a call into a function's middle, a hard-coded address where the original refers (8.3), a declared unit edge inside a function |
| **ill-formed** | H is no program, or φ is no mapping: the model cannot even be applied. | a unit that does not compile, a declaration line without its reason, a function of an object without its address comment, two of our definitions at one address without a reason the toolchain gives (8.7) |
| **gap** | Open where an answer is due: bytes nothing explains once the surroundings are laid out, a part of H that is missing. | unexplained code inside a unit, library code no member explains, an import library the toolchain does not have |
| **stale** | An observation older than H: the next build or lint makes it current. | a unit changed since its compile, a lint that did not parse today's text |
| **debt** | A regression of an experiment, allowed only when declared (8.6). | a debt item with its witness; more of them than the gate allows |

The gate fails on errors of any category; a contradiction between two top claims is a bug.

## 6. Done

**I_H = I.** H builds the original image byte for byte. Then H places every object at its original address, φ is the
identity, and the address comments only restate where the build puts things. Every structural answer is reproduced
and no contradiction is left.

That φ disappears in the end is a check on the model: the finished state needs no separate mapping, because the
program is the explanation of the image.

## 7. Working

We only ever edit **H and φ**. C follows. The loop:

```
edit H and φ ──▶ build I_H, run rules and experiments ──▶ C: answers and contradictions ──▶ edit H and φ
```

**Layout** and **match** are two strategies in this loop, not two kinds of work:

- **Layout** builds H's skeleton and φ until φ covers every byte: the unit files in the original's order, a draft
  (or `@rough`) per function, the boundaries, the starts, the dead bytes. Its claims are declared (from H through φ)
  and derived (walk, fill, literal order, leaked paths). The answer becomes **total**.
- **Match** changes H until experiments pass. The answer becomes **strong**.

Layout comes first for a reason:

- **Conventions need neighbours.** Fill between contributions, contiguity (a function owns its bytes up to the next
  start) and literal order work only once the surrounding starts and units exist.
- **The consistency rule needs every user.** A type carried from a matched caller (8.8) only reaches callers that
  exist in H.
- **Totality shows the gaps.** Once φ covers every byte, what is unexplained is visible.

## 8. Examples

### 8.1 Names do not become claims

`UpdateViews` or `foo`: same bytes. No experiment could catch a wrong name, so names are not a question, and H's names
are not carried over as claims. They reach the claim system only when the image itself holds them (exports, imports,
`__FILE__` strings): then a name is part of what an analysis of I reads.

### 8.2 Reference claims from static analysis

An analysis of I can claim that a field is a reference, independent of H. The evidence comes in tiers:

| Tier | Evidence | Support |
|---|---|---|
| Near-certain | Branch targets (`call rel32`, `jmp rel32`). Absolute memory operands (`mov eax, [0x4a1230]`, `[ecx*4 + 0x4a1230]`): in non-PIC 32-bit code nothing but an address goes there. The image's base relocations, where present: complete and exact. | derived |
| Strong | An immediate (`push 0x4b0010`, `mov reg, 0x4b0010`) or an aligned dword in data that equals the start of a known function, string or data object. Convention: "an immediate equal to the start of a known object is its address". | derived |
| Ambiguous | An immediate inside the image that lands on nothing in particular: `&arr[5]`, a field, or a flag mask that happens to be in range. | open; an exception or H decides |

"Is a ref" can be derived. "Is not a ref" cannot, unless the image has base relocations: looking like a number is
not evidence.

### 8.3 A hard-coded address in a matching function

H writes `*(int *)0x4a1230` where the original refers to `g_foo`. The function's bytes match.

- **H through φ**: the instruction streams align exactly, so φ covers the field. In I_H the field is a constant, so
  the claim is `ref(b) = none`, declared.
- **Analysis of I**: an absolute memory operand, so `ref(b) = g_foo`'s address, derived.
- Same question, different answers: a **contradiction**. H has less support and is changed.

The byte comparison does not rescue H: constant and reference give the same bytes. The object experiment that checks
references does catch it, wherever the image tells which fields are references: with base relocations directly,
without them through the derived ref claims.

A matching byte comparison is therefore not enough. Equal bytes compare the program at one layout. The real criterion
is that H reproduces I **for every layout**: equal bytes with relocated fields masked, and the same reference targets.

What this cannot catch: differences that survive any relinking, like `0x10` against `FLAG_VISIBLE`. The bytes cannot
see them, so they are outside the model, like names (section 9).

### 8.4 Replacing the hard-coded address with the symbol

We write `g_foo` instead of `0x4a1230`. Our linker does not put `g_foo` at 0x4a1230 yet, so the linked bytes differ.

- **The function's experiment** still passes: the field is a relocation now, its value is masked, and the
  reference check asks whether the original's field points to φ(`g_foo`). The address comment on `g_foo` says
  φ(`g_foo`) = 0x4a1230, so it does.
- **H through φ** now claims `ref(b) = g_foo` and agrees with the analysis: the contradiction is gone.
- **The wrong placement** belongs to `g_foo`, not to the function: φ says 0x4a1230, I_H puts it elsewhere. That is
  `g_foo`'s experiment failing and is fixed by the data layout.
- If `g_foo` has no address comment yet, φ(`g_foo`) is undefined and the reference check cannot be decided: open, not
  failed. Giving `g_foo` its φ settles it.

The change is a strict improvement. If the function's evaluation got worse, its experiment would be testing
something that belongs to `g_foo`.

### 8.5 A header restructure that costs a match

A function matches. We restructure headers because the new layout is clearly better. VC6's register allocation shifts
and the match is lost.

- H changed, so the experiments are rerun. The function's fails, and its reproduced claims go.
- "The new headers are more correct" is our judgment: it has no support beyond our word.
- Under VC6 headers are partly **observable**: declaration order, the prototypes in scope (`short` against `int`
  parameters, return types, calling convention) and whether a call sees a prototype at all change the code. The
  change would have made the experiment fail if it was wrong, and it did. That is evidence against it. The original
  source produced these bytes with this compiler, so an arrangement like the original's reproduces them.
- Which details of H leak into the bytes depends on the toolchain, not on what feels like organisation. The experiment
  tells.
- A weaker experiment may still pass: equal up to register renaming (the shape grade). It still supports the extent
  and the control flow, only not the exact allocation.

### 8.6 Regressions without getting stuck

A rule that forbids any lost match blocks progress: the right header arrangement is often easier to find once more
is settled, and a strict rule locks the project into a local optimum.

The way out is to separate two things:

| | Can it go down? |
|---|---|
| **Knowledge about I**: reproduced claims from any witness, past or present | No. It only grows. |
| **Quality of the current H**: do its experiments pass? | Yes, temporarily. |

**A witness does not expire.** A witness is an (H, φ) whose experiment passed: an old commit. Once one exists, it is a
fact about I that a source with that extent, those references and that structure rebuilds those bytes. The header
restructure in 8.5 costs the current H a match; it costs no knowledge.

So the rule is **never regress silently**, not "never regress":

- A regression is allowed when it is declared: which object, why, what it waits for, the last witness commit.
- It becomes a **debt item**: listed, counted, not a gate failure.
- An unexplained regression fails the gate.
- Debt is bounded (at most N open, each naming what it waits for), so it does not pile up.
- The last witness stays available to diff against.
- A re-match pass walks the debt once the structure settles. Many small shifts share one cause (one prototype, one
  declaration order), so they come back together.

### 8.7 Several symbols at one address

Some toolchain behaviour gives one address several objects of H:

- **String pooling** (`/GF`): identical literals `"error"` in different places of H become one string in I.
- **Identical COMDAT folding** (`/OPT:ICF`): functions or const objects with identical bytes are folded into one body.
- **Aliases**: two declarations naming the same datum.

Here **φ is many-to-one**: several objects of H map to one range of I. That is no contradiction. The structural answer
stays single: `owner(b)` is one object, because I holds one string or one body. H's toolchain explains the folding,
and at the end I_H folds them the same way, so the experiment checks it.

Many-to-one is legal **only when the toolchain or the image explains it**: a fold the toolchain makes, an alias that
is declared, the image's own spellings of one object (an export and its library symbol, the CRT's decorated user
entry). Two of our own definitions at one address without such a reason are not φ being many-to-one, they are φ
being ill-formed: one of the two address comments is wrong.

Each site that uses `"error"` or `foo_a` has its own ref question with the same target: different sites, one answer
each.

What stays open: **which unit's copy the linker kept**. The bytes are identical whichever unit wins, so no experiment
can tell (section 4). The unit answer stays declared, or derived where a link-order convention decides it. That is the
model saying "the bytes cannot know", not a gap.

Not the same thing: **containment**. An object of H that φ maps into another object's range (`g_x` = `&arr[3]`, a
struct field) is no second owner: the owner is the outer object, and uses of the inner one are references with an
offset.

### 8.8 Consistent declarations and `@original`

The lint (`dcp lint`: clang as a type checker over the units) is not a readability check. It is an analysis with a
convention about how the original was written:

> The original was consistent C: each function and object had one declaration, and every use agreed with it.

That holds almost everywhere; few prototypes in the original were superseded by local views.

The rule **connects questions across objects**. A passing experiment supports a type where the bytes discriminate: a
caller that matches only when it passes `short` arguments supports `d2_MoveObj(short, short, int)`, reproduced. The
convention carries that to the declaration and to every other use, derived. A caller in H that passes an `int`
contradicts it before its own experiment fails, and also where its own experiment could not tell. That is how the
rule catches mistakes early: it moves evidence from where the bytes decide to where they do not (yet).

**`@original why`** is an **exception** to the convention at one site: the original itself was inconsistent here (it
called the function through another spelling). It removes the convention's premise at that site; it does not outvote
it. Its reason is an experiment: the matched caller, whose bytes would change with the consistent spelling. The
spelling stays in the unit that needs it (a cast macro in the unit's head), never in a shared header: two headers that
disagree cannot be included together.

**`@vc6 why`** is a different exception: the checker's model of C (clang) differs from H's toolchain at this site. The
gap is in the checker, not in H.

What follows:

- **An exception must discriminate.** `@original` is valid only if the consistent spelling changes the bytes. A tool
  can check it: build the variant without the exception and compare. If the bytes stay the same, the exception has no
  evidence. (`improvement-reports/detect-nested-call-in-arguments.md` is such a case: an `@original` for a
  "six-argument call" whose real cause was a nested call.)
- **Exceptions go stale.** When H changes, the experiment behind an exception is rerun; one that no longer
  discriminates is flagged.
- **Exceptions are visible and counted**, like debt items, each naming its evidence.

### 8.9 Writing a function and its address comment

We write a function and `/* 0x401230, sends the reply */` above it. What is what?

- The **function** is H. It is not a claim; it is a program whose build we know completely.
- The **address comment** is φ for that function: our object is the original's bytes at 0x401230.
- The **claims** follow from both: a function starts at 0x401230, these bytes are this unit, each call site goes to
  this callee, the signature is this. All declared.
- When the function matches, the experiment adds reproduced claims next to them. Our declared claims stay as they
  are.
- At the end, the build places the function at 0x401230 by itself, and the comment restates what the build does.

## 9. Outside the model: readability

This model is about one thing: how H corresponds to the original. Everything in it is a question the original's
bytes could, at least in principle, decide.

Readability is a different thing: a standard for H as source code, whatever the original was. Good names, no Ghidra
macros (`CONCAT`, `undefined4`), real types instead of casts, no `@rough` or TODO markers, `FLAG_VISIBLE` instead of
`0x10`, descriptive address comments. Two sources that build the same I_H can differ completely in readability, and
no experiment against I can prefer one.

So readability is kept apart:

- It produces **no claims** and no contradictions about I. It judges H against its own standard.
- It **never overrides** the model: a more readable H that fails an experiment is not more correct (8.5). Where the
  two pull apart, the model decides what H must do, and readability decides how to write it.
- What looks like readability but **predicts the bytes** belongs to the model, not here: consistent declarations
  (8.8) are a convention about the original that catches mismatches early; types are partly observable (section 2).
  The test is the one from section 4: could the original's bytes ever decide it?

## 10. The model in the code and on the command line

The source names the model's concepts, and the command line speaks them:

| Model | Code | Command line |
|---|---|---|
| a claim `(range, question, answer, support, why)` | `store::Claim` (the `claim` table): a range, a kind, a value, a `Support`, its producer and reason | `dcp claims RANGE [--question Q] [--support S]` |
| support | `store::Support`: `Open`, `Declared`, `Derived`, `Observed`, `Reproduced` (`is_top`: observed or reproduced); a rule's `max_support` | `support=` on every claim |
| the questions | `store::Question`: section, owner, start, unit, ref, toolchain; `Question::kinds` names the stored kinds that answer each (`symbol` / `region` / `source` the owner, `unit` / `boundary` the unit) | `dcp claims --question` |
| what a stored kind is | `store::role`: a claim answering a question, φ (`name`), an experiment (`experiment`), readability (`readability`), H's build (`build`), a rule's intermediate result (`evidence`) | `role` in `dcp claims --json` |
| the answer | `answers.rs` (the `answer` table): per run of bytes the owner at its highest support, the unit, the H object, the section; `answers::stacked` per question | `dcp answers [RANGE]`; `dcp why ADDR` by question, the answer first and the claims stacked under it |
| φ | `phi.rs`: built from the `name` claims (address comments, declarations, library members, exports, imports, the user entry); `Phi::of(name)` and `Phi::at(addr)`; `Phi::many` with `many_reason` | `dcp phi [ADDR\|NAME] [--many]`; φ in `dcp why` |
| a finding and its category | `Finding` (the `finding` table); `registry::Category` and `registry::CHECKS` give every check id its category | `dcp findings [--category C]`; `dcp check` counts per category and lists the errors grouped by category |
| the object experiment | `M.match` (the byte criterion) and the reference check (`refcheck.rs`: each relocated field of ours that lines up against φ(its symbol), a literal by its bytes; equal, different or open), `G.grade`'s `experiment` claim (outcome byte / shape / draft, the failing B rules, the distance, the consistency calls, the open references) | `dcp grade`: `experiment=`; `dcp asmdiff` / `dcp diffclass`: `ref:` / `literal:` |
| a placed library member | `S.crt.code`, `S.crt.data`, `S.lib.data`: reproduced | |
| a reference the byte comparison cannot see (8.3) | `A1` (a cast the source scan sees), `M.ref.missing` (an absolute operand our bytes hold as a constant), `M8` / `M9` / `M10` (the reference check's findings on a byte match: our reference against the original's target through φ, a literal by its bytes), `D6` | `dcp findings --category contradiction` |
| readability (§9) | `readability.rs` (Q1..Q6, Q8), `G.grade`'s `readability` row, apart from the experiment | `dcp grade`: `readability=` |
| an exception | `exceptions.rs`: `@original why`, `@vc6 why` with their reasons | `dcp exceptions` |
| debt, a witness | the accepted column of `ledger/grades.tsv` (`queues::Debt`: the grade before and now, the witness commit, why, what it waits for); `M1.debt` lists them and bounds them by `[gate] max_debt` | `dcp debt add NAME --to G --why W --waits-for X`, `dcp debt list` |

What the code does not do yet:

| Model | Today |
|---|---|
| One answer per (byte, question) | The `answer` table holds the owner, the unit and the section; `ref`, `start` and `toolchain` are answered per address on demand (`dcp why`), not kept |
| Every contradiction names its two claims | The cross-kind checks (`L13`, `C.walk`, ...) compute their own predicate over the claims; a finding names the producers (`a=`, `b=`), not the claim rows |
| Unit and image experiments | Unit boundaries rest on the evidence rules (`L.analyze`: fill, literal order, leaks) and D4's definition order; there is no explicit unit experiment |
| Types are questions | `M.lint` reports clang's M5 / M6 / M7; types are no claims of their own |
| An exception must discriminate (8.8) | `dcp exceptions` lists them and counts the ones without a reason; that the consistent spelling would change the bytes is not checked (a trial build without the exception) |
| Warnings | Not part of the model: hints, not findings; they stay lint output |
