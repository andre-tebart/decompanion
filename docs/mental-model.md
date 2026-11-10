# The mental model

decompanion answers one question for every address of the target: *what is here?* This document describes the model
behind that answer: what we observe, what we write, how the two are connected, what we claim about the original,
and how evidence moves claims.

The section numbers are stable: the code cites them (`docs/mental-model.md §8.6`). A new concept is placed in this
document first, then in the code (section 10).

## Start here

### The model in six sentences

1. The original program is a block of bytes we can read: the **image I**.
2. We write a program that builds an image of its own: the **source H** (code, headers, declarations and the
   toolchain). Its build is **I_H**, and we know everything about it.
3. We say which part of H is which part of I: the **correspondence φ** ("our `d2_MoveObj` is the original's bytes at
   0x401230").
4. From H, φ and I we get **claims** about the original ("a function starts at 0x401230"). Each has a **support**:
   how hard it is to overturn.
5. An **experiment** builds I_H and compares it with I through φ. A pass makes claims strong; a failure shows where
   H is wrong.
6. Where claims cannot all hold, the tool reports a **finding**. We fix it by changing H or φ, never C directly. The work
   is done when I_H = I, byte for byte.

### The picture

```
   H  (we write: source + toolchain) ──── build ────▶  I_H  (our image, known completely)
   │                                                     │
   φ  (we write: which object of H is which part of I)   │  experiment: compare through φ
   │                                                     │
   ▼                                                     ▼
   I  (we observe: the original's bytes)  ◀──────────────┘

   C, the claims about I, come from four sources:
     H through φ  ·  analysis of I  ·  reading I's format  ·  experiments
```

### The running example

One function follows us through sections 1 to 6. We write it with its address comment above it:

```c
/* 0x401230, moves an object to a cell */
void d2_MoveObj(short x, short y, int flags) { ... }
```

Each section ends with what its idea says about this function.

### How to read this document

- **New to the project:** read sections 1 to 7 in order, then the cases in section 8 that interest you.
- **Looking up a word:** the glossary at the end gives each term one line and the section that defines it.
- **Working on the code:** section 10 maps every concept to its type and its command.

## 1. The four things

**In short:** we observe I, we write H and φ, and the claims C follow from those three.

| Thing | What it is | Known how? |
|---|---|---|
| **I**, the image | The original's bytes. | Observed. |
| **H**, the source | Everything we write that builds an image: the C code, the headers, the declarations, and the complete toolchain with its configuration (compiler and linker versions, flags, link order, libraries). | Completely: we have it and we build it. |
| **φ**, the correspondence | Which of H's objects is which part of I: "our `UpdateViews` is the original's bytes at 0x401230". | Written by us. |
| **C**, the claims | Statements about the original: "byte b is the start of a function", each with a support level. | Derived from the other three. |

### H is a program, not a set of claims

Building H gives our own image I_H, and everything about I_H is known with certainty: every function, unit, type,
reference and boundary (the linker map, the relocations, the symbols).

Two words used throughout:

- A **unit** is one source file of H compiled to one object file. The linker places a unit's contents together, so
  a unit is also a contiguous stretch of I.
- A **relocation** is a field in the code or data whose value is the address of another object. The linker fills
  it in, so its value changes whenever that object moves.

### φ links H and I

φ says which object of H is which part of I: a function, a datum, a unit, a range of bytes. Most of it is our word,
and that part is declared. The rest comes from elsewhere and carries that source's support: the names the image
itself holds (exports, imports: observed), and the toolchain's library members, placed where their bytes match
(reproduced; see 8.7). Our part we write in two places.

**The address comment** above a function or datum in the source. `/* 0x401230, moves an object to a cell */` above
`d2_MoveObj` says: our `d2_MoveObj` is the original's bytes at 0x401230.

**The declaration files, `decl/*.dcl`**, hold what has no place in the C source. Each line is one statement about an
address or a range of I, and its reason follows `--`:

```
0x401000 boundary start tu=net -- leaked by a log string
0x401230 start -- reached only through a table at 0x4a2000
0x4012f0..0x401300 bytes dead -- unreachable copy of the epilogue after a noreturn call
0x405000..0x405100 foreign kind=masm -- hand-written asm
```

| Line | Says |
|---|---|
| `boundary start` / `boundary end`, `tu=UNIT` | where a unit's bytes begin or end in I: φ for units |
| `start` | a function starts here, though no function of H has this address yet |
| `bytes dead` | no code reaches these bytes, such as an unreachable tail after a call that never returns. They belong to the surrounding unit, but no function of H accounts for them. |
| `foreign kind=K` | our C compiler did not make these bytes: hand-written assembly (`kind=masm`), for example. H's C code will never produce them. |

`bytes dead` and `foreign` lines both say: "these bytes of I have no counterpart in H's code yet, and this is why".
Other kinds of line declare names, tables, library units, and the `overrun` exception of 8.8. `src/decl.rs` has the
full grammar.

φ stops at objects. Which instruction of our function is which instruction of the original's is not φ: we do not
write it, and the experiment finds it by aligning the two functions (section 4).

### C comes from carrying things over

Through φ, H's structure becomes claims about I: "these bytes are unit `net`", "a function starts at 0x401230". For a
single instruction, the alignment (section 4) says which of the original's instructions ours stands for, and then
H's facts about it carry over too: "the call at 0x401250 goes to `d2_GetCell`". Analysis of I and experiments add
claims of their own (section 3).

### The toolchain is part of H

I_H is H's sources built by H's toolchain. The toolchain is a choice like the code: an experiment tests both at
once, and a wrong compiler version or flag fails experiments just like wrong code. A toolchain error usually shows as
many functions failing the same way, not as one bad function.

Derived claims rest on toolchain conventions (VC6 fill bytes, LINK places objects in order), so they are only as
good as H's toolchain. Evidence in the image supports that choice (the Rich header, the library code the toolchain
ships), and every passing experiment supports it further.

> **Running example.** The function body is **H**: a program whose build we know completely, not a claim. The
> address comment is **φ**: our object is the original's bytes at 0x401230. The **claims** follow from both: a
> function starts at 0x401230, these bytes belong to this unit, each call site goes to this callee, the signature
> is this one.

## 2. Claims and their kinds

**In short:** a claim is a statement about a byte range of I. Its kind says what it talks about.

A claim states something about a byte range **of I**, named by I's addresses:

| Claim | Kind | Value |
|---|---|---|
| "0x401230 is the start of a function" | start | yes |
| "0x401230..0x4012f0 belongs to `d2_MoveObj`" | owner | `d2_MoveObj` |
| "0x401000..0x405000 is made by unit `net`" | unit | `net` |
| "the field at 0x401251 refers to 0x402000" | ref | 0x402000 |

**Claims are always about I.** A claim that comes from H is about I too: φ carries H's structure over to I's
addresses (section 1). The bytes of I_H need no claims, because we know everything about them. What H says about a
part of I that φ does not map yet is nothing: there is no claim there.

### The kinds

The kinds are structural: about how the image was made, not about how we like to read it.

| Kind | A claim of it says |
|---|---|
| section | which section of the image the bytes are in |
| owner | which object the bytes belong to: a function, a global, a string, a table, fill, ... |
| start | whether a function starts here |
| unit | which unit made the bytes |
| ref | whether the field at this address is a reference, and to what |
| type | the type of an object, or a function's signature (parameters, return type, calling convention) |
| toolchain | which compiler, version or flag made the bytes |

**Most kinds have one value per byte.** A byte has one owner, one section, one unit. When something looks
multi-valued, the kind is made finer until it is not: "the target of the field at b", not "the references of b".
This is the simplest consistency rule (section 5).

**Types are partly observable.** Some type choices change the bytes (`short` against `int` parameters, one argument
more or less), others do not.

**Names and comments make no claims.** The bytes usually do not decide them (8.1). They are part of H, and this
model says nothing about them (section 9).

> **Running example.** "A function starts at 0x401230", "these bytes are unit `net`" and "the first parameter is
> `short`" are claims. "This function is called `d2_MoveObj`" is not: `d2_MoveObj` and `foo` build the same bytes.

## 3. Claims and support

**In short:** every claim carries a support level that says how hard it is to overturn, and claims stack instead of
replacing each other.

A claim is `(range, kind, value, support, why)`, where the range is a range of I's addresses. Its support
depends on where it comes from:

| Source | How | Support |
|---|---|---|
| **H through φ** | H's structure carried over to I. Nothing but our word supports it. An external analyzer's output (Ghidra's function starts) is the same: someone's word. | declared |
| **Analysis of I** | A rule over the bytes and other claims under a named **convention**: a toolchain convention (VC6 fill, LINK order), an encoding rule (an absolute memory operand is an address), a convention about how the original was written (it was consistent C, 8.8). Independent of H. | derived |
| **Reading I's format** | The image read under its format's specification: the section table, the base relocations, the export and import tables, the headers. | observed |
| **Experiment** | I_H compared with I through φ, passing. H's structure there is confirmed in the aspects the bytes discriminate (section 4). A placed library member is one too: the toolchain's archives are part of H, and the member's bytes are compared with I. So is the toolchain probe: a flag whose anchors stop matching under any other value. | reproduced |

No claim at all means **open**: nothing is known.

### What the order means

The order `declared < derived < observed = reproduced` ranks **how hard a claim is to overturn**, not how true it
is:

| To overturn a ... claim | it takes |
|---|---|
| declared | a better reason |
| derived | a place where the convention does not hold (an exception, section 5) |
| observed | a rule that misreads the format: a bug |
| reproduced | a *different* H that also reproduces the bytes, or a rule that compares wrongly: a bug |

Observed and reproduced share the top rank: two top claims that disagree are a bug in a rule, whichever they are.

**Nothing is proven.** A finished decompilation does not show what the original source was; it shows that a source
exists that rebuilds the image byte for byte. That is a complete and honest result, and it is all the bytes can give.

### Two rules for combining claims

**A rule's support** is the min of its ceiling and the support of each premise: a conclusion is no stronger than its
weakest input.

**Claims stack, they are not upgraded.** The address comment's claim stays declared forever. When the function
matches, the experiment adds a reproduced claim that agrees with it. If the match is lost later, the reproduced claim
goes and the declared one is still there.

> **Running example.** "A function starts at 0x401230" is declared: only the address comment says so. The analysis
> of I sees `call 0x401230` elsewhere in the original and adds the same claim, derived. Both stay; the answer
> (section 5) takes the stronger one.

## 4. Experiments

**In short:** an experiment compares I_H with I through φ over one object, and it supports only what would have made
it fail.

An experiment compares I_H with I through φ over one object and observes *equal* or *not equal*. It is an
observation, not a claim. A passing experiment yields reproduced claims; a failing one shows where H is wrong.

### An experiment supports only what could have failed it

- A function 10 bytes too long breaks the match, so a passing match supports the function's extent.
- `0x4a1230` and `g_foo` give the same bytes, so a passing byte comparison says nothing about whether that field is
  a reference, unless the experiment checks references as well (8.3).

### An experiment tests one thing and masks the rest

Whatever belongs to something else is masked. A relocated field's value is the address of another object, so it is
masked. Instead, the experiment checks that the field refers to the same thing on both sides: the field in I points
to φ(the target the field has in I_H).

### The alignment

φ says which function of ours to compare with which bytes of the original. To compare them, the experiment has to
know which of our instructions stands for which of the original's. It finds out by putting the two disassembly
listings side by side and lining up the instructions that agree, like a text diff (`dcp asmdiff` shows it):

```
ours (I_H)                     original (I)
push ebp                       push ebp          0x401230   equal run
mov  ebp, esp                  mov  ebp, esp     0x401231   equal run
...                            ...
call d2_GetCell                call 0x402000     0x401250   equal run: our call is this call
mov  eax, [ebp+8]              mov  ecx, [ebp+8] 0x401255   hunk ┐ the two sides differ here
add  eax, 4                    lea  ecx, [ecx+4] 0x401258   hunk ┘
ret                            ret               0x40125b   equal run
```

The **alignment** splits the two listings into **equal runs** and **hunks**, and it pairs instructions:

- **In an equal run**, each of our instructions is paired with the original's at the same place. The bytes show it.
- **In a hunk**, an instruction is paired only under a named convention (in a hunk of the same length on both sides,
  the instruction at the same position), or not at all. Unpaired, which instruction is which is open.

What the alignment is:

- **Part of the experiment, not of φ.** We do not write it and cannot edit it; it is what comparing produces. The
  grade is read off it, and the reference check uses its pairs: the original's field at the paired instruction must
  point to φ(our target).
- **No stronger than its pairing.** A claim carried over through a pair (the call at 0x401250 goes to `d2_GetCell`)
  is no stronger than the pair or than φ: an equal-run pair is as good as the bytes, a positional pair rests on its
  convention.
- **Evidence about φ.** If almost nothing lines up, the address comment is likely wrong.
- **One per function.** Everything that asks which instruction is which (the reference check, the grade, the branch
  check, `asmdiff`) reads the same alignment, so they cannot disagree.

### The hierarchy

| Experiment | Tests | Masks |
|---|---|---|
| **Object** (function, datum) | its bytes and the targets of its references | the values of relocated fields |
| **Unit** | the order of its functions, its data, its literals, its boundaries | the objects' own bytes (tested above) |
| **Image** | the order of the units and libraries, the fill between them | everything inside a unit |

How close a function's experiment comes is its **grade**: *byte* (the bytes match and every reference agrees),
*shape* (equal up to register allocation and scheduling), *draft* (neither yet).

> **Running example.** We compile `d2_MoveObj` and compare it with the bytes at 0x401230. Where it calls
> `d2_GetCell`, the call's field is masked and the check asks whether the original's call goes to φ(`d2_GetCell`).
> Equal: the extent, the control flow and the call targets become reproduced. Our name for the function was never
> tested, and it gains nothing.

## 5. Answers and contradictions

**In short:** the answer at an address is what its claims say, kind by kind, at their highest support. Claims that a
consistency rule says cannot all hold are a contradiction, one of five kinds of finding.

### Answers

"What is here?" is answered kind by kind:

| Concept | Definition |
|---|---|
| **Answer** for (byte, kind) | What the claims of that kind covering the byte say, at their highest support. For a kind with one value per byte, the one value they agree on. Open if no claim of the kind covers the byte. |
| **Confirmation** | Two claims of the same kind on the same bytes saying the same thing. |

### Contradictions and consistency rules

A **contradiction** is a set of claims, usually two, that cannot all hold. Which claims cannot all hold is said by a
**consistency rule**. Each rule has a name and is checked like any other rule, and the contradiction's finding names
the rule and its claims.

| Consistency rule | Says | Contradicted by |
|---|---|---|
| one value per byte | a kind with one value per byte has one value there (section 2) | two owners of a byte; two units of a byte; our field a constant where the original's refers (8.3) |
| a call goes to a start | the target of a call is the start of a function | a call into a function's middle (ref against owner) |
| a unit edge is between objects | a unit boundary does not fall inside an object | a declared unit edge inside a function (unit against owner) |
| a reference lands on an object | a near-certain reference of I does not point into bytes we give as padding | a reference into our datum's padding (8.7, ref against owner) |

The claims can be of one kind or of several. Two kinds of rule:

- **Rules from the meaning of the kinds**, such as one value per byte: a byte cannot have two owners. A violation
  means one of the claims is wrong.
- **Conventions**, such as a call goes to a start: the compiler emits code that way, but hand-written code may not.
  Like every convention, they take exceptions.

In practice a contradiction is almost always H through φ against an analysis of I, or two analyses against each
other.

### Resolving a contradiction

Of the claims a rule says cannot all hold, revise or drop the one with the least support. That usually means
changing H or φ. With equal support:

| Both sides are | What it means |
|---|---|
| declared | Ours to decide: two of our statements disagree. |
| derived | One convention does not hold there, and it needs an exception. |
| top (observed or reproduced) | A **bug**: one H cannot make both true, and the format reads one way, so a rule is wrong. |

An **exception** is a declared statement that a convention does not hold at one site, with a reason. It removes
the convention's premise there; it does not outvote it (8.8).

### Findings

Not everything the tool reports is a contradiction. A **finding** is one of five things:

| Category | What it says | Examples |
|---|---|---|
| **contradiction** | Claims that a consistency rule says cannot all hold. | two owners of a byte, a call into a function's middle, a hard-coded address where the original refers (8.3), a declared unit edge inside a function |
| **ill-formed** | H is no program, or φ is no mapping: the model cannot even be applied. | a unit that does not compile, a declaration line without its reason, a function of an object without its address comment, two of our definitions at one address without a reason the toolchain gives (8.7) |
| **gap** | Open where an answer is due: bytes nothing explains once the surroundings are laid out, a part of H that is missing. | unexplained code inside a unit, library code no member explains, an import library the toolchain does not have |
| **stale** | An observation older than H: the next build or lint makes it current. | a unit changed since its compile, a lint that did not parse today's text |
| **debt** | A regression of an experiment, allowed only when declared (8.6). | a debt item with its witness; more of them than the gate allows |

The **gate** (the check that work must pass before it lands) fails on errors of any category. A contradiction
between two top claims is a bug.

> **Running example.** Suppose our address comment said 0x401228 while the original has `call 0x401230`. Then our
> function owns 0x401228 onwards, and the call goes into its middle: "a call goes to a start" is contradicted. The call's
> reference is derived and our address comment declared, so the address comment is changed.

## 6. Done

**In short:** the work is done when I_H = I, and then φ is no longer needed.

**I_H = I.** H builds the original image byte for byte. Then H places every object at its original address, φ is the
identity, and the address comments only restate where the build puts things. Every structural answer is reproduced
and no contradiction is left.

That φ disappears in the end is a check on the model: the finished state needs no separate mapping, because the
program is the explanation of the image.

> **Running example.** The build places `d2_MoveObj` at 0x401230 by itself. The address comment now restates what
> the build does.

## 7. Working

**In short:** we only ever edit H and φ, first making the answer total (layout), then strong (match).

We only ever edit **H and φ**. C follows. The loop:

```
edit H and φ ──▶ build I_H, run rules and experiments ──▶ C: answers and findings ──▶ edit H and φ
```

### Layout first, then match

**Layout** and **match** are two strategies in this loop, not two kinds of work:

- **Layout** builds H's skeleton and φ until φ covers every byte: the unit files in the original's order, a draft
  (or `@rough`) per function, the boundaries, the starts, the dead bytes. Its claims are declared (from H through φ)
  and derived (walk, fill, literal order, leaked paths). The answer becomes **total**.
- **Match** changes H until experiments pass. The answer becomes **strong**.

Layout comes first for three reasons:

- **Conventions need neighbours.** Fill between contributions, contiguity (a function owns its bytes up to the next
  start) and literal order work only once the surrounding starts and units exist.
- **The consistency rule needs every user.** A type carried from a matched caller (8.8) only reaches callers that
  exist in H.
- **Totality shows the gaps.** Once φ covers every byte, what is unexplained is visible.

### Queues and tiers

Match work is handed out as **queues** over the grades:

| Queue | Holds |
|---|---|
| base | the meaning: every function below shape + readable |
| deep | allocation and scheduling: every function below byte, or tagged `@deep` / `@stuck` |
| names | the names |

A queue item is no claim: it is a view of C that says who should edit H next.

Each base item also has a **tier**, easy or hard, so that weaker workers take the easy work and stronger workers the
rest:

- **Easy** is a prediction from the grade alone: readability-only work on a function of modest size, or a code
  draft of a short function that is already close to the original (`[queue] easy_max_bytes`, `easy_max_dist`,
  `easy_read_max_bytes`).
- **Hard** is everything else, and every function a worker *handed up* with `@hard why`: base work that this
  worker could not finish. The tag corrects the prediction from the outcome. It keeps the function in the base
  queue, and shape + readable ends it. Every deep item is hard.
- The prediction is checked against outcomes: each wrap counts the functions raised and the hand-ups
  (`@hard`, `@deep`, `@stuck`). The bounds are tuned from those counts, not guessed.

## 8. Cases

Each case applies the ideas above to one situation that comes up in practice.

| Case | Situation | What it teaches | Builds on |
|---|---|---|---|
| 8.1 | a function's name | why names make no claims | 2, 4 |
| 8.2 | a field that may be an address | how analysis of I claims references | 3 |
| 8.3 | `*(int *)0x4a1230` in a matching function | equal bytes are not enough | 4, 5 |
| 8.4 | replacing it with `g_foo` | each experiment tests its own object | 4 |
| 8.5 | a header change that costs a match | our judgment against an experiment | 3, 4 |
| 8.6 | allowing that loss | knowledge never regresses, debt is declared | 5 |
| 8.7 | one string used in many places | when φ may be many-to-one | 1, 5 |
| 8.8 | one prototype, many callers | conventions across objects, exceptions | 3, 5 |

### 8.1 Names do not become claims

`UpdateViews` or `foo`: same bytes. No experiment could catch a wrong name, so H's names are not carried over as claims.

Names reach the claim system only when the image itself holds them (exports, imports, `__FILE__` strings): then a
name is part of what an analysis of I reads.

### 8.2 Reference claims from static analysis

An analysis of I can claim that a field is a reference, independent of H. The evidence comes in tiers:

| Tier | Evidence | Support |
|---|---|---|
| Exact | The image's base relocations, where present: complete and exact. Not an analysis but the format read (section 3). | observed |
| Near-certain | Branch targets (`call rel32`, `jmp rel32`). Absolute memory operands (`mov eax, [0x4a1230]`, `[ecx*4 + 0x4a1230]`): in non-PIC 32-bit code nothing but an address goes there. | derived |
| Strong | An immediate (`push 0x4b0010`, `mov reg, 0x4b0010`) or an aligned dword in data that equals the start of a known function, string or data object. Convention: "an immediate equal to the start of a known object is its address". | derived |
| Ambiguous | An immediate inside the image that lands on nothing in particular: `&arr[5]`, a field, or a flag mask that happens to be in range. | open; an exception or H decides |

"Is a ref" can be derived. "Is not a ref" cannot, unless the image has base relocations: looking like a number is
not evidence.

### 8.3 A hard-coded address in a matching function

**Situation.** H writes `*(int *)0x4a1230` where the original refers to `g_foo`. The function's bytes match.

**The claims.**

- **H through φ**: the alignment pairs the instruction in an equal run, so H's fact about the field carries over. In I_H the field is a constant, so
  the claim is `ref(b) = none`, declared.
- **Analysis of I**: an absolute memory operand, so `ref(b) = g_foo`'s address, derived.
- Two values for the target of one field: a **contradiction** (one value per byte). H has less support and is
  changed.

**Why the match does not help.** Constant and reference give the same bytes. The object experiment that checks
references does catch it, wherever the image tells which fields are references: with base relocations directly,
without them through the derived ref claims.

**The lesson.** Equal bytes compare the program at one layout. The real criterion is that H reproduces I **for every
layout**: equal bytes with relocated fields masked, and the same reference targets.

**The limit.** Differences that survive any relinking, like `0x10` against `FLAG_VISIBLE`, cannot be caught. The
bytes cannot see them, so they are outside the model, like names (section 9).

### 8.4 Replacing the hard-coded address with the symbol

**Situation.** We write `g_foo` instead of `0x4a1230`. Our linker does not put `g_foo` at 0x4a1230 yet, so the
linked bytes differ.

**What the model says.**

- **The function's experiment** still passes: the field is a relocation now, its value is masked, and the
  reference check asks whether the original's field points to φ(`g_foo`). The address comment on `g_foo` says
  φ(`g_foo`) = 0x4a1230, so it does.
- **H through φ** now claims `ref(b) = g_foo` and agrees with the analysis: the contradiction is gone.
- **The wrong placement** belongs to `g_foo`, not to the function: φ says 0x4a1230, I_H puts it elsewhere. That is
  `g_foo`'s experiment failing, and it is fixed by the data layout.
- **If `g_foo` has no address comment yet**, φ(`g_foo`) is undefined and the reference check cannot be decided:
  open, not failed. Giving `g_foo` its φ settles it.

**The lesson.** The change is a strict improvement. If the function's evaluation got worse, its experiment would be
testing something that belongs to `g_foo`.

### 8.5 A header restructure that costs a match

**Situation.** A function matches. We restructure headers because the new layout is clearly better. VC6's register
allocation shifts and the match is lost.

**What the model says.**

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

**The lesson.** The experiment outranks our sense of order. Whether we may accept the loss for now is 8.6.

### 8.6 Regressions without getting stuck

**The problem.** A rule that forbids any lost match blocks progress: the right header arrangement is often easier to
find once more is settled, and a strict rule locks the project into a local optimum.

**The way out** is to separate two things:

| | Can it go down? |
|---|---|
| **Knowledge about I**: reproduced claims from any witness, past or present | No. It only grows. |
| **Quality of the current H**: do its experiments pass? | Yes, temporarily. |

**A witness does not expire.** A witness is an (H, φ) whose experiment passed: an old commit. Once one exists, it is a
fact about I that a source with that extent, those references and that structure rebuilds those bytes. The header
restructure in 8.5 costs the current H a match; it costs no knowledge.

**The rule is "never regress silently"**, not "never regress":

- A regression is allowed when it is declared: which object, why, what it waits for, the last witness commit.
- It becomes a **debt item**: listed, counted, not a gate failure.
- An unexplained regression fails the gate.
- Debt is bounded (at most N open, each naming what it waits for), so it does not pile up.
- The last witness stays available to diff against.
- A re-match pass walks the debt once the structure settles. Many small shifts share one cause (one prototype, one
  declaration order), so they come back together.

### 8.7 Several symbols at one address

**Situation.** Some toolchain behaviour gives one address several objects of H:

- **String pooling** (`/GF`): identical literals `"error"` in different places of H become one string in I.
- **Identical COMDAT folding** (`/OPT:ICF`): functions or const objects with identical bytes are folded into one body.
- **Aliases**: two declarations naming the same datum.

**φ is many-to-one here, and that is no contradiction.** Several objects of H map to one range of I. The structural
answer stays single: `owner(b)` is one object, because I holds one string or one body. H's toolchain explains the
folding, and at the end I_H folds them the same way, so the experiment checks it.

Each site that uses `"error"` or `foo_a` has its own ref claim with the same target: different sites, one value
each.

**Many-to-one needs a reason.** It is legal only when the toolchain or the image explains it: a fold the toolchain
makes, an alias that is declared, the image's own spellings of one object (an export and its library symbol, the
CRT's decorated user entry). Two of our own definitions at one address without such a reason are not φ being
many-to-one. They are φ being ill-formed: one of the two address comments is wrong.

**What stays open: which unit's copy the linker kept.** The bytes are identical whichever unit wins, so no
experiment can tell (section 4). The unit answer stays declared, or derived where a link-order convention decides
it. That is the model saying "the bytes cannot know", not a gap.

**Not the same thing: containment.** An object of H that φ maps into another object's range (`g_x` = `&arr[3]`, a
struct field) is no second owner. The owner is the outer object, and uses of the inner one are references with an
offset.

Containment holds both ways:

- **A reference of H must stay inside its object.** A reference at `sym + N` outside sym's declared size (sizeof;
  one past the end is inside) is no address of sym. H is ill-formed there (`M.contain`), whatever the bytes compare,
  because the sum moves with sym when relinked: `&cm_SendRing + 0x4973c0` is the constant 0xf00500.
- **The compiler's own arithmetic is exempt:** an indexed displacement, and a loop's pointer one element past either
  end.
- **A view past its container** is the same case (`D7`).
- **A near-certain reference of I into our padding** (bytes our object gives a datum as padding) contradicts H's
  layout on the owner (`D9`): the datum is larger, or an object of its own is missing there.

### 8.8 Consistent declarations and `@original`

**The convention.** The lint (`dcp lint`: clang as a type checker over the units) is not a readability check. It is
an analysis with a convention about how the original was written:

> The original was consistent C: each function and object had one declaration, and every use agreed with it.

That holds almost everywhere; few prototypes in the original were superseded by local views.

**It connects claims across objects.** A passing experiment supports a type where the bytes discriminate: a caller
that matches only when it passes `short` arguments supports `d2_MoveObj(short, short, int)`, reproduced. The
convention carries that to the declaration and to every other use, derived. A caller in H that passes an `int`
contradicts it before its own experiment fails, and also where its own experiment could not tell. That is how the
rule catches mistakes early: it moves evidence from where the bytes decide to where they do not (yet).

**The exceptions**, each declared at one site with a reason:

| Exception | Says | Its evidence |
|---|---|---|
| `@original why` | The original itself was inconsistent here: it called the function through another spelling. | The matched caller, whose bytes would change with the consistent spelling. |
| `@vc6 why` | The checker's model of C (clang) differs from H's toolchain at this site. The gap is in the checker, not in H. | |
| `0xADDR overrun -- why` (decl/text.dcl) | The original's access at that instruction overruns its object (against the extent convention, S.extent: a pointer stays inside its object). | The rest of I that contradicts the overrun extent. |

Like every exception, `@original` removes the convention's premise at that site; it does not outvote it. Its
spelling stays in the unit that needs it (a cast macro in the unit's head), never in a shared header: two headers
that disagree cannot be included together.

The overrun exception, in detail: `memset(f.talent, 0, 6 * sizeof(int))` clears one int past a five-int field.
Without the exception, the overrun proves the object and its neighbour one object (D8) and moves H away from the
bytes: the record copies elsewhere still say 0x2c. Here the evidence is the 11-dword copies of the record. It is
declared on I's instruction because H has no line for it. One whose instruction proves no extent is stale.

**What follows for every exception:**

- **An exception must discriminate.** `@original` is valid only if the consistent spelling changes the bytes. A tool
  can check it: build the variant without the exception and compare. If the bytes stay the same, the exception has no
  evidence. (`improvement-reports/detect-nested-call-in-arguments.md` is such a case: an `@original` for a
  "six-argument call" whose real cause was a nested call.)
- **Exceptions go stale.** When H changes, the experiment behind an exception is rerun; one that no longer
  discriminates is flagged.
- **Exceptions are visible and counted**, like debt items, each naming its evidence.

## 9. Outside the model: readability

**In short:** readability judges H as source code. It makes no claims about I and never overrides the model.

This model is about one thing: how H corresponds to the original. Everything in it is a statement the original's
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

**The test** is the one from section 4: could the original's bytes ever decide it? If yes, it belongs to the model;
if no, it is readability.

## 10. The model in the code and on the command line

The source names the model's concepts, and the command line speaks them:

| Model | Code | Command line |
|---|---|---|
| a claim `(range, kind, value, support, why)` | `store::Claim` (the `claim` table): a range, a kind, a value, a `Support`, its producer and reason | `dcp claims RANGE [--question Q] [--support S]` |
| support | `store::Support`: `Open`, `Declared`, `Derived`, `Observed`, `Reproduced` (`is_top`: observed or reproduced); a rule's `max_support` | `support=` on every claim |
| the kinds of claim | `store::Question` (named question in the code): section, owner, start, unit, ref, toolchain; `Question::kinds` names the stored kinds of each (`symbol` / `region` / `source` the owner, `unit` / `boundary` the unit) | `dcp claims --question` |
| what a stored kind is | `store::role`: a claim of a kind, φ (`name`), an experiment (`experiment`), readability (`readability`), H's build (`build`), a rule's intermediate result (`evidence`) | `role` in `dcp claims --json` |
| the answer | `answers.rs` (the `answer` table): per run of bytes the owner at its highest support, the unit, the H object, the section; `answers::stacked` per kind | `dcp answers [RANGE]`; `dcp why ADDR` by kind, the answer first and the claims stacked under it |
| φ | `phi.rs`: built from the `name` claims (address comments, declarations, library members, exports, imports, the user entry); `Phi::of(name)` and `Phi::at(addr)`; `Phi::many` with `many_reason` | `dcp phi [ADDR\|NAME] [--many]`; φ in `dcp why` |
| the alignment (§4) | no one type yet (see below); the nearest is `diffclass::Cuts`, the cut correspondence of one function's two listings (`Cuts::pairs`), which the branch check reads | `dcp asmdiff`, `dcp diffclass` |
| a finding and its category | `Finding` (the `finding` table); `registry::Category` and `registry::CHECKS` give every check id its category; `registry::floor`: an ill-formed check is never below error | `dcp findings [--category C]`; `dcp check` counts per category and lists the errors grouped by category |
| the object experiment | `M.match` (the byte criterion) and the reference check (`refcheck.rs`: each relocated field of ours that lines up against φ(its symbol), a literal by its bytes; equal, different or open), `G.grade`'s `experiment` claim (outcome byte / shape / draft, or open when the unit has no object: not run, no fall, one M1 line per unit; the failing B rules, the distance, the consistency calls, the open references) | `dcp grade`: `experiment=`; `dcp asmdiff` / `dcp diffclass`: `ref:` / `literal:` |
| a placed library member | `S.crt.code`, `S.crt.data`, `S.lib.data`: reproduced | |
| a reference the byte comparison cannot see (8.3) | `A1` (a cast the source scan sees), `M.ref.missing` (an absolute operand our bytes hold as a constant), `M8` / `M9` / `M10` (the reference check's findings on a byte match: our reference against the original's target through φ, a literal by its bytes), `D6` | `dcp findings --category contradiction` |
| readability (§9) | `readability.rs` (Q1..Q6, Q8), `G.grade`'s `readability` row, apart from the experiment | `dcp grade`: `readability=` |
| an exception | `exceptions.rs`: `@original why`, `@vc6 why` with their reasons; `0xADDR overrun -- why` in decl/text.dcl (an instruction of I has no line in H) | `dcp exceptions` |
| a queue item and its tier (§7) | `queues::queue` (base / deep / names), `queues::tier` with `queues::Tiers` (`[queue]`); the `@hard` tag (`level` hard: still base work) | `dcp next [--deep\|--names] [--tier easy\|hard]` (`tier=` per item, `easy=` / `hard=` counts); `dcp escalate NAME --hard "why"`; the wrap's `hand-ups:` line |
| H's build without dcp | `export.rs`: the link's `LinkPlan` (link.rs) with the units and their flags as data, `export/<target>.json` and the inputs dcp generates (entry stub, alias object, import library) in `export/<target>/`; paths outside the project are spelled with a name of `[paths]` (`decompanion.local.toml` gives a machine's own directories) or `{toolchain}/...`. The archives dcp writes carry no time stamps (`coff::archive_without_times`), so the export only changes when H does | `dcp export`, `dcp export --check` (stale / missing / extra files, exit 1) |
| debt, a witness | the accepted column of `ledger/grades.tsv` (`queues::Debt`: the grade before and now, the witness commit, why, what it waits for); `M1.debt` lists them and bounds them by `[gate] max_debt` | `dcp debt add NAME --to G --why W --waits-for X`, `dcp debt list` |

What the code does not do yet:

| Model | Today |
|---|---|
| An answer per (byte, kind) | The `answer` table holds the owner, the unit and the section; `ref`, `start` and `toolchain` are answered per address on demand (`dcp why`), not kept |
| One alignment per function | Several readers align the listings themselves: `refcheck::sites_aligned` (its own pairs: equal lines, same-mnemonic lines of equal-length hunks), `diffclass::compare_tables` (its own map of the equal runs), asmdiff's `diff_lines` (frame-masked), besides `Cuts`; they can pair an instruction differently (tasks/normalized-alignment.md) |
| Every contradiction names its rule and its claims | The consistency rules are checks of category contradiction (`L13`, `C.walk`, ...), each computing its own predicate; a finding names the producers (`a=`, `b=`), not the claim rows |
| The kinds of claim | They are called questions: `store::Question`, `dcp claims --question`, `dcp why` by question |
| Unit and image experiments | Unit boundaries rest on the evidence rules (`L.analyze`: fill, literal order, leaks) and D4's definition order; there is no explicit unit experiment |
| Types are claims | `M.lint` reports clang's M5 / M6 / M7; types are no claims of their own |
| An exception must discriminate (8.8) | `dcp exceptions` lists them and counts the ones without a reason; that the consistent spelling would change the bytes is not checked (a trial build without the exception) |
| Warnings | Not part of the model: hints, not findings; they stay lint output |
| A stale export is a finding | `dcp export --check` reports it and fails; no rule emits a stale finding for it, so `dcp status` / `dcp check` do not show it |

## Glossary

| Term | Meaning | Section |
|---|---|---|
| alignment | the experiment's pairing of our instructions with the original's: equal runs and hunks | 4 |
| answer | what the claims of one kind on a byte say, at their highest support | 5 |
| bug | two top claims that disagree: a rule is wrong | 3, 5 |
| C, claim | `(range, kind, value, support, why)`: a statement about a byte range of I | 1, 2, 3 |
| containment | an object of H inside another object's range: a reference with an offset, not a second owner | 8.7 |
| consistency rule | a named rule that says which claims cannot all hold | 5 |
| contradiction | claims that a consistency rule says cannot all hold | 5 |
| convention | a named regularity an analysis of I relies on (VC6 fill, LINK order, consistent C) | 3 |
| dead bytes | bytes of I no code reaches, declared with `bytes dead` | 1 |
| debt | a declared regression of an experiment, with its witness | 5, 8.6 |
| declaration (`decl/*.dcl`) | a line of φ about an address or range that has no place in the C source, with its reason | 1 |
| declared / derived / observed / reproduced | the support levels, from easiest to hardest to overturn | 3 |
| exception | a declared statement that a convention does not hold at one site, with a reason | 5, 8.8 |
| experiment | I_H compared with I through φ over one object: equal or not | 4 |
| finding | what the tool reports: contradiction, ill-formed, gap, stale or debt | 5 |
| foreign bytes | bytes of I our C compiler did not make (hand-written assembly), declared with `foreign` | 1 |
| gap | open where an answer is due | 5 |
| gate | the check that fails on errors of any category | 5 |
| grade | how close a function's experiment comes: byte, shape or draft | 4 |
| equal run, hunk | a stretch where both listings agree; a stretch where they differ | 4 |
| H | our source and toolchain: everything we write that builds an image | 1 |
| I, I_H | the original image; the image H builds | 1 |
| ill-formed | H is no program or φ is no mapping | 5 |
| kind (of claim) | what a claim talks about: section, owner, start, unit, ref, type, toolchain | 2 |
| layout / match | the two strategies: make the answer total, then strong | 7 |
| open | no claim covers it: nothing is known | 3 |
| φ | which object of H is which part of I, as we state it | 1 |
| queue, tier | who should edit H next; easy or hard work | 7 |
| readability | H judged as source code, outside the model | 9 |
| relocation | a field whose value is another object's address, filled in by the linker | 1 |
| stale | an observation older than H | 5 |
| unit | one source file of H compiled to one object; a contiguous stretch of I | 1 |
| witness | an (H, φ), an old commit, whose experiment passed | 8.6 |
