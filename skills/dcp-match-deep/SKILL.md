---
name: dcp-match-deep
description: Run one match-deep session of a decompanion project - take functions from the deep queue (dcp next --deep) one at a time and bring each to byte by trying source variants (dcp try) and reading the frames (dcp frame), keeping what each round taught in the function's @deep note (dcp note). An item ends byte + readable or with its meaning bug fixed, never otherwise; it has no time limit. A session is 4 items. Use when the user says "match-deep", "/match-deep", "dcp-match-deep", "deep pass" or "work the deep queue".
argument-hint: "[items=4]"
---

# Match-deep session: 4 items, the main checkout

Goal: every item of `dcp next --deep` to **byte + readable**: our compiled function identical to the original's
bytes, from a source that still means what the original does and reads clean. Deep items are already shape or
close to it; what is left is mostly register allocation, stack slots, instruction order and the spelling VC6
needs to choose the original's code. A deep item that turns out to differ in **meaning** is a bug in our C:
fixing it matters more than the bytes (section 3).

Items: `$ARGUMENTS` (`items=N`; nothing given is 4).

Hard rules
- The hard rules of the dcp-match-base skill apply unchanged (tools, files, the sources as the state, no grade
  may fall, never an address of the original in code). Read its "Hard rules" once if you have not.
- An item ends in one of two ways only: **byte + readable** (section 2.6), or **its meaning bug fixed** (section
  3). Until then the item is not done, the next item is not taken and the session does not end. There is no
  time limit on an item, and neither the time spent nor the number of rounds run is ever a reason to stop or to
  move on.
- Every variant is tried with `dcp try` (section 2.3), not by editing the tree and rebuilding: it compiles in
  scratch copies of the unit and writes nothing. The tree changes only for the variant you keep
  (`--apply LABEL`, or an editor), then `dcp build`.
- The source you keep must mean what the original does, and a reader must still follow it: no `volatile`, dead
  stores, `goto`s or register tricks without an `@original` comment saying which original quirk they reproduce.
  A spelling that only reproduces allocation (a declaration order, a loop form) needs no comment.
- Never edit `ledger/tiebreak.tsv` or `ledger/attempts.tsv` by hand: dcp writes them; you commit them.

## 1. Start

1. `dcp session start --kind match-deep` (the gate, as for match-base). When it says it counted an unfinished
   attempt (an earlier session ended inside its item), commit `ledger/attempts.tsv` (`session: unfinished
   attempt of <name>`).
2. `dcp next --deep`. It hands out this session's item and keeps handing out the same one until it is done. The
   line says `attempts=N` (how many earlier sessions took it and ended without finishing it), `why=@deep` (the
   note in its address comment: what earlier sessions found and tried, older text as `prior:`) or `why=untagged`
   (below byte in a unit whose base work is done: nobody has tried it, there are no notes).
3. Read the item's `@deep` note whole before anything else. Do not repeat a round it records; start from where it
   ends (its best variant, the hunks it names as left, the mechanism it describes).
4. Read the project's matching guide whole if it has one (e.g. `notes/vc6-quick.md`): it is the method for this
   compiler. Where it says what to do before the first variant and which rounds to run, that is binding here. Its
   reference (e.g. `notes/vc6-matching.md`, grouped by the symptom seen in the diff) is searched by the hunk class
   and the construct you face.

## 2. Work loop: one item at a time, always the first

### 2.1 Read where it stands
- `dcp grade NAME`: the gates, `dist`, the `declaration set:` line (2.2), `census:` / M8 / M10 lines.
- `dcp asmdiff NAME --changed` (`--regs auto` when only a register renaming is left), `dcp diffclass NAME` (the
  hunk classes and `proof:`).
- `dcp fn NAME` prints the function with its file lines (`at=src/<unit>.c:FIRST-LAST`).
- `dcp asmdiff NAME --changed --lines`: each of our lines with the source line VC6 compiled it from (`; unit.c:LINE`),
  so a hunk points at the statements a variant has to change. `dcp listing NAME`: VC6's own listing of the function
  (offsets, bytes, `; Line N`, its frame symbols `_x$ = N`).

### 2.2 The declaration set is dcp's, not yours
VC6 breaks some allocation ties by the count of declarations before a function, so a header or an unrelated
declaration can move a function's code without its text changing. dcp settles that by itself: `dcp grade NAME`,
`dcp build` and `dcp try` compile a close function's text under every declaration-set shift and say one of two
things on the `declaration set:` line (in `dcp try`: `declaration set of <variant>:`):
- **this text is byte under a declaration set (named): done (proven byte)**: the item is done (2.6). Commit the
  text with `ledger/tiebreak.tsv`.
- **no declaration set makes this text byte: the difference is in the text, go on**: what is left is in the
  function's text. Work it (2.3).
There is nothing else to measure and no other reading of it: the declaration set is never a reason to leave an
item.

### 2.3 Variants (`dcp try`)
Write the variants you want to compare into a scratch file (not in the tree), each starting with `### label`:

```text
### index-loop
<<<
    for (p = list; *p; p++)
===
    for (i = 0; list[i]; i++)
>>>

### whole-function
/* 0x4ac170 */
unsigned short f(unsigned short k)
{
    ...
}
```

A `<<< old === new >>>` block replaces text inside this function only (each old text must occur once in it: a
twin function's equal lines are never touched); a body without blocks is the function's whole new text (its
first comment only marks it as such: `--apply` keeps the function's own address comment and note). Then
`dcp try NAME FILE` prints one row per variant: `grade ins bytes code hunks`. `code` is a hash of the compiled
function: variants with the same code print `= label`, and a variant with the control's code means that source
lever does nothing for VC6 here (drop it). `BYTE` marks a byte match. The closest row, when it is close, gets its
`declaration set of <label>:` line (2.2). Generators: `dcp try NAME --move-line N --to A..B` moves file line N (a
declaration) before each line of A..B. Keep a variant with `dcp try NAME FILE --apply LABEL`, then `dcp build`,
`dcp grade NAME`.

Work in rounds: one lever per round (declaration order, loop form, operand order, if/else order, a temporary
introduced or removed, a narrower or wider type), many variants per round, keep the best, repeat. Generate the
variants file with a small script when a round has more than a handful (all orders of a run of statements, every
position of one statement, the product of two or three choices).

Choose between variants by WHERE they differ from the original, not by the count alone: `best:` and the `ins`
column rank by distance, but a variant with the original's block layout at a larger count can be one step from
byte, and a small count behind an unusual construct (a `goto`, a `volatile`, a hand-advanced pointer) is usually
a local optimum. Read a variant's instruction diff before keeping or dropping it when it changes the layout (the
project's variant-diff tool if it has one; else apply it, build, `dcp asmdiff`, revert). The lever is often not in
the hunk's own statement: another `return`, a declaration's scope, a statement far above.

### 2.4 Stack slots (`dcp frame NAME`)
When `slots` / `frame` hunks are left, `dcp frame NAME` lists both frames: each of our slots as `[esp+X]` after the
prologue (`[ebp-X]` in an ebp frame) with the variable VC6 put there (from its listing; `buf+0x8` inside an array,
`a/b` for locals VC6 packed into one slot), its size and use (`array`, `rN wN`), the original's slots the alignment
pairs it with (`<- moved`, `<- several`), the original's slots no slot of ours pairs with, `shared in the
original:` (one slot of the original for two locals of ours, named: their lifetimes do not overlap there, so VC6
packed them), and the holes. The locals' sizes, how often each is referenced and their scopes decide the layout
(VC6 does not follow the declaration order): merge or split locals, change an array's size or element type,
declare a local that is only used inside a block in that block, add or remove a reference, until the frames agree.

### 2.5 The journal: `dcp note` after every round that taught something
The item's `@deep` note is what the next session starts from if this one ends inside the item. After every round
that taught something (a lever that moved the code, one that provably does nothing, the mechanism behind a hunk),
write the note anew: `dcp note NAME "..."` with what the original does at the hunks left, the mechanism that
decides them, each round with its best row (`dcp try` rows: "index loop: shape, 9 ins; for-init: = control"),
the best variant kept, and the exact hunks left (`asmdiff` lines). Each `dcp note` of this session replaces the
session's own earlier text; the note as the session found it stays as `prior:` by itself (do not repeat it). Keep
it to what the next reader needs, not a diary. Commit the note with the work it describes.

### 2.6 Done
- **Byte + readable** (built byte, or proven byte under a declaration set: 2.2): commit `<unit>: <name> byte
  (match-deep)`. The build clears the tag. That is the item; take the next.
- **Not byte yet**: the item goes on. Keep the best variant when it builds and nothing got worse, update the note
  (2.5), and run the next round. When you run out of ideas, that is the moment to widen the search, not to stop:
  - go back to the project guide's rounds and run every one you have not run on this item, in its order;
  - read the instruction diffs of the far variants too, not only of the best rows: a variant that moved the
    layout the original's way at a larger count shows where the lever is;
  - use the compiler-tracing tools the project has (e.g. a listing, a trace of the allocator's choices, a
    variant-diff tool) on the hunk that is left, until you can say which value gets which register or slot and why;
  - re-read the original at the hunks left, and the statements far above them: another `return`, a declaration's
    scope, a temporary, the order of two statements that compute one value.
  A round that leaves the code unchanged tells you which levers VC6 ignores here; write that into the note and
  take the next lever.

## 3. A meaning difference is a bug: fix it first
Deep items were escalated as allocation-only, but the reading may have been wrong. When `dcp grade NAME` or
`dcp diffclass NAME` names a concrete difference (`census:`, `witness:`, an M8 / M10 that is not `(crossed: ...)`,
`differs:`, a branch without a proof), or your reading finds a wrong index, field, constant, call or condition:
fix the meaning before any variant work. Commit it on its own (`<unit>: <name> fix: <what was wrong>`), with the
evidence in the message. It counts as the item.

## 4. VC6 lessons (add what you find to the project's notes, not here)
- VC6 packs locals whose lifetimes do not overlap into one stack slot, and splits local structs into fields (some
  in registers, some in memory). A frame 4 bytes short per vector usually means the original used a 4-float vector
  type.
- `x /= n` with a constant n compiles to a reciprocal multiply; `test ah,5 / jp` against `and eax,0x100 / je`
  follows how the condition is written (`>=` against a negated `<`).
- A literal used in two distant statements can get a callee-saved register; a `const` local is folded and never
  does.
- Two constants of one expression are folded into one literal (`0.1f * (1/60.f)`): when the original loads both,
  they sat in separate statements. An operand in `.rdata` only this unit uses is often a `static const`.
- Register allocation follows which values are allocation candidates (named locals, repeated constants, common
  subexpressions) and how often each is referenced; the declaration set only breaks ties, and dcp settles those
  (2.2).

## 5. When to stop
A session is **4 items**, each byte + readable or fixed (one commit each, besides the note updates), then the
wrap-up, however long the items take. Do not hurry an item to get to the next one or to finish the session. The
session does not end, and the next item is not taken, while the current item is neither byte + readable nor
fixed.

## 6. Wrap up
1. `dcp build` exits 0; the tree holds only committed work.
2. `dcp session wrap` (it must say `gate: ok`), commit `session: match-deep wrap (<units>)` (with
   `ledger/attempts.tsv` when the wrap wrote it).
3. Final message: each item with its outcome (byte / fixed, and how), the levers that moved code and the ones
   that never did, tooling problems met (for the orchestrator's reports), the next `dcp next --deep` item. Stop.
