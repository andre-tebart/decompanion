# Containment: references and views stay inside their object

- **Priority:** P0 · **Size:** M · **Root:** R2

## Problem

- `&cm_SendRing + 0x4973c0` (the constant 0xf00500) prints as `=` ("an alias: no error") and passes M8.
- D7 never flags `&d3_MipSkip + 1` on a one-byte char.
- The original's absolute operands land in bytes that our data layout calls padding or "room". Nothing reports it.
- `dcp why 0xf00500` lists a test mask as a site-reproduced ref into `cm_SendRing`.

## Root cause

- `same_values` (asmcmd.rs:53-112) and M8 resolve sym+addend arithmetic and accept any result.
- D7 (rules.rs:1019-1053) compares against the COFF size. That size is the distance to the next symbol, padding
  included (coff.rs:360-387).
- No rule compares a near-certain ref of I with H's declared extent.
- `site_confirmed` accepts a relocated field that matches an *immediate* as reference evidence.

## Task

1. An H reference or view at sym+off that lies outside sym's declared C size is ill-formed: no containment (§8.7).
   - The size is sizeof from the front end; one past the end is allowed.
   - Run it for every compiled function, not only matched ones.
2. A near-certain ref of I (an absolute memory operand) into bytes that H calls padding or room is a contradiction on
   the owner question. `dcp data map` lists such addresses under the room, with user counts.
3. `site_confirmed`: an immediate equal to our relocated field is no reference evidence, unless the image's base
   relocations say so (§8.2, ambiguous tier).
4. asmdiff's `same_values` must not print `=` for an out-of-object target.

## Rejected

- A separate asmdiff class for this.
- "Split the object by access" as a rule. At most a hint (§8.2, ambiguous tier).

## Model

- §8.7 containment.
- §8.3: equal bytes hold at one layout only.
- §8.2 tiers.
- §4: an experiment supports only what would have made it fail.

## Reports

- asmdiff-reloc-vs-immediate-equal (part 2)
- lint-symbol-plus-offset-immediate
- data-view-past-object-end-unflagged
- data-map-undeclared-refs-in-room
- data-size-vs-original-extent
- data-split-object-by-access (hint)
- dump-unaligned-unknown-labels
