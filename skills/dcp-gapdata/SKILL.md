---
name: dcp-gapdata
description: Run one gap data session of a decompanion project - take the gap blocks the code uses (the full_data_<addr> / full_rdata_<addr> GAPDATA arrays no symbol covers yet) one datum or record family at a time and settle its name, type, extent and owner unit, so every access is typed before deep matching starts. A view macro or a raw access the type change moves is read against the original and either fixed (a data bug) or kept as an @original why view when the original itself is inconsistent. Options scope=used|all (default used) and unit=NAME. A session is 8 groups. Use when the user says "gapdata", "/gapdata", "dcp-gapdata", "gap data pass" or "resolve the gap blocks".
argument-hint: "[unit=NAME] [scope=used|all]"
---

# Gap data session: 8 groups, the main checkout

Goal: **every gap datum the code uses becomes a typed object** - a name, a type, its own extent and its owner
unit. The gap blocks (`full_data_<addr>` / `full_rdata_<addr>`, arrays of `GAPDATA`
(`__declspec(align(1)) unsigned char`), defined in the gap block at the end of `src/main.c` and declared
`extern GAPDATA` wherever used) are bytes no symbol covers: their place in main says nothing about ownership,
and every access through one is untyped (`(char *)(unsigned)&full_data_62aaac`,
`U_I((unsigned)&full_data_624560)`) or hidden in a view macro (`#define X (*(T *)&full_data_6f25b0)`).
Settling one also exposes the accesses that disagree: sites reading the same datum at different widths,
signedness or element sizes. Each is either **our bug** (fix the access per the original's instructions) or **a
real inconsistency of the original** (an `@original why` view with byte-matched evidence). Finding those is the
point of the session; the typed data is the product.

Scope: `$ARGUMENTS` (`scope=used`, the default, takes the blocks code references - raw accesses in function
bodies first, then those only reached through view macros; `scope=all` adds the unreferenced blocks last.
`unit=NAME` keeps only the blocks with a user in `src/NAME.c`; both options may be given).

Hard rules
- Every tool is `dcp ...` from the project root. Every
  `dcp` of the project runs in the project's daemon, which the first command starts. `dcp <command> -h`
  explains each one; output is one record per line, `key=value`, addresses `0x%08x`.
- Files stay UTF-8 without BOM with LF line endings. Change C text only with a file-editing tool, never with
  shell heredocs, `sed` or quoted script strings (they eat backslashes). Never edit `build/` or
  `ledger/grades.tsv` (only `dcp session wrap` / `dcp promote` / `dcp debt add` write it); commit
  `ledger/tiebreak.tsv` when a probe writes it.
- The sources are the state: the address comment on every data definition, the declarations in
  `include/<unit>.h`, and the unit's lead comment (its `Open: data:` lines, rewritten, never appended to). No
  notes files, no session log.
- One definition per datum, in its owner's file among that unit's data in address order; one declaration in
  `include/<owner>.h`. A named datum never stays `extern GAPDATA`: the gap block is only the bytes no symbol
  covers yet, and the remainder stays a `full_` block at its own address.
- Never write an address of the original into code; reference symbols by name.
- No grade may fall: `dcp check` fails on M1. A byte-matched user is evidence of the original's object: when a
  type change moves its bytes, the type or the owner is wrong, not the match, except for a declaration-set
  tie-break (section 5).
- A move that breaks D1 / D4 / D8 was the wrong owner or the wrong size: undo it. Never answer it with padding,
  alignment tricks or a second definition.

## 1. Start

1. `dcp session start`. It is the gate (clean tree, every unit compiles, no error finding, the link ok). On
   `gate: FAIL` fix what it lists (or revert), commit, start again; an `obligation=toolchain.*` /
   `obligation=libs.archives` line is a human decision: stop and hand it to the user. A gap data session is
   counted in groups (section 4), so no `--kind` (the kinds are layout and match-base).
2. Inventory the gap blocks (`src/main.c`, its `GAPDATA full_data_<addr>[N]` / `full_rdata_<addr>[N]`
   definitions) and each block's users: `dcp refs full_data_<addr>` prints the definition, every `extern
   GAPDATA` and each use with its file, line and function. `dcp data map` (no unit) is the per-unit summary:
   declarations, externs and their findings. Classify each block: **raw** (a function body takes its address or
   reads it, outside any `#define`), **view only** (only through a `#define` macro over it), **unreferenced**
   (no code use; externs alone are not a use). Keep the total and the used count: the session's before numbers.
3. Apply the scope. With `unit=NAME`, keep the blocks with a user in `src/NAME.c` and read that unit's lead
   comment, especially its `Open: data:` lines (a boundary owner, a datum named but left in place).

## 2. Picking a group

A group is the unit of work and of the count: **one datum**, or **one family the same functions read
together** (the fields of one record that become one struct). It is settled completely - name, type, extent,
owner, definition, declaration and every access - before the next. Raw-access data before view-only data,
unreferenced data last (`scope=all`). Take the one with the most users; between equals, the one whose sites
agree on the most of its name and type (the least unresolved reads). A family is one group however many fields
it has.

## 3. Settling a group

### 3.1 Name and type from the users and the bytes
- `dcp refs full_data_<addr>`: every site, with what it does with the address (a load, a store, a pointer
  passed to a call, an index, a loop bound). The widths, offsets and strides of the sites are the type.
- `dcp dump 0xADDR LEN --dword --float --str`: the bytes - a readable string, a pointer, `{0,0,0,0,0,0,0xe0,0x3f}`
  the double 0.5, an array of records by its stride. `dcp disasm 0xADDR` / `dcp asmdiff NAME --at 0xSITE` when
  the C does not say whether a load is a byte, a word or a dword, signed or unsigned.
- Name it from its strings, the texts that refer to it and the unit's naming style, not from its address. Type
  it as every site uses it; a family is one struct with its fields at their offsets (a `typedef` in the owner's
  header, one comment per field, the offsets and what reads them). An array's element size and count come from
  the stride and the loop bound, not from the gap block's length.

### 3.2 Extent: the object's size, not the gap's
- The extent is the object's: the end of the last field a site touches, a string's NUL, a loop's one-past end.
  A gap may hold several objects. A bound used only as a loop's end (`p < (unsigned)full_data_X`) is no object:
  its bytes join the block they bound.
- Split the gap: write the typed definition at its address with its address comment, and keep the bytes
  before and after as `full_<section>_<addr>` blocks at their own addresses (names from the addresses, bytes
  from `dcp dump`, never a hole). The section kind stays the original's (`data` or `rdata`; an rdata object the
  code never writes may be `const`).
- `dcp data map UNIT` shows each declaration with `size=`, `room=` (to the next start), `over=`, `by=` and its
  `room_ref` lines: the addresses past the object the original's code reads. D1 (overlap), D7 (a view past its
  container) and D8 (the original proves a bigger object) are the size evidence. `dcp data fix` (dry run) only
  shrinks an array to its room and reorders for D4; it never splits a gap block or drops an extern. Use it to
  read the D1/D4 context, never `--write` in this session.

### 3.3 Owner: the unit whose data block the address lies in
- VC6 lays one unit's data contiguously: the owner is the unit whose definitions the address lies between, in
  `dcp data map UNIT` (per-unit summary plus `dcp layout literals`; users in only one unit support it). Write
  the definition into `src/<owner>.c` among that unit's definitions of its section kind, in address order
  (`dcp data map OWNER`; a definition out of order is D4), with its address comment.
- One declaration in `include/<owner>.h` (the struct typedef too), with the address comment. Drop every
  `extern GAPDATA <name>[]` of it in every unit, and replace the gap-block definition with the typed one (and
  the remainders).
- Rewrite every site (3.4). Including the owner's header may collide with a local copy: settle it as match-base
  2.3 does (`dcp headers conflicts`), never with a second declaration.
- **Boundary**: an address between two units' data blocks, with users in both and no clean owner, is named and
  typed in place if the evidence is strong, left in the gap block, and recorded as one line `Open: data:
  <addr> <name>, owner <A> or <B> (<evidence>)` in the lead comment. A boundary case is not settled: it does
  not count toward the 8, and you take another group.

### 3.4 Every access site
- A raw access becomes the typed name: `(char *)(unsigned)&full_data_62aaac` -> the char array,
  `U_I((unsigned)&full_data_624560)` -> the int object (or its established view name), `&obj` where a pointer is
  needed, a field or an index where the original adds an offset or walks a record.
- A view macro over the datum is removed: the object's name replaces it, and a macro that is one field of a
  record becomes `record.field`. A macro over a part of a bigger object becomes the field at that offset.
  Never leave two names for one address (a `C.name.alias` error); if the view's name is the good one, give it
  to the definition and declaration.
- After the rewrite `dcp refs <name>` shows one definition, one declaration and every use typed; no `extern
  GAPDATA` of it remains, and no `full_` name of that address is used by code.

### 3.5 Read every moved site against the original
The type change can change code even when it looks harmless. `dcp build` exits 0 and prints the summary;
`dcp check` lists every M1 line. For each function whose grade moved (and each site of the group, even when its
grade did not) read `dcp asmdiff NAME --at 0xSITE --context 12` (or `dcp disasm 0xSITE --range +0x0..+0x20`):
- the width and signedness of the load (`movzx` / `movsx` vs `mov`, byte vs dword, `jl` / `jb`, `cmp` of an
  unsigned);
- the element size and stride (`[base + index*4]`, `add reg, 4` vs `1`, a pointer increment);
- float vs int (`fld` / `fstp`, `_ftol`, a floating constant's bytes), and how the address itself is taken
  (`lea` vs `mov`).
Decide which side is wrong:
- **Our access disagrees with the original's instructions**: our C is wrong. Fix the access. This is a **bug**:
  the commit prefix is `data bug:` and its body has one line per fixed access: function, address, before,
  after (section 3.7).
- **The original reads the same datum inconsistently** (two byte-matched users at different widths, signedness
  or element sizes): the datum is one object, the second reading is the original's. Keep one view macro at the
  unit that needs it, with the evidence: `#define NAME (*(T2 *)&datum)  /* 0xADDR, @original why: <user>
  reads it as T2 (byte-matched) while <user> reads T */`. `dcp exceptions` lists the marker. Do not choose one
  width for the object and cast the other site silently, and do not split the datum.
- A matched user that still matches after the change confirms the address (`M.data.site`). One that stops
  matching means a wrong address, type or owner: find which before you touch the access.

### 3.6 Gate before the commit
- `dcp build` exits 0; `dcp check` shows no D1, no D4, no D8 and no M1, except a tie-break (section 5).
- A D1 / D4 / D8 the move caused is the wrong owner or the wrong size: undo the move (restore the block, the
  sites and the externs), fix the evidence and settle it again. Never pad the object, align it or add a second
  definition to pass.
- `dcp data map OWNER` puts the definition between its neighbours; `dcp why 0xADDR` names the owner.

### 3.7 Commit
One group, one commit: `<unit>: data <name> from the gap block (typing)` - the owner unit, the datum or struct,
and in the body the extents moved, the declarations dropped and the sites typed when they are not obvious.
A group that fixed accesses is prefixed `data bug:` and lists each fixed access in the body, one line each:
`main_Report 0x538a10: read main_Flag as a byte -> an int (the original's mov eax, dword ptr
[0x624560] at the same site)`. `git log --grep "data bug"` is how the user finds them: never fix an access
without saying so. A message of more than one line goes through a file (`git commit -F <file>`); `git status`
clean before the next group.

## 4. When to stop
A session is **8 groups** committed (each settles a datum or family completely and meets the gate), then the
wrap-up. Stop early only when the scope has no settled group left, or every remaining group is a boundary left
as `Open: data:` with a reason. Never stop because a group is big: a record family with many fields is one
group, however long. A boundary group does not count.

## 5. Tie-breaks
VC6 /O2 can change a function's bytes by the declaration set alone (a moved data definition, a new declaration,
a typedef nothing uses). `dcp build` probes the unit of such a fall (`dcp headers probe UNIT` by hand; recorded
in `ledger/tiebreak.tsv`: commit it). A function whose own text did not change and whose bytes move under the
probe is no fall: M1 prints `tie-break: N functions moved (UNIT)`, and promote takes it. Keep the change. Any
other M1 is a wrong owner, size or access: fix it or undo the move; never `dcp debt add` for it in this session.

`dcp headers sample NAME` measures one function more widely than the unit probe (random unused declarations
and layout-preserving member changes inside the include chain); use it when a fall is not explained by the probe.

## 6. Wrap up
1. Keep the group in progress only if it builds and checks clean; else revert it.
2. `dcp session wrap`: builds, links, checks, promotes the grade baseline and prints the report. It must say
   `gate: ok`. Commit the last group first (it promotes nothing with uncommitted src/, include/ or decl/).
3. Rewrite the lead comment of every unit you touched to its current state: drop the `Open: data:` lines you
   settled, keep one line per boundary still open with its reason. No dated or "this session" lines.
4. Commit: `session: gapdata wrap (<units>)`.
5. Final message, short: gap blocks before -> after (used / total, section 1's count), the groups committed,
   **every bug fixed** (one line each: function, address, before, after), the boundary questions left open and
   why, and the next group you would take. Stop.
