# Skill sync and fixes

- **Priority:** P1 · **Size:** S-M · **Root:** R12
- **Depends on:** model-decisions (for the M7 wording)

## Problem

- gildegold runs an older copy of the skills in `.claude/skills/`. It lacks the M9/M10 paragraph, the `verdict=`
  text, `--divergence-explained`, loop steps 4-5 and the Filing section. Nothing detects this.
- skills/dcp-match-base/SKILL.md contradicts itself and the tool in several places.
- Workers keep rediscovering the same VC6 spellings.

## Tool task

`dcp session start` warns when the project's `.claude/skills/*` differ from the installed dcp's skills
(`dcp skills install` exists).

## Skill edits

skills/dcp-match-base/SKILL.md:

- :96: delete "the grade does not read it yet"; it is stale since 3b4d6a9 and contradicts :131-136.
- :124: the stop criterion is the grade (classes *or* proof), not the class list.
- :255: rewrite the escalation criterion. Escalate when the function is shape or proved and only byte is missing, or
  when every code hunk is read and named as allocation or scheduling, with the asmdiff lines. Add the case where
  readability is blocked by a head conflict: it is not raised; settle the head, or `@stuck` with the `Open:` line as
  the reason.
- :270: "stale @deep" means byte + readable (as M2 and auto-clear define it), not shape + readable. Add one sentence
  on auto-clear and the names queue (`dcp next --names`).
- :140-142 and :73-74: fix the loop heuristic by signedness. `jl`/`jge` against an address means a signed compare (an
  int index loop); `jb`/`jae` means a pointer walk.
- :173-192 and :63: move M7 out of readability into its own consistency item. It gates what model-decisions decides.
  Include the callee's header where possible, never add a prototype only to silence M7, and leave an `Open: head:`
  line when blocked.
- :110: build and grade report M5 (once show-computed-findings is done).
- :20, :22-23 (layout :18): replace "any editing tool will do" with one rule. C text goes only through the
  file-editing tool, or `dcp fn --replace` with a file written by it. Never a heredoc (quoted or not), sed,
  `python -c` or a shell argument.
- :185, :196: for `@original` evidence, first run `dcp refs`: if every caller pushes short, the prototype is wrong. Then
  cite the call site's asmdiff line or the headers-conflicts call finding.
- :33: descriptions in address comments need evidence too; a guess says it is a guess.
- :286 (layout :193): update the lead comment when it is out of date; leave it when it is still accurate.
- :155: make shell-neutral ("put a why with backslashes in `--from FILE`").
- Remove project-specific content from the generic skill (`full_data_`, "no shape function on gildegold differs by
  more than 7", the d2/ai examples).

New sections:

- A **VC6 spellings reference**:
  - x87 compare forms and operand load order;
  - constant folding, unary minus against fmul, fimul against fild+fmul;
  - clamp via max/min, loop rotation `do{}while(1)`, dead stores through another lvalue;
  - the return value held in a callee-saved register, ICF stubs, rep stosd against memset, volatile reloads;
  - block-scoped slot sharing, inner-block locals;
  - case labels dropped from a switch range, multi-char tags;
  - cross-jump and tail merging.
- **The queue order**: drafts first, then `read` items, so a jump back within a unit is normal. Explain what `name=`
  and `section=` mean.
- asmdiff `-`/`+`: a patch from ours to the original. B2 "identical instructions" means encoding only.
- The dump typed flags (`--float`, `--dword`, `--str`) and `dcp why` for f32 values.

Commit rules (with session-progress-from-tool): count with the tool, not commits. A grade change with no source change
needs no commit. A separate typing commit is required only for head includes and shared-header edits. One data-commit
rule covers both gap-block and in-unit data. A rename may share the commit.

## Reports

- all skill-* reports
- diffclass-idiom-hints
- vc6-optimizer-hints
- diffclass-volatile-reload-hint
- diffclass-encoding-only-note
- next-why-skipped
- next-bare-name
- asmdiff-side-markers-confusing
- dump-multiple-typed-values
