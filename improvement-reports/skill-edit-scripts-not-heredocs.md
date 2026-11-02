# match-base skill: put edit scripts that touch backslashes in a file, not a heredoc

- **Source:** match-base session 2026-11-01 (gildegold), worker 4
- **Area:** dcp-match-base skill
- **Problem:** a Python-in-heredoc edit of the `D3FL_POS` macro (its `\` continuations) failed its assert, and another heredoc script broke too. The skill already warns about string literals and `#define` continuations in shell edits, but not about heredoc scripts.
- **Proposal:** one line in the skill: write edit scripts that touch backslashes to a file with the Write tool and run that, not a heredoc.
- **Cost of not having it:** about 5 minutes.

## Also seen (match-base session 2026-11-01 (gildegold), worker 5)
- A heredoc'd Python edit stripped a backslash from a string literal in main_BeginPlayerRound (see lint-string-literal-bytes-vs-original.md).

## Also seen (match-base session 2026-11-01 (gildegold), worker 11)
- A python heredoc holding a large C body with apostrophes failed with "unexpected EOF"; worked around with Write + a splice script (~2 minutes). Skill suggestion: write large function bodies to the scratchpad with the Write tool.

## Also seen (match-base session 2026-11-01 (gildegold), worker 13)
- Even quoted heredocs (`cat <<'EOF'`) turned `"\\"` into `"\"` in C string literals three times (caught by grep). Skill wording: "heredocs, even quoted ones".

## Also seen (match-base session 2026-11-02 (gildegold), worker 15)
- One long `python - <<'EOF'` failed with "unexpected EOF while looking for matching `''"; another collapsed doubled backslashes in C string literals. Reliable path: write the script and the C body as files in the scratchpad and run `python -I file`. Recommend that pattern explicitly for large rewrites. (The orchestrator hit the same heredoc failure while filing these reports.)

## Also seen (match-base session 2026-11-02 (gildegold), worker 33)
- A stray `cat > file` waiting on stdin blocked a multi-file edit (~2 minutes, then git status to confirm nothing was written). Pattern that worked: edit scripts in the scratchpad run as `python -I script spec.json`.

## Also seen (match-base session 2026-11-02 (gildegold), worker 46)
- Backslashes were halved through heredocs, Python triple-quoted strings and even the agent's own tool input; the worker resorted to `chr(92)`. Proposal: one recommended backslash-safe edit path, e.g. `dcp sub FILE --old-file A --new-file B`. See lint-string-literal-bytes-vs-original.md for the damage it caused.

## Also seen (match-base session 2026-11-02 (gildegold), worker 48)
- A long Bash heredoc containing Python was silently truncated (closing `PYEOF` and the script's last line lost); a `.py` writing C string literals with backslashes needed `chr(92)` tricks. A sentence recommending the Write tool for helper scripts would have saved two failed edits.

## Also seen (match-base session 2026-11-02 (gildegold), worker 55)
- Heredocs stripped backslashes even in quoted `'EOF'` blocks; one form string broke (caught by M9), another needed `chr(92)`. See scoped-function-body-edit.md for the proposed fix.

## Also seen (match-base session 2026-11-02 (gildegold), worker 59)
- A PowerShell write emptied src/f3gm.c because a variable did not survive between shell calls; restored from git. Another argument for a dcp-side function replace (scoped-function-body-edit.md).

## Also seen (match-base session 2026-11-02 (gildegold), worker 65)
- Backslash sequences in heredoc-fed Python and in shell arguments did not survive in Git Bash (`\\n` mangled), breaking several trial edits; scratch files worked around it.

## Also seen (match-base session 2026-11-03 (gildegold), worker 70)
- Even a *quoted* heredoc (`python - <<'EOF'`) collapsed `\\` to `\`: `"...f\\xfcr '%s'..."` in gm_ItemPrice became the UTF-8 bytes of ü (`303 274` in `od -c`); a second script's search string with `\\xfc` failed its assert. Environment (Bash tool), not dcp; `dcp asmdiff` showed the bad literal. Test: `python - <<'EOF'` with `print(len('a\\x'))` printing 3 means collapse. ~5 minutes plus one build/grade round. Proposal: skill says quoted heredocs are affected too; write scripts to a file or use the Edit tool.
