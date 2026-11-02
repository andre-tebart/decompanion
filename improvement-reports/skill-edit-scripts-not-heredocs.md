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
