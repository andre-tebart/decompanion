# match-base skill: put edit scripts that touch backslashes in a file, not a heredoc

- **Source:** match-base session 2026-11-01 (gildegold), worker 4
- **Area:** dcp-match-base skill
- **Problem:** a Python-in-heredoc edit of the `D3FL_POS` macro (its `\` continuations) failed its assert, and another heredoc script broke too. The skill already warns about string literals and `#define` continuations in shell edits, but not about heredoc scripts.
- **Proposal:** one line in the skill: write edit scripts that touch backslashes to a file with the Write tool and run that, not a heredoc.
- **Cost of not having it:** about 5 minutes.
