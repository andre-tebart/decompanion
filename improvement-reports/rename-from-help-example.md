# `dcp rename --from`: show the file format in `-h`

- **Source:** match-base session 2026-11-01 (gildegold), worker 2
- **Area:** dcp rename
- **Problem:** a helper agent piped input through `cat` and the command hung; nothing in the help says what the `--from` file must look like.
- **Proposal:** a short `-h` example of the `--from` line format, and fail fast (instead of hanging) when stdin or the argument is not usable.
- **Cost of not having it:** one stuck helper run, about 15 minutes.
