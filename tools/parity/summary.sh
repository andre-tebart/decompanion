#!/usr/bin/env bash
# tools/parity/summary.sh OUT_DIR: the exit codes of a recording, and the head of every failed command's output.
cd "$1" || exit 1
grep -h '^--- exit' ./*.txt | sort | uniq -c
for f in ./*.txt; do
    if [ "$(sed -n 2p "$f")" != "--- exit 0" ]; then
        echo "== $f: $(head -1 "$f") ($(sed -n 2p "$f"))"
        sed -n '/^--- stdout/,$p' "$f" | grep -v '^---' | head -"${2:-4}"
    fi
done
