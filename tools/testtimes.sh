#!/usr/bin/env bash
# tools/parity/testtimes.sh FILTER: the wall clock of every test matching FILTER, one process each, slowest first.
bin=$(ls -t target/debug/deps/dcp-*.exe | head -1)
export DCP_TEST_BUDGET_MS=0
"$bin" --list "$1" 2>/dev/null | grep ': test$' | sed 's/: test$//' | while read -r t; do
    s=$(date +%s%N); "$bin" --exact "$t" -q >/dev/null 2>&1; e=$(date +%s%N)
    echo "$(( (e - s) / 1000000 )) $t"
done | sort -rn | head -"${2:-25}"
