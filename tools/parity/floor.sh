#!/usr/bin/env bash
# tools/parity/floor.sh DCP_EXE PROJECT_DIR: what a process start costs from Git Bash, against dcp's own floor.
dcp=$1; cd "$2" || exit 1
for c in "/usr/bin/true" "/c/Windows/System32/whoami.exe" "$dcp --version" "$dcp --no-daemon --version" "$dcp serve --status" "$dcp fn bmp_GetInfo"; do
    printf '%-60s' "$c"
    for _ in 1 2 3 4 5 6 7; do
        s=$(date +%s%N); $c >/dev/null 2>&1; e=$(date +%s%N)
        printf ' %3d' $(( (e - s) / 1000000 ))
    done
    echo
done
