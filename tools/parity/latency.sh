#!/usr/bin/env bash
# tools/parity/latency.sh DCP_EXE PROJECT_DIR [RUNS]: the wall clock of the cheap commands, end to end (client,
# daemon, output), median of RUNS (default 7), in ms; the daemon is warmed first.
dcp=$1; cd "$2" || exit 1; runs=${3:-7}
"$dcp" fn bmp_GetInfo >/dev/null 2>&1
med() { sort -n | awk '{a[NR]=$1} END {print a[int((NR+1)/2)]}'; }
t() {
    for _ in $(seq "$runs"); do
        s=$(date +%s%N); "$dcp" "$@" >/dev/null 2>&1; e=$(date +%s%N)
        echo $(( (e - s) / 1000000 ))
    done | med
}
printf '%-34s %6s\n' command ms
for c in "serve --status" "fn bmp_GetInfo" "fn main_GameLoop" "grade bmp_GetInfo" "grade main_GameLoop" "next" "dump 0x0053a520 16" \
         "why 0x0053a520" "disasm pool_Next" "asmdiff main_Unk53b840" "diffclass main_Unk53b840" "refs pool_Next" "build" "status"; do
    eval "set -- $c"
    printf '%-34s %6s\n' "$c" "$(t "$@")"
done
