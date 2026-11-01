#!/usr/bin/env bash
# The parity harness of the pure-Rust port (temporary: removed after the cutover).
#
#   tools/parity/run.sh DCP_EXE PROJECT_REPO COMMANDS OUT_DIR
#
# Clones PROJECT_REPO into OUT_DIR.work, starts the dcp daemon there, runs `setup --no-analyzer` and `build`, then
# every line of COMMANDS (shell words; `#` lines and blank lines are skipped), and records each command as
# OUT_DIR/NNN.txt: the command line, its exit code, its stdout and its stderr, normalised (CRLF, the clone's path,
# durations, pids, uptimes, memory). Two recordings compare with `diff -r OUT_A OUT_B`.
set -u
dcp=$1; repo=$2; cmds=$(cd "$(dirname "$3")" && pwd)/$(basename "$3"); out=$4
mkdir -p "$(dirname "$out")"
out=$(cd "$(dirname "$out")" && pwd)/$(basename "$out")
work="$out.work"
if [ -f "$work/build/daemon.json" ] || [ -f "$work/build/dcp-daemon.json" ]; then
    (cd "$work" && "$dcp" serve --stop >/dev/null 2>&1); sleep 2
fi
rm -rf "$work" "$out"
mkdir -p "$out"
git clone -q "$repo" "$work" || exit 1
cd "$work" || exit 1
# the corpus is pinned: the project keeps moving while the port runs (PARITY_REV overrides)
git checkout -q -B parity "${PARITY_REV:-2129854}" || exit 1
export PARITY_ROOT_FWD; PARITY_ROOT_FWD=$(pwd -W)

norm() {
    perl -pe '
        BEGIN { $f = $ENV{PARITY_ROOT_FWD}; ($b = $f) =~ s{/}{\\}g; ($bb = $b) =~ s{\\}{\\\\}g; }
        s/\r$//;
        s/\Q$bb\E/<ROOT>/gi; s/\Q$b\E/<ROOT>/gi; s/\Q$f\E/<ROOT>/gi;
        s/ +\d+ ms\b/ N ms/g; s/\b\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\b/T/g; s/\belapsed=\d+m/elapsed=Nm/g; s/\bms=\d+(\.\d+)?/ms=N/g; s/\b(total|request)=\d+(\.\d+)?/$1=N/g;
        s/\bobj=[0-9a-f]{12,16}\b/obj=H/g;
        s/\b(pid|uptime|memory_mb|requests)=\S+/$1=N/g; s/\(pid \d+/(pid N/g; s/supervisor pid \d+/supervisor pid N/g;
    '
}

n=0
run() {
    local f; f=$(printf '%s/%03d.txt' "$out" "$n"); n=$((n + 1))
    "$dcp" "$@" >"$out/.o" 2>"$out/.e"; local rc=$?
    { printf '$ dcp %s\n--- exit %d\n--- stdout\n' "$*" "$rc"; norm <"$out/.o"; printf -- '--- stderr\n'; norm <"$out/.e"; } >"$f"
    rm -f "$out/.o" "$out/.e"
}

run serve
run setup --no-analyzer
run build
while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    eval "set -- $line"
    run "$@"
done <"$cmds"
"$dcp" serve --stop >/dev/null 2>&1
sleep 1
echo "parity: $n commands recorded in $out"
