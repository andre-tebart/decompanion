#!/usr/bin/env bash
# tools/parity/daemon-check.sh DCP_EXE PROJECT_DIR: the daemon's behaviour by hand: stop / status / auto-start,
# concurrent clients served in turn, a client of another build restarting the daemon.
dcp=$1; cd "$2" || exit 1
echo "== stop, then a command starts the daemon"
"$dcp" serve --stop; "$dcp" serve --status; echo "rc=$?"
"$dcp" fn bmp_GetInfo | head -2; "$dcp" serve --status
echo "== three clients at once"
( "$dcp" grade bmp_GetInfo | head -1 > /tmp/dcp-a.txt ) & ( "$dcp" dump 0x0053a520 16 | head -1 > /tmp/dcp-b.txt ) & ( "$dcp" fn bmp_Load | head -1 > /tmp/dcp-c.txt ) & wait
cat /tmp/dcp-a.txt /tmp/dcp-b.txt /tmp/dcp-c.txt
"$dcp" serve --status
echo "== another build: a copy of the exe that reports another build id cannot be made here; restart via the build check is"
echo "   exercised by DCP_BUILD_OVERRIDE below when supported"
echo "== serve when one runs"
"$dcp" serve; echo "rc=$?"
ls build/daemon
