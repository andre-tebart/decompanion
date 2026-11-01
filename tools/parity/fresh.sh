#!/usr/bin/env bash
# tools/parity/fresh.sh REPO DIR [REV]: a clean clone of REPO at REV (default: the parity corpus's) in DIR.
rm -rf "$2"
git clone -q "$1" "$2" && cd "$2" && git checkout -q -B parity "${3:-2129854}"
