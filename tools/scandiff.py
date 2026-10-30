"""The source scan through the front end (libclang, ledger/srcscan.py's models) against the regex scan it replaces,
file by file: the functions, the data declarations, the scan errors, the function-like macros, the views, the raw
object macros and the pointer casts each one finds. Kept while the regex scan
is (docs/plan.md section 18).

    uv run python tools/scandiff.py --root ../gildegold [--show 20] [--file SUBSTRING]

Prints per category the entries only one side has, grouped by file, then the totals.
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from decompanion import fsmemo
from decompanion.ledger import srcscan


def both(root: Path):
    files = []
    for d, pats in (("src", ("*.c", "*.h")), ("include", ("*.h",))):
        if (root / d).exists():
            files += sorted({(d + "/" + r, p) for r, p in fsmemo.walk(root / d, pats)}, key=lambda t: t[0].lower())
    ms = srcscan.models(root, files)
    old, new = srcscan.Scan(), srcscan.Scan()
    for rel, p in files:
        text = fsmemo.read_text(p)
        srcscan.scan_file(rel, text, old)
        srcscan.scan_file(rel, text, new, ms.get(rel, srcscan.EMPTY))
    return old, new


def keys(sc: srcscan.Scan):
    return {
        "functions": Counter((f.file, f.line, f.name, f.addrs, f.unlinked, f.static) for f in sc.functions),
        "data": Counter((d.file, d.line, d.name, d.kind, d.addrs, d.unlinked, d.static) for d in sc.data),
        "errors": Counter((e.file, e.line, e.check, e.message) for e in sc.errors),
        "macros": Counter(sc.macros),
        "views": Counter((v.file, v.line, v.name, v.container, v.offset, v.addrs, v.alias) for v in sc.views),
        "rawobj": Counter(sc.rawobj),
        "ptrcasts": Counter((c.file, c.line, c.text, c.value) for c in sc.ptrcasts),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--show", type=int, default=20)
    ap.add_argument("--file", default="")
    a = ap.parse_args(argv)
    root = Path(a.root).resolve()
    fsmemo.attach(root)
    old, new = both(root)
    ko, kn = keys(old), keys(new)
    for cat in ko:
        only_old = sorted(x for x in (ko[cat] - kn[cat]).elements() if a.file in x[0])
        only_new = sorted(x for x in (kn[cat] - ko[cat]).elements() if a.file in x[0])
        print(f"== {cat}: regex {sum(ko[cat].values())}, libclang {sum(kn[cat].values())}; "
              f"only regex {len(only_old)}, only libclang {len(only_new)}")
        for tag, xs in (("regex   ", only_old), ("libclang", only_new)):
            for x in xs[:a.show]:
                print(f"  {tag} {x}")
            if len(xs) > a.show:
                print(f"  {tag} ... {len(xs) - a.show} more")
    return 0


if __name__ == "__main__":
    sys.exit(main())
