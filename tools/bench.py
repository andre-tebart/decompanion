"""The speed of the match loop on a target project: edit -> build -> diffclass / asmdiff -> grade, timed per command.

    python tools/bench.py --root ../gildegold --fn 0x5dcf00 --swap "ai_ShotHitHeight + height::height + ai_ShotHitHeight" \
        --rename ai_ShotHitsGround [--runs 3] [--scenarios S0,S1,...] [--uv] [--verify] [--label NAME]

Every command runs as its own process (the project's .venv dcp, or `uv run dcp` with --uv), with DCP_TIMING=1, in
the project's daemon (`dcp serve` must run). Scenarios,
each applied inside the function's span of its unit file src/<unit>.c (found with `dcp fn`) and reverted (the
tree is left as it was found; a dirty tree is refused):

  S0  nothing changed (the floor of every command)
  S1  a body edit that changes the object (--swap OLD::NEW, a text replaced in the function's span)
  S2  a comment-only edit in the function's address comment
  S3  a blank line before the function's address comment (only line numbers move: of the function and of every
      function below it in the unit)
  S4  a comment line appended to the unit's first project header (--header, default: the unit's header
      include/<unit>.h when it exists)
  S5  `dcp rename` of the first --rename name to a new name and back
  S6  `dcp rename` of every --rename name (comma-separated) in a row, the session's pattern, and back
  S7  one `dcp rename` of every --rename name (all pairs in one call), and back

After each scenario's edit: build, diffclass FN, asmdiff FN, grade FN, next, dump FN 4, why FN, draft FN --show,
-h; after the revert: build. The table (median / min / max wall seconds per scenario and command) goes to stdout,
the raw runs (wall time, exit code, the `rules:` and `timing:` lines) to <root>/build/bench/<date>-<rev>-<label>.json.

--verify (--verify-build: also `dcp build --force`, the compile rows checked too): after each scenario's revert, the store is checked against a forced recompute: the current runs'
(rule, out_hash) and the tu hash are read, `dcp setup --force --no-analyzer` reruns every rule with every
shortcut off (DCP_NO_SHORTCUTS=1) in a fresh process (`python -m decompanion.cli`, not the daemon), and the two
must be equal.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import statistics
import subprocess
import sys
import time
from pathlib import Path

STEPS = ("build", "diffclass", "asmdiff", "grade", "next", "dump", "why", "draft", "-h")


def git(root: Path, *args) -> str:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=True).stdout.strip()


class Bench:
    def __init__(self, a):
        self.a = a
        self.root = Path(a.root).resolve()
        exe = self.root / ".venv" / "Scripts" / ("dcp.exe" if os.name == "nt" else "dcp")
        self.cmd = ["uv", "run", "dcp"] if a.uv else [str(exe)]
        py = self.root / ".venv" / "Scripts" / ("python.exe" if os.name == "nt" else "python")
        self.fresh = (["uv", "run", "python"] if a.uv else [str(py)]) + ["-m", "decompanion.cli"]
        self.runs: list[dict] = []
        self.fn = a.fn

    def dcp(self, scenario: str, step: str, *argv, env=None, record=True, fresh=False) -> dict:
        e = dict(os.environ, DCP_TIMING=os.environ.get("DCP_TIMING") or "1", **(env or {}))
        t = time.perf_counter()
        p = subprocess.run((self.fresh if fresh else self.cmd) + list(argv), cwd=self.root, capture_output=True, text=True, env=e)
        wall = time.perf_counter() - t
        lines = [l for l in p.stderr.splitlines() if l.startswith(("rules:", "timing:"))]
        row = {"scenario": scenario, "step": step, "argv": list(argv), "wall": round(wall, 3), "rc": p.returncode,
               "lines": lines}
        if p.returncode not in (0, 1):
            row["stderr"] = p.stderr[-2000:]
            print(f"  ! {step}: exit {p.returncode}\n{p.stderr[-800:]}", file=sys.stderr)
        if record:
            self.runs.append(row)
        if self.a.verbose:
            print(f"  {scenario} {step:<10} {wall:6.2f}s rc={p.returncode} {' | '.join(lines)}")
        return row

    def loop(self, scenario: str):
        fn = self.fn
        self.dcp(scenario, "build", "build")
        self.dcp(scenario, "diffclass", "diffclass", fn)
        self.dcp(scenario, "asmdiff", "asmdiff", fn)
        self.dcp(scenario, "grade", "grade", fn)
        self.dcp(scenario, "next", "next")
        self.dcp(scenario, "dump", "dump", fn, "4")
        self.dcp(scenario, "why", "why", fn)
        self.dcp(scenario, "draft", "draft", fn, "--show")
        self.dcp(scenario, "-h", "-h")

    # ------------------------------------------------------------------ the function's span and the edits
    def span(self) -> tuple[Path, int, int]:
        """The function's unit file and its span (first, last line, 1-based): `dcp fn`'s record `at=FILE:A-B`."""
        p = subprocess.run(self.cmd + ["fn", self.fn], cwd=self.root, capture_output=True, text=True)
        m = re.search(r"\bat=(\S+):(\d+)-(\d+)", p.stdout.split("\n", 1)[0])
        if p.returncode or not m:
            sys.exit(f"bench: `dcp fn {self.fn}` found no function\n{p.stderr[-800:]}")
        return self.root / m[1], int(m[2]), int(m[3])

    @staticmethod
    def in_span(a: int, b: int, fn):
        """An edit of the lines a..b of a text (1-based, inclusive), the rest left as it is."""
        def change(t):
            lines = t.split("\n")
            return "\n".join(lines[:a - 1] + fn("\n".join(lines[a - 1:b])).split("\n") + lines[b:])
        return change

    def header(self) -> Path:
        if self.a.header:
            return self.root / self.a.header
        h = self.root / "include" / f"{self.span()[0].stem}.h"
        if not h.exists():
            sys.exit(f"bench: no {h}; name one with --header")
        return h

    @staticmethod
    def edit(path: Path, fn):
        text = path.read_bytes().decode("utf-8")
        new = fn(text)
        assert new != text, f"bench: the edit of {path} changed nothing"
        path.write_bytes(new.encode("utf-8"))
        return text

    def scenario(self, name: str):
        if name == "S0":
            self.loop(name)
            return
        if name in ("S5", "S6", "S7"):
            names = [x for x in (self.a.rename or "").split(",") if x]
            if not names:
                print(f"bench: {name} needs --rename NAME[,NAME...]; skipped", file=sys.stderr)
                return
            names = names[:1] if name == "S5" else names
            log = self.root / "names.log"                    # append-only: the bench lines are taken out again
            saved = log.read_bytes() if log.exists() else None
            try:
                there = [w for old in names for w in (old, old + "Bench")]
                back = [w for old in names for w in (old + "Bench", old)]
                if name == "S7":
                    self.dcp(name, "rename", "rename", *there, "--why", "bench")
                else:
                    for old in names:
                        self.dcp(name, "rename", "rename", old, old + "Bench", "--why", "bench")
                self.loop(name)
                self.dcp(name, "rename", "rename", *back, "--why", "bench", record=False)
            finally:
                if saved is not None:
                    log.write_bytes(saved)
            self.dcp(name, "revert-build", "build")
            return
        unit, a, b = self.span()
        if name == "S1":
            if not self.a.swap or "::" not in self.a.swap:
                print("bench: S1 needs --swap OLD::NEW; skipped", file=sys.stderr)
                return
            o, n = self.a.swap.split("::", 1)
            path, change = unit, self.in_span(a, b, lambda t: t.replace(o, n, 1) if o in t
                                              else sys.exit(f"bench: {o!r} not in {unit.name}:{a}-{b}"))
        elif name == "S2":
            path, change = unit, self.in_span(a, a, lambda t: t.replace("*/", " (bench) */", 1))
        elif name == "S3":
            path, change = unit, self.in_span(a, a, lambda t: "\n" + t)
        elif name == "S4":
            path, change = self.header(), (lambda t: t + "/* bench */\n")
        else:
            sys.exit(f"bench: unknown scenario {name}")
        orig = self.edit(path, change)
        try:
            self.loop(name)
        finally:
            path.write_bytes(orig.encode("utf-8"))
        self.dcp(name, "revert-build", "build")

    # ------------------------------------------------------------------ the oracle
    def state(self, target="exe"):
        db = sqlite3.connect(f"file:{self.root / 'build' / (target + '.sqlite')}?mode=ro", uri=True)
        runs = dict(db.execute("SELECT rule, out_hash FROM run WHERE current=1").fetchall())
        tus = db.execute("SELECT unit, src_hash, flags_hash, include_hash, obj_hash, ok FROM tu ORDER BY unit").fetchall()
        self.facts = {}
        for rule, lo, hi, kind, value, level, by in db.execute(
                "SELECT r.rule, f.lo, f.hi, f.kind, f.value, f.level, f.by FROM fact f JOIN run r ON r.id=f.run_id "
                "WHERE r.current=1 AND r.rule NOT IN ('L.src', 'L.decl')"):
            self.facts.setdefault(rule, set()).add((lo, hi, kind, value, level, by))
        db.close()
        return runs, tus

    def verify(self, scenario: str) -> bool:
        before = self.state()
        facts_before = self.facts
        env = {"DCP_NO_SHORTCUTS": "1"}
        if self.a.verify_build:                         # every unit compiled again: the tu rows are checked too
            self.dcp(scenario, "verify", "build", "--force", env=env, record=False, fresh=True)
        self.dcp(scenario, "verify", "setup", "--force", "--no-analyzer", env=env, record=False, fresh=True)
        after = self.state()
        bad = sorted(r for r in set(before[0]) | set(after[0]) if before[0].get(r) != after[0].get(r))
        if self.a.verify_build:
            # CL stamps every object with the time of the compile: a recompile of the same text gives another
            # object hash, and M.compile's facts name it; everything else must be equal
            bad = [r for r in bad if r != "M.compile"]
            before = (before[0], [t[:4] + t[5:] for t in before[1]])
            after = (after[0], [t[:4] + t[5:] for t in after[1]])
        ok = not bad and before[1] == after[1]
        for r in bad:
            a, b = facts_before.get(r, set()), self.facts.get(r, set())
            for x in sorted(a - b)[:3]:
                print(f"  {r} incremental only: {str(x)[:300]}")
            for x in sorted(b - a)[:3]:
                print(f"  {r} recomputed only:  {str(x)[:300]}")
        print(f"verify {scenario}: {'ok' if ok else 'FAIL'}"
              + (f"  rules differ: {', '.join(bad)}" if bad else "") + ("" if before[1] == after[1] else "  tu rows differ"))
        return ok

    # ------------------------------------------------------------------ main
    def main(self):
        if git(self.root, "status", "--porcelain", "--untracked-files=no"):
            sys.exit(f"bench: {self.root} has uncommitted changes; commit or stash them first")
        scenarios = self.a.scenarios.split(",")
        self.dcp("warm", "build", "build", record=False)            # every scenario starts from a current store
        ok = True
        for i in range(self.a.runs):
            for s in scenarios:
                print(f"run {i + 1}/{self.a.runs} {s}", file=sys.stderr)
                self.scenario(s)
                if self.a.verify or self.a.verify_build:
                    ok = self.verify(s) and ok
        if git(self.root, "status", "--porcelain", "--untracked-files=no"):
            print("bench: WARNING: the tree is not clean after the run", file=sys.stderr)
        self.report()
        return 0 if ok else 1

    def report(self):
        groups: dict[tuple, list] = {}
        for r in self.runs:
            groups.setdefault((r["scenario"], r["step"]), []).append(r["wall"])
        print(f"| scenario | step | n | median s | min | max |\n|---|---|---|---|---|---|")
        for (s, st), ws in groups.items():
            print(f"| {s} | {st} | {len(ws)} | {statistics.median(ws):.2f} | {min(ws):.2f} | {max(ws):.2f} |")
        rev = git(Path(__file__).resolve().parent.parent, "rev-parse", "--short", "HEAD")
        out = self.root / "build" / "bench"
        out.mkdir(parents=True, exist_ok=True)
        path = out / f"{time.strftime('%Y%m%d-%H%M%S')}-{rev}-{self.a.label or ('uv' if self.a.uv else 'exe')}.json"
        path.write_text(json.dumps({"fn": self.fn, "cmd": self.cmd, "runs": self.runs}, indent=1), encoding="utf-8")
        print(f"raw: {path}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", required=True)
    ap.add_argument("--fn", required=True, help="the function's address (its span in src/<unit>.c is edited)")
    ap.add_argument("--swap", help="S1: OLD::NEW, a text of the function's span replaced (it must change the object)")
    ap.add_argument("--rename", help="S5 / S6 / S7: NAME[,NAME...] to rename and back (S5 the first, S6 all in a row, S7 all in one call)")
    ap.add_argument("--header", help="S4: the header to edit (relative to the root)")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--scenarios", default="S0,S1,S2,S3,S4,S5,S6,S7")
    ap.add_argument("--uv", action="store_true", help="run `uv run dcp` instead of the venv's dcp")
    ap.add_argument("--verify", action="store_true", help="check the store against a forced recompute after each scenario")
    ap.add_argument("--verify-build", action="store_true", help="--verify with `dcp build --force` first (slow: every unit)")
    ap.add_argument("--label", default="")
    ap.add_argument("-v", "--verbose", action="store_true", help="print every command as it runs")
    return Bench(ap.parse_args()).main()


if __name__ == "__main__":
    sys.exit(main())
