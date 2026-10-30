"""The speed of the match loop on a target project: edit -> build -> diffclass / asmdiff -> grade, timed per command.

    python tools/bench.py --root ../gildegold --fn 0x5dcf00 --swap "ai_ShotHitHeight + height::height + ai_ShotHitHeight" \
        --rename ai_ShotHitsGround [--runs 3] [--scenarios S0,S1,...] [--uv] [--verify] [--label NAME]

Every command runs as its own process (the project's .venv dcp, or `uv run dcp` with --uv), with DCP_TIMING=1; a
running `dcp serve` is used when there is one (the client decides), so the same script measures both. Scenarios,
each applied to the function's fragment file and reverted (the tree is left as it was found; a dirty tree is
refused):

  S0  nothing changed (the floor of every command)
  S1  a body edit that changes the object (--swap OLD::NEW, a text replaced in the fragment)
  S2  a comment-only edit in the fragment
  S3  a blank line after the fragment's address comment (only line numbers move)
  S4  a comment line appended to the unit's first project header (--header, default: the fragment unit's
      header include/<unit>.h when it exists)
  S5  `dcp rename` of --rename to a new name and back

After each scenario's edit: build, diffclass FN, asmdiff FN, grade FN, next, dump FN 4, why FN, draft FN --show,
-h; after the revert: build. The table (median / min / max wall seconds per scenario and command) goes to stdout,
the raw runs (wall time, exit code, the `rules:` and `timing:` lines) to <root>/build/bench/<date>-<rev>-<label>.json.

--verify (--verify-build: also `dcp build --force`, the compile rows checked too): after each scenario's revert, the store is checked against a forced recompute: the current runs'
(rule, out_hash) and the tu hash are read, `dcp setup --force --no-analyzer` reruns every rule with every
shortcut off (DCP_NO_SHORTCUTS=1, DCP_NO_DAEMON=1), and the two must be equal.
"""
from __future__ import annotations

import argparse
import json
import os
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
        self.runs: list[dict] = []
        self.fn = a.fn

    def dcp(self, scenario: str, step: str, *argv, env=None, record=True) -> dict:
        e = dict(os.environ, DCP_TIMING="1", **(env or {}))
        t = time.perf_counter()
        p = subprocess.run(self.cmd + list(argv), cwd=self.root, capture_output=True, text=True, env=e)
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

    # ------------------------------------------------------------------ the fragment and the edits
    def fragment(self) -> Path:
        addr = int(self.fn, 16)
        hits = sorted(self.root.glob(f"src/*/f_{addr:x}.c"))
        if not hits:
            sys.exit(f"bench: no src/*/f_{addr:x}.c for {self.fn}")
        return hits[0]

    def header(self) -> Path:
        if self.a.header:
            return self.root / self.a.header
        h = self.root / "include" / f"{self.fragment().parent.name}.h"
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
        frag = self.fragment()
        if name == "S0":
            self.loop(name)
            return
        if name == "S5":
            old = self.a.rename
            if not old:
                print("bench: S5 needs --rename NAME; skipped", file=sys.stderr)
                return
            new = old + "Bench"
            log = self.root / "names.log"                    # append-only: the two bench lines are taken out again
            saved = log.read_bytes() if log.exists() else None
            try:
                self.dcp(name, "rename", "rename", old, new, "--why", "bench")
                self.loop(name)
                self.dcp(name, "rename", "rename", new, old, "--why", "bench", record=False)
            finally:
                if saved is not None:
                    log.write_bytes(saved)
            self.dcp(name, "revert-build", "build")
            return
        if name == "S1":
            if not self.a.swap or "::" not in self.a.swap:
                print("bench: S1 needs --swap OLD::NEW; skipped", file=sys.stderr)
                return
            o, n = self.a.swap.split("::", 1)
            path, change = frag, (lambda t: t.replace(o, n, 1) if o in t else sys.exit(f"bench: {o!r} not in {frag}"))
        elif name == "S2":
            path, change = frag, (lambda t: t.replace("*/", " (bench) */", 1))
        elif name == "S3":
            path, change = frag, (lambda t: t.replace("*/\n", "*/\n\n", 1))
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
        env = {"DCP_NO_SHORTCUTS": "1", "DCP_NO_DAEMON": "1"}
        if self.a.verify_build:                         # every unit compiled again: the tu rows are checked too
            self.dcp(scenario, "verify", "build", "--force", env=env, record=False)
        self.dcp(scenario, "verify", "setup", "--force", "--no-analyzer", env=env, record=False)
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
    ap.add_argument("--fn", required=True, help="the function's address (its fragment src/*/f_<addr>.c is edited)")
    ap.add_argument("--swap", help="S1: OLD::NEW, a text of the fragment replaced (it must change the object)")
    ap.add_argument("--rename", help="S5: a name to rename and back")
    ap.add_argument("--header", help="S4: the header to edit (relative to the root)")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--scenarios", default="S0,S1,S2,S3,S4,S5")
    ap.add_argument("--uv", action="store_true", help="run `uv run dcp` instead of the venv's dcp")
    ap.add_argument("--verify", action="store_true", help="check the store against a forced recompute after each scenario")
    ap.add_argument("--verify-build", action="store_true", help="--verify with `dcp build --force` first (slow: every unit)")
    ap.add_argument("--label", default="")
    ap.add_argument("-v", "--verbose", action="store_true", help="print every command as it runs")
    return Bench(ap.parse_args()).main()


if __name__ == "__main__":
    sys.exit(main())
