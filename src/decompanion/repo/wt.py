"""Worktrees: `dcp wt new|list|drop` and `dcp seed`.

A worktree is a git worktree of the target project at ../<project>-wt/<NAME> on branch wt/<NAME>. Its build/
starts empty; .dcp/main_store names the main checkout's build directory, and every store of the worktree
(build/<target>.sqlite) overlays main's store of the same target: a rule run whose inputs main already ran
is copied from main instead of recomputed, blobs (Ghidra drafts, disassembly) are read from main. `dcp seed
PATH` is the plain-copy fallback: it copies this checkout's stores into another checkout's build/.
"""
from __future__ import annotations

import sqlite3
import subprocess
from pathlib import Path


class WtError(RuntimeError):
    pass


def git(root: Path, *args, check=True) -> str:
    r = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)
    if check and r.returncode != 0:
        raise WtError(f"git {' '.join(args)}: {r.stderr.strip() or r.stdout.strip()}")
    return r.stdout


def wt_path(root: Path, name: str) -> Path:
    return root.parent / f"{root.name}-wt" / name


def new(root: Path, name: str) -> Path:
    if (root / ".dcp" / "main_store").exists():
        raise WtError(f"{root} is a worktree itself; run `dcp wt new` in the main checkout")
    if not (root / ".git").exists():
        raise WtError(f"{root} is not a git repository")
    path = wt_path(root, name)
    if path.exists():
        raise WtError(f"{path} exists")
    git(root, "worktree", "add", "-b", f"wt/{name}", str(path))
    (path / ".dcp").mkdir(parents=True, exist_ok=True)
    (path / ".dcp" / "main_store").write_text((root / "build").resolve().as_posix() + "\n", newline="\n")
    return path


def entries(root: Path) -> list[dict]:
    """The worktrees on wt/* branches: [{name, path, head, branch}]."""
    out, cur = [], {}
    for line in git(root, "worktree", "list", "--porcelain").splitlines() + [""]:
        if not line:
            if cur.get("branch", "").startswith("refs/heads/wt/"):
                cur["name"] = cur["branch"][len("refs/heads/wt/"):]
                out.append(cur)
            cur = {}
            continue
        k, _, v = line.partition(" ")
        cur[k] = v
    return out


def drop(root: Path, name: str, force: bool = False) -> list[str]:
    e = next((x for x in entries(root) if x["name"] == name), None)
    if e is None:
        raise WtError(f"no worktree wt/{name}")
    msgs = []
    git(root, "worktree", "remove", *(("--force",) if force else ()), e["worktree"])
    msgs.append(f"removed {e['worktree']}")
    r = subprocess.run(["git", "-C", str(root), "branch", "-D" if force else "-d", f"wt/{name}"], capture_output=True, text=True)
    if r.returncode == 0:
        msgs.append(f"deleted branch wt/{name}")
    else:
        msgs.append(f"kept branch wt/{name} (not merged; --force deletes it)")
    return msgs


def seed(src_build: Path, dest_root: Path) -> list[str]:
    """Copy every store of src_build into dest_root/build (sqlite backup: consistent while WAL is in use)."""
    dest = dest_root / "build"
    dest.mkdir(parents=True, exist_ok=True)
    out = []
    for p in sorted(src_build.glob("*.sqlite")):
        s = sqlite3.connect(p)
        d = sqlite3.connect(dest / p.name)
        s.backup(d)
        d.close()
        s.close()
        out.append(p.name)
    return out
