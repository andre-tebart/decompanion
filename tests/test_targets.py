"""The target dimension: [[target]] tables, one store per target, --target, `dcp target add|list`, the
milestone-1 [target] form, and the worktree overlay per target."""
import subprocess

import pytest

from conftest import build_pe, dcp

from decompanion.config import ConfigError, Project


def test_two_targets_two_stores(tiny2):
    p = Project(tiny2)
    assert [t.name for t in p.targets] == ["tiny", "other"] and p.target_name == "tiny"
    q = Project(tiny2, "other")
    assert q.store_path().name == "other.sqlite" and q.image.sha256 != p.image.sha256
    code, out = dcp(tiny2, "setup")
    assert code == 0 and "target=tiny" in out
    code, out = dcp(tiny2, "--target", "other", "setup")
    assert code == 0 and "target=other" in out
    assert (tiny2 / "build" / "tiny.sqlite").exists() and (tiny2 / "build" / "other.sqlite").exists()
    # --target after the command works too, and why answers for both
    code, out = dcp(tiny2, "why", "0x10001020", "--target", "other")
    assert code == 0 and "target=other" in out and "cls=func" in out
    code, out = dcp(tiny2, "why", "0x10001020")
    assert "target=tiny" in out
    code, out = dcp(tiny2, "check")
    assert code == 0 and "check target=tiny" in out and "check target=other" in out
    with pytest.raises(ConfigError):
        Project(tiny2, "nope")


def test_target_add_and_list(tiny):
    other = build_pe(tiny / "second.dll", variant=2)
    code, out = dcp(tiny, "target", "add", "second", str(other))
    assert code == 0
    p = Project(tiny)
    assert [t.name for t in p.targets] == ["tiny", "second"]
    code, out = dcp(tiny, "target", "list")
    assert "targets=2" in out and "target=second" in out and "default=yes" in out
    code, out = dcp(tiny, "--target", "second", "setup")
    assert code == 0 and (tiny / "build" / "second.sqlite").exists()


def test_legacy_target_form(tmp_path):
    d = tmp_path / "old"
    d.mkdir()
    pe = build_pe(d / "Server.dll")
    (d / "decompanion.toml").write_text(f'[target]\npath = "{pe.as_posix()}"\n\n[toolchain]\nplugin = "vc6"\nreason = "x"\n\n'
                                        f'[libs]\narchives = []\n', newline="\n")
    p = Project(d)
    assert p.target_name == "server" and p.targets[0].legacy
    assert p.store_path().name == "server.sqlite"
    other = build_pe(d / "b.dll", variant=1)
    code, _ = dcp(d, "target", "add", "b", str(other))
    assert code == 0
    p = Project(d)
    assert [t.name for t in p.targets] == ["server", "b"] and not p.targets[0].legacy


def test_overlay_per_target(tiny2):
    """A worktree's store reads main's runs: the first setup there copies them instead of recomputing."""
    assert dcp(tiny2, "setup")[0] == 0
    assert dcp(tiny2, "--target", "other", "setup")[0] == 0
    wt = tiny2.parent / "wt1"
    import shutil
    shutil.copytree(tiny2, wt, ignore=shutil.ignore_patterns("build"))
    (wt / ".dcp").mkdir()
    (wt / ".dcp" / "main_store").write_text((tiny2 / "build").as_posix() + "\n", newline="\n")
    p = Project(wt, "other")
    assert p.store.main is not None and p.store.main.name == "other.sqlite"
    from decompanion.rules.engine import Engine
    import decompanion.rules  # noqa: F401
    res = Engine(p, p.store).run()
    assert not any(r.ran for r in res)       # every run found in main's store (same inputs)


def test_wt_commands(tiny):
    (tiny / ".gitignore").write_text("build/\n.dcp/\n", newline="\n")          # as `dcp init` writes it
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tiny, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tiny, check=True)
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "init"], cwd=tiny, check=True)
    code, out = dcp(tiny, "wt", "new", "w1")
    assert code == 0, out
    path = tiny.parent / f"{tiny.name}-wt" / "w1"
    assert (path / ".dcp" / "main_store").read_text().strip() == (tiny / "build").resolve().as_posix()
    code, out = dcp(tiny, "wt", "list")
    assert "worktree=w1" in out
    code, out = dcp(tiny, "seed", str(path))
    assert code == 0
    code, out = dcp(tiny, "wt", "drop", "w1")
    assert code == 0 and not path.exists()
