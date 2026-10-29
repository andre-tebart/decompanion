"""The session report's grade changes (repo/session.py grade_changes): the function grades against the baseline
ledger/grades.tsv at the session's base commit."""
import subprocess
from pathlib import Path

from decompanion.repo import session as S


def git(root: Path, *args):
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def test_grade_changes(tmp_path):
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.email", "t@example.com")
    git(tmp_path, "config", "user.name", "t")
    (tmp_path / "ledger").mkdir()
    (tmp_path / "ledger" / "grades.tsv").write_text(
        "target\taddress\tname\tunit\tcode\treadability\tlevel\n"
        "exe\t0x00401000\tf\tu\tdraft\tdraft\t\n"
        "exe\t0x00401040\tg\tu\tshape\treadable\t\n"
        "exe\t0x00401080\th\tu\tdraft\tdraft\t\n"
        "dll\t0x10001000\tx\tv\tdraft\tdraft\t\n", newline="\n")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "base")
    base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=tmp_path, capture_output=True, text=True).stdout.strip()
    rows = [{"addr": 0x401000, "unit": "u", "name": "f", "code": "shape", "readability": "readable", "level": ""},
            {"addr": 0x401040, "unit": "u", "name": "g", "code": "shape", "readability": "readable", "level": ""},
            {"addr": 0x4010c0, "unit": "u", "name": "k", "code": "draft", "readability": "draft", "level": "deep"}]
    ch = S.grade_changes(tmp_path, base, "exe", rows)
    assert ch == [(0x401000, "u", "f", "draft+draft", "shape+readable"),
                  (0x401080, "u", "h", "draft+draft", None),                 # gone since the base
                  (0x4010c0, "u", "k", None, "draft+draft deep")]            # new, escalated
