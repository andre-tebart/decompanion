"""Writing declarations into decompanion.toml without losing its comments: a line editor for the one-line
`key = value` form the project file uses (strings, numbers and arrays of strings on one line, `reason.<key>`
dotted keys). Every edit is checked by parsing the result and comparing the value that was set.

A table is `[name]` (the first table of that name) or the n-th `[[target]]`; a key is set in place when the
table has it, else appended after the table's last key line. A missing `[name]` table is appended at the end
of the file. The older one-reason form `reason = "..."` of a table is spelled out per key first
(`reason.<key> = "..."` for every key of the table it covered) so that a per-key reason can join it.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

HEADER = re.compile(r"^\s*\[\[?\s*([A-Za-z0-9_.\-]+)\s*\]\]?\s*(#.*)?$")


def value_text(v) -> str:
    """A TOML value on one line: a basic string, an integer, a boolean or an array of strings."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(value_text(x) for x in v) + "]"
    s = str(v)
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def _span(lines: list[str], table: str, index: int | None) -> tuple[int, int] | None:
    """(header line, end exclusive) of the table, None when absent. `index`: the n-th [[table]]."""
    heads = []
    for i, line in enumerate(lines):
        m = HEADER.match(line)
        if m:
            heads.append((i, m.group(1), line.lstrip().startswith("[[")))
    k = 0
    for j, (i, name, arr) in enumerate(heads):
        if name != table or arr != (index is not None):
            continue
        if index is not None and k != index:
            k += 1
            continue
        end = heads[j + 1][0] if j + 1 < len(heads) else len(lines)
        return i, end
    return None


def _key_line(lines, lo, hi, key) -> int | None:
    pat = re.compile(r"^\s*" + re.escape(key).replace(r"\.", r"\s*\.\s*") + r"\s*=")
    for i in range(lo + 1, hi):
        if pat.match(lines[i]):
            return i
    return None


def _last_key(lines, lo, hi) -> int:
    last = lo
    for i in range(lo + 1, hi):
        s = lines[i].strip()
        if s and not s.startswith("#"):
            last = i
    return last


def set_keys(path: Path, table: str, values: dict, index: int | None = None, covered: tuple = ()) -> str:
    """Set `values` ({key: value}; dotted keys such as `reason.root`) in one table of the file; returns the new
    text (written). `covered`: the keys an older one-reason `reason = "..."` of the table speaks for (it is
    spelled out per key before a `reason.<key>` is set)."""
    path = Path(path)
    text = path.read_text()
    lines = text.split("\n")
    span = _span(lines, table, index)
    if span is None:
        if index is not None:
            raise ValueError(f"no [[{table}]] #{index + 1} in {path.name}")
        while lines and not lines[-1].strip():
            lines.pop()
        lines += ["", f"[{table}]", ""]
        span = (len(lines) - 2, len(lines))
    lo, hi = span
    if any(k.startswith("reason.") for k in values):
        old = _key_line(lines, lo, hi, "reason")
        if old is not None:
            cur = tomllib.loads(lines[old])["reason"]
            if isinstance(cur, str):
                tab = _table_of(tomllib.loads(text), table, index)
                spelled = [f"reason.{k} = {value_text(cur)}" for k in covered if k in tab]
                lines[old:old + 1] = spelled
                hi += len(spelled) - 1
    for key, v in values.items():
        line = f"{key} = {value_text(v)}"
        at = _key_line(lines, lo, hi, key)
        if at is not None:
            lines[at] = line
        else:
            at = _last_key(lines, lo, hi) + 1
            lines.insert(at, line)
            hi += 1
    new = "\n".join(lines)
    if not new.endswith("\n"):
        new += "\n"
    parsed = _table_of(tomllib.loads(new), table, index)
    for key, v in values.items():
        got = parsed
        for part in key.split("."):
            got = got.get(part) if isinstance(got, dict) else None
        want = list(v) if isinstance(v, tuple) else v
        if got != want:
            raise ValueError(f"{path.name}: setting {key} in [{table}] gave {got!r}, not {want!r}")
    path.write_text(new, newline="\n")
    return new


def _table_of(cfg: dict, table: str, index: int | None) -> dict:
    t = cfg.get(table)
    if index is None:
        return t if isinstance(t, dict) else {}
    if isinstance(t, list):
        return t[index]
    return t if isinstance(t, dict) and index == 0 else {}
