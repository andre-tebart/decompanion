"""Check rules (C.* and the numbered setup checks): they read facts and emit conflicts only. A conflict never
removes a fact; it makes `dcp check` fail (error, bug) or `dcp conflicts` list it (warn)."""
from __future__ import annotations

import re



def declared_build(decl: str) -> int | None:
    """The build number a declaration names: its last run of digits ('cl 12.00.9044' -> 9044)."""
    m = re.search(r"(\d+)\D*$", decl or "")
    return int(m.group(1)) if m else None

