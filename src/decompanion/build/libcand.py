"""`dcp libs candidates`: the evidence of the obligation libs.archives. Every run-time archive of the declared
toolchain root is placed into the image on its own with S.crt.code's search, and reported as members, placed and
bytes; two archives conflict where they place sections of different names on overlapping bytes. The core's
(native/dcp_core/src/libcand.rs, where the criterion is stated); this module is its face.
"""
from __future__ import annotations

from .. import native


def candidates(p, force: bool = False, log=None) -> dict:
    """Place every candidate archive (kept per image and archive contents); store and return the summary
    {root, image, archives: [...] sorted by placed bytes, conflicts: [...], ms, cached}."""
    summary, lines = native.core().libs_candidates(p.core, native.source_hash(), force)
    for line in lines if log else ():
        log(line)
    return summary
