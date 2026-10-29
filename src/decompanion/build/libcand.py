"""`dcp libs candidates`: the evidence of the obligation libs.archives. Every run-time archive of the declared
toolchain root (Toolchain.library_candidates; VC6: LIBC, LIBCMT, their debug variants, MSVCRT, the C++
libraries) is placed into the image on its own with S.crt.code's search (rules/setup.py place_members), and
reported as members (objects in the archive), placed (members with a placed section), bytes (placed bytes).
Two archives conflict where they place sections of different names on overlapping bytes.

Each archive's result is cached as a blob keyed by (the placement's code, the image's sha256, the archive's
contents' sha256), like a rule run; the summary of the last call is the store's meta `libs.candidates` (what
`dcp status` shows as the evidence). Nothing here declares anything: `dcp libs declare` does, with a reason.
"""
from __future__ import annotations

import json
import time

from ..ledger.store import file_hash, sha256
from ..obligations import CANDIDATES_META


def place_one(p, archive) -> dict:
    """{archive, members, placed, bytes, places: [[lo, hi, name], ...]} of one archive (uncached)."""
    from ..rules.setup import Placement, lib_sections, place_members
    secs = lib_sections(p.objfmt, [archive])
    members = len({o.name for o in p.objfmt.archive_objects(archive)})
    sites = set(p.image.relocations())
    places = [pl for pl in place_members(p.image, secs, sites) if isinstance(pl, Placement)]
    units = {pl.unit for pl in places}
    return {"archive": archive.name, "members": members, "placed": len(units), "bytes": sum(pl.hi - pl.lo for pl in places),
            "places": [[pl.lo, pl.hi, pl.name] for pl in places]}


def conflicts(results: list[dict]) -> list[dict]:
    """Archive pairs placing sections of different names on overlapping bytes: {a, b, overlaps, first}."""
    out = []
    for i, a in enumerate(results):
        for b in results[i + 1:]:
            pb = sorted(b["places"])
            n, first = 0, None
            for lo, hi, name in a["places"]:
                for blo, bhi, bname in pb:
                    if blo >= hi:
                        break
                    if bhi > lo and bname != name:
                        n += 1
                        first = first if first is not None else min(lo, blo)
            if n:
                out.append({"a": a["archive"], "b": b["archive"], "overlaps": n, "first": first})
    return out


def candidates(p, force: bool = False, log=None) -> dict:
    """Place every candidate archive (cached per image and archive contents); store and return the summary
    {root, archives: [...] sorted by placed bytes, conflicts: [...], ms, cached}."""
    from ..rules.engine import RULES
    t0 = time.perf_counter()
    code = RULES["S.crt.code"].code_hash
    st, img = p.store, p.image
    results, cached = [], 0
    for archive in p.toolchain.library_candidates():
        key = sha256("libs.candidates", code, img.sha256, file_hash(archive))
        r = None if force else st.blob_json(key)
        if r is None:
            t1 = time.perf_counter()
            r = place_one(p, archive)
            st.put_blob_json(key, "libs.candidates", r)
            if log:
                log(f"placed {archive.name}: {r['placed']} members, {int((time.perf_counter() - t1) * 1000)} ms")
        else:
            cached += 1
        results.append(r)
    results.sort(key=lambda r: (-r["bytes"], r["archive"]))
    summary = {"root": p.toolchain_decl.get("root") or "", "image": img.sha256,
               "archives": [{k: r[k] for k in ("archive", "members", "placed", "bytes")} for r in results],
               "conflicts": conflicts(results)}
    st.set_meta(CANDIDATES_META, json.dumps(summary, sort_keys=True))
    summary["ms"] = int((time.perf_counter() - t0) * 1000)
    summary["cached"] = cached
    return summary
