"""`dcp toolchain probe`: which compiler flags the matched functions prove (rule S.probe of the plan, run as a
command; its result feeds the rule M.flags.proven).

Anchors: every byte-matched function of the target (code grade byte), compiled as its unit; and, when the
toolchain root holds CRT sources (VC6: VC98/CRT/SRC), every source whose object is a library member placed in
the image (S.crt.code), its functions compared at their placed addresses. The CRT anchors are reported apart:
their objects were built by another compiler build with the library's own flags (the Rich header lists them
separately), so they say nothing about the flags of the user's units.

The grid (Toolchain.probe_grid; VC6: /O1 /O2 /Ox x /G3 /G4 /G5 /G6 x /Oy /Oy- x /Gy x /GF /Gf x /Ob0 /Ob1 /Ob2):
every combination replaces the grid's flags among the unit's flags (the other flags stay); a combination the
compiler refuses (an unknown or incompatible option) is pruned. Each anchor unit is compiled once per
combination (one process each, in the pool; objects cached by the unit's text and flags), each anchor compared
with the masked compare of M.match. The best combination is the one matching most anchors (ties: the
declared flags, then the compiler's defaults (Toolchain.probe_defaults), then grid order). A flag of the best
combination is *distinguished by N anchors* when every other value of its group (the rest of the combination
unchanged) loses at least one anchor, N being the anchors lost under any of them; *indistinguishable* when some
other value keeps every anchor (the report names those values and how many anchors rule out the rest). The
probe result (store meta `probe`) is read by M.flags.proven.
"""
from __future__ import annotations

import hashlib
import itertools
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..ledger.fact import Kind, canonical
from ..ledger.store import sha256
from ..match import compare as C
from . import compile as B


def combos(grid) -> list[tuple[str, ...]]:
    return list(itertools.product(*(alts for _, alts in grid)))


def strip_grid(flags: list[str], grid) -> list[str]:
    every = {f.lower() for _, alts in grid for f in alts}
    return [f for f in flags if f.lower() not in every]


def crt_sources(project) -> list[tuple[str, Path]]:
    """(placed member unit, source path) of every CRT source under the toolchain root whose object is placed."""
    tc = project.toolchain
    src = tc.root / "VC98" / "CRT" / "SRC" if tc.root else None
    if src is None or not src.exists():
        return []
    placed = {}
    for f in project.store.facts(Kind.unit):
        tu = f.value.get("tu", "")
        if tu.startswith("lib:") and "/" in tu:
            placed.setdefault(tu.rsplit("/", 1)[1].lower(), tu)
    out = []
    for p in sorted(src.iterdir()):
        if p.suffix.lower() == ".c":
            unit = placed.get(p.stem.lower() + ".obj")
            if unit:
                out.append((unit, p))
    return out


def probe(project, log=None) -> dict:
    t0 = time.perf_counter()
    root, tc, img, st = project.root, project.toolchain, project.image, project.store
    grid = tc.probe_grid()
    all_combos = combos(grid)
    from ..ledger import grades as G
    rows = [r for r in G.function_grades(st) if r["code"] == "byte"]
    units_ = {a.unit: a for a in B.plan(project)}
    jobs = []           # (job id, kind, unit, source path rel, base flags, include dirs, anchors [(id, name, addr)])
    for unit in sorted({r["unit"] for r in rows}):
        a = units_.get(unit)
        if a is None:
            continue
        flags = B.compile_flags(project, a.target, unit)
        anchors = [(f"{r['addr']:#010x}", r["name"], r["addr"]) for r in rows if r["unit"] == unit]
        jobs.append((unit, "user", unit, Path(a.path), strip_grid(flags, grid), B.include_dirs(unit), anchors, a.text))
    lib_names = {}
    for f in st.facts(Kind.name):
        if f.value.get("origin") == "lib" and f.value.get("unit"):
            for n in f.value["name"].split("|"):
                lib_names[(f.value["unit"], n)] = f.lo
    for unit, path in crt_sources(project):
        anchors = [(f"{a:#010x}", n, a) for (u, n), a in sorted(lib_names.items()) if u == unit]
        if anchors:
            jobs.append((unit, "crt", unit, path, [], [path.parent], anchors, path.read_text(errors="replace")))
    relocs = sorted(img.relocations()) or None
    starts = sorted({f.lo for f in st.facts(Kind.start)} | {s.end for s in img.sections if s.holds_code})

    def key_of(job, combo):
        jid, kind, unit, src, base, dirs, anchors, text = job
        return sha256("probe", text, canonical([*base, *combo]), canonical([str(d) for d in dirs]))

    def run(item):
        job, combo, key = item
        jid, kind, unit, src, base, dirs, anchors, text = job
        flags = [*base, *combo]
        tmp = Path("build") / "obj" / "probe" / key[:16] / "p.obj"
        (root / tmp).parent.mkdir(parents=True, exist_ok=True)
        res = tc.compile(src, tmp, flags, dirs, root)
        if res.refused_flags:
            out = {"refused": res.refused_flags}
        elif not res.ok:
            out = {"failed": [d.text() for d in res.errors][:3]}
        else:
            data = (root / tmp).read_bytes()
            h = hashlib.sha256(data).hexdigest()
            dest = B.obj_path(root, h)
            if not dest.exists():
                os.replace(root / tmp, dest)
            else:
                (root / tmp).unlink()
            out = {"obj": h}
        try:
            (root / tmp).parent.rmdir()
        except OSError:
            pass
        return key, out

    work = [(j, c, key_of(j, c)) for j in jobs for c in all_combos]
    results = {}

    def compile_missing(items):
        todo = []
        for j, c, key in items:
            hit = st.blob_json(key)
            if hit is not None and ("obj" not in hit or B.obj_path(root, hit["obj"]).exists()):
                results[key] = hit
            else:
                todo.append((j, c, key))
        with ThreadPoolExecutor(os.cpu_count() or 4) as pool:
            for key, res in pool.map(run, todo):
                st.put_blob_json(key, "probe", res)
                results[key] = res
        return len(todo)

    # a unit that does not compile under the first combination (a CRT source without its private headers)
    # is not compiled under the others
    n = compile_missing([(j, all_combos[0], key_of(j, all_combos[0])) for j in jobs])
    dead = {j[0] for j in jobs if "failed" in results[key_of(j, all_combos[0])]}
    n += compile_missing([w for w in work if w[0][0] not in dead])
    for j, c, key in work:
        if j[0] in dead:
            results.setdefault(key, results[key_of(j, all_combos[0])])
    todo = [None] * n
    results = {(j[0], c): results[key] for j, c, key in work}
    out_combos = []
    anchors_out = []
    for jid, kind, unit, src, base, dirs, anchors, text in jobs:
        for aid, name, addr in anchors:
            anchors_out.append({"id": aid, "name": name, "unit": unit, "kind": kind})
    for combo in all_combos:
        matched, refused, failed = [], None, []
        for jid, kind, unit, src, base, dirs, anchors, text in jobs:
            res = results[(jid, combo)]
            if "refused" in res:
                refused = res["refused"]
                continue
            if "failed" in res:
                failed.append(unit)
                continue
            obj = C.read_object(project, res["obj"])
            idx = {}
            for s in obj.functions():
                idx.setdefault(s.name, s)
                idx.setdefault(tc.undecorate(s.name), s)
            for aid, name, addr in anchors:
                s = idx.get(name)
                if s is None:
                    continue
                code = obj.function_code(s)
                import bisect
                i = bisect.bisect_right(starts, addr)
                nxt = starts[i] if i < len(starts) else img.end
                if C.compare(img, code, addr, relocs, nxt, tc.fill_forms).matched:
                    matched.append(aid)
        out_combos.append({"flags": list(combo), "matched": sorted(set(matched)), "refused": refused, "failed": sorted(set(failed))})
    result = {"grid": [[g, list(a)] for g, a in grid], "anchors": anchors_out, "combos": out_combos,
              "declared": project.toolchain_decl.get("cflags") or [], "defaults": tc.probe_defaults()}
    st.set_meta("probe", canonical(result))                  # what M.flags.proven reads: no timings in it
    result = dict(result, ms=int((time.perf_counter() - t0) * 1000), compiles=len(todo), cached=len(work) - len(todo))
    if log:
        log(f"probe: {len(jobs)} anchor units, {len(all_combos)} combinations, {result['compiles']} compiles, {result['ms']} ms")
    return result


def analyse(result: dict) -> dict:
    """The best combination and, per group, the anchors that distinguish its flag (module docstring); only user
    anchors count, the CRT anchors are listed apart (the core's: mrules.rs analyse)."""
    from .. import native
    return native.core().probe_analyse(result)


def report(project, result: dict):
    from ..cli import record
    an = analyse(result)
    users = [a for a in result["anchors"] if a["kind"] == "user"]
    crts = [a for a in result["anchors"] if a["kind"] == "crt"]
    refused = [c for c in result["combos"] if c["refused"]]
    crt_units = sorted({a["unit"] for a in crts})
    crt_failed = sorted({u for c in result["combos"] for u in c["failed"] if u in crt_units})
    crt_matched = sorted({a for c in result["combos"] for a in c["matched"] if a in {x["id"] for x in crts}})
    print(record(target=project.target_name, anchors=len(users), crt_anchors=len(crts), combinations=len(result["combos"]),
                 refused=len(refused), compiles=result["compiles"], cached=result.get("cached", 0), ms=result["ms"]))
    if crts:
        print("  " + record(crt_sources=len(crt_units), crt_sources_failing=len(crt_failed), crt_anchors_matched_somewhere=len(crt_matched))
              + "  (CRT anchors are reported apart: another compiler build, the library's own flags)")
    for a in users:
        print("  " + record(anchor=a["id"], name=a["name"], unit=a["unit"]))
    if an["best"] is None:
        print("  no combination the compiler accepts")
        return
    print("  " + record(best=" ".join(an["best"]["flags"]), matched=f"{an['matched']}/{len(users)}",
                        declared=" ".join(result.get("declared") or [])))
    for n, flags in an["ranked"]:
        print("    " + record(matched=n, flags=" ".join(flags)))
    for g in an["groups"]:
        if not g["alternatives"]:
            verdict = "fixed in the grid (no alternative)"
        elif g["anchors"]:
            verdict = f"distinguished by {len(g['anchors'])} anchors from {len(g['units'])} units"
        elif g["ruled_out"]:
            verdict = (f"indistinguishable from {' '.join(g['same_as'])} ({len(g['ruled_out'])} anchors rule out the other "
                       f"alternatives)")
        else:
            verdict = "indistinguishable"
        print("  " + record(flag=g["flag"], group=g["group"]) + "  " + verdict
              + (f"  (crt anchors: {len(g['crt_anchors'])})" if g["crt_anchors"] else ""))
