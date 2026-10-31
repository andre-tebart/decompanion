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
probe result (store meta `probe`) is read by M.flags.proven. The probe and its analysis are the core's
(native/dcp_core/src/probe.rs, mrules.rs); this module is their face and prints the report.
"""
from __future__ import annotations

from .. import native


def probe(project, log=None) -> dict:
    """Run the probe (module docstring); its result with ms, compiles and cached."""
    result, line = native.core().probe_run(project.core)
    if log:
        log(line)
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
