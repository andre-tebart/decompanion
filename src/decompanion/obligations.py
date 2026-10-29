"""The guided decisions: every human decision of a decompilation is an **obligation** the tool names when it
becomes due, with the evidence it has, the command that resolves it and the check that verifies it afterwards.
`dcp init` declares nothing; the obligations are computed here from the configuration and the store on every
call (never stored, never written by hand), and `dcp status` prints them in order. A declaration (`dcp toolchain
declare`, `dcp libs declare`, `dcp analyzer declare`) always carries a reason and is always level declared;
the rules raise it (C.toolchain checks the builds against the Rich header, S.crt.code places the archives'
members, M.flags.proven proves flags).

The obligations, in order (the ids are stable; Project.waiting names the ones a rule input waits on):
  toolchain.compiler   the compiler build of the user's objects       dcp toolchain declare compiler=...
  toolchain.linker     the linker build                               dcp toolchain declare linker=...
  toolchain.root       the installation of that toolchain            dcp toolchain declare root=...
  toolchain.cflags     the compiler flags (until the probe proves)    dcp toolchain declare cflags=...
  libs.archives        the static libraries linked in                 dcp libs declare ARCHIVE...   (due once the root is declared)
  analyzer             the third-party analyzer for the drafts        dcp analyzer declare ghidra|rea|none
  layout               functions without a fragment, open units       dcp session start, dcp layout next
  match                the grade queue                                dcp next
An obligation is open while its value is missing or declared without a reason. The toolchain and libs
obligations are the gate of `dcp session start` and `dcp check` (`gate`); the analyzer is due before the first
draft is wanted; layout and match are the work itself.
"""
from __future__ import annotations

import bisect
import datetime
import json
from dataclasses import dataclass

GATE = ("toolchain.", "libs.")
PROJECT_WIDE = ("toolchain.root", "analyzer")      # one declaration for every target
CANDIDATES_META = "libs.candidates"                # the last `dcp libs candidates` summary (build/libcand.py)


@dataclass
class Obligation:
    id: str
    target: str | None          # None: the project's (one declaration for every target)
    missing: str                # what a human has to decide
    evidence: str = ""          # what the tool knows so far (short; `dcp toolchain`, `dcp libs candidates` have the rest)
    resolve: str = ""           # the command that resolves it
    waits: str = ""             # not due yet: the obligation it follows

    @property
    def gate(self) -> bool:
        """Open, it fails `dcp session start` and `dcp check`."""
        return self.id.startswith(GATE)

    def fields(self) -> dict:
        out = {"obligation": self.id, "target": self.target}
        if self.waits:
            out["waits"] = self.waits
        out["missing"] = self.missing
        if self.evidence and not self.waits:
            out["evidence"] = self.evidence
        out["resolve"] = self.resolve
        return out


def declared_build(text: str) -> int | None:
    from .rules.checks import declared_build as db
    return db(text)


def rich_fact(p):
    from .ledger.fact import Kind
    return next(iter(p.store.facts(Kind.toolchain, rules=("S.rich",))), None)


def candidate_text(tc, e) -> str:
    lib = f" lib={e['archive_objects']}" if e.get("archive_objects") else ""
    lang = f" {e['language']}" if e.get("language") and e["language"] != "C" else ""
    return f"{tc.declare(e)} x{e['count']}{lang}{lib}"


def built_at(img) -> str:
    return datetime.datetime.fromtimestamp(img.timestamp, datetime.UTC).strftime("%Y-%m-%d")


def install_text(inst, decl: dict, rich) -> str:
    """One installation as evidence: its tool versions and which declared (or, before the declaration, which
    Rich) builds it makes."""
    v = inst.versions
    vers = " ".join(f"{k} {v[k]}" for k in ("cl", "c2", "link") if k in v)
    makes = []
    for key, build in (("compiler", inst.compiler_build), ("linker", inst.linker_build)):
        want = declared_build(decl.get(key) or "")
        if want is not None:
            if build == want:
                makes.append(f"the declared {key}")
        elif rich is not None and build in {c["build"] for c in rich.value.get(key + "s") or []}:
            makes.append(f"a Rich {key} ({build})")
    return f"{inst.root.as_posix()} ({vers}{'; makes ' + ' and '.join(makes) if makes else ''})"


def libs_evidence(p) -> str:
    """The last `dcp libs candidates` of this root (meta, cheap), else the command."""
    m = p.store.meta(CANDIDATES_META)
    if m:
        d = json.loads(m)
        if d.get("root") == (p.toolchain_decl.get("root") or ""):
            rows = sorted(d["archives"], key=lambda r: (-r["bytes"], r["archive"]))
            top = ", ".join(f"{r['archive']} placed={r['placed']}" for r in rows[:4] if r["placed"])
            return f"dcp libs candidates: {top or 'no archive places a member'}"
    return "not placed yet: dcp libs candidates places every run-time archive of the root"


def setup_obligations(p) -> list[Obligation]:
    """The toolchain, libs and analyzer obligations of the current target (open ones only)."""
    out: list[Obligation] = []
    t = p.target_name
    tc = p.toolchain
    decl = p.toolchain_decl
    reasons = decl.get("reasons") or {}
    rich = rich_fact(p)
    img = p.image

    def state(key) -> str | None:
        """None: declared with a reason; else what is missing."""
        if not decl.get(key):
            return "missing"
        if not reasons.get(key):
            return "declared without a reason"
        return None

    for key, what in (("compiler", "the compiler build that made the user's objects"), ("linker", "the linker build")):
        s = state(key)
        if s is None:
            continue
        cands = (rich.value.get(key + "s") or []) if rich else []
        ev = [f"Rich {key}s " + (", ".join(candidate_text(tc, c) for c in cands) or "none")] if rich else ["no Rich header"]
        if key == "compiler":
            ev.append(f"built {built_at(img)}")
            crt = tc.crt_strings(img)
            if crt:
                ev.append(f"CRT strings {len(crt)} ({crt[0][1].strip()})")
        else:
            ev.append(f"PE linker version {img.linker_version[0]}.{img.linker_version[1]:02d}")
        out.append(Obligation(f"toolchain.{key}", t, f"{what} ({s})", "; ".join(ev),
                              f'dcp toolchain declare {key}="<one of the Rich {key}s>" --why "..."'))
    s = state("root")      # a declared root the plugin finds no compiler under is no open obligation: the match
    if s is not None:      # rules warn (M.compile) and `dcp toolchain` says available=no
        installs = tc.installs()
        ev = "installs found: " + ("; ".join(install_text(i, decl, rich) for i in installs) if installs else "none")
        out.append(Obligation("toolchain.root", None, f"the installation of that toolchain ({s})", ev,
                              'dcp toolchain declare root=DIR --why "..."'))
    s = state("cflags")
    if s is not None:
        wiz = " ".join(tc.wizard_cflags())
        out.append(Obligation("toolchain.cflags", t, f"the compiler flags ({s})",
                              (f"the {tc.key} project wizard's release flags {wiz}; " if wiz else "")
                              + "dcp toolchain probe proves flags once functions byte-match",
                              'dcp toolchain declare cflags="/F1 /F2 ..." --why "..."'))
    ad = p.archives_decl_for()
    s = "missing" if ad["archives"] is None else (None if ad["reason"] else "declared without a reason")
    if s is not None:
        waits = "toolchain.root" if not decl.get("root") else ""
        out.append(Obligation("libs.archives", t, f"the static libraries linked into the image ({s})", libs_evidence(p) if not waits else "",
                              'dcp libs candidates; dcp libs declare ARCHIVE... --why "..."', waits))
    a = analyzer_obligation(p)
    if a is not None:
        out.append(a)
    return out


def analyzer_obligation(p) -> Obligation | None:
    from .config import reason_of
    cfg = p.cfg.get("analyzer") or {}
    if reason_of(cfg, "plugin"):
        return None
    az = p.analyzer
    inst = az.available()
    found = f"found at {inst.where}" if inst.ok else f"not available: {inst.reason}"
    from .ledger import drafts
    n = len(drafts.entries(p.store))
    origin = "as dcp init found it" if cfg.get("plugin") else "the default, no [analyzer] plugin written"
    ev = f"[analyzer] plugin={az.key} {origin} ({found}); drafts={n}"
    return Obligation("analyzer", None, "the analyzer whose pseudocode the drafts start from (computed, not confirmed)", ev,
                      'dcp analyzer declare ghidra|rea|none [root=DIR] [file=PATH] --why "..."')


def work_obligations(p, view=None) -> list[Obligation]:
    """The layout and match obligations of the current target: the first open function and the counts; the
    first item of the grade queue."""
    from collections import Counter

    from .ledger import grades as G
    from .ledger import layoutview as LV
    out = []
    v = view or LV.View.load(p, p.store)
    glo, ghi, _ = v.game
    funcs = [lo for lo, _, _ in v.funcs if glo <= lo < ghi]
    without = sum(1 for a in funcs if a not in v.sources)
    rows = LV.unit_rows(v)
    c = Counter(r["status"] for r in rows)
    nxt = first_open(v)
    if nxt or c.get("open"):
        ev = ""
        if nxt:
            ev = (f"next={nxt['addr']:#010x} kind={nxt['kind']} size={nxt['size']} unit={nxt['unit'] or '-'} start={nxt['how']} "
                  f"analyzed={'yes' if nxt['analyzed'] else 'no'} (dcp layout next: the evidence)")
        out.append(Obligation("layout", p.target_name,
                              f"{without} of {len(funcs)} functions of the game code without a fragment; units open={c.get('open', 0)} "
                              f"separated={c.get('separated', 0)}", ev, "dcp session start; dcp layout next; dcp draft --next"))
    grades = G.function_grades(p.store)
    if grades:
        q = G.queue(p.store, "base")
        below = sum(1 for r in grades if r["code"] != "byte" or r["readability"] != "readable")
        if below:
            ev = f"next={q[0]['addr']:#010x} {q[0]['name']} {q[0]['code']}+{q[0]['readability']}" if q else "base queue empty: dcp next --deep"
            out.append(Obligation("match", p.target_name, f"{below} of {len(grades)} fragments below byte + readable", ev, "dcp next"))
    return out


def first_open(v) -> dict | None:
    """The first open item of the game code (what `dcp layout next` shows first, without its evidence lines)."""
    from .ledger import drafts
    items = v.items()
    starts = sorted({lo for lo, _, w, _ in items if w in ("func", "start")} | {v.game[1]})
    for lo, hi, what, f in items:
        if what in ("func", "start") and lo in v.sources:
            continue
        k = bisect.bisect_right(starts, lo)
        nxt = starts[k] if k < len(starts) else v.game[1]
        u = v.unit_at(lo)
        hows = ",".join(sorted({s.value["how"] for s in v.starts.get(lo, [])})) or "-"
        return {"addr": lo, "kind": what, "size": (nxt - lo) if what != "unknown" else (hi - lo), "unit": u.tu if u else None,
                "how": hows, "analyzed": drafts.draft(v.store, v.project.image.sha256, lo) is not None}
    return None


def compute(p, view=None, work: bool = True) -> list[Obligation]:
    """Every open obligation of the current target, in order (the project-wide ones included)."""
    out = setup_obligations(p)
    if work:
        out += work_obligations(p, view)
    return out


def phase(obls: list[Obligation]) -> str:
    if any(o.gate for o in obls):
        return "setup"
    if any(o.id == "layout" for o in obls):
        return "layout"
    if any(o.id == "match" for o in obls):
        return "match"
    return "done"


def gate_failures(p) -> list[Obligation]:
    """The open toolchain and libs obligations of the current target (the session and check gate)."""
    return [o for o in setup_obligations(p) if o.gate]
