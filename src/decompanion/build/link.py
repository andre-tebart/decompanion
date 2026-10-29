"""The full link of a target (lifted from the first attempt's link/link.py full_link): every object of the
target through the toolchain's linker, the unresolved externals classified.

What goes in (Toolchain.link, LinkJob):
  objects      every compiled unit of the target, in the order of their first fragment's address (LINK lays
               the objects out in command-line order), plus a generated entry object when the start-up code
               calls an entry the sources name otherwise (Toolchain.entry_object), plus the alias object
  /INCLUDE     every external function symbol the objects define (so /OPT:REF keeps it and its references are
               checked)
  a dll        /DLL /BASE:<image base> and a module definition file from the image's exports with their
               ordinals (Toolchain.module_definition); an export whose address has no fragment yet is left out
               of it and listed as undrafted (open layout work: LINK cannot build an export nothing defines)
  libraries    the target's archives (the static CRT), the import library of every DLL the image imports
               (Toolchain.import_library_name, found in the toolchain's library directories or the project's
               libs/), the toolchain's default libraries
  aliases      one weak external per extra name of a data address: when the sources give one address several
               names (`extern` views of one object under another type), the name an object defines is the
               canonical one and every other resolves to it
Output under build/link/<target>/: the image, the map, the response file, link.log and the unresolved
externals in four files, classified as in the first attempt:
  data      a data name of the sources (a definition or an `extern` with an address) nothing defines: define it
  renames   a stale name: it spells (placeholder) or is registered at the address of a function whose fragment
            defines another name
  aliases   a name declared at the address of a data object defined under another name
  undrafted a placeholder (or a name the ledger registers) whose address has no definition in the sources yet: a
            function start without a fragment, or a data address no definition names; open layout work, not a link
            error (the link is ok when nothing else is unresolved)
  other     everything else (a real name without an address, a CRT internal, ...)
The link is skipped when its inputs (the arguments, every object and library by content hash) are those of the
last successful-or-not link and its log is on disk: the result is read back.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..ledger import srcscan
from ..ledger.fact import Kind
from ..ledger.store import sha256
from ..match import compare as C
from ..toolchains.base import LinkJob


@dataclass
class LinkReport:
    target: str
    ok: bool = False
    skipped: str = ""
    objects: int = 0
    includes: int = 0
    unresolved: dict = field(default_factory=dict)     # class -> [lines]
    errors: list = field(default_factory=list)
    out: str = ""
    cached: bool = False
    ms: int = 0

    @property
    def n_unresolved(self):
        return sum(len(v) for v in self.unresolved.values())


def file_digest(p: Path) -> str:
    return hashlib.sha256(Path(p).read_bytes()).hexdigest() if Path(p).exists() else "missing"


def find_library(project, name: str) -> Path | None:
    tc = project.toolchain
    for d in [project.root / "libs", *tc.library_search_dirs()]:
        for p in (d / name, d / name.upper()):
            if p.exists():
                return p
        if d.exists():
            for p in d.iterdir():
                if p.name.lower() == name.lower():
                    return p
    return None


def full_link(project, log=None) -> LinkReport:
    root, tc, img, st = project.root, project.toolchain, project.image, project.store
    rep = LinkReport(project.target_name)
    t0 = time.perf_counter()
    out_dir = root / "build" / "link" / project.target_name
    out_dir.mkdir(parents=True, exist_ok=True)
    tus = st.tus()
    builds = sorted(st.facts(Kind.build), key=lambda f: (f.lo, f.value["tu"]))
    failed = [f.value["tu"] for f in builds if not f.value["ok"]]
    if failed:
        rep.errors.append("units that do not compile: " + ", ".join(failed))
    order = [f.value["tu"] for f in builds if f.value["ok"] and f.value["tu"] in tus]
    objs = []
    for u in order:
        p = root / "build" / "obj" / f"{tus[u]['obj_hash']}.obj"
        if p.exists():
            objs.append((u, p))
    rep.objects = len(objs)
    if not objs:
        rep.skipped = "no compiled unit"
        return rep
    parsed = [(u, C.read_object(project, tus[u]["obj_hash"])) for u, _ in objs]
    defined = set()
    includes = []
    for u, o in parsed:
        for s in o.symbols.values():
            if s.defined and s.external:
                defined.add(s.name)
        for s in o.functions():
            if s.external:
                includes.append(s.name)
    rep.includes = len(includes)
    kind = img.kind
    # the user entry: the name the sources give the function at the address the CRT start-up calls
    entry_at = {f.lo for f in st.facts(Kind.name) if f.value.get("origin") == "entry"}
    src_names = {}
    for f in st.facts(Kind.source):
        if f.value.get("what") == "func" and f.run == "L.src":
            src_names[f.lo] = f.value["symbol"]
    user = next((src_names[a] for a in sorted(entry_at) if a in src_names), None)
    extra = []
    entry_obj = tc.entry_object(kind, out_dir, user)
    if entry_obj is not None:
        extra.append(entry_obj)
    # aliases: several source names of one data address
    by_addr: dict[int, list[str]] = {}
    for f in st.facts(Kind.name):
        if f.value.get("origin") == "source" and f.run == "L.src" and f.lo not in src_names:
            by_addr.setdefault(f.lo, []).append(f.value["name"])
    aliases = []
    for a, names in sorted(by_addr.items()):
        syms = [(n, tc.data_symbol(n)) for n in sorted(set(names))]
        canon = next((s for n, s in syms if s in defined), None)
        if canon is None:
            continue
        aliases += [(s, canon) for n, s in syms if s != canon and s not in defined]
    if aliases:
        alias_obj = out_dir / "aliases.obj"
        project.objfmt.alias_object(alias_obj, aliases)
        extra.append(alias_obj)
    libs = [*project.lib_archives]
    missing_libs = []
    for dll in sorted({i.dll for i in img.imports()}, key=str.lower):
        name = tc.import_library_name(dll)
        p = find_library(project, name)
        if p is None:
            missing_libs.append(f"no import library {name} for {dll}")
        else:
            libs.append(p)
    libs += tc.default_libraries(kind)
    rep.errors += missing_libs
    def_file = None
    open_exports = []
    if img.is_dll:
        def_file = out_dir / f"{project.target_name}.def"
        exports = [e for e in img.exports() if not e.forwarder]
        open_exports = [f"{e.name or '#' + str(e.ordinal)}  (export, no fragment at {e.va:#010x} yet)" for e in exports if e.va not in src_names]
        text = tc.module_definition(project.image_path.stem, [e for e in exports if e.va in src_names])
        if not def_file.exists() or def_file.read_text() != text:
            def_file.write_text(text, newline="\n")
    out = out_dir / project.image_path.name
    job = LinkJob(cwd=root, out=out, objects=[*extra, *(p for _, p in objs)], libraries=libs, dll=img.is_dll, base=img.base,
                  map_file=out_dir / f"{project.target_name}.map", def_file=def_file, includes=includes,
                  subsystem=kind if kind in ("gui", "console") else "", rsp=out_dir / "link.rsp")
    rep.out = out.relative_to(root).as_posix()
    key = sha256(json.dumps([str(x) for x in job.objects] + [str(x) for x in libs] + includes),
                 *(file_digest(p) for p in [*job.objects, *[x for x in libs if isinstance(x, Path)]]),
                 file_digest(def_file) if def_file else "", str(img.base))
    cache = out_dir / "link.json"
    hit = None
    if cache.exists():
        try:
            hit = json.loads(cache.read_text())
        except ValueError:
            hit = None
    if hit is not None and hit.get("key") == key and "raw" in hit and (out.exists() or not hit.get("link_ok")):
        rep.unresolved, rep.cached = classify(project, hit["raw"]), True    # the classes follow the current facts
        rep.unresolved["undrafted"] += open_exports
        rep.errors += hit["errors"]
        rep.ok = not rep.errors and (hit["link_ok"] or (bool(hit["raw"]) and not any(v for k, v in rep.unresolved.items() if k != "undrafted")))
        rep.ms = int((time.perf_counter() - t0) * 1000)
        return rep
    if out.exists():
        out.unlink()
    res = tc.link(job)
    (out_dir / "link.log").write_text(res.log, newline="\n")
    rep.unresolved = classify(project, res.unresolved)
    rep.unresolved["undrafted"] += open_exports
    rep.errors += res.errors
    rep.ok = not rep.errors and (res.ok or (bool(res.unresolved) and not any(v for k, v in rep.unresolved.items() if k != "undrafted")))
    for k, lines in rep.unresolved.items():
        (out_dir / f"unresolved-{k}.txt").write_text("".join(l + "\n" for l in lines), newline="\n")
    cache.write_text(json.dumps({"key": key, "ok": rep.ok, "link_ok": res.ok, "raw": res.unresolved, "unresolved": rep.unresolved,
                                 "errors": res.errors}), newline="\n")
    rep.ms = int((time.perf_counter() - t0) * 1000)
    return rep


def classify(project, unresolved: list[str]) -> dict[str, list[str]]:
    """The five classes of the module docstring, one line per symbol (`symbol  ->  hint`)."""
    st, tc = project.store, project.toolchain
    starts = {f.lo for f in st.facts(Kind.start)}
    registered: dict[str, set] = {}
    for f in st.facts(Kind.name):
        if f.value.get("origin") in ("decl", "export", "entry"):
            registered.setdefault(f.value["name"], set()).add(f.lo)
    data_names, func_at, name_at = set(), {}, {}
    for f in st.facts(Kind.source):
        if f.run == "L.src":
            if f.value.get("what") == "func":
                func_at[f.lo] = f.value["symbol"]
            elif f.value.get("what") == "data":
                data_names.add(f.value["symbol"])
    data_at = {}
    for f in st.facts(Kind.name):
        if f.run == "L.src":
            name_at.setdefault(f.value["name"], set()).add(f.lo)
            if f.lo not in func_at:
                data_at.setdefault(f.lo, f.value["name"])
    sc = srcscan.scan(project.root, project.input_hash("src"))
    for d in sc.data:
        data_names.add(d.name)
    out = {"data": [], "renames": [], "aliases": [], "undrafted": [], "other": []}
    img = project.image
    for u in unresolved:
        cn = tc.undecorate(u)
        addrs = set(name_at.get(cn, ()))
        m = srcscan.PLACEHOLDER_ADDR.fullmatch(cn)
        if m:
            addrs.add(int(m.group(1) or m.group(2), 16))
        hit = next((a for a in sorted(addrs) if a in func_at and func_at[a] != cn), None)
        if hit is not None:
            out["renames"].append(f"{u}  ->  {func_at[hit]}  ({hit:#010x})")
            continue
        hit = next((a for a in sorted(addrs) if a in data_at and data_at[a] != cn), None)
        if hit is not None:
            out["aliases"].append(f"{u}  ->  {data_at[hit]}  ({hit:#010x})")
            continue
        if not addrs and cn in registered:
            addrs = set(registered[cn])
        open_at = sorted(a for a in addrs if a not in func_at and a not in data_at and img.section_of(a) is not None
                         and (a in starts or not img.section_of(a).holds_code))
        if open_at:                     # a placeholder or a registered name whose address the sources do not define yet
            what = "no fragment" if open_at[0] in starts else "no definition"
            out["undrafted"].append(f"{u}  ({what} at {open_at[0]:#010x} yet)")
            continue
        if cn in data_names:
            out["data"].append(u)
            continue
        where = sorted(a for a in addrs if a not in func_at)
        out["other"].append(u + (f"  (no fragment at {where[0]:#010x})" if where else ""))
    return out
