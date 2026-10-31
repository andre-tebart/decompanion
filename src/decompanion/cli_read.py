"""dcp: the reading commands of the layout phase (milestone 4): disasm, dump, refs, layout literals, layout
starts. Same output contract as cli.py: one record per line, key=value tokens, addresses 0x%08x, counts
before lists. Nothing here decides anything: every line is a fact of the store, a byte of the image, or a line
of the sources.
"""
from __future__ import annotations

import bisect
import re
import struct
import sys
from pathlib import Path

from .cli import fmt_addr, open_project, parse_addr, parse_range, record, refresh
from .ledger.fact import Kind, Level


def err(cmd: str, msg: str) -> int:
    print(f"dcp {cmd}: {msg}", file=sys.stderr)
    return 1


# ------------------------------------------------------------------------------------------------ lookups
def resolve(p, names, key: str) -> int | None:
    """An address from `0xADDR`, a name the ledger knows (ledger/names.py), or a placeholder spelling one."""
    from .ledger import srcscan
    k = key.strip()
    if k.lower().startswith("0x"):
        return parse_addr(k)
    hits = names.by_name.get(k)
    if hits:
        return sorted(hits)[0]
    m = srcscan.PLACEHOLDER_ADDR.fullmatch(k)
    if m:
        return srcscan.placeholder_value(m)
    return None


def all_starts(p) -> list[int]:
    """Every known function start of the target (start facts of any producer, function and thunk symbols) and
    the end of every code section: what bounds a function's slot."""
    st = p.store
    s = {f.lo for f in st.facts(Kind.start)}
    s |= {f.lo for f in st.facts(Kind.symbol) if f.value.get("skind") in ("func", "thunk") and f.level > Level.open}
    s |= {sec.end for sec in p.image.sections if sec.holds_code}
    return sorted(s)


def walk_func(p, a: int):
    """The walked or placed function / thunk symbol covering a (not the match phase's), or None."""
    return next((f for f in p.store.facts(Kind.symbol, a, a + 1) if f.value.get("skind") in ("func", "thunk")
                 and not f.run.startswith("M.") and f.level > Level.open), None)


def annotate(isa, names, text: str) -> str:
    """The instruction text with ` <label>` after every number the ledger names (Names.annotate)."""
    return names.annotate(text)


# ------------------------------------------------------------------------------------------------ disasm
def cmd_disasm(args):
    """The original's instructions at ADDR (through the target's ISA plugin) with the ledger's name after every
    address operand. Default length: the rest of the function holding ADDR (else up to the next start, at most
    0x400 bytes); LEN as a byte count or `..END`. --ours NAME: our compiled function from its unit's object,
    each relocated field with the symbol our object refers to."""
    from .ledger.names import Names
    p, e = open_project(args)
    refresh(p, e)
    names = Names(p, p.store)
    isa, img, tc = p.isa, p.image, p.toolchain
    if args.ours:
        return disasm_ours(p, args.ours)
    if not args.addr:
        return err("disasm", "ADDR (or --ours NAME) is required")
    a = resolve(p, names, args.addr)
    if a is None or img.section_of(a) is None:
        return err("disasm", f"{args.addr}: no such address or name in target {p.target_name}")
    fn = walk_func(p, a)
    if args.len:
        hi = parse_addr(args.len[2:]) if args.len.startswith("..") else a + parse_addr(args.len)
    elif fn is not None:
        hi = fn.hi
    else:
        ss = all_starts(p)
        i = bisect.bisect_right(ss, a)
        hi = min(ss[i] if i < len(ss) else a + 0x40, a + 0x400)
    sec = img.section_of(a)
    hi = min(hi, sec.end)
    if fn is not None and fn.lo < a:
        # inside a function: decoded from its start, so the listing begins at the first instruction boundary at or
        # after ADDR (an address inside an instruction decodes as garbage, or not at all)
        lines = [ln for ln in isa.disasm(img.read(fn.lo, hi - fn.lo), fn.lo, tc.fill_forms) if ln.addr >= a]
        if lines and lines[0].addr != a:
            print(f"note: {fmt_addr(a)} is inside an instruction of {names.name(fn.lo) or fmt_addr(fn.lo)}: the listing "
                  f"starts at the next instruction, {fmt_addr(lines[0].addr)}")
            a = lines[0].addr
    else:
        lines = isa.disasm(img.read(a, hi - a), a, tc.fill_forms)
    starts = set(all_starts(p))
    print(record(target=p.target_name, disasm=(a, hi), section=sec.name, function=(fn.lo, fn.hi) if fn else None,
                 name=names.name(fn.lo) if fn else None, instructions=len(lines)))
    end = a
    for ln in lines:
        if ln.addr in starts:
            hows = sorted({f.value.get("how", "") for f in p.store.facts(Kind.start, ln.addr, ln.addr + 1)} - {""})
            print(f"-- {fmt_addr(ln.addr)}  {names.name(ln.addr) or '-'}  start: {','.join(hows) or 'symbol'}")
        raw = img.read(ln.addr, ln.size).hex()
        print(f"   {fmt_addr(ln.addr)}  {raw:<16} {annotate(isa, names, ln.text)}" + ("   ; fill" if ln.fill else ""))
        end = ln.addr + ln.size
    if end < hi:
        print(f"   {fmt_addr(end)}  ({hi - end} bytes do not decode)")
    return 0


def disasm_ours(p, key: str) -> int:
    from .cli_match import find_function
    from .match import compare as C
    r = find_function(p, key)
    if r is None:
        return err("disasm", f"--ours {key}: no compiled function of that name or address (dcp build)")
    t = p.store.tus().get(r["unit"])
    if t is None or not t["ok"]:
        return err("disasm", f"unit {r['unit']} has no object (dcp build)")
    obj = C.read_object(p, t["obj_hash"])
    sym = C.function_index(obj, p.toolchain).get(r["name"]) if obj else None
    if sym is None:
        return err("disasm", f"the object of unit {r['unit']} defines no {r['name']}")
    code = obj.function_code(sym)
    relocs = {off: (p.toolchain.undecorate(s.name) if s is not None else "?") for off, rel, s in code.relocs}
    lines = p.isa.disasm(code.data, r["addr"], p.toolchain.fill_forms)
    print(record(target=p.target_name, ours=r["name"], unit=r["unit"], at=r["addr"], size=len(code.data), relocations=len(relocs),
                 code=r["code"]))
    for ln in lines:
        o = ln.addr - r["addr"]
        hit = [relocs[k] for k in sorted(relocs) if o <= k < o + ln.size]
        tail = ("   ; reloc " + ", ".join(hit)) if hit else ""
        print(f"   {fmt_addr(ln.addr)}  {code.data[o:o + ln.size].hex():<16} {ln.text}{tail}" + ("   ; fill" if ln.fill else ""))
    return 0


# ------------------------------------------------------------------------------------------------ dump
def printable(b: int) -> str:
    return chr(b) if 0x20 <= b <= 0x7e or 0xa0 <= b <= 0xff else "."


def cmd_dump(args):
    """The original's bytes at ADDR: 16 per row as hex and latin-1, with the symbols that start in each row;
    clipped at the end of the section, rows beyond its file data marked. --str: every NUL-terminated string
    starting in the range; --dword: every aligned dword as unsigned, signed and float, with its name when it is
    an address; --float: every aligned float, and the double at every 8-aligned offset."""
    from .ledger.names import Names
    p, e = open_project(args)
    refresh(p, e)
    names = Names(p, p.store)
    img = p.image
    a = resolve(p, names, args.addr)
    if a is None or not img.in_image(a):
        return err("dump", f"{args.addr}: no such address or name in target {p.target_name}")
    n = parse_addr(args.len) if args.len else 0x40
    sec = img.section_of(a)
    hi = a + n
    note = None
    if sec is not None and hi > sec.end:
        hi, note = sec.end, f"at the end of {sec.name}"
    data = img.read(a, hi - a)
    off = img.off(a)
    print(record(target=p.target_name, dump=(a, hi), section=sec.name if sec else "(headers)", rva=f"{a - img.base:#x}",
                 file_off=f"{off:#x}" if off is not None else None, clipped=note))
    raw_end = (sec.va + sec.raw_size) if sec else hi
    starts = {}
    for f in p.store.facts(Kind.symbol, a, hi):
        if not f.run.startswith("M."):
            starts.setdefault(max(f.lo, a), []).append(f)
    for row in range(a, hi, 16):
        chunk = data[row - a:row - a + 16]
        tags = []
        for s in range(row, row + len(chunk)):
            for f in starts.get(s, ()):
                nm = names.name(f.lo)
                tags.append(f"{f.value.get('skind')}@{f.lo:#x}" + (f"={nm}" if nm else "") + (f"..{f.hi:#x}" if f.lo < a else ""))
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(printable(b) for b in chunk)
        print(f"{fmt_addr(row)}  {hx:<47}  |{asc:<16}|" + (("  " + " ".join(tags)) if tags else "")
              + ("  (no file data)" if row >= raw_end else ""))
    if args.str:
        k = 0
        while k < len(data):
            if data[k] and (k == 0 or data[k - 1] == 0):
                s = img.cstr(a + k)
                if s and all(0x20 <= c <= 0x7e or c in (9, 10, 13) or c >= 0xa0 for c in s):
                    print("  " + record(string=a + k, length=len(s), text=s.decode("latin-1")))
                k += max(len(s), 1)
                continue
            k += 1
    if args.dword:
        for k in range(0, len(data) - 3, 4):
            u = int.from_bytes(data[k:k + 4], "little")
            i = u - (1 << 32) if u & 0x80000000 else u
            f = struct.unpack("<f", data[k:k + 4])[0]
            print("  " + record(at=a + k, u32=f"{u:#010x}", i32=str(i), f32=f"{f:.7g}", name=names.label(u) if img.in_image(u) else None))
    if args.float:
        for k in range(0, len(data) - 3, 4):
            f = struct.unpack("<f", data[k:k + 4])[0]
            d = struct.unpack("<d", data[k:k + 8])[0] if k + 8 <= len(data) and (a + k) % 8 == 0 else None
            print("  " + record(at=a + k, f32=f"{f:.7g}", f64=f"{d:.15g}" if d is not None else None))
    return 0


# ------------------------------------------------------------------------------------------------ refs
def source_files(root: Path) -> list[Path]:
    out = []
    for d, pats in (("src", ("*.c", "*.h")), ("include", ("*.h",))):
        base = root / d
        if base.exists():
            out += sorted({q for pat in pats for q in base.rglob(pat)})
    return out


def cmd_refs(args):
    """Everything that names one function or datum: its definition and address comment, every fact that names
    the address (name facts of every origin, declarations, the analyzer's draft), the symbol and unit there, every
    reference to it and from it (with the ledger's names), and every line of src/ and include/ that mentions
    one of its names as a whole word or its address as a number."""
    from .ledger import drafts as G
    from .ledger.names import Names
    p, e = open_project(args)
    refresh(p, e)
    names = Names(p, p.store)
    st = p.store
    a = resolve(p, names, args.what)
    if a is None:
        print(record(target=p.target_name, refs=args.what, address=None) + "  (no address: searching the sources for the name)")
        idents = {args.what}
    else:
        idents = {n for n, _ in names.all_at.get(a, ())} | ({args.what} if not args.what.lower().startswith("0x") else set())
        src = next((f for f in st.facts(Kind.source, a, a + 1) if f.lo == a and f.run == "L.src"), None)
        if src is not None:
            idents.add(src.value["symbol"])
        sym = walk_func(p, a) or next((f for f in st.facts(Kind.symbol, a, a + 1) if not f.run.startswith("M.")), None)
        unit = next((f for f in st.facts(Kind.unit, a, a + 1) if "status" in f.value), None)
        print(record(target=p.target_name, refs=args.what, address=a, name=names.name(a), origin=names.origin(a),
                     symbol=sym.value.get("skind") if sym else None, extent=(sym.lo, sym.hi) if sym else None,
                     level=sym.level.name if sym else None, unit=unit.value["tu"] if unit else None))
        if src is not None:
            first = (p.root / src.value["file"]).read_text(errors="replace").split("\n", 1)[0] if (p.root / src.value["file"]).exists() else ""
            print("  " + record(definition=f"{src.value['file']}:{src.value['line']}", symbol=src.value["symbol"], comment=first.strip()))
        for f in st.facts(Kind.name, a, a + 1):
            if f.lo == a:
                print("  " + record(named=f.value["name"], origin=f.value.get("origin"), level=f.level.name, by=f.by))
        for f in st.facts(Kind.start, a, a + 1):
            if f.lo == a:
                print("  " + record(start=f.value.get("how"), level=f.level.name, by=f.by))
        d = G.draft(st, p.image.sha256, a)
        if d is not None:
            print("  " + record(analyzer=d.analyzer, draft=d.name or None, size=d.size, source=d.source) + f"  (dcp draft {a:#x} --show)")
        lo, hi = (sym.lo, sym.hi) if sym is not None and sym.lo == a else (a, a + 1)
        refs_to = [f for f in st.facts(Kind.ref) if f.value.get("to") == a or (lo <= f.value.get("to", -1) < hi and not lo <= f.lo < hi)]
        refs_from = [f for f in st.facts(Kind.ref, lo, hi)] if hi > lo + 1 else []
        print(f"  refs_to={len(refs_to)}  refs_from={len(refs_from)}")
        for f in sorted(refs_to, key=lambda f: f.lo):
            fn = walk_func(p, f.lo)
            print("  " + record(ref_to=f.value["rkind"], site=f.lo, to=f.value["to"], fn=fn.lo if fn else None,
                                fn_name=names.name(fn.lo) if fn else None))
        for f in sorted(refs_from, key=lambda f: (f.lo, f.value["rkind"])):
            print("  " + record(ref_from=f.value["rkind"], site=f.lo, to=f.value["to"], name=names.label(f.value["to"])))
    words = re.compile(r"\b(" + "|".join(sorted(map(re.escape, idents))) + r")\b") if idents else None
    num = re.compile(rf"\b0x0*{a:x}\b", re.I) if a is not None else None
    hits = 0
    for path in source_files(p.root):
        rel = path.relative_to(p.root).as_posix()
        for i, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            if (words and words.search(line)) or (num and num.search(line)):
                print(f"  {rel}:{i}: {line.strip()}")
                hits += 1
    for path in sorted((p.root / "decl").glob("*.dcl")) if (p.root / "decl").exists() else []:
        rel = path.relative_to(p.root).as_posix()
        for i, line in enumerate(path.read_text().splitlines(), 1):
            if (words and words.search(line)) or (num and num.search(line)):
                print(f"  {rel}:{i}: {line.strip()}")
                hits += 1
    print(f"  source_lines={hits}  names={','.join(sorted(idents)) or '-'}")
    return 0


# ------------------------------------------------------------------------------------------------ layout literals
def literal_targets(p, v):
    """{target address: {section, kind, users: set of function starts, sites, data_refs}} of every data address a
    code site refers to: through base relocations when the image has them (exact for a dll), else through the
    walk's memory operands and immediates. A string symbol counts once (its start); import slots are skipped."""
    img, st = p.image, p.store
    code = [(s.va, s.end) for s in img.sections if s.holds_code]
    use = ("reloc",) if img.relocations() else ("operand", "immediate")
    strings = sorted((f.lo, f.hi) for f in v.syms if f.value.get("skind") == "string")
    slos = [s[0] for s in strings]
    skip = sorted((f.lo, f.hi) for f in v.syms if f.value.get("skind") in ("iat",))
    from .rules import layout as L
    at = L.container(v.funcs)
    out = {}
    ops = sorted((f.lo, f.hi, f.value.get("size")) for f in st.facts(Kind.ref) if f.value["rkind"] == "operand")
    op_los = [o[0] for o in ops]

    def operand_size(site):
        j = bisect.bisect_right(op_los, site) - 1
        return ops[j][2] if j >= 0 and ops[j][0] <= site < ops[j][1] else None
    for r in st.facts(Kind.ref):
        if r.value["rkind"] not in use:
            continue
        t = r.value["to"]
        sec = img.section_of(t)
        if sec is None or sec.holds_code or any(lo <= t < hi for lo, hi in skip):
            continue
        i = bisect.bisect_right(slos, t) - 1
        kind = "data"
        if i >= 0 and strings[i][0] <= t < strings[i][1]:
            t, kind = strings[i][0], "string"
        rec = out.setdefault(t, {"section": sec.name, "kind": kind, "users": set(), "sites": 0, "data_refs": 0, "size": None,
                                 "writable": sec.writable})
        if any(lo <= r.lo < hi for lo, hi in code):
            fn = at(r.lo)
            if fn is not None:
                rec["users"].add(fn[0])
                rec["sites"] += 1
                sz = operand_size(r.lo)
                if sz and rec["size"] is None:
                    rec["size"] = sz
        else:
            rec["data_refs"] += 1
    return out


def cmd_layout_literals(args):
    """The literal-pool view of a unit or a range (B-LIT made visible): every data address the functions of the
    range refer to, in address order per section, with its first user (the lowest function start among all its
    users in the image) and that user's unit; the block of each function (the lowest and highest literal it is
    the first user of, and the jump from the highest literal first used by an earlier function: a big forward
    jump skips another unit's block, and `between=` names the later functions (and their units) whose literals
    fill the gap: the objects the link order puts in between); per unit the block of its first-used pooled literals (strings and
    constants of read-only sections, reached from code only) and whether it interleaves with a neighbour's.
    VC6 /GF + LINK: pooled literals sit with their first user in link order, so neighbouring units' blocks do
    not interleave."""
    from .ledger import layoutview as LV
    from .rules import layout as L
    p, e = open_project(args)
    refresh(p, e)
    v = LV.View.load(p, p.store)
    img = p.image
    glo, ghi, _ = v.game
    unit = None
    if args.what is None:
        lo, hi = glo, ghi
    elif args.what.lower().startswith("0x"):
        lo, hi = parse_range(args.what)
    else:
        unit = next((u for u in v.units if u.tu == args.what), None)
        if unit is None:
            return err("layout literals", f"no unit {args.what!r} (dcp layout units), and not a range 0xLO..0xHI")
        lo, hi = unit.lo, unit.hi
    targets = literal_targets(p, v)
    uat = L.unit_index(v.units)

    def utu(a):
        i = uat(a) if a is not None else None
        return v.units[i].tu if i is not None else None

    def pooled(t, r):
        return r["data_refs"] == 0 and r["users"] and (r["kind"] == "string" or not r["writable"])

    fns = [f for f in v.funcs if lo <= f[0] < hi]
    mine = sorted(t for t, r in targets.items() if any(lo <= u < hi for u in r["users"]))
    secs = sorted({targets[t]["section"] for t in mine})
    print(record(target=p.target_name, literals=(lo, hi), unit=unit.tu if unit else None, functions=len(fns), targets=len(mine),
                 sections=",".join(secs) or None))
    # per function: its block per section and the jump from the earlier functions' highest literal
    by_first = {}
    for t, r in targets.items():
        if r["users"] and pooled(t, r):
            by_first.setdefault(min(r["users"]), []).append(t)
    for fs, _, _ in fns:
        own = sorted(by_first.get(fs, []))
        for sec in sorted({targets[t]["section"] for t in own}):
            ts = [t for t in own if targets[t]["section"] == sec]
            earlier = [t for t, r in targets.items() if r["section"] == sec and pooled(t, r) and min(r["users"]) < fs]
            jump = ts[0] - max(earlier) if earlier else None
            gap = sorted({min(r["users"]) for t, r in targets.items() if r["section"] == sec and pooled(t, r)
                          and earlier and max(earlier) < t < ts[0]})
            between = ",".join(f"{g:#010x}({utu(g) or '-'})" for g in gap[:4]) + (f",+{len(gap) - 4}" if len(gap) > 4 else "")
            print("  " + record(fn=fs, unit=utu(fs), section=sec, first_used=len(ts), block=(ts[0], ts[-1] + 1),
                                jump=(f"{jump:+#x}" if jump is not None else None), between=between or None))
    for t in mine:
        r = targets[t]
        first = min(r["users"])
        extra = {}
        if r["kind"] == "string":
            extra["text"] = img.cstr(t)[:48].decode("latin-1")
        elif not r["writable"] and r["size"] in (4, 8):
            raw = img.read(t, r["size"])
            extra["value"] = f"{struct.unpack('<f' if r['size'] == 4 else '<d', raw)[0]:.9g}"
        print("  " + record(lit=t, section=r["section"], kind=r["kind"], first=first, first_unit=utu(first),
                            first_in_range=lo <= first < hi, users=len(r["users"]), data_refs=r["data_refs"] or None,
                            pooled=pooled(t, r), **extra))
    # unit blocks and interleaving among the units touching the range and their neighbours
    blocks = {}
    for t, r in targets.items():
        if not pooled(t, r):
            continue
        i = uat(min(r["users"]))
        if i is None:
            continue
        b = blocks.setdefault((i, r["section"]), [t, t + 1, 0])
        b[0], b[1], b[2] = min(b[0], t), max(b[1], t + 1), b[2] + 1
    near = {i for i, u in enumerate(v.units) if u.lo < hi and lo < u.hi}
    near |= {i - 1 for i in near if i > 0} | {i + 1 for i in near if i + 1 < len(v.units)}
    for (i, sec), (blo, bhi, n) in sorted(blocks.items(), key=lambda kv: (kv[0][1], kv[1][0])):
        if i not in near:
            continue
        inter = sorted(v.units[j].tu for (j, s2), (c, d, _) in blocks.items() if s2 == sec and j != i and c < bhi and blo < d)
        print("  " + record(unit_block=v.units[i].tu, section=sec, range=(blo, bhi), literals=n, interleaves=",".join(inter) or None))
    return 0


# ------------------------------------------------------------------------------------------------ layout fptrs
def cmd_layout_fptrs(args):
    """Every function pointer in data: a relocated address field (a `ref` reloc fact) outside the code sections
    whose target is a known function start, in site order, with the function's name and unit and the distance
    to the previous site of the same section (`delta=`: a repeating delta is the stride of a table of structs,
    such as zlib's configuration_table). A unit or a code range selects by the functions pointed to, a data
    range by the sites; default: every function pointer."""
    from .ledger import layoutview as LV
    from .ledger.names import Names
    from .rules import layout as L
    p, e = open_project(args)
    refresh(p, e)
    v = LV.View.load(p, p.store)
    img = p.image
    names = Names(p, p.store)
    starts = set(all_starts(p))
    uat = L.unit_index(v.units)
    by_site, by_target = None, None
    if args.what is None:
        pass
    elif args.what.lower().startswith("0x"):
        lo, hi = parse_range(args.what)
        sec = img.section_of(lo)
        if sec is not None and sec.holds_code:
            by_target = (lo, hi)
        else:
            by_site = (lo, hi)
    else:
        unit = next((u for u in v.units if u.tu == args.what), None)
        if unit is None:
            return err("layout fptrs", f"no unit {args.what!r} (dcp layout units), and not a range 0xLO..0xHI")
        by_target = (unit.lo, unit.hi)
    rows = []
    for f in p.store.facts(Kind.ref):
        if f.value["rkind"] != "reloc" or f.value["to"] not in starts:
            continue
        sec = img.section_of(f.lo)
        if sec is None or sec.holds_code:
            continue
        rows.append((f.lo, sec.name, f.value["to"]))
    rows.sort()
    prev = {}
    out = []
    for site, sec, to in rows:
        delta = site - prev[sec] if sec in prev else None
        prev[sec] = site
        if by_site and not by_site[0] <= site < by_site[1] or by_target and not by_target[0] <= to < by_target[1]:
            continue
        i = uat(to)
        out.append(record(site=site, section=sec, to=to, name=names.name(to), unit=v.units[i].tu if i is not None else None,
                          delta=delta))
    print(record(target=p.target_name, fptrs=len(out), what=args.what))
    for line in out:
        print("  " + line)
    return 0


# ------------------------------------------------------------------------------------------------ layout starts
def cmd_layout_starts(args):
    """Every function start in a range (default: the game code) with its evidence: every `how` of its start
    facts (export, entry, crt, libref, call, tail, immediate, fptr, decl, source, the analyzer's key), the number of code
    sites that reach it (call, tail, immediate, relocation, operand), the size to the next start, the walk's
    extent, what precedes it (B-FILL), its unit, whether a source drafts it and whether the analyzer has a draft."""
    from .ledger import drafts as G
    from .ledger import layoutview as LV
    from .ledger.names import Names
    p, e = open_project(args)
    refresh(p, e)
    v = LV.View.load(p, p.store)
    names = Names(p, p.store)
    glo, ghi, _ = v.game
    lo, hi = parse_range("..".join(args.range)) if args.range else (glo, ghi)
    starts = {}
    for a, fs in v.starts.items():
        for f in fs:
            starts.setdefault(a, set()).add(f.value.get("how", ""))
    inner = set()
    for flo, fhi, f in v.funcs:
        starts.setdefault(flo, set())
        inner.update(f.value.get("inner", ()))
    keys = sorted(a for a in starts if a not in inner)
    callers = {}
    for r in p.store.facts(Kind.ref):
        if r.value["rkind"] in ("call", "tail", "immediate", "reloc", "operand"):
            callers[r.value["to"]] = callers.get(r.value["to"], 0) + 1
    ends = sorted(set(keys) | {sec.end for sec in p.image.sections if sec.holds_code})
    analyzed = {x.start for x in G.entries(p.store)}
    fn_at = {flo: (flo, fhi) for flo, fhi, _ in v.funcs}
    rows = [a for a in keys if lo <= a < hi]
    print(record(target=p.target_name, starts=len(rows), range=(lo, hi), game=(glo, ghi)))
    for a in rows:
        i = bisect.bisect_right(ends, a)
        nxt = ends[i] if i < len(ends) else hi
        u = v.unit_at(a)
        fl = v.fills.get(a) or {}
        print(record(start=a, how=",".join(sorted(starts[a] - {""})) or "symbol", callers=callers.get(a, 0), size=nxt - a,
                     extent=fn_at.get(a), fill=fl.get("pre"), unit=u.tu if u else None, drafted=a in v.sources,
                     analyzed=a in analyzed, name=names.name(a)))
    return 0
