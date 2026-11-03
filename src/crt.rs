//! The library rules (rules/setup.py documents each criterion; checks.py C.toolchain and S2): the Rich header,
//! the library members placed by their bytes (S.crt.code: place_members), the names their relocations resolve
//! (S.crt.refs), their data sections (S.crt.data), data-only members (S.lib.data), import stubs (S.thunk).
//!
//! native_inputs: {"toolchain": key, "libs": [archive paths], "archives": [archive paths], "decl": the target's
//! toolchain declaration, "target": its name}.

use crate::error::{Error, Result};
use crate::coff::{self, Obj, ABSOLUTE, RELATIVE};
use crate::image;
use crate::rules::Ctx;
use crate::store::{self, Out, Claim, DERIVED, REPRODUCED};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::rc::Rc;

fn err(e: rusqlite::Error) -> Error {
    Error::runtime(e.to_string())
}

fn inputs(ctx: &Ctx) -> Result<&crate::rules::Inputs> {
    Ok(&ctx.inputs)
}

fn toolchain(x: &crate::rules::Inputs) -> Result<Box<dyn crate::toolchain::Toolchain>> {
    crate::toolchain::of(&x.toolchain).ok_or_else(|| Error::runtime("no such toolchain"))
}

fn facts(ctx: &Ctx, db: &Connection, kind: &str) -> Result<Vec<Rc<Claim>>> {
    store::claims(db, &ctx.db, kind, &ctx.needed, |_| true).map_err(err)
}

/// (archive file name, its objects) of the archives an input lists.
fn archives(x: &crate::rules::Inputs, key: &str) -> Result<Vec<(String, Vec<Obj>)>> {
    let mut out = vec![];
    for p in if key == "libs" { &x.libs } else { &x.archives } {
        let b = std::fs::read(p).map_err(|e| Error::runtime(format!("{p}: {e}")))?;
        let name = std::path::Path::new(p).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        out.push((name, coff::archive_objects(&b).map_err(|e| Error::runtime(format!("{p}: {e}")))?));
    }
    Ok(out)
}

/// The name a placed section goes by: its first external symbol, else its first symbol.
fn sec_first_name(o: &Obj, secnum: usize) -> Option<&str> {
    let syms = &o.sections[secnum].syms;
    syms.iter().map(|&k| &o.symbols[k]).find(|s| s.external()).or_else(|| syms.first().map(|&k| &o.symbols[k])).map(|s| s.name.as_str())
}

// ------------------------------------------------------------------------------------------------ S.rich

/// S.rich: the Rich header decoded with the toolchain's product table, with the archives' objects per tool.
pub fn s_rich(ctx: &Ctx, _db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    let entries = img.rich();
    if entries.is_empty() {
        return Ok(());
    }
    let x = inputs(ctx)?;
    let tc = toolchain(x)?;
    let libs = archives(x, "archives")?;
    let stamps = coff::comp_ids(libs.iter().flat_map(|(_, os)| os.iter()));
    let tools = tc.archive_tools(&stamps);
    out.claim(img.base as i64, img.end() as i64, "toolchain", tc.rich_candidates(&entries, &tools), DERIVED);
    Ok(())
}

// ------------------------------------------------------------------------------------------------ S.crt.code

/// One placed group of identical library sections.
pub struct Placement {
    pub lo: i64,
    pub hi: i64,
    pub name: String,                   // the first external symbol, `a|b` for a group of several members
    pub unit: String,                   // lib:<archive>/<member>, `|`-joined for a group
    pub lib: String,                    // the archive of the group's first member
    pub members: usize,                 // the members of the group (1: the identity is proven)
    pub values: Vec<(u32, Vec<String>)>, // every named symbol inside the section: (offset, names)
}

pub enum Placed {
    At(Placement),
    Issue(&'static str, i64, i64, String), // ambiguous | duplicate
}

fn longest_run(mask: &[u8]) -> (usize, usize) {
    let (mut best, mut i) = ((0, 0), 0);
    while i < mask.len() {
        if mask[i] != 0 {
            i += 1;
            continue;
        }
        let mut j = i;
        while j < mask.len() && mask[j] == 0 {
            j += 1;
        }
        if j - i > best.1 {
            best = (i, j - i);
        }
        i = j;
    }
    best
}

/// One library code section: (archive, object, section number).
type Member<'a> = (&'a str, &'a Obj, usize);

/// What a member placed at one address says about other addresses: its references (the name it references, with
/// the address the image's field resolves to; `#<lib>/<object>#<secnum>` for another section of its own object,
/// with that section's base; `#<lib>/<object>:<name>` for a compiler constant, which the linker keeps per object),
/// its external definitions (name, address), and whether every reference into its own section lands where the
/// section's symbol is.
struct Says {
    refs: Vec<(String, i64)>,
    defs: Vec<(String, i64)>,
    self_ok: bool,
}

fn says(img: &crate::pe::Image, (lib, o, k): Member, va: i64) -> Says {
    let sec = &o.sections[k];
    let mut out = Says { refs: vec![], defs: vec![], self_ok: true };
    for r in &sec.relocs {
        let (kind, width) = r.kind_width();
        if kind != ABSOLUTE && kind != RELATIVE {
            continue;
        }
        let Some(sym) = o.symbol_at(r.symbol_index) else { continue };
        let site = (va as u32).wrapping_add(r.offset);
        let Some(t) = r.resolve(site, &img.read(site, width as usize), o.addend(k, r)) else { continue };
        let t = t as i64;
        if sym.defined() && sym.secnum as usize == k {
            out.self_ok &= t == va + sym.value as i64;
        } else if sym.defined() && sym.constant().is_some() {
            out.refs.push((format!("#{lib}/{}:{}", o.name, sym.name), t));
        } else if sym.defined() && sym.external() {
            out.refs.push((sym.name.clone(), t));
        } else if sym.defined() {
            out.refs.push((format!("#{lib}/{}#{}", o.name, sym.secnum), t - sym.value as i64));
        } else if sym.unresolved() {
            out.refs.push((sym.name.clone(), t));
        }
    }
    for &si in &sec.syms {
        let s = &o.symbols[si];
        if s.external() && s.defined() {
            out.defs.push((s.name.clone(), va + s.value as i64));
        }
    }
    out
}

/// The name a dllimport pointer imports, as the image's import table spells it (`__imp__Sleep@4` -> `Sleep`);
/// None for a C++ name.
fn import_name(sym: &str) -> Option<&str> {
    let s = sym.strip_prefix(coff::IMPORT_PREFIX)?;
    let s = s.strip_prefix('_').unwrap_or(s);
    if s.starts_with('?') {
        return None;
    }
    Some(match s.rsplit_once('@') {
        Some((n, d)) if !d.is_empty() && d.bytes().all(|c| c.is_ascii_digit()) => n,
        _ => s,
    })
}

/// What the image's imports and the members placed alone have settled: where a name is (a placed member defines
/// it, or its reference resolves it), the names placed members define at an address, the names they reference at
/// an address, the import slots (all, and by name).
#[derive(Default)]
struct Known {
    at: HashMap<String, i64>,
    defs: HashMap<i64, BTreeSet<String>>,
    refd: HashMap<i64, BTreeSet<String>>,
    slots: HashMap<i64, Option<String>>,
    imports: HashMap<String, i64>,
}

impl Known {
    fn new(img: &crate::pe::Image) -> Known {
        let mut k = Known::default();
        for imp in img.imports() {
            if let Some(n) = &imp.name {
                k.imports.entry(n.clone()).or_insert(imp.slot as i64);
            }
            k.slots.insert(imp.slot as i64, imp.name);
        }
        k
    }

    /// Where a reference's name is settled (an import pointer: by the import's name).
    fn of(&self, key: &str) -> Option<i64> {
        if key.starts_with(coff::IMPORT_PREFIX) {
            return import_name(key).and_then(|n| self.imports.get(n).copied());
        }
        self.at.get(key).copied()
    }

    /// The member at this address contradicts what is settled: a reference into its own section misses the
    /// symbol; a reference resolves where its name is not, or where a placed member defines other names; an
    /// import pointer is no import slot, or the slot of another name; a definition sits where its name is not, or where placed members
    /// reference other names.
    fn contradicts(&self, s: &Says) -> bool {
        if !s.self_ok {
            return true;
        }
        for (key, t) in &s.refs {
            if self.of(key).is_some_and(|a| a != *t) {
                return true;
            }
            if key.starts_with(coff::IMPORT_PREFIX) {
                match self.slots.get(t) {
                    None => return true,
                    Some(Some(n)) if import_name(key).is_some_and(|k| k != n) => return true,
                    _ => {}
                }
            } else if !key.starts_with('#') && self.defs.get(t).is_some_and(|ns| !ns.contains(key)) {
                return true;
            }
        }
        for (name, a) in &s.defs {
            if self.at.get(name).is_some_and(|x| x != a) {
                return true;
            }
            if self.refd.get(a).is_some_and(|ns| ns.iter().any(|n| !s.defs.iter().any(|(d, b)| d == n && b == a))) {
                return true;
            }
        }
        false
    }

    /// Every reference of the member resolves where its name is settled (and it has one): its targets confirm it.
    fn confirms(&self, s: &Says) -> bool {
        !s.refs.is_empty() && !self.contradicts(s) && s.refs.iter().all(|(key, t)| self.of(key) == Some(*t))
    }

    fn learn(&mut self, s: &Says) {
        for (name, a) in &s.defs {
            self.at.insert(name.clone(), *a);
            self.defs.entry(*a).or_default().insert(name.clone());
        }
        for (key, t) in &s.refs {
            if !key.starts_with(coff::IMPORT_PREFIX) {
                self.at.entry(key.clone()).or_insert(*t);
            }
            if !key.starts_with('#') && !key.starts_with(coff::IMPORT_PREFIX) {
                self.refd.entry(*t).or_default().insert(key.clone());
            }
        }
    }
}

/// Library sections of equal masked bytes, the positions where they match, and per position what each member
/// placed there says.
struct Group<'a> {
    members: Vec<Member<'a>>,
    short: bool, // fewer than LONG_MIN compared bytes: placed only where its targets confirm it
    n: i64,
    hits: Vec<(i64, Vec<Says>)>,
}

/// The fewest compared bytes of a section its targets may confirm; with LONG_MIN its bytes place it unless its
/// targets contradict it.
const SHORT_MIN: usize = 4;
const LONG_MIN: usize = 8;

/// setup.place_members: the placements of the archives' code sections in the image's code sections. A section
/// matches where its masked bytes equal the image's; it is placed there only when what its relocations resolve to
/// agrees with the imports and the other placed members (a member placed alone settles the names it defines and
/// references, until nothing changes). Sections of equal masked bytes are told apart by their targets; those
/// that stay alike are placed together (φ open between them). A short section is placed only where every
/// target confirms it.
pub fn place_members(img: &crate::pe::Image, libs: &[(String, Vec<Obj>)], reloc_sites: &BTreeSet<i64>) -> Vec<Placed> {
    // (lib, object, section number) in (lib, object name, section) order
    let mut secs: Vec<Member> = vec![];
    for (lib, objs) in libs {
        for o in objs {
            for k in o.code_sections() {
                secs.push((lib, o, k));
            }
        }
    }
    secs.sort_by(|a, b| (a.0, &a.1.name, a.2).cmp(&(b.0, &b.1.name, b.2)));
    let mut keyed: Vec<((Vec<u8>, Vec<u8>), Vec<Member>)> = vec![];
    let mut at: HashMap<(Vec<u8>, Vec<u8>), usize> = HashMap::new();
    for (lib, o, k) in secs {
        let s = &o.sections[k];
        let data = s.data.clone().unwrap_or_default();
        let mask = s.mask();
        let compared = mask.iter().filter(|&&m| m == 0).count();
        if compared < SHORT_MIN || (compared < LONG_MIN && s.relocs.is_empty()) {
            continue;
        }
        let key = (data, mask);
        match at.get(&key) {
            Some(&i) => keyed[i].1.push((lib, o, k)),
            None => {
                at.insert(key.clone(), keyed.len());
                keyed.push((key, vec![(lib, o, k)]));
            }
        }
    }
    keyed.sort_by(|a, b| (a.1[0].0, &a.1[0].1.name, a.1[0].2).cmp(&(b.1[0].0, &b.1[0].1.name, b.1[0].2)));
    let code_secs: Vec<&crate::pe::Section> = img.sections.iter().filter(|s| s.holds_code()).collect();
    let mut groups: Vec<Group> = vec![];
    for ((data, mask), members) in keyed {
        let (aoff, alen) = longest_run(&mask);
        let anchor = &data[aoff..(aoff + alen).min(data.len())];
        let n = data.len() as i64;
        let mut hits: BTreeSet<i64> = BTreeSet::new();
        for s in &code_secs {
            let raw = img.section_data(s);
            let mut from = 0;
            while let Some(p) = memchr::memmem::find(&raw[from..], anchor).map(|p| p + from) {
                if p >= aoff {
                    let start = p - aoff;
                    if start + data.len() <= raw.len() && raw[start..start + data.len()].iter().zip(&data).zip(&mask).all(|((x, y), m)| *m != 0 || x == y) {
                        hits.insert(s.va as i64 + start as i64);
                    }
                }
                from = p + 1;
            }
        }
        let sec0 = &members[0].1.sections[members[0].2];
        let hits: Vec<(i64, Vec<Says>)> = hits.into_iter()
            .filter(|&va| reloc_sites.is_empty()
                || (sec0.relocs.iter().filter(|r| r.kind_width().0 == ABSOLUTE).all(|r| reloc_sites.contains(&(va + r.offset as i64)))
                    && !reloc_sites.range(va..va + n).any(|&site| mask[(site - va) as usize] == 0)))
            .map(|va| (va, members.iter().map(|&m| says(img, m, va)).collect()))
            .collect();
        if !hits.is_empty() {
            let short = mask.iter().filter(|&&m| m == 0).count() < LONG_MIN;
            groups.push(Group { members, short, n, hits });
        }
    }
    // the members at a position that survive what is settled: a long one unless contradicted, a short one confirmed
    let alive = |known: &Known, g: &Group, says: &[Says]| -> Vec<usize> {
        (0..g.members.len()).filter(|&i| if g.short { known.confirms(&says[i]) } else { !known.contradicts(&says[i]) }).collect()
    };
    let overlaps = |placed: &[(i64, i64)], lo: i64, hi: i64| placed.iter().any(|&(a, b)| lo < b && a < hi);
    // place members alone until nothing changes: the only survivor at a position, at no other position of its group
    let mut known = Known::new(img);
    let mut placed: Vec<(i64, i64)> = vec![];
    let mut alone: HashMap<(usize, usize), usize> = HashMap::new(); // (group, hit) -> the member placed alone
    loop {
        let mut changed = false;
        for (gi, g) in groups.iter().enumerate() {
            let lives: Vec<(usize, Vec<usize>)> = g.hits.iter().enumerate()
                .filter(|(hi, (va, _))| !alone.contains_key(&(gi, *hi)) && !overlaps(&placed, *va, va + g.n))
                .map(|(hi, (_, s))| (hi, alive(&known, g, s))).filter(|(_, m)| !m.is_empty()).collect();
            for (hi, ms) in &lives {
                let m = ms[0];
                let (va, says) = &g.hits[*hi];
                if ms.len() == 1 && !lives.iter().any(|(h, o)| h != hi && o.contains(&m)) && !alone.iter().any(|(&(g2, _), &m2)| g2 == gi && m2 == m)
                    && !overlaps(&placed, *va, va + g.n) && !known.contradicts(&says[m]) {
                    known.learn(&says[m]);
                    placed.push((*va, va + g.n));
                    alone.insert((gi, *hi), m);
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    // then every group in order: its members placed alone, and the rest where they survive (together)
    let mut out = vec![];
    let mut done: Vec<(i64, i64)> = vec![];
    for (gi, g) in groups.iter().enumerate() {
        let labels: Vec<String> = g.members.iter().map(|(lib, o, k)| format!("{lib}/{}:{}#{k}", o.name, o.sections[*k].name)).collect();
        let taken: HashSet<usize> = alone.iter().filter(|(k, _)| k.0 == gi).map(|(_, &m)| m).collect();
        let mut at: Vec<(i64, Vec<usize>, bool)> = vec![];
        let mut rest: Vec<(i64, Vec<usize>, bool)> = vec![];
        for (hi, (va, says)) in g.hits.iter().enumerate() {
            match alone.get(&(gi, hi)) {
                Some(&m) => at.push((*va, vec![m], true)),
                None => {
                    let ms: Vec<usize> = alive(&known, g, says).into_iter().filter(|m| !taken.contains(m)).collect();
                    if !ms.is_empty() && !overlaps(&placed, *va, va + g.n) {
                        rest.push((*va, ms, false));
                    } else if !ms.is_empty() && !g.short {
                        out.push(Placed::Issue("duplicate", *va, va + g.n, format!("{} matches where another member is placed", labels.join("|"))));
                    }
                }
            }
        }
        if rest.len() > g.members.len() - taken.len() {
            out.push(Placed::Issue("ambiguous", rest[0].0, rest[0].0 + g.n,
                                   format!("{} matches at {} positions: {}", labels.join("|"), rest.len(),
                                           rest.iter().take(6).map(|x| format!("{:#x}", x.0)).collect::<Vec<_>>().join(", "))));
            rest.clear();
        }
        at.extend(rest);
        at.sort();
        for (va, ms, mine) in at {
            let hi = va + g.n;
            if !mine && overlaps(&done, va, hi) {
                if !g.short {
                    out.push(Placed::Issue("duplicate", va, hi, format!("{} matches where another member is placed", labels.join("|"))));
                }
                continue;
            }
            done.push((va, hi));
            let members: Vec<Member> = ms.iter().map(|&i| g.members[i]).collect();
            let names: BTreeSet<String> = members.iter().map(|(_, o, k)| sec_first_name(o, *k).map(|s| s.to_string())
                .unwrap_or_else(|| format!("{}:{}#{k}", o.name, o.sections[*k].name))).collect();
            let units: BTreeSet<String> = members.iter().map(|(lib, o, _)| format!("lib:{lib}/{}", o.name)).collect();
            let join = |s: &BTreeSet<String>| s.iter().cloned().collect::<Vec<_>>().join("|");
            let mut values: BTreeMap<u32, BTreeSet<String>> = BTreeMap::new();
            for (_, o, k) in &members {
                for &si in &o.sections[*k].syms {
                    let s = &o.symbols[si];
                    if s.named() {
                        values.entry(s.value).or_default().insert(s.name.clone());
                    }
                }
            }
            out.push(Placed::At(Placement { lo: va, hi, name: join(&names), unit: join(&units), lib: members[0].0.to_string(), members: members.len(),
                                            values: values.iter().map(|(v, ns)| (*v, ns.iter().cloned().collect())).collect() }));
        }
    }
    out
}

fn reloc_sites(ctx: &Ctx, db: &Connection) -> Result<BTreeSet<i64>> {
    Ok(facts(ctx, db, "ref")?.iter().filter(|f| f.s("rkind") == Some("reloc")).map(|f| f.lo).collect())
}

/// S.crt.code: a library member's code section placed where its masked bytes equal the image's, once.
pub fn s_crt_code(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    let x = inputs(ctx)?;
    let libs = archives(x, "libs")?;
    for p in place_members(&img, &libs, &reloc_sites(ctx, db)?) {
        match p {
            Placed::Issue(what, lo, hi, msg) => out.finding("warn", &format!("S.crt.{what}"), lo, hi, msg, ""),
            Placed::At(pl) => {
                let mut v = json!({"skind": "func", "name": pl.name, "extent": "reproduced", "unit": pl.unit});
                if pl.members > 1 {
                    v["candidates"] = json!(pl.members);
                }
                out.claim(pl.lo, pl.hi, "symbol", v, REPRODUCED);
                out.claim(pl.lo, pl.hi, "unit", json!({"tu": pl.unit, "lib": pl.lib}), REPRODUCED);
                for (value, ns) in &pl.values {
                    let a = pl.lo + *value as i64;
                    out.claim(a, a + 1, "start", json!({"skind": "func", "how": "crt"}), REPRODUCED);
                    out.claim(a, a + 1, "name", json!({"name": ns.join("|"), "origin": "lib", "unit": pl.unit}), REPRODUCED);
                }
            }
        }
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ S.crt.refs, S.crt.data

/// unit:name -> the placed func symbol (S.crt.code's), and the units placed.
fn placed_funcs(ctx: &Ctx, db: &Connection) -> Result<(HashMap<String, Rc<Claim>>, HashSet<String>)> {
    let mut placed = HashMap::new();
    for f in facts(ctx, db, "symbol")? {
        if f.s("skind") == Some("func") && f.s("unit").is_some_and(|u| u.starts_with("lib:")) {
            placed.insert(format!("{}:{}", f.s("unit").unwrap(), f.s("name").unwrap_or("")), f.clone());
        }
    }
    let units = placed.values().filter_map(|f| f.s("unit").map(|u| u.to_string())).collect();
    Ok((placed, units))
}

/// (section number, its placed func symbol) of every code section of an object that S.crt.code placed whole.
fn placed_sections<'a>(o: &Obj, unit: &str, placed: &'a HashMap<String, Rc<Claim>>) -> Vec<(usize, &'a Rc<Claim>)> {
    o.code_sections()
        .into_iter()
        .filter_map(|k| {
            let f = placed.get(&format!("{unit}:{}", sec_first_name(o, k).unwrap_or("")))?;
            (f.hi - f.lo == o.sections[k].size as i64).then_some((k, f))
        })
        .collect()
}

/// S.crt.refs: the addresses a placed library section's relocations resolve name what they reference.
pub fn s_crt_refs(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    let x = inputs(ctx)?;
    let (placed, units) = placed_funcs(ctx, db)?;
    let mut resolved: BTreeMap<String, BTreeMap<i64, i64>> = BTreeMap::new();
    let mut functions: HashSet<String> = HashSet::new();
    for (lib, objs) in archives(x, "libs")? {
        for o in &objs {
            let unit = format!("lib:{lib}/{}", o.name);
            if !units.contains(&unit) {
                continue;
            }
            for (k, f) in placed_sections(o, &unit, &placed) {
                for r in &o.sections[k].relocs {
                    let Some(sym) = o.symbol_at(r.symbol_index) else { continue };
                    let (kind, width) = r.kind_width();
                    if kind != ABSOLUTE && kind != RELATIVE {
                        continue;
                    }
                    if sym.defined() {
                        continue;
                    }
                    let site = f.lo as u32 + r.offset;
                    let Some(target) = r.resolve(site, &img.read(site, width as usize), o.addend(k, r)) else { continue };
                    if sym.unresolved() && !sym.dllimport() {
                        *resolved.entry(sym.name.clone()).or_default().entry(target as i64).or_insert(0) += 1;
                        if sym.function() {
                            functions.insert(sym.name.clone());
                        }
                    }
                }
            }
        }
    }
    for (name, addrs) in resolved {
        let lo = *addrs.keys().next().unwrap();
        if addrs.len() > 1 {
            out.finding("bug", "S.crt.refs", lo, lo + 1, format!("{name} resolves to {} addresses: {}", addrs.len(),
                                                                   addrs.iter().map(|(a, n)| format!("{a:#x}x{n}")).collect::<Vec<_>>().join(", ")), "");
            continue;
        }
        let n = addrs[&lo];
        if !img.in_image(lo as u32) {
            continue;
        }
        out.claim(lo, lo + 1, "name", json!({"name": name, "origin": "lib", "sites": n}), REPRODUCED);
        if functions.contains(&name) {
            out.claim(lo, lo + 1, "start", json!({"skind": "func", "how": "libref"}), REPRODUCED);
        }
    }
    Ok(())
}

/// S.crt.data: a placed member's data section sits where its own absolute relocations into it point.
pub fn s_crt_data(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    let x = inputs(ctx)?;
    let (placed, _) = placed_funcs(ctx, db)?;
    let mut done: Vec<(i64, i64)> = vec![];
    for (lib, objs) in archives(x, "libs")? {
        for o in &objs {
            let unit = format!("lib:{lib}/{}", o.name);
            let mut bases: BTreeMap<usize, BTreeMap<i64, i64>> = BTreeMap::new();
            for (k, f) in placed_sections(o, &unit, &placed) {
                for r in &o.sections[k].relocs {
                    let (kind, width) = r.kind_width();
                    if kind != ABSOLUTE {
                        continue;
                    }
                    let Some(sym) = o.symbol_at(r.symbol_index) else { continue };
                    let Some(ss) = o.section_of(sym) else { continue };
                    if !sym.defined() || ss.code() || ss.discard() {
                        continue;
                    }
                    let site = f.lo as u32 + r.offset;
                    let Some(target) = r.resolve(site, &img.read(site, width as usize), o.addend(k, r)) else { continue };
                    let base = target.wrapping_sub(sym.value) as i64;
                    *bases.entry(sym.secnum as usize).or_default().entry(base).or_insert(0) += 1;
                }
            }
            for (secnum, bs) in bases {
                let sec = &o.sections[secnum];
                let lo = *bs.keys().next().unwrap();
                if bs.len() > 1 {
                    out.finding("warn", "S.crt.data", lo, lo + 1, format!("{unit} {}#{secnum} has {} bases: {}", sec.name, bs.len(),
                                                                            bs.iter().map(|(b, n)| format!("{b:#x}x{n}")).collect::<Vec<_>>().join(", ")), "");
                    continue;
                }
                if sec.size == 0 || !img.in_image(lo as u32) {
                    continue;
                }
                let hi = lo + sec.size as i64;
                if done.iter().any(|&(a, b)| lo < b && a < hi) {
                    out.finding("warn", "S.crt.data", lo, hi, format!("{unit} {}#{secnum} overlaps another placed data section", sec.name), "");
                    continue;
                }
                done.push((lo, hi));
                let named: Vec<&coff::Symbol> = sec.syms.iter().map(|&k| &o.symbols[k]).filter(|s| s.named()).collect();
                let name = named.first().map(|s| s.name.clone()).unwrap_or_else(|| format!("{}:{}#{secnum}", o.name, sec.name));
                out.claim(lo, hi, "symbol", json!({"skind": "crt.data", "name": name, "extent": "reproduced", "unit": unit, "section": sec.name,
                                                  "bss": sec.data.is_none()}), REPRODUCED);
                out.claim(lo, hi, "unit", json!({"tu": unit, "lib": lib}), REPRODUCED);
                for s in named {
                    let a = lo + s.value as i64;
                    out.claim(a, a + 1, "name", json!({"name": s.name, "origin": "lib", "unit": unit}), REPRODUCED);
                }
            }
        }
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ S.lib.data

/// S.lib.data: a data-only member's initialised data placed where its bytes occur once.
pub fn s_lib_data(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    let x = inputs(ctx)?;
    let raws: Vec<(u32, &[u8])> = img.sections.iter().filter(|s| !s.holds_code() && !s.uninitialized()).map(|s| (s.va, img.section_data(s))).collect();
    let mut done: Vec<(i64, i64)> = facts(ctx, db, "symbol")?.iter().filter(|f| f.s("skind") == Some("crt.data")).map(|f| (f.lo, f.hi)).collect();
    done.sort();
    let mut seen: HashMap<(i64, Vec<u8>), usize> = HashMap::new();
    // (lo, hi, value, unit, lib, named symbols (offset, name))
    let mut pending: Vec<(i64, i64, Value, String, String, Vec<(u32, String)>)> = vec![];
    for (lib, objs) in archives(x, "libs")? {
        for o in &objs {
            if !o.code_sections().is_empty() {
                continue;
            }
            for k in 1..o.sections.len() {
                let sec = &o.sections[k];
                let Some(data) = &sec.data else { continue };
                if sec.code() || sec.discard() || !sec.relocs.is_empty() || sec.size < 8 || sec.name.starts_with(".idata") {
                    continue; // .idata$*: an import member's tables, the image's import region
                }
                if data.iter().filter(|&&b| b != 0).count() < 8 {
                    continue;
                }
                let mut hits: Vec<i64> = vec![];
                for (va, raw) in &raws {
                    let mut from = 0;
                    while hits.len() < 2 {
                        let Some(p) = memchr::memmem::find(&raw[from.min(raw.len())..], data).map(|p| p + from) else { break };
                        hits.push(*va as i64 + p as i64);
                        from = p + 1;
                    }
                }
                if hits.len() != 1 {
                    continue;
                }
                let (lo, hi) = (hits[0], hits[0] + sec.size as i64);
                if let Some(&i) = seen.get(&(lo, data.clone())) {
                    let c = pending[i].2["candidates"].as_i64().unwrap_or(1);
                    pending[i].2["candidates"] = json!(c + 1);
                    continue;
                }
                if done.iter().any(|&(a, b)| lo < b && a < hi) {
                    continue;
                }
                let unit = format!("lib:{lib}/{}", o.name);
                let named: Vec<(u32, String)> = sec.syms.iter().map(|&s| &o.symbols[s]).filter(|s| s.named()).map(|s| (s.value, s.name.clone())).collect();
                let name = named.first().map(|s| s.1.clone()).unwrap_or_else(|| format!("{}:{}", o.name, sec.name));
                let v = json!({"skind": "crt.data", "name": name, "extent": "reproduced", "unit": unit, "section": sec.name, "bss": false, "how": "content",
                               "candidates": 1});
                seen.insert((lo, data.clone()), pending.len());
                done.push((lo, hi));
                pending.push((lo, hi, v, unit, lib.clone(), named));
            }
        }
    }
    for (lo, hi, v, unit, lib, named) in pending {
        out.claim(lo, hi, "symbol", v, REPRODUCED);
        out.claim(lo, hi, "unit", json!({"tu": unit, "lib": lib}), REPRODUCED);
        for (value, name) in named {
            let a = lo + value as i64;
            out.claim(a, a + 1, "name", json!({"name": name, "origin": "lib", "unit": unit}), REPRODUCED);
        }
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ S.thunk

/// S.thunk: an import stub whose slot is an iat slot, outside the placed library code, where the linker's
/// layout makes it a library contribution.
pub fn s_thunk(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    let tc = toolchain(inputs(ctx)?)?;
    let size = tc.import_stub_size() as i64;
    let packed = size < tc.function_alignment() as i64;
    let syms = facts(ctx, db, "symbol")?;
    let slots: HashMap<i64, String> = syms.iter().filter(|f| f.s("skind") == Some("iat")).map(|f| (f.lo, f.s("name").unwrap_or("").to_string())).collect();
    let crt: Vec<(i64, i64)> = syms.iter().filter(|f| f.s("skind") == Some("func")).map(|f| (f.lo, f.hi)).collect();
    let first_lib = crt.iter().map(|c| c.0).min();
    let mut cands: Vec<(i64, String)> = vec![];
    for s in img.sections.iter().filter(|s| s.holds_code()) {
        for (p, slot) in tc.import_stubs(img.section_data(s)) {
            let va = s.va as i64 + p as i64;
            if let Some(name) = slots.get(&(slot as i64)) {
                if !crt.iter().any(|&(a, b)| a <= va && va < b) {
                    cands.push((va, name.clone()));
                }
            }
        }
    }
    let at: HashSet<i64> = cands.iter().map(|c| c.0).collect();
    for (va, name) in cands {
        if first_lib.is_some_and(|f| va >= f) || (packed && (at.contains(&(va - size)) || at.contains(&(va + size)))) {
            out.claim(va, va + size, "symbol", json!({"skind": "thunk", "name": name, "extent": "derived"}), DERIVED);
            out.claim(va, va + 1, "name", json!({"name": format!("thunk:{name}"), "origin": "import"}), DERIVED);
        }
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ C.toolchain, S2

/// checks.declared_build: the last run of digits of a declaration ('cl 12.00.9044' -> 9044).
fn declared_build(d: &str) -> Option<i64> {
    let b = d.as_bytes();
    let end = b.iter().rposition(|c| c.is_ascii_digit())? + 1;
    let start = b[..end].iter().rposition(|c| !c.is_ascii_digit()).map(|i| i + 1).unwrap_or(0);
    d[start..end].parse().ok()
}

/// repr() of a str, as Python spells it.
fn py_repr(s: &str) -> String {
    let q = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut out = String::from(q);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == q => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(q);
    out
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::Object(o) => !o.is_empty(),
    }
}

/// C.toolchain: the target's toolchain declaration against the Rich header's candidates.
pub fn c_toolchain(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    let x = inputs(ctx)?;
    let tc = toolchain(x)?;
    let decl = &x.decl;
    let t = x.target.as_str();
    let by = format!("decl:decompanion.toml:{t}");
    let base = img.base as i64;
    for key in ["compiler", "linker", "cflags"] {
        let reason = decl["reasons"][key].as_str().unwrap_or("");
        if truthy(&decl[key]) && reason.trim().is_empty() {
            out.finding("error", "C.toolchain", base, base + 1, format!("target {t}: the {key} declaration has no reason"), &by);
        }
    }
    let Some(rich) = facts(ctx, db, "toolchain")?.into_iter().next() else { return Ok(()) };
    for (key, list) in [("compiler", "compilers"), ("linker", "linkers")] {
        let cands = rich.value[list].as_array().cloned().unwrap_or_default();
        if cands.is_empty() {
            continue;
        }
        let spelled = cands.iter().map(|c| format!("{} ({} x{})", tc.declare(c["tool"].as_str().unwrap_or(""), c["family"].as_str().unwrap_or(""),
                                                                     c["build"].as_u64().unwrap_or(0) as u32),
                                                 c["tool"].as_str().unwrap_or(""), c["count"])).collect::<Vec<_>>().join(", ");
        let d = decl[key].as_str().unwrap_or("");
        if d.is_empty() {
            out.finding2("error", "C.toolchain", base, base + 1, format!("target {t}: no {key} declared; the Rich header's {key} candidates: {spelled}"), &by, &rich.by);
            continue;
        }
        let b = declared_build(d);
        if !cands.iter().any(|c| c["build"].as_i64() == b) {
            out.finding2("error", "C.toolchain", base, base + 1,
                          format!("target {t}: declared {key} {} names build {}, no {key} entry of the Rich header has it (candidates: {spelled})", py_repr(d),
                                  b.map(|b| b.to_string()).unwrap_or_else(|| "None".into())), &by, &rich.by);
        }
    }
    Ok(())
}

/// S2.rich.members: the library objects the Rich header counts should be placed members.
pub fn s2_rich_members(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    let x = inputs(ctx)?;
    let Some(rich) = facts(ctx, db, "toolchain")?.into_iter().next() else { return Ok(()) };
    let Some(b) = declared_build(x.decl["compiler"].as_str().unwrap_or("")) else { return Ok(()) };
    let members: HashSet<String> = facts(ctx, db, "unit")?.iter().filter_map(|f| f.s("tu").map(|s| s.to_string())).collect();
    let counted: i64 = rich.value["compilers"].as_array().into_iter().flatten().filter(|c| c["build"].as_i64() != Some(b)).filter_map(|c| c["count"].as_i64()).sum();
    if counted != 0 && (members.len() as i64) < counted {
        out.finding("warn", "S2", img.base as i64, img.base as i64 + 1,
                     format!("Rich header counts {counted} library objects (compiler entries of other builds than {b}), {} members placed", members.len()), "");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::coff::testlib::{archive, code_obj, comp_obj};
    use crate::pe::testpe::{build, BASE, DATA, TEXT};
    use crate::rules::testkit::{of, Kit};
    use serde_json::json;

    const RICH: &[(u32, u32, u32)] = &[(0x30, 9044, 3), (0x0a, 8047, 5), (0x04, 8447, 1)];

    /// The synthetic dll's f1 (calls f2 and f3) as a library member: REL32 relocations to undefined _f2 / _f3.
    fn libc(dir: &std::path::Path) -> String {
        let img = build(None);
        let mut code = img[0x400..0x420].to_vec(); // .text's file data: f1 and its nop fill
        code[4..8].fill(0); // the object holds the calls' addend (0), the image the displacement
        code[9..13].fill(0);
        let obj = code_obj(&code, &[(4, 1, 0x14), (9, 2, 0x14)], &[("_f1", 0, 1, 2), ("_f2", 0, 0, 2), ("_f3", 0, 0, 2)]);
        let p = dir.join("LIBC.LIB");
        std::fs::write(&p, archive(&[("f1.obj", obj), ("stamp.obj", comp_obj(0x0a, 8047))])).unwrap();
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn rich_and_toolchain() {
        let k = Kit::new(&build(Some(RICH)));
        let lib = libc(&k.dir);
        let x = json!({"toolchain": "vc6", "archives": [lib]}).to_string();
        let (rows, _) = k.run("S.rich", &[], &x);
        let r = &of(&rows, "toolchain")[0].2;
        assert_eq!(r["entries"][1]["archive_objects"], 1);
        k.record("S.rich", &[], &x);
        let decl = |c: &str, reason: &str| json!({"toolchain": "vc6", "target": "t", "decl": {"compiler": c, "linker": "link 6.00.8447", "cflags": ["/O2"],
                                                   "reasons": {"compiler": reason, "linker": "x", "cflags": "x"}}}).to_string();
        let (_, c) = k.run("C.toolchain", &["S.rich"], &decl("cl 12.00.9044", "x"));
        assert!(c.is_empty());
        let (_, c) = k.run("C.toolchain", &["S.rich"], &decl("cl 12.00.8168", ""));
        let m: Vec<&str> = c.iter().map(|x| x.message.as_str()).collect();
        assert_eq!(m, ["target t: declared compiler 'cl 12.00.8168' names build 8168, no compiler entry of the Rich header has it \
                        (candidates: cl 12.00.8047 (Utc12_C x5), cl 12.00.9044 (Utc12_2_C x3))",
                       "target t: the compiler declaration has no reason"]);
        k.put("S.crt.code", &[]);
        let (_, c) = k.run("S2.rich.members", &["S.rich", "S.crt.code"], &decl("cl 12.00.9044", "x"));
        assert_eq!(c[0].message, "Rich header counts 5 library objects (compiler entries of other builds than 9044), 0 members placed");
    }

    #[test]
    fn members_placed_and_their_references() {
        let k = Kit::new(&build(None));
        let x = json!({"toolchain": "vc6", "libs": [libc(&k.dir)]}).to_string();
        k.record("S.relocs", &[], "");
        let (rows, c) = k.run("S.crt.code", &["S.relocs"], &x);
        assert!(c.is_empty());
        let t = (BASE + TEXT) as i64;
        assert_eq!(of(&rows, "symbol"), vec![(t, t + 0x20, json!({"skind": "func", "name": "_f1", "extent": "reproduced", "unit": "lib:LIBC.LIB/f1.obj"}))]);
        assert_eq!(of(&rows, "unit")[0].2, json!({"tu": "lib:LIBC.LIB/f1.obj", "lib": "LIBC.LIB"}));
        assert_eq!(of(&rows, "name")[0].2, json!({"name": "_f1", "origin": "lib", "unit": "lib:LIBC.LIB/f1.obj"}));
        k.record("S.crt.code", &["S.relocs"], &x);
        let (rows, c) = k.run("S.crt.refs", &["S.crt.code"], &x);
        assert!(c.is_empty());
        let names: Vec<(i64, String)> = of(&rows, "name").iter().map(|n| (n.0 - t, n.2["name"].as_str().unwrap().to_string())).collect();
        assert_eq!(names, [(0x20, "_f2".to_string()), (0x30, "_f3".to_string())]);
        assert!(of(&rows, "start").is_empty()); // the test object's symbols carry no function type
        let (rows, _) = k.run("S.crt.data", &["S.crt.code"], &x);
        assert!(rows.is_empty());
        k.put("S.crt.data", &[]);
        let (rows, _) = k.run("S.lib.data", &["S.crt.code", "S.crt.data"], &x);
        assert!(rows.is_empty());
        let d = (BASE + DATA) as i64;
        k.record("S.imports", &[], "");
        let (rows, _) = k.run("S.thunk", &["S.imports", "S.crt.code"], r#"{"toolchain": "vc6"}"#);
        assert!(rows.is_empty() && d > 0); // the dll holds no `jmp [slot]` stub
    }

    /// A text section of: 0x00 fopen (calls 0x20), 0x0e a GetTickCount caller, 0x20 openfile, 0x30 atoi (calls 0x40),
    /// 0x40 atol, 0x50 atoi's shape calling 0x20; and library members for them.
    fn targets_image() -> (crate::pe::Image, Vec<(&'static str, Vec<u8>)>) {
        use crate::coff::testlib::code_obj;
        use crate::pe::testpe::build_with;
        let call = |at: u32, to: u32| (to as i32 - (at as i32 + 4)).to_le_bytes();
        let slot = BASE + DATA + 0x150;
        let mut t = vec![0xccu8; 0x60];
        let fopen = |c: [u8; 4]| [&[0x55u8, 0x8b, 0xec, 0x51, 0x52, 0xe8][..], &c, &[0x5a, 0x59, 0x5d, 0xc3]].concat();
        let imp = |c: [u8; 4]| [&[0x55u8, 0x8b, 0xec, 0xff, 0x15][..], &c, &[0x5d, 0xc3, 0x90]].concat();
        let atoi = |c: [u8; 4]| [&[0xffu8, 0x74, 0x24, 0x04, 0xe8][..], &c, &[0x59, 0xc3]].concat();
        let leaf = |b: u8| [&[0x33u8, 0xc0][..], &[b; 7], &[0xc3]].concat();
        for (at, code) in [(0x00, fopen(call(6, 0x20))), (0x0e, imp(slot.to_le_bytes())), (0x20, leaf(0x40)), (0x30, atoi(call(0x35, 0x40))),
                           (0x40, leaf(0x48)), (0x50, atoi(call(0x55, 0x20)))] {
            t[at..at + code.len()].copy_from_slice(&code);
        }
        let img = crate::pe::Image::parse(build_with(None, Some(&t))).unwrap();
        let caller = |code: Vec<u8>, off: u32, typ: u16, me: &str, callee: &str| code_obj(&code, &[(off, 1, typ)], &[(me, 0, 1, 2), (callee, 0, 0, 2)]);
        let objs = vec![
            ("a.obj", caller(fopen([0; 4]), 6, 0x14, "_fopen", "__openfile")),
            ("b.obj", caller(fopen([0; 4]), 6, 0x14, "__wfopen", "__wopenfile")),
            ("c.obj", code_obj(&leaf(0x40), &[], &[("__openfile", 0, 1, 2)])),
            ("d.obj", caller(atoi([0; 4]), 5, 0x14, "_atoi", "_atol")),
            ("e.obj", code_obj(&leaf(0x48), &[], &[("_atol", 0, 1, 2)])),
            ("f.obj", caller(imp([0; 4]), 5, 0x06, "_ticks", "__imp__GetTickCount@0")),
            ("g.obj", caller(imp([0; 4]), 5, 0x06, "_wticks", "__imp__GetTickCountW@0")),
        ];
        (img, objs)
    }

    /// (name, lo, members) of the placements, the issues' messages.
    fn place(img: &crate::pe::Image, objs: &[(&str, Vec<u8>)], keep: &[&str]) -> (Vec<(String, u32, usize)>, Vec<String>) {
        let objs = objs.iter().filter(|(n, _)| keep.contains(n)).map(|(n, b)| crate::coff::Obj::parse_named(n, b).unwrap()).collect();
        let (mut at, mut issues) = (vec![], vec![]);
        for p in super::place_members(img, &[("L.LIB".to_string(), objs)], &Default::default()) {
            match p {
                super::Placed::At(x) => at.push((x.name, x.lo as u32 - BASE - TEXT, x.members)),
                super::Placed::Issue(w, _, _, m) => issues.push(format!("{w}: {m}")),
            }
        }
        at.sort_by_key(|x| x.1);
        (at, issues)
    }

    #[test]
    fn members_told_apart_by_their_targets() {
        let (img, objs) = targets_image();
        let all = ["a.obj", "b.obj", "c.obj", "d.obj", "e.obj", "f.obj", "g.obj"];
        let (at, issues) = place(&img, &objs, &all);
        let s = |n: &str, lo, m| (n.to_string(), lo, m);
        // fopen: the callee placed at 0x20 is __openfile; the import slot is GetTickCount's; atoi (short): its callee
        // _atol is placed at 0x40, and the same shape at 0x50 calls __openfile
        assert_eq!(at, [s("_fopen", 0, 1), s("_ticks", 0x0e, 1), s("__openfile", 0x20, 1), s("_atoi", 0x30, 1), s("_atol", 0x40, 1)]);
        assert!(issues.is_empty(), "{issues:?}");
        // nothing tells fopen from _wfopen: placed together, φ open between them; atoi's callee unknown: not placed
        let (at, _) = place(&img, &objs, &["a.obj", "b.obj", "d.obj"]);
        assert_eq!(at, [s("__wfopen|_fopen", 0, 2)]);
    }
}

