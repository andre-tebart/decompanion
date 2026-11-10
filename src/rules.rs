//! The rules. Each runs on the store directly: it reads the current facts of its needed runs, builds its facts and
//! conflicts and records its run. A rule's criterion is its doc text in registry.rs (`dcp rules -v` prints it).

use crate::error::{Error, Result};
use crate::compare::{compare, Compared};
use crate::store::{self, Out, Claim, DECLARED, DERIVED, OPEN};
use crate::{image, with_conn};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::rc::Rc;

/// What the engine hands a native rule: the store, its needed runs, the project's paths and inputs.
pub struct Ctx {
    pub rule: String,
    pub version: String,
    pub code_hash: String,
    pub input_hash: String,
    pub db: String,
    pub needed: Vec<String>,
    pub root: String,
    pub image: String,
    pub fill_forms: Vec<Vec<u8>>,
    pub record: bool,
    pub shortcuts: bool,
    pub inputs: Rc<Inputs>,
}

/// What a rule reads of the project besides the store and the image: the configuration's (project.rs) and, for the
/// rules of the sources, what the front end computes (the source scan's pieces, the tree's raw macros and described
/// addresses, the last lint).
#[derive(Default, serde::Deserialize)]
#[serde(default)]
pub struct Inputs {
    pub root: Option<String>,   // the toolchain's root, expanded
    pub archives: Vec<String>,  // the target's library archives (none while `libs` waits)
    pub libs: Vec<String>,      // the target's library archives
    pub decl: Value,            // the target's toolchain declaration
    pub target: String,
    pub targets: Vec<String>,   // the default first
    pub images: HashMap<String, String>,
    pub function_alignment: i64,
    pub code_rank: HashMap<String, i64>,
    pub scan: crate::layout::ScanRef,
    pub raw: Vec<String>,
    pub described: Vec<i64>,
    pub lint_calls: Option<HashMap<String, Vec<(i64, String)>>>,
    pub linted: Vec<String>,
    pub units: HashMap<String, String>, // unit -> its text's hash today (M.lint)
    pub max_debt: i64,                  // the gate's bound on declared regressions ([gate] max_debt; M1.baseline)
}

#[cfg(test)]
impl Inputs {
    /// A test's inputs from a JSON object ('' for none).
    pub fn of(json: &str) -> Inputs {
        if json.is_empty() { Inputs::default() } else { serde_json::from_str(json).unwrap() }
    }
}

// ------------------------------------------------------------------------------------------------ compiled functions

/// One sourced function with its compiled code compared (match.compiled_functions' rows).
pub struct Compiled {
    pub obj: crate::ObjIndex,
    pub src: Rc<Claim>,
    pub c: Rc<Compared>,
    pub code: Rc<crate::coff::FunctionCode>,
    pub next: u32, // the next known start (the end of the function's slot)
}

impl Compared {
    pub fn aid_ok(&self) -> bool {
        match self.abs_image {
            None => true,
            Some(n) => self.sites_ok && self.abs_ours == n,
        }
    }
    pub fn matched(&self) -> bool {
        self.diffs.is_empty() && self.tail_ok && self.aid_ok()
    }
    /// Compared.why: why the function is no match ('' when it is).
    pub fn why(&self) -> String {
        let mut out = vec![];
        if !self.diffs.is_empty() {
            out.push(format!("{} of {} bytes differ, the first at +{:#x}", self.diffs.len(), self.size, self.diffs[0]));
        }
        if !self.tail_ok {
            out.push(format!("the original continues after our end: {:#x}..{:#x} is no fill", self.tail.0, self.tail.1));
        }
        if let Some(n) = self.abs_image {
            if !self.sites_ok {
                let s: Vec<String> = self.missing_sites.iter().take(6).map(|a| format!("{:#x}", a)).collect();
                out.push(format!("absolute relocation sites of ours that are no base relocation of the image: {}", s.join(",")));
            } else if self.abs_ours != n {
                out.push(format!("relocs {}/{}: the image relocates fields we do not", self.abs_ours, n));
            }
        }
        out.join("; ")
    }
}

/// The compiled units of the store's tu table: unit -> (object hash, compiled ok) (the `objects` input).
pub fn objects(db: &Connection) -> Result<HashMap<String, (String, bool)>> {
    let err = |e: rusqlite::Error| Error::runtime(e.to_string());
    let mut st = db.prepare_cached("SELECT unit, obj_hash, ok FROM tu").map_err(err)?;
    let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, (r.get::<_, String>(1)?, r.get::<_, i64>(2)? != 0)))).map_err(err)?;
    rows.collect::<Result<_, _>>().map_err(err)
}

/// One function's compare is computed from its object (build/obj/<content hash>.obj), its symbol there, its
/// address and the next start (and the image, the relocation sites, the fill forms: the stamp).
type FnKey = (String, usize, u32, u32);
type Stamp = (String, Option<Vec<u32>>, Vec<Vec<u8>>);

thread_local! {
    static COMPARED: std::cell::RefCell<(Stamp, HashMap<FnKey, (Rc<crate::coff::FunctionCode>, Rc<Compared>)>)> =
        std::cell::RefCell::new(Default::default());
}

/// A sourced function without compiled code: its source, why, and whether its experiment ran. With no object of
/// its unit (it failed to compile, or is not compiled yet) the experiment is not run: open, not a fall
///; an object without the function is our failure: the experiment ran.
pub struct Missing {
    pub src: Rc<Claim>,
    pub why: String,
    pub ran: bool,
}

/// match.compiled_functions: every L.src function source of the current target whose unit compiled and whose
/// object defines it, compared with the image (sorted by address); the others as Missing.
pub fn compiled_functions(ctx: &Ctx, db: &Connection) -> Result<(Vec<Compiled>, Vec<Missing>)> {
    let err = |e: rusqlite::Error| Error::runtime(format!("{}: {e}", ctx.db));
    let img = image(&ctx.image)?;
    // the relocation sites only for an image that has base relocations
    let relocs = if img.relocations().is_empty() {
        None
    } else {
        let mut v: Vec<u32> = store::los(db, &ctx.db, "ref", &ctx.needed, |f| f.s("rkind") == Some("reloc"))
            .map_err(err)?
            .into_iter()
            .map(|x| x as u32)
            .collect();
        v.sort_unstable();
        if v.is_empty() { None } else { Some(v) }
    };
    // starts_of: start facts, function / thunk symbols above open, the end of every code section
    let mut starts: Vec<u32> = store::los(db, &ctx.db, "start", &ctx.needed, |_| true).map_err(err)?.into_iter().map(|x| x as u32).collect();
    starts.extend(
        store::los(db, &ctx.db, "symbol", &ctx.needed, |f| matches!(f.s("skind"), Some("func") | Some("thunk")) && f.support > OPEN)
            .map_err(err)?
            .into_iter()
            .map(|x| x as u32),
    );
    for s in img.sections.iter().filter(|s| s.holds_code()) {
        starts.push(s.end());
    }
    starts.sort_unstable();
    starts.dedup();
    let srcs = store::claims(db, &ctx.db, "source", &ctx.needed, |f| &*f.rule == "L.src" && f.s("what") == Some("func"))
        .map_err(err)?;
    let forms = crate::compare::fill_order(&ctx.fill_forms);
    let (mut out, mut missing) = (vec![], vec![]);
    // the compares of the latest call (one refresh's rules share them), under the image and the relocation sites
    let stamp = (ctx.image.clone(), relocs.clone(), ctx.fill_forms.clone());
    let mut held = COMPARED.with(|h| std::mem::take(&mut *h.borrow_mut()));
    if held.0 != stamp {
        held = (stamp, HashMap::new());
    }
    let mut used: HashMap<FnKey, (Rc<crate::coff::FunctionCode>, Rc<Compared>)> = HashMap::new();
    // C.objects: each compiled unit's object, read once (not per function)
    let objects = objects(db)?;
    let mut objs: HashMap<String, Option<(String, crate::ObjIndex)>> = HashMap::new();
    let current: std::collections::HashSet<String> = objects
        .values()
        .filter(|(h, ok)| *ok && !h.is_empty())
        .map(|(h, _)| format!("{}/build/obj/{}.obj", ctx.root, h))
        .collect();
    crate::live_objects(&current);
    for s in srcs {
        let unit = s.s("unit").unwrap_or("").to_string();
        let name = s.s("symbol").unwrap_or("").to_string();
        if !objs.contains_key(&unit) {
            let o = match objects.get(&unit) {
                Some((h, true)) if !h.is_empty() => {
                    let path = format!("{}/build/obj/{}.obj", ctx.root, h);
                    crate::object_if(&path)?.map(|o| (path, o))
                }
                _ => None,
            };
            objs.insert(unit.clone(), o);
        }
        let obj = objs[&unit].clone();
        let Some((path, obj)) = obj else {
            let why = if objects.contains_key(&unit) { "failed to compile" } else { "is not compiled (dcp build)" };
            missing.push(Missing { why: format!("no object: the unit {unit} {why}"), src: s, ran: false });
            continue;
        };
        let Some(&k) = obj.1.get(&name) else {
            missing.push(Missing { why: format!("the object of unit {unit} defines no function {name}"), src: s, ran: true });
            continue;
        };
        let lo = s.lo as u32;
        let i = starts.partition_point(|&x| x <= lo);
        let next = if i < starts.len() { starts[i] } else { img.end() };
        let key = (path, k, lo, next);
        let (code, c) = match held.1.get(&key) {
            Some(x) => x.clone(),
            None => {
                let code = obj.0.function_code(k);
                let c = compare(&img, &code, lo, relocs.as_deref(), next, &forms);
                (Rc::new(code), Rc::new(c))
            }
        };
        used.insert(key, (code.clone(), c.clone()));
        out.push(Compiled { obj: obj.clone(), src: s, c, code, next });
    }
    COMPARED.with(|h| *h.borrow_mut() = (held.0, used));
    Ok((out, missing))
}

// ------------------------------------------------------------------------------------------------ the rules

/// M.draft (R2): a sourced function that is no byte match owns the code walk's extent of its start.
fn m_draft(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let (funcs, _) = compiled_functions(ctx, db)?;
    let mut walk: HashMap<i64, Rc<Claim>> = HashMap::new();
    let keep = |f: &Claim| &*f.rule == "S.codewalk" && f.s("skind") == Some("func");
    for f in store::claims(db, &ctx.db, "symbol", &ctx.needed, keep).map_err(|e| Error::runtime(e.to_string()))? {
        walk.insert(f.lo, f); // a later fact of the same start wins, as the dict comprehension does
    }
    for x in &funcs {
        if x.c.matched() {
            continue;
        }
        let Some(w) = walk.get(&x.src.lo) else { continue };
        let v = json!({"file": x.src.value["file"], "unit": x.src.value["unit"], "symbol": x.src.value["symbol"],
                       "what": "draft", "why": x.c.why()});
        out.claim(x.src.lo, w.hi, "source", v, w.support.min(x.src.support).min(DERIVED));
    }
    Ok(())
}

/// The end of the last instruction of a matched function's code that is no fill form (0 when every one is fill),
/// as isa.listing gives it: the code decoded with each relocated field holding the image base (the base's bytes
/// repeated over a masked run), each instruction's fill test on its own bytes.
fn last_code_end(base: u32, code: &[u8], mask: &[u8], va: u32, forms: &[Vec<u8>]) -> u32 {
    let dummy = base.to_le_bytes();
    let mut data = code.to_vec();
    let mut k = 0;
    while k < mask.len() {
        if mask[k] != 0 {
            let mut e = k;
            while e < mask.len() && mask[e] != 0 {
                e += 1;
            }
            for j in k..e {
                data[j] = dummy[(j - k) % 4];
            }
            k = e;
        } else {
            k += 1;
        }
    }
    let lines = crate::dis::lengths(&data, va);
    let fill = |&(addr, size): &(u32, u32)| {
        let o = (addr - va) as usize;
        let b = &code[o..(o + size as usize).min(code.len())];
        forms.iter().any(|f| f.as_slice() == b)
    };
    let mut n = lines.len();
    while n > 0 && fill(&lines[n - 1]) {
        n -= 1;
    }
    if n == 0 { 0 } else { lines[n - 1].0 + lines[n - 1].1 }
}

/// M.match (R1): a sourced function whose compiled function is a byte match owns its bytes: a `symbol` func to
/// the end of its last instruction that is no fill (or its first jump / index table), a `source` (what: match)
/// over the whole section.
fn m_match(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let (funcs, _) = compiled_functions(ctx, db)?;
    let img = image(&ctx.image)?;
    let keep = |f: &Claim| matches!(f.s("skind"), Some("jumptable") | Some("idxtable"));
    let mut tables: Vec<(i64, Option<i64>)> = store::claims(db, &ctx.db, "symbol", &ctx.needed, keep)
        .map_err(|e| Error::runtime(e.to_string()))?
        .iter()
        .map(|f| (f.lo, f.value.get("fn").and_then(|v| v.as_i64())))
        .collect();
    tables.sort();
    let forms = crate::compare::fill_order(&ctx.fill_forms);
    for x in &funcs {
        if !x.c.matched() {
            continue;
        }
        let a = x.src.lo;
        let end = a + x.c.size as i64;
        let mut code_end = tables.iter().find(|(lo, f)| *f == Some(a) && a < *lo && *lo < end).map(|t| t.0).unwrap_or(end);
        let n = (code_end - a) as usize;
        let last = last_code_end(img.base, &x.code.data[..n], &x.code.mask[..n.min(x.code.mask.len())], a as u32, &forms);
        if last != 0 {
            code_end = code_end.min(last as i64);
        }
        let aid = match x.c.abs_image {
            None => "-".to_string(),
            Some(m) => format!("{}/{}", x.c.abs_ours, m),
        };
        let v = x.src.value.clone();
        out.claim(a, code_end, "symbol", json!({"skind": "func", "extent": "matched", "name": v["symbol"], "unit": v["unit"],
                                              "file": v["file"], "relocs": aid}), crate::store::REPRODUCED);
        out.claim(a, end, "source", json!({"file": v["file"], "unit": v["unit"], "symbol": v["symbol"], "what": "match",
                                          "relocs": aid}), crate::store::REPRODUCED);
    }
    Ok(())
}

/// The original's absolute memory operands inside a function of ours [lo, lo + len) whose instruction holds no
/// relocated field of ours: (site, size, the address it refers to). `refs`: the walk's operand references (the
/// instruction's range, its target); `fields`: our relocated fields (offset, width) in the function.
pub(crate) fn missing_refs(lo: i64, len: i64, fields: &[(u32, u32)], refs: &[(i64, i64, i64)]) -> Vec<(i64, i64, i64)> {
    refs.iter().filter(|&&(a, b, _)| lo <= a && b <= lo + len).filter(|&&(a, b, _)| {
        let (o, e) = (a - lo, b - lo);
        !fields.iter().any(|&(off, w)| (off as i64) < e && o < off as i64 + w as i64)
    }).copied().collect()
}

/// M.ref.missing: a byte-matched function whose instruction holds, as a constant, the
/// address an absolute memory operand of the original refers to. The analysis of the original claims a reference (derived),
/// our code none (declared): our bytes equal the original's only at this layout.
fn m_ref_missing(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let err = |e: rusqlite::Error| Error::runtime(format!("{}: {e}", ctx.db));
    let (funcs, _) = compiled_functions(ctx, db)?;
    let refs: Vec<Rc<Claim>> = store::claims(db, &ctx.db, "ref", &ctx.needed, |f| f.s("rkind") == Some("operand")).map_err(err)?;
    if refs.is_empty() {
        return Ok(());
    }
    let mut sorted: Vec<(i64, i64, i64, usize)> = refs.iter().enumerate()
        .map(|(i, f)| (f.lo, f.hi, f.value.get("to").and_then(|v| v.as_i64()).unwrap_or(0), i)).collect();
    sorted.sort_unstable();
    let phi = phi_of(ctx, db)?;
    for x in funcs.iter().filter(|x| x.c.matched()) {
        let (lo, len) = (x.src.lo, x.code.code_len.unwrap_or(x.code.data.len() as u32) as i64);
        let i = sorted.partition_point(|r| r.0 < lo);
        let inside: Vec<(i64, i64, i64)> = sorted[i..].iter().take_while(|r| r.0 < lo + len).map(|r| (r.0, r.1, r.2)).collect();
        let fields: Vec<(u32, u32)> = x.code.relocs.iter().map(|(off, r)| (*off, r.kind_width().1)).collect();
        for (a, b, to) in missing_refs(lo, len, &fields, &inside) {
            let by = sorted.iter().find(|r| r.0 == a && r.1 == b && r.2 == to).map(|r| refs[r.3].by.clone()).unwrap_or_default();
            let what = phi.names_at(to).into_iter().next().map(|n| format!("{n} ({to:#x})")).unwrap_or_else(|| format!("{to:#x}"));
            out.finding2("error", "M.ref.missing", a, b,
                         format!("{} at {lo:#x}: the instruction at {a:#x} holds {to:#x} as a constant where the original refers to {what}: \
                                  write the object, not its address (the bytes match at this layout only)", x.src.s("symbol").unwrap_or("")),
                         &x.src.by, &by);
        }
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ M.lint

/// srcscan.Spans: (file, line) -> the function whose span holds the line (address comment to the end of its
/// definition; an end of 0: to the next span).
struct Spans {
    by: HashMap<String, Vec<(i64, i64, i64)>>, // file -> (first, last, address), sorted by first (stable)
}

impl Spans {
    fn at(&self, file: &str, line: i64) -> Option<i64> {
        let xs = self.by.get(file)?;
        let k = xs.partition_point(|x| x.0 <= line);
        if k == 0 {
            return None;
        }
        let (_, hi, a) = xs[k - 1];
        if hi != 0 && line > hi {
            return None;
        }
        Some(a)
    }
}

/// FILE_LINE (`^(.*?):(\d+): `): the file and line a lint line starts with.
fn file_line(text: &str) -> Option<(&str, i64)> {
    let first = text.split('\n').next().unwrap_or("");
    let b = first.as_bytes();
    for i in 0..b.len() {
        if b[i] != b':' {
            continue;
        }
        let mut j = i + 1;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        if j > i + 1 && j + 1 < b.len() + 1 && b.get(j) == Some(&b':') && b.get(j + 1) == Some(&b' ') {
            return Some((&first[..i], first[i + 1..j].parse().ok()?));
        }
    }
    None
}

/// M5 / M6 / M7 and a stale lint (M.lint), from the last `dcp lint`.
fn m_lint(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let err = |e: rusqlite::Error| Error::runtime(format!("{}: {e}", ctx.db));
    let meta: Option<String> = db
        .query_row("SELECT value FROM meta WHERE key='lint'", [], |r| r.get(0))
        .map(Some)
        .or_else(|e| if matches!(e, rusqlite::Error::QueryReturnedNoRows) { Ok(None) } else { Err(e) })
        .map_err(err)?;
    let res: Value = meta.and_then(|m| serde_json::from_str(&m).ok()).unwrap_or(Value::Null);
    // a lint of an older decompanion (calls without their lines) counts as none, as Project.input("lint")
    let old = res.get("calls").and_then(|c| c.as_object()).map(|m| m.values().any(|cs| {
        cs.as_array().map(|a| a.iter().any(|c| c.is_string())).unwrap_or(false)
    })).unwrap_or(false);
    let empty = match &res {
        Value::Null => true,
        Value::Object(m) => m.is_empty(),
        _ => false,
    };
    if empty || old {
        return Ok(());
    }
    let img = image(&ctx.image)?;
    let base = img.base as i64;
    let mut by: HashMap<String, Vec<(i64, i64, i64)>> = HashMap::new();
    for f in store::claims(db, &ctx.db, "source", &ctx.needed, |f| f.s("what") == Some("func")).map_err(err)?.iter() {
        let file = f.s("file").unwrap_or("").to_string();
        let first = f.value.get("comment").or_else(|| f.value.get("line")).and_then(|v| v.as_i64()).unwrap_or(0);
        let last = f.value.get("end").and_then(|v| v.as_i64()).unwrap_or(0);
        by.entry(file).or_default().push((first, last, f.lo));
    }
    for xs in by.values_mut() {
        xs.sort_by_key(|x| x.0);
    }
    let spans = Spans { by };
    let at = |file: Option<&str>, line: Option<i64>| -> i64 {
        match (file, line) {
            (Some(f), Some(l)) => spans.at(f, l).unwrap_or(base),
            _ => base,
        }
    };
    let strs = |k: &str| -> Vec<String> {
        res.get(k).and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
    };
    for (key, check) in [("errors", "M6"), ("cross", "M5")] {
        for e in strs(key) {
            let a = match file_line(&e) {
                Some((f, l)) => at(Some(f), Some(l)),
                None => base,
            };
            out.finding("error", check, a, a + 1, e, "");
        }
    }
    if let Some(calls) = res.get("calls").and_then(|c| c.as_object()) {
        for (f, cs) in calls {
            for c in cs.as_array().into_iter().flatten() {
                let line = c.get(0).and_then(|v| v.as_i64());
                let text = c.get(1).and_then(|v| v.as_str()).unwrap_or("");
                let a = at(Some(f), line);
                out.finding("warn", "M7", a, a + 1, format!("{f}: call without a prototype: {text}"), "");
            }
        }
    }
    let parsed = res.get("units").and_then(|u| u.as_object());
    let mut stale: Vec<&String> = ctx.inputs.units.iter()
        .filter(|(u, h)| parsed.and_then(|p| p.get(*u)).and_then(|v| v.as_str()) != Some(h.as_str())).map(|(u, _)| u).collect();
    stale.sort();
    if !stale.is_empty() {
        let names: Vec<&str> = stale.iter().map(|s| s.as_str()).collect();
        out.finding("warn", "M.lint.stale", base, base + 1,
                     format!("the last lint did not parse today's text of: {} (dcp lint)", names.join(", ")), "");
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ data rules

/// φ as this rule sees it: from the `name` claims of the rules it needs.
fn phi_of(ctx: &Ctx, db: &Connection) -> Result<crate::phi::Phi> {
    let names = store::claims(db, &ctx.db, "name", &ctx.needed, |_| true).map_err(|e| Error::runtime(format!("{}: {e}", ctx.db)))?;
    Ok(crate::phi::Phi::new(&names, &[]))
}

/// One data definition of the sources with an address (match_data.data_objects): its L.src fact, its unit's
/// object and the data symbol of its C name there (kind, size).
struct DataObj {
    f: Rc<Claim>,
    obj: Option<crate::ObjIndex>,
    sym: Option<(usize, &'static str, u32)>,
}

impl DataObj {
    fn symbol(&self) -> Option<&crate::coff::Symbol> {
        Some(&self.obj.as_ref()?.0.symbols[self.sym?.0])
    }
    fn kind(&self) -> Option<&'static str> {
        self.sym.map(|s| s.1)
    }
    fn size(&self) -> Option<u32> {
        self.sym.map(|s| s.2)
    }
}

fn data_objects(ctx: &Ctx, db: &Connection) -> Result<Vec<DataObj>> {
    let err = |e: rusqlite::Error| Error::runtime(format!("{}: {e}", ctx.db));
    let mut index: HashMap<String, (crate::ObjIndex, HashMap<String, (usize, &'static str, u32)>)> = HashMap::new();
    for (unit, (h, ok)) in &objects(db)? {
        if !*ok || h.is_empty() {
            continue;
        }
        let Some(o) = crate::object_if(&format!("{}/build/obj/{}.obj", ctx.root, h))? else { continue };
        let mut idx = HashMap::new();
        for d in o.0.data_symbols() {
            idx.entry(crate::coff::undecorate(&o.0.symbols[d.sym].name)).or_insert((d.sym, d.kind, d.size));
        }
        index.insert(unit.clone(), (o, idx));
    }
    let mut fs: Vec<Rc<Claim>> = store::claims(db, &ctx.db, "source", &ctx.needed, |f| &*f.rule == "L.src" && f.s("what") == Some("data"))
        .map_err(err)?;
    fs.sort_by(|a, b| (a.lo, a.s("file")).cmp(&(b.lo, b.s("file"))));
    Ok(fs
        .into_iter()
        .map(|f| {
            let hit = index.get(f.s("unit").unwrap_or(""));
            let sym = hit.and_then(|(_, idx)| idx.get(f.s("symbol").unwrap_or("")).copied());
            DataObj { obj: hit.map(|(o, _)| o.clone()), sym, f }
        })
        .collect())
}

/// least_size: the fewest bytes a symbol at `value` (None: no symbol) with the COFF size `size` can have. COFF
/// records no sizes: a size runs to the next symbol of the section, taking in the alignment padding in front of
/// it, which is less than the alignment of the offset where the distance ends (at most 8: VC6 aligns an object
/// of 8 bytes or more to 8, smaller ones naturally); exactly `size` when that offset is odd.
pub fn least(value: Option<u32>, size: u32) -> u32 {
    let Some(v) = value else { return size };
    if size == 0 {
        return 0;
    }
    let end = v.wrapping_add(size);
    let a = if end % 8 == 0 { 8 } else if end % 4 == 0 { 4 } else if end % 2 == 0 { 2 } else { 1 };
    1u32.max(size.saturating_sub(a - 1))
}

/// padding_masked: the mask with the possible alignment padding masked too, the zero bytes from the least size
/// on (the padding in front of the next symbol is zero in our object; a nonzero byte there is the symbol's own).
pub fn padding_masked(data: &[u8], mask: &[u8], least: usize) -> Vec<u8> {
    let mut m = mask.to_vec();
    for k in least..data.len() {
        if data[k] == 0 && k < m.len() {
            m[k] = 1;
        }
    }
    m
}

/// The least size of a data definition (None without a size).
fn least_size(d: &DataObj) -> Option<u32> {
    Some(least(d.symbol().map(|s| s.value), d.size()?))
}

/// The size of a data definition's declared type, the front end's (None: a type it does not know).
fn declared_size(d: &DataObj) -> Option<i64> {
    d.f.value.get("size").and_then(|v| v.as_i64()).filter(|&n| n > 0)
}

/// match_data.extent: [address, address + n), never one byte for want of a size: the declared type's size when
/// our object's symbol can be that large (its COFF size takes in the padding to the next symbol), else the
/// symbol's least size; without a symbol of ours the declared type's size; without either the contiguity
/// convention, up to `next` (the next definition's address or the section's end).
fn data_extent(d: &DataObj, next: i64) -> (i64, i64) {
    let decl = declared_size(d);
    let n = match (least_size(d).filter(|&l| l > 0), d.size()) {
        (Some(l), Some(s)) => decl.filter(|&n| l as i64 <= n && n <= s as i64).unwrap_or(l as i64),
        _ => decl.unwrap_or(next - d.f.lo),
    };
    (d.f.lo, d.f.lo + n.max(1))
}

/// Per data definition (data_objects' order) where its contiguity extent ends: the next definition's address
/// above it in the same section of the image, else that section's end.
fn extent_ends(ctx: &Ctx, objs: &[DataObj]) -> Result<Vec<i64>> {
    let img = image(&ctx.image)?;
    let mut los: Vec<i64> = objs.iter().map(|d| d.f.lo).collect();
    los.sort_unstable();
    los.dedup();
    Ok(objs.iter()
        .map(|d| {
            let end = img.section_of(d.f.lo as u32).map_or(d.f.lo + 1, |s| s.va as i64 + s.vsize.max(s.raw_size) as i64);
            let k = los.partition_point(|&x| x <= d.f.lo);
            los.get(k).copied().unwrap_or(i64::MAX).min(end)
        })
        .collect())
}

/// match_data.site_confirmed: address -> C name of every data address a byte-matched function's absolute
/// relocation confirms (the first such relocation wins). Only a near-certain reference is evidence: a
/// memory operand's displacement, or an immediate at a base relocation of the image. An immediate otherwise may
/// be a number (`&g_Ring + 0x4973c0` is the mask 0xf00500): the original's field minus our addend confirms
/// nothing.
fn site_confirmed(ctx: &Ctx, db: &Connection) -> Result<HashMap<u32, String>> {
    let img = image(&ctx.image)?;
    let based: std::collections::HashSet<u32> = img.relocations().into_iter().collect();
    let (funcs, _) = compiled_functions(ctx, db)?;
    let mut out = HashMap::new();
    for x in &funcs {
        if !x.c.matched() {
            continue;
        }
        let obj = &x.obj.0;
        let mut ins: Option<Vec<crate::dis::Ins>> = None;
        for (off, r) in &x.code.relocs {
            let Some(t) = obj.symbol_at(r.symbol_index) else { continue };
            let (kind, width) = r.kind_width();
            if !t.named() || t.function() || t.constant().is_some() || t.name.starts_with("__imp_") || kind != crate::coff::ABSOLUTE {
                continue;
            }
            let site = (x.src.lo as u32).wrapping_add(*off);
            let ins = ins.get_or_insert_with(|| crate::dis::decode(x.code.code().0, 0));
            let near = match crate::refcheck::field_at(ins, *off) {
                Some((_, crate::dis::FieldKind::Disp)) => true,
                Some((_, crate::dis::FieldKind::Imm | crate::dis::FieldKind::Imm2)) => based.contains(&site),
                _ => false,
            };
            if !near {
                continue;
            }
            if let Some(to) = r.resolve(site, &img.bytes(site, width as usize), obj.addend(x.code.secnum, r)) {
                out.entry(to).or_insert_with(|| crate::coff::undecorate(&t.name));
            }
        }
    }
    Ok(out)
}

fn global(d: &DataObj, extent: &str, kind: &str) -> Value {
    json!({"skind": "global", "name": d.f.value["symbol"], "unit": d.f.value["unit"], "extent": extent, "kind": kind})
}

/// M.data.site: a data definition whose address a byte-matched function's relocation to the same symbol confirms.
fn m_data_site(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let confirmed = site_confirmed(ctx, db)?;
    let objs = data_objects(ctx, db)?;
    for (d, next) in objs.iter().zip(extent_ends(ctx, &objs)?) {
        if confirmed.get(&(d.f.lo as u32)).map(|s| s.as_str()) == d.f.s("symbol") {
            let (lo, hi) = data_extent(d, next);
            out.claim(lo, hi, "symbol", global(d, "site", d.kind().unwrap_or("-")), crate::store::REPRODUCED);
        }
    }
    Ok(())
}

fn masked_equal(img: &crate::pe::Image, at: u32, data: &[u8], mask: &[u8]) -> bool {
    let have = img.bytes(at, data.len());
    (0..data.len()).all(|k| mask.get(k).copied().unwrap_or(0) != 0 || Some(&data[k]) == have.get(k))
}

/// match_data.content_hits: the image's initialised non-code data addresses where data occurs (masked), at most 2.
fn content_hits(img: &crate::pe::Image, data: &[u8], mask: &[u8]) -> Vec<u32> {
    let (mut run, mut k0): (&[u8], usize) = (&[], 0);
    let mut i = 0;
    while i < data.len() {
        if mask.get(i).copied().unwrap_or(0) != 0 {
            i += 1;
            continue;
        }
        let mut j = i;
        while j < data.len() && mask.get(j).copied().unwrap_or(0) == 0 {
            j += 1;
        }
        if j - i > run.len() {
            run = &data[i..j];
            k0 = i;
        }
        i = j;
    }
    let mut out = vec![];
    if run.len() < 4 {
        return out;
    }
    let finder = memchr::memmem::Finder::new(run);
    for s in &img.sections {
        if s.holds_code() || s.uninitialized() {
            continue;
        }
        let raw = img.section_data(s);
        for p in finder.find_iter(raw) {
            let at = (s.va as i64) + p as i64 - k0 as i64;
            if at >= s.va as i64 && masked_equal(img, at as u32, data, mask) {
                out.push(at as u32);
                if out.len() >= 2 {
                    return out;
                }
            }
        }
    }
    out
}

/// M.data.content: a data definition M.data.site does not place whose bytes occur in the image's initialised
/// data at the declared address and nowhere else.
fn m_data_content(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    let confirmed = site_confirmed(ctx, db)?;
    let objs = data_objects(ctx, db)?;
    for (d, next) in objs.iter().zip(extent_ends(ctx, &objs)?) {
        let (Some(sym), Some(kind), Some(size)) = (d.symbol(), d.kind(), d.size()) else { continue };
        if !(kind == "data" || kind == "rdata") || confirmed.get(&(d.f.lo as u32)).map(|s| s.as_str()) == d.f.s("symbol") {
            continue;
        }
        let obj = &d.obj.as_ref().unwrap().0;
        let Some(sec) = obj.section_of(sym) else { continue };
        let Some(sdata) = sec.data.as_ref() else { continue };
        // symbol_bytes, then padding_masked: the zero bytes from the least size on masked too
        let (a, b) = (sym.value as usize, sym.value as usize + size as usize);
        let data = &sdata[a.min(sdata.len())..b.min(sdata.len())];
        let full = sec.mask();
        let mask = padding_masked(data, &full[a.min(full.len())..b.min(full.len())], least_size(d).unwrap_or(0) as usize);
        let unmasked: Vec<usize> = (0..data.len()).filter(|&k| mask.get(k).copied().unwrap_or(0) == 0).collect();
        if unmasked.len() < 4 || !unmasked.iter().any(|&k| data[k] != 0) {
            continue;
        }
        let hits = content_hits(&img, data, &mask);
        if hits.len() == 1 && hits[0] as i64 == d.f.lo {
            let (lo, hi) = data_extent(d, next);
            out.claim(lo, hi, "symbol", global(d, "content", kind), crate::store::REPRODUCED);
        } else if hits.len() == 1 && !masked_equal(&img, d.f.lo as u32, data, &mask) {
            out.finding("error", "M.data.content", d.f.lo, d.f.lo + 1,
                         format!("{}: its bytes occur once in the image, at {:#x}, not at the declared {:#x}",
                                 d.f.s("symbol").unwrap_or(""), hits[0], d.f.lo), &d.f.by);
        }
    }
    Ok(())
}

/// M.data.draft: every other data definition with an address owns its declared extent.
fn m_data_draft(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let err = |e: rusqlite::Error| Error::runtime(format!("{}: {e}", ctx.db));
    let placed: std::collections::HashSet<i64> =
        store::los(db, &ctx.db, "symbol", &ctx.needed, |_| true).map_err(err)?.into_iter().collect();
    let objs = data_objects(ctx, db)?;
    for (d, next) in objs.iter().zip(extent_ends(ctx, &objs)?) {
        if placed.contains(&d.f.lo) {
            continue;
        }
        let (lo, hi) = data_extent(d, next);
        out.claim(lo, hi, "symbol", global(d, "draft", d.kind().unwrap_or("-")), DECLARED);
    }
    Ok(())
}

/// match_data.text_position: (file, line) -> its place in the order the unit's translation unit defines things.
fn text_position(root: &str, unit: &str) -> impl Fn(&str, i64) -> (i64, i64) {
    let text = std::fs::read(format!("{root}/src/{unit}.c"))
        .map(|b| String::from_utf8_lossy(&b).replace("\r\n", "\n").replace('\r', "\n"))
        .unwrap_or_default();
    let mut inc: HashMap<String, i64> = HashMap::new();
    let mut line = 1i64;
    for l in text.split('\n') {
        // ^[ \t]*#[ \t]*include[ \t]*["<]([^">]+)[">]
        let s = l.trim_start_matches([' ', '\t']);
        if let Some(r) = s.strip_prefix('#') {
            let r = r.trim_start_matches([' ', '\t']);
            if let Some(r) = r.strip_prefix("include") {
                let r = r.trim_start_matches([' ', '\t']);
                if r.starts_with('"') || r.starts_with('<') {
                    let body = &r[1..];
                    if let Some(e) = body.find(['"', '>']) {
                        if e > 0 {
                            let name = basename(&body[..e]).to_lowercase();
                            inc.entry(name).or_insert(line);
                        }
                    }
                }
            }
        }
        line += 1;
    }
    let own = format!("src/{unit}.c");
    move |file: &str, line: i64| {
        if file == own {
            (line, 0)
        } else {
            (*inc.get(&basename(file).to_lowercase()).unwrap_or(&(1 << 30)), line)
        }
    }
}

fn basename(p: &str) -> &str {
    p.rsplit(['/', '\\']).next().unwrap_or(p)
}

/// A data definition as D8 reads it: its address, least and object size, C name, producer.
pub(crate) struct ExtentDecl {
    pub lo: i64,
    pub least: i64,
    pub size: i64,
    pub name: String,
    pub by: String,
    pub unit: String,
    pub kind: String, // the object's section kind (data / rdata / bss)
}

/// An S.extent fact: [lo, hi) is one object of the original.
pub(crate) struct ExtentEv {
    pub lo: i64,
    pub hi: i64,
    pub base: i64,
    pub site: i64,
    pub how: String,
    pub to: i64,
}

/// D8: the evidence merged into objects (overlapping ranges are one object); an object that more than one
/// declaration overlaps, or that reaches past the one declaration's object size or starts before it, is a
/// conflict (severity, lo, hi, message, the first declaration's producer), always an error: declarations that are
/// pieces of one unit and section kind tiling the object without a hole link where the original's bytes are (a
/// unit's definitions keep their order and adjacency), but one object of the original as several of ours is no valid φ
///; their message names the merge. `named`: a registered name of an address.
pub(crate) fn d8(decls: &[ExtentDecl], ev: &[ExtentEv], named: impl Fn(i64) -> Option<String>) -> Vec<(&'static str, i64, i64, String, String)> {
    let mut ev: Vec<&ExtentEv> = ev.iter().collect();
    ev.sort_by_key(|e| (e.lo, -e.hi));
    let mut objects: Vec<(i64, i64, &ExtentEv)> = vec![]; // (lo, hi, the evidence reaching farthest)
    for e in ev {
        match objects.last_mut() {
            Some(o) if e.lo < o.1 => {
                if e.hi > o.1 {
                    o.1 = e.hi;
                    o.2 = e;
                }
            }
            _ => objects.push((e.lo, e.hi, e)),
        }
    }
    let mut decls: Vec<&ExtentDecl> = decls.iter().collect();
    decls.sort_by_key(|d| d.lo);
    let mut out = vec![];
    for (lo, hi, why) in objects {
        let inside: Vec<&&ExtentDecl> = decls.iter().filter(|d| d.lo < hi && lo < d.lo + d.least.max(1)).collect();
        let Some(first) = inside.first() else { continue };
        if inside.len() == 1 && first.lo <= lo && hi <= first.lo + first.size.max(1) {
            continue;
        }
        let (base, site) = (why.base, why.site);
        let how = match why.how.as_str() {
            "field" => format!("an access through the address {base:#x} at {site:#x}"),
            "bound" => format!("a loop from {base:#x} at {site:#x}"),
            "copy" => format!("a block copy at {site:#x}"),
            "call" => {
                let f = named(why.to).map(|n| format!("{n} ({:#x})", why.to)).unwrap_or_else(|| format!("{:#x}", why.to));
                format!("the address {base:#x} passed at {site:#x} to {f}, which reaches that far through it")
            }
            h => format!("{h} at {site:#x}"),
        };
        let msg = if first.lo <= lo {
            let rest: Vec<String> = inside[1..].iter().map(|d| format!("{} (+{:#x})", d.name, d.lo - first.lo)).collect();
            let rest = if rest.is_empty() { String::new() } else { format!("; declared inside it: {}: views of it or fields of its type", rest.join(", ")) };
            format!("{} at {:#x} is {} bytes, the original's code uses {lo:#x}..{hi:#x} as one object ({how}): {} needs at least {} bytes{rest}",
                    first.name, first.lo, first.size, first.name, hi - first.lo)
        } else {
            let names: Vec<String> = inside.iter().map(|d| format!("{} ({:#x}, {} bytes)", d.name, d.lo, d.size)).collect();
            format!("the original's code uses {lo:#x}..{hi:#x} ({} bytes) as one object ({how}), which starts before {}: one declaration at {lo:#x} \
                     holds {}", hi - lo, first.name, names.join(", "))
        };
        let tiled = inside.len() > 1 && first.lo <= lo
            && inside.iter().all(|d| d.unit == first.unit && d.kind == first.kind && !d.unit.is_empty())
            && inside.windows(2).all(|w| w[1].lo <= w[0].lo + w[0].size)
            && inside.last().is_some_and(|d| hi <= d.lo + d.size);
        let msg = if tiled {
            let cut = if first.lo < lo { format!(" ({} holds bytes before it: cut it there unless the rows say otherwise)", first.name) } else { String::new() };
            format!("{msg} (all of unit {}, in order and without a hole: it links as the original's, but it is one object: declare one object \
                     holding {lo:#x}..{hi:#x}, the pieces inside as its fields, or as views of it with `@original` where a unit needs another \
                     spelling; the range is what the accesses reach, a lower bound: a table's start and end follow from its rows' stride{cut})",
                    first.unit)
        } else {
            msg
        };
        out.push(("error", lo, hi, msg, first.by.clone()));
    }
    out
}

/// The data definitions whose padding the original's references reach. `defs`: per definition its address, its
/// size (declared, else its symbol's least) and its object size (to the next symbol of its section in our
/// object): the padding is the bytes between the two, cut at the next known start of the image (`starts`,
/// sorted). Per such definition (its index) its end, where the padding ends and the targets of `into` (target ->
/// sites) in it, in address order. Undeclared bytes after the last definition of a unit are a gap (no claim of
/// ours), not padding.
fn room_refs(defs: &[(i64, i64, i64)], starts: &[i64], into: &std::collections::BTreeMap<i64, Vec<i64>>) -> Vec<(usize, i64, i64, Vec<(i64, Vec<i64>)>)> {
    let mut out = vec![];
    for (k, &(lo, n, size)) in defs.iter().enumerate() {
        let end = lo + n;
        let i = starts.partition_point(|&s| s <= lo);
        let next = starts.get(i).copied().unwrap_or(i64::MAX).min(lo + size);
        if n <= 0 || next <= end {
            continue;
        }
        let hits: Vec<(i64, Vec<i64>)> = into.range(end..next).map(|(t, s)| (*t, s.clone())).collect();
        if !hits.is_empty() {
            out.push((k, end, next, hits));
        }
    }
    out
}

/// Whether the instruction at `site` of the image has a memory operand at the absolute address `t` with no base
/// and no index register.
pub(crate) fn bare_operand(img: &crate::pe::Image, site: i64, t: i64) -> bool {
    crate::dis::decode(&img.read(site as u32, 16), site as u32).first().is_some_and(|x| {
        x.ops.iter().any(|o| o.typ == crate::dis::OpType::Mem && o.base == crate::dis::Reg::None && o.index == crate::dis::Reg::None && o.disp == t)
    })
}

/// D1 / D4 / D5 / D6 / D7 / D8 / D9 (D.data).
fn d_data(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let err = |e: rusqlite::Error| Error::runtime(format!("{}: {e}", ctx.db));
    let img = image(&ctx.image)?;
    let objs = data_objects(ctx, db)?;
    let mut starts: Vec<i64> = store::los(db, &ctx.db, "symbol", &ctx.needed, |f| {
        matches!(f.s("skind"), Some("global") | Some("crt.data") | Some("string") | Some("iat"))
    })
    .map_err(err)?;
    starts.extend(objs.iter().map(|d| d.f.lo));
    starts.sort_unstable();
    starts.dedup();
    for d in &objs {
        let name = d.f.s("symbol").unwrap_or("");
        if let Some(size) = d.size() {
            if size > 1 {
                let i = starts.partition_point(|&s| s <= d.f.lo);
                if i < starts.len() && starts[i] < d.f.lo + size as i64 {
                    let least = least_size(d).unwrap_or(0) as i64;
                    let room = starts[i] - d.f.lo;
                    if room < least {
                        out.finding("error", "D1", d.f.lo, d.f.lo + size as i64,
                                     format!("{name} at {:#x} ({least} bytes at least) overlaps the symbol at {:#x}", d.f.lo, starts[i]),
                                     &d.f.by);
                    } else {
                        out.finding("warn", "D1", d.f.lo, d.f.lo + size as i64,
                                     format!("{name} at {:#x}: the object gives it {size} bytes, the symbol at {:#x} leaves {room}; fine if \
                                              the last {} are alignment padding", d.f.lo, starts[i], size as i64 - room), &d.f.by);
                    }
                }
            }
        }
        if d.symbol().map(|s| s.common()).unwrap_or(false) {
            let va = d.f.lo as u32;
            if img.section_of(va).is_some() && img.off(va).is_none() {
                out.finding("error", "D5", d.f.lo, d.f.lo + 1,
                             format!("{name} at {:#x} lies in uninitialised data and is a tentative definition: write it `= 0` so \
                                      it is placed with its unit", d.f.lo), &d.f.by);
            }
        }
    }
    // D7: a view whose offset lies at or past its container's end (a view of a view: of the definition the chain
    // ends at)
    let views: HashMap<String, (i64, String, String)> = store::claims(db, &ctx.db, "name", &ctx.needed, |f| f.s("view").is_some())
        .map_err(err)?
        .iter()
        .map(|f| (f.s("name").unwrap_or("").to_string(), (f.lo, f.s("view").unwrap_or("").to_string(), f.by.clone())))
        .collect();
    let mut defs: HashMap<&str, Vec<&DataObj>> = HashMap::new();
    for d in &objs {
        defs.entry(d.f.s("symbol").unwrap_or("")).or_default().push(d);
    }
    let mut vnames: Vec<&String> = views.keys().collect();
    vnames.sort();
    for vname in vnames {
        let (at, first, by) = &views[vname];
        let mut c = first.as_str();
        for _ in 0..8 {
            match views.get(c) {
                Some((_, next, _)) if !defs.contains_key(c) => c = next,
                _ => break,
            }
        }
        // the definition of that name at or below the view's address (a static name may have several)
        let Some(d) = defs.get(c).and_then(|ds| ds.iter().filter(|d| d.f.lo <= *at).max_by_key(|d| d.f.lo)) else { continue };
        // the declared type's size (the front end's; the padding to the next symbol is no part of the object),
        // else the object's size, padding included
        let Some(size) = declared_size(d).or(d.size().map(|s| s as i64)) else { continue };
        let off = at - d.f.lo;
        if off >= size {
            let via = if c == first { String::new() } else { format!(" (through {first})") };
            out.finding2("error", "D7", *at, *at + 1,
                          format!("view {vname} at {at:#x} is {c}{via} +{off:#x}, outside {c} ({size} bytes): the view reads whatever the \
                                   linker puts after {c}; declare {c} as large as the original's object (a struct or an array)"),
                          by, &d.f.by);
        }
    }
    // D9: the original's absolute memory operands into the bytes past a definition's declared size, before the
    // next known object (padding or room by our layout)
    let refs = store::claims(db, &ctx.db, "ref", &ctx.needed, |f| f.s("rkind") == Some("operand")).map_err(err)?;
    let mut into: std::collections::BTreeMap<i64, Vec<i64>> = std::collections::BTreeMap::new(); // target -> sites
    for f in &refs {
        if let Some(t) = f.value.get("to").and_then(|v| v.as_i64()) {
            into.entry(t).or_default().push(f.lo);
        }
    }
    let sized: Vec<(&DataObj, (i64, i64, i64))> = objs.iter()
        .filter_map(|d| Some((d, (d.f.lo, declared_size(d).or(least_size(d).map(|l| l as i64))?, d.size()? as i64))))
        .collect();
    let defs: Vec<(i64, i64, i64)> = sized.iter().map(|x| x.1).collect();
    for (k, end, next, hits) in room_refs(&defs, &starts, &into) {
        let d = sized[k].0;
        // an indexed operand's displacement is the compiler's arithmetic (`[arr-4+ecx*4]`): only a bare address
        let bare: Vec<(i64, usize)> = hits.into_iter().filter_map(|(t, sites)| {
            let n = sites.iter().filter(|&&s| bare_operand(&img, s, t)).count();
            (n > 0).then_some((t, n))
        }).collect();
        if bare.is_empty() {
            continue;
        }
        let name = d.f.s("symbol").unwrap_or("");
        let each: Vec<String> = bare.iter().take(8).map(|(t, n)| format!("{t:#x} (+{:#x}, {n} use{})", t - d.f.lo, if *n == 1 { "" } else { "s" })).collect();
        let more = if bare.len() > 8 { format!(" and {} more", bare.len() - 8) } else { String::new() };
        out.finding("error", "D9", d.f.lo, next,
                     format!("{name} at {:#x} is {} bytes, our object pads it to {next:#x}; the original's code refers to {}{more} in that padding: \
                              {name} is larger (an array or a struct), or an object of its own is missing there (dcp data map)",
                             d.f.lo, end - d.f.lo, each.join(", ")), &d.f.by);
    }
    // D8: the original's code proves a range one object (S.extent): one declaration must hold all of it
    let phi = phi_of(ctx, db)?;
    let ev: Vec<ExtentEv> = store::claims(db, &ctx.db, "evidence", &ctx.needed, |f| f.s("ekind") == Some("extent")).map_err(err)?
        .iter()
        .map(|f| {
            let i = |k: &str| f.value.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
            ExtentEv { lo: f.lo, hi: f.hi, base: i("base"), site: i("site"), how: f.s("how").unwrap_or("").to_string(), to: i("to") }
        })
        .collect();
    let decls: Vec<ExtentDecl> = objs.iter()
        .filter_map(|d| d.size().map(|s| ExtentDecl { lo: d.f.lo, least: least_size(d).unwrap_or(1) as i64, size: s as i64,
                                                      name: d.f.s("symbol").unwrap_or("").to_string(), by: d.f.by.clone(),
                                                      unit: d.f.s("unit").unwrap_or("").to_string(), kind: d.kind().unwrap_or("").to_string() }))
        .collect();
    let named = |a: i64| phi.names_at(a).into_iter().next();
    for (sev, lo, hi, msg, by) in d8(&decls, &ev, named) {
        out.finding(sev, "D8", lo, hi, msg, &by);
    }
    // D4: per unit and section kind, in the unit file's text order
    let mut per: std::collections::BTreeMap<(String, &'static str), Vec<&DataObj>> = std::collections::BTreeMap::new();
    for d in &objs {
        if let Some(k) = d.kind() {
            if k == "data" || k == "rdata" || k == "bss" {
                per.entry((d.f.s("unit").unwrap_or("").to_string(), k)).or_default().push(d);
            }
        }
    }
    for ((unit, kind), fs) in &per {
        let at = text_position(&ctx.root, unit);
        let mut order: Vec<&&DataObj> = fs.iter().collect();
        order.sort_by_key(|d| at(d.f.s("file").unwrap_or(""), d.f.value.get("line").and_then(|v| v.as_i64()).unwrap_or(0)));
        for w in order.windows(2) {
            let (a, b) = (w[0], w[1]);
            if b.f.lo < a.f.lo {
                out.finding2("error", "D4", b.f.lo, b.f.lo + 1,
                              format!("unit {unit} ({kind}): {} ({:#x}) is defined after {} ({:#x}) but lies before it",
                                      b.f.s("symbol").unwrap_or(""), b.f.lo, a.f.s("symbol").unwrap_or(""), a.f.lo),
                              &b.f.by, &a.f.by);
            }
        }
    }
    // D6: pointer-table entries
    for d in &objs {
        let (Some(sym), Some(size)) = (d.symbol(), d.size()) else { continue };
        if size == 0 {
            continue;
        }
        let obj = &d.obj.as_ref().unwrap().0;
        let Some(sec) = obj.section_of(sym) else { continue };
        if sec.data.is_none() {
            continue;
        }
        for r in &sec.relocs {
            let (kind, width) = r.kind_width();
            if !(sym.value <= r.offset && r.offset < sym.value + size) || kind != crate::coff::ABSOLUTE {
                continue;
            }
            let Some(t) = obj.symbol_at(r.symbol_index) else { continue };
            if !t.named() || t.constant().is_some() {
                continue;
            }
            let site = (d.f.lo as u32).wrapping_add(r.offset - sym.value);
            let Some(to) = r.resolve(site, &img.bytes(site, width as usize), obj.addend(sym.secnum as usize, r)) else { continue };
            let cname = crate::coff::undecorate(t.name.strip_prefix("__imp_").unwrap_or(&t.name));
            let Some(regs) = phi.of(&cname) else { continue };
            if regs.is_empty() || regs.contains_key(&(to as i64)) {
                continue;
            }
            let (b, lvl) = regs.iter().next().unwrap();
            let others = phi.names_at(to as i64).into_iter().collect::<Vec<_>>().join(", ");
            let others = if others.is_empty() { "nothing registered".to_string() } else { others };
            out.finding(if lvl.is_top() { "bug" } else { "error" }, "D6", site as i64, (site + width) as i64,
                         format!("{} +{:#x}: our entry refers to {cname} (registered at {:#x}), the original's to {:#x} ({others})",
                                 d.f.s("symbol").unwrap_or(""), r.offset - sym.value, b, to), &d.f.by);
        }
    }
    Ok(())
}

/// A native rule's output (its facts and conflicts, unsorted).
pub(crate) fn dispatch(ctx: &Ctx) -> Result<Out> {
    let mut out = Out::new(&ctx.rule, &ctx.version);
    with_conn(&ctx.db, |db| match ctx.rule.as_str() {
        "M.draft" => m_draft(ctx, db, &mut out),
        "S.headers" => crate::setup::s_headers(ctx, db, &mut out),
        "S.sections" => crate::setup::s_sections(ctx, db, &mut out),
        "S.datadirs" => crate::setup::s_datadirs(ctx, db, &mut out),
        "S.imports" => crate::setup::s_imports(ctx, db, &mut out),
        "S.exports" => crate::setup::s_exports(ctx, db, &mut out),
        "S.entry" => crate::setup::s_entry(ctx, db, &mut out),
        "S.relocs" => crate::setup::s_relocs(ctx, db, &mut out),
        "S7.entry.section" => crate::setup::s7_entry_section(ctx, db, &mut out),
        "S4.import.libs" => crate::setup::s4_import_libs(ctx, db, &mut out),
        "C.overlap" => crate::setup::c_overlap(ctx, db, &mut out),
        "C.ref.target" => crate::setup::c_ref_target(ctx, db, &mut out),
        "C.name.alias" => crate::layout::c_name_alias(ctx, db, &mut out),
        "S5.crt.gaps" => crate::setup::s5_crt_gaps(ctx, db, &mut out),
        "S.entry.user" => crate::setup::s_entry_user(ctx, db, &mut out),
        "S.strings" => crate::setup::s_strings(ctx, db, &mut out),
        "S.fill" => crate::setup::s_fill(ctx, db, &mut out),
        "S.unknown" => crate::setup::s_unknown(ctx, db, &mut out),
        "L.decl" => crate::decl::l_decl(ctx, db, &mut out),
        "S.codewalk" => crate::walk::s_codewalk(ctx, db, &mut out),
        "S.extent" => crate::extent::s_extent(ctx, db, &mut out),
        "M.compile" => crate::mrules::m_compile(ctx, db, &mut out),
        "M.flags.probe" => crate::mrules::m_flags_probe(ctx, db, &mut out),
        "L.decl.start" => crate::decl::l_decl_start(ctx, db, &mut out),
        "L.analyzer" => crate::layout::l_analyzer(ctx, db, &mut out),
        "L.analyze" => crate::layout::l_analyze(ctx, db, &mut out),
        "S.rich" => crate::crt::s_rich(ctx, db, &mut out),
        "S.crt.code" => crate::crt::s_crt_code(ctx, db, &mut out),
        "S.crt.refs" => crate::crt::s_crt_refs(ctx, db, &mut out),
        "S.crt.data" => crate::crt::s_crt_data(ctx, db, &mut out),
        "S.lib.data" => crate::crt::s_lib_data(ctx, db, &mut out),
        "S.thunk" => crate::crt::s_thunk(ctx, db, &mut out),
        "C.toolchain" => crate::crt::c_toolchain(ctx, db, &mut out),
        "S2.rich.members" => crate::crt::s2_rich_members(ctx, db, &mut out),
        "L3.lit.order" => crate::layout::l3_lit_order(ctx, db, &mut out),
        "L6.declared" => crate::layout::l6_declared(ctx, db, &mut out),
        "L8.leak" => crate::layout::l8_leak(ctx, db, &mut out),
        "M.bytes.declared" => crate::layout::m_bytes_declared(ctx, db, &mut out),
        "M.match" => m_match(ctx, db, &mut out),
        "M.ref.missing" => m_ref_missing(ctx, db, &mut out),
        "M.lint" => m_lint(ctx, db, &mut out),
        "M.data.site" => m_data_site(ctx, db, &mut out),
        "M.data.content" => m_data_content(ctx, db, &mut out),
        "M.data.draft" => m_data_draft(ctx, db, &mut out),
        "D.data" => d_data(ctx, db, &mut out),
        "L9.analyzer.span" => crate::layout::l9_analyzer_span(ctx, db, &mut out),
        "L.src.extent" => crate::layout::l_src_extent(ctx, db, &mut out),
        "L.src.refs" => crate::walk::l_src_refs(ctx, db, &mut out),
        "L5.placeholder" => crate::layout::l5_placeholder(ctx, db, &mut out),
        "A1.addr.cast" => crate::layout::a1_addr_cast(ctx, db, &mut out),
        "L13.data.code" => crate::layout::l13_data_code(ctx, db, &mut out),
        "L.unit.extent" => crate::layout::l_unit_extent(ctx, db, &mut out),
        "M1.baseline" => crate::layout::m1_baseline(ctx, db, &mut out),
        "M.tiebreak" => crate::tiebreak::m_tiebreak(ctx, db, &mut out),
        "G.grade" => crate::grade::g_grade(ctx, db, &mut out),
        "L1.src.start" => crate::layout::l1_src_start(ctx, db, &mut out),
        "L.src" => crate::layout::l_src(ctx, db, &mut out),
        "L4.boundary" => crate::layout::l4_boundary(ctx, db, &mut out),
        "L10.unexplained" => crate::layout::l10_unexplained(ctx, db, &mut out),
        "L14.unit.outside" => crate::layout::l14_unit_outside(ctx, db, &mut out),
        other => Err(Error::runtime(format!("no native rule {other}"))),
    })?;
    Ok(out)
}

// ------------------------------------------------------------------------------------------------ test kit

#[cfg(test)]
pub(crate) mod testkit {
    //! A store in a temporary directory with an image beside it; rules run on it as the engine runs them.
    use crate::{with_db, write_run};
    use super::*;
    use crate::{ClaimRow, Finding};
    use crate::store::{Support, REPRODUCED};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static N: AtomicUsize = AtomicUsize::new(0);

    /// The declaration a test's toy rule name runs under (every output, any level).
    pub static TEST_RULE: crate::registry::RuleDef = crate::registry::RuleDef {
        id: "T", version: "1", max_support: REPRODUCED, phase: "T", loader: true, needs: &[], outputs: &[
            "section", "region", "symbol", "start", "name", "source", "unit", "boundary", "toolchain", "ref", "experiment", "readability", "build", "evidence"],
        inputs: &[], doc: "",
    };

    pub struct Kit {
        pub dir: std::path::PathBuf,
        pub db: String,
        pub image: String,
    }

    impl Kit {
        pub fn new(image: &[u8]) -> Kit {
            let dir = crate::testkit::scratch(&format!("kit-{}", N.fetch_add(1, Ordering::Relaxed)));
            std::fs::create_dir_all(&dir).unwrap();
            let img = dir.join("image.dll");
            std::fs::write(&img, image).unwrap();
            // the store as the core opens one (with_db: WAL), not SQLite's defaults (a rollback journal, a sync each write)
            let db = dir.join("store.sqlite").to_string_lossy().into_owned();
            crate::with_db(&db, |c| c.execute_batch(crate::store::SCHEMA)).unwrap();
            Kit { db, image: img.to_string_lossy().into_owned(), dir }
        }

        pub fn ctx(&self, rule: &str, needed: &[&str], extra: &str) -> Ctx {
            Ctx { rule: rule.into(), version: "1".into(), code_hash: "test".into(), input_hash: format!("test:{rule}"), db: self.db.clone(),
                  needed: needed.iter().map(|s| s.to_string()).collect(), root: self.dir.to_string_lossy().into_owned(),
                  image: self.image.clone(), fill_forms: vec![vec![0x90], vec![0xcc], vec![0x8b, 0xff], vec![0x8d, 0x49, 0x00]],
                  record: true, shortcuts: true, inputs: Rc::new(Inputs::of(extra)) }
        }

        /// A rule's output, sorted as recorded.
        pub fn run(&self, rule: &str, needed: &[&str], extra: &str) -> (Vec<ClaimRow>, Vec<Finding>) {
            dispatch(&self.ctx(rule, needed, extra)).unwrap().sorted()
        }

        /// Run and record a rule (the rules that need it read its facts).
        pub fn record(&self, rule: &str, needed: &[&str], extra: &str) {
            crate::engine::run_native(crate::engine::rule(rule).unwrap_or(&TEST_RULE), &self.ctx(rule, needed, extra)).unwrap();
        }

        /// Record a run of these claims (lo, hi, kind, value, support) under a rule's name, `by` its producer.
        pub fn put(&self, rule: &str, facts: &[(i64, i64, &str, serde_json::Value, Support)]) {
            let mut out = Out::new(rule, "1");
            for (lo, hi, kind, v, support) in facts {
                out.claim(*lo, *hi, kind, v.clone(), *support);
            }
            let (rows, confl) = out.sorted();
            with_db(&self.db, |db| write_run(db, &self.db, rule, "1", "test", &format!("put:{rule}"), &rows, &confl, 0, true)).unwrap();
        }
    }

    impl Drop for Kit {
        fn drop(&mut self) {
            crate::forget_conn(&self.db);
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// (lo, hi, kind, value) of the rows of one kind.
    pub fn of(rows: &[ClaimRow], kind: &str) -> Vec<(i64, i64, serde_json::Value)> {
        rows.iter().filter(|r| r.kind == kind).map(|r| (r.lo, r.hi, serde_json::from_str(&r.value).unwrap())).collect()
    }
}

#[cfg(test)]
mod tests_ref_missing {
    /// An absolute operand of the original inside our function counts as missing only when no relocated field of
    /// ours lies in its instruction; operands outside the function are not ours to judge.
    #[test]
    fn missing_where_no_field_of_ours() {
        let lo = 0x401000;
        // mov eax, [0x4a1230] at +0x10 (6 bytes): our field at +0x12; mov [0x4a1240], ecx at +0x20: none of ours
        let refs = [(lo + 0x10, lo + 0x16, 0x4a1230), (lo + 0x20, lo + 0x26, 0x4a1240), (lo + 0x40, lo + 0x46, 0x4a1250)];
        assert_eq!(super::missing_refs(lo, 0x30, &[(0x12, 4)], &refs), [(lo + 0x20, lo + 0x26, 0x4a1240)]);
        assert!(super::missing_refs(lo, 0x30, &[(0x12, 4), (0x22, 4)], &refs).is_empty());
    }
}

#[cfg(test)]
mod tests_aligned {
    /// D8 against the play-session crashes: a save header declared one int that the original's reader fills up to
    /// +0xfc, its fields drafted as globals of their own; a table declared short of the loop's bound.
    #[test]
    fn d8_declarations_smaller_than_the_proven_object() {
        use super::{d8, ExtentDecl, ExtentEv};
        let decl = |lo: i64, size: i64, name: &str, unit: &str| ExtentDecl { lo, least: size, size, name: name.into(), by: format!("src:{name}"),
                                                                             unit: unit.into(), kind: "bss".into() };
        let ev = |lo: i64, hi: i64, how: &str, to: i64| ExtentEv { lo, hi, base: lo, site: 0x51c99d, how: how.into(), to };
        let decls = [decl(0x76f920, 4, "net_Unk76f920", "ls"), decl(0x76f990, 4, "full_data_76f990", "main"), decl(0x76f994, 4, "full_data_76f994", "main"),
                     decl(0x60c7c0, 748, "net_Unk60c7c0", "cm"), decl(0x100, 16, "whole", "a"), decl(0x200, 8, "inner", "a"),
                     decl(0x300, 4, "gap_300", "main"), decl(0x304, 4, "gap_304", "main")];
        let evs = [ev(0x76f920, 0x76fa1c, "call", 0x51cee0), ev(0x76f920, 0x76f924, "field", 0), ev(0x60c7c0, 0x60cb00, "bound", 0),
                   ev(0x100, 0x110, "copy", 0), ev(0x1f8, 0x204, "copy", 0), ev(0x300, 0x308, "copy", 0)];
        let named = |a: i64| (a == 0x51cee0).then(|| "io_ReadHeader".to_string());
        let got = d8(&decls, &evs, named);
        let msgs: Vec<&str> = got.iter().map(|g| g.3.as_str()).collect();
        assert_eq!(got.iter().map(|g| (g.0, g.1, g.2, g.4.as_str())).collect::<Vec<_>>(),
                   [("error", 0x1f8, 0x204, "src:inner"), ("error", 0x300, 0x308, "src:gap_300"), ("error", 0x60c7c0, 0x60cb00, "src:net_Unk60c7c0"),
                    ("error", 0x76f920, 0x76fa1c, "src:net_Unk76f920")], "{msgs:?}");
        assert!(msgs[1].ends_with("(all of unit main, in order and without a hole: it links as the original's, but it is one object: declare one \
                                    object holding 0x300..0x308, the pieces inside as its fields, or as views of it with `@original` where a unit \
                                    needs another spelling; the range is what the accesses reach, a lower bound: a table's start and end follow \
                                    from its rows' stride)"), "{}", msgs[1]);
        let msgs = [msgs[0], msgs[2], msgs[3]];
        assert!(msgs[2].starts_with("net_Unk76f920 at 0x76f920 is 4 bytes, the original's code uses 0x76f920..0x76fa1c as one object (the address \
                                     0x76f920 passed at 0x51c99d to io_ReadHeader (0x51cee0), which reaches that far through it): \
                                     net_Unk76f920 needs at least 252 bytes; declared inside it: full_data_76f990 (+0x70), full_data_76f994 (+0x74)"),
                "{}", msgs[2]);
        assert!(msgs[1].contains("net_Unk60c7c0 needs at least 832 bytes") && !msgs[1].contains("declared inside"), "{}", msgs[1]);
        assert!(msgs[0].contains("which starts before inner: one declaration at 0x1f8 holds inner (0x200, 8 bytes)"), "{}", msgs[0]);
    }
}

#[cfg(test)]
mod tests_extent {
    use super::{data_extent, DataObj};
    use std::rc::Rc;

    /// No symbol of ours: the declared type's size, else up to the next definition (never one byte).
    #[test]
    fn data_extent_without_our_symbol() {
        let d = |v: serde_json::Value| DataObj {
            f: Rc::new(crate::store::Claim { id: 1, rule: Rc::from("L.src"), lo: 0x5ed1b0, hi: 0x5ed1b1, text: String::new(), value: v,
                                             support: crate::store::DECLARED, by: "src:a.c:1".into(), reason: None }),
            obj: None,
            sym: None,
        };
        assert_eq!(data_extent(&d(serde_json::json!({"size": 4})), 0x5ed1c0), (0x5ed1b0, 0x5ed1b4));
        assert_eq!(data_extent(&d(serde_json::json!({})), 0x5ed1bd), (0x5ed1b0, 0x5ed1bd));
    }
}

#[cfg(test)]
mod tests_room {
    /// D9's padding: a 1-byte char our object pads to 4 bytes, the original reading +1; the reference past the
    /// padding (another object's) and one inside the declared size are no hits; a definition without padding has none.
    #[test]
    fn references_into_a_definitions_padding() {
        let into: std::collections::BTreeMap<i64, Vec<i64>> = [(0x100, vec![0x10]), (0x101, vec![0x20, 0x30]), (0x104, vec![0x40]), (0x110, vec![0x50])]
            .into_iter().collect();
        let defs = [(0x100, 1, 4), (0x104, 4, 4), (0x108, 4, 0x10)];
        let starts = [0x100, 0x104, 0x108, 0x10c];
        let got = super::room_refs(&defs, &starts, &into);
        assert_eq!(got, [(0, 0x101, 0x104, vec![(0x101, vec![0x20, 0x30])])]);
    }
}
