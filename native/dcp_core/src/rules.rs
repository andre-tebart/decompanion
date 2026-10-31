//! The native rules (docs/plan.md section 20). Each runs on the store directly: it reads the current facts of
//! its needed runs, builds its facts and conflicts and records its run, or (shadow) returns its out_hash only.
//! A rule here keeps its Python docstring as the criterion (`dcp rules` prints it); the code is this file.

use crate::compare::{compare, Compared};
use crate::store::{self, Out, SFact, DECLARED, DERIVED, OPEN};
use crate::{image, run_hash, with_conn, with_db, write_run};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
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
    pub main: String, // a worktree's main store (a read-only file: URI), '' outside one
    pub needed: Vec<String>,
    pub root: String,
    pub image: String,
    pub fill_forms: Vec<Vec<u8>>,
    pub capstone: String,                           // the capstone library the Python package loaded
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
    pub toolchain: String,
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
    pub src: Rc<SFact>,
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
pub fn objects(db: &Connection) -> PyResult<HashMap<String, (String, bool)>> {
    let err = |e: rusqlite::Error| PyRuntimeError::new_err(e.to_string());
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

/// match.compiled_functions: every L.src function source of the current target whose unit compiled and whose
/// object defines it, compared with the image (sorted by address); the others as (source, why).
pub fn compiled_functions(ctx: &Ctx, db: &Connection) -> PyResult<(Vec<Compiled>, Vec<(Rc<SFact>, String)>)> {
    let err = |e: rusqlite::Error| PyRuntimeError::new_err(format!("{}: {e}", ctx.db));
    let img = image(&ctx.image)?;
    // the relocation sites only for an image that has base relocations (Python reads them, then drops them)
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
        store::los(db, &ctx.db, "symbol", &ctx.needed, |f| matches!(f.s("skind"), Some("func") | Some("thunk")) && f.level > OPEN)
            .map_err(err)?
            .into_iter()
            .map(|x| x as u32),
    );
    for s in img.sections.iter().filter(|s| s.holds_code()) {
        starts.push(s.end());
    }
    starts.sort_unstable();
    starts.dedup();
    let srcs = store::facts(db, &ctx.db, "source", &ctx.needed, |f| &*f.rule == "L.src" && f.s("what") == Some("func"))
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
            missing.push((s, format!("no object: the unit {why}")));
            continue;
        };
        let Some(&k) = obj.1.get(&name) else {
            missing.push((s, format!("the object of unit {unit} defines no function {name}")));
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
fn m_draft(ctx: &Ctx, db: &Connection, out: &mut Out) -> PyResult<()> {
    let (funcs, _) = compiled_functions(ctx, db)?;
    let mut walk: HashMap<i64, Rc<SFact>> = HashMap::new();
    let keep = |f: &SFact| &*f.rule == "S.codewalk" && f.s("skind") == Some("func");
    for f in store::facts(db, &ctx.db, "symbol", &ctx.needed, keep).map_err(|e| PyRuntimeError::new_err(e.to_string()))? {
        walk.insert(f.lo, f); // a later fact of the same start wins, as the dict comprehension does
    }
    for x in &funcs {
        if x.c.matched() {
            continue;
        }
        let Some(w) = walk.get(&x.src.lo) else { continue };
        let v = json!({"file": x.src.value["file"], "unit": x.src.value["unit"], "symbol": x.src.value["symbol"],
                       "what": "draft", "why": x.c.why()});
        out.fact(x.src.lo, w.hi, "source", v, w.level.min(x.src.level).min(DERIVED));
    }
    Ok(())
}

/// The end of the last instruction of a matched function's code that is no fill form (0 when every one is fill),
/// as isa.listing gives it: the code decoded with each relocated field holding the image base (the base's bytes
/// repeated over a masked run), each instruction's fill test on its own bytes.
fn last_code_end(ctx: &Ctx, base: u32, code: &[u8], mask: &[u8], va: u32, forms: &[Vec<u8>]) -> PyResult<u32> {
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
    let lines = crate::cs::lengths(&ctx.capstone, &data, va).map_err(PyRuntimeError::new_err)?;
    let fill = |&(addr, size): &(u32, u32)| {
        let o = (addr - va) as usize;
        let b = &code[o..(o + size as usize).min(code.len())];
        forms.iter().any(|f| f.as_slice() == b)
    };
    let mut n = lines.len();
    while n > 0 && fill(&lines[n - 1]) {
        n -= 1;
    }
    Ok(if n == 0 { 0 } else { lines[n - 1].0 + lines[n - 1].1 })
}

/// M.match (R1): a sourced function whose compiled function is a byte match owns its bytes: a `symbol` func to
/// the end of its last instruction that is no fill (or its first jump / index table), a `source` (what: match)
/// over the whole section.
fn m_match(ctx: &Ctx, db: &Connection, out: &mut Out) -> PyResult<()> {
    let (funcs, _) = compiled_functions(ctx, db)?;
    let img = image(&ctx.image)?;
    let keep = |f: &SFact| matches!(f.s("skind"), Some("jumptable") | Some("idxtable"));
    let mut tables: Vec<(i64, Option<i64>)> = store::facts(db, &ctx.db, "symbol", &ctx.needed, keep)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?
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
        let last = last_code_end(ctx, img.base, &x.code.data[..n], &x.code.mask[..n.min(x.code.mask.len())], a as u32, &forms)?;
        if last != 0 {
            code_end = code_end.min(last as i64);
        }
        let aid = match x.c.abs_image {
            None => "-".to_string(),
            Some(m) => format!("{}/{}", x.c.abs_ours, m),
        };
        let v = x.src.value.clone();
        out.fact(a, code_end, "symbol", json!({"skind": "func", "extent": "matched", "name": v["symbol"], "unit": v["unit"],
                                              "file": v["file"], "relocs": aid}), crate::store::PROVEN);
        out.fact(a, end, "source", json!({"file": v["file"], "unit": v["unit"], "symbol": v["symbol"], "what": "match",
                                          "relocs": aid}), crate::store::PROVEN);
    }
    Ok(())
}

/// Python's repr of a bytes object: b'..' (b".." when it holds ' and no "), \\ \t \n \r and the quote escaped,
/// printable ASCII as is, every other byte \xhh.
fn py_bytes(b: &[u8]) -> String {
    let q = if b.contains(&b'\'') && !b.contains(&b'"') { b'"' } else { b'\'' };
    let mut s = String::from("b");
    s.push(q as char);
    for &c in b {
        match c {
            b'\\' => s.push_str("\\\\"),
            b'\t' => s.push_str("\\t"),
            b'\n' => s.push_str("\\n"),
            b'\r' => s.push_str("\\r"),
            _ if c == q => {
                s.push('\\');
                s.push(c as char);
            }
            0x20..=0x7e => s.push(c as char),
            _ => s.push_str(&format!("\\x{:02x}", c)),
        }
    }
    s.push(q as char);
    s
}

fn latin1(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

/// compare.aligned_sites: the offsets of `sites` ((offset, width) of our relocated fields) whose instruction
/// starts at the same offset with the same size on both sides and agrees in every unmasked byte (all of them for
/// a match).
pub fn aligned_sites(dll: &str, ours: &[u8], mask: &[u8], orig: &[u8], va: u32, matched: bool, sites: &[(u32, u32)])
    -> Result<std::collections::HashSet<u32>, String> {
    if matched {
        return Ok(sites.iter().map(|s| s.0).collect());
    }
    let lines = crate::cs::lengths(dll, ours, va)?;
    let theirs: HashMap<u32, u32> = crate::cs::lengths(dll, orig, va)?.into_iter().map(|(a, n)| (a - va, n)).collect();
    let starts: Vec<u32> = lines.iter().map(|l| l.0 - va).collect();
    let mut out = std::collections::HashSet::new();
    for &(off, width) in sites {
        let i = starts.partition_point(|&s| s <= off);
        if i == 0 {
            continue;
        }
        let (o, n) = (starts[i - 1], lines[i - 1].1);
        if off + width > o + n || theirs.get(&o) != Some(&n) {
            continue;
        }
        if (o..o + n).all(|k| {
            let k = k as usize;
            mask.get(k).copied().unwrap_or(0) != 0 || ours.get(k) == orig.get(k)
        }) {
            out.insert(off);
        }
    }
    Ok(out)
}

/// aligned_sites for Python (tests/test_match.py).
#[pyfunction]
#[pyo3(name = "aligned_sites")]
pub fn py_aligned_sites(dll: &str, ours: Vec<u8>, mask: Vec<u8>, orig: Vec<u8>, va: u32, matched: bool, sites: Vec<(u32, u32)>)
    -> PyResult<std::collections::HashSet<u32>> {
    aligned_sites(dll, &ours, &mask, &orig, va, matched, &sites).map_err(PyRuntimeError::new_err)
}

/// M8 / M9 / M10 (M8.reloc): each relocation of ours whose site lines up with the original's code, resolved against
/// the image: a registered symbol the original's site does not refer to (M8), a literal or a floating constant
/// whose bytes the original does not hold there (M9 / M10).
fn m8_reloc(ctx: &Ctx, db: &Connection, out: &mut Out) -> PyResult<()> {
    let err = |e: rusqlite::Error| PyRuntimeError::new_err(format!("{}: {e}", ctx.db));
    let img = image(&ctx.image)?;
    let (funcs, _) = compiled_functions(ctx, db)?;
    let (by_name, by_addr) = name_registry(ctx, db)?;
    for x in &funcs {
        if !(x.c.matched() || (x.c.abs_image.is_some() && x.c.aid_ok())) {
            continue;
        }
        let va = x.src.lo as u32;
        let orig = img.bytes(va, x.code.data.len());
        let sites: Vec<(u32, u32)> = x.code.relocs.iter().map(|(off, r)| (*off, r.kind_width().1)).collect();
        let aligned = aligned_sites(&ctx.capstone, &x.code.data, &x.code.mask, &orig, va, x.c.matched(), &sites)
            .map_err(PyRuntimeError::new_err)?;
        let (obj, _) = &*x.obj;
        let symbol = x.src.s("symbol").unwrap_or("");
        let unit = x.src.s("unit").unwrap_or("");
        for (off, r) in &x.code.relocs {
            let Some(target) = obj.symbol_at(r.symbol_index) else { continue };
            let (kind, width) = r.kind_width();
            if !(kind == crate::coff::ABSOLUTE || kind == crate::coff::RELATIVE) || !aligned.contains(off) {
                continue;
            }
            let site = va.wrapping_add(*off);
            let Some(to) = r.resolve(site, &img.bytes(site, width as usize), obj.addend(x.code.secnum, r)) else { continue };
            let k = target.constant();
            let tsec = if target.secnum > 0 { obj.sections.get(target.secnum as usize) } else { None };
            if let (Some(k), Some(data)) = (k, tsec.and_then(|s| s.data.as_ref())) {
                let mut lit: &[u8] = data.get(target.value as usize..).unwrap_or(&[]);
                if k == "string" {
                    if let Some(z) = lit.iter().position(|&c| c == 0) {
                        lit = &lit[..z + 1];
                    }
                }
                let have = img.bytes(to, lit.len());
                if *have != *lit {
                    let mut hint = String::new();
                    let body = latin1(&lit[..lit.len().saturating_sub(1)]).replace('\\', "/");
                    if k == "string" && body.starts_with(&format!("src/{unit}/")) {
                        let z = img.bytes(to, 260);
                        let z = latin1(z.split(|&c| c == 0).next().unwrap_or(&[]));
                        hint = format!("; the unit's original file name? dcp decl add \"{:#010x} file tu={unit} path={z} -- ...\"", to);
                    }
                    let what = if k == "string" { "literal" } else { "constant" };
                    let msg = format!("{symbol} at {:#x}: our {what} {} differs from the original's bytes {} at {:#x}{hint}",
                                      x.src.lo, py_bytes(&lit[..lit.len().min(40)]), py_bytes(&have[..have.len().min(40)]), to);
                    out.conflict("error", if k == "string" { "M9" } else { "M10" }, site as i64, (site + width) as i64, msg, &x.src.by);
                }
                continue;
            }
            if !target.named() || k.is_some() {
                continue;
            }
            let linker = target.name.strip_prefix("__imp_").unwrap_or(&target.name);
            let cname = crate::coff::undecorate(linker);
            let Some(regs) = by_name.get(&cname) else { continue };
            if regs.is_empty() || regs.contains_key(&(to as i64)) {
                continue;
            }
            let (b, lvl) = regs.iter().next().unwrap();
            let others = by_addr.get(&(to as i64)).map(|s| s.iter().cloned().collect::<Vec<_>>().join(", "));
            let others = match others {
                Some(o) if !o.is_empty() => o,
                _ => "nothing registered".to_string(),
            };
            let sev = if *lvl == crate::store::PROVEN { "bug" } else { "error" };
            let msg = format!("{symbol} at {:#x}: our object references {cname} (registered at {:#x}) where the original's site \
                               refers to {:#x} ({others})", x.src.lo, b, to);
            out.conflict(sev, "M8", site as i64, (site + width) as i64, msg, &x.src.by);
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
fn m_lint(ctx: &Ctx, db: &Connection, out: &mut Out) -> PyResult<()> {
    let err = |e: rusqlite::Error| PyRuntimeError::new_err(format!("{}: {e}", ctx.db));
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
    for f in store::facts(db, &ctx.db, "source", &ctx.needed, |f| f.s("what") == Some("func")).map_err(err)?.iter() {
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
            out.conflict("error", check, a, a + 1, e, "");
        }
    }
    if let Some(calls) = res.get("calls").and_then(|c| c.as_object()) {
        for (f, cs) in calls {
            for c in cs.as_array().into_iter().flatten() {
                let line = c.get(0).and_then(|v| v.as_i64());
                let text = c.get(1).and_then(|v| v.as_str()).unwrap_or("");
                let a = at(Some(f), line);
                out.conflict("warn", "M7", a, a + 1, format!("{f}: call without a prototype: {text}"), "");
            }
        }
    }
    let parsed = res.get("units").and_then(|u| u.as_object());
    let mut stale: Vec<&String> = ctx.inputs.units.iter()
        .filter(|(u, h)| parsed.and_then(|p| p.get(*u)).and_then(|v| v.as_str()) != Some(h.as_str())).map(|(u, _)| u).collect();
    stale.sort();
    if !stale.is_empty() {
        let names: Vec<&str> = stale.iter().map(|s| s.as_str()).collect();
        out.conflict("warn", "M.lint", base, base + 1,
                     format!("the last lint did not parse today's text of: {} (dcp lint)", names.join(", ")), "");
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ data rules

type Registry = (HashMap<String, std::collections::BTreeMap<i64, i64>>, HashMap<i64, std::collections::BTreeSet<String>>);

/// match.name_registry: C name -> {address: the producer's best level}, address -> {C names}.
fn name_registry(ctx: &Ctx, db: &Connection) -> PyResult<Registry> {
    let err = |e: rusqlite::Error| PyRuntimeError::new_err(format!("{}: {e}", ctx.db));
    let mut by_name: HashMap<String, std::collections::BTreeMap<i64, i64>> = HashMap::new();
    let mut by_addr: HashMap<i64, std::collections::BTreeSet<String>> = HashMap::new();
    for f in store::facts(db, &ctx.db, "name", &ctx.needed, |_| true).map_err(err)?.iter() {
        let raw = f.s("name").unwrap_or("");
        let origin = f.s("origin");
        for n in raw.split('|') {
            let n = match origin {
                Some("import") => n.split_once('!').map(|x| x.1).unwrap_or(n).to_string(),
                Some("lib") => crate::coff::undecorate(n),
                _ => n.to_string(),
            };
            let e = by_name.entry(n.clone()).or_default().entry(f.lo).or_insert(OPEN);
            *e = (*e).max(f.level);
            by_addr.entry(f.lo).or_default().insert(n);
        }
    }
    Ok((by_name, by_addr))
}

/// One data definition of the sources with an address (match_data.data_objects): its L.src fact, its unit's
/// object and the data symbol of its C name there (kind, size).
struct DataObj {
    f: Rc<SFact>,
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

fn data_objects(ctx: &Ctx, db: &Connection) -> PyResult<Vec<DataObj>> {
    let err = |e: rusqlite::Error| PyRuntimeError::new_err(format!("{}: {e}", ctx.db));
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
    let mut fs: Vec<Rc<SFact>> = store::facts(db, &ctx.db, "source", &ctx.needed, |f| &*f.rule == "L.src" && f.s("what") == Some("data"))
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

#[pyfunction]
#[pyo3(name = "least_size")]
pub fn py_least_size(value: Option<u32>, size: u32) -> u32 {
    least(value, size)
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

#[pyfunction]
#[pyo3(name = "padding_masked")]
pub fn py_padding_masked(data: Vec<u8>, mask: Vec<u8>, least: usize) -> Vec<u8> {
    padding_masked(&data, &mask, least)
}

/// The least size of a data definition (None without a size).
fn least_size(d: &DataObj) -> Option<u32> {
    Some(least(d.symbol().map(|s| s.value), d.size()?))
}

/// match_data.extent: [address, address + least size) (one byte without a size).
fn data_extent(d: &DataObj) -> (i64, i64) {
    let n = least_size(d).unwrap_or(0).max(1);
    (d.f.lo, d.f.lo + n as i64)
}

/// match_data.site_confirmed: address -> C name of every data address a byte-matched function's absolute
/// relocation confirms (the first such relocation wins).
fn site_confirmed(ctx: &Ctx, db: &Connection) -> PyResult<HashMap<u32, String>> {
    let img = image(&ctx.image)?;
    let (funcs, _) = compiled_functions(ctx, db)?;
    let mut out = HashMap::new();
    for x in &funcs {
        if !x.c.matched() {
            continue;
        }
        let obj = &x.obj.0;
        for (off, r) in &x.code.relocs {
            let Some(t) = obj.symbol_at(r.symbol_index) else { continue };
            let (kind, width) = r.kind_width();
            if !t.named() || t.function() || t.constant().is_some() || t.name.starts_with("__imp_") || kind != crate::coff::ABSOLUTE {
                continue;
            }
            let site = (x.src.lo as u32).wrapping_add(*off);
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
fn m_data_site(ctx: &Ctx, db: &Connection, out: &mut Out) -> PyResult<()> {
    let confirmed = site_confirmed(ctx, db)?;
    for d in data_objects(ctx, db)? {
        if confirmed.get(&(d.f.lo as u32)).map(|s| s.as_str()) == d.f.s("symbol") {
            let (lo, hi) = data_extent(&d);
            out.fact(lo, hi, "symbol", global(&d, "site", d.kind().unwrap_or("-")), crate::store::PROVEN);
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
fn m_data_content(ctx: &Ctx, db: &Connection, out: &mut Out) -> PyResult<()> {
    let img = image(&ctx.image)?;
    let confirmed = site_confirmed(ctx, db)?;
    for d in data_objects(ctx, db)? {
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
        let mask = padding_masked(data, &full[a.min(full.len())..b.min(full.len())], least_size(&d).unwrap_or(0) as usize);
        let unmasked: Vec<usize> = (0..data.len()).filter(|&k| mask.get(k).copied().unwrap_or(0) == 0).collect();
        if unmasked.len() < 4 || !unmasked.iter().any(|&k| data[k] != 0) {
            continue;
        }
        let hits = content_hits(&img, data, &mask);
        if hits.len() == 1 && hits[0] as i64 == d.f.lo {
            let (lo, hi) = data_extent(&d);
            out.fact(lo, hi, "symbol", global(&d, "content", kind), crate::store::PROVEN);
        } else if hits.len() == 1 && !masked_equal(&img, d.f.lo as u32, data, &mask) {
            out.conflict("error", "M.data.content", d.f.lo, d.f.lo + 1,
                         format!("{}: its bytes occur once in the image, at {:#x}, not at the declared {:#x}",
                                 d.f.s("symbol").unwrap_or(""), hits[0], d.f.lo), &d.f.by);
        }
    }
    Ok(())
}

/// M.data.draft: every other data definition with an address owns its declared extent.
fn m_data_draft(ctx: &Ctx, db: &Connection, out: &mut Out) -> PyResult<()> {
    let err = |e: rusqlite::Error| PyRuntimeError::new_err(format!("{}: {e}", ctx.db));
    let placed: std::collections::HashSet<i64> =
        store::los(db, &ctx.db, "symbol", &ctx.needed, |_| true).map_err(err)?.into_iter().collect();
    for d in data_objects(ctx, db)? {
        if placed.contains(&d.f.lo) {
            continue;
        }
        let (lo, hi) = data_extent(&d);
        out.fact(lo, hi, "symbol", global(&d, "draft", d.kind().unwrap_or("-")), DECLARED);
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

/// D1 / D4 / D5 / D6 (D.data).
fn d_data(ctx: &Ctx, db: &Connection, out: &mut Out) -> PyResult<()> {
    let err = |e: rusqlite::Error| PyRuntimeError::new_err(format!("{}: {e}", ctx.db));
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
                        out.conflict("error", "D1", d.f.lo, d.f.lo + size as i64,
                                     format!("{name} at {:#x} ({least} bytes at least) overlaps the symbol at {:#x}", d.f.lo, starts[i]),
                                     &d.f.by);
                    } else {
                        out.conflict("warn", "D1", d.f.lo, d.f.lo + size as i64,
                                     format!("{name} at {:#x}: the object gives it {size} bytes, the symbol at {:#x} leaves {room}; fine if \
                                              the last {} are alignment padding", d.f.lo, starts[i], size as i64 - room), &d.f.by);
                    }
                }
            }
        }
        if d.symbol().map(|s| s.common()).unwrap_or(false) {
            let va = d.f.lo as u32;
            if img.section_of(va).is_some() && img.off(va).is_none() {
                out.conflict("error", "D5", d.f.lo, d.f.lo + 1,
                             format!("{name} at {:#x} lies in uninitialised data and is a tentative definition: write it `= 0` so \
                                      it is placed with its unit", d.f.lo), &d.f.by);
            }
        }
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
                out.conflict2("error", "D4", b.f.lo, b.f.lo + 1,
                              format!("unit {unit} ({kind}): {} ({:#x}) is defined after {} ({:#x}) but lies before it",
                                      b.f.s("symbol").unwrap_or(""), b.f.lo, a.f.s("symbol").unwrap_or(""), a.f.lo),
                              &b.f.by, &a.f.by);
            }
        }
    }
    // D6: pointer-table entries
    let (by_name, by_addr) = name_registry(ctx, db)?;
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
            let Some(regs) = by_name.get(&cname) else { continue };
            if regs.is_empty() || regs.contains_key(&(to as i64)) {
                continue;
            }
            let (b, lvl) = regs.iter().next().unwrap();
            let others = by_addr.get(&(to as i64)).map(|s| s.iter().cloned().collect::<Vec<_>>().join(", ")).unwrap_or_default();
            let others = if others.is_empty() { "nothing registered".to_string() } else { others };
            out.conflict(if *lvl == crate::store::PROVEN { "bug" } else { "error" }, "D6", site as i64, (site + width) as i64,
                         format!("{} +{:#x}: our entry refers to {cname} (registered at {:#x}), the original's to {:#x} ({others})",
                                 d.f.s("symbol").unwrap_or(""), r.offset - sym.value, b, to), &d.f.by);
        }
    }
    Ok(())
}

/// A native rule's output (its facts and conflicts, unsorted).
pub(crate) fn dispatch(ctx: &Ctx) -> PyResult<Out> {
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
        "S5.crt.gaps" => crate::setup::s5_crt_gaps(ctx, db, &mut out),
        "S.entry.user" => crate::setup::s_entry_user(ctx, db, &mut out),
        "S.strings" => crate::setup::s_strings(ctx, db, &mut out),
        "S.fill" => crate::setup::s_fill(ctx, db, &mut out),
        "S.unknown" => crate::setup::s_unknown(ctx, db, &mut out),
        "L.decl" => crate::decl::l_decl(ctx, db, &mut out),
        "S.codewalk" => crate::walk::s_codewalk(ctx, db, &mut out),
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
        "M8.reloc" => m8_reloc(ctx, db, &mut out),
        "M.lint" => m_lint(ctx, db, &mut out),
        "M.data.site" => m_data_site(ctx, db, &mut out),
        "M.data.content" => m_data_content(ctx, db, &mut out),
        "M.data.draft" => m_data_draft(ctx, db, &mut out),
        "D.data" => d_data(ctx, db, &mut out),
        "L9.analyzer.span" => crate::layout::l9_analyzer_span(ctx, db, &mut out),
        "L.src.extent" => crate::layout::l_src_extent(ctx, db, &mut out),
        "L5.placeholder" => crate::layout::l5_placeholder(ctx, db, &mut out),
        "A1.addr.cast" => crate::layout::a1_addr_cast(ctx, db, &mut out),
        "L13.data.code" => crate::layout::l13_data_code(ctx, db, &mut out),
        "L.unit.extent" => crate::layout::l_unit_extent(ctx, db, &mut out),
        "M1.baseline" => crate::layout::m1_baseline(ctx, db, &mut out),
        "G.grade" => crate::grade::g_grade(ctx, db, &mut out),
        "L1.src.start" => crate::layout::l1_src_start(ctx, db, &mut out),
        "L.src" => crate::layout::l_src(ctx, db, &mut out),
        "L4.boundary" => crate::layout::l4_boundary(ctx, db, &mut out),
        "L10.unexplained" => crate::layout::l10_unexplained(ctx, db, &mut out),
        "L14.unit.outside" => crate::layout::l14_unit_outside(ctx, db, &mut out),
        other => Err(PyRuntimeError::new_err(format!("no native rule {other}"))),
    })?;
    Ok(out)
}

// ------------------------------------------------------------------------------------------------ test kit

#[cfg(test)]
pub(crate) mod testkit {
    //! A store in a temporary directory with an image beside it; rules run on it as the engine runs them.
    use super::*;
    use crate::{ConflictRow, Row};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static N: AtomicUsize = AtomicUsize::new(0);

    /// The declaration a test's toy rule name runs under (every output, any level).
    pub static TEST_RULE: crate::registry::RuleDef = crate::registry::RuleDef {
        id: "T", version: "1", ceiling: 3, phase: "T", loader: true, python: false, needs: &[], outputs: &[
            "section", "region", "symbol", "start", "name", "source", "unit", "boundary", "toolchain", "ref", "grade", "build", "evidence"],
        inputs: &[], doc: "",
    };

    pub struct Kit {
        pub dir: std::path::PathBuf,
        pub db: String,
        pub image: String,
    }

    impl Kit {
        pub fn new(image: &[u8]) -> Kit {
            let dir = std::env::temp_dir().join(format!("dcp-test-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
            std::fs::create_dir_all(&dir).unwrap();
            let img = dir.join("image.dll");
            std::fs::write(&img, image).unwrap();
            let db = dir.join("store.sqlite");
            let c = Connection::open(&db).unwrap();
            c.execute_batch(crate::store::SCHEMA).unwrap();
            Kit { db: db.to_string_lossy().into_owned(), image: img.to_string_lossy().into_owned(), dir }
        }

        pub fn ctx(&self, rule: &str, needed: &[&str], extra: &str) -> Ctx {
            Ctx { rule: rule.into(), version: "1".into(), code_hash: "test".into(), input_hash: format!("test:{rule}"), db: self.db.clone(),
                  main: String::new(), needed: needed.iter().map(|s| s.to_string()).collect(), root: self.dir.to_string_lossy().into_owned(),
                  image: self.image.clone(), fill_forms: vec![vec![0x90], vec![0xcc], vec![0x8b, 0xff], vec![0x8d, 0x49, 0x00]],
                  capstone: String::new(), record: true, shortcuts: true, inputs: Rc::new(Inputs::of(extra)) }
        }

        /// A rule's output, sorted as recorded.
        pub fn run(&self, rule: &str, needed: &[&str], extra: &str) -> (Vec<Row>, Vec<ConflictRow>) {
            dispatch(&self.ctx(rule, needed, extra)).unwrap().sorted()
        }

        /// Run and record a rule (the rules that need it read its facts).
        pub fn record(&self, rule: &str, needed: &[&str], extra: &str) {
            crate::engine::run_native(crate::engine::rule(rule).unwrap_or(&TEST_RULE), &self.ctx(rule, needed, extra)).unwrap();
        }

        /// Record a run of these facts (lo, hi, kind, value, level) under a rule's name, `by` its producer.
        pub fn put(&self, rule: &str, facts: &[(i64, i64, &str, serde_json::Value, i64)]) {
            let mut out = Out::new(rule, "1");
            for (lo, hi, kind, v, level) in facts {
                out.fact(*lo, *hi, kind, v.clone(), *level);
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
    pub fn of(rows: &[Row], kind: &str) -> Vec<(i64, i64, serde_json::Value)> {
        rows.iter().filter(|r| r.kind == kind).map(|r| (r.lo, r.hi, serde_json::from_str(&r.value).unwrap())).collect()
    }
}
