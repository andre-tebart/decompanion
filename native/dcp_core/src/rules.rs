//! The native rules (docs/plan.md section 20). Each runs on the store directly: it reads the current facts of
//! its needed runs, builds its facts and conflicts and records its run, or (shadow) returns its out_hash only.
//! A rule here keeps its Python docstring as the criterion (`dcp rules` prints it); the code is this file.

use crate::compare::{compare, Compared};
use crate::store::{self, Out, SFact, DERIVED, OPEN};
use crate::{image, run_hash, with_conn, with_db, write_run};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use rusqlite::Connection;
use serde_json::json;
use std::collections::HashMap;
use std::rc::Rc;

/// What the engine hands a native rule (RuleContext's view, as plain data).
#[derive(FromPyObject)]
#[pyo3(from_item_all)]
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
    pub objects: HashMap<String, (String, bool)>, // unit -> (object hash, compiled ok)
    pub capstone: String,                           // the capstone library the Python package loaded
    pub record: bool,
    pub shortcuts: bool,
}

// ------------------------------------------------------------------------------------------------ compiled functions

/// One sourced function with its compiled code compared (match.compiled_functions' rows).
pub struct Compiled {
    pub src: Rc<SFact>,
    pub c: Compared,
    pub code: crate::coff::FunctionCode,
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
    // C.objects: each compiled unit's object, read once (not per function)
    let mut objs: HashMap<String, Option<crate::ObjIndex>> = HashMap::new();
    let current: std::collections::HashSet<String> = ctx
        .objects
        .values()
        .filter(|(h, ok)| *ok && !h.is_empty())
        .map(|(h, _)| format!("{}/build/obj/{}.obj", ctx.root, h))
        .collect();
    crate::live_objects(&current);
    for s in srcs {
        let unit = s.s("unit").unwrap_or("").to_string();
        let name = s.s("symbol").unwrap_or("").to_string();
        if !objs.contains_key(&unit) {
            let o = match ctx.objects.get(&unit) {
                Some((h, true)) if !h.is_empty() => {
                    let path = format!("{}/build/obj/{}.obj", ctx.root, h);
                    crate::object_if(&path)?
                }
                _ => None,
            };
            objs.insert(unit.clone(), o);
        }
        let obj = objs[&unit].clone();
        let Some(obj) = obj else {
            let why = if ctx.objects.contains_key(&unit) { "failed to compile" } else { "is not compiled (dcp build)" };
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
        let code = obj.0.function_code(k);
        let c = compare(&img, &code, lo, relocs.as_deref(), next, &forms);
        out.push(Compiled { src: s, c, code });
    }
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

/// Run a native rule: (facts, conflicts, out_hash); recorded unless ctx.record is false (shadow).
#[pyfunction]
pub fn run_rule(ctx: Ctx) -> PyResult<(usize, usize, String)> {
    let t0 = std::time::Instant::now();
    let mut out = Out::new(&ctx.rule, &ctx.version);
    with_conn(&ctx.db, |db| match ctx.rule.as_str() {
        "M.draft" => m_draft(&ctx, db, &mut out),
        "M.match" => m_match(&ctx, db, &mut out),
        other => Err(PyRuntimeError::new_err(format!("no native rule {other}"))),
    })?;
    let ms = t0.elapsed().as_millis() as i64;
    let (rows, confl) = out.sorted();
    let (nf, nc) = (rows.len(), confl.len());
    if !ctx.record {
        return Ok((nf, nc, run_hash(&rows, &confl)));
    }
    let (_, h) = with_db(&ctx.db, |db| {
        write_run(db, &ctx.rule, &ctx.version, &ctx.code_hash, &ctx.input_hash, &rows, &confl, ms, ctx.shortcuts)
    })?;
    Ok((nf, nc, h))
}
