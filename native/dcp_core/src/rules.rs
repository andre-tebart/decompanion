//! The native rules (docs/plan.md section 20). Each runs on the store directly: it reads the current facts of
//! its needed runs, builds its facts and conflicts and records its run, or (shadow) returns its out_hash only.
//! A rule here keeps its Python docstring as the criterion (`dcp rules` prints it); the code is this file.

use crate::compare::{compare, Compared};
use crate::store::{self, Out, SFact, DERIVED, OPEN};
use crate::{image, object, run_hash, with_conn, with_db, write_run};
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
    let refs = store::facts(db, &ctx.db, "ref", &ctx.needed).map_err(err)?;
    let mut relocs: Vec<u32> = refs.iter().filter(|f| f.s("rkind") == Some("reloc")).map(|f| f.lo as u32).collect();
    relocs.sort_unstable();
    let relocs = if relocs.is_empty() || img.relocations().is_empty() { None } else { Some(relocs) };
    // starts_of: start facts, function / thunk symbols above open, the end of every code section
    let mut starts: Vec<u32> = store::facts(db, &ctx.db, "start", &ctx.needed).map_err(err)?.iter().map(|f| f.lo as u32).collect();
    for f in store::facts(db, &ctx.db, "symbol", &ctx.needed).map_err(err)?.iter() {
        if matches!(f.s("skind"), Some("func") | Some("thunk")) && f.level > OPEN {
            starts.push(f.lo as u32);
        }
    }
    for s in img.sections.iter().filter(|s| s.holds_code()) {
        starts.push(s.end());
    }
    starts.sort_unstable();
    starts.dedup();
    let srcs: Vec<Rc<SFact>> = store::facts(db, &ctx.db, "source", &ctx.needed)
        .map_err(err)?
        .iter()
        .filter(|f| f.s("what") == Some("func") && &*f.rule == "L.src")
        .cloned()
        .collect();
    let (mut out, mut missing) = (vec![], vec![]);
    // C.objects: each compiled unit's object, read once per call (a file test per function costs ~20 us each)
    let mut objs: HashMap<String, Option<Rc<(crate::coff::Obj, HashMap<String, usize>)>>> = HashMap::new();
    for s in srcs {
        let unit = s.s("unit").unwrap_or("").to_string();
        let name = s.s("symbol").unwrap_or("").to_string();
        if !objs.contains_key(&unit) {
            let o = match ctx.objects.get(&unit) {
                Some((h, true)) if !h.is_empty() => {
                    let path = format!("{}/build/obj/{}.obj", ctx.root, h);
                    if std::path::Path::new(&path).exists() { Some(object(&path)?) } else { None }
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
        let c = compare(&img, &code, lo, relocs.as_deref(), next, &ctx.fill_forms);
        out.push(Compiled { src: s, c, code });
    }
    Ok((out, missing))
}

// ------------------------------------------------------------------------------------------------ the rules

/// M.draft (R2): a sourced function that is no byte match owns the code walk's extent of its start.
fn m_draft(ctx: &Ctx, db: &Connection, out: &mut Out) -> PyResult<()> {
    let (funcs, _) = compiled_functions(ctx, db)?;
    let mut walk: HashMap<i64, Rc<SFact>> = HashMap::new();
    for f in store::facts(db, &ctx.db, "symbol", &ctx.needed).map_err(|e| PyRuntimeError::new_err(e.to_string()))?.iter() {
        if f.s("skind") == Some("func") && &*f.rule == "S.codewalk" {
            walk.insert(f.lo, f.clone()); // a later fact of the same start wins, as the dict comprehension does
        }
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

/// Run a native rule: (facts, conflicts, out_hash); recorded unless ctx.record is false (shadow).
#[pyfunction]
pub fn run_rule(ctx: Ctx) -> PyResult<(usize, usize, String)> {
    let t0 = std::time::Instant::now();
    let mut out = Out::new(&ctx.rule, &ctx.version);
    with_conn(&ctx.db, |db| match ctx.rule.as_str() {
        "M.draft" => m_draft(&ctx, db, &mut out),
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
