//! `dcp asmdiff` and `dcp diffclass`: one graded function's reading as G.grade takes it (diffclass.rs: our
//! listing against the original's, the switch tables, the hunks and the verdict), for the commands to print.

use crate::diffclass::{self, Env, Hunk, Tables, Verdict};
use crate::project::Project;
use crate::store;
use crate::x86::Line;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use serde_json::Value;
use std::collections::{BTreeSet, HashSet};

/// A function's reading: its grade row, our listing, the original's, the tables compare, the hunks and the verdict.
pub struct Reading {
    pub row: Value,
    pub la: Vec<Line>,
    pub lb: Vec<Line>,
    pub tables: Option<Tables>,
    pub hunks: Vec<Hunk>,
    pub verdict: Verdict,
}

fn py_int0(s: &str) -> Option<i64> {
    let t = s.trim().to_lowercase();
    t.strip_prefix("0x").map(|h| i64::from_str_radix(h, 16).ok()).unwrap_or_else(|| t.parse().ok())
}

/// The function grade row named `key` (a function name or an address).
pub fn find_function(db: &str, key: &str) -> PyResult<Option<Value>> {
    let a = if key.to_lowercase().starts_with("0x") { py_int0(key) } else { None };
    Ok(crate::queues::function_grades(db)?.iter().cloned()
        .find(|r| r.get("name").and_then(|v| v.as_str()) == Some(key) || (a.is_some() && r["addr"].as_i64() == a))
        .map(Value::Object))
}

/// Every known function start (start facts, function and thunk symbols above open) and the end of every code
/// section: what bounds a function's slot.
pub fn all_starts(db: &str, img: &crate::pe::Image) -> PyResult<Vec<i64>> {
    let mut s: BTreeSet<i64> = crate::with_db(db, |c| store::facts_of(c, db, "start", None, |_| true))?.iter().map(|f| f.lo).collect();
    s.extend(crate::with_db(db, |c| store::facts_of(c, db, "symbol", None, |f| matches!(f.s("skind"), Some("func" | "thunk")) && f.level > store::OPEN))?
        .iter().map(|f| f.lo));
    s.extend(img.sections.iter().filter(|x| x.holds_code()).map(|x| x.end() as i64));
    Ok(s.into_iter().collect())
}

/// The reading of a graded function (its object's code against the original), or why there is none.
pub fn reading(p: &Project, capstone: &str, row: Value) -> Result<Result<Reading, String>, PyErr> {
    let db = p.store_path();
    let unit = row["unit"].as_str().unwrap_or("").to_string();
    let name = row["name"].as_str().unwrap_or("").to_string();
    let a = row["addr"].as_i64().unwrap_or(0);
    let tus = crate::compile::tu_rows(&db)?;
    let Some(t) = tus.get(&unit).filter(|t| t.ok) else { return Ok(Err(format!("unit {unit} has no object (dcp build)"))) };
    let root = p.root.to_string_lossy().into_owned();
    let obj = std::fs::read(crate::compile::obj_path(&root, &t.obj_hash)).ok().and_then(|d| crate::coff::Obj::parse(&d).ok());
    let Some((obj, k)) = obj.and_then(|o| o.function_index().get(&name).copied().map(|k| (o, k))) else {
        return Ok(Err(format!("the object of unit {unit} defines no {name}")));
    };
    let code = obj.function_code(k);
    let img = crate::image(&p.target(None).map_err(PyRuntimeError::new_err)?.path)?;
    let tc = crate::toolchain::of(&p.toolchain_key()).ok_or_else(|| PyRuntimeError::new_err("no toolchain"))?;
    let fill_forms: Vec<Vec<u8>> = tc.fill_forms().iter().map(|f| f.to_vec()).collect();
    let fills: HashSet<Vec<u8>> = fill_forms.iter().cloned().collect();
    let forms = crate::compare::fill_order(&fill_forms);
    let env = Env { dll: capstone, img: &img, range: (img.base as i64, img.end() as i64), fills: &fills, forms: &forms };
    let e = |s: String| PyRuntimeError::new_err(s);
    let d = &row["dist"];
    let (extent, slot) = match (d.get("extent").and_then(|v| v.as_i64()), d.get("slot").and_then(|v| v.as_i64())) {
        (Some(x), Some(s)) => (x, s),
        _ => {
            let walk = crate::with_db(&db, |c| store::facts_of(c, &db, "symbol", None, |f| {
                f.lo == a && matches!(&*f.rule, "S.codewalk" | "L.src.extent") && f.s("skind") == Some("func")
            }))?;
            let extent = match walk.first() {
                Some(w) => w.hi - w.lo,
                None => {
                    let (cd, cm) = code.code();
                    diffclass::code_size(&env, cd, cm, a as u32).map_err(e)?
                }
            };
            let st = all_starts(&db, &img)?;
            let nxt = st.get(st.partition_point(|&x| x <= a)).copied().unwrap_or(img.end() as i64);
            (extent, extent.max(nxt - a))
        }
    };
    let o = diffclass::original(&env, a as u32, extent, slot, tc.function_alignment() as i64).map_err(e)?;
    let (cd, cm) = code.code();
    let la = crate::x86::strip_fill(crate::x86::listing(env.dll, cd, a as u32, Some(cm), env.range, env.fills).map_err(e)?);
    let data = img.read(a as u32, o.code.max(0) as usize);
    let lb = crate::x86::strip_fill(crate::x86::listing(env.dll, &data, a as u32, None, env.range, env.fills).map_err(e)?);
    let tables = diffclass::compare_tables(&env, &obj, &code, a as u32, &la, &lb, &o.tables);
    let (hunks, verdict) = diffclass::analyse(&la, &lb, tables.as_ref());
    Ok(Ok(Reading { row, la, lb, tables, hunks, verdict }))
}

// ------------------------------------------------------------------------------------------------ Python's face
