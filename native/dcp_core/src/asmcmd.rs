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
    /// the texts of la and lb with names for X (reading's `names`): our relocations' symbols, the ledger's labels
    pub named: Option<(Vec<String>, Vec<String>)>,
}

/// How an address of the original reads by name (`asmdiff --symbols`): a number inside the function's slot `own`
/// (a jump of its own) as the number, else the ledger's label (dcp disasm's), else the printable C string the
/// image holds there, else the number.
fn label(names: &crate::names::Names, img: &crate::pe::Image, own: (i64, i64), v: i64) -> String {
    if own.0 <= v && v < own.1 {
        return format!("{v:#x}");
    }
    if let Ok(Some(l)) = names.label_of(v) {
        return l;
    }
    let s = img.cstr_n(v as u32, 256);
    if s.len() >= 2 && s.len() < 256 && s.iter().all(|&c| (0x20..0x7f).contains(&c) || c == b'\t' || c == b'\n') {
        let t: String = s.iter().take(40).map(|&c| c as char).collect();
        return format!("\"{}\"", t.replace('\n', "\\n"));
    }
    format!("{v:#x}")
}

/// How our relocated field (at `off` of the function at `a`) reads by name: what the original's field refers to
/// (label) when that is our symbol (the ledger registers its C name there) or our literal's bytes (M8 / M9 hold);
/// else our symbol (a string literal as its text), `+off` for an addend.
#[allow(clippy::too_many_arguments)]
fn reloc_name(obj: &crate::coff::Obj, code: &crate::coff::FunctionCode, r: &crate::coff::Reloc, a: u32, off: u32,
              img: &crate::pe::Image, names: &crate::names::Names, own: (i64, i64)) -> String {
    let Some(sym) = obj.symbol_at(r.symbol_index) else { return "?".into() };
    let addend = obj.addend(code.secnum, r);
    let site = a.wrapping_add(off);
    let to = r.resolve(site, &img.bytes(site, r.kind_width().1 as usize), addend).filter(|&t| img.in_image(t));
    let theirs = |t: u32| label(names, img, own, t.wrapping_add(addend) as i64);
    let data = if sym.secnum > 0 { obj.sections.get(sym.secnum as usize).and_then(|s| s.data.as_ref()) } else { None };
    let base = match (sym.constant(), data) {
        (Some("string"), Some(d)) => {
            let lit = d.get(sym.value as usize..).unwrap_or(&[]);
            let lit = &lit[..lit.iter().position(|&c| c == 0).map(|z| z + 1).unwrap_or(lit.len())];
            if let Some(t) = to.filter(|&t| *img.bytes(t, lit.len()) == *lit) {
                return theirs(t);
            }
            let t: String = lit.iter().take_while(|&&c| c != 0).take(40).map(|&c| match c {
                b'\n' => "\\n".to_string(),
                0x20..=0x7e => (c as char).to_string(),
                _ => format!("\\x{c:02x}"),
            }).collect();
            format!("\"{t}\"")
        }
        _ => {
            let cname = crate::coff::undecorate(sym.name.strip_prefix("__imp_").unwrap_or(&sym.name));
            if let Some(t) = to.filter(|&t| names.by_name.iter().any(|(n, at)| *n == cname && at.contains(&(t as i64)))) {
                return theirs(t);
            }
            crate::coff::undecorate(&sym.name)
        }
    };
    match addend as i32 {
        0 => base,
        n => format!("{base}{}{:#x}", if n < 0 { "-" } else { "+" }, n.unsigned_abs()),
    }
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

/// The reading of a graded function (its object's code against the original), or why there is none; with `names`,
/// the texts with names for X too.
pub fn reading(p: &Project, capstone: &str, row: Value, names: Option<&crate::names::Names>) -> Result<Result<Reading, String>, PyErr> {
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
    let named = match names {
        None => None,
        Some(names) => {
            // the same listings (strip_fill drops trailing lines only): ours by the relocations inside each
            // instruction in offset order, the original's by the ledger; a number inside the function's slot (a
            // jump of its own) stays a number on both sides
            let own = (a, a + slot);
            let ours = |ins: u32, k: Option<usize>, v: i64| -> Option<String> {
                let o = ins - a as u32;
                let size = la.iter().find(|l| l.addr == ins).map(|l| l.size).unwrap_or(0);
                match k {
                    Some(k) => code.relocs.iter().filter(|(off, _)| o <= *off && *off < o + size).nth(k)
                        .map(|(off, r)| reloc_name(&obj, &code, r, a as u32, *off, &img, names, own)),
                    None => Some(label(names, &img, own, v)),
                }
            };
            let theirs = |_: u32, _: Option<usize>, v: i64| -> Option<String> {
                Some(label(names, &img, own, v))
            };
            let na = crate::x86::listing_named(env.dll, cd, a as u32, Some(cm), env.range, env.fills, &ours).map_err(e)?;
            let nb = crate::x86::listing_named(env.dll, &data, a as u32, None, env.range, env.fills, &theirs).map_err(e)?;
            Some((na.into_iter().take(la.len()).map(|l| l.text).collect(), nb.into_iter().take(lb.len()).map(|l| l.text).collect()))
        }
    };
    Ok(Ok(Reading { row, la, lb, tables, hunks, verdict, named }))
}

// ------------------------------------------------------------------------------------------------ Python's face
