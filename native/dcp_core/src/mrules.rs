//! M.compile and M.flags.proven (and probe.analyse, which M.flags.proven reads): the match rules of the build.

use crate::compile::{obj_path, tu_rows_of};
use crate::plan;
use crate::project::Project;
use crate::rules::Ctx;
use crate::store::{Out, DECLARED, PROVEN};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};

fn project_of(ctx: &Ctx) -> PyResult<Project> {
    Project::open(std::path::Path::new(&ctx.root), Some(&ctx.inputs.target), "").map_err(PyRuntimeError::new_err)
}

/// M.compile: one `build` fact per translation unit of the current target (its compile's outcome), the gate errors
/// of a failed, uncompiled or stale unit, an override without a reason, and M.gen (the object against the
/// address comments).
pub fn m_compile(ctx: &Ctx, db: &Connection, out: &mut Out) -> PyResult<()> {
    let p = project_of(ctx)?;
    let img = crate::image(&ctx.image)?;
    let (base, end) = (img.base as i64, img.end() as i64);
    let in_image = |a: i64| base <= a && a < end;
    let err = |e: String| PyRuntimeError::new_err(e);
    for o in plan::unit_overrides(&p) {
        let reason = o.get("reason").map(|r| r.as_str().map(|s| s.to_string()).unwrap_or_else(|| crate::project::toml_json(r).to_string())).unwrap_or_default();
        if reason.trim().is_empty() {
            let glob = match o.get("glob") {
                Some(toml::Value::String(s)) => crate::decl::py_repr(s),
                Some(v) => crate::project::toml_json(v).to_string(),
                None => "None".into(),
            };
            out.conflict("error", "M.compile", base, base + 1, format!("[[toolchain.unit]] glob={glob}: an override without a reason"), "");
        }
    }
    let tools = crate::vc6::Tools::of(&p);
    let rows = tu_rows_of(db).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let root = p.root.to_string_lossy().into_owned();
    for a in plan::plan(&p).map_err(err)?.iter() {
        let at = a.first_addr().filter(|&x| in_image(x)).unwrap_or(base);
        let flags = plan::compile_flags(&p, &a.target, &a.unit).map_err(err)?;
        let Some(row) = rows.get(&a.unit) else {
            out.fact(at, at + 1, "build", json!({"tu": a.unit, "ok": false, "stale": true, "errors": ["not compiled"], "warnings": 0,
                                                 "functions": a.functions.len()}), PROVEN);
            if tools.available() {
                out.conflict("error", "M.compile", at, at + 1, format!("unit {} is not compiled (dcp build)", a.unit), "");
            } else {
                out.conflict("warn", "M.compile", at, at + 1, format!("unit {} is not compiled: the toolchain is not available (root {})", a.unit,
                                                                      tools.root.as_deref().unwrap_or("None")), "");
            }
            continue;
        };
        let errors: Vec<String> = row.diags.iter().filter(|d| d.2 == "error")
            .map(|(f, l, sev, code, msg)| if f.is_empty() { format!("{sev} {code}: {msg}") } else { format!("{f}({l}): {sev} {code}: {msg}") }).collect();
        let warnings = row.diags.iter().filter(|d| d.2 == "warning").count();
        let stale = row.src_hash != a.src_hash || row.flags != flags;
        let mut v = json!({"tu": a.unit, "ok": row.ok, "stale": stale, "flags": row.flags.join(" "), "warnings": warnings,
                           "functions": a.functions.len(), "file": a.file});
        if row.ok {
            v["obj"] = json!(row.obj_hash.chars().take(16).collect::<String>());
        }
        if !errors.is_empty() {
            v["errors"] = json!(errors.iter().take(20).collect::<Vec<_>>());
        }
        out.fact(at, at + 1, "build", v, PROVEN);
        if !row.ok {
            let trimmed = row.log.trim();
            let last = trimmed.lines().last().filter(|_| !trimmed.is_empty()).unwrap_or("no diagnostics");
            let why = if errors.is_empty() { last.to_string() } else { errors.iter().take(3).cloned().collect::<Vec<_>>().join("; ") };
            out.conflict("error", "M.compile", at, at + 1, format!("unit {} does not compile: {why}", a.unit), "");
            continue;
        } else if stale {
            out.conflict("warn", "M.compile", at, at + 1, format!("unit {} changed since its compile (dcp build)", a.unit), "");
        }
        let Ok(data) = std::fs::read(obj_path(&root, &row.obj_hash)) else { continue };
        let Ok(obj) = crate::coff::Obj::parse(&data) else { continue };
        let mut defined: BTreeMap<String, String> = BTreeMap::new();
        for k in obj.functions() {
            let name = &obj.symbols[k].name;
            defined.entry(crate::coff::undecorate(name)).or_insert_with(|| name.clone());
        }
        let mut ours: BTreeMap<&str, Option<i64>> = BTreeMap::new();
        for (addr, name) in &a.functions {
            ours.entry(name.as_str()).or_insert(*addr);
        }
        for (name, raw) in &defined {
            if !ours.contains_key(name.as_str()) {
                out.conflict("error", "M.gen", at, at + 1,
                             format!("unit {}: the object defines {name} ({raw}), no address comment of the target in {} does", a.unit, a.file), "");
            }
        }
        for (name, addr) in &ours {
            let where_ = addr.filter(|&x| in_image(x)).unwrap_or(at);
            if !defined.contains_key(*name) {
                out.conflict("error", "M.gen", where_, where_ + 1,
                             format!("{}: the object of unit {} defines no function {name} (dropped by the compiler as an unreferenced static, or not parsed as a definition)",
                                     a.file, a.unit), "");
            }
        }
    }
    Ok(())
}

/// probe.analyse: the best combination and, per group, the anchors that distinguish its flag; only user anchors
/// count, the CRT anchors are listed apart.
pub fn analyse(result: &Value) -> Value {
    let grid: Vec<(String, Vec<String>)> = result["grid"].as_array().into_iter().flatten()
        .map(|g| (g[0].as_str().unwrap_or("").to_string(), g[1].as_array().into_iter().flatten().map(|x| x.as_str().unwrap_or("").to_string()).collect()))
        .collect();
    let key = |v: &Value| v.as_str().map(|s| s.to_string()).unwrap_or_else(|| v.to_string());
    let kinds: HashMap<String, &Value> = result["anchors"].as_array().into_iter().flatten().map(|a| (key(&a["id"]), a)).collect();
    let combos: Vec<&Value> = result["combos"].as_array().into_iter().flatten().collect();
    let flags_of = |c: &Value| -> Vec<String> { c["flags"].as_array().into_iter().flatten().map(|f| f.as_str().unwrap_or("").to_string()).collect() };
    let by: HashMap<Vec<String>, &Value> = combos.iter().map(|c| (flags_of(c), *c)).collect();
    let refused = |c: &Value| c["refused"].as_array().is_some_and(|a| !a.is_empty()) || c["refused"].as_bool() == Some(true);
    let valid: Vec<&Value> = combos.iter().copied().filter(|c| !refused(c)).collect();
    if valid.is_empty() {
        return json!({"best": null, "groups": []});
    }
    let lower = |k: &str| -> BTreeSet<String> { result[k].as_array().into_iter().flatten().filter_map(|f| f.as_str()).map(|s| s.to_lowercase()).collect() };
    let (declared, defaults) = (lower("declared"), lower("defaults"));
    let kind_of = |a: &str| kinds.get(a).and_then(|k| k["kind"].as_str()).unwrap_or("");
    let matched = |c: &Value| -> Vec<String> { c["matched"].as_array().into_iter().flatten().map(key).collect() };
    let user = |c: &Value| matched(c).into_iter().filter(|a| kind_of(a) == "user").count();
    let top = valid.iter().map(|c| user(c)).max().unwrap();
    let score = |c: &Value| {
        let fs = flags_of(c);
        (fs.iter().filter(|f| declared.contains(&f.to_lowercase())).count(), fs.iter().filter(|f| defaults.contains(&f.to_lowercase())).count())
    };
    let mut best: Option<&Value> = None;
    for c in valid.iter().copied().filter(|c| user(c) == top) {
        if best.is_none_or(|b| score(c) > score(b)) {
            best = Some(c);
        }
    }
    let best = best.unwrap();
    let bflags = flags_of(best);
    let bmatched: BTreeSet<String> = matched(best).into_iter().collect();
    let mut groups = vec![];
    for (k, (g, alts)) in grid.iter().enumerate() {
        let (mut lost, mut crt_lost) = (BTreeSet::new(), BTreeSet::new());
        let (mut tried, mut same) = (0, vec![]);
        for v in alts {
            if Some(v) == bflags.get(k) {
                continue;
            }
            let mut other = bflags.clone();
            if k < other.len() {
                other[k] = v.clone();
            }
            let Some(c) = by.get(&other).filter(|c| !refused(c)) else { continue };
            tried += 1;
            let cm: BTreeSet<String> = matched(c).into_iter().collect();
            let gone: Vec<&String> = bmatched.difference(&cm).collect();
            let user_gone: Vec<&String> = gone.iter().copied().filter(|a| kind_of(a) == "user").collect();
            if user_gone.is_empty() {
                same.push(v.clone());
            }
            lost.extend(user_gone.into_iter().cloned());
            crt_lost.extend(gone.iter().filter(|a| kind_of(a) == "crt").map(|a| (*a).clone()));
        }
        let unique = tried > 0 && same.is_empty();
        let units: BTreeSet<String> = lost.iter().filter_map(|a| kinds.get(a).map(|k| key(&k["unit"]))).collect();
        groups.push(json!({"group": g, "flag": bflags.get(k).cloned().unwrap_or_default(), "alternatives": tried,
                           "anchors": if unique { lost.iter().cloned().collect::<Vec<_>>() } else { vec![] },
                           "units": if unique { units.into_iter().collect::<Vec<_>>() } else { vec![] },
                           "crt_anchors": crt_lost.into_iter().collect::<Vec<_>>(), "same_as": same, "ruled_out": lost.into_iter().collect::<Vec<_>>()}));
    }
    let mut ranked: Vec<(usize, Vec<String>)> = valid.iter().map(|c| (user(c), flags_of(c))).collect();
    ranked.sort_by_key(|x| std::cmp::Reverse(x.0));
    ranked.truncate(5);
    json!({"best": best, "matched": top, "groups": groups, "ranked": ranked})
}

/// M.flags.proven: from the last probe, one `toolchain` fact per flag group naming the best combination's flag and
/// how many anchors and units distinguish it; proven from two units on, else declared; a proven flag the declared
/// cflags lack is an error (M.flags).
pub fn m_flags_proven(ctx: &Ctx, db: &Connection, out: &mut Out) -> PyResult<()> {
    let p = project_of(ctx)?;
    let _ = p;
    use rusqlite::OptionalExtension;
    let m: Option<String> = db.query_row("SELECT value FROM meta WHERE key='probe'", [], |r| r.get(0)).optional()
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let Some(m) = m else { return Ok(()) };
    let res: Value = serde_json::from_str(&m).unwrap_or(Value::Null);
    if res.is_null() {
        return Ok(());
    }
    let img = crate::image(&ctx.image)?;
    let (base, end) = (img.base as i64, img.end() as i64);
    let declared: BTreeSet<String> = ctx.inputs.decl["cflags"].as_array().into_iter().flatten().filter_map(|f| f.as_str()).map(|s| s.to_lowercase()).collect();
    let an = analyse(&res);
    for g in an["groups"].as_array().into_iter().flatten() {
        let n = |k: &str| g[k].as_array().map(|a| a.len()).unwrap_or(0);
        let lvl = if n("units") >= 2 { PROVEN } else { DECLARED };
        let flag = g["flag"].as_str().unwrap_or("");
        out.fact(base, end, "toolchain", json!({"flag": flag, "group": g["group"], "anchors": n("anchors"), "units": n("units"),
                                                "crt_anchors": n("crt_anchors")}), lvl);
        if lvl == PROVEN && !declared.contains(&flag.to_lowercase()) {
            out.conflict("error", "M.flags", base, base + 1,
                         format!("the probe proves {flag} ({}, {} anchors from {} units); the declared cflags do not hold it",
                                 g["group"].as_str().unwrap_or(""), n("anchors"), n("units")), "");
        }
    }
    Ok(())
}

/// probe.analyse for Python.
#[pyfunction]
pub fn probe_analyse<'py>(py: Python<'py>, result: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
    crate::pystore::json_py(py, &analyse(&crate::pystore::py_value(result)?))
}
