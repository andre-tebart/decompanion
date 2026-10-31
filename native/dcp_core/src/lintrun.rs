//! A lint run (source/lint.py's lint and stale are its face; the checks M5..M7 are lint.rs's): every unit of the
//! current target and the all-declarations unit through the front end, as VC6 sees them.
//!
//! Cache: per unit in the store's blob table, keyed by the unit's text, the clang arguments and the unit's include
//! hash (the compile's), so a unit is parsed again exactly when it would be compiled again; the all-declarations
//! unit by its text and the contents of include/. The result of a run is the store meta `lint` (the input `lint` of
//! M.lint and G.grade). The parses of a run go to threads; a unit parsed alone stays live (the scan's parse of an
//! edit serves its lint).

use crate::clang::CDiag;
use crate::frontend::{self, Front};
use crate::fsmemo;
use crate::project::{py_path, sha256_parts, Project};
use crate::store::canon;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::sync::LazyLock;

const VERSION: &str = "7";
const CPARSE_VERSION: &str = "4";

fn canonical(v: &Value) -> String {
    let mut s = String::new();
    canon(&mut s, v);
    s
}

/// The header files of include/, sorted as Path sorts them on Windows (by the lower-case name).
fn include_headers(root: &str) -> Vec<(String, String)> {
    let inc = Path::new(root).join("include");
    let mut out: Vec<(String, String)> = std::fs::read_dir(&inc).into_iter().flatten().flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.to_lowercase().ends_with(".h"))
        .map(|n| (n.clone(), py_path(&inc.join(&n).to_string_lossy())))
        .collect();
    out.sort_by_key(|x| x.0.to_lowercase());
    out
}

/// header name -> the units it is private to (`@private UNIT[,UNIT..]` in its first 20 lines).
pub fn private_headers(root: &str) -> BTreeMap<String, BTreeSet<String>> {
    static PRIVATE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"@private[ \t]+([A-Za-z_][\w]*(?:[ \t]*,[ \t]*[A-Za-z_]\w*)*)").unwrap());
    let mut out = BTreeMap::new();
    for (name, p) in include_headers(root) {
        let text = fsmemo::read_text(&p).unwrap_or_default();
        let head: Vec<&str> = text.split('\n').take(20).collect();
        if let Some(m) = PRIVATE.captures(&head.join("\n")) {
            out.insert(name, m[1].split(',').map(|u| u.trim().to_string()).collect());
        }
    }
    out
}

/// The `#include "..."` of a file: (the header's name, the line).
fn quoted_includes(p: &str) -> Vec<(String, i64)> {
    static INCLUDE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r#"(?m)^[ \t]*#[ \t]*include[ \t]+"([^"]+)""#).unwrap());
    let text = fsmemo::read_text(p).unwrap_or_default();
    INCLUDE.captures_iter(&text).map(|m| {
        let name = Path::new(&m[1]).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        (name, text[..m.get(0).unwrap().start()].matches('\n').count() as i64 + 1)
    }).collect()
}

fn unit_sources(root: &str) -> Vec<(String, String)> {
    let src = py_path(&format!("{root}/src"));
    if !Path::new(&src).exists() {
        return vec![];
    }
    fsmemo::walk(&src, &["*.c".into()]).into_iter().map(|(r, p)| (format!("src/{r}"), p)).collect()
}

/// M5 lines: a file outside a private header's units that includes it.
fn private_violations(root: &str, private: &BTreeMap<String, BTreeSet<String>>) -> Vec<String> {
    let mut out = vec![];
    if private.is_empty() {
        return out;
    }
    let mut files = unit_sources(root);
    files.extend(include_headers(root).into_iter().map(|(n, p)| (format!("include/{n}"), p)));
    for (rel, p) in files {
        let stem = Path::new(&rel).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let name = Path::new(&rel).file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        for (h, line) in quoted_includes(&p) {
            let Some(units) = private.get(&h) else { continue };
            let ok = if rel.starts_with("src/") {
                units.contains(&stem)
            } else {
                name == h || private.get(&name).is_some_and(|mine| mine.is_subset(units))
            };
            if !ok {
                out.push(format!("{rel}:{line}: includes {h}, private to {} (@private in the header)", units.iter().cloned().collect::<Vec<_>>().join(",")));
            }
        }
    }
    out
}

/// What a lint run gives: (the `lint` meta value, units parsed, units cached).
pub fn lint(p: &Project) -> Result<(Value, usize, usize), String> {
    let root = p.root.to_string_lossy().into_owned();
    let db = p.store_path();
    crate::pystore::st_open(&db, &p.main_uri()).map_err(|e| e.to_string())?;
    let front = Front::of(&root)?;
    let version = crate::clang::clang_version().map_err(|e| e.to_string())?;
    let clang = [CPARSE_VERSION.to_string(), version, canonical(&json!(frontend::ARGS)), canonical(&json!(front.sysdirs))];
    let units = crate::plan::plan(p)?;
    let defines = vec![frontend::target_macro(&p.target_name)];
    let tus = crate::compile::tu_keys(&db).map_err(|e| e.to_string())?;
    let args = front.args(&defines);
    let blob = |k: &str| -> Result<Option<Vec<CDiag>>, String> {
        let d = crate::with_db(&db, |c| {
            use rusqlite::OptionalExtension;
            c.query_row("SELECT data FROM blob WHERE hash=?", [k], |r| r.get::<_, Vec<u8>>(0)).optional()
        }).map_err(|e| e.to_string())?;
        Ok(d.and_then(|d| serde_json::from_slice(&d).ok()))
    };
    // (unit or None for the all-declarations unit, key, path, presumed)
    let mut jobs: Vec<(Option<String>, String, String, bool)> = vec![];
    let mut results: HashMap<String, Vec<CDiag>> = HashMap::new();
    for a in units.iter() {
        let inc = tus.get(&a.unit).map(|r| r.include_hash.clone()).unwrap_or_default();
        let mut parts = vec!["lint".to_string(), VERSION.into()];
        parts.extend(clang.iter().cloned());
        parts.extend([a.src_hash.clone(), inc]);
        parts.extend(defines.iter().cloned());
        let key = sha256_parts(&parts);
        match blob(&key)? {
            Some(d) => {
                results.insert(a.unit.clone(), d);
            }
            None => jobs.push((Some(a.unit.clone()), key, py_path(&format!("{root}/{}", a.file)), false)),
        }
    }
    let scan = frontend::scan(&root, Some(&p.input_hash("src")?.unwrap_or_default()))?;
    let private = private_headers(&root);
    let headers: Vec<String> = include_headers(&root).into_iter().filter(|(n, _)| !private.contains_key(n)).map(|(n, _)| format!("include/{n}")).collect();
    let srcs: Vec<String> = unit_sources(&root).into_iter().map(|x| x.0).collect();
    let ad = Python::attach(|_| crate::lint::lint_alldecls(scan.piece_ids(), Some(p.target_name.clone()), headers, srcs)).map_err(|e| e.to_string())?;
    let text = ad.text().to_string();
    let mut parts = vec!["alldecls".to_string(), VERSION.into()];
    parts.extend(clang.iter().cloned());
    parts.push(text.clone());
    parts.extend(defines.iter().cloned());
    for (_, h) in include_headers(&root) {
        parts.push(fsmemo::sha256(&h).map_err(|e| format!("{h}: {e}"))?);
    }
    let akey = sha256_parts(&parts);
    let mut cross = blob(&akey)?;
    if cross.is_none() {
        let out = Path::new(&root).join("build").join("lint").join(&p.target_name).join("alldecls.c");
        std::fs::create_dir_all(out.parent().unwrap()).map_err(|e| e.to_string())?;
        std::fs::write(&out, &text).map_err(|e| e.to_string())?;
        jobs.push((None, akey.clone(), py_path(&out.to_string_lossy()), true));
    }
    let unit_jobs = jobs.iter().filter(|j| j.0.is_some()).count();
    let keep_one = unit_jobs == 1;
    let parsed = run_threads(&jobs, |(unit, _, path, presumed)| -> Result<Vec<CDiag>, String> {
        let text = fsmemo::read_text(path).map_err(|e| format!("{path}: {e}"))?;
        frontend::with_parse(path, &args, &text, keep_one && unit.is_some(), |u| u.diags(&root, &text, *presumed).map_err(|e| e.to_string()))
    });
    for ((unit, key, _, _), diags) in jobs.iter().zip(parsed) {
        let diags = diags?;
        let data = canonical(&serde_json::to_value(&diags).unwrap_or(Value::Null));
        crate::with_db(&db, |c| c.execute("INSERT OR IGNORE INTO blob (hash, kind, data) VALUES (?, 'lint', ?)", rusqlite::params![key, data.as_bytes()])
            .map(|_| ())).map_err(|e| e.to_string())?;
        match unit {
            None => cross = Some(diags),
            Some(u) => {
                results.insert(u.clone(), diags);
            }
        }
    }
    let per_unit: Vec<Vec<CDiag>> = units.iter().map(|a| results.get(&a.unit).cloned().unwrap_or_default()).collect();
    let (errors, at) = crate::lint::lint_units(per_unit, &root).map_err(|e| e.to_string())?;
    let mut conflicts = crate::lint::lint_cross(&ad, cross.unwrap_or_default(), &root).map_err(|e| e.to_string())?;
    conflicts.extend(private_violations(&root, &private));
    let mut calls: BTreeMap<String, BTreeSet<(i64, String)>> = BTreeMap::new();
    for (file, line, text) in at {
        calls.entry(file).or_default().insert((line, text));
    }
    let errors: BTreeSet<String> = errors.into_iter().collect();
    let conflicts: BTreeSet<String> = conflicts.into_iter().collect();
    let res = json!({
        "units": units.iter().map(|a| (a.unit.clone(), json!(a.src_hash))).collect::<serde_json::Map<_, _>>(),
        "includes": units.iter().map(|a| (a.unit.clone(), json!(tus.get(&a.unit).map(|r| r.include_hash.clone()).unwrap_or_default()))).collect::<serde_json::Map<_, _>>(),
        "errors": errors, "cross": conflicts,
        "calls": calls.into_iter().map(|(f, cs)| (f, json!(cs.into_iter().map(|(l, t)| json!([l, t])).collect::<Vec<_>>()))).collect::<serde_json::Map<_, _>>(),
    });
    crate::pystore::st_set_meta(&db, "lint", &canonical(&res)).map_err(|e| e.to_string())?;
    p.forget_input("lint");
    Ok((res, unit_jobs, units.len() - unit_jobs))
}

/// The units whose source or include set changed since the last lint (by the compile's hashes), None when there
/// was no lint run.
pub fn stale(p: &Project) -> Result<Option<Vec<String>>, String> {
    let db = p.store_path();
    crate::pystore::st_open(&db, &p.main_uri()).map_err(|e| e.to_string())?;
    let Some(m) = crate::pystore::st_meta(&db, "lint").map_err(|e| e.to_string())? else { return Ok(None) };
    let m: Value = serde_json::from_str(&m).unwrap_or(Value::Null);
    let tus = crate::compile::tu_keys(&db).map_err(|e| e.to_string())?;
    let mut changed: BTreeSet<String> = tus.iter().filter(|(u, r)| {
        m["units"].get(u.as_str()).and_then(|v| v.as_str()) != Some(r.src_hash.as_str())
            || m["includes"].get(u.as_str()).and_then(|v| v.as_str()) != Some(r.include_hash.as_str())
    }).map(|(u, _)| u.clone()).collect();
    if let Some(us) = m["units"].as_object() {
        changed.extend(us.keys().filter(|u| !tus.contains_key(*u)).cloned());
    }
    Ok(Some(changed.into_iter().collect()))
}

/// The last lint's value as the rules read it: None when there is none or it is of an older decompanion (calls
/// without their lines).
pub fn last(db: &rusqlite::Connection) -> Option<Value> {
    use rusqlite::OptionalExtension;
    let m: String = db.query_row("SELECT value FROM meta WHERE key='lint'", [], |r| r.get(0)).optional().ok()??;
    let v: Value = serde_json::from_str(&m).ok()?;
    let old = v["calls"].as_object().is_some_and(|cs| cs.values().any(|c| c.as_array().is_some_and(|a| a.iter().any(|x| x.is_string()))));
    (!v.is_null() && !old).then_some(v)
}

fn run_threads<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).min(items.len().max(1));
    let next = std::sync::atomic::AtomicUsize::new(0);
    let out: std::sync::Mutex<Vec<Option<R>>> = std::sync::Mutex::new((0..items.len()).map(|_| None).collect());
    std::thread::scope(|s| {
        for _ in 0..n {
            s.spawn(|| loop {
                let k = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if k >= items.len() {
                    break;
                }
                let r = f(&items[k]);
                out.lock().unwrap()[k] = Some(r);
            });
        }
    });
    out.into_inner().unwrap().into_iter().map(|r| r.unwrap()).collect()
}

// ------------------------------------------------------------------------------------------------ Python's face

/// lint.lint: the run's value with `parsed` and `cached`.
#[pyfunction]
pub fn lint_run<'py>(py: Python<'py>, project: PyRef<'py, crate::project::PyProject>) -> PyResult<Bound<'py, PyAny>> {
    let (mut v, parsed, cached) = lint(&project.p).map_err(PyRuntimeError::new_err)?;
    v["parsed"] = json!(parsed);
    v["cached"] = json!(cached);
    crate::pystore::json_py(py, &v)
}

#[pyfunction]
pub fn lint_stale(project: PyRef<'_, crate::project::PyProject>) -> PyResult<Option<Vec<String>>> {
    stale(&project.p).map_err(PyRuntimeError::new_err)
}

/// header name -> the units it is private to.
#[pyfunction]
pub fn lint_private_headers<'py>(py: Python<'py>, root: &str) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    for (h, us) in private_headers(root) {
        d.set_item(h, pyo3::types::PySet::new(py, us)?)?;
    }
    Ok(d)
}
