//! The compile (build/compile.py ensure is its face): every stale translation unit of a target through the
//! toolchain, one compiler process per unit on threads, the objects content-addressed under build/obj/<sha256>.obj,
//! the outcome in the store's `tu` table.
//!
//! A unit is stale iff one of three hashes differs from its tu row: the source hash (the text of src/<unit>.c), the
//! flags hash (the target's cflags plus the unit's override and the target's define), or the include hash (the
//! contents of every file in the unit's include set). The include set comes from the preprocessor and is kept in the
//! store by (source hash, flags hash, listing hash of every include search directory): it can only change when the
//! unit's text, its flags, a file in the set, or a directory listing changes, and a changed file in the set already
//! makes the unit stale, after which the set is read again. A failed unit keeps a row with ok=0, its log and
//! diagnostics and its input hashes (it is not compiled again until an input changes). Nothing here reads a
//! modification time.

use crate::fsmemo;
use crate::plan::{self, Tu};
use crate::project::{py_path, sha256_parts, Project};
use crate::store::canon;
use crate::vc6::{Diag, Tools};
use crate::with_db;
use pyo3::prelude::*;
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

/// A tu row's keys and outcome.
#[derive(Clone)]
pub struct TuKeys {
    pub amalg: String,
    pub src_hash: String,
    pub flags_hash: String,
    pub include_hash: String,
    pub obj_hash: String,
    pub ok: bool,
}

pub fn tu_keys(db: &str) -> PyResult<HashMap<String, TuKeys>> {
    with_db(db, |c| {
        let mut st = c.prepare("SELECT unit, amalg, src_hash, flags_hash, include_hash, obj_hash, ok FROM tu")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, TuKeys {
            amalg: r.get(1)?, src_hash: r.get(2)?, flags_hash: r.get(3)?, include_hash: r.get(4)?, obj_hash: r.get(5)?, ok: r.get::<_, i64>(6)? != 0,
        })))?;
        rows.collect()
    })
}

/// A whole tu row: (amalg, src_hash, flags, flags_hash, include_hash, obj_hash, ok, log, diags [[file, line,
/// severity, code, message]]).
pub struct TuRow {
    pub flags: Vec<String>,
    pub src_hash: String,
    pub obj_hash: String,
    pub ok: bool,
    pub log: String,
    pub diags: Vec<(String, i64, String, String, String)>,
}

pub fn tu_rows(db: &str) -> PyResult<HashMap<String, TuRow>> {
    with_db(db, |c| {
        let mut st = c.prepare("SELECT unit, flags, src_hash, obj_hash, ok, log, diags FROM tu")?;
        let rows = st.query_map([], |r| {
            let flags: Value = serde_json::from_str(&r.get::<_, String>(1)?).unwrap_or(Value::Null);
            let diags: Value = serde_json::from_str(&r.get::<_, String>(6)?).unwrap_or(Value::Null);
            let s = |v: &Value| v.as_str().unwrap_or("").to_string();
            Ok((r.get::<_, String>(0)?, TuRow {
                flags: flags.as_array().map(|a| a.iter().map(s).collect()).unwrap_or_default(),
                src_hash: r.get(2)?, obj_hash: r.get(3)?, ok: r.get::<_, i64>(4)? != 0, log: r.get(5)?,
                diags: diags.as_array().map(|a| a.iter().map(|d| (s(&d[0]), d[1].as_i64().unwrap_or(0), s(&d[2]), s(&d[3]), s(&d[4]))).collect()).unwrap_or_default(),
            }))
        })?;
        rows.collect()
    })
}

fn canonical(v: &Value) -> String {
    let mut s = String::new();
    canon(&mut s, v);
    s
}

fn include_set(db: &str, key: &str) -> PyResult<Option<Vec<String>>> {
    let t: Option<String> = with_db(db, |c| c.query_row("SELECT files FROM include_set WHERE key=?", [key], |r| r.get(0)).optional())?;
    Ok(t.map(|t| serde_json::from_str(&t).unwrap_or_default()))
}

fn put_include_set(db: &str, key: &str, files: &[String]) -> PyResult<()> {
    let s = canonical(&json!(files));
    with_db(db, |c| c.execute("INSERT OR REPLACE INTO include_set (key, files) VALUES (?, ?)", [key, &s]).map(|_| ()))
}

/// The hash of the names below one directory (os.walk's order, the subdirectories sorted, names lower case).
fn dir_listing_hash(d: &str) -> String {
    fn walk(base: &Path, top: &Path, h: &mut Sha256) {
        let Ok(it) = std::fs::read_dir(base) else { return };
        let (mut files, mut dirs) = (vec![], vec![]);
        for e in it.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            match e.file_type() {
                Ok(t) if t.is_dir() => dirs.push(n),
                Ok(_) => files.push(n),
                Err(_) => {}
            }
        }
        files.sort();
        dirs.sort();
        let rel = base.strip_prefix(top).map(|r| r.to_string_lossy().into_owned()).unwrap_or_default();
        let rel = if rel.is_empty() { ".".to_string() } else { rel }.to_lowercase();
        for f in files {
            h.update(format!("{rel}/{}", f.to_lowercase()).as_bytes());
            h.update(b"\0");
        }
        for d in dirs {
            walk(&base.join(d), top, h);
        }
    }
    let mut h = Sha256::new();
    let p = Path::new(d);
    if p.exists() {
        walk(p, p, &mut h);
    }
    fsmemo::hex(&h.finalize())
}

/// One build's memo of the listing hashes and the include files' hashes.
#[derive(Default)]
struct Memo {
    listing: Mutex<HashMap<String, String>>,
    files: Mutex<HashMap<String, String>>,
}

impl Memo {
    fn listing_hash(&self, dirs: &[String]) -> String {
        let parts: Vec<String> = dirs.iter().map(|d| {
            let hit = self.listing.lock().unwrap().get(d).cloned(); // the guard ends here: the insert below locks again
            let h = hit.unwrap_or_else(|| {
                let h = dir_listing_hash(d);
                self.listing.lock().unwrap().insert(d.clone(), h.clone());
                h
            });
            format!("{d}={h}")
        }).collect();
        sha256_parts(&parts)
    }

    fn file(&self, path: &str) -> String {
        let hit = self.files.lock().unwrap().get(path).cloned();
        if let Some(h) = hit {
            return h;
        }
        let h = if Path::new(path).is_file() { fsmemo::sha256(path).unwrap_or_else(|_| "missing".into()) } else { "missing".into() };
        self.files.lock().unwrap().insert(path.to_string(), h.clone());
        h
    }

    fn set(&self, files: &[String]) -> String {
        let mut fs: Vec<&String> = files.iter().collect();
        fs.sort_by_key(|f| f.to_lowercase());
        let parts: Vec<String> = fs.iter().map(|f| format!("{}={}", f.to_lowercase(), self.file(f))).collect();
        sha256_parts(&parts)
    }
}

/// What a build did.
#[derive(Default)]
pub struct Report {
    pub target: String,
    pub units: usize,
    pub compiled: Vec<String>,
    pub failed: Vec<String>,
    pub removed: Vec<String>,
    pub preprocessed: usize,
    pub ms: i64,
    pub unavailable: bool,
    pub log: Vec<String>,
}

pub fn obj_path(root: &str, obj_hash: &str) -> String {
    py_path(&format!("{root}/build/obj/{obj_hash}.obj"))
}

/// The compiler's diagnostics in the unit's file at its physical lines.
fn located(root: &str, a: &Tu, diags: Vec<Diag>) -> Vec<Diag> {
    let text = fsmemo::read_text(&py_path(&format!("{root}/{}", a.file))).unwrap_or_default();
    diags.into_iter().map(|mut d| {
        let hits = if d.file.is_empty() { vec![] } else { plan::locate(&text, &a.file, &d.file, d.line) };
        if let Some(&first) = hits.first() {
            if hits.len() > 1 {
                d.message += &format!("; or {}", hits[1..].iter().map(|k| format!("{}({k})", a.file)).collect::<Vec<_>>().join(", "));
            }
            d.file = a.file.clone();
            d.line = first;
        }
        d
    }).collect()
}

fn win(rel: &str) -> String {
    rel.replace('/', "\\")
}

/// Bring the objects of the current target up to date.
pub fn ensure(p: &Project, force: bool, jobs: Option<usize>) -> Result<Report, String> {
    let t0 = std::time::Instant::now();
    let root = p.root.to_string_lossy().into_owned();
    let db = p.store_path();
    crate::pystore::st_open(&db, &p.main_uri()).map_err(|e| e.to_string())?;
    let mut rep = Report { target: p.target_name.clone(), ..Default::default() };
    fsmemo::new_epoch();
    p.forget_input("src");
    p.forget_input("decl");
    if force {
        fsmemo::forget_all();
    }
    let units = plan::plan(p)?;
    rep.units = units.len();
    let tools = Tools::of(p);
    if !units.is_empty() && !tools.available() {
        rep.unavailable = true;
        rep.log.push(format!("build: the toolchain is not available (root {}): {} units not compiled",
                             tools.root.as_deref().unwrap_or("None"), units.len()));
        return Ok(rep);
    }
    let rows = tu_keys(&db).map_err(|e| e.to_string())?;
    let memo = Memo::default();
    let dirs = vec!["include".to_string()];
    let mut search = vec![py_path(&format!("{root}/include"))];
    search.extend(tools.system_include().into_iter().map(|d| if Path::new(&d).is_absolute() { d } else { py_path(&format!("{root}/{d}")) }));
    // (unit, flags, key)
    let mut work: Vec<(&Tu, Vec<String>, String)> = vec![];
    let mut todo_pre = vec![];
    for a in units.iter() {
        let flags = plan::compile_flags(p, &a.target, &a.unit)?;
        let key = sha256_parts(&[a.src_hash.clone(), sha256_parts(&[canonical(&json!(flags))]), memo.listing_hash(&search)]);
        let row = rows.get(&a.unit);
        if include_set(&db, &key).map_err(|e| e.to_string())?.is_none() && row.is_some_and(|r| r.src_hash == a.src_hash) && !force {
            todo_pre.push(work.len());
        }
        work.push((a, flags, key));
    }
    let ours = |a: &Tu| -> Vec<String> {
        let mut v = vec![crate::vc6::resolved(&root, &a.file).to_lowercase()];
        if let Some(f) = &a.file_name {
            v.push(crate::vc6::resolved(&root, f).to_lowercase());
        }
        v
    };
    let preprocess = |k: usize| -> Option<Vec<String>> {
        let (a, flags, _) = &work[k];
        let (files, err) = tools.includes(&win(&a.file), flags, &dirs, &root).ok()?;
        if !err.is_empty() {
            return None;
        }
        let own = ours(a);
        Some(files.into_iter().filter(|f| !own.contains(&f.to_lowercase())).collect())
    };
    let n = jobs.unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4));
    let pre = run_threads(n, &todo_pre, |&k| preprocess(k));
    for (k, files) in todo_pre.iter().zip(pre) {
        if let Some(files) = files {
            put_include_set(&db, &work[*k].2, &files).map_err(|e| e.to_string())?;
        }
        rep.preprocessed += 1;
    }
    let mut stale = vec![];
    for (k, (a, flags, key)) in work.iter().enumerate() {
        let files = include_set(&db, key).map_err(|e| e.to_string())?;
        let fh = sha256_parts(&[canonical(&json!(flags))]);
        let fresh = match (&files, rows.get(&a.unit)) {
            (Some(files), Some(row)) => !force && row.src_hash == a.src_hash && row.flags_hash == fh && row.include_hash == memo.set(files)
                && row.amalg == a.file && (!row.ok || Path::new(&obj_path(&root, &row.obj_hash)).exists()),
            _ => false,
        };
        if !fresh {
            stale.push(k);
        }
    }
    if !stale.is_empty() {
        rep.log.push(format!("build: compiling {} of {} units (target {})", stale.len(), units.len(), p.target_name));
        let results = run_threads(n, &stale, |&k| {
            let (a, flags, _) = &work[k];
            let tmp = format!("build\\obj\\tmp\\{}\\{}.obj", a.target, a.unit);
            let tmp_abs = py_path(&format!("{root}/{tmp}"));
            let _ = std::fs::create_dir_all(Path::new(&tmp_abs).parent().unwrap());
            let _ = std::fs::remove_file(&tmp_abs);
            let files = preprocess(k);
            let res = tools.compile(&win(&a.file), &tmp, flags, &dirs, &root);
            let res = res.map(|mut r| {
                r.diags = located(&root, a, std::mem::take(&mut r.diags));
                r
            });
            let mut obj_hash = String::new();
            if let Ok(r) = &res {
                if r.ok {
                    if let Ok(data) = std::fs::read(&tmp_abs) {
                        obj_hash = fsmemo::hex(&Sha256::digest(&data));
                        let dest = obj_path(&root, &obj_hash);
                        if Path::new(&dest).exists() {
                            let _ = std::fs::remove_file(&tmp_abs);
                        } else {
                            let _ = std::fs::rename(&tmp_abs, &dest);
                        }
                    }
                }
            }
            (res, files, obj_hash)
        });
        let _ = std::fs::create_dir_all(py_path(&format!("{root}/build/obj")));
        for (k, (res, files, obj_hash)) in stale.iter().zip(results) {
            let (a, flags, key) = &work[*k];
            let res = res?;
            if let Some(files) = &files {
                put_include_set(&db, key, files).map_err(|e| e.to_string())?;
            }
            let mut diags: Vec<Value> = res.diags.iter().map(|d| json!([d.file, d.line, d.severity, d.code, d.message])).collect();
            diags.extend(res.refused.iter().map(|f| json!(["", 0, "error", "refused", f])));
            let include_hash = files.as_ref().map(|f| memo.set(f)).unwrap_or_else(|| "unknown".into());
            let at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0);
            with_db(&db, |c| c.execute(
                "INSERT OR REPLACE INTO tu (unit, amalg, src_hash, flags, flags_hash, include_hash, obj_hash, ok, log, diags, at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                params![a.unit, a.file, a.src_hash, canonical(&json!(flags)), sha256_parts(&[canonical(&json!(flags))]), include_hash, obj_hash,
                        res.ok as i64, res.log, canonical(&Value::Array(diags)), at]).map(|_| ())).map_err(|e| e.to_string())?;
            rep.compiled.push(a.unit.clone());
            if !res.ok {
                rep.failed.push(a.unit.clone());
            }
            let errs: Vec<&Diag> = res.diags.iter().filter(|d| d.severity == "error").collect();
            let warns = res.diags.iter().filter(|d| d.severity == "warning").count();
            rep.log.push(format!("  {} {}  errors={} warnings={warns}{}", if res.ok { "ok  " } else { "FAIL" }, a.unit, errs.len(),
                                 if obj_hash.is_empty() { String::new() } else { format!("  obj={}", &obj_hash[..12]) }));
            for d in errs.iter().take(10) {
                rep.log.push(format!("       {}", d.text()));
            }
        }
    }
    let planned: std::collections::HashSet<&str> = units.iter().map(|a| a.unit.as_str()).collect();
    let mut gone: Vec<&String> = rows.keys().filter(|u| !planned.contains(u.as_str())).collect();
    gone.sort();
    for u in gone {
        with_db(&db, |c| c.execute("DELETE FROM tu WHERE unit=?", [u]).map(|_| ())).map_err(|e| e.to_string())?;
        rep.removed.push(u.clone());
    }
    p.forget_input("objects");
    rep.ms = t0.elapsed().as_millis() as i64;
    Ok(rep)
}

/// f over the items on n threads, results in the items' order.
fn run_threads<T: Sync, R: Send>(n: usize, items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let next = std::sync::atomic::AtomicUsize::new(0);
    let out: Mutex<Vec<Option<R>>> = Mutex::new((0..items.len()).map(|_| None).collect());
    std::thread::scope(|s| {
        for _ in 0..n.max(1).min(items.len().max(1)) {
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

/// compile.ensure: (target, units, compiled, failed, removed, preprocessed, ms, unavailable, log lines).
#[pyfunction]
#[pyo3(signature = (project, force=false, jobs=None))]
#[allow(clippy::type_complexity)]
pub fn compile_ensure(project: PyRef<'_, crate::project::PyProject>, force: bool, jobs: Option<usize>)
    -> PyResult<(String, usize, Vec<String>, Vec<String>, Vec<String>, usize, i64, bool, Vec<String>)> {
    let r = ensure(&project.p, force, jobs).map_err(pyo3::exceptions::PyRuntimeError::new_err)?;
    Ok((r.target, r.units, r.compiled, r.failed, r.removed, r.preprocessed, r.ms, r.unavailable, r.log))
}
