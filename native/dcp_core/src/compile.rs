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

use crate::error::{Error, Result};
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

pub fn tu_keys(db: &str) -> Result<HashMap<String, TuKeys>> {
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

pub fn tu_rows(db: &str) -> Result<HashMap<String, TuRow>> {
    with_db(db, |c| tu_rows_of(c))
}

/// tu_rows on a connection the caller holds.
pub fn tu_rows_of(c: &rusqlite::Connection) -> rusqlite::Result<HashMap<String, TuRow>> {
    {
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
    }
}

fn canonical(v: &Value) -> String {
    let mut s = String::new();
    canon(&mut s, v);
    s
}

fn include_set(db: &str, key: &str) -> Result<Option<Vec<String>>> {
    let t: Option<String> = with_db(db, |c| c.query_row("SELECT files FROM include_set WHERE key=?", [key], |r| r.get(0)).optional())?;
    Ok(t.map(|t| serde_json::from_str(&t).unwrap_or_default()))
}

fn put_include_set(db: &str, key: &str, files: &[String]) -> Result<()> {
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
        let spare = stale.len() * 2 <= n;
        let results = run_threads(n, &stale, |&k| {
            let (a, flags, _) = &work[k];
            let tmp = format!("build\\obj\\tmp\\{}\\{}.obj", a.target, a.unit);
            let tmp_abs = py_path(&format!("{root}/{tmp}"));
            let _ = std::fs::create_dir_all(Path::new(&tmp_abs).parent().unwrap());
            let _ = std::fs::remove_file(&tmp_abs);
            let compile = || tools.compile(&win(&a.file), &tmp, flags, &dirs, &root);
            // the include set (a preprocessor process of its own) beside the compile while the pool has threads to
            // spare (an edit or a rename compiles one unit: ~0.2 s of 0.7 s on gildegold's main.c)
            let (files, res) = if spare {
                std::thread::scope(|s| {
                    let pre = s.spawn(|| preprocess(k));
                    let res = compile();
                    (pre.join().unwrap_or(None), res)
                })
            } else {
                (preprocess(k), compile())
            };
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

// ------------------------------------------------------------------------------------------------ a variant's objects

/// A variant's row of one unit (build/variant/<target>/<variant>.json).
#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct VariantRow {
    amalg: String,
    src_hash: String,
    flags_hash: String,
    include_hash: String,
    obj_hash: String,
    ok: bool,
    log: String,
}

pub fn variant_rows_path(p: &Project, variant: &str) -> String {
    py_path(&format!("{}/build/variant/{}/{variant}.json", p.root.to_string_lossy(), p.target_name))
}

/// The objects of a run::Variant (run.rs) of the current target: the units its flags reach, compiled with the unit's
/// flags plus the variant's, into the shared object store; staleness as `ensure` decides it, the rows in the
/// variant's own file (the store's tu table and the "objects" input stay the main build's). The report and unit ->
/// object path of every unit that compiled. The main build must be current: the other units link its objects.
pub fn ensure_variant(p: &Project, v: &crate::run::Variant, force: bool) -> Result<(Report, HashMap<String, String>), String> {
    let t0 = std::time::Instant::now();
    let root = p.root.to_string_lossy().into_owned();
    let db = p.store_path();
    crate::pystore::st_open(&db, &p.main_uri()).map_err(|e| e.to_string())?;
    let mut rep = Report { target: p.target_name.clone(), ..Default::default() };
    let units = plan::plan(p)?;
    let mine: Vec<(&Tu, Vec<String>)> = units.iter().filter_map(|a| {
        let extra = v.extra(&a.unit);
        (!extra.is_empty()).then_some((a, extra))
    }).collect();
    rep.units = mine.len();
    let tools = Tools::of(p);
    if !mine.is_empty() && !tools.available() {
        rep.unavailable = true;
        rep.log.push(format!("build: the toolchain is not available (root {}): {} units not compiled", tools.root.as_deref().unwrap_or("None"), mine.len()));
        return Ok((rep, HashMap::new()));
    }
    let path = variant_rows_path(p, &v.name);
    let old: HashMap<String, VariantRow> = std::fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    let memo = Memo::default();
    let dirs = vec!["include".to_string()];
    let mut search = vec![py_path(&format!("{root}/include"))];
    search.extend(tools.system_include().into_iter().map(|d| if Path::new(&d).is_absolute() { d } else { py_path(&format!("{root}/{d}")) }));
    let mut work: Vec<(&Tu, Vec<String>, String)> = vec![];
    for (a, extra) in mine {
        let mut flags = plan::compile_flags(p, &a.target, &a.unit)?;
        flags.extend(extra);
        let fh = sha256_parts(&[canonical(&json!(flags))]);
        work.push((a, flags, fh));
    }
    let mut rows: HashMap<String, VariantRow> = HashMap::new();
    let mut stale = vec![];
    for (k, (a, _, fh)) in work.iter().enumerate() {
        let key = sha256_parts(&[a.src_hash.clone(), fh.clone(), memo.listing_hash(&search)]);
        let files = include_set(&db, &key).map_err(|e| e.to_string())?;
        let fresh = match (&files, old.get(&a.unit)) {
            (Some(files), Some(r)) => !force && r.src_hash == a.src_hash && &r.flags_hash == fh && r.include_hash == memo.set(files) && r.amalg == a.file
                && (!r.ok || Path::new(&obj_path(&root, &r.obj_hash)).exists()),
            _ => false,
        };
        if fresh {
            rows.insert(a.unit.clone(), old[&a.unit].clone());
        } else {
            stale.push(k);
        }
    }
    if !stale.is_empty() {
        rep.log.push(format!("build: compiling {} of {} units of variant {} (target {})", stale.len(), work.len(), v.name, p.target_name));
        let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        let results = run_threads(n, &stale, |&k| {
            let (a, flags, _) = &work[k];
            let tmp = format!("build\\obj\\tmp\\{}@{}\\{}.obj", a.target, v.name, a.unit);
            let tmp_abs = py_path(&format!("{root}/{tmp}"));
            let _ = std::fs::create_dir_all(Path::new(&tmp_abs).parent().unwrap());
            let _ = std::fs::remove_file(&tmp_abs);
            let files = tools.includes(&win(&a.file), flags, &dirs, &root).ok().filter(|(_, e)| e.is_empty()).map(|(f, _)| f);
            let res = tools.compile(&win(&a.file), &tmp, flags, &dirs, &root).map(|mut r| {
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
        for (k, (res, files, obj_hash)) in stale.iter().zip(results) {
            let (a, _, fh) = &work[*k];
            let res = res?;
            let key = sha256_parts(&[a.src_hash.clone(), fh.clone(), memo.listing_hash(&search)]);
            if let Some(files) = &files {
                put_include_set(&db, &key, files).map_err(|e| e.to_string())?;
            }
            let include_hash = files.as_ref().map(|f| memo.set(f)).unwrap_or_else(|| "unknown".into());
            rows.insert(a.unit.clone(), VariantRow { amalg: a.file.clone(), src_hash: a.src_hash.clone(), flags_hash: fh.clone(), include_hash,
                                                     obj_hash: obj_hash.clone(), ok: res.ok, log: res.log.clone() });
            rep.compiled.push(a.unit.clone());
            let errs: Vec<&Diag> = res.diags.iter().filter(|d| d.severity == "error").collect();
            rep.log.push(format!("  {} {}  errors={}{}", if res.ok { "ok  " } else { "FAIL" }, a.unit, errs.len(),
                                 if obj_hash.is_empty() { String::new() } else { format!("  obj={}", &obj_hash[..12]) }));
            for d in errs.iter().take(10) {
                rep.log.push(format!("       {}", d.text()));
            }
        }
    }
    let mut failed: Vec<String> = rows.iter().filter(|(_, r)| !r.ok).map(|(u, _)| u.clone()).collect();
    failed.sort();
    rep.failed = failed;
    if !stale.is_empty() || rows.len() != old.len() {
        std::fs::create_dir_all(Path::new(&path).parent().unwrap()).map_err(|e| e.to_string())?;
        let sorted: std::collections::BTreeMap<&String, &VariantRow> = rows.iter().collect();
        std::fs::write(&path, serde_json::to_string_pretty(&sorted).unwrap_or_default()).map_err(|e| format!("{path}: {e}"))?;
    }
    let objs = rows.iter().filter(|(_, r)| r.ok).map(|(u, r)| (u.clone(), obj_path(&root, &r.obj_hash))).collect();
    rep.ms = t0.elapsed().as_millis() as i64;
    Ok((rep, objs))
}

// ------------------------------------------------------------------------------------------------ a rename's objects

/// A unit a rename touches (its file or a file of its include set), compiled and current before the write: its tu
/// row and its preprocessed text then.
pub struct Before {
    unit: String,
    flags: Vec<String>,
    obj_hash: String,
    log: String,
    diags: String,
    text: String,
}

/// The units of the current target that read one of `touched` (project-relative paths a rename is about to write)
/// and are compiled and current, each preprocessed (CL /E) as it stands. A unit without a known include set, a failed
/// or stale one is left to the build.
pub fn rename_before(p: &Project, touched: &[String]) -> Result<Vec<Before>, String> {
    let root = p.root.to_string_lossy().into_owned();
    let db = p.store_path();
    let tools = Tools::of(p);
    if touched.is_empty() || !tools.available() {
        return Ok(vec![]);
    }
    let touched: std::collections::HashSet<String> = touched.iter().map(|r| crate::vc6::resolved(&root, r).to_lowercase()).collect();
    fsmemo::new_epoch();
    p.forget_input("src");
    let units = plan::plan(p)?;
    let rows = tu_rows(&db).map_err(|e| e.to_string())?;
    let keys = tu_keys(&db).map_err(|e| e.to_string())?;
    let memo = Memo::default();
    let mut search = vec![py_path(&format!("{root}/include"))];
    search.extend(tools.system_include().into_iter().map(|d| if Path::new(&d).is_absolute() { d } else { py_path(&format!("{root}/{d}")) }));
    let mut todo: Vec<(&Tu, Vec<String>)> = vec![];
    for a in units.iter() {
        let (Some(row), Some(k)) = (rows.get(&a.unit), keys.get(&a.unit)) else { continue };
        let flags = plan::compile_flags(p, &a.target, &a.unit)?;
        let fh = sha256_parts(&[canonical(&json!(flags))]);
        let key = sha256_parts(&[a.src_hash.clone(), fh.clone(), memo.listing_hash(&search)]);
        let Some(files) = include_set(&db, &key).map_err(|e| e.to_string())? else { continue };
        let current = row.ok && k.src_hash == a.src_hash && k.flags_hash == fh && k.include_hash == memo.set(&files) && k.amalg == a.file
            && Path::new(&obj_path(&root, &k.obj_hash)).exists();
        let reads = touched.contains(&crate::vc6::resolved(&root, &a.file).to_lowercase()) || files.iter().any(|f| touched.contains(&f.to_lowercase()));
        if current && reads {
            todo.push((a, flags));
        }
    }
    let dirs = vec!["include".to_string()];
    let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let texts = run_threads(n, &todo, |(a, flags)| tools.preprocess(&win(&a.file), flags, &dirs, &root));
    let mut out = vec![];
    for ((a, flags), text) in todo.into_iter().zip(texts) {
        let (Ok(text), Some(row)) = (text?, rows.get(&a.unit)) else { continue };
        let diags = json!(row.diags.iter().map(|d| json!([d.0, d.1, d.2, d.3, d.4])).collect::<Vec<_>>());
        out.push(Before { unit: a.unit.clone(), flags, obj_hash: row.obj_hash.clone(), log: row.log.clone(), diags: canonical(&diags), text });
    }
    Ok(out)
}

/// The text with every identifier that is a key of mapping replaced by its value; string and character literals and
/// numbers stay.
fn renamed_tokens(text: &str, mapping: &std::collections::BTreeMap<String, String>) -> String {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let (mut i, mut last) = (0, 0);
    while i < b.len() {
        let c = b[i];
        if c == b'"' || c == b'\'' {
            i += 1;
            while i < b.len() && b[i] != c && b[i] != b'\n' {
                i += if b[i] == b'\\' { 2 } else { 1 };
            }
            i += 1;
        } else if c.is_ascii_digit() {
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'.') {
                i += 1;
            }
        } else if c.is_ascii_alphabetic() || c == b'_' {
            let s = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            if let Some(new) = mapping.get(&text[s..i]) {
                out.push_str(&text[last..s]);
                out.push_str(new);
                last = i;
            }
        } else {
            i += 1;
        }
    }
    out.push_str(&text[last.min(text.len())..]);
    out
}

/// The tu rows as they are (every column), for `tu_restore`: a rename refused after its write puts the sources
/// back and with them the rows, so the build finds the objects from before current instead of compiling again.
pub fn tu_snapshot(p: &Project) -> Result<Vec<Vec<rusqlite::types::Value>>, String> {
    let db = p.store_path();
    with_db(&db, |c| {
        let mut st = c.prepare("SELECT unit, amalg, src_hash, flags, flags_hash, include_hash, obj_hash, ok, log, diags, at FROM tu")?;
        let rows = st.query_map([], |r| (0..11).map(|i| r.get::<_, rusqlite::types::Value>(i)).collect::<Result<Vec<_>, _>>())?;
        rows.collect()
    }).map_err(|e| e.to_string())
}

/// Put back the tu rows of a `tu_snapshot`.
pub fn tu_restore(p: &Project, rows: &[Vec<rusqlite::types::Value>]) -> Result<(), String> {
    let db = p.store_path();
    with_db(&db, |c| {
        let tx = c.unchecked_transaction()?;
        tx.execute("DELETE FROM tu", [])?;
        {
            let mut st = tx.prepare("INSERT INTO tu (unit, amalg, src_hash, flags, flags_hash, include_hash, obj_hash, ok, log, diags, at) \
                                     VALUES (?,?,?,?,?,?,?,?,?,?,?)")?;
            for r in rows {
                st.execute(rusqlite::params_from_iter(r.iter()))?;
            }
        }
        tx.commit()
    }).map_err(|e| e.to_string())?;
    p.forget_input("objects");
    Ok(())
}

/// After a rename's write: each unit of `before` whose preprocessed text is now its text then with the old
/// identifiers replaced by the new ones (and none of the new names occurred then) compiles to the same object but
/// for the names of the renamed symbols: its object is the one from before with those symbols renamed, its tu row
/// the one from before with the new hashes (the messages name the new names). A unit whose text changed otherwise
/// (a name stringified or pasted, a macro tested by #ifdef) is left stale for the build to compile. The units reused.
pub fn rename_after(p: &Project, before: Vec<Before>, mapping: &std::collections::BTreeMap<String, String>) -> Result<Vec<String>, String> {
    if before.is_empty() {
        return Ok(vec![]);
    }
    let root = p.root.to_string_lossy().into_owned();
    let db = p.store_path();
    let tools = Tools::of(p);
    fsmemo::new_epoch();
    p.forget_input("src");
    let units = plan::plan(p)?;
    let by_unit: HashMap<&str, &Tu> = units.iter().map(|a| (a.unit.as_str(), a)).collect();
    let news: Vec<regex::Regex> = mapping.values().map(|n| regex::Regex::new(&format!(r"\b{}\b", regex::escape(n))).unwrap()).collect();
    let todo: Vec<(&Before, &Tu)> = before.iter()
        .filter(|b| !news.iter().any(|r| r.is_match(&b.text)))
        .filter_map(|b| by_unit.get(b.unit.as_str()).map(|a| (b, *a))).collect();
    let dirs = vec!["include".to_string()];
    let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let done = run_threads(n, &todo, |(b, a)| -> Result<Option<(Vec<String>, String)>, String> {
        let Ok(text) = tools.preprocess(&win(&a.file), &b.flags, &dirs, &root)? else { return Ok(None) };
        if text != renamed_tokens(&b.text, mapping) {
            return Ok(None);
        }
        let Ok(old) = std::fs::read(obj_path(&root, &b.obj_hash)) else { return Ok(None) };
        let Some(obj) = crate::coff::rename_symbols(&old, mapping) else { return Ok(None) };
        let obj_hash = fsmemo::hex(&Sha256::digest(&obj));
        let dest = obj_path(&root, &obj_hash);
        if !Path::new(&dest).exists() {
            let tmp = format!("{dest}.{}.tmp", std::process::id());
            std::fs::write(&tmp, &obj).map_err(|e| format!("{tmp}: {e}"))?;
            std::fs::rename(&tmp, &dest).map_err(|e| format!("{dest}: {e}"))?;
        }
        Ok(Some((crate::vc6::include_files(&text, &win(&a.file), &root), obj_hash)))
    });
    let memo = Memo::default();
    let mut search = vec![py_path(&format!("{root}/include"))];
    search.extend(tools.system_include().into_iter().map(|d| if Path::new(&d).is_absolute() { d } else { py_path(&format!("{root}/{d}")) }));
    let olds: Vec<(regex::Regex, &String)> = mapping.iter().map(|(o, n)| (regex::Regex::new(&format!(r"\b{}\b", regex::escape(o))).unwrap(), n)).collect();
    let words = |t: &str| olds.iter().fold(t.to_string(), |t, (r, n)| r.replace_all(&t, regex::NoExpand(n)).into_owned());
    let mut reused = vec![];
    for ((b, a), r) in todo.iter().zip(done) {
        let Some((files, obj_hash)) = r? else { continue };
        let fh = sha256_parts(&[canonical(&json!(b.flags))]);
        let key = sha256_parts(&[a.src_hash.clone(), fh.clone(), memo.listing_hash(&search)]);
        put_include_set(&db, &key, &files).map_err(|e| e.to_string())?;
        let at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0);
        with_db(&db, |c| c.execute(
            "INSERT OR REPLACE INTO tu (unit, amalg, src_hash, flags, flags_hash, include_hash, obj_hash, ok, log, diags, at) VALUES (?,?,?,?,?,?,?,1,?,?,?)",
            params![a.unit, a.file, a.src_hash, canonical(&json!(b.flags)), fh, memo.set(&files), obj_hash, words(&b.log), words(&b.diags), at])
            .map(|_| ())).map_err(|e| e.to_string())?;
        reused.push(a.unit.clone());
    }
    p.forget_input("objects");
    Ok(reused)
}

// ------------------------------------------------------------------------------------------------ Python's face

/// compile.ensure: (target, units, compiled, failed, removed, preprocessed, ms, unavailable, log lines).
#[pyfunction]
#[pyo3(signature = (project, force=false, jobs=None))]
#[allow(clippy::type_complexity)]
pub fn compile_ensure(project: PyRef<'_, crate::project::PyProject>, force: bool, jobs: Option<usize>)
    -> Result<(String, usize, Vec<String>, Vec<String>, Vec<String>, usize, i64, bool, Vec<String>)> {
    let r = ensure(&project.p, force, jobs).map_err(Error::runtime)?;
    Ok((r.target, r.units, r.compiled, r.failed, r.removed, r.preprocessed, r.ms, r.unavailable, r.log))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_renamed() {
        let m: std::collections::BTreeMap<String, String> = [("get".to_string(), "read".to_string())].into();
        let t = "#line 1 \"get.h\"\nint get(void); int getter = 0x1get; char *s = \"get\", c = 'g'; x = get;\n";
        assert_eq!(renamed_tokens(t, &m), "#line 1 \"get.h\"\nint read(void); int getter = 0x1get; char *s = \"get\", c = 'g'; x = read;\n");
    }
}
