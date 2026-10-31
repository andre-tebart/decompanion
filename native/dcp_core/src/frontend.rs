//! The source scan's orchestration (ledger/srcscan.py is its face): every project file as each target's compile
//! sees it, read by the front end (libclang, clang.rs) and scanned per file (srcscan.rs scan_file).
//!
//! - The front end: the project's libclang (`[lint] libclang = "<path>"`, else the libclang.dll beside `clang` on
//!   PATH, else the LLVM default install path), the toolchain's headers as system headers, include/ for the
//!   quoted includes, the target's `DCP_TARGET_<name>` defined.
//! - models: each unit file src/<unit>.c is one translation unit; a header takes the model of the first unit (by
//!   name) that includes it; a file no unit holds is parsed alone. Each parse is kept by its text, arguments and
//!   libclang (in memory and in build/cache/cparse/<key>.json) as long as every file it read is unchanged. The
//!   parses a scan needs run on threads, each with its own index; a lone one (the unit an edit changed) stays live
//!   for its next reparse (LIVE units at most).
//! - scan: every file's piece, kept while its text and its models are the same (an edit scans only the files it
//!   changed), joined; the L16 guards over the whole tree; memoised per tree hash.

use crate::clang::{self, FileModel, ModelOut, Unit};
use crate::fsmemo;
use crate::project::{py_path, sha256_parts, Project};
use crate::srcscan::{self, FilePart};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

pub const ARGS: [&str; 9] = ["--target=i386-pc-windows-msvc", "-fms-compatibility", "-fms-extensions", "-fms-compatibility-version=12",
                             "-std=gnu89", "-ferror-limit=0", "-Wno-everything", "-Wdeprecated-non-prototype",
                             "-Wimplicit-function-declaration"];
const DEFAULT_LIBCLANG: &str = "C:/Program Files/LLVM/bin/libclang.dll";
pub const NOT_FOUND: &str = "libclang not found ([lint] libclang = ... in decompanion.toml, or an LLVM installation: clang on PATH or C:/Program Files/LLVM)";
const MODEL_VERSION: &str = "19"; // bump when the scan's translation units change
const CPARSE_VERSION: &str = "4";
const LIVE: usize = 4;

fn err(e: impl std::fmt::Display) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

/// clang on PATH.
fn which_clang() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join("clang.exe")).find(|p| p.is_file())
}

/// The libclang to load for a configuration (None: the defaults only); None when there is none.
pub fn library(cfg: Option<&toml::Table>) -> Option<String> {
    let want = cfg.and_then(|c| c.get("lint")).and_then(|l| l.get("libclang")).and_then(|v| v.as_str());
    let cands: Vec<PathBuf> = match want {
        Some(w) => vec![PathBuf::from(w)],
        None => which_clang().map(|c| c.with_file_name("libclang.dll")).into_iter().chain([PathBuf::from(DEFAULT_LIBCLANG)]).collect(),
    };
    cands.into_iter().find(|c| c.exists()).map(|c| c.to_string_lossy().into_owned())
}

/// The macro every compile of a target defines (a function of some targets only stands under `#if` on it).
pub fn target_macro(name: &str) -> String {
    format!("DCP_TARGET_{}", name.chars().map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' }).collect::<String>())
}

/// What a parse of the project needs: its root, the system include directories, the include directories, the
/// targets with the macros their compiles define (the default first; one unnamed target without a configuration).
pub struct Front {
    pub root: String,
    pub sysdirs: Vec<String>,
    pub incdirs: Vec<String>,
    pub targets: Vec<(Option<String>, Vec<String>)>,
}

impl Front {
    /// The project at root's front end, its libclang loaded.
    pub fn of(root: &str) -> Result<Front, String> {
        let r = Path::new(root);
        let incdirs = vec![py_path(&r.join("include").to_string_lossy())];
        if !r.join(crate::project::CONFIG_NAME).exists() {
            clang::load(&library(None).ok_or(NOT_FOUND)?)?;
            return Ok(Front { root: root.into(), sysdirs: vec![], incdirs, targets: vec![(None, vec![])] });
        }
        let p = Project::open(r, None, "")?;
        clang::load(&library(Some(&p.cfg)).ok_or(NOT_FOUND)?)?;
        Ok(Front { root: root.into(), sysdirs: system_dirs(&p), incdirs, targets: p.targets.iter().map(|t| (Some(t.name.clone()), vec![target_macro(&t.name)])).collect() })
    }

    pub fn args(&self, defines: &[String]) -> Vec<String> {
        let mut a: Vec<String> = ARGS.iter().map(|s| s.to_string()).collect();
        for d in &self.sysdirs {
            a.push("-isystem".into());
            a.push(d.clone());
        }
        a.extend(self.incdirs.iter().map(|d| format!("-I{d}")));
        a.extend(defines.iter().map(|d| format!("-D{d}")));
        a
    }
}

/// The toolchain's header directories that exist (VC6: [toolchain] include_dirs, then VC98/Include of the root).
pub fn system_dirs(p: &Project) -> Vec<String> {
    let root = p.toolchain_root();
    let raw = p.cfg.get("toolchain").and_then(|t| t.get("include_dirs")).and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let mut out: Vec<String> = raw.iter().filter_map(|v| v.as_str())
        .map(|s| py_path(&s.replace("{toolchain.root}", root.as_deref().unwrap_or("")))).collect();
    if let Some(r) = root {
        out.push(py_path(&format!("{r}/VC98/Include")));
    }
    out.retain(|d| Path::new(d).exists());
    out
}

// ------------------------------------------------------------------------------------------------ the models

type Files = Arc<Vec<(String, Arc<FileModel>)>>;

#[derive(serde::Serialize, serde::Deserialize)]
struct Kept {
    deps: Vec<(String, String)>,
    files: Vec<(String, FileModel)>,
}

struct LiveUnit {
    key: (String, Vec<String>),
    text: String,
    deps: Vec<(String, String)>,
    unit: Unit,
}

static MODELS: std::sync::LazyLock<Mutex<HashMap<String, (Vec<(String, String)>, Files)>>> = std::sync::LazyLock::new(Default::default);
static LAST_DEPS: std::sync::LazyLock<Mutex<HashMap<String, Vec<String>>>> = std::sync::LazyLock::new(Default::default);
static LIVE_UNITS: std::sync::LazyLock<Mutex<VecDeque<LiveUnit>>> = std::sync::LazyLock::new(Default::default);

fn unchanged(deps: &[(String, String)]) -> bool {
    deps.iter().all(|(d, h)| fsmemo::sha256(d).is_ok_and(|x| x == *h))
}

fn deps_of(paths: &[String]) -> Result<Vec<(String, String)>, String> {
    let mut ps: Vec<&String> = paths.iter().collect();
    ps.sort();
    ps.dedup();
    ps.into_iter().map(|d| fsmemo::sha256(d).map(|h| (d.clone(), h)).map_err(|e| format!("{d}: {e}"))).collect()
}

fn files_of(m: ModelOut) -> Files {
    Arc::new(m.files.into_iter().map(|(r, f)| (r, Arc::new(f))).collect())
}

/// A kept model whose dependencies (every file the parse read) are unchanged, else None.
fn model_hit(root: &str, key: &str) -> Option<Files> {
    let hit = MODELS.lock().unwrap().get(key).cloned();
    let hit = match hit {
        Some(h) => h,
        None => {
            let path = Path::new(root).join("build").join("cache").join("cparse").join(format!("{key}.json"));
            let k: Kept = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
            (k.deps, Arc::new(k.files.into_iter().map(|(r, f)| (r, Arc::new(f))).collect()))
        }
    };
    if !unchanged(&hit.0) {
        return None;
    }
    MODELS.lock().unwrap().insert(key.to_string(), hit.clone());
    Some(hit.1)
}

fn model_keep(root: &str, key: &str, m: &ModelOut, files: &Files) {
    if m.missing {
        return;
    }
    let Ok(deps) = deps_of(&m.deps) else { return };
    MODELS.lock().unwrap().insert(key.to_string(), (deps.clone(), files.clone()));
    let build = Path::new(root).join("build");
    if build.is_dir() {
        let path = build.join("cache").join("cparse").join(format!("{key}.json"));
        let kept = Kept { deps, files: files.iter().map(|(r, f)| (r.clone(), (**f).clone())).collect() };
        if let Ok(data) = serde_json::to_vec(&kept) {
            let _ = std::fs::create_dir_all(path.parent().unwrap());
            let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
            if std::fs::write(&tmp, data).is_ok() {
                let _ = std::fs::rename(&tmp, &path);
            }
        }
    }
}

/// One parse's model; `keep`: the unit stays live (its next parse with the same arguments while the files it read
/// are unchanged reparses it over its preamble).
pub fn parse_model(root: &str, path: &str, args: &[String], text: &str, keep: bool) -> Result<ModelOut, String> {
    with_parse(path, args, text, keep, |u| u.model_out(root, text).map_err(|e| e.to_string()))
}

/// f of a parse of the text; `keep`: the parse is (or becomes) a live unit (parse_model).
pub fn with_parse<R>(path: &str, args: &[String], text: &str, keep: bool, f: impl FnOnce(&Unit) -> Result<R, String>) -> Result<R, String> {
    if !keep {
        let u = clang::parse(path, args, text, false)?;
        return f(&u);
    }
    let key = (path.to_lowercase(), args.to_vec());
    let hit = {
        let mut live = LIVE_UNITS.lock().unwrap();
        live.iter().position(|l| l.key == key).and_then(|i| live.remove(i))
    };
    let mut lu = match hit {
        Some(mut l) if unchanged(&l.deps) => {
            if l.text != text {
                l.unit.reparse_text(text)?;
                l.deps = deps_of(&l.unit.included().map_err(|e| e.to_string())?)?;
                l.text = text.to_string();
            }
            l
        }
        _ => {
            let unit = clang::parse(path, args, text, true)?;
            let deps = deps_of(&unit.included().map_err(|e| e.to_string())?)?;
            LiveUnit { key, text: text.to_string(), deps, unit }
        }
    };
    let m = f(&lu.unit);
    let mut live = LIVE_UNITS.lock().unwrap();
    lu.text = text.to_string();
    live.push_back(lu);
    while live.len() > LIVE {
        live.pop_front();
    }
    m
}

/// Run parses on threads (each its own index): their models in order.
fn parse_all(root: &str, jobs: &[(String, String, Vec<String>, String)]) -> Vec<Result<ModelOut, String>> {
    if jobs.len() == 1 {
        let (_, path, args, text) = &jobs[0];
        return vec![parse_model(root, path, args, text, true)];
    }
    let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).min(jobs.len().max(1));
    let next = std::sync::atomic::AtomicUsize::new(0);
    let out: Mutex<Vec<Option<Result<ModelOut, String>>>> = Mutex::new((0..jobs.len()).map(|_| None).collect());
    std::thread::scope(|s| {
        for _ in 0..n {
            s.spawn(|| loop {
                let k = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if k >= jobs.len() {
                    break;
                }
                let (_, path, args, text) = &jobs[k];
                let r = parse_model(root, path, args, text, false);
                out.lock().unwrap()[k] = Some(r);
            });
        }
    });
    out.into_inner().unwrap().into_iter().map(|r| r.unwrap()).collect()
}

fn is_unit_file(rel: &str) -> bool {
    rel.strip_prefix("src/").is_some_and(|r| r.ends_with(".c") && !r.contains('/'))
}

/// rel -> the front end's model of that file as a compile with `defines` sees it (module docstring).
pub fn models(front: &Front, files: &[(String, String)], defines: &[String]) -> Result<HashMap<String, Arc<FileModel>>, String> {
    let version = clang_version()?;
    let args = front.args(defines);
    let mut args_text = String::new();
    crate::store::canon(&mut args_text, &serde_json::json!(args));
    let key_of = |path: &str, rel: &str| -> Result<String, String> {
        let sha = fsmemo::sha256(path).map_err(|e| format!("{path}: {e}"))?;
        Ok(sha256_parts(&["srcscan.model", MODEL_VERSION, CPARSE_VERSION, &version, &args_text, path, &format!("{rel}={sha}")]))
    };
    let run = |tus: Vec<(String, String)>| -> Result<Vec<Files>, String> {
        let mut got: Vec<Option<Files>> = vec![None; tus.len()];
        let mut misses = vec![];
        for (k, (key, path)) in tus.iter().enumerate() {
            match model_hit(&front.root, key) {
                Some(h) => {
                    let deps = MODELS.lock().unwrap().get(key).map(|x| x.0.iter().map(|d| d.0.clone()).collect()).unwrap_or_default();
                    LAST_DEPS.lock().unwrap().insert(path.clone(), deps);
                    got[k] = Some(h);
                }
                None => {
                    let text = fsmemo::read_text(path).map_err(|e| format!("{path}: {e}"))?;
                    misses.push((k, (key.clone(), path.clone(), args.clone(), text)));
                }
            }
        }
        let jobs: Vec<(String, String, Vec<String>, String)> = misses.iter().map(|m| m.1.clone()).collect();
        for ((k, (key, path, _, _)), m) in misses.iter().zip(parse_all(&front.root, &jobs)) {
            let m = m?;
            let files = files_of(ModelOut { files: m.files.clone(), deps: m.deps.clone(), missing: m.missing });
            model_keep(&front.root, key, &m, &files);
            LAST_DEPS.lock().unwrap().insert(path.clone(), m.deps.clone());
            got[*k] = Some(files);
        }
        Ok(got.into_iter().map(|g| g.unwrap()).collect())
    };
    let mut out: HashMap<String, Arc<FileModel>> = HashMap::new();
    let units: Vec<(String, String)> = files.iter().filter(|(rel, _)| is_unit_file(rel)).map(|(rel, p)| Ok((key_of(p, rel)?, p.clone()))).collect::<Result<_, String>>()?;
    for fs in run(units)? {
        for (rel, m) in fs.iter() {
            out.entry(rel.clone()).or_insert_with(|| m.clone());
        }
    }
    let alone: Vec<&(String, String)> = files.iter().filter(|(rel, _)| !out.contains_key(rel)).collect();
    let tus: Vec<(String, String)> = alone.iter().map(|(rel, p)| Ok((key_of(p, rel)?, p.clone()))).collect::<Result<_, String>>()?;
    for ((rel, _), fs) in alone.iter().zip(run(tus)?) {
        let m = fs.iter().find(|(r, _)| r == rel).map(|(_, m)| m.clone()).unwrap_or_default();
        out.insert(rel.clone(), m);
    }
    Ok(out)
}

fn clang_version() -> Result<String, String> {
    Python::attach(|_| clang::clang_version()).map_err(|e| e.to_string())
}

/// (path relative to root, full path) of src/**/*.c, src/**/*.h and include/**/*.h, in the scan's order.
pub fn project_files(root: &str) -> Vec<(String, String)> {
    let mut files = vec![];
    for (d, pats) in [("src", vec!["*.c".to_string(), "*.h".to_string()]), ("include", vec!["*.h".to_string()])] {
        let base = py_path(&Path::new(root).join(d).to_string_lossy());
        if Path::new(&base).exists() {
            let mut fs: Vec<(String, String)> = fsmemo::walk(&base, &pats).into_iter().map(|(r, p)| (format!("{d}/{r}"), p)).collect();
            fs.sort();
            fs.dedup();
            fs.sort_by_key(|t| t.0.to_lowercase());
            files.extend(fs);
        }
    }
    files
}

// ------------------------------------------------------------------------------------------------ the scan

/// A scanned tree: every file's part joined (the files' parts in file order), the scan's own errors (L16), the
/// models it was scanned with.
pub struct Scan {
    pub parts: Vec<Rc<FilePart>>,
    pub own_errors: Vec<srcscan::ErrRow>,
    pub files: usize,
    pub models: HashMap<String, Arc<FileModel>>,
    pub target_models: Vec<(Option<String>, HashMap<String, Arc<FileModel>>)>,
}

impl Scan {
    pub fn piece_ids(&self) -> Vec<u64> {
        self.parts.iter().map(|p| p.piece.id()).collect()
    }

    /// The hash of what the native rules read of the scan (its files' pieces, its own errors).
    pub fn digest(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        for p in &self.parts {
            h.update(p.piece.digest().as_bytes());
        }
        let r = |s: &str| crate::decl::py_repr(s);
        let rows: Vec<String> = self.own_errors.iter().map(|(f, l, c, m)| format!("({}, {}, {l}, {})", r(c), r(f), r(m))).collect();
        h.update(format!("[{}]", rows.join(", ")).as_bytes());
        fsmemo::hex(&h.finalize())
    }

    pub fn functions(&self) -> impl Iterator<Item = &srcscan::FnRow> {
        self.parts.iter().flat_map(|p| p.functions.iter())
    }
}

type FileKey = (String, String, String); // root, rel, sha256

thread_local! {
    static SCANS: RefCell<Vec<((String, String), Rc<Scan>)>> = const { RefCell::new(Vec::new()) };
    static PARTS: RefCell<HashMap<FileKey, (Vec<Arc<FileModel>>, Rc<FilePart>)>> = RefCell::new(HashMap::new());
}

fn address_for(addrs: &[(Option<String>, u64)], target: &str, default: &str) -> Option<u64> {
    addrs.iter().find(|(t, _)| t.as_deref().unwrap_or(default) == target).map(|x| x.1)
}

/// L16: a function compiled into a target its address comment does not list, or listed for a target whose compile
/// does not hold it (its `#if` on the DCP_TARGET_<name> macros).
fn guards(functions: &[&srcscan::FnRow], targets: &[String]) -> Vec<srcscan::ErrRow> {
    let mut out = vec![];
    for ((file, line, _, name, addrs, unlinked, _), (.., ts)) in functions.iter().map(|f| (&f.0, &f.1)) {
        if *unlinked || ts.is_empty() || addrs.iter().any(|(t, _)| t.as_ref().is_some_and(|t| !targets.contains(t))) {
            continue;
        }
        let listed: Vec<&String> = targets.iter().filter(|t| address_for(addrs, t, &targets[0]).is_some()).collect();
        let extra: Vec<&String> = ts.iter().filter(|t| !listed.contains(t)).collect();
        let missing: Vec<&String> = listed.iter().copied().filter(|t| !ts.contains(t)).collect();
        let join = |xs: &[&String]| xs.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
        if !extra.is_empty() {
            out.push((file.clone(), *line, "L16".to_string(), format!(
                "{name} is compiled into {}, its address comment lists no address there (guard it: #if on {})", join(&extra),
                listed.iter().map(|t| target_macro(t)).collect::<Vec<_>>().join(", "))));
        }
        if !missing.is_empty() {
            out.push((file.clone(), *line, "L16".to_string(), format!("{name}: its address comment lists {}, whose compile does not hold it (its #if)", join(&missing))));
        }
    }
    out
}

/// Scan the project at root (memoised per tree hash): every file as each target's compile sees it.
pub fn scan(root: &str, tree_hash: Option<&str>) -> Result<Rc<Scan>, String> {
    if let Some(t) = tree_hash {
        if let Some(s) = SCANS.with(|c| c.borrow().iter().find(|(k, _)| k.0 == root && k.1 == t).map(|x| x.1.clone())) {
            return Ok(s);
        }
    }
    let front = Front::of(root)?;
    let files = project_files(root);
    let mut per_target: Vec<(Option<String>, HashMap<String, Arc<FileModel>>)> = vec![];
    for (t, d) in &front.targets {
        per_target.push((t.clone(), models(&front, &files, d)?));
    }
    let default_named = front.targets[0].0.is_some();
    let empty = Arc::new(FileModel::default());
    let mut parts = vec![];
    let mut used: HashMap<FileKey, (Vec<Arc<FileModel>>, Rc<FilePart>)> = HashMap::new();
    for (rel, p) in &files {
        let m = per_target[0].1.get(rel).cloned().unwrap_or_else(|| empty.clone());
        let views: Vec<(Option<String>, Arc<FileModel>)> = if default_named {
            per_target.iter().map(|(t, ms)| (t.clone(), ms.get(rel).cloned().unwrap_or_else(|| empty.clone()))).collect()
        } else {
            vec![]
        };
        let held: Vec<Arc<FileModel>> = std::iter::once(m.clone()).chain(views.iter().map(|v| v.1.clone())).collect();
        let key = (root.to_string(), rel.clone(), fsmemo::sha256(p).map_err(|e| format!("{p}: {e}"))?);
        let hit = PARTS.with(|c| c.borrow().get(&key).filter(|(h, _)| h.len() == held.len() && h.iter().zip(&held).all(|(a, b)| Arc::ptr_eq(a, b)))
            .map(|x| x.1.clone()));
        let part = match hit {
            Some(x) => x,
            None => {
                let text = fsmemo::read_text(p).map_err(|e| format!("{p}: {e}"))?;
                let vs: Vec<(Option<String>, &FileModel)> = views.iter().map(|(t, m)| (t.clone(), &**m)).collect();
                Rc::new(Python::attach(|_| srcscan::scan_file_rs(rel, &text, &m, &vs)).map_err(|e| e.to_string())?)
            }
        };
        used.insert(key, (held, part.clone()));
        parts.push(part);
    }
    PARTS.with(|c| {
        let mut c = c.borrow_mut();
        c.retain(|k, _| k.0 != root);
        c.extend(used);
    });
    let mut own_errors = vec![];
    if default_named {
        let targets: Vec<String> = front.targets.iter().filter_map(|t| t.0.clone()).collect();
        let fns: Vec<&srcscan::FnRow> = parts.iter().flat_map(|p| p.functions.iter()).collect();
        own_errors = guards(&fns, &targets);
    }
    let models = per_target[0].1.clone();
    let s = Rc::new(Scan { files: parts.len(), parts, own_errors, models, target_models: per_target });
    if let Some(t) = tree_hash {
        SCANS.with(|c| {
            let mut c = c.borrow_mut();
            if c.len() > 2 {
                c.clear();
            }
            c.push(((root.to_string(), t.to_string()), s.clone()));
        });
    }
    Ok(s)
}

/// (raw macro names (Q4), described addresses (Q6)) over every source and header of a scan.
pub fn context(s: &Scan) -> (Vec<String>, Vec<i64>) {
    use std::sync::LazyLock;
    static DEREF_CAST: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"\*\s*\(\s*(?:const\s+|volatile\s+|unsigned\s+|signed\s+|struct\s+|union\s+|enum\s+)*[A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*\s*\*+\s*(?:const\s*)?\)").unwrap()
    });
    let mut defs: Vec<(&str, &str)> = vec![];
    let mut seen = std::collections::HashSet::new();
    for p in &s.parts {
        for (n, b) in &p.macros {
            if seen.insert(n.as_str()) {
                defs.push((n, b));
            }
        }
    }
    let obj: std::collections::BTreeSet<&str> = s.parts.iter().flat_map(|p| p.rawobj.iter().map(|x| x.as_str())).collect();
    let mut raw: std::collections::BTreeSet<&str> = defs.iter().filter(|(_, b)| DEREF_CAST.is_match(b)).map(|(n, _)| *n).collect();
    raw.extend(obj.iter().copied());
    while !raw.is_empty() {
        let fns: Vec<String> = raw.iter().filter(|n| !obj.contains(*n)).map(|n| regex::escape(n)).collect();
        let mut alts = vec![];
        if !fns.is_empty() {
            alts.push(format!(r"\b({})\s*\(", fns.join("|")));
        }
        if !obj.is_empty() {
            alts.push(format!(r"\b({})\b", obj.iter().map(|n| regex::escape(n)).collect::<Vec<_>>().join("|")));
        }
        let pat = regex::Regex::new(&alts.join("|")).unwrap();
        let more: Vec<&str> = defs.iter().filter(|(n, b)| !raw.contains(n) && pat.is_match(b)).map(|(n, _)| *n).collect();
        if more.is_empty() {
            break;
        }
        raw.extend(more);
    }
    let mut described: Vec<i64> = s.parts.iter().flat_map(|p| p.described.iter().map(|&a| a as i64)).collect();
    described.sort();
    described.dedup();
    (raw.into_iter().map(|x| x.to_string()).collect(), described)
}

// ------------------------------------------------------------------------------------------------ Python's face

/// A scanned tree as srcscan.Scan's readers see it (srcscan.py makes its dataclasses of the rows).
#[pyclass(unsendable)]
pub struct ScanObj {
    pub s: Rc<Scan>,
}

fn rows<'py, T: pyo3::IntoPyObject<'py> + Clone>(py: Python<'py>, xs: impl Iterator<Item = T>) -> PyResult<Bound<'py, PyList>> {
    PyList::new(py, xs)
}

#[pymethods]
impl ScanObj {
    #[getter]
    fn files(&self) -> usize {
        self.s.files
    }

    /// The rows of Function: ((file, line, unit, name, addrs, unlinked, what), (deep, stuck, rough, comment line,
    /// static, end line, targets)).
    #[getter]
    fn function_rows<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        rows(py, self.s.functions().cloned())
    }

    #[getter]
    fn data_rows<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        rows(py, self.s.parts.iter().flat_map(|p| p.data.iter().cloned()))
    }

    #[getter]
    fn placeholder_rows<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        rows(py, self.s.parts.iter().flat_map(|p| p.placeholders.iter().cloned()))
    }

    /// Every file's errors, then the scan's own (L16).
    #[getter]
    fn error_rows<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        rows(py, self.s.parts.iter().flat_map(|p| p.errors.iter().cloned()).chain(self.s.own_errors.iter().cloned()))
    }

    #[getter]
    fn own_error_rows<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        rows(py, self.s.own_errors.iter().cloned())
    }

    #[getter]
    fn macros<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        rows(py, self.s.parts.iter().flat_map(|p| p.macros.iter().cloned()))
    }

    #[getter]
    fn described(&self) -> Vec<u64> {
        self.s.parts.iter().flat_map(|p| p.described.iter().copied()).collect()
    }

    #[getter]
    fn ptrcast_rows<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        rows(py, self.s.parts.iter().flat_map(|p| p.ptrcasts.iter().cloned()))
    }

    #[getter]
    fn view_rows<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        rows(py, self.s.parts.iter().flat_map(|p| p.views.iter().cloned()))
    }

    #[getter]
    fn rawobj(&self) -> Vec<String> {
        self.s.parts.iter().flat_map(|p| p.rawobj.iter().cloned()).collect()
    }

    /// The ids of its files' pieces in the core.
    #[getter]
    fn piece_ids(&self) -> Vec<u64> {
        self.s.piece_ids()
    }

    fn digest(&self) -> String {
        self.s.digest()
    }

    /// The default target's model of a file (the empty model when it has none).
    fn model<'py>(&self, py: Python<'py>, rel: &str) -> PyResult<Bound<'py, PyDict>> {
        clang::file_model_py(py, self.s.models.get(rel).map(|m| &**m).unwrap_or(&FileModel::default()))
    }

    /// (raw macro names, described addresses) of the tree (G.grade's Q4 / Q6 context).
    fn context(&self) -> (Vec<String>, Vec<i64>) {
        context(&self.s)
    }
}

/// srcscan.scan: the scan of the project at root (memoised per tree hash).
#[pyfunction]
#[pyo3(signature = (root, tree_hash=None))]
pub fn front_scan(py: Python<'_>, root: &str, tree_hash: Option<&str>) -> PyResult<ScanObj> {
    let _ = py;
    Ok(ScanObj { s: scan(root, tree_hash).map_err(err)? })
}

/// The front end's model of one text parsed alone (no unit around it): {files, deps, missing}'s entry for rel.
#[pyfunction]
pub fn front_model_alone<'py>(py: Python<'py>, root: &str, rel: &str, text: &str) -> PyResult<Bound<'py, PyDict>> {
    let front = py.detach(|| Front::of(root)).map_err(err)?;
    let path = py_path(&Path::new(root).join(rel).to_string_lossy());
    let m = py.detach(|| parse_model(root, &path, &front.args(&[]), text, false)).map_err(err)?;
    let r = Path::new(rel).to_string_lossy().replace('\\', "/");
    clang::file_model_py(py, m.files.iter().find(|(x, _)| *x == r).map(|x| &x.1).unwrap_or(&FileModel::default()))
}

/// The unit files' last parses' dependencies (what local_refs reads): path -> files read.
#[pyfunction]
pub fn front_last_deps(path: &str) -> Vec<String> {
    LAST_DEPS.lock().unwrap().get(path).cloned().unwrap_or_default()
}

/// The front end's arguments and system directories of the project at root: (sysdirs, incdirs, targets).
#[pyfunction]
#[allow(clippy::type_complexity)]
pub fn front_of(root: &str) -> PyResult<(Vec<String>, Vec<String>, Vec<(Option<String>, Vec<String>)>)> {
    let f = Front::of(root).map_err(err)?;
    Ok((f.sysdirs, f.incdirs, f.targets))
}
