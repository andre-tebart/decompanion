//! The analyzer seam: a third-party tool that reads the image and hands back opinions about it (function starts,
//! names, a pseudocode body per function). Ghidra (headless, its post-script DcpExport.java) and no analyzer at all
//! are the plugins (`[analyzer] plugin = ghidra | none`; the default ghidra). An analyzer's output is never a computed fact: its function starts are declared `start` facts
//! (L.analyzer), its pseudocode is draft text for `dcp draft`, its function bodies are checked against our starts
//! (L9). The rules read the stored entries (input `drafts`), never the plugin.
//!
//! Where Ghidra and its JDK are (first hit wins):
//!   Ghidra   [analyzer] root = "..." in decompanion.toml, else $GHIDRA_INSTALL_DIR, else the newest
//!            C:/Tools/ghidra_* directory holding support/analyzeHeadless(.bat)
//!   JDK      [analyzer] java_home = "...", else $JAVA_HOME, else the newest
//!            C:/Program Files/Eclipse Adoptium/jdk-21* directory (Ghidra 12 needs JDK 21)
//!   [analyzer] timeout = 60   seconds per function for the decompiler
//!
//! The run: `analyzeHeadless <out_dir> <name> -import <binary> -processor <language> -overwrite -scriptPath <dir>
//! -postScript DcpExport.java <out_dir>/export.json <timeout> starts.txt` (out_dir is build/ghidra/<target>, name its
//! last part); when the project already holds the binary, `-process <binary name> -noanalysis` instead, unless the
//! export is `fresh` (a start seeded before is no longer ours). starts.txt lists our function starts: where Ghidra has
//! no function the script creates one (`seeded`). The script writes the batch_decompile shape plus each
//! function's body (start, end, size, address ranges). The log is <out_dir>/headless.log.
//!
//! The export inside `dcp setup` (export key: sha256(analyzer key, image sha256, script hash, our starts)): run when
//! the key is stale, and replace the target's drafts with what it returned. Our starts are the function starts in the
//! code sections (every start fact but the analyzer's own, every walked or placed function; no inner label).

use crate::project::{py_path, sha256_parts, Project};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The analyzer plugins, in registration order; the default.
pub const KEYS: [&str; 2] = ["ghidra", "none"];
pub const DEFAULT: &str = "ghidra";
const KIND: &str = "drafts";
const EXPORT: &str = "drafts.export";
const STARTS: &str = "drafts.starts";
const SCRIPT: (&str, &str) = ("DcpExport.java", include_str!("../../../src/decompanion/data/ghidra/DcpExport.java"));

fn err(e: impl std::fmt::Display) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

fn posix(p: &str) -> String {
    p.replace('\\', "/")
}

/// What `available()` found: where the tool is (or the file it reads), or the reason it is not there; a note setup
/// prints although the analyzer is there.
#[derive(Default)]
pub struct Install {
    pub at: String,
    pub reason: Option<String>,
    pub note: String,
    pub root: Option<String>,
    pub headless: Option<String>,
    pub java_home: Option<String>,
    pub timeout: i64,
}

impl Install {
    pub fn ok(&self) -> bool {
        self.reason.is_none()
    }
}

/// An export: the entries (draft values), the items that failed, the analysed binary's sha256, the output files.
#[derive(Default)]
pub struct Export {
    pub entries: Vec<Value>,
    pub failed: Vec<String>,
    pub digest: String,
    pub ms: u128,
    pub out: Option<String>,
}

pub struct Analyzer {
    pub key: String,
    cfg: toml::Table,
    expand: Box<dyn Fn(&str) -> String + Send + Sync>,
}

/// The newest directory of a `<dir>/<prefix>*` pattern (by name) holding `must` (case-insensitive prefix, as
/// Windows globs).
fn newest(dir: &str, prefix: &str, must: &str) -> Option<String> {
    let mut hits: Vec<PathBuf> = std::fs::read_dir(dir).ok()?.flatten().map(|e| e.path())
        .filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().to_lowercase().starts_with(&prefix.to_lowercase())))
        .filter(|p| p.is_dir() && p.join(must).exists()).collect();
    hits.sort_by_key(|p| p.file_name().map(|n| n.to_os_string()));
    hits.last().map(|p| posix(&p.to_string_lossy()))
}

impl Analyzer {
    /// The analyzer of a project ([analyzer] plugin = ..., the default ghidra), with its table.
    pub fn of(p: &Project) -> Result<Analyzer, String> {
        let cfg = p.cfg.get("analyzer").and_then(|v| v.as_table()).cloned().unwrap_or_default();
        let key = cfg.get("plugin").and_then(|v| v.as_str()).filter(|k| !k.is_empty()).unwrap_or(DEFAULT).to_string();
        if !KEYS.contains(&key.as_str()) {
            return Err(format!("unknown analyzer plugin {} (known: {}); name one with [analyzer] plugin = ...", crate::decl::py_repr(&key), KEYS.join(", ")));
        }
        let (root, tc_root) = (p.root.to_string_lossy().into_owned(), p.toolchain_root().unwrap_or_default());
        Ok(Analyzer { key, cfg, expand: Box::new(move |s| {
            let s = s.replace("{toolchain.root}", &tc_root);
            if Path::new(&s).is_absolute() { py_path(&s) } else { py_path(&format!("{root}/{s}")) }
        }) })
    }

    /// The default analyzer without configuration (what `dcp init` looks for).
    pub fn default_unconfigured() -> Analyzer {
        Analyzer { key: DEFAULT.into(), cfg: toml::Table::new(), expand: Box::new(|s| s.to_string()) }
    }

    /// Where the tool is, or the reason it is not there (module docs).
    pub fn available(&self) -> Install {
        match self.key.as_str() {
            "none" => Install { at: "none".into(), note: "no analyzer configured: no drafts, dcp draft writes @rough skeletons".into(), ..Default::default() },
            _ => self.ghidra(),
        }
    }

    fn ghidra(&self) -> Install {
        let exe = if cfg!(windows) { "analyzeHeadless.bat" } else { "analyzeHeadless" };
        let cfg_s = |k: &str| self.cfg.get(k).and_then(|v| v.as_str()).filter(|v| !v.is_empty()).map(|v| v.to_string());
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let (root, tried) = if let Some(r) = cfg_s("root") {
            let r = posix(&(self.expand)(&r));
            (Some(r.clone()), format!("[analyzer] root = {r}"))
        } else if let Some(r) = env("GHIDRA_INSTALL_DIR") {
            (Some(posix(&r)), format!("$GHIDRA_INSTALL_DIR = {}", posix(&r)))
        } else {
            (newest("C:/Tools", "ghidra_", &format!("support/{exe}")), "C:/Tools/ghidra_*".to_string())
        };
        let Some(root) = root.filter(|r| Path::new(r).join("support").join(exe).exists()) else {
            return Install { reason: Some(format!("Ghidra not found ({tried}): set [analyzer] root = \"...\" in decompanion.toml or $GHIDRA_INSTALL_DIR to the \
                                                   installation (the folder that holds support/analyzeHeadless)")), ..Default::default() };
        };
        let java = if let Some(j) = cfg_s("java_home") {
            Some(posix(&(self.expand)(&j)))
        } else if let Some(j) = env("JAVA_HOME") {
            Some(posix(&j))
        } else {
            newest("C:/Program Files/Eclipse Adoptium", "jdk-21", "bin")
        };
        if let Some(j) = java.as_ref().filter(|j| !Path::new(j).join("bin").exists()) {
            return Install { reason: Some(format!("the JDK {j} has no bin/ ([analyzer] java_home or $JAVA_HOME)")), ..Default::default() };
        }
        let timeout = self.cfg.get("timeout").and_then(|v| v.as_integer()).unwrap_or(60);
        Install { at: root.clone(), headless: Some(format!("{root}/support/{exe}")), root: Some(root), java_home: java, timeout, ..Default::default() }
    }

    /// The hash of what makes the export besides the image and our starts (the shipped post-script).
    pub fn script_hash(&self) -> String {
        use sha2::{Digest, Sha256};
        match self.key.as_str() {
            "ghidra" => crate::fsmemo::hex(&Sha256::digest(SCRIPT.1.as_bytes())),
            _ => String::new(),
        }
    }

    /// One entry per function the tool knows; Err(message) when the tool failed.
    pub fn export(&self, inst: &Install, image: &str, isa: &str, starts: &[i64], out_dir: &str, fresh: bool) -> Result<Export, String> {
        match self.key.as_str() {
            "ghidra" => self.ghidra_export(inst, image, isa, starts, out_dir, fresh),
            _ => Ok(Export::default()),
        }
    }

    fn ghidra_export(&self, inst: &Install, image: &str, isa: &str, starts: &[i64], out_dir: &str, fresh: bool) -> Result<Export, String> {
        let lang = match isa {
            "x86" => "x86:LE:32:default",
            _ => return Err(format!("no Ghidra language for the instruction set {} (analyzers.rs)", crate::decl::py_repr(isa))),
        };
        let d = PathBuf::from(out_dir);
        std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
        let script_dir = d.join("script");
        std::fs::create_dir_all(&script_dir).map_err(|e| e.to_string())?;
        let script = script_dir.join(SCRIPT.0);
        if std::fs::read_to_string(&script).ok().as_deref() != Some(SCRIPT.1) {
            std::fs::write(&script, SCRIPT.1).map_err(|e| e.to_string())?;
        }
        let (out, log) = (d.join("export.json"), d.join("headless.log"));
        let name = d.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let binary = Path::new(image);
        let rep = d.join(format!("{name}.rep"));
        let t0 = std::time::Instant::now();
        let mut code = None;
        for attempt in 0..2 {
            let _ = std::fs::remove_file(&out);
            let idata = rep.join("idata");
            let have = !fresh && d.join(format!("{name}.gpr")).exists() && idata.exists()
                && crate::fsmemo::walk(&idata.to_string_lossy(), &["*.prp".to_string()]).first().is_some();
            let mut args: Vec<String> = vec![d.to_string_lossy().into_owned(), name.clone()];
            if have {
                args.extend(["-process".into(), binary.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(), "-noanalysis".into()]);
            } else {
                args.extend(["-import".into(), image.to_string(), "-processor".into(), lang.into(), "-overwrite".into()]);
            }
            let st = d.join("starts.txt");
            std::fs::write(&st, starts.iter().map(|a| format!("{a:#010x}\n")).collect::<String>()).map_err(|e| e.to_string())?;
            args.extend(["-scriptPath".into(), script_dir.to_string_lossy().into_owned(), "-postScript".into(), SCRIPT.0.into(), out.to_string_lossy().into_owned(),
                         inst.timeout.to_string(), st.to_string_lossy().into_owned()]);
            let logf = std::fs::File::create(&log).map_err(|e| e.to_string())?;
            let mut cmd = std::process::Command::new(inst.headless.as_deref().unwrap_or(""));
            cmd.args(&args).current_dir(&d).stdin(std::process::Stdio::null()).stdout(logf.try_clone().map_err(|e| e.to_string())?).stderr(logf);
            if let Some(j) = &inst.java_home {
                cmd.env("JAVA_HOME", j);
            }
            code = cmd.status().ok().and_then(|s| s.code());
            if out.exists() || !have || attempt == 1 {
                break;
            }
            // a stale or foreign project: import afresh, once
            let _ = std::fs::remove_file(d.join(format!("{name}.gpr")));
            let _ = std::fs::remove_dir_all(&rep);
        }
        let ms = t0.elapsed().as_millis();
        if !out.exists() {
            let text = String::from_utf8_lossy(&std::fs::read(&log).unwrap_or_default()).into_owned();
            let last = text.lines().filter(|l| l.contains("ERROR") || l.contains("Exception")).last().map(|l| l.trim().to_string());
            let first = last.unwrap_or_else(|| format!("analyzeHeadless exit {}, no export written", code.map(|c| c.to_string()).unwrap_or_else(|| "None".into())));
            return Err(format!("{first} (log: {})", posix(&log.to_string_lossy())));
        }
        let (digest, entries, failed) = parse(&out.to_string_lossy(), &self.key).map_err(|e| e.to_string())?;
        Ok(Export { entries, failed, digest, ms, out: Some(out.to_string_lossy().into_owned()) })
    }
}

fn hex_of(v: &Value) -> Result<i64, String> {
    let s = v.as_str().ok_or_else(|| format!("{v} is no address"))?;
    let t = s.trim();
    let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    i64::from_str_radix(t, 16).map_err(|_| format!("invalid literal for int() with base 16: {}", crate::decl::py_repr(s)))
}

/// A file in the batch_decompile shape (what the export script writes): (the analysed binary's sha256 or '', the ok entries as draft values, one
/// message per item that failed).
pub fn parse(path: &str, key: &str) -> Result<(String, Vec<Value>, Vec<String>), String> {
    let d: Value = serde_json::from_slice(&std::fs::read(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let digest = d["subject"]["digest"]["sha256"].as_str().unwrap_or("").to_string();
    let name = Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let (mut out, mut failed) = (vec![], vec![]);
    let py = |v: &Value| match v {
        Value::Null => "None".to_string(),
        Value::String(s) => s.clone(),
        v => v.to_string(),
    };
    for it in d["normalized_result"]["items"].as_array().cloned().unwrap_or_default() {
        if it.get("status").and_then(|s| s.as_str()) != Some("ok") || it.get("pseudocode").is_none() {
            let e = it.get("error").map(py).unwrap_or_default();
            failed.push(crate::srcscan::py_strip(&format!("{}: {} {e}", py(&it["address"]), py(&it["status"]))).to_string());
            continue;
        }
        let req = hex_of(&it["address"])?;
        let proc_ = it.get("procedure").filter(|p| p.is_object()).cloned().unwrap_or(json!({}));
        let start = match proc_.get("address").filter(|a| a.as_str().is_some_and(|s| !s.is_empty())) { Some(a) => hex_of(a)?, None => req };
        let text = it["pseudocode"].as_str().unwrap_or("").replace("\r\n", "\n").trim_matches('\n').to_string() + "\n";
        let body = it.get("body").filter(|b| b.is_object()).cloned().unwrap_or(json!({}));
        let mut v = json!({"start": start, "name": proc_.get("name").and_then(|n| n.as_str()).unwrap_or(""), "requested": req, "source": name,
                           "body": text, "analyzer": key});
        if let Some(end) = body.get("end").filter(|e| e.as_str().is_some_and(|s| !s.is_empty())) {
            let ranges: Vec<Value> = body.get("ranges").and_then(|r| r.as_array()).cloned().unwrap_or_default().iter()
                .map(|r| Ok(json!([hex_of(&r[0])?, hex_of(&r[1])?]))).collect::<Result<_, String>>()?;
            v["end"] = json!(hex_of(end)?);
            v["size"] = body.get("size").cloned().unwrap_or(Value::Null);
            v["ranges"] = json!(ranges);
        }
        if it.get("seeded").is_some_and(|s| s.as_bool() == Some(true)) {
            v["seeded"] = json!(true);
        }
        out.push(v);
    }
    Ok((digest, out, failed))
}

// ------------------------------------------------------------------------------------------------ the export in setup

/// Our function starts in the code sections (module docs).
fn our_starts(p: &Project, img: &crate::pe::Image) -> PyResult<Vec<i64>> {
    let db = p.store_path();
    let code: Vec<(i64, i64)> = img.sections.iter().filter(|s| s.holds_code()).map(|s| (s.va as i64, s.end() as i64)).collect();
    let (starts, syms) = crate::with_db(&db, |c| {
        Ok((crate::store::facts_of(c, &db, "start", None, |f| &*f.rule != "L.analyzer")?,
            crate::store::facts_of(c, &db, "symbol", None, |f| f.s("skind") == Some("func") && f.level > crate::store::OPEN && !f.rule.starts_with("M."))?))
    })?;
    let mut out: BTreeSet<i64> = starts.iter().map(|f| f.lo).collect();
    let mut inner: BTreeSet<i64> = BTreeSet::new();
    for f in syms.iter() {
        out.insert(f.lo);
        inner.extend(f.value.get("inner").and_then(|v| v.as_array()).into_iter().flatten().filter_map(|x| x.as_i64()));
    }
    Ok(out.difference(&inner).copied().filter(|a| code.iter().any(|&(lo, hi)| lo <= *a && *a < hi)).collect())
}

fn export_key(az: &Analyzer, sha: &str, starts: &[i64]) -> String {
    sha256_parts(&[az.key.clone(), sha.to_string(), az.script_hash(), starts.iter().map(|a| format!("{a:x}")).collect::<Vec<_>>().join(",")])
}

/// Make these entries the store's drafts (every older draft of this store goes) and set meta `drafts`.
fn replace(db: &str, sha: &str, entries: &[Value]) -> PyResult<usize> {
    crate::pystore::st_drop_blobs(db, KIND)?;
    let mut by_start: std::collections::BTreeMap<i64, &Value> = std::collections::BTreeMap::new();
    for e in entries {
        by_start.insert(e["start"].as_i64().unwrap_or(0), e);
    }
    let mut h = String::new();
    for (a, v) in &by_start {
        let k = sha256_parts(&[KIND.to_string(), sha.to_string(), format!("{a:08x}")]);
        let mut data = String::new();
        crate::store::canon(&mut data, v);
        crate::pystore::st_put_blob(db, &k, KIND, data.as_bytes(), true)?;
        h = sha256_parts(&[h, k, data]);
    }
    crate::pystore::st_set_meta(db, KIND, &h)?;
    Ok(by_start.len())
}

fn sha_of(p: &Project) -> PyResult<String> {
    crate::fsmemo::sha256(&p.target(None).map_err(err)?.path).map_err(err)
}

/// up-to-date | stale | none (never exported).
#[pyfunction]
pub fn analyzer_state(project: PyRef<'_, crate::project::PyProject>) -> PyResult<String> {
    state(&project.p)
}

/// up-to-date | stale | none (never exported).
pub fn state(p: &Project) -> PyResult<String> {
    let db = p.store_path();
    let Some(have) = crate::pystore::st_meta(&db, EXPORT)? else { return Ok("none".into()) };
    let az = Analyzer::of(p).map_err(crate::project::cfg_err)?;
    let img = crate::image(&p.target(None).map_err(err)?.path)?;
    let key = export_key(&az, &sha_of(p)?, &our_starts(p, &img)?);
    Ok(if have == key { "up-to-date" } else { "stale" }.into())
}

/// `dcp setup`'s analyzer step: export when the configured analyzer is available and its key is stale (or forced);
/// store the entries. {analyzer, status (unavailable | up-to-date | exported | failed), reason, where, stored, note,
/// failed, skipped, ms, out}.
fn run(py: Python<'_>, p: &Project, force: bool) -> PyResult<Value> {
    let az = Analyzer::of(p).map_err(crate::project::cfg_err)?;
    let inst = az.available();
    let mut o = json!({"analyzer": az.key, "status": "", "reason": "", "where": "", "stored": 0, "note": "", "failed": [], "ms": 0, "out": null});
    if !inst.ok() {
        o["status"] = json!("unavailable");
        o["reason"] = json!(inst.reason);
        return Ok(o);
    }
    let db = p.store_path();
    let target = p.target(None).map_err(err)?.clone();
    let img = crate::image(&target.path)?;
    let sha = sha_of(p)?;
    let starts = our_starts(p, &img)?;
    let key = export_key(&az, &sha, &starts);
    o["where"] = json!(inst.at);
    if !force && crate::pystore::st_meta(&db, EXPORT)?.as_deref() == Some(key.as_str()) {
        o["status"] = json!("up-to-date");
        o["note"] = json!(inst.note);
        return Ok(o);
    }
    let prev = crate::pystore::st_meta(&db, STARTS)?;
    let fresh = prev.is_some_and(|prev| {
        let ours: BTreeSet<i64> = starts.iter().copied().collect();
        !prev.split(',').filter(|x| !x.is_empty()).filter_map(|x| i64::from_str_radix(x, 16).ok()).all(|a| ours.contains(&a))
    });
    let isa = target.isa.clone().unwrap_or_else(|| img.default_isa().unwrap_or("").to_string());
    let out_dir = py_path(&format!("{}/build/{}/{}", p.root.to_string_lossy(), az.key, p.target_name));
    let ex = match py.detach(|| az.export(&inst, &target.path, &isa, &starts, &out_dir, fresh)) {
        Ok(ex) => ex,
        Err(e) => {
            o["status"] = json!("failed");
            o["reason"] = json!(e);
            return Ok(o);
        }
    };
    o["failed"] = json!(ex.failed);
    o["ms"] = json!(ex.ms as u64);
    o["out"] = json!(ex.out);
    if !ex.digest.is_empty() && ex.digest != sha {
        o["status"] = json!("failed");
        o["reason"] = json!(format!("{} analysed sha256 {}, target {} is {}", az.key, &ex.digest[..16.min(ex.digest.len())], p.target_name, &sha[..16]));
        return Ok(o);
    }
    let n = replace(&db, &sha, &ex.entries)?;
    crate::pystore::st_set_meta(&db, EXPORT, &key)?;
    crate::pystore::st_set_meta(&db, STARTS, &starts.iter().map(|a| format!("{a:x}")).collect::<Vec<_>>().join(","))?;
    p.forget_input("drafts");
    o["status"] = json!("exported");
    o["stored"] = json!(n);
    o["note"] = json!(inst.note);
    Ok(o)
}

/// `dcp setup`'s analyzer step, printed: (stdout lines, stderr lines, ok (False: the export failed), exported (the
/// caller refreshes the rules)).
#[pyfunction]
pub fn analyzer_step(py: Python<'_>, project: PyRef<'_, crate::project::PyProject>, force: bool) -> PyResult<(Vec<String>, Vec<String>, bool, bool)> {
    use crate::cliread::{record, Tok};
    let p = &project.p;
    let o = run(py, p, force)?;
    let st = |k: &str| o[k].as_str().unwrap_or("").to_string();
    let (a, reason) = (st("analyzer"), st("reason"));
    let (mut out, mut errs) = (vec![], vec![]);
    match st("status").as_str() {
        "unavailable" => errs.push(format!("analyzer={a} unavailable: {reason}")),
        "failed" => return Ok((out, vec![format!("analyzer={a} failed: {reason}")], false, false)),
        "exported" => {
            let root = posix(&p.root.to_string_lossy());
            let rel = o["out"].as_str().map(posix).and_then(|x| x.strip_prefix(&format!("{root}/")).map(|r| r.to_string()));
            let failed: Vec<String> = o["failed"].as_array().map(|f| f.iter().filter_map(|x| x.as_str().map(|x| x.to_string())).collect()).unwrap_or_default();
            out.push(record(&[("analyzer", Tok::S(a.clone())), ("exported", Tok::I(o["stored"].as_i64().unwrap_or(0))), ("failed", Tok::I(failed.len() as i64)),
                              ("ms", Tok::I(o["ms"].as_i64().unwrap_or(0))), ("where", Tok::S(st("where"))), ("out", rel.map(Tok::S).unwrap_or(Tok::No))]));
            out.extend(failed.iter().take(20).map(|f| format!("  failed  {f}")));
        }
        _ => {}
    }
    let note = st("note");
    if !note.is_empty() {
        errs.push(format!("analyzer={a}: {note}"));
    }
    Ok((out, errs, true, st("status") == "exported"))
}

/// The analyzer of a project and what `available()` found: {key, ok, where, reason, note, root, java_home}.
#[pyfunction]
pub fn analyzer_available<'py>(py: Python<'py>, project: PyRef<'py, crate::project::PyProject>) -> PyResult<Bound<'py, PyAny>> {
    let az = Analyzer::of(&project.p).map_err(crate::project::cfg_err)?;
    install_py(py, &az.key, &az.available())
}

fn install_py<'py>(py: Python<'py>, key: &str, i: &Install) -> PyResult<Bound<'py, PyAny>> {
    crate::pystore::json_py(py, &json!({"key": key, "ok": i.ok(), "where": i.at, "reason": i.reason, "note": i.note, "root": i.root, "java_home": i.java_home}))
}

/// The default analyzer without configuration and what it finds (`dcp init`'s [analyzer] keys).
#[pyfunction]
pub fn analyzer_default<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
    let az = Analyzer::default_unconfigured();
    install_py(py, &az.key, &az.available())
}

/// The analyzer plugins (the default first).
#[pyfunction]
pub fn analyzer_keys() -> Vec<&'static str> {
    KEYS.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped script's hash is the file's (the export key of a project does not change with the port).
    #[test]
    fn script_hash_is_the_files() {
        use sha2::{Digest, Sha256};
        let f = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../src/decompanion/data/ghidra/DcpExport.java")).unwrap();
        assert_eq!(Analyzer::default_unconfigured().script_hash(), crate::fsmemo::hex(&Sha256::digest(&f)));
    }

    #[test]
    fn batch_decompile_shape() {
        let dir = std::env::temp_dir().join(format!("dcp-az-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("batch.json");
        std::fs::write(&f, r#"{"subject": {"digest": {"sha256": "ab"}}, "normalized_result": {"items": [
            {"address": "0x401000", "status": "ok", "procedure": {"address": "0x401000", "name": "FUN_00401000"}, "pseudocode": "\r\nvoid f(void)\r\n{\r\n}\r\n\n",
             "body": {"start": "0x401000", "end": "0x401010", "size": 16, "ranges": [["0x401000", "0x401010"]]}, "seeded": true},
            {"address": "0x401020", "status": "ok", "procedure": {}, "pseudocode": "int g(void) { return 0; }"},
            {"address": "0x401040", "status": "error", "error": "timeout"},
            {"address": "0x401060", "status": "ok"}]}}"#).unwrap();
        let (digest, entries, failed) = parse(&f.to_string_lossy(), "ghidra").unwrap();
        assert_eq!(digest, "ab");
        assert_eq!(entries[0], json!({"start": 0x401000, "name": "FUN_00401000", "requested": 0x401000, "source": "batch.json", "body": "void f(void)\n{\n}\n",
                                       "analyzer": "ghidra", "end": 0x401010, "size": 16, "ranges": [[0x401000, 0x401010]], "seeded": true}));
        assert_eq!(entries[1]["start"], 0x401020);
        assert_eq!(failed, ["0x401040: error timeout", "0x401060: ok"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
