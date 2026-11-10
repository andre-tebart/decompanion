//! The project: decompanion.toml and what hangs off it that is plain data: the target, its toolchain and
//! library-archive declarations with their reasons, the obligations an input waits on, and the content hashes of
//! the named external inputs.
//!
//! decompanion.toml
//!   [target]       name, path, sha256; compiler, linker, cflags, archives; reason.<key> (or reason = "..." for every
//!                  key of the table). The name (the store's file name, the ledgers' first column, `target=` in the
//!                  output) defaults to the binary's stem.
//!   [toolchain]    root, include_dirs, lib_dirs, [[toolchain.unit]] flag overrides.
//!   [[variant]], [[setup]], [[run]]  build variants and running a build (run.rs).
//!   [paths]        name = "directory": the directories outside the project the configuration reads, each the
//!                  default of a machine; `{name}` in any string of the configuration (reasons excepted) stands for it.
//!
//! decompanion.local.toml (beside it, not committed: one machine's)
//!   [paths]        name = "directory": this machine's directories, over the defaults of decompanion.toml.

use crate::error::{Error, Result};
use crate::fsmemo;
use crate::store::canon;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const CONFIG_NAME: &str = "decompanion.toml";
pub const LOCAL_CONFIG_NAME: &str = "decompanion.local.toml";
/// The placeholders other code expands (run.rs: {root}): no path name may take them.
const RESERVED_NAMES: [&str; 1] = ["root"];
const TOOLCHAIN_KEYS: [&str; 3] = ["compiler", "linker", "cflags"];
const TARGET_KEYS: [&str; 8] = ["name", "path", "sha256", "archives", "compiler", "linker", "cflags", "reason"];
const REASON_KEYS: [&str; 5] = ["compiler", "linker", "cflags", "archives", "root"];

pub(crate) fn cfg_err(msg: String) -> Error {
    Error::config(msg)
}

/// A TOML value as JSON (a datetime as its text).
pub fn toml_json(v: &toml::Value) -> Value {
    match v {
        toml::Value::String(s) => Value::String(s.clone()),
        toml::Value::Integer(i) => json!(i),
        toml::Value::Float(f) => json!(f),
        toml::Value::Boolean(b) => Value::Bool(*b),
        toml::Value::Datetime(d) => Value::String(d.to_string()),
        toml::Value::Array(a) => Value::Array(a.iter().map(toml_json).collect()),
        toml::Value::Table(t) => Value::Object(t.iter().map(|(k, v)| (k.clone(), toml_json(v))).collect()),
    }
}

/// str(Path(s)) on Windows: separators as backslashes, no doubled separators, no `.` parts, no trailing one.
pub fn native_path(s: &str) -> String {
    if !cfg!(windows) {
        return s.to_string();
    }
    let s = s.replace('/', "\\");
    let b = s.as_bytes();
    let (prefix, rest) = if s.starts_with("\\\\") {
        ("\\\\", &s[2..])
    } else if b.len() >= 2 && b[1] == b':' {
        if s[2..].starts_with('\\') { (&s[..3], &s[3..]) } else { (&s[..2], &s[2..]) }
    } else if s.starts_with('\\') {
        ("\\", &s[1..])
    } else {
        ("", s.as_str())
    };
    let parts: Vec<&str> = rest.split('\\').filter(|p| !p.is_empty() && *p != ".").collect();
    let out = format!("{prefix}{}", parts.join("\\"));
    if out.is_empty() { ".".into() } else { out }
}

fn posix(p: &str) -> String {
    p.replace('\\', "/")
}

fn is_absolute(s: &str) -> bool {
    let b = s.as_bytes();
    if cfg!(windows) {
        (b.len() >= 3 && b[1] == b':' && (b[2] == b'/' || b[2] == b'\\')) || s.starts_with("\\\\") || s.starts_with("//")
    } else {
        s.starts_with('/')
    }
}

fn sha_hex(data: &[u8]) -> String {
    fsmemo::hex(&Sha256::digest(data))
}

/// store.sha256(*parts): each part followed by a NUL.
pub fn sha256_parts<S: AsRef<str>>(parts: &[S]) -> String {
    crate::hash_parts(parts.iter().map(|p| p.as_ref().to_string()))
}

fn canonical(v: &Value) -> String {
    let mut s = String::new();
    canon(&mut s, v);
    s
}

/// The reason a table gives for one of its keys: `reason.<key>`, or the older form `reason = "..."`; '' when none.
pub(crate) fn reason_of(table: Option<&toml::Table>, key: &str) -> String {
    let r = match table.and_then(|t| t.get("reason")) {
        Some(toml::Value::Table(t)) => t.get(key).cloned(),
        Some(v) => Some(v.clone()),
        None => None,
    };
    match r {
        Some(toml::Value::String(s)) => s.trim().to_string(),
        Some(toml::Value::Boolean(false)) | None => String::new(),
        Some(v) => toml_json(&v).to_string().trim_matches('"').trim().to_string(),
    }
}

#[derive(Clone)]
pub struct Target {
    pub name: String,
    pub path: String, // as str(Path) spells it
    pub sha256: String,
    pub toolchain: Vec<(String, Value)>, // compiler, linker, cflags as the table declares them
    pub archives: Option<Vec<String>>,
    pub reasons: Vec<(String, String)>,
}

/// The name of a target: the binary's stem, lower case, reduced to [a-z0-9_-].
pub fn target_name_of(path: &str) -> String {
    let stem = Path::new(path).file_stem().map(|s| s.to_string_lossy().to_lowercase()).unwrap_or_default();
    let n: String = stem.chars().map(|c| if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-' { c } else { '_' }).collect();
    if n.chars().next().is_some_and(|c| c.is_alphabetic()) { n } else { format!("t{n}") }
}

pub(crate) fn is_identifier(name: &str) -> bool {
    let mut c = name.chars();
    c.next().is_some_and(|f| f.is_ascii_alphabetic()) && c.all(|x| x.is_ascii_alphanumeric() || x == '_' || x == '-')
}

pub struct Project {
    pub root: PathBuf,
    pub cfg: toml::Table,
    pub target: Target,
    pub target_name: String,
    pub(crate) core_hash: String,
    hashes: Mutex<HashMap<String, String>>,
    waits: Mutex<HashMap<String, Vec<String>>>,
}

/// The directory at or above `start` that holds decompanion.toml.
pub fn find_root(start: &Path) -> Option<PathBuf> {
    start.ancestors().find(|d| d.join(CONFIG_NAME).exists()).map(|d| d.to_path_buf())
}

impl Project {
    pub fn open(root: &Path, core_hash: &str) -> Result<Project, String> {
        let text = std::fs::read_to_string(root.join(CONFIG_NAME)).map_err(|e| format!("{}: {e}", root.join(CONFIG_NAME).display()))?;
        let (cfg, _) = load_config(root, &text)?;
        let target = parse_target(&cfg, root)?;
        let p = Project { root: root.to_path_buf(), cfg, target_name: target.name.clone(), target, core_hash: core_hash.into(),
                              hashes: Mutex::new(HashMap::new()), waits: Mutex::new(HashMap::new()) };
        if ["variant", "setup", "run"].iter().any(|k| p.cfg.contains_key(*k)) {
            p.run_cfg()?; // a contradiction in the run tables is an error of every command, as one in the targets is
        }
        Ok(p)
    }

    pub(crate) fn table(&self, name: &str) -> Option<&toml::Table> {
        self.cfg.get(name).and_then(|v| v.as_table())
    }

    fn tc_str(&self, key: &str) -> String {
        self.table("toolchain").and_then(|t| t.get(key)).map(|v| match v {
            toml::Value::String(s) => s.clone(),
            v => toml_json(v).to_string(),
        }).unwrap_or_default()
    }

    /// The gate's bound on debt items: `[gate] max_debt`; -1 (no bound) when not set.
    pub fn max_debt(&self) -> i64 {
        self.cfg.get("gate").and_then(|g| g.get("max_debt")).and_then(|v| v.as_integer()).unwrap_or(-1)
    }

    /// The easy tier's bounds (crate::queues): `[queue] easy_max_bytes`, `easy_max_dist`,
    /// `easy_read_max_bytes`, each the default when not set.
    pub fn tiers(&self) -> crate::queues::Tiers {
        let d = crate::queues::Tiers::default();
        let q = self.cfg.get("queue");
        let int = |k: &str, or: i64| q.and_then(|g| g.get(k)).and_then(|v| v.as_integer()).unwrap_or(or);
        crate::queues::Tiers { max_bytes: int("easy_max_bytes", d.max_bytes), max_dist: int("easy_max_dist", d.max_dist),
                               read_max_bytes: int("easy_read_max_bytes", d.read_max_bytes) }
    }


    /// A path of the configuration: `{toolchain.root}` replaced, relative to the project root.
    pub fn expand(&self, s: &str) -> String {
        let s = s.replace("{toolchain.root}", &self.tc_str("root"));
        if is_absolute(&s) { native_path(&s) } else { native_path(&format!("{}/{s}", self.root.to_string_lossy())) }
    }

    /// The toolchain declaration: root from [toolchain]; compiler, linker and cflags from [target]; `from` where each
    /// came from (toolchain / target / missing), `reasons` their reasons.
    pub fn toolchain_decl(&self) -> Result<Value, String> {
        let tc = self.table("toolchain");
        let t = &self.target;
        let own: HashMap<&str, &Value> = t.toolchain.iter().map(|(k, v)| (k.as_str(), v)).collect();
        let own_reasons: HashMap<&str, &str> = t.reasons.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let root = tc.and_then(|t| t.get("root")).map(toml_json).unwrap_or(Value::String(String::new()));
        let has_root = tc.and_then(|t| t.get("root")).is_some_and(|v| v.as_str() != Some(""));
        let mut out = serde_json::Map::new();
        out.insert("root".into(), root);
        let mut src = serde_json::Map::new();
        let mut reasons = serde_json::Map::new();
        src.insert("root".into(), json!(if has_root { "toolchain" } else { "missing" }));
        reasons.insert("root".into(), json!(if has_root { reason_of(tc, "root") } else { String::new() }));
        for k in TOOLCHAIN_KEYS {
            let (v, from, reason) = if let Some(v) = own.get(k) {
                ((*v).clone(), "target", own_reasons.get(k).copied().unwrap_or("").to_string())
            } else {
                (if k == "cflags" { json!([]) } else { json!("") }, "missing", String::new())
            };
            out.insert(k.into(), v);
            src.insert(k.into(), json!(from));
            reasons.insert(k.into(), json!(reason));
        }
        out.insert("from".into(), Value::Object(src));
        out.insert("reasons".into(), Value::Object(reasons));
        Ok(Value::Object(out))
    }

    /// The library-archive declaration: the archives as written (None when the target declares none), where they
    /// come from (target | missing), the reason.
    pub fn archives_decl(&self) -> (Option<Vec<String>>, &'static str, String) {
        let t = &self.target;
        match &t.archives {
            Some(a) => (Some(a.clone()), "target", t.reasons.iter().find(|(k, _)| k == "archives").map(|(_, r)| r.clone()).unwrap_or_default()),
            None => (None, "missing", String::new()),
        }
    }

    /// The target's library archives (expanded; each must exist).
    pub fn lib_archives(&self) -> Result<Vec<String>, String> {
        let mut out = vec![];
        for s in self.archives_decl().0.unwrap_or_default() {
            let p = self.expand(&s);
            if !Path::new(&p).exists() {
                return Err(format!("[target] archives: {p} does not exist"));
            }
            out.push(p);
        }
        Ok(out)
    }

    /// The obligations an external input waits on: absent until a human declares it.
    pub fn waiting(&self, name: &str) -> Result<Vec<String>, String> {
        if let Some(w) = self.waits.lock().unwrap().get(name) {
            return Ok(w.clone());
        }
        let out = match name {
            "libs" => {
                let (a, _, _) = self.archives_decl();
                match a {
                    None => vec!["libs.archives".to_string()],
                    Some(a) if self.tc_str("root").is_empty() && a.iter().any(|s| s.contains("{toolchain.root}")) => vec!["toolchain.root".to_string()],
                    _ => vec![],
                }
            }
            "toolchain" => {
                let d = self.toolchain_decl()?;
                ["compiler", "linker"].iter().filter(|k| d[**k].as_str().map(|s| s.is_empty()).unwrap_or(d[**k].is_null()))
                    .map(|k| format!("toolchain.{k}")).collect()
            }
            _ => vec![],
        };
        self.waits.lock().unwrap().insert(name.to_string(), out.clone());
        Ok(out)
    }

    /// Every obligation the given inputs wait on, in order, once.
    pub fn waiting_for(&self, inputs: &[String]) -> Result<Vec<String>, String> {
        let mut out: Vec<String> = vec![];
        for i in inputs {
            for w in self.waiting(i)? {
                if !out.contains(&w) {
                    out.push(w);
                }
            }
        }
        Ok(out)
    }

    pub fn build_dir(&self) -> PathBuf {
        self.root.join("build")
    }

    pub fn store_path(&self) -> String {
        native_path(&self.build_dir().join(format!("{}.sqlite", self.target_name)).to_string_lossy())
    }

    /// The toolchain's root, expanded (None when [toolchain] names none).
    pub fn toolchain_root(&self) -> Option<String> {
        let r = self.tc_str("root");
        (!r.is_empty()).then(|| self.expand(&r))
    }

    /// The toolchain's tools are installed (VC6: VC98/Bin/CL.EXE under the root).
    pub fn toolchain_available(&self) -> bool {
        let root = self.tc_str("root");
        !root.is_empty() && Path::new(&self.expand(&root)).join("VC98").join("Bin").join("CL.EXE").exists()
    }

    fn file_hash(p: &str) -> Result<String, String> {
        fsmemo::sha256(p).map_err(|e| format!("{p}: {e}"))
    }

    /// The content hash of a named input; None for one another module computes (scan).
    pub fn input_hash(&self, name: &str) -> Result<Option<String>, String> {
        if let Some(h) = self.hashes.lock().unwrap().get(name) {
            return Ok(Some(h.clone()));
        }
        let root = self.root.to_string_lossy().into_owned();
        let h = match name {
            "image" => Self::file_hash(&self.target.path)?,
            "config" => {
                let local = native_path(&format!("{root}/{LOCAL_CONFIG_NAME}"));
                let local = if Path::new(&local).exists() { Self::file_hash(&local)? } else { "none".into() };
                sha256_parts(&[Self::file_hash(&native_path(&format!("{root}/{CONFIG_NAME}")))?, local])
            }
            "libs" | "archives" => {
                let libs = if self.waiting("libs")?.is_empty() { self.lib_archives()? } else { vec![] };
                let mut data = String::new();
                for p in &libs {
                    let n = Path::new(p).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                    data.push_str(&format!("{n}:{}\n", Self::file_hash(p)?));
                }
                sha_hex(data.as_bytes())
            }
            "decl" => fsmemo::tree_hash(&[native_path(&format!("{root}/decl"))], &["*.dcl".into()]).map_err(|e| e.to_string())?,
            "src" => fsmemo::tree_hash(&[native_path(&format!("{root}/src")), native_path(&format!("{root}/include"))], &["*.c".into(), "*.h".into()])
                .map_err(|e| e.to_string())?,
            "toolchain" => sha256_parts(&[canonical(&self.toolchain_decl()?)]),
            "target" => sha256_parts(&[canonical(&json!({"name": self.target.name, "path": posix(&self.target.path), "sha256": self.target.sha256}))]),
            "baseline" => {
                let p = native_path(&format!("{root}/ledger/grades.tsv"));
                if Path::new(&p).exists() { Self::file_hash(&p)? } else { "none".into() }
            }
            "tiebreak" => {
                let p = native_path(&format!("{root}/{}", crate::tiebreak::LEDGER));
                if Path::new(&p).exists() { Self::file_hash(&p)? } else { "none".into() }
            }
            "objects" | "probe" | "lint" | "drafts" => {
                let path = self.store_path();
                crate::storedb::st_open(&path).map_err(|e| e.to_string())?;
                let meta = |k: &str| crate::storedb::st_meta(&path, k).map_err(|e| e.to_string()).map(|v| v.unwrap_or_default());
                match name {
                    "objects" => {
                        let tu = crate::storedb::tu_hash(&path).map_err(|e| e.to_string())?;
                        sha256_parts(&[tu.as_str(), if self.toolchain_available() { "true" } else { "false" }])
                    }
                    k => sha256_parts(&[meta(k)?]),
                }
            }
            "scan" => {
                let src = self.input_hash("src")?.unwrap_or_default();
                crate::frontend::scan(&self.root.to_string_lossy(), Some(&src))?.digest()
            }
            _ => return Err(format!("unknown input {}", crate::decl::quote_str(name))),
        };
        self.hashes.lock().unwrap().insert(name.to_string(), h.clone());
        Ok(Some(h))
    }

    pub fn forget_input(&self, name: &str) {
        let mut h = self.hashes.lock().unwrap();
        h.remove(name);
        if name == "src" {
            h.remove("scan");
        }
    }
}

// ------------------------------------------------------------------------------------------------ the CLI's project

impl Project {
    /// The project at `root` (None: the directory holding decompanion.toml at or above the working directory), with
    /// a target selected (None: the default one). A missing configuration is an Error::Config.
    pub fn find(root: Option<&str>) -> Result<Project> {
        let start = match root {
            Some(r) => PathBuf::from(r),
            None => std::env::current_dir().map_err(|e| cfg_err(e.to_string()))?,
        };
        let start = std::path::absolute(&start).unwrap_or(start);
        let root = if start.join(CONFIG_NAME).exists() {
            start
        } else {
            find_root(&start).ok_or_else(|| cfg_err(format!("no {CONFIG_NAME} in {} or above (run dcp init)", start.display())))?
        };
        let root = PathBuf::from(native_path(&root.to_string_lossy()));
        Project::open(&root, crate::CORE_HASH).map_err(cfg_err)
    }

    /// The target's image, checked: the file exists, its sha256 is the declared one.
    #[cfg(test)]
    pub fn image_checked(&self) -> Result<std::rc::Rc<crate::pe::Image>> {
        let t = &self.target;
        if !Path::new(&t.path).exists() {
            return Err(cfg_err(format!("target {}: {} does not exist", t.name, t.path)));
        }
        let img = crate::image(&t.path)?;
        let sha = crate::fsmemo::sha256(&t.path).map_err(|e| cfg_err(format!("{}: {e}", t.path)))?;
        if !t.sha256.is_empty() && sha != t.sha256 {
            return Err(cfg_err(format!("target {}: {} has sha256 {sha}, the declared one is {}", t.name, t.path, t.sha256)));
        }
        Ok(img)
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(toml: &str) -> Result<Project, String> {
        let d = crate::testkit::scratch(&format!("project-{}", sha_hex(toml.as_bytes())));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(CONFIG_NAME), toml).unwrap();
        let p = Project::open(&d, "core");
        let _ = std::fs::remove_dir_all(&d);
        p
    }

    /// [paths] names directories: decompanion.toml gives defaults, decompanion.local.toml this machine's; `{name}`
    /// expands in every string but reasons; the placeholders of other code stay; an unnamed `{name}` is an error.
    #[test]
    fn named_paths() {
        let d = crate::testkit::scratch("project-named-paths");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let cfg = r#"
[[target]]
path = "{game}/Game.exe"
archives = ["{toolchain.root}/VC98/Lib/LIBC.LIB", "{dx8}/lib/dxguid.lib"]
reason.archives = "the {dx8} SDK's order"
[toolchain]
root = "{msvc6}"
include_dirs = ["{dx6}/include"]
[paths]
msvc6 = "C:/VC6"
dx6 = "C:/SDK/DX61/"
dx8 = "C:/SDK/DX8"
game = "C:/Games/Game"
[[setup]]
name = "s"
  [[setup.stage]]
  from = "{target.dir}"
  link = ["{root}/x"]
"#;
        std::fs::write(d.join(CONFIG_NAME), cfg).unwrap();
        std::fs::write(d.join(LOCAL_CONFIG_NAME), "[paths]\ngame = 'D:\\My Game'\ndx8 = \"E:/sdk8\"\n").unwrap();
        let (c, names) = load_config(&d, cfg).unwrap();
        assert_eq!(names.get("game").map(|s| s.as_str()), Some("D:/My Game"));
        assert_eq!(names.get("dx6").map(|s| s.as_str()), Some("C:/SDK/DX61"));
        let t = &c["target"].as_array().unwrap()[0];
        assert_eq!(t["path"].as_str(), Some("D:/My Game/Game.exe"));
        assert_eq!(t["archives"].as_array().unwrap().iter().map(|a| a.as_str().unwrap()).collect::<Vec<_>>(),
                   ["{toolchain.root}/VC98/Lib/LIBC.LIB", "E:/sdk8/lib/dxguid.lib"]);
        assert_eq!(t["reason"]["archives"].as_str(), Some("the {dx8} SDK's order"));
        assert_eq!(c["toolchain"]["root"].as_str(), Some("C:/VC6"));
        assert_eq!(c["toolchain"]["include_dirs"][0].as_str(), Some("C:/SDK/DX61/include"));
        let stage = &c["setup"][0]["stage"][0];
        assert_eq!((stage["from"].as_str(), stage["link"][0].as_str()), (Some("{target.dir}"), Some("{root}/x")));
        // an unnamed directory; a local file with more than [paths]; a reserved name
        std::fs::remove_file(d.join(LOCAL_CONFIG_NAME)).unwrap();
        let e = load_config(&d, &cfg.replace("{game}", "{gamedir}")).unwrap_err();
        assert!(e.contains("{gamedir} names no directory") && e.contains(LOCAL_CONFIG_NAME), "{e}");
        std::fs::write(d.join(LOCAL_CONFIG_NAME), "[paths]\ngame = \"D:/g\"\n[toolchain]\nroot = \"x\"\n").unwrap();
        assert!(load_config(&d, cfg).unwrap_err().contains("[paths] only"));
        std::fs::write(d.join(LOCAL_CONFIG_NAME), "[paths]\nroot = \"D:/g\"\n").unwrap();
        assert!(load_config(&d, cfg).unwrap_err().contains("other than root"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn targets_and_declarations() {
        let p = project(r#"
[target]
path = "C:/g/Some Game.exe"
compiler = "cl 12.00.9044"
reason.compiler = "rich"
archives = ["{toolchain.root}/VC98/Lib/LIBC.LIB"]
reason.archives = "S.rich"
[toolchain]
root = "C:/Tools/VC"
reason = "probe"
"#).unwrap();
        assert_eq!(p.target_name, "some_game");
        let d = p.toolchain_decl().unwrap();
        assert_eq!((d["compiler"].as_str(), d["linker"].as_str()), (Some("cl 12.00.9044"), Some("")));
        assert_eq!(d["from"], json!({"root": "toolchain", "compiler": "target", "linker": "missing", "cflags": "missing"}));
        assert_eq!((d["reasons"]["compiler"].as_str(), d["reasons"]["root"].as_str()), (Some("rich"), Some("probe")));
        let (a, from, r) = p.archives_decl();
        assert_eq!((a.unwrap()[0].as_str(), from, r.as_str()), ("{toolchain.root}/VC98/Lib/LIBC.LIB", "target", "S.rich"));
        assert!(p.waiting("libs").unwrap().is_empty());
        if cfg!(windows) {
            assert_eq!(p.expand("{toolchain.root}/VC98/Lib/LIBC.LIB"), r"C:\Tools\VC\VC98\Lib\LIBC.LIB");
        }
    }

    #[test]
    fn errors_and_waiting() {
        assert_eq!(project("x = 1").err().unwrap(), "decompanion.toml: no [target] table");
        assert!(project("[[target]]\npath = \"a.dll\"\n").err().unwrap().contains("one [target] table"));
        assert!(project("[target]\npath = \"a.dll\"\nbogus = 1\n").err().unwrap().contains("has unknown keys bogus"));
        assert!(project("[target]\nname = \"1x\"\npath = \"a.dll\"\n").err().unwrap().contains("is not an identifier"));
        let p = project("[target]\npath = \"a.dll\"\n").unwrap();
        assert_eq!(p.waiting("libs").unwrap(), ["libs.archives"]);
        assert_eq!(p.waiting_for(&["libs".into(), "toolchain".into()]).unwrap(), ["libs.archives", "toolchain.compiler", "toolchain.linker"]);
        assert_eq!(target_name_of("C:/x/123.dll"), "t123");
    }

    #[test]
    fn native_paths() {
        if cfg!(windows) {
            assert_eq!(native_path("C:/a//b/./c/"), r"C:\a\b\c");
            assert_eq!(native_path("C:/"), r"C:\");
        }
    }
}

/// The [target] table of a configuration.
fn parse_target(cfg: &toml::Table, root: &Path) -> Result<Target, String> {
    let tab = match cfg.get("target") {
        Some(toml::Value::Table(t)) => t,
        Some(toml::Value::Array(_)) => return Err(format!("{CONFIG_NAME}: one [target] table, not a [[target]] list")),
        _ => return Err(format!("{CONFIG_NAME}: no [target] table")),
    };
    let Some(path) = tab.get("path").and_then(|v| v.as_str()) else { return Err(format!("{CONFIG_NAME}: [target] has no path")) };
    let tc_root = cfg.get("toolchain").and_then(|t| t.get("root")).and_then(|v| v.as_str()).unwrap_or("");
    let path = path.replace("{toolchain.root}", tc_root);
    let path = if is_absolute(&path) { native_path(&path) } else { native_path(&format!("{}/{path}", root.to_string_lossy())) };
    let mut unknown: Vec<&str> = tab.keys().map(|k| k.as_str()).filter(|k| !TARGET_KEYS.contains(k)).collect();
    unknown.sort();
    if !unknown.is_empty() {
        return Err(format!("{CONFIG_NAME}: [target] has unknown keys {} (known: {})", unknown.join(", "), TARGET_KEYS.join(", ")));
    }
    let archives = match tab.get("archives") {
        None => None,
        Some(toml::Value::Array(a)) if a.iter().all(|x| x.is_str()) => Some(a.iter().map(|x| x.as_str().unwrap().to_string()).collect()),
        Some(_) => return Err(format!("{CONFIG_NAME}: [target] archives is not a list of paths")),
    };
    match tab.get("reason") {
        Some(toml::Value::Table(r)) => {
            let mut bad: Vec<&str> = r.keys().map(|k| k.as_str()).filter(|k| !REASON_KEYS.contains(k)).collect();
            bad.sort();
            if let Some(b) = bad.first() {
                return Err(format!("{CONFIG_NAME}: [target] reason.{b} names no declaration (known: {})", REASON_KEYS.join(", ")));
            }
        }
        Some(toml::Value::String(_)) | None => {}
        Some(_) => return Err(format!("{CONFIG_NAME}: [target] reason is neither a string nor reason.<key> = ...")),
    }
    let toolchain = TOOLCHAIN_KEYS.iter().filter_map(|k| tab.get(*k).map(|v| (k.to_string(), toml_json(v)))).collect();
    let reasons = ["compiler", "linker", "cflags", "archives"].iter()
        .filter_map(|k| Some(reason_of(Some(tab), k)).filter(|r| !r.is_empty()).map(|r| (k.to_string(), r))).collect();
    let name = tab.get("name").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(|s| s.to_string()).unwrap_or_else(|| target_name_of(&path));
    if !is_identifier(&name) {
        return Err(format!("{CONFIG_NAME}: [target] name {} is not an identifier ([A-Za-z][A-Za-z0-9_-]*)", crate::decl::quote_str(&name)));
    }
    Ok(Target { name, sha256: tab.get("sha256").and_then(|v| v.as_str()).unwrap_or("").to_string(), path, toolchain, archives,
                reasons })
}

/// `[paths]` of a configuration table: (name, directory) in name order, the names checked.
fn paths_table(cfg: &toml::Table, file: &str) -> Result<Vec<(String, String)>, String> {
    let Some(v) = cfg.get("paths") else { return Ok(vec![]) };
    let t = v.as_table().ok_or_else(|| format!("{file}: [paths] is not a table of name = \"directory\""))?;
    let mut out = vec![];
    for (k, d) in t {
        if !is_identifier(k) || RESERVED_NAMES.contains(&k.as_str()) {
            return Err(format!("{file}: [paths] {k}: a name is an identifier ([A-Za-z][A-Za-z0-9_-]*) other than {}", RESERVED_NAMES.join(", ")));
        }
        let d = d.as_str().ok_or_else(|| format!("{file}: [paths] {k} is not a directory (a string)"))?;
        if d.contains('{') {
            return Err(format!("{file}: [paths] {k} = {}: a directory names no other path", crate::decl::quote_str(d)));
        }
        out.push((k.clone(), d.replace('\\', "/").trim_end_matches('/').to_string()));
    }
    Ok(out)
}

/// `{name}` replaced by its directory in every string of the value; a reason (key `reason`, `reason.*`) stays as
/// written. A `{name}` no [paths] names is collected in `missing`, except the placeholders other code expands
/// ({root}; the dotted ones such as {toolchain.root} are no names).
fn expand_names(v: &mut toml::Value, key: &str, names: &BTreeMap<String, String>, missing: &mut BTreeSet<String>) {
    if key == "reason" || key.starts_with("reason.") {
        return;
    }
    match v {
        toml::Value::String(s) if s.contains('{') => {
            let mut out = String::with_capacity(s.len());
            let mut rest = s.as_str();
            while let Some(i) = rest.find('{') {
                out.push_str(&rest[..i]);
                let after = &rest[i + 1..];
                match after.find('}').map(|j| &after[..j]).filter(|n| is_identifier(n)) {
                    Some(n) if names.contains_key(n) => {
                        out.push_str(&names[n]);
                        rest = &after[n.len() + 1..];
                        continue;
                    }
                    Some(n) if !RESERVED_NAMES.contains(&n) => {
                        missing.insert(n.to_string());
                    }
                    _ => {}
                }
                out.push('{');
                rest = after;
            }
            out.push_str(rest);
            *s = out;
        }
        toml::Value::Array(a) => a.iter_mut().for_each(|x| expand_names(x, key, names, missing)),
        toml::Value::Table(t) => t.iter_mut().for_each(|(k, x)| expand_names(x, k, names, missing)),
        _ => {}
    }
}

/// The configuration of a project: decompanion.toml's text parsed, `{name}` expanded by the named directories
/// ([paths] of decompanion.toml, then of decompanion.local.toml when it exists); (table, the names).
pub fn load_config(root: &Path, text: &str) -> Result<(toml::Table, BTreeMap<String, String>), String> {
    let mut cfg: toml::Table = text.parse().map_err(|e: toml::de::Error| format!("{CONFIG_NAME}: {}", e.message()))?;
    let mut names: BTreeMap<String, String> = paths_table(&cfg, CONFIG_NAME)?.into_iter().collect();
    let local = root.join(LOCAL_CONFIG_NAME);
    if local.exists() {
        let text = std::fs::read_to_string(&local).map_err(|e| format!("{}: {e}", local.display()))?;
        let lcfg: toml::Table = text.parse().map_err(|e: toml::de::Error| {
            let hint = if e.message().contains("escape") { r" (a Windows path: C:/Tools/x or 'C:\Tools\x')" } else { "" };
            format!("{LOCAL_CONFIG_NAME}: {}{hint}", e.message().trim_end())
        })?;
        if let Some(k) = lcfg.keys().find(|k| *k != "paths") {
            return Err(format!("{LOCAL_CONFIG_NAME}: [{k}]: this file holds [paths] only (one machine's directories)"));
        }
        names.extend(paths_table(&lcfg, LOCAL_CONFIG_NAME)?);
    }
    let mut missing = BTreeSet::new();
    for (k, v) in cfg.iter_mut().filter(|(k, _)| *k != "paths") {
        expand_names(v, k, &names, &mut missing);
    }
    if !missing.is_empty() {
        let m: Vec<String> = missing.into_iter().map(|n| format!("{{{n}}}")).collect();
        return Err(format!("{CONFIG_NAME}: {} names no directory: give it in [paths] of {LOCAL_CONFIG_NAME} (name = \"DIR\")", m.join(", ")));
    }
    Ok((cfg, names))
}

