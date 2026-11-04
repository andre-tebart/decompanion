//! Running a build (docs/run.md): build variants, run setups and run profiles of decompanion.toml.
//!
//!   [[variant]]  name, targets, cflags, reason; [[variant.unit]] glob (a unit name pattern or a list), cflags, reason.
//!                Extra flags on top of a target's build. A variant compiles only the units its flags reach, into
//!                the shared object store; its rows live in build/variant/<target>/<variant>.json, never in the
//!                store's tu table, so the matching build stays as it is. Its link: build/link/<target>/<variant>/.
//!   [[setup]]    name, dir, exe, reason; [[setup.stage]] from, link, copy; [[setup.step]] / [[setup.after]] run.
//!                The run directory: the original's folders linked (junctions) and its files copied (once, when
//!                missing) into it, the built exe copied next to them, then the project's own
//!                steps (any command: a registry value, an ini edit, ...) before the launch, `after` once it exited.
//!   [[run]]      name, target, variant, setup, args, env, seconds, reason: what `dcp run NAME` builds, stages and
//!                starts.
//!
//! The core builds and stages and writes the launch spec build/run/<run>.json; the process the user typed `dcp`
//! in runs the steps and the program (launch.py): the daemon has no window to start a game in.

use crate::error::{Error, Result};
use crate::cliread::{record, Tok};
use crate::fsmemo;
use crate::project::{py_path, toml_json, Project, CONFIG_NAME};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

const VARIANT_KEYS: [&str; 5] = ["name", "targets", "cflags", "unit", "reason"];
const VARIANT_UNIT_KEYS: [&str; 3] = ["glob", "cflags", "reason"];
const SETUP_KEYS: [&str; 7] = ["name", "dir", "exe", "stage", "step", "after", "reason"];
const STAGE_KEYS: [&str; 4] = ["from", "link", "copy", "reason"];
const STEP_KEYS: [&str; 2] = ["run", "reason"];
const RUN_KEYS: [&str; 10] = ["name", "target", "variant", "setup", "args", "env", "seconds", "debug", "dump", "reason"];
pub const DUMPS: [&str; 4] = ["full", "state", "normal", "none"];

#[derive(Clone, Debug, PartialEq)]
pub struct VariantUnit {
    pub globs: Vec<String>,
    pub cflags: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Variant {
    pub name: String,
    pub targets: Vec<String>,
    pub cflags: Vec<String>,
    pub units: Vec<VariantUnit>,
}

impl Variant {
    /// The flags the variant adds to one unit: its cflags, then those of the first [[variant.unit]] whose glob
    /// matches the unit name.
    pub fn extra(&self, unit: &str) -> Vec<String> {
        let mut out = self.cflags.clone();
        if let Some(u) = self.units.iter().find(|u| u.globs.iter().any(|g| fsmemo::fnmatch(unit.as_bytes(), g.as_bytes()))) {
            out.extend(u.cflags.iter().cloned());
        }
        out
    }

    pub fn applies_to(&self, target: &str) -> bool {
        self.targets.is_empty() || self.targets.iter().any(|t| t == target)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Stage {
    pub from: String, // as written: {target.dir}, {toolchain.root} and {root} expand when staging
    pub link: Vec<String>,
    pub copy: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Setup {
    pub name: String,
    pub dir: String, // as written
    pub exe: Option<String>,
    pub stages: Vec<Stage>,
    pub steps: Vec<Vec<String>>,
    pub after: Vec<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RunProfile {
    pub name: String,
    pub target: Option<String>,
    pub variant: Option<String>,
    pub setup: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub seconds: f64,
    pub debug: bool,
    pub dump: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RunCfg {
    pub variants: Vec<Variant>,
    pub setups: Vec<Setup>,
    pub runs: Vec<RunProfile>,
}

fn tables<'a>(v: Option<&'a toml::Value>, what: &str) -> Result<Vec<&'a toml::Table>, String> {
    match v {
        None => Ok(vec![]),
        Some(toml::Value::Array(a)) => a.iter().map(|x| x.as_table().ok_or_else(|| format!("{CONFIG_NAME}: [[{what}]] holds a value that is not a table"))).collect(),
        Some(toml::Value::Table(t)) => Ok(vec![t]),
        Some(_) => Err(format!("{CONFIG_NAME}: {what} is not a table list ([[{what}]])")),
    }
}

fn check_keys(t: &toml::Table, known: &[&str], what: &str) -> Result<(), String> {
    let mut bad: Vec<&str> = t.keys().map(|k| k.as_str()).filter(|k| !known.contains(k)).collect();
    bad.sort();
    if bad.is_empty() {
        Ok(())
    } else {
        Err(format!("{CONFIG_NAME}: {what} has unknown keys {} (known: {})", bad.join(", "), known.join(", ")))
    }
}

fn strs(t: &toml::Table, key: &str, what: &str) -> Result<Vec<String>, String> {
    match t.get(key) {
        None => Ok(vec![]),
        Some(toml::Value::String(s)) if key == "glob" => Ok(vec![s.clone()]),
        Some(toml::Value::Array(a)) => a.iter().map(|x| match x {
            toml::Value::String(s) => Ok(s.clone()),
            _ => Err(format!("{CONFIG_NAME}: {what}: {key} holds a value that is not a string")),
        }).collect(),
        Some(_) => Err(format!("{CONFIG_NAME}: {what}: {key} is not a list of strings")),
    }
}

fn name_of(t: &toml::Table, kind: &str, i: usize) -> Result<String, String> {
    let n = t.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if n.is_empty() {
        return Err(format!("{CONFIG_NAME}: {kind} #{} has no name", i + 1));
    }
    if !crate::project::is_identifier(n) {
        return Err(format!("{CONFIG_NAME}: {kind} name {} is not an identifier ([A-Za-z][A-Za-z0-9_-]*)", crate::decl::py_repr(n)));
    }
    Ok(n.to_string())
}

fn commands(t: &toml::Table, key: &str, what: &str) -> Result<Vec<Vec<String>>, String> {
    let mut out = vec![];
    for (i, s) in tables(t.get(key), key)?.into_iter().enumerate() {
        let w = format!("{what} {key} #{}", i + 1);
        check_keys(s, &STEP_KEYS, &w)?;
        let run = strs(s, "run", &w)?;
        if run.is_empty() {
            return Err(format!("{CONFIG_NAME}: {w}: run is missing or empty (a command as a list: [\"program\", \"arg\", ...])"));
        }
        out.push(run);
    }
    Ok(out)
}

fn dup(names: &[&str], kind: &str) -> Result<(), String> {
    for (i, n) in names.iter().enumerate() {
        if names[..i].contains(n) {
            return Err(format!("{CONFIG_NAME}: {kind} {} declared twice", crate::decl::py_repr(n)));
        }
    }
    Ok(())
}

/// The [[variant]], [[setup]] and [[run]] tables, checked against each other and the targets.
pub fn parse(cfg: &toml::Table, targets: &[String]) -> Result<RunCfg, String> {
    let mut out = RunCfg::default();
    for (i, t) in tables(cfg.get("variant"), "variant")?.into_iter().enumerate() {
        let name = name_of(t, "variant", i)?;
        let what = format!("variant {}", crate::decl::py_repr(&name));
        check_keys(t, &VARIANT_KEYS, &what)?;
        let ts = strs(t, "targets", &what)?;
        if let Some(bad) = ts.iter().find(|x| !targets.contains(x)) {
            return Err(format!("{CONFIG_NAME}: {what}: no target {} (targets: {})", crate::decl::py_repr(bad), targets.join(", ")));
        }
        let mut units = vec![];
        for (k, u) in tables(t.get("unit"), "variant.unit")?.into_iter().enumerate() {
            let w = format!("{what} unit #{}", k + 1);
            check_keys(u, &VARIANT_UNIT_KEYS, &w)?;
            let globs = strs(u, "glob", &w)?;
            if globs.is_empty() {
                return Err(format!("{CONFIG_NAME}: {w} has no glob (a unit name pattern, or a list of them)"));
            }
            units.push(VariantUnit { globs, cflags: strs(u, "cflags", &w)? });
        }
        out.variants.push(Variant { name, targets: ts, cflags: strs(t, "cflags", &what)?, units });
    }
    for (i, t) in tables(cfg.get("setup"), "setup")?.into_iter().enumerate() {
        let name = name_of(t, "setup", i)?;
        let what = format!("setup {}", crate::decl::py_repr(&name));
        check_keys(t, &SETUP_KEYS, &what)?;
        let mut stages = vec![];
        for (k, s) in tables(t.get("stage"), "setup.stage")?.into_iter().enumerate() {
            let w = format!("{what} stage #{}", k + 1);
            check_keys(s, &STAGE_KEYS, &w)?;
            let from = s.get("from").and_then(|v| v.as_str()).filter(|s| !s.is_empty())
                .ok_or_else(|| format!("{CONFIG_NAME}: {w} has no from (the folder to take files from, e.g. \"{{target.dir}}\")"))?;
            stages.push(Stage { from: from.to_string(), link: strs(s, "link", &w)?, copy: strs(s, "copy", &w)? });
        }
        let str_of = |k: &str| t.get(k).and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(|s| s.to_string());
        let exe = str_of("exe");
        if exe.as_deref().is_some_and(|e| e.contains(['/', '\\'])) {
            return Err(format!("{CONFIG_NAME}: {what}: exe is a file name in the run directory, not a path"));
        }
        out.setups.push(Setup {
            dir: str_of("dir").unwrap_or_else(|| format!("build/run/{name}")), exe, stages,
            steps: commands(t, "step", &what)?, after: commands(t, "after", &what)?, name,
        });
    }
    for (i, t) in tables(cfg.get("run"), "run")?.into_iter().enumerate() {
        let name = name_of(t, "run", i)?;
        let what = format!("run {}", crate::decl::py_repr(&name));
        check_keys(t, &RUN_KEYS, &what)?;
        let str_of = |k: &str| t.get(k).and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(|s| s.to_string());
        let target = str_of("target");
        if let Some(bad) = target.as_ref().filter(|x| !targets.contains(x)) {
            return Err(format!("{CONFIG_NAME}: {what}: no target {} (targets: {})", crate::decl::py_repr(bad), targets.join(", ")));
        }
        let variant = str_of("variant");
        if let Some(v) = &variant {
            let Some(var) = out.variants.iter().find(|x| &x.name == v) else {
                return Err(format!("{CONFIG_NAME}: {what}: no [[variant]] {}", crate::decl::py_repr(v)));
            };
            let tn = target.clone().unwrap_or_else(|| targets.first().cloned().unwrap_or_default());
            if !var.applies_to(&tn) {
                return Err(format!("{CONFIG_NAME}: {what}: variant {} is not for target {tn} (its targets: {})", crate::decl::py_repr(v), var.targets.join(", ")));
            }
        }
        let setup = str_of("setup").ok_or_else(|| format!("{CONFIG_NAME}: {what} names no setup"))?;
        if !out.setups.iter().any(|s| s.name == setup) {
            return Err(format!("{CONFIG_NAME}: {what}: no [[setup]] {}", crate::decl::py_repr(&setup)));
        }
        let env = match t.get("env") {
            None => vec![],
            Some(toml::Value::Table(e)) => e.iter().map(|(k, v)| (k.clone(), match v {
                toml::Value::String(s) => s.clone(),
                v => toml_json(v).to_string(),
            })).collect(),
            Some(_) => return Err(format!("{CONFIG_NAME}: {what}: env is not a table (env = {{ NAME = \"value\" }})")),
        };
        let seconds = match t.get("seconds") {
            None => 0.0,
            Some(toml::Value::Integer(n)) if *n >= 0 => *n as f64,
            Some(toml::Value::Float(f)) if *f >= 0.0 => *f,
            Some(_) => return Err(format!("{CONFIG_NAME}: {what}: seconds is not a number >= 0")),
        };
        let debug = match t.get("debug") {
            None => false,
            Some(toml::Value::Boolean(b)) => *b,
            Some(_) => return Err(format!("{CONFIG_NAME}: {what}: debug is not true or false")),
        };
        let dump = str_of("dump").unwrap_or_else(|| "full".into());
        if !DUMPS.contains(&dump.as_str()) {
            return Err(format!("{CONFIG_NAME}: {what}: dump {} is none of {}", crate::decl::py_repr(&dump), DUMPS.join(", ")));
        }
        out.runs.push(RunProfile { name, target, variant, setup, args: strs(t, "args", &what)?, env, seconds, debug, dump });
    }
    dup(&out.variants.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(), "variant")?;
    dup(&out.setups.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(), "setup")?;
    dup(&out.runs.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(), "run")?;
    Ok(out)
}

impl Project {
    pub fn run_cfg(&self) -> Result<RunCfg, String> {
        parse(&self.cfg, &self.targets.iter().map(|t| t.name.clone()).collect::<Vec<_>>())
    }

    pub fn variant(&self, name: &str) -> Result<Variant, String> {
        let c = self.run_cfg()?;
        let v = c.variants.into_iter().find(|v| v.name == name).ok_or_else(|| format!("no [[variant]] {}", crate::decl::py_repr(name)))?;
        if !v.applies_to(&self.target_name) {
            return Err(format!("variant {} is not for target {} (its targets: {})", v.name, self.target_name, v.targets.join(", ")));
        }
        Ok(v)
    }
}

// ------------------------------------------------------------------------------------------------ staging

fn matches(name: &str, pats: &[String], is_dir: bool) -> bool {
    let n = name.to_lowercase();
    pats.iter().any(|p| {
        let (p, dirs_only) = match p.strip_suffix('/') {
            Some(p) => (p, true),
            None => (p.as_str(), false),
        };
        (!dirs_only || is_dir) && fsmemo::fnmatch(n.as_bytes(), p.to_lowercase().as_bytes())
    })
}

fn same_path(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

fn is_link(p: &Path) -> bool {
    std::fs::symlink_metadata(p).map(|m| m.file_type().is_symlink() || std::fs::read_link(p).is_ok()).unwrap_or(false)
}

#[cfg(windows)]
fn make_dir_link(link: &Path, to: &Path) -> Result<(), String> {
    // a junction needs no privilege (a directory symbolic link does)
    let out = std::process::Command::new("cmd").args(["/c", "mklink", "/J"]).arg(link).arg(to).output().map_err(|e| format!("mklink: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("mklink /J {} {}: {}", link.display(), to.display(), String::from_utf8_lossy(&out.stdout).trim()))
    }
}

#[cfg(not(windows))]
fn make_dir_link(link: &Path, to: &Path) -> Result<(), String> {
    std::os::unix::fs::symlink(to, link).map_err(|e| format!("{}: {e}", link.display()))
}

/// What staging did.
#[derive(Default, Debug)]
pub struct Staged {
    pub linked: usize,
    pub copied: usize,
    pub kept: usize,
    pub exe_copied: bool,
}

/// One stage into `dir`: the entries of `from` (top level) its patterns name. A folder of `link` becomes a junction
/// (made again when it points elsewhere); a file (of `copy`, or of `link`: a file is never linked, a step editing it
/// would edit the original) a copy made once (an existing one is kept: steps may edit it). `from` is only read.
pub fn stage_one(from: &Path, dir: &Path, link: &[String], copy: &[String], st: &mut Staged) -> Result<(), String> {
    let it = std::fs::read_dir(from).map_err(|e| format!("stage from {}: {e}", from.display()))?;
    let mut entries: Vec<(String, bool, PathBuf)> = it.flatten()
        .map(|e| (e.file_name().to_string_lossy().into_owned(), e.file_type().map(|t| t.is_dir()).unwrap_or(false), e.path())).collect();
    entries.sort();
    for (name, is_dir, src) in entries {
        let dest = dir.join(&name);
        if is_dir && matches(&name, link, true) {
            if is_link(&dest) {
                if same_path(&dest, &src) {
                    st.kept += 1;
                    continue;
                }
                std::fs::remove_dir(&dest).or_else(|_| std::fs::remove_file(&dest)).map_err(|e| format!("{}: {e}", dest.display()))?;
            } else if dest.exists() {
                return Err(format!("{} exists and is not a link: remove it to link {}", dest.display(), src.display()));
            }
            make_dir_link(&dest, &src)?;
            st.linked += 1;
        } else if !is_dir && (matches(&name, copy, false) || matches(&name, link, false)) {
            if dest.exists() {
                st.kept += 1;
            } else {
                std::fs::copy(&src, &dest).map_err(|e| format!("{} -> {}: {e}", src.display(), dest.display()))?;
                st.copied += 1;
            }
        }
    }
    Ok(())
}

/// Copy the built program into the run directory when its bytes differ (a path-keyed setting such as a compatibility
/// layer stays valid: the path does not change).
pub fn place_exe(built: &Path, dest: &Path) -> Result<bool, String> {
    let same = dest.exists() && std::fs::metadata(built).map(|m| m.len()).ok() == std::fs::metadata(dest).map(|m| m.len()).ok()
        && std::fs::read(built).ok() == std::fs::read(dest).ok();
    if same {
        return Ok(false);
    }
    if is_link(dest) {
        std::fs::remove_file(dest).map_err(|e| format!("{}: {e}", dest.display()))?;
    }
    std::fs::copy(built, dest).map_err(|e| format!("{} -> {}: {e} (is the program still running?)", built.display(), dest.display()))?;
    Ok(true)
}

/// A path of a setup: {root}, {target.dir}, {toolchain.root} replaced, relative to the project root.
fn expand(p: &Project, s: &str, target_dir: &str) -> String {
    let root = p.root.to_string_lossy().into_owned();
    p.expand(&s.replace("{target.dir}", target_dir).replace("{root}", &root))
}

fn inside(a: &Path, b: &Path) -> bool {
    let (Ok(a), Ok(b)) = (std::fs::canonicalize(a), std::fs::canonicalize(b)) else { return false };
    a.starts_with(b)
}

// ------------------------------------------------------------------------------------------------ the variant build

/// The variant's build of the current target: its units compiled (compile::ensure_variant) and linked into
/// build/link/<target>/<variant>/. The main build must be current (the caller built it).
pub fn variant_build(p: &Project, v: &Variant, force: bool) -> Result<(crate::compile::Report, crate::link::LinkReport), String> {
    let (rep, objs) = crate::compile::ensure_variant(p, v, force)?;
    if rep.unavailable || !rep.failed.is_empty() {
        let skipped = if rep.unavailable { "the toolchain is not available".into() } else { format!("variant units do not compile: {}", rep.failed.join(", ")) };
        return Ok((rep, crate::link::LinkReport { target: p.target_name.clone(), skipped, ..Default::default() }));
    }
    let link = crate::link::full_link_with(p, Some((&v.name, &objs)))?;
    Ok((rep, link))
}

// ------------------------------------------------------------------------------------------------ entry points

fn err(e: impl std::fmt::Display) -> Error {
    Error::runtime(e.to_string())
}

/// `dcp run --list`: one line per profile.
pub fn run_list(p: &crate::project::Project) -> Result<Vec<String>> {
    let c = p.run_cfg().map_err(err)?;
    let mut out = vec![record(&[("runs", Tok::I(c.runs.len() as i64)), ("variants", Tok::I(c.variants.len() as i64)), ("setups", Tok::I(c.setups.len() as i64))])];
    for r in &c.runs {
        let opt = |x: &Option<String>| x.clone().map(Tok::S).unwrap_or(Tok::No);
        out.push(format!("  {}", record(&[("run", Tok::S(r.name.clone())), ("target", Tok::S(r.target.clone().unwrap_or_else(|| p.targets[0].name.clone()))),
                                          ("variant", opt(&r.variant)), ("setup", Tok::S(r.setup.clone())), ("args", Tok::S(r.args.join(" ")))])));
    }
    Ok(out)
}

/// The target a run profile builds (None: no such profile).
pub fn run_target(p: &crate::project::Project, name: &str) -> Result<Option<String>> {
    let c = p.run_cfg().map_err(err)?;
    Ok(c.runs.iter().find(|r| r.name == name).map(|r| r.target.clone().unwrap_or_else(|| p.targets[0].name.clone())))
}

fn compile_lines(rep: &crate::compile::Report, variant: &str) -> Vec<String> {
    let mut out = vec![record(&[("variant", Tok::S(variant.into())), ("target", Tok::S(rep.target.clone())), ("units", Tok::I(rep.units as i64)),
                                ("compiled", Tok::I(rep.compiled.len() as i64)), ("failed", Tok::I(rep.failed.len() as i64)), ("ms", Tok::I(rep.ms))])];
    out.extend(rep.log.iter().map(|l| format!("  {l}")));
    out
}

/// `dcp build --variant NAME` after the main build: (lines, ok).
pub fn variant_build_command(p: &crate::project::Project, variant: &str, force: bool) -> Result<(Vec<String>, bool)> {
    let v = p.variant(variant).map_err(err)?;
    let (rep, link) = variant_build(p, &v, force).map_err(err)?;
    let mut out = compile_lines(&rep, &v.name);
    let (lines, ok) = crate::matchcmd::link_report_lines(&link);
    out.extend(lines);
    Ok((out, ok && rep.failed.is_empty() && !rep.unavailable))
}

/// `dcp run NAME` in the core: build the profile's variant (or link the main build), stage its setup's directory and
/// write the launch spec build/run/<name>.json. (lines, error, spec path). The main build is the caller's.
#[allow(clippy::too_many_arguments)]
pub fn run_prepare(p: &crate::project::Project, name: &str, no_build: bool, seconds: Option<f64>, extra: Vec<String>,
                   debug: Option<bool>, dump: Option<String>) -> Result<(Vec<String>, Option<String>, Option<String>)> {
    let t0 = std::time::Instant::now();
    let c = p.run_cfg().map_err(err)?;
    let Some(r) = c.runs.iter().find(|r| r.name == name) else {
        let names: Vec<&str> = c.runs.iter().map(|r| r.name.as_str()).collect();
        return Ok((vec![], Some(format!("no [[run]] {} (runs: {})", crate::decl::py_repr(name), if names.is_empty() { "none".into() } else { names.join(", ") })), None));
    };
    let setup = c.setups.iter().find(|s| s.name == r.setup).cloned().ok_or_else(|| err(format!("no [[setup]] {}", r.setup)))?;
    let target = p.target(None).map_err(err)?.clone();
    let root = p.root.to_string_lossy().into_owned();
    let mut lines = vec![];
    // the program: the variant's link, else the main link
    let link_dir = match &r.variant {
        Some(v) => py_path(&format!("{root}/build/link/{}/{v}", target.name)),
        None => py_path(&format!("{root}/build/link/{}", target.name)),
    };
    let exe_name = Path::new(&target.path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let built = PathBuf::from(py_path(&format!("{link_dir}/{exe_name}")));
    if !no_build {
        let (ok, ls) = match &r.variant {
            Some(v) => {
                let v = p.variant(v).map_err(err)?;
                let (rep, link) = variant_build(p, &v, false).map_err(err)?;
                let (mut ls, ok) = crate::matchcmd::link_report_lines(&link);
                let mut out = compile_lines(&rep, &v.name);
                out.append(&mut ls);
                (ok && rep.failed.is_empty() && !rep.unavailable, out)
            }
            None => {
                let link = crate::link::full_link(p).map_err(err)?;
                let (ls, ok) = crate::matchcmd::link_report_lines(&link);
                (ok, ls)
            }
        };
        lines.extend(ls);
        if !ok {
            return Ok((lines, Some(format!("run {name}: the build does not link: nothing staged")), None));
        }
    }
    if !built.exists() {
        return Ok((lines, Some(format!("run {name}: {} does not exist{}", built.display(), if no_build { " (run without --no-build)" } else { "" })), None));
    }
    let target_dir = Path::new(&target.path).parent().map(|d| d.to_string_lossy().into_owned()).unwrap_or_default();
    let dir = PathBuf::from(expand(p, &setup.dir, &target_dir));
    std::fs::create_dir_all(&dir).map_err(|e| err(format!("{}: {e}", dir.display())))?;
    let mut st = Staged::default();
    for s in &setup.stages {
        let from = PathBuf::from(expand(p, &s.from, &target_dir));
        if inside(&dir, &from) {
            return Ok((lines, Some(format!("setup {}: the run directory {} lies inside {}, which staging only reads", setup.name, dir.display(), from.display())), None));
        }
        if let Err(e) = stage_one(&from, &dir, &s.link, &s.copy, &mut st) {
            return Ok((lines, Some(format!("setup {}: {e}", setup.name)), None));
        }
    }
    let exe = dir.join(setup.exe.clone().unwrap_or(exe_name));
    st.exe_copied = place_exe(&built, &exe).map_err(err)?;
    let s = |x: &Path| x.to_string_lossy().into_owned();
    let map = py_path(&format!("{link_dir}/{}.map", target.name));
    let hook_env: BTreeMap<&str, String> = [
        ("DCP_ROOT", root.clone()), ("DCP_TARGET", target.name.clone()), ("DCP_VARIANT", r.variant.clone().unwrap_or_default()),
        ("DCP_RUN", r.name.clone()), ("DCP_SETUP", setup.name.clone()), ("DCP_RUN_DIR", s(&dir)), ("DCP_EXE", s(&exe)),
        ("DCP_ORIGINAL", target.path.clone()), ("DCP_MAP", map),
    ].into_iter().collect();
    let mut args = r.args.clone();
    args.extend(extra);
    let debug = debug.unwrap_or(r.debug);
    let dump = dump.unwrap_or_else(|| r.dump.clone());
    if !DUMPS.contains(&dump.as_str()) {
        return Ok((lines, Some(format!("--dump {dump}: none of {}", DUMPS.join(", "))), None));
    }
    let symbols = py_path(&format!("{root}/build/run/{name}.symbols.tsv"));
    if debug {
        std::fs::create_dir_all(py_path(&format!("{root}/build/run"))).map_err(|e| err(e.to_string()))?;
        if let Err(e) = run_symbols(p, &hook_env["DCP_MAP"], &symbols, r.variant.as_deref()) {
            lines.push(format!("  note the symbol table is not written ({e}): crash reports name module offsets only"));
        }
    }
    let spec = json!({
        "run": r.name, "root": root, "dir": s(&dir), "exe": s(&exe), "args": args,
        "env": Value::Object(r.env.iter().map(|(k, v)| (k.clone(), json!(v))).collect()),
        "seconds": seconds.unwrap_or(r.seconds), "steps": setup.steps, "after": setup.after, "hook_env": hook_env,
        "debug": debug, "dump": dump, "symbols": symbols, "crash_root": py_path(&format!("{root}/build/crash")),
    });
    let spec_path = py_path(&format!("{root}/build/run/{name}.json"));
    std::fs::create_dir_all(Path::new(&spec_path).parent().unwrap()).map_err(|e| err(e.to_string()))?;
    std::fs::write(&spec_path, serde_json::to_string_pretty(&spec).unwrap_or_default()).map_err(|e| err(format!("{spec_path}: {e}")))?;
    lines.push(record(&[("run", Tok::S(r.name.clone())), ("dir", Tok::S(crate::vc6::rel_to(&root, &s(&dir)))), ("exe", Tok::S(exe.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default())),
                        ("exe_copied", Tok::B(st.exe_copied)), ("linked", Tok::I(st.linked as i64)), ("copied", Tok::I(st.copied as i64)), ("kept", Tok::I(st.kept as i64)),
                        ("steps", Tok::I(setup.steps.len() as i64)), ("debug", Tok::B(debug)), ("ms", Tok::I(t0.elapsed().as_millis() as i64))]));
    Ok((lines, None, Some(spec_path)))
}

/// The symbol table of a debugged run (debugger.rs): the link map's symbols with their unit (by the object's content
/// hash: the main build's tu rows, the variant's rows), definition line and original address (the source scan).
/// Written again only when the map or the sources changed.
fn run_symbols(p: &Project, map: &str, out: &str, variant: Option<&str>) -> Result<(), String> {
    let src = p.input_hash("src").map_err(|e| e.to_string())?.unwrap_or_default();
    let key = format!("{} {src}", fsmemo::sha256(map).map_err(|e| format!("{map}: {e}"))?);
    if crate::debugger::symbols_key(out) == key {
        return Ok(());
    }
    let bytes = std::fs::read(map).map_err(|e| format!("{map}: {e}"))?;
    let text: String = bytes.iter().map(|&b| b as char).collect(); // latin-1
    let mut by_obj: HashMap<String, String> = HashMap::new();
    for (u, row) in crate::compile::tu_rows(&p.store_path()).map_err(|e| e.to_string())? {
        by_obj.insert(format!("{}.obj", row.obj_hash), u);
    }
    if let Some(v) = variant {
        let rows: Value = std::fs::read_to_string(crate::compile::variant_rows_path(p, v)).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
        for (u, row) in rows.as_object().into_iter().flatten() {
            if let Some(h) = row["obj_hash"].as_str() {
                by_obj.insert(format!("{h}.obj"), u.clone());
            }
        }
    }
    let root = p.root.to_string_lossy().into_owned();
    let scan = crate::frontend::scan(&root, Some(&src))?;
    let default = p.targets[0].name.clone();
    let mut source: HashMap<(String, String), (i64, Option<u32>)> = HashMap::new();
    for f in scan.functions() {
        let Some(unit) = f.0 .0.strip_prefix("src/").and_then(|r| r.strip_suffix(".c")) else { continue };
        let orig = f.0 .4.iter().find(|(t, _)| t.as_deref().unwrap_or(&default) == p.target_name).map(|x| x.1 as u32);
        source.entry((unit.to_string(), f.0 .3.clone())).or_insert((f.0 .1, orig));
    }
    let syms = crate::debugger::symbols(&text, |o| by_obj.get(o).cloned(), |u, n| source.get(&(u.to_string(), n.to_string())).copied());
    crate::debugger::write_symbols(out, &key, &syms)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(s: &str) -> toml::Table {
        s.parse().unwrap()
    }

    const GOOD: &str = r#"
[[variant]]
name = "debug"
targets = ["exe"]
  [[variant.unit]]
  glob = ["dd_*", "gfx"]
  cflags = ["/DFIX"]
  [[variant.unit]]
  glob = "main"
  cflags = ["/DSTART"]
[[setup]]
name = "game"
exe = "Game.exe"
  [[setup.stage]]
  from = "{target.dir}"
  link = ["*/"]
  copy = ["*.ini"]
  [[setup.step]]
  run = ["python", "shim.py"]
[[run]]
name = "play"
variant = "debug"
setup = "game"
args = ["DIRECTWINDOW"]
env = { START = "new", N = 3 }
seconds = 20
"#;

    #[test]
    fn parses_and_resolves_flags() {
        let c = parse(&cfg(GOOD), &["exe".into()]).unwrap();
        let v = &c.variants[0];
        assert_eq!(v.extra("dd_vesa"), ["/DFIX"]);
        assert_eq!(v.extra("main"), ["/DSTART"]);
        assert!(v.extra("shp").is_empty());
        assert_eq!(c.setups[0].dir, "build/run/game");
        assert_eq!(c.setups[0].steps, vec![vec!["python".to_string(), "shim.py".into()]]);
        let r = &c.runs[0];
        assert_eq!((r.seconds, r.env.clone()), (20.0, vec![("N".to_string(), "3".to_string()), ("START".into(), "new".into())]));
    }

    #[test]
    fn contradictions_are_errors() {
        let t = ["exe".to_string()];
        let e = |s: &str| parse(&cfg(s), &t).unwrap_err();
        assert!(e("[[variant]]\nname = \"d\"\ncflag = []\n").contains("unknown keys cflag"));
        assert!(e("[[variant]]\nname = \"d\"\ntargets = [\"dll\"]\n").contains("no target 'dll'"));
        assert!(e("[[setup]]\nname = \"s\"\n[[run]]\nname = \"r\"\nsetup = \"s\"\nvariant = \"x\"\n").contains("no [[variant]] 'x'"));
        assert!(e("[[run]]\nname = \"r\"\nsetup = \"s\"\n").contains("no [[setup]] 's'"));
        assert!(e("[[setup]]\nname = \"s\"\n[[setup.step]]\nrun = []\n").contains("run is missing or empty"));
        assert!(e("[[setup]]\nname = \"s\"\n[[setup]]\nname = \"s\"\n").contains("declared twice"));
        assert!(e("[[setup]]\nname = \"s\"\nexe = \"a/b.exe\"\n").contains("not a path"));
        assert!(e("[[variant]]\nname = \"d\"\ntargets = [\"exe\"]\n[[setup]]\nname = \"s\"\n[[run]]\nname = \"r\"\nsetup = \"s\"\nvariant = \"d\"\ntarget = \"exe\"\nseconds = -1\n")
            .contains("seconds"));
    }

    #[test]
    fn staging() {
        let base = crate::testkit::scratch("run-stage");
        let _ = std::fs::remove_dir_all(&base);
        let (orig, other, dir) = (base.join("orig"), base.join("other"), base.join("run"));
        for d in [orig.join("Data"), orig.join("Movie"), other.join("Data"), dir.clone()] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(orig.join("Data").join("a.bin"), "a").unwrap();
        std::fs::write(orig.join("game.ini"), "x=1").unwrap();
        std::fs::write(orig.join("Mss32.DLL"), "dll").unwrap();
        std::fs::write(orig.join("Game.exe"), "orig").unwrap();
        let (link, copy) = (vec!["*/".to_string(), "*.dll".into()], vec!["*.ini".to_string()]);
        // a junction left pointing elsewhere is made again
        make_dir_link(&dir.join("Data"), &other.join("Data")).unwrap();
        let mut st = Staged::default();
        stage_one(&orig, &dir, &link, &copy, &mut st).unwrap();
        assert_eq!((st.linked, st.copied, st.kept), (2, 2, 0), "{st:?}");
        assert!(dir.join("Data").join("a.bin").exists());
        assert!(!dir.join("Game.exe").exists());
        // a second staging keeps everything; an edited copy stays edited; the original is untouched
        std::fs::write(dir.join("game.ini"), "x=2").unwrap();
        let mut st = Staged::default();
        stage_one(&orig, &dir, &link, &copy, &mut st).unwrap();
        assert_eq!((st.linked, st.copied, st.kept), (0, 0, 4), "{st:?}");
        assert_eq!(std::fs::read_to_string(orig.join("game.ini")).unwrap(), "x=1");
        // a real folder in the way is not removed
        std::fs::remove_dir(dir.join("Movie")).unwrap();
        std::fs::create_dir(dir.join("Movie")).unwrap();
        assert!(stage_one(&orig, &dir, &link, &copy, &mut Staged::default()).unwrap_err().contains("is not a link"));
        // the program is copied when its bytes change only
        let built = base.join("built.exe");
        std::fs::write(&built, "v1").unwrap();
        assert!(place_exe(&built, &dir.join("Game.exe")).unwrap());
        assert!(!place_exe(&built, &dir.join("Game.exe")).unwrap());
        std::fs::write(&built, "v2").unwrap();
        assert!(place_exe(&built, &dir.join("Game.exe")).unwrap());
        for d in ["Data", "Movie"] {
            let _ = std::fs::remove_dir(dir.join(d));
        }
        let _ = std::fs::remove_dir_all(&base);
    }
}
