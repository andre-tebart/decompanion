//! The command-line tests: whole dcp commands in this process over a synthetic project (the tests/ of the Python
//! frontend, ported). The synthetic dll and its archives are conftest.py's, byte for byte, so the expected values are
//! the ones the Python tests asserted. Tests that need an installation (VC6, libclang, Ghidra, the GOG binaries) are
//! `#[ignore = "e2e: ..."]`: `cargo test -- --ignored` runs them.

mod layout;
mod launch;
mod layout_tools;
mod matching;
mod multitarget;
mod obligations;
mod seams;
mod servers;
mod source_checks;
mod targets;

use crate::pystore;
use crate::store::SFact;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};

pub use crate::testkit::*;


static N: AtomicUsize = AtomicUsize::new(0);

/// A fresh empty directory for one test.
pub fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("dcp-cli-{}-{}-{name}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}


pub fn read(root: &Path, rel: &str) -> String {
    std::fs::read_to_string(root.join(rel)).unwrap()
}

/// The config file with `old` replaced by `new` (once; `old` must be there).
pub fn set_config(root: &Path, old: &str, new: &str) {
    let t = read(root, "decompanion.toml");
    assert!(t.contains(old), "{old:?} not in the config");
    write(root, "decompanion.toml", &t.replacen(old, new, 1));
}

/// Key lines appended to the [[target]] table of `name`.
pub fn target_table(root: &Path, name: &str, extra: &str) {
    set_config(root, &format!("name = \"{name}\"\n"), &format!("name = \"{name}\"\n{extra}\n"));
}


pub fn tiny() -> PathBuf {
    make_project(&tmp("proj").join("proj"), false)
}

pub fn tiny2() -> PathBuf {
    make_project(&tmp("proj2").join("proj2"), true)
}

/// Write src/<name>.c from its parts, a blank line between two parts; an empty part is left out.
pub fn unit(root: &Path, name: &str, parts: &[&str]) -> PathBuf {
    let text = parts.iter().filter(|p| !p.is_empty()).map(|p| if p.ends_with('\n') { p.to_string() } else { format!("{p}\n") }).collect::<Vec<_>>().join("\n");
    write(root, &format!("src/{name}.c"), &text);
    root.join("src").join(format!("{name}.c"))
}

/// Run a command line in this process over the project at root: (exit code, stdout, stderr).
pub fn dcp3(root: &Path, args: &[&str]) -> (i32, String, String) {
    let _shared = crate::fsmemo::EXCLUSIVE.read().unwrap_or_else(|e| e.into_inner());
    let mut argv: Vec<String> = vec!["dcp".into(), "--root".into(), root.to_string_lossy().into_owned()];
    argv.extend(args.iter().map(|a| a.to_string()));
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = crate::cli::run(&argv, &mut out, &mut err);
    (code, String::from_utf8_lossy(&out).into_owned(), String::from_utf8_lossy(&err).into_owned())
}

/// (exit code, stdout).
pub fn dcp(root: &Path, args: &[&str]) -> (i32, String) {
    let (c, o, _) = dcp3(root, args);
    (c, o)
}

/// A command line without --root (init).
pub fn dcp_bare(args: &[&str]) -> (i32, String, String) {
    let _shared = crate::fsmemo::EXCLUSIVE.read().unwrap_or_else(|e| e.into_inner());
    let mut argv: Vec<String> = vec!["dcp".into()];
    argv.extend(args.iter().map(|a| a.to_string()));
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = crate::cli::run(&argv, &mut out, &mut err);
    (code, String::from_utf8_lossy(&out).into_owned(), String::from_utf8_lossy(&err).into_owned())
}

pub fn project(root: &Path, target: Option<&str>) -> crate::project::Project {
    crate::project::Project::find(Some(&root.to_string_lossy()), target).unwrap()
}

/// The facts of one kind of a target's current runs.
pub fn facts(root: &Path, kind: &str, target: Option<&str>) -> Vec<Rc<SFact>> {
    let p = project(root, target);
    let db = p.store_path();
    pystore::st_open(&db, &p.main_uri()).unwrap();
    pystore::st_facts(&db, Some(kind), None, None, None).unwrap().into_iter().map(|(_, f)| f).collect()
}

/// A conflict: (severity, check, lo, hi, message, a, b).
pub type Conflict = (String, String, i64, i64, String, String, String);

pub fn conflicts(root: &Path, target: Option<&str>) -> Vec<Conflict> {
    let p = project(root, target);
    let db = p.store_path();
    pystore::st_open(&db, &p.main_uri()).unwrap();
    pystore::st_conflicts(&db, None, None).unwrap()
}

pub fn conflicts_of(root: &Path, target: Option<&str>, check: &str) -> Vec<Conflict> {
    conflicts(root, target).into_iter().filter(|c| c.1 == check).collect()
}

/// The rules of a target refreshed as a command refreshes them: whether any ran.
pub fn engine_ran(root: &Path, target: Option<&str>) -> bool {
    let p = project(root, target);
    pystore::st_open(&p.store_path(), &p.main_uri()).unwrap();
    crate::engine::engine_run(&p, "", None, false).unwrap().iter().any(|r| r.ran)
}

/// Switch the project's analyzer to Ghidra: a stand-in installation beside the project whose analyzeHeadless copies
/// the batch_decompile file `export` to where the post-script would write it.
pub fn use_fake_ghidra(root: &Path, export: &Path) {
    let fake = root.parent().unwrap().join(format!("{}-ghidra", root.file_name().unwrap().to_string_lossy()));
    std::fs::create_dir_all(fake.join("support")).unwrap();
    std::fs::create_dir_all(fake.join("jdk").join("bin")).unwrap();
    let bat = format!("@echo off\r\n:loop\r\nif \"%~1\"==\"\" goto :eof\r\nif \"%~1\"==\"-postScript\" (\r\n  copy /y \"{}\" \"%~3\" >nul\r\n  goto :eof\r\n)\r\nshift\r\ngoto loop\r\n",
                      export.to_string_lossy());
    std::fs::write(fake.join("support").join("analyzeHeadless.bat"), bat).unwrap();
    set_config(root, "[analyzer]\nplugin = \"none\"\n",
               &format!("[analyzer]\nplugin = \"ghidra\"\nroot = \"{}\"\njava_home = \"{}\"\n", posix(&fake), posix(&fake.join("jdk"))));
}

/// The sha256 of a file.
pub fn sha256_of(p: &Path) -> String {
    crate::fsmemo::sha256(&p.to_string_lossy()).unwrap()
}

/// The first line of `out` that starts with `prefix`.
pub fn line_with<'a>(out: &'a str, prefix: &str) -> &'a str {
    out.lines().find(|l| l.starts_with(prefix)).unwrap_or_else(|| panic!("no line {prefix:?} in:\n{out}"))
}
