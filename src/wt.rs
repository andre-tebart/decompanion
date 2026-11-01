//! Worktrees: `dcp wt new|list|drop` and `dcp seed`.
//!
//! A worktree is a git worktree of the target project at ../<project>-wt/<NAME> on branch wt/<NAME>. Its build/
//! starts empty; .dcp/main_store names the main checkout's build directory, and every store of the worktree
//! (build/<target>.sqlite) overlays main's store of the same target: a rule run whose inputs main already ran is
//! copied from main instead of recomputed, blobs (the analyzer's drafts, disassembly) are read from main. `dcp seed
//! PATH` is the plain-copy fallback: it copies this checkout's stores into another checkout's build/.

use crate::cliread::{record, Tok};
use pyo3::prelude::*;
use std::path::{Path, PathBuf};

fn posix(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

fn git(root: &Path, args: &[&str]) -> Result<String, String> {
    let o = std::process::Command::new("git").arg("-C").arg(root).args(args).output().map_err(|e| e.to_string())?;
    if !o.status.success() {
        let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
        let msg = if err.is_empty() { String::from_utf8_lossy(&o.stdout).trim().to_string() } else { err };
        return Err(format!("git {}: {msg}", args.join(" ")));
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

/// A path as Path.resolve() spells it.
fn resolved(p: &Path) -> PathBuf {
    let abs = std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
    std::fs::canonicalize(&abs).map(|c| PathBuf::from(c.to_string_lossy().trim_start_matches(r"\\?\").to_string())).unwrap_or(abs)
}

fn new(root: &Path, name: &str) -> Result<Vec<String>, String> {
    if root.join(".dcp").join("main_store").exists() {
        return Err(format!("{} is a worktree itself; run `dcp wt new` in the main checkout", root.display()));
    }
    if !root.join(".git").exists() {
        return Err(format!("{} is not a git repository", root.display()));
    }
    let rname = root.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let path = root.parent().unwrap_or(root).join(format!("{rname}-wt")).join(name);
    if path.exists() {
        return Err(format!("{} exists", path.display()));
    }
    git(root, &["worktree", "add", "-b", &format!("wt/{name}"), &path.to_string_lossy()])?;
    std::fs::create_dir_all(path.join(".dcp")).map_err(|e| e.to_string())?;
    std::fs::write(path.join(".dcp").join("main_store"), posix(&resolved(&root.join("build"))) + "\n").map_err(|e| e.to_string())?;
    Ok(vec![record(&[("worktree", Tok::S(name.into())), ("path", Tok::S(posix(&path))), ("branch", Tok::S(format!("wt/{name}"))),
                     ("overlay", Tok::S(posix(&root.join("build"))))])])
}

/// The worktrees on wt/* branches: (name, worktree path, HEAD).
fn entries(root: &Path) -> Result<Vec<(String, String, String)>, String> {
    let mut out = vec![];
    let (mut wt, mut head, mut branch) = (String::new(), String::new(), String::new());
    for line in git(root, &["worktree", "list", "--porcelain"])?.lines().chain([""]) {
        if line.is_empty() {
            if let Some(n) = branch.strip_prefix("refs/heads/wt/") {
                out.push((n.to_string(), wt.clone(), head.clone()));
            }
            (wt, head, branch) = (String::new(), String::new(), String::new());
            continue;
        }
        let (k, v) = line.split_once(' ').unwrap_or((line, ""));
        match k {
            "worktree" => wt = v.to_string(),
            "HEAD" => head = v.to_string(),
            "branch" => branch = v.to_string(),
            _ => {}
        }
    }
    Ok(out)
}

fn list(root: &Path) -> Result<Vec<String>, String> {
    let es = entries(root)?;
    let mut out = vec![format!("worktrees={}", es.len())];
    for (name, wt, head) in es {
        let path = PathBuf::from(&wt);
        out.push(record(&[("worktree", Tok::S(name)), ("path", Tok::S(posix(&path))), ("head", Tok::S(head.chars().take(12).collect())),
                          ("overlay", Tok::B(path.join(".dcp").join("main_store").exists()))]));
    }
    Ok(out)
}

fn drop(root: &Path, name: &str, force: bool) -> Result<Vec<String>, String> {
    let Some((_, wt, _)) = entries(root)?.into_iter().find(|e| e.0 == name) else {
        return Err(format!("no worktree wt/{name}"));
    };
    let mut args = vec!["worktree", "remove"];
    if force {
        args.push("--force");
    }
    args.push(&wt);
    git(root, &args)?;
    let mut out = vec![format!("removed {wt}")];
    out.push(match git(root, &["branch", if force { "-D" } else { "-d" }, &format!("wt/{name}")]) {
        Ok(_) => format!("deleted branch wt/{name}"),
        Err(_) => format!("kept branch wt/{name} (not merged; --force deletes it)"),
    });
    Ok(out)
}

/// Copy every store of the build directory into dest/build (a consistent copy while WAL is in use).
fn seed(build: &Path, dest: &Path) -> Result<Vec<String>, String> {
    let dest = resolved(dest);
    let to = dest.join("build");
    std::fs::create_dir_all(&to).map_err(|e| e.to_string())?;
    let mut stores: Vec<PathBuf> = std::fs::read_dir(build).map(|rd| rd.flatten().map(|e| e.path()).collect()).unwrap_or_default();
    stores.retain(|p| p.extension().is_some_and(|x| x == "sqlite") && p.is_file());
    stores.sort_by_key(|p| p.to_string_lossy().to_lowercase());
    let mut names = vec![];
    for p in &stores {
        let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let target = to.join(&name);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", target.to_string_lossy()));
        }
        let c = rusqlite::Connection::open(p).map_err(|e| format!("{}: {e}", p.display()))?;
        c.execute("VACUUM INTO ?1", [target.to_string_lossy()]).map_err(|e| format!("{}: {e}", p.display()))?;
        names.push(name);
    }
    Ok(vec![record(&[("seeded", Tok::S(posix(&dest))), ("stores", Tok::S(if names.is_empty() { "-".into() } else { names.join(",") }))])])
}

/// `dcp wt new|list|drop NAME [--force]` and `dcp seed PATH` of the project at root: (lines, the error to exit 2 with).
#[pyfunction]
#[pyo3(signature = (root, cmd, arg=None, force=false))]
pub fn wt_command(root: &str, cmd: &str, arg: Option<String>, force: bool) -> (Vec<String>, Option<String>) {
    let root = Path::new(root);
    let arg = arg.unwrap_or_default();
    let r = match cmd {
        "new" => new(root, &arg),
        "list" => list(root),
        "drop" => drop(root, &arg, force),
        "seed" => seed(&root.join("build"), Path::new(&arg)),
        _ => Err(format!("unknown worktree command {cmd}")),
    };
    match r {
        Ok(lines) => (lines, None),
        Err(e) => (vec![], Some(e)),
    }
}
