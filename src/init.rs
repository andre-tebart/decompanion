//! `dcp init DIR TARGET`: create a project around one binary; `dcp skills install`.
//!
//! The project is a git repository of its own; the `dcp` on PATH works on it. It holds the typed state (sources,
//! decl/, decompanion.toml, names.log, claims.log, ledger/grades.tsv) and nothing derived (build/ is ignored). The
//! original binary is referenced by path and pinned by sha256; it is never copied into the repository (a PE32
//! image of an x86 machine). Init declares nothing: the toolchain, the library archives and the analyzer are
//! obligations (decide.rs) that `dcp status` names with their evidence once `dcp setup` ran, resolved by `dcp
//! toolchain declare`, `dcp libs declare` and `dcp analyzer declare`, each with a reason. The [analyzer] table holds
//! the Ghidra installation this machine has until it is confirmed. The decompanion skills
//! (skills/ of the decompanion repository) are installed into .claude/skills/ (`dcp skills install` updates them in
//! an existing project).

use crate::error::{Error, Result};
use crate::project::CONFIG_NAME;
use std::path::{Path, PathBuf};

const CONFIG: &str = r#"# decompanion project: {name}
# Everything here is typed state; `dcp` derives the rest into build/ (ignored).
#
# Init declares nothing. Every decision of the decompilation is an obligation `dcp status` names when it is due,
# with the evidence and the command that resolves it: `dcp toolchain declare compiler=... linker=... root=...
# cflags=... --why "..."`, `dcp libs declare ARCHIVE... --why "..."`, `dcp analyzer declare ... --why "..."`.
# The declarations land here with their reasons (reason.<key> = "...").

# The binary built from this codebase: its path and sha256 (computed from the file), and its toolchain declaration
# (compiler, linker, cflags, archives) once made.
{target_block}
[sources]
roots = ["src"]
include = ["include"]

[analyzer]
# Ghidra, which `dcp setup` runs headless for a draft of every function (root, java_home, timeout = seconds per
# function). Its function starts are declarations.
# Written by `dcp init` from what this machine has; an obligation until `dcp analyzer declare` confirms it.
{analyzer}
"#;

const GITATTRIBUTES: &str = "# LF and UTF-8 (no BOM) everywhere: the store hashes file contents.
* text=auto eol=lf
*.dll binary
*.exe binary
*.obj binary
*.lib binary
# append-only logs: keep both sides' additions
names.log merge=union
claims.log merge=union
# the grade baseline is promoted on main only
ledger/grades.tsv merge=ours
";

const GITIGNORE: &str = "/build/
.dcp/
";

/// A TOML basic string.
fn toml_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn posix(s: &str) -> String {
    s.replace('\\', "/")
}

/// A path as Path.resolve() spells it (native separators; the real case of what exists).
fn resolve(p: &Path) -> PathBuf {
    let abs = std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
    match std::fs::canonicalize(&abs) {
        Ok(c) => PathBuf::from(c.to_string_lossy().trim_start_matches(r"\\?\").to_string()),
        Err(_) => abs,
    }
}

/// The [target] table of a binary: what the file itself gives (no declaration).
fn target_block(path: &Path, sha: &str) -> Vec<String> {
    vec!["[target]".into(), format!("path = {}", toml_str(&posix(&path.to_string_lossy()))), format!("sha256 = {}", toml_str(sha))]
}

/// The sha256 of a binary that reads as a PE32 image of an x86 machine.
fn open_target(path: &Path) -> Result<String, String> {
    let shown = path.to_string_lossy();
    let data = std::fs::read(path).map_err(|e| format!("{shown}: {e}"))?;
    let sha = crate::fsmemo::hex(&<sha2::Sha256 as sha2::Digest>::digest(&data));
    let img = crate::pe::Image::parse(data).map_err(|e| format!("{shown}: not a PE32 image ({e})"))?;
    if img.default_isa() != Some("x86") {
        return Err(format!("{shown}: machine type {:#x} is not x86", img.machine));
    }
    Ok(sha)
}

/// The [analyzer] keys of a new project: the Ghidra installation it finds (a comment when there is none).
fn analyzer_lines() -> Vec<String> {
    let inst = crate::analyzers::Analyzer::default_unconfigured().available();
    if let Some(r) = inst.reason {
        return vec![format!("# {r}")];
    }
    let mut out = vec![];
    for (v, k) in [(inst.root, "root"), (inst.java_home, "java_home")] {
        if let Some(v) = v {
            out.push(format!("{k} = {}", toml_str(&posix(&v))));
        }
    }
    out
}

mod shipped {
    include!(concat!(env!("OUT_DIR"), "/skills.rs"));
}

/// Copy the shipped skills (skills/<name>/... of the decompanion repository, built into the core: build.rs) into
/// <root>/.claude/skills/; the paths written (relative, posix). An unchanged file is not written again unless
/// `force`.
pub fn install_skills(root: &Path, force: bool) -> std::io::Result<Vec<String>> {
    let mut out = vec![];
    for (rel, data) in shipped::SKILLS {
        let to = format!(".claude/skills/{rel}");
        let dst = root.join(&to);
        if !force && std::fs::read(&dst).is_ok_and(|old| old == *data) {
            continue;
        }
        std::fs::create_dir_all(dst.parent().unwrap())?;
        std::fs::write(&dst, data)?;
        out.push(to);
    }
    Ok(out)
}

fn io(e: std::io::Error) -> String {
    e.to_string()
}

fn init(dir: &str, target: &str, name: Option<String>) -> Result<Vec<String>, String> {
    let dir = resolve(Path::new(dir));
    let target = resolve(Path::new(target));
    if !target.exists() {
        return Err(format!("target {} does not exist", target.display()));
    }
    let name = name.unwrap_or_else(|| dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default());
    let sha = open_target(&target)?;
    for sub in ["decl", "src", "include", "ledger", "notes", ".claude/skills"] {
        std::fs::create_dir_all(dir.join(sub)).map_err(io)?;
    }
    let dir = resolve(&dir);
    let analyzer = analyzer_lines();
    let target_file = target.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let files: [(&str, String); 10] = [
        (CONFIG_NAME, CONFIG.replace("{name}", &name).replace("{analyzer}", &analyzer.join("\n"))
            .replace("{target_block}", &(target_block(&target, &sha).join("\n") + "\n"))),
        (".gitattributes", GITATTRIBUTES.into()),
        (".gitignore", GITIGNORE.into()),
        (".editorconfig", "root = true\n\n[*]\ncharset = utf-8\nend_of_line = lf\ninsert_final_newline = true\n".into()),
        ("decl/text.dcl", "# declarations about the code sections; one fact per line, sorted by address (`dcp decl add` inserts)\n\
                           # ADDR[..END] KIND [WORD ...] [key=value ...] -- reason\n".into()),
        ("decl/data.dcl", "# declarations about the data sections; one fact per line, sorted by address (`dcp decl add` inserts)\n".into()),
        ("names.log", String::new()),
        ("claims.log", String::new()),
        ("ledger/grades.tsv", String::new()),
        ("README.md", format!("# {name}\n\nA decompanion target project for `{target_file}`. Run `dcp setup`, then follow `dcp status`.\n")),
    ];
    for (rel, text) in &files {
        let p = dir.join(rel);
        if !p.exists() {
            std::fs::write(&p, text).map_err(io)?;
        }
    }
    if !dir.join(".git").exists() {
        let st = std::process::Command::new("git").args(["init", "-q", "-b", "main"]).current_dir(&dir).status().map_err(io)?;
        if !st.success() {
            return Err(format!("git init failed in {}", dir.display()));
        }
    }
    let skills = install_skills(&dir, false).map_err(io)?;
    let mut out = vec![
        format!("initialised {} for {target_file} (sha256 {})", dir.display(), &sha[..16]),
        "  declared: nothing (toolchain, libraries, analyzer: the obligations of dcp status)".to_string(),
        format!("  analyzer (to confirm): {}", analyzer.iter().filter(|l| !l.starts_with('#')).cloned().collect::<Vec<_>>().join("  ")),
    ];
    if !skills.is_empty() {
        let names: std::collections::BTreeSet<&str> = skills.iter().filter_map(|x| x.split('/').nth(2)).collect();
        out.push(format!("  skills: {} in .claude/skills/ (dcp skills install updates them)", names.into_iter().collect::<Vec<_>>().join(", ")));
    }
    out.push("next: cd there, dcp setup (it prints the open obligations; dcp status repeats them)".into());
    Ok(out)
}

/// Create the project around one binary (module docs); the lines to print, or the message to exit with.
pub fn init_project(dir: &str, target: &str, name: Option<String>) -> (Vec<String>, Option<String>) {
    match init(dir, target, name) {
        Ok(lines) => (lines, None),
        Err(e) => (vec![], Some(e)),
    }
}

/// `dcp skills install`: the paths written.
pub fn skills_install(root: &str, force: bool) -> Result<Vec<String>> {
    install_skills(Path::new(root), force).map_err(|e| Error::os(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_lines() {
        assert_eq!(toml_str(r#"a\b"c"#), r#""a\\b\"c""#);
        assert_eq!(target_block(Path::new(r"C:\x\a.dll"), "ab"), ["[target]", "path = \"C:/x/a.dll\"", "sha256 = \"ab\""]);
    }
}
