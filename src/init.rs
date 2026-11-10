//! `dcp init DIR TARGET`: create a target project around one binary; `dcp target add`; `dcp skills install`.
//!
//! The project is a git repository of its own; the `dcp` on PATH works on it. It holds the typed state (sources,
//! decl/, decompanion.toml, names.log, claims.log, ledger/grades.tsv) and nothing derived (build/ is ignored). The
//! original binary is referenced by path and pinned by sha256; it is never copied into the repository. The image
//! format is the registered one that reads the binary, the instruction set the one its machine type implies
//! (computed, not decisions). Init declares nothing: the toolchain, the library archives and the analyzer are
//! obligations (decide.rs) that `dcp status` names with their evidence once `dcp setup` ran, resolved by `dcp
//! toolchain declare`, `dcp libs declare` and `dcp analyzer declare`, each with a reason. The [analyzer] table holds
//! the plugin this machine has (ghidra when found, else none) until it is confirmed. The decompanion skills
//! (skills/ of the decompanion repository) are installed into .claude/skills/ (`dcp skills install` updates them in
//! an existing project).

use crate::error::{Error, Result};
use crate::project::{is_identifier, target_name_of, CONFIG_NAME, IMAGE_FORMATS};
use std::path::{Path, PathBuf};

const CONFIG: &str = r#"# decompanion target project: {name}
# Everything here is typed state; `dcp` derives the rest into build/ (ignored).
#
# Init declares nothing. Every decision of the decompilation is an obligation `dcp status` names when it is due,
# with the evidence and the command that resolves it: `dcp toolchain declare compiler=... linker=... root=...
# cflags=... --why "..."`, `dcp libs declare ARCHIVE... --why "..."`, `dcp analyzer declare ... --why "..."`.
# The declarations land here with their reasons (reason.<key> = "...").

# The binaries built from this codebase; the first is the default target (`--target NAME` selects another,
# `dcp target add NAME PATH` adds one). Each target has its own store, build/<name>.sqlite, and its own
# toolchain declaration (compiler, linker, cflags, archives). name, path, sha256, image and isa are computed
# from the file.
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

/// The lines of one [[target]] table: what the file itself gives (no declaration).
fn target_block(name: &str, path: &Path, sha: &str, image: &str, isa: &str) -> Vec<String> {
    vec!["[[target]]".into(), format!("name = {}", toml_str(name)), format!("path = {}", toml_str(&posix(&path.to_string_lossy()))),
         format!("sha256 = {}", toml_str(sha)), format!("image = {}", toml_str(image)), format!("isa = {}", toml_str(isa))]
}

/// (image format, instruction set, sha256) of a binary: the first registered format that reads it.
fn open_target(path: &Path) -> Result<(&'static str, &'static str, String), String> {
    let shown = path.to_string_lossy();
    let data = std::fs::read(path).map_err(|e| format!("{shown}: {e}"))?;
    let sha = crate::fsmemo::hex(&<sha2::Sha256 as sha2::Digest>::digest(&data));
    let img = crate::pe::Image::parse(data).map_err(|e| format!("{shown}: no image format reads it ({}: {e})", IMAGE_FORMATS[0]))?;
    let isa = img.default_isa().ok_or_else(|| format!("{shown}: machine type {:#x} implies no known instruction set", img.machine))?;
    Ok((IMAGE_FORMATS[0], isa, sha))
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

fn init(dir: &str, target: &str, name: Option<String>, target_name: Option<String>) -> Result<Vec<String>, String> {
    let dir = resolve(Path::new(dir));
    let target = resolve(Path::new(target));
    if !target.exists() {
        return Err(format!("target {} does not exist", target.display()));
    }
    let name = name.unwrap_or_else(|| dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default());
    let tname = target_name.unwrap_or_else(|| target_name_of(&target.to_string_lossy()));
    if !is_identifier(&tname) {
        return Err(format!("target name {} is not an identifier ([A-Za-z][A-Za-z0-9_-]*)", crate::decl::py_repr(&tname)));
    }
    let (fmt, isa, sha) = open_target(&target)?;
    for sub in ["decl", "src", "include", "ledger", "notes", "libs", ".claude/skills"] {
        std::fs::create_dir_all(dir.join(sub)).map_err(io)?;
    }
    let dir = resolve(&dir);
    let analyzer = analyzer_lines();
    let target_file = target.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let files: [(&str, String); 10] = [
        (CONFIG_NAME, CONFIG.replace("{name}", &name).replace("{analyzer}", &analyzer.join("\n"))
            .replace("{target_block}", &(target_block(&tname, &target, &sha, fmt, isa).join("\n") + "\n"))),
        (".gitattributes", GITATTRIBUTES.into()),
        (".gitignore", GITIGNORE.into()),
        (".editorconfig", "root = true\n\n[*]\ncharset = utf-8\nend_of_line = lf\ninsert_final_newline = true\n".into()),
        ("decl/text.dcl", "# declarations about the code sections; one fact per line, sorted by address (`dcp decl add` inserts)\n\
                           # [TARGET:]ADDR[..END] KIND [WORD ...] [key=value ...] -- reason\n".into()),
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
        format!("initialised {} for {target_file} as target {tname} (sha256 {})", dir.display(), &sha[..16]),
        format!("  computed: image={fmt} isa={isa}; declared: nothing (toolchain, libraries, analyzer: the obligations of dcp status)"),
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
pub fn init_project(dir: &str, target: &str, name: Option<String>, target_name: Option<String>) -> (Vec<String>, Option<String>) {
    match init(dir, target, name, target_name) {
        Ok(lines) => (lines, None),
        Err(e) => (vec![], Some(e)),
    }
}

fn add(root: &str, name: &str, path: &str) -> Result<Vec<String>, String> {
    let cfg_path = Path::new(root).join(CONFIG_NAME);
    let text = crate::fsmemo::read_text(&cfg_path.to_string_lossy()).map_err(io)?;
    let cfg: toml::Table = text.parse().map_err(|e: toml::de::Error| format!("{CONFIG_NAME}: {}", e.message()))?;
    if !is_identifier(name) {
        return Err(format!("target name {} is not an identifier ([A-Za-z][A-Za-z0-9_-]*)", crate::decl::py_repr(name)));
    }
    let path = resolve(Path::new(path));
    if !path.exists() {
        return Err(format!("{} does not exist", path.display()));
    }
    let (fmt, isa, sha) = open_target(&path)?;
    let existing = crate::project::targets_of(root, &text)?;
    if existing.iter().any(|(n, _)| n == name) {
        return Err(format!("target {} exists", crate::decl::py_repr(name)));
    }
    let mut lines: Vec<String> = text.split('\n').map(|l| l.to_string()).collect();
    if matches!(cfg.get("target"), Some(toml::Value::Table(_))) {
        // the milestone-1 form: [target] without a name
        let i = lines.iter().position(|l| l.trim() == "[target]").ok_or("no [target] line")?;
        lines[i] = "[[target]]".into();
        lines.insert(i + 1, format!("name = \"{}\"", target_name_of(&existing[0].1)));
    }
    let heads: Vec<usize> = lines.iter().enumerate().filter(|(_, l)| l.trim() == "[[target]]").map(|(k, _)| k).collect();
    let last = *heads.last().ok_or("no [[target]] table")?;
    let mut end = (last + 1..lines.len()).find(|&k| lines[k].trim_start().starts_with('[')).unwrap_or(lines.len());
    while end > last + 1 && lines[end - 1].trim().is_empty() {
        end -= 1;
    }
    let block = target_block(name, &path, &sha, fmt, isa);
    let mut ins = vec![String::new()];
    ins.extend(block.iter().cloned());
    lines.splice(end..end, ins);
    let new = lines.join("\n");
    new.parse::<toml::Table>().map_err(|e| format!("{CONFIG_NAME}: {}", e.message()))?;
    std::fs::write(&cfg_path, &new).map_err(io)?;
    crate::fsmemo::new_epoch();
    let mut out = vec![format!("added to {CONFIG_NAME}:")];
    out.extend(block.iter().map(|l| format!("  {l}")));
    out.push(format!("target={name}  store=build/{name}.sqlite  (run `dcp setup --target {name}`)"));
    Ok(out)
}

/// `dcp target add`: append a [[target]] table to decompanion.toml (after the last one), rewriting the single-table
/// [target] form into the list form first. Like `dcp init` it declares nothing. The lines, or the message to exit
/// with.
pub fn target_add(root: &str, name: &str, path: &str) -> (Vec<String>, Option<String>) {
    match add(root, name, path) {
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
        assert_eq!(target_block("t", Path::new(r"C:\x\a.dll"), "ab", "pe32", "x86"),
                   ["[[target]]", "name = \"t\"", "path = \"C:/x/a.dll\"", "sha256 = \"ab\"", "image = \"pe32\"", "isa = \"x86\""]);
    }

    #[test]
    fn adds_a_target_to_the_single_table_form() {
        let d = crate::testkit::scratch("init");
        std::fs::create_dir_all(&d).unwrap();
        let bin = d.join("game.exe");
        std::fs::write(&bin, crate::pe::testpe::build(None)).unwrap();
        let root = d.to_string_lossy().into_owned();
        std::fs::write(d.join(CONFIG_NAME), "# top\n[target]\npath = \"game.exe\"\n\n[sources]\nroots = [\"src\"]\n").unwrap();
        let out = add(&root, "other", &bin.to_string_lossy()).unwrap();
        assert_eq!(out[0], "added to decompanion.toml:");
        let text = std::fs::read_to_string(d.join(CONFIG_NAME)).unwrap();
        assert!(text.starts_with("# top\n[[target]]\nname = \"game\"\npath = \"game.exe\"\n\n[[target]]\nname = \"other\"\n"), "{text}");
        assert!(text.ends_with("isa = \"x86\"\n\n[sources]\nroots = [\"src\"]\n"), "{text}");
        assert_eq!(add(&root, "other", &bin.to_string_lossy()).unwrap_err(), "target 'other' exists");
        assert!(add(&root, "bad name", &bin.to_string_lossy()).unwrap_err().contains("is not an identifier"));
        std::fs::remove_dir_all(&d).unwrap();
    }
}
