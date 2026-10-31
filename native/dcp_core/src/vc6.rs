//! CL.EXE and LINK.EXE of Visual C++ 6: the environment they run in, one process per translation unit, the include
//! set from the preprocessor's `#line` directives (VC6 has no /showIncludes), and the diagnostics.
//!
//! The environment: VC98/Bin and Common/MSDev98/Bin (MSPDB60.DLL) on PATH, VC98/Include on INCLUDE, VC98/Lib on LIB;
//! `[toolchain] include_dirs` / `lib_dirs` (paths, `{toolchain.root}` expanded) are searched before them.

use crate::project::{py_path, Project};
use std::path::Path;
use std::process::Command;
use std::sync::LazyLock;

/// One compiler or linker message: the file and line it names ('' / 0 for the command line), its severity (error /
/// warning; a fatal error is an error), the tool's code (C2065, D4002, LNK2001) and the text.
#[derive(Clone, Debug)]
pub struct Diag {
    pub file: String,
    pub line: i64,
    pub severity: String,
    pub code: String,
    pub message: String,
}

impl Diag {
    pub fn text(&self) -> String {
        let at = if self.file.is_empty() { "command line".to_string() } else { format!("{}({})", self.file, self.line) };
        format!("{at}: {} {}: {}", self.severity, self.code, self.message)
    }
}

pub struct CompileResult {
    pub ok: bool,
    pub log: String,
    pub diags: Vec<Diag>,
    pub refused: Vec<String>,
}

/// The VC6 installation under the toolchain root and the extra header / library directories of the configuration.
#[derive(Clone)]
pub struct Tools {
    pub root: Option<String>,
    pub extra_include: Vec<String>,
    pub extra_lib: Vec<String>,
}

fn expand(root: &Option<String>, s: &str) -> String {
    py_path(&s.replace("{toolchain.root}", root.as_deref().unwrap_or("")))
}

impl Tools {
    pub fn of(p: &Project) -> Tools {
        let root = p.toolchain_root();
        let list = |k: &str| -> Vec<String> {
            p.cfg.get("toolchain").and_then(|t| t.get(k)).and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str()).map(|s| expand(&root, s)).collect()).unwrap_or_default()
        };
        Tools { extra_include: list("include_dirs"), extra_lib: list("lib_dirs"), root }
    }

    pub fn available(&self) -> bool {
        self.root.as_ref().is_some_and(|r| Path::new(r).join("VC98").join("Bin").join("CL.EXE").exists())
    }

    pub fn bindir(&self) -> String {
        py_path(&format!("{}/VC98/Bin", self.root.as_deref().unwrap_or("")))
    }

    pub fn system_include(&self) -> Vec<String> {
        let mut v = self.extra_include.clone();
        if let Some(r) = &self.root {
            v.push(py_path(&format!("{r}/VC98/Include")));
        }
        v
    }

    pub fn lib_path(&self) -> Vec<String> {
        let mut v = self.extra_lib.clone();
        if let Some(r) = &self.root {
            v.push(py_path(&format!("{r}/VC98/Lib")));
        }
        v
    }

    /// Run a tool of VC98/Bin in cwd: (exit code, stdout, stderr), decoded as Python's text mode does (cp1252, an
    /// undecodable byte replaced).
    pub fn run(&self, tool: &str, args: &[String], cwd: &str) -> Result<(i32, String, String), String> {
        let mut path = format!("{};{}", self.bindir(), py_path(&format!("{}/Common/MSDev98/Bin", self.root.as_deref().unwrap_or(""))));
        if let Some(old) = std::env::var_os("PATH") {
            path.push(';');
            path.push_str(&old.to_string_lossy());
        }
        let out = Command::new(Path::new(&self.bindir()).join(tool)).args(args).current_dir(cwd)
            .env("PATH", path).env("INCLUDE", self.system_include().join(";")).env("LIB", self.lib_path().join(";"))
            .output().map_err(|e| format!("{tool}: {e}"))?;
        Ok((out.status.code().unwrap_or(-1), cp1252(&out.stdout), cp1252(&out.stderr)))
    }

    fn missing(&self) -> CompileResult {
        let msg = format!("VC6 not found under the toolchain root {} (VC98/Bin/CL.EXE)", self.root.as_deref().unwrap_or("None"));
        CompileResult { ok: false, log: format!("{msg}\n"), diags: vec![Diag { file: "".into(), line: 0, severity: "error".into(), code: "toolchain".into(), message: msg }], refused: vec![] }
    }

    /// CL /nologo /c <flags> /I<dirs> /Fo<obj> <src>: one process, one unit.
    pub fn compile(&self, src: &str, obj: &str, flags: &[String], include_dirs: &[String], cwd: &str) -> Result<CompileResult, String> {
        if !self.available() {
            return Ok(self.missing());
        }
        let mut args: Vec<String> = vec!["/nologo".into(), "/c".into()];
        args.extend(flags.iter().cloned());
        args.extend(include_dirs.iter().map(|d| format!("/I{d}")));
        args.push(format!("/Fo{obj}"));
        args.push(src.into());
        let (code, out, err) = self.run("CL.EXE", &args, cwd)?;
        let log = format!("{out}{err}").replace("\r\n", "\n");
        let (diags, refused) = diagnostics(&log);
        let ok = code == 0 && Path::new(cwd).join(obj).exists() && refused.is_empty();
        Ok(CompileResult { ok, log, diags, refused })
    }

    /// CL /nologo /Zs <flags> /I<dirs> <src>: the syntax and type checks of the front end, no object.
    pub fn syntax_check(&self, src: &str, flags: &[String], include_dirs: &[String], cwd: &str) -> Result<CompileResult, String> {
        if !self.available() {
            return Ok(self.missing());
        }
        let mut args: Vec<String> = vec!["/nologo".into(), "/Zs".into()];
        args.extend(flags.iter().filter(|f| {
            let u = f.to_uppercase();
            u != "/C" && u != "/ZS" && !["/FO", "/FA", "/FD", "/FR"].iter().any(|p| u.starts_with(p))
        }).cloned());
        args.extend(include_dirs.iter().map(|d| format!("/I{d}")));
        args.push(src.into());
        let (code, out, err) = self.run("CL.EXE", &args, cwd)?;
        let log = format!("{out}{err}").replace("\r\n", "\n");
        let (diags, refused) = diagnostics(&log);
        Ok(CompileResult { ok: code == 0 && refused.is_empty(), log, diags, refused })
    }

    /// The include set: CL /E and every distinct path its `#line` directives name, resolved against cwd, without
    /// the unit itself; (files, '' or the failure).
    pub fn includes(&self, src: &str, flags: &[String], include_dirs: &[String], cwd: &str) -> Result<(Vec<String>, String), String> {
        if !self.available() {
            return Ok((vec![], format!("VC6 not found under the toolchain root {}", self.root.as_deref().unwrap_or("None"))));
        }
        let mut args: Vec<String> = vec!["/nologo".into(), "/E".into()];
        args.extend(flags.iter().filter(|f| {
            let u = f.to_uppercase();
            let two: String = u.chars().take(2).collect();
            ["/D", "/U", "/I"].contains(&two.as_str()) || ["/X", "/J", "/ZA", "/ZE"].contains(&u.as_str())
        }).cloned());
        args.extend(include_dirs.iter().map(|d| format!("/I{d}")));
        args.push(src.into());
        let (code, out, err) = self.run("CL.EXE", &args, cwd)?;
        if code != 0 {
            return Ok((vec![], err.replace("\r\n", "\n")));
        }
        static LINE_DIRECTIVE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r#"(?m)^#line\s+\d+\s+"((?:[^"\\]|\\.)*)""#).unwrap());
        static ESC: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"\\(.)").unwrap());
        let me = resolved(cwd, src);
        let mut done = std::collections::HashSet::new();
        let mut seen: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
        for m in LINE_DIRECTIVE.captures_iter(&out) {
            let raw = m.get(1).unwrap().as_str();
            if !done.insert(raw.to_string()) {
                continue;
            }
            let p = resolved(cwd, &ESC.replace_all(raw, "$1"));
            if p != me {
                seen.entry(p.to_lowercase()).or_insert(p);
            }
        }
        Ok((seen.into_values().collect(), String::new()))
    }
}

/// Path(raw) against cwd, resolved (Path.resolve: the file's real spelling when it exists).
pub fn resolved(cwd: &str, raw: &str) -> String {
    let p = if Path::new(raw).is_absolute() { raw.to_string() } else { format!("{cwd}/{raw}") };
    match std::fs::canonicalize(&p) {
        Ok(c) => {
            let s = c.to_string_lossy().into_owned();
            s.strip_prefix(r"\\?\").map(|x| x.to_string()).unwrap_or(s)
        }
        Err(_) => py_path(&p),
    }
}

/// Bytes as Python decodes them in text mode on this system (cp1252; an undefined byte as U+FFFD).
pub fn cp1252(b: &[u8]) -> String {
    const HIGH: [u16; 32] = [0x20AC, 0xFFFD, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0xFFFD,
                             0x017D, 0xFFFD, 0xFFFD, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A,
                             0x0153, 0xFFFD, 0x017E, 0x0178];
    let s: String = b.iter().map(|&c| match c {
        0x80..=0x9F => char::from_u32(HIGH[(c - 0x80) as usize] as u32).unwrap_or('\u{FFFD}'),
        c => c as char,
    }).collect();
    s.replace("\r\n", "\n").replace('\r', "\n")
}

/// (the diagnostics of a CL / LINK run, the flags the compiler refused).
pub fn diagnostics(text: &str) -> (Vec<Diag>, Vec<String>) {
    static SOURCE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"^(.*?)\((\d+)\)\s*:\s*(fatal error|error|warning)\s+([A-Z]+\d+)\s*:\s*(.*)$").unwrap());
    static COMMAND: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"^(?:\w+\s*:\s*)?Command line (fatal error|error|warning)\s+([A-Z]+\d+)\s*:\s*(.*)$").unwrap());
    static LINK: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"^(.*?)\s*:\s*(fatal error|error|warning)\s+(LNK\d+)\s*:\s*(.*)$").unwrap());
    static FLAG: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"'(/[^']+)'").unwrap());
    const REFUSED: [&str; 4] = ["D4002", "D2016", "D4024", "D2021"];
    let sev = |s: &str| if s == "warning" { "warning" } else { "error" }.to_string();
    let (mut out, mut refused) = (vec![], vec![]);
    for line in text.lines() {
        let s = line.trim();
        if let Some(m) = SOURCE.captures(s) {
            out.push(Diag { file: m[1].trim().into(), line: m[2].parse().unwrap_or(0), severity: sev(&m[3]), code: m[4].into(), message: m[5].trim().into() });
        } else if let Some(m) = COMMAND.captures(s) {
            out.push(Diag { file: String::new(), line: 0, severity: sev(&m[1]), code: m[2].into(), message: m[3].trim().into() });
            if REFUSED.contains(&&m[2]) {
                let flags: Vec<String> = FLAG.captures_iter(&m[3]).map(|c| c[1].to_string()).collect();
                if flags.is_empty() {
                    refused.push(m[3].trim().to_string());
                } else {
                    refused.extend(flags);
                }
            }
        } else if let Some(m) = LINK.captures(s) {
            out.push(Diag { file: m[1].trim().into(), line: 0, severity: sev(&m[2]), code: m[3].into(), message: m[4].trim().into() });
        }
    }
    (out, refused)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_of_cl_and_link() {
        let (d, r) = diagnostics("net.c\nsrc\\net.c(12) : error C2065: 'x' : undeclared identifier\n\
                                  Command line warning D4002 : ignoring unknown option '/G7'\n\
                                  foo.obj : error LNK2001: unresolved external symbol _x\n");
        assert_eq!(d.len(), 3);
        assert_eq!((d[0].file.as_str(), d[0].line, d[0].code.as_str()), ("src\\net.c", 12, "C2065"));
        assert_eq!(d[0].text(), "src\\net.c(12): error C2065: 'x' : undeclared identifier");
        assert_eq!(r, ["/G7"]);
        assert_eq!((d[2].file.as_str(), d[2].code.as_str()), ("foo.obj", "LNK2001"));
        assert_eq!(cp1252(&[0x80, b'a', 0xe4]), "\u{20ac}a\u{e4}");
    }
}
