//! The exceptions: a declared statement that a convention does not hold at one
//! site, with its reason. It removes the convention's premise there; it does not outvote it. Two kinds live in the
//! sources, as a marker on the line they exempt (lint.rs `exemption`):
//! - `@original why`: the original itself was inconsistent here (it called a function through another spelling);
//!   its evidence is an experiment whose bytes need the spelling.
//! - `@vc6 why`: the checker's model of C (clang) differs from our toolchain at this site; the gap is the checker's.
//! One kind is a declaration of the original's instruction, since the sources have no line for it (decl/text.dcl):
//! - `0xADDR overrun -- why`: the original's access at that instruction overruns its object (a memset one int
//!   past a field); S.extent takes it for no evidence of the object's extent.
//!
//! Exceptions are visible and counted, like debt: `dcp exceptions` lists them.

use std::path::Path;

/// The kind of an exception.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// the original was inconsistent here
    Original,
    /// the checker (clang) differs from the toolchain here
    Checker,
    /// the original's access at an instruction overruns its object (decl `overrun`)
    Overrun,
}

impl Kind {
    pub fn marker(self) -> &'static str {
        match self {
            Kind::Original => "@original",
            Kind::Checker => "@vc6",
            Kind::Overrun => "overrun",
        }
    }
}

/// One exception: where, which kind, why.
#[derive(Clone, Debug, PartialEq)]
pub struct Exception {
    pub file: String, // relative to the project root, with /
    pub line: usize,  // from 1
    pub kind: Kind,
    pub why: String,  // the text after the marker up to the comment's end ('' when none: no evidence named)
}

/// The exceptions of one file's text.
pub fn of_text(file: &str, text: &str) -> Vec<Exception> {
    let mut out = vec![];
    for (i, line) in text.lines().enumerate() {
        let Some(m) = crate::lint::exemption(line) else { continue };
        let at = line.find(m).unwrap_or(0) + m.len();
        let rest = &line[at..];
        let rest = rest.split("*/").next().unwrap_or("");
        let why = rest.split_whitespace().collect::<Vec<_>>().join(" ");
        out.push(Exception { file: file.to_string(), line: i + 1, kind: if m == "@vc6" { Kind::Checker } else { Kind::Original }, why });
    }
    out
}

/// The exceptions the declarations make (decl/*.dcl `overrun` lines of any target), by file and line.
pub fn of_decls(root: &Path, targets: &[String]) -> Vec<Exception> {
    let r = root.to_string_lossy();
    let (ds, _) = crate::decl::load(&crate::decl::files(&r), &r, targets);
    ds.into_iter()
        .filter(|d| d.kind == "overrun")
        .map(|d| Exception { file: d.file.clone(), line: d.line as usize, kind: Kind::Overrun, why: d.reason.trim().to_string() })
        .collect()
}

/// Every exception of the project's sources (src/*.c, include/*.h, recursively), by file and line.
pub fn of_project(root: &Path) -> Vec<Exception> {
    let mut files: Vec<(String, std::path::PathBuf)> = vec![];
    for (dir, ext) in [("src", "c"), ("include", "h")] {
        let mut stack = vec![root.join(dir)];
        while let Some(d) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&d) else { continue };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x.eq_ignore_ascii_case(ext)) {
                    let rel = p.strip_prefix(root).unwrap_or(&p).to_string_lossy().replace('\\', "/");
                    files.push((rel, p));
                }
            }
        }
    }
    files.sort();
    let mut out = vec![];
    for (rel, p) in files {
        if let Ok(b) = std::fs::read(&p) {
            let text = String::from_utf8_lossy(&b);
            if text.contains("@original") || text.contains("@vc6") {
                out.extend(of_text(&rel, &text));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers_with_their_reasons() {
        let text = "int f(char *p);  /* @original a.c's spelling */\nint g(void);\n    add2(1);  /* @vc6 */\n// @original   the caller pushes one argument\n";
        let e = of_text("src/a.c", text);
        assert_eq!(e.iter().map(|x| (x.line, x.kind, x.why.as_str())).collect::<Vec<_>>(),
                   [(1, Kind::Original, "a.c's spelling"), (3, Kind::Checker, ""), (4, Kind::Original, "the caller pushes one argument")]);
    }
}
