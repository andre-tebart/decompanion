//! `dcp headers conflicts UNIT HEADER..`: what including headers into a unit's head region would collide with,
//! before the include is made. A trial copy of the unit's file (`#include "<header>"` after its last include, or
//! before the first file-scope statement that uses a name the headers declare when that comes first, or before the
//! line --at names; written to build/lint/<target>/trial/) is parsed by clang the way `dcp lint` parses it (the same
//! flags, system and include directories), and so is the unit as it is; the diagnostics only the trial has are what
//! the include causes (a group of diagnostics compared by files, messages and lines, a line of the unit's file by
//! its text, since the include shifts the trial's lines). A `call` or `other` finding whose diagnostic group has a
//! line with an exemption marker (`@original why` / `@vc6 why`, lint::exemption, the lines `dcp lint` exempts for
//! M6: a call's arguments, an asm operand) is listed with `exempt=<marker>` and blocks nothing: the summary's
//! counts, the exit code and --write leave it out. A `supersedes`, `clash`, `header` or `vc6` finding is never
//! exempt: VC6 rejects a redeclaration with another type whatever the marker says, and a pair called clean compiles.
//!
//!   supersedes  a declaration of the unit the header declares differently (`conflicting types`, `redefinition ..
//!               with a different type`, a struct defined twice): the local one goes, and its users follow the
//!               header's type
//!   duplicate   a declaration of the head region (the lines before the unit's first function) the header repeats
//!               with the same type: safe to drop (no diagnostic, by name; each name of a multi-name
//!               `extern int a, b, c;` line)
//!   clash       two headers disagree (both sides in include/): no head edit settles it; one header is wrong
//!   call        a call of the unit the header's prototype rejects (too few / too many arguments), with the
//!               original's evidence at the matching call site of the same function: the pushes since the previous
//!               call (or the function's start) and the `add esp, N` after it (VC6 merges the cleanup of
//!               consecutive calls, so a missing one says nothing)
//!   prototyped  a call that compiled without a prototype (implicit or K&R) and now has one: it compiles, but its
//!               argument conversions (int -> float, the width of a short) may change the code. Per call site
//!               (every call of the callee in the unit's bodies): `constants: safe` when each argument is a
//!               constant whose push the prototype cannot change (an integer or string constant to a parameter that
//!               is no float / double, a floating constant to a double), else re-grade (an expression, an integer
//!               constant to a floating parameter, a floating constant to a float)
//!   header      an error inside a header itself in this unit's include set (a type it needs, a missing include)
//!   vc6         an error only VC6's front end reports (the toolchain's syntax check, `CL /Zs` with the unit's flags,
//!               over the same two files): clang accepts what VC6 rejects, a struct parameter passed by value whose
//!               type is incomplete in the unit (C2079) the known case; at a line no clang item names
//!   other       any other new error
//!
//! Then the functions to re-grade (a `call` / `vc6` / `supersedes` / `other` line in their span, a `prototyped` call
//! that is not safe) and a warning:
//!   declaration-set  the includes add declarations to the unit, or --write drops head duplicates: under VC6 /O2 the
//!                    declaration set of a unit alone moves code generation (gildegold: removing uncalled prototypes
//!                    flipped byte matches to shape), so every function of the unit is re-graded, byte ones first
//! The tool reads only; `--write` inserts the includes and drops the `duplicate` declarations of the head (a line
//! whose names are all duplicates goes, comment and all; a multi-name extern line keeps its other declarators), and
//! only when the trial without them has no new error at all (clang's or VC6's). `--trial` compiles the unit as --write
//! would leave it (build/obj/trial/, removed after) and grades every function of the unit against the original as
//! G.grade grades its code (byte by M.match's compare, else shape / draft by the instruction diff over the extent and
//! slot of its grade row): the falls (exit 1) and the rises, the declaration set's effect itself; nothing is written.
//! Positions are in characters, as Python's str offsets were.

use crate::error::{Error, Result};
use crate::clang::{CDiag, FileModel};
use crate::cliread::{fmt_addr, record, Tok};
use crate::frontend::{self, Front, Scan};
use crate::project::{py_path, Project};
use crate::readability::Source;
use crate::srcscan::{py_strip, Src};
use crate::store;
use pyo3::prelude::*;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::rc::Rc;
use std::sync::{Arc, LazyLock};

const ORDER: [&str; 8] = ["clash", "header", "supersedes", "call", "vc6", "other", "prototyped", "duplicate"];
const BLOCKING: [&str; 6] = ["clash", "header", "supersedes", "call", "vc6", "other"];
const TRIAL_MARK: &str = "   /* dcp headers conflicts: trial */";

macro_rules! re {
    ($name:ident, $pat:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pat).unwrap());
    };
}

re!(INCLUDE, r"^[ \t]*#[ \t]*include\b");
re!(QUOTED, r"'(\w+)'");
re!(ARGS, r"too (few|many) arguments to function call, expected (?:at least )?(\d+), have (\d+)");
re!(CONFLICT, r"^(?:conflicting types for|redefinition of|redeclaration of|typedef redefinition with different types|non-static declaration of|static declaration of)\b");
re!(INCLUDE_LINE, r#"(?m)^[ \t]*#[ \t]*include[ \t]+"([^"]+)""#);
re!(IDENT, r"\b[A-Za-z_]\w*\b");
re!(EXTERN_AT, r"^([ \t]*)extern\b([^;(]*);");
re!(DECLARATOR, r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)*$");
re!(INT_CONST, r#"^(?:[-+~]?\s*(?:0[xX][0-9a-fA-F]+|\d+)[uUlL]*|'(?:\\.|[^'\\])+'|sizeof\b.*|NULL)$"#);
re!(FLOAT_CONST, r"^[-+]?\s*(?:(?:\d+\.\d*|\.\d+)(?:[eE][-+]?\d+)?|\d+[eE][-+]?\d+)[fFlL]?$");
re!(CAST, r"^\(\s*(?:const\s+|volatile\s+|unsigned\s+|signed\s+|struct\s+|union\s+|enum\s+)*[A-Za-z_]\w*[\s\w]*\**\s*\)");
re!(FLOATING, r"\b(float|double)\b");
re!(DOUBLE, r"\bdouble\b");
re!(ADD_ESP, r"^add esp, (0x[0-9a-f]+|\d+)");

fn err(e: impl std::fmt::Display) -> Error {
    Error::runtime(e.to_string())
}

fn s(x: impl Into<String>) -> Tok {
    Tok::S(x.into())
}

fn os(x: Option<impl Into<String>>) -> Tok {
    x.map(|v| Tok::S(v.into())).unwrap_or(Tok::No)
}

fn chars(v: &[char]) -> String {
    v.iter().collect()
}

/// The char index of a byte offset of s.
fn ci(s: &str, byte: usize) -> usize {
    s[..byte].chars().count()
}

fn read(root: &str, rel: &str) -> String {
    crate::fsmemo::read_text(&py_path(&format!("{root}/{rel}"))).unwrap_or_default()
}

/// Python's `" ".join(x.split())`.
fn collapse(x: &str) -> String {
    x.split(crate::srcscan::py_space).filter(|w| !w.is_empty()).collect::<Vec<_>>().join(" ")
}

// ------------------------------------------------------------------------------------------------ the diagnostics

#[derive(Clone)]
struct Dg {
    file: String,
    line: i64,
    kind: String,
    msg: String,
    flag: String,
    name: Option<String>,
}

impl From<&CDiag> for Dg {
    fn from(d: &CDiag) -> Dg {
        Dg { file: d.file.clone(), line: d.line, kind: d.kind.clone(), msg: d.msg.clone(), flag: d.flag.clone(), name: d.name.clone().filter(|n| !n.is_empty()) }
    }
}

type Group = Vec<Dg>;

fn grouped(diags: Vec<Dg>) -> Vec<Group> {
    let mut groups: Vec<Group> = vec![];
    for d in diags {
        match groups.last_mut() {
            Some(g) if d.kind == "note" => g.push(d),
            _ => groups.push(vec![d]),
        }
    }
    groups
}

fn fmt_group(g: &Group) -> String {
    let d = &g[0];
    let mut s = format!("{}:{}: {}{}", d.file, d.line, d.msg, if d.flag.is_empty() { String::new() } else { format!(" [{}]", d.flag) });
    for n in &g[1..] {
        s += &format!(" / note {}:{}: {}", n.file, n.line, n.msg);
    }
    s
}


/// An M7 call: (callee, `proto` through a K&R declaration / `undeclared`); None for any other diagnostic.
fn call_of(d: &Dg) -> Option<(String, &'static str)> {
    if d.kind != "warning" {
        return None;
    }
    let callee = || d.name.clone().unwrap_or_else(|| "?".into());
    if d.flag == "-Wdeprecated-non-prototype" && d.msg.starts_with("passing arguments") {
        return Some((callee(), "proto"));
    }
    if d.flag == "-Wimplicit-function-declaration" {
        return Some((callee(), "undeclared"));
    }
    None
}

/// The symbol a diagnostic group is about: the first one named, the diagnostic's own before its notes'.
fn symbol_of(g: &Group) -> Option<String> {
    g.iter().find_map(|d| d.name.clone())
}

fn same_file(a: &str, b: &str) -> bool {
    let (na, nb) = (a.replace('\\', "/").to_lowercase(), b.replace('\\', "/").to_lowercase());
    na == nb || na.ends_with(&format!("/{nb}")) || nb.ends_with(&format!("/{na}"))
}

// ------------------------------------------------------------------------------------------------ the project

/// The texts and models of a tree: the front end, the scan when there is one (a file whose text is the file on disk
/// has the scan's model; any other text is parsed alone).
struct Texts {
    root: String,
    front: Front,
    scan: Option<Rc<Scan>>,
}

struct Ctx<'a> {
    p: &'a Project,
    t: Texts,
    scan: Rc<Scan>,
}

impl std::ops::Deref for Ctx<'_> {
    type Target = Texts;

    fn deref(&self) -> &Texts {
        &self.t
    }
}

impl Texts {
    /// The front end's model of one text parsed alone (no unit around it).
    fn model_alone(&self, rel: &str, text: &str) -> Arc<FileModel> {
        let path = py_path(&format!("{}/{rel}", self.root));
        let r = rel.replace('\\', "/");
        let m = frontend::parse_model(&self.root, &path, &self.front.args(&[]), text, false).ok();
        Arc::new(m.and_then(|m| m.files.into_iter().find(|(x, _)| *x == r).map(|x| x.1)).unwrap_or_default())
    }

    /// The scan's model of a file when text is the file as it is on disk, else None.
    fn model_of(&self, rel: &str, text: &str) -> Option<Arc<FileModel>> {
        let scan = self.scan.as_ref()?;
        let disk = crate::fsmemo::read_text(&py_path(&format!("{}/{rel}", self.root))).ok()?;
        (disk == text).then(|| scan.models.get(rel).cloned().unwrap_or_default())
    }

    /// Every file-scope declaration and definition of a function or data object that is not static (lint's).
    fn file_scope_decls(&self, rel: &str, text: &str, m: Option<Arc<FileModel>>) -> Vec<crate::lint::Decl> {
        let m = m.unwrap_or_else(|| self.model_alone(rel, text));
        let src = Src::new(text, &m.comments, &m.strings);
        crate::lint::file_decls(rel, &src, &crate::lint::mdecls(&m.decls))
    }

    /// name -> line (the first) of every file-scope prototype and extern data declaration of a file, in file order.
    fn declared_names(&self, rel: &str, text: &str) -> Vec<(String, i64)> {
        let mut out: Vec<(String, i64)> = vec![];
        for d in self.file_scope_decls(rel, text, self.model_of(rel, text)) {
            if (d.kind == "proto" || d.kind == "extern") && !out.iter().any(|x| x.0 == d.name) {
                out.push((d.name.clone(), d.line));
            }
        }
        out
    }

    /// name -> every line declaring it.
    fn declared_lines(&self, rel: &str, text: &str) -> HashMap<String, HashSet<i64>> {
        let mut out: HashMap<String, HashSet<i64>> = HashMap::new();
        for d in self.file_scope_decls(rel, text, self.model_of(rel, text)) {
            if d.kind == "proto" || d.kind == "extern" {
                out.entry(d.name.clone()).or_default().insert(d.line);
            }
        }
        out
    }

    /// The project-relative paths of the headers and every header they include (quoted, in the include
    /// directory), each once.
    fn header_closure(&self, headers: &[String]) -> Vec<String> {
        let (mut out, mut todo): (Vec<String>, std::collections::VecDeque<String>) = (vec![], headers.iter().cloned().collect());
        while let Some(h) = todo.pop_front() {
            let name = Path::new(&h).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let rel = format!("include/{name}");
            if Path::new(&py_path(&format!("{}/{rel}", self.root))).exists() && !out.contains(&rel) {
                let text = read(&self.root, &rel);
                out.push(rel);
                todo.extend(INCLUDE_LINE.captures_iter(&text).map(|c| c[1].to_string()));
            }
        }
        out
    }

    /// name -> header file:line of every prototype and extern the headers (and what they include) declare.
    fn head_names(&self, headers: &[String]) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = vec![];
        for rel in self.header_closure(headers) {
            for (n, ln) in self.declared_names(&rel, &read(&self.root, &rel)) {
                if !out.iter().any(|x| x.0 == n) {
                    out.push((n, format!("{rel}:{ln}")));
                }
            }
        }
        out
    }
}

impl Ctx<'_> {
    /// (file, line) -> the target's function whose span holds the line.
    fn spans(&self) -> Spans {
        let default = self.p.targets[0].name.clone();
        let mut by: HashMap<String, Vec<(i64, i64, i64)>> = HashMap::new();
        for ((file, _, _, _, addrs, _, _), (_, _, _, comment_line, _, end_line, _)) in self.scan.functions() {
            if let Some((_, a)) = addrs.iter().find(|(t, _)| t.as_deref().unwrap_or(&default) == self.p.target_name) {
                by.entry(file.clone()).or_default().push((*comment_line, *end_line, *a as i64));
            }
        }
        for xs in by.values_mut() {
            xs.sort_by_key(|x| x.0);
        }
        Spans { by }
    }
}

struct Spans {
    by: HashMap<String, Vec<(i64, i64, i64)>>,
}

impl Spans {
    fn at(&self, file: &str, line: i64) -> Option<i64> {
        let xs = self.by.get(file)?;
        let k = xs.partition_point(|x| x.0 <= line);
        let x = xs.get(k.checked_sub(1)?)?;
        if x.1 != 0 && line > x.1 {
            return None;
        }
        Some(x.2)
    }
}

/// The file's code (comments and strings blanked) with its preprocessor lines and the ranges the preprocessor
/// skipped blanked too; offsets unchanged.
fn live_code(src: &Source, m: &FileModel) -> String {
    let code = chars(&src.code);
    let dead: HashSet<i64> = m.dead.iter().flat_map(|&(a, b)| a..=b).collect();
    let mut cont = false;
    let mut out: Vec<String> = vec![];
    for (n, ln) in code.split('\n').enumerate() {
        let directive = cont || ln.trim_start_matches(crate::srcscan::py_space).starts_with('#');
        cont = directive && ln.trim_end_matches(crate::srcscan::py_space).ends_with('\\');
        out.push(if directive || dead.contains(&(n as i64 + 1)) { " ".repeat(ln.chars().count()) } else { ln.to_string() });
    }
    out.join("\n")
}

// ------------------------------------------------------------------------------------------------ the head's text

/// The line index (0-based) after the file's last include (0 without one).
fn after_includes(text: &str) -> usize {
    text.split('\n').enumerate().filter(|(_, l)| INCLUDE.is_match(l)).map(|(i, _)| i + 1).max().unwrap_or(0)
}

/// The text with an `#include "h"` line per header inserted before line index `pos`.
fn insert_includes(text: &str, headers: &[String], pos: usize) -> String {
    let lines: Vec<&str> = text.split('\n').collect();
    let pos = pos.min(lines.len());
    let add: Vec<String> = headers.iter().map(|h| format!("#include \"{h}\"{TRIAL_MARK}")).collect();
    lines[..pos].iter().map(|l| l.to_string()).chain(add).chain(lines[pos..].iter().map(|l| l.to_string())).collect::<Vec<_>>().join("\n")
}

/// Where the includes go in a unit's file (a line index, 0-based): after its last include, or earlier, at the start
/// of the file-scope statement holding the first use of a name the headers declare when that use comes first.
fn include_pos(x: &Texts, rel: &str, text: &str, names: &HashSet<String>) -> usize {
    let after = after_includes(text);
    if names.is_empty() {
        return after;
    }
    let src = Source::new(text);
    let m = x.model_of(rel, text).unwrap_or_else(|| x.model_alone(rel, text));
    let code = live_code(&src, &m);
    let decl_lines = x.declared_lines(rel, text);
    let mut first = None;
    for mm in IDENT.find_iter(&code) {
        let n = mm.as_str();
        let line = src.line_of(ci(&code, mm.start())) as i64;
        if names.contains(n) && !decl_lines.get(n).is_some_and(|ls| ls.contains(&line)) {
            first = Some(line as usize - 1);
            break;
        }
    }
    let Some(first) = first.filter(|&f| f < after) else { return after };
    let raw: Vec<&str> = text.split('\n').collect();
    let code_lines: Vec<&str> = code.split('\n').collect();
    let mut inside: HashSet<usize> = HashSet::new(); // line indices (0-based) that start inside a comment
    for (cs, ce, _) in &src.comments {
        inside.extend(src.line_of(*cs)..src.line_of(ce.saturating_sub(1)));
    }
    let (mut ok, mut depth, mut prev) = (vec![], 0i64, ';');
    for (i, l) in code_lines.iter().enumerate() {
        ok.push(depth == 0 && !inside.contains(&i) && matches!(prev, ';' | '}' | '#'));
        let t = py_strip(l);
        if raw.get(i).is_some_and(|r| r.trim_start_matches(crate::srcscan::py_space).starts_with('#')) {
            prev = '#';
        } else if !t.is_empty() {
            prev = t.chars().last().unwrap();
        }
        depth += l.matches('{').count() as i64 - l.matches('}').count() as i64;
    }
    (0..=first).rev().find(|&i| ok[i]).unwrap_or(0)
}

/// One head line without the declarators of `names` in its `extern T a, b, c;` statements: None when no code is
/// left (the line goes, its comment with it), else the line with the other declarators (and its comment) kept.
fn drop_names(line: &str, names: &HashSet<String>) -> Option<String> {
    let lc: Vec<char> = line.chars().collect();
    let code = chars(&Source::new(line).code);
    let sub = |a: usize, b: usize| chars(&lc[a.min(lc.len())..b.min(lc.len()).max(a.min(lc.len()))]);
    let mut out: Vec<String> = vec![];
    let mut pos = 0usize; // chars
    let mut at = 0usize; // bytes of code
    while at <= code.len() {
        let cand = at == 0 || code.as_bytes()[at - 1] == b';';
        let m = if cand { EXTERN_AT.captures(&code[at..]) } else { None };
        let Some(m) = m else {
            at += code[at..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            continue;
        };
        let (m0, g1, g2) = (m.get(0).unwrap(), m.get(1).unwrap(), m.get(2).unwrap());
        let (ms, me) = (ci(&code, at + m0.start()), ci(&code, at + m0.end()));
        let s2 = ci(&code, at + g2.start());
        let next_at = at + m0.end();
        let chunks: Vec<&str> = g2.as_str().split(',').collect();
        // each declarator's name and where it starts in its chunk (the part before `=`, trailing space cut)
        let heads: Vec<Option<(usize, String)>> = chunks.iter().map(|c| {
            let t = c.split('=').next().unwrap_or("").trim_end_matches(crate::srcscan::py_space);
            DECLARATOR.captures(t).map(|cp| (ci(c, cp.get(0).unwrap().start()), cp[1].to_string()))
        }).collect();
        if heads.iter().any(|h| h.is_none()) {
            at = next_at;
            continue;
        }
        let kept: Vec<usize> = (0..chunks.len()).filter(|&i| !names.contains(&heads[i].as_ref().unwrap().1)).collect();
        if kept.len() == chunks.len() {
            at = next_at;
            continue;
        }
        let c0: Vec<char> = chunks[0].chars().collect();
        let spec = chars(&c0[..heads[0].as_ref().unwrap().0]).trim_end_matches([' ', '\t', '*']).chars().count();
        let mut starts = vec![s2];
        for c in &chunks {
            starts.push(starts.last().unwrap() + c.chars().count() + 1);
        }
        let decls: Vec<String> = kept.iter().map(|&i| {
            py_strip(&sub(starts[i] + if i == 0 { spec } else { 0 }, starts[i] + chunks[i].chars().count())).to_string()
        }).collect();
        out.push(sub(pos, ms));
        if !kept.is_empty() {
            out.push(format!("{}extern{} {};", g1.as_str(), sub(s2, s2 + spec), decls.join(", ")));
        }
        pos = me;
        at = next_at;
    }
    out.push(sub(pos, lc.len()));
    let new = out.concat().trim_end_matches(crate::srcscan::py_space).to_string();
    if py_strip(&chars(&Source::new(&new).code)).is_empty() {
        return None;
    }
    Some(if line.chars().next().is_some_and(crate::srcscan::py_space) { new } else { new.trim_start_matches(crate::srcscan::py_space).to_string() })
}

/// A head line with its duplicates `names` dropped; a line whose declarations (`line_names`) are all duplicates but
/// are no extern data statement (a prototype) goes whole: None.
fn drop_line(line: &str, names: &HashSet<String>, line_names: &HashSet<String>) -> Option<String> {
    let new = drop_names(line, names)?;
    if new == line && line_names.is_subset(names) {
        return None;
    }
    Some(new)
}

/// Lines of the project's files by `file:line`, read once.
struct Reader {
    root: String,
    memo: HashMap<String, Vec<String>>,
}

impl Reader {
    fn raw(&mut self, loc: &str) -> String {
        let (f, n) = loc.rsplit_once(':').unwrap_or(("", loc));
        if !self.memo.contains_key(f) {
            let p = if Path::new(f).is_absolute() { py_path(f) } else { py_path(&format!("{}/{f}", self.root)) };
            let ls = if Path::new(&p).exists() {
                crate::fsmemo::read_text(&p).unwrap_or_default().split('\n').map(|l| l.to_string()).collect()
            } else {
                vec![]
            };
            self.memo.insert(f.to_string(), ls);
        }
        let ls = &self.memo[f];
        match py_strip(n).parse::<usize>() {
            Ok(k) if k > 0 && k <= ls.len() => ls[k - 1].clone(),
            _ => String::new(),
        }
    }

    fn line(&mut self, loc: &str) -> String {
        collapse(&self.raw(loc)).chars().take(160).collect()
    }
}

// ------------------------------------------------------------------------------------------------ the trial

struct Trial {
    unit: crate::plan::Tu,
    base: Vec<Group>,
    tri: Vec<Group>,
    new: String,
    lines: [Vec<String>; 2], // the unit file's lines: the base's, the trial copy's
    vc6: Option<(Vec<Dg>, Vec<Dg>)>,
    pos: usize,
}

/// The diagnostics of a trial copy as the unit's file's: the copy's own lines, or the name and line its `#line`
/// directives give (VC6's) mapped back.
fn map_diags(a: &crate::plan::Tu, text: &str, rel: &str, diags: Vec<Dg>) -> Vec<Dg> {
    diags.into_iter().map(|mut d| {
        if !d.file.is_empty() && same_file(&d.file, rel) {
            d.file = a.file.clone();
        } else if !d.file.is_empty() {
            if let Some(&hit) = crate::plan::locate(text, rel, &d.file, d.line).first() {
                d.file = a.file.clone();
                d.line = hit;
            }
        }
        d
    }).collect()
}

/// A path as the project names it: relative to root in posix spelling when it lies below root.
fn project_rel(root: &str, f: &str) -> String {
    let full = if Path::new(f).is_absolute() { f.to_string() } else { format!("{root}/{f}") };
    let canon = |p: &str| -> String {
        let c = std::fs::canonicalize(p).map(|c| c.to_string_lossy().into_owned()).unwrap_or_else(|_| py_path(p));
        c.strip_prefix(r"\\?\").map(|x| x.to_string()).unwrap_or(c)
    };
    let (cf, cr) = (canon(&full), canon(root));
    match Path::new(&cf).strip_prefix(&cr) {
        Ok(r) => r.to_string_lossy().replace('\\', "/"),
        Err(_) => f.replace('\\', "/"),
    }
}

/// The toolchain's own front end over a trial file (VC6: CL /Zs with the unit's flags), as lint-style diagnostics;
/// None when it is not installed.
fn vc6_diags(p: &Project, tools: &crate::vc6::Tools, a: &crate::plan::Tu, rel: &str, root: &str) -> Result<Option<Vec<Dg>>, String> {
    if !tools.available() {
        return Ok(None);
    }
    let flags = crate::plan::compile_flags(p, &a.target, &a.unit)?;
    let res = tools.syntax_check(rel, &flags, &["include".to_string()], root)?;
    Ok(Some(res.diags.iter().map(|d| Dg {
        file: if d.file.is_empty() { String::new() } else { project_rel(root, &d.file) },
        line: d.line,
        kind: d.severity.clone(),
        msg: format!("{}: {}", d.code, d.message),
        flag: String::new(),
        name: None,
    }).collect()))
}

/// The unit with `headers` included and the head's duplicates `drop` removed ({line: the names to drop there}).
/// The includes go before the file's line `at` (1-based) when given, else where include_pos puts them; the
/// position kept is a line index (0-based) of the file on disk.
fn trial(x: &Ctx, unit: &str, headers: &[String], drop: &BTreeMap<i64, HashSet<String>>, at: Option<i64>) -> Result<Trial, String> {
    let p = x.p;
    let a = crate::plan::plan(p)?.iter().find(|t| t.unit == unit).cloned()
        .ok_or_else(|| format!("LookupError: no unit {unit} in target {}", p.target_name))?;
    let head = a.file.clone();
    let old = read(&x.root, &head);
    let lines: Vec<&str> = old.split('\n').collect();
    let pos = match at.filter(|&a| a != 0) {
        Some(at) => (at - 1).max(0) as usize,
        None => include_pos(x, &head, &old, &x.head_names(headers).into_iter().map(|h| h.0).collect()),
    };
    let mut per_line: HashMap<i64, HashSet<String>> = HashMap::new();
    for (n, ln) in x.declared_names(&head, &old) {
        per_line.entry(ln).or_default().insert(n);
    }
    let empty = HashSet::new();
    let (mut kept, mut kpos) = (vec![], pos as i64);
    for (i, l) in lines.iter().enumerate() {
        let i = i as i64 + 1;
        let mut l = l.to_string();
        if let Some(names) = drop.get(&i) {
            match drop_line(&l, names, per_line.get(&i).unwrap_or(&empty)) {
                None => {
                    kpos -= (i <= pos as i64) as i64;
                    continue;
                }
                Some(n) => l = n,
            }
        }
        kept.push(l);
    }
    let new = insert_includes(&kept.join("\n"), headers, kpos.max(0) as usize);
    let dir = format!("build/lint/{}/trial", p.target_name);
    std::fs::create_dir_all(py_path(&format!("{}/{dir}", x.root))).map_err(|e| e.to_string())?;
    let (rb, rn) = (format!("{dir}/{unit}.base.c"), format!("{dir}/{unit}.trial.c"));
    std::fs::write(py_path(&format!("{}/{rb}", x.root)), &old).map_err(|e| e.to_string())?;
    std::fs::write(py_path(&format!("{}/{rn}", x.root)), &new).map_err(|e| e.to_string())?;
    let args = x.front.args(&[frontend::target_macro(&p.target_name)]);
    let tools = crate::vc6::Tools::of(p);
    let root = x.root.as_str();
    let clang = |rel: &str, text: &str| -> Result<Vec<Dg>, String> {
        let path = py_path(&format!("{root}/{rel}"));
        let ds = frontend::with_parse(&path, &args, text, false, |u| u.diags(root, text, false).map_err(|e| e.to_string()))?;
        Ok(ds.iter().map(Dg::from).collect())
    };
    // VC6's two runs while clang parses both
    let (db, dn, vb, vn) = std::thread::scope(|sc| {
        let vb = sc.spawn(|| vc6_diags(p, &tools, &a, &rb, root));
        let vn = sc.spawn(|| vc6_diags(p, &tools, &a, &rn, root));
        let dn = sc.spawn(|| clang(&rn, &new));
        let db = clang(&rb, &old);
        (db, dn.join().unwrap(), vb.join().unwrap(), vn.join().unwrap())
    });
    let (base, tri) = (map_diags(&a, &old, &rb, db?), map_diags(&a, &new, &rn, dn?));
    let vc6 = match (vb?, vn?) {
        (Some(b), Some(n)) => Some((map_diags(&a, &old, &rb, b), map_diags(&a, &new, &rn, n))),
        _ => None,
    };
    let split = |t: &str| t.split('\n').map(|l| l.to_string()).collect::<Vec<_>>();
    let lines = [split(&old), split(&new)];
    Ok(Trial { unit: a, base: grouped(base), tri: grouped(tri), new, lines, vc6, pos })
}

impl Trial {
    /// A diagnostic's line as its text reads: the unit file's in the base or the trial copy, another file's as the
    /// file reads.
    fn text(&self, d: &Dg, base: bool, rd: &mut Reader) -> String {
        if d.file == self.unit.file {
            let ls = &self.lines[if base { 0 } else { 1 }];
            return if d.line > 0 { ls.get(d.line as usize - 1).cloned().unwrap_or_default() } else { String::new() };
        }
        rd.raw(&format!("{}:{}", d.file, d.line))
    }

    /// The trial's error groups the base does not have. A group compares by its diagnostics' files, messages and
    /// lines, a line of the unit file by its text: the includes (and the dropped duplicates) shift the trial's lines,
    /// and an error the unit had before is not the includes' doing.
    fn new_errors(&self, rd: &mut Reader) -> Vec<&Group> {
        let mut key = |g: &Group, base: bool| -> Vec<(String, String, String)> {
            g.iter().map(|d| (d.file.clone(), d.msg.clone(), if d.file == self.unit.file { self.text(d, base, rd) } else { d.line.to_string() })).collect()
        };
        let seen: HashSet<_> = self.base.iter().map(|g| key(g, true)).collect();
        self.tri.iter().filter(|g| g[0].kind == "error" && !seen.contains(&key(g, false))).collect()
    }

    /// The exemption marker of a trial group (lint::exemption): the first any of its lines carries, as dcp lint
    /// exempts an M6 group; only for what VC6 compiles anyway, a check at a use (a call's arguments, an asm
    /// operand). A redeclaration with another type (`supersedes`, `clash`) or an error inside a header is never
    /// exempt: VC6 rejects it whatever the marker says (C2371), so the pair would not compile.
    fn exemption(&self, g: &[Dg], rd: &mut Reader) -> Option<&'static str> {
        let d = &g[0];
        let declaration = CONFLICT.is_match(&d.msg) && g.len() > 1;
        let in_header = d.file.starts_with("include/") && !g.iter().any(|y| y.file == self.unit.file);
        if declaration || in_header {
            return None;
        }
        g.iter().find_map(|d| crate::lint::exemption(&self.text(d, false, rd)))
    }
}

/// The VC6 errors only the trial has (by file and message: the trial's lines are shifted).
fn vc6_new(vc6: &Option<(Vec<Dg>, Vec<Dg>)>) -> Vec<Dg> {
    let Some((vbase, vtri)) = vc6 else { return vec![] };
    let seen: HashSet<(&str, &str)> = vbase.iter().filter(|d| d.kind == "error").map(|d| (d.file.as_str(), d.msg.as_str())).collect();
    vtri.iter().filter(|d| d.kind == "error" && !seen.contains(&(d.file.as_str(), d.msg.as_str()))).cloned().collect()
}

// ------------------------------------------------------------------------------------------------ the analysis

#[derive(Default)]
struct Item {
    kind: &'static str,
    name: Option<String>,
    at: String,
    other: Option<String>,
    msg: String,
    ours: String,
    theirs: String,
    func: Option<i64>,
    evidence: Vec<String>,
    fns: Vec<i64>,
    sites: Vec<String>,
    exempt: Option<&'static str>, // the marker of an exempt finding (lint::exemption): not a blocker
}

struct Analysis {
    unit: crate::plan::Tu,
    items: Vec<Item>,
    vc6: bool,
    added: usize,
}

fn analyse(x: &Ctx, capstone: &str, unit: &str, headers: &[String], at: Option<i64>) -> Result<Result<Analysis, String>> {
    let t = match trial(x, unit, headers, &BTreeMap::new(), at) {
        Ok(t) => t,
        Err(e) if e.starts_with("LookupError: ") => return Ok(Err(e["LookupError: ".len()..].to_string())),
        Err(e) => return Err(err(e)),
    };
    let root = &x.root;
    let head = t.unit.file.clone();
    let old_text = read(root, &head);
    let old_lines: Vec<&str> = old_text.split('\n').collect();
    let last_inc = t.pos as i64 - 1; // the trial includes follow the file's line index pos - 1
    let n_added = headers.len() as i64;
    let mut base_calls: BTreeMap<(String, String), Vec<i64>> = BTreeMap::new();
    for g in &t.base {
        let d = &g[0];
        if let Some((c, _)) = call_of(d).filter(|c| c.0 != "?") {
            base_calls.entry((d.file.clone(), c)).or_default().push(d.line);
        }
    }
    let fix = |d: &Dg| -> String {
        if d.file == head {
            let line = d.line;
            if last_inc + 1 < line && line <= last_inc + 1 + n_added {
                return format!("{head}:{line} (the trial include)");
            }
            return format!("{head}:{}", if line <= last_inc + 1 { line } else { line - n_added });
        }
        format!("{}:{}", d.file, d.line)
    };
    let is_unit = |f: &str| f == head;
    let spans = x.spans();
    let fn_at = |d: &Dg| -> Option<i64> {
        if d.file.is_empty() {
            return None;
        }
        let fixed = fix(d);
        let loc = fixed.split(' ').next().unwrap_or("");
        let (f, n) = loc.rsplit_once(':').unwrap_or(("", loc));
        if !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()) { spans.at(f, n.parse().ok()?) } else { None }
    };
    let mut items: Vec<Item> = vec![];
    let mut conflicting: HashSet<String> = HashSet::new();
    let mut rd = Reader { root: root.clone(), memo: HashMap::new() };
    let db = x.p.store_path();
    let target = x.p.target(None).map_err(err)?.path.clone();
    let names = crate::names::Names::build(&db, &x.p.main_uri(), &target)?;
    let mut trial_calls: HashSet<(String, String)> = HashSet::new();
    for g in &t.tri {
        let d = &g[0];
        if d.kind == "warning" {
            if let Some((c, _)) = call_of(d).filter(|c| c.0 != "?") {
                trial_calls.insert((d.file.clone(), c));
            }
        }
    }
    for g in t.new_errors(&mut rd) {
        let d = &g[0];
        let exempt = t.exemption(g, &mut rd);
        let name = symbol_of(g);
        if ARGS.is_match(&d.msg) {
            let note = g[1..].iter().find(|x| x.msg.contains("declared here"));
            let callee = note.and_then(|n| n.name.clone()).or(name);
            let func = fn_at(d);
            let evidence = call_evidence(x, capstone, &names, func, callee.as_deref())?;
            items.push(Item { kind: "call", name: callee, at: fix(d), other: note.map(fix), msg: d.msg.clone(), ours: rd.line(&fix(d)),
                              theirs: note.map(|n| rd.line(&fix(n))).unwrap_or_default(), func, evidence, exempt, ..Default::default() });
            continue;
        }
        if CONFLICT.is_match(&d.msg) && g.len() > 1 {
            let note = &g[1];
            let sides = [d, note];
            let ours = sides.iter().position(|s| is_unit(&s.file));
            let theirs = (0..2).find(|&i| Some(i) != ours && sides[i].file.starts_with("include/"));
            let Some(ours) = ours else {
                items.push(Item { kind: "clash", name, at: fix(d), other: Some(fix(note)), msg: d.msg.clone(), ours: rd.line(&fix(d)),
                                  theirs: rd.line(&fix(note)), exempt, ..Default::default() });
                continue;
            };
            if let Some(n) = &name {
                conflicting.insert(n.clone());
            }
            let th = sides[theirs.unwrap_or(1)];
            items.push(Item { kind: "supersedes", name, at: fix(sides[ours]), other: Some(fix(th)), msg: d.msg.clone(), ours: rd.line(&fix(sides[ours])),
                              theirs: rd.line(&fix(th)), func: fn_at(sides[ours]), exempt, ..Default::default() });
            continue;
        }
        if d.file.starts_with("include/") && !g.iter().any(|y| is_unit(&y.file)) {
            items.push(Item { kind: "header", name, at: fix(d), msg: d.msg.clone(), ours: rd.line(&fix(d)), exempt, ..Default::default() });
            continue;
        }
        items.push(Item { kind: "other", name, at: fix(d), other: g.get(1).map(fix), msg: d.msg.clone(), ours: rd.line(&fix(d)), func: fn_at(d),
                          exempt, ..Default::default() });
    }
    // what VC6 itself rejects and clang accepted (C2079: a struct by value, incomplete in this unit); never exempt
    // (the pair would not compile). VC6's own C2371 of a `supersedes` line says the same as it; an exempt finding
    // hides nothing VC6 rejects at its line
    let mut reported: HashSet<String> = items.iter().filter(|i| i.exempt.is_none()).map(|i| i.at.clone()).collect();
    for d in vc6_new(&t.vc6) {
        let at = if d.file.is_empty() { "(command line)".to_string() } else { fix(&d) };
        if !reported.insert(at.clone()) {
            continue;
        }
        let q = QUOTED.captures(&d.msg).map(|c| c[1].to_string());
        let ours = if d.file.is_empty() { String::new() } else { rd.line(&at) };
        items.push(Item { kind: "vc6", name: q, at, msg: d.msg.clone(), ours, func: fn_at(&d), ..Default::default() });
    }
    let mut per_callee: BTreeMap<String, Vec<(String, i64)>> = BTreeMap::new();
    for ((f, callee), lines) in &base_calls {
        if trial_calls.contains(&(f.clone(), callee.clone())) || !is_unit(f) {
            continue;
        }
        per_callee.entry(callee.clone()).or_default().extend(lines.iter().map(|l| (f.clone(), *l)));
    }
    // the headers' declarations (and those of what they include)
    let mut hdr_names: Vec<(String, String)> = vec![];
    let mut hdr_decls: HashMap<String, crate::lint::Decl> = HashMap::new();
    for rel in x.header_closure(headers) {
        let text = read(root, &rel);
        for (n, ln) in x.declared_names(&rel, &text) {
            if !hdr_names.iter().any(|h| h.0 == n) {
                hdr_names.push((n, format!("{rel}:{ln}")));
            }
        }
        for d in x.file_scope_decls(&rel, &text, x.model_of(&rel, &text)) {
            hdr_decls.entry(d.name.clone()).or_insert(d);
        }
    }
    for (callee, sites) in per_callee {
        let found = call_sites(x, &t.unit, &callee);
        let sites = if found.is_empty() { sites } else { found };
        let classes: Vec<(String, i64, (bool, &str))> = sites.iter().map(|(f, ln)| {
            let p = py_path(&format!("{root}/{f}"));
            let text = Path::new(&p).exists().then(|| read(root, f));
            (f.clone(), *ln, call_class(text.as_deref(), *ln, &callee, hdr_decls.get(&callee)))
        }).collect();
        let risky: Vec<&(String, i64, (bool, &str))> = classes.iter().filter(|c| !c.2 .0).collect();
        let fns: BTreeSet<i64> = risky.iter().filter_map(|(f, ln, _)| spans.at(f, *ln)).collect();
        let n_safe = sites.len() - risky.len();
        items.push(Item {
            kind: "prototyped", name: Some(callee.clone()), at: format!("{}:{}", sites[0].0, sites[0].1),
            msg: format!("{} calls compiled without a prototype; the header's now converts their arguments: safe={n_safe} (constant arguments, the pushes \
                          cannot change) regrade={} (float widening / integer promotion may change them)", sites.len(), risky.len()),
            fns: fns.into_iter().collect(), sites: classes.iter().map(|(f, ln, c)| format!("{f}:{ln} ({})", c.1)).collect(), ..Default::default()
        });
    }
    // duplicates: names of the head region the headers declare too, without a diagnostic
    let end = x.scan.functions().filter(|f| f.0 .0 == head).map(|f| f.1 .3).min().unwrap_or(1 << 30);
    let mut mine = x.declared_names(&head, &old_lines.join("\n"));
    mine.sort_by_key(|m| m.1);
    for (n, ln) in mine {
        if let Some((_, h)) = hdr_names.iter().find(|h| h.0 == n) {
            if !conflicting.contains(&n) && ln < end {
                let at = format!("{head}:{ln}");
                items.push(Item { kind: "duplicate", name: Some(n.clone()), ours: rd.line(&at), theirs: rd.line(h), at, other: Some(h.clone()),
                                  msg: "the header declares it the same way".into(), ..Default::default() });
            }
        }
    }
    let added = declaration_set(x, &t.unit, &head, &hdr_names);
    Ok(Ok(Analysis { unit: t.unit, items, vc6: t.vc6.is_some(), added }))
}

/// (file, line) of every call of `callee` inside a function body of the unit's file.
fn call_sites(x: &Ctx, a: &crate::plan::Tu, callee: &str) -> Vec<(String, i64)> {
    let pat = Regex::new(&format!(r"\b{}\s*\(", regex::escape(callee))).unwrap();
    let text = read(&x.root, &a.file);
    let src = Source::new(&text);
    let model = x.model_of(&a.file, &text).unwrap_or_default();
    let code = live_code(&src, &model);
    let (mut depth, mut pos) = (0i64, 0usize);
    let mut out = vec![];
    for hit in pat.find_iter(&code) {
        for c in code[pos..hit.start()].chars() {
            depth += (c == '{') as i64 - (c == '}') as i64;
        }
        pos = hit.start();
        if depth > 0 {
            out.push((a.file.clone(), src.line_of(ci(&code, hit.start())) as i64));
        }
    }
    out
}

/// What the includes do to the unit's declaration set: the number of names the headers add (declared nowhere in
/// the unit or its current headers).
fn declaration_set(x: &Ctx, a: &crate::plan::Tu, head: &str, hdr_names: &[(String, String)]) -> usize {
    let mut have: HashSet<String> = x.declared_names(&a.file, &read(&x.root, &a.file)).into_iter().map(|n| n.0).collect();
    let current: Vec<String> = INCLUDE_LINE.captures_iter(&read(&x.root, head)).map(|c| c[1].to_string()).collect();
    for rel in x.header_closure(&current) {
        have.extend(x.declared_names(&rel, &read(&x.root, &rel)).into_iter().map(|n| n.0));
    }
    hdr_names.iter().map(|h| &h.0).collect::<HashSet<_>>().iter().filter(|n| !have.contains(**n)).count()
}

/// int | float | string | expr: the class of one call argument.
fn arg_kind(arg: &str) -> &'static str {
    let mut s = py_strip(arg).to_string();
    loop {
        let Some(m) = CAST.find(&s) else { break };
        let rest = py_strip(&s[m.end()..]).to_string();
        if rest.is_empty() {
            break;
        }
        s = rest;
    }
    while s.starts_with('(') && s.ends_with(')') && s.len() >= 2 {
        s = py_strip(&s[1..s.len() - 1]).to_string();
    }
    if s.starts_with('"') {
        "string"
    } else if FLOAT_CONST.is_match(&s) {
        "float"
    } else if INT_CONST.is_match(&s) {
        "int"
    } else {
        "expr"
    }
}

/// The argument texts of the first call of `callee` on line `line` (1-based) of a source text.
fn call_args(text: &str, line: i64, callee: &str) -> Option<Vec<String>> {
    let lines: Vec<&str> = text.split('\n').collect();
    if line < 1 || line as usize > lines.len() {
        return None;
    }
    let off: usize = lines[..line as usize - 1].iter().map(|l| l.len() + 1).sum();
    let end = off + lines[line as usize - 1].len();
    let pat = Regex::new(&format!(r"\b{}\s*\(", regex::escape(callee))).unwrap();
    let m = pat.find_at(&text[..end], off)?;
    let t: Vec<char> = text.chars().collect();
    let (mut args, mut depth, mut cur, mut i) = (vec![], 1, String::new(), ci(text, m.end()));
    while i < t.len() && depth > 0 {
        let c = t[i];
        if c == '"' || c == '\'' {
            let mut j = i + 1;
            while j < t.len() && t[j] != c {
                j += if t[j] == '\\' { 2 } else { 1 };
            }
            cur.extend(&t[i..(j + 1).min(t.len())]);
            i = j + 1;
            continue;
        }
        if c == '(' {
            depth += 1;
        } else if c == ')' {
            depth -= 1;
            if depth == 0 {
                break;
            }
        }
        if c == ',' && depth == 1 {
            args.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
        i += 1;
    }
    if !py_strip(&cur).is_empty() || !args.is_empty() {
        args.push(cur);
    }
    Some(args.iter().map(|a| py_strip(a).to_string()).collect())
}

/// (safe, why) of a call that compiled without a prototype and gets the header's: safe when every argument is a
/// constant whose push the prototype cannot change.
fn call_class(text: Option<&str>, line: i64, callee: &str, decl: Option<&crate::lint::Decl>) -> (bool, &'static str) {
    let Some(args) = call_args(text.unwrap_or(""), line, callee) else { return (false, "call not found: re-grade") };
    let mut params: Vec<String> = vec![];
    if let Some(d) = decl.filter(|d| d.func()) {
        let sp: Vec<char> = d.spelling().chars().collect();
        let st = chars(&sp);
        let from = st.find(callee).map(|b| ci(&st, b)).unwrap_or(sp.len().saturating_sub(1));
        if let Some(k) = sp[from.min(sp.len())..].iter().position(|&c| c == '(').map(|k| k + from) {
            let close = sp.iter().rposition(|&c| c == ')').unwrap_or(sp.len().saturating_sub(1));
            let inner = if k + 1 <= close { chars(&sp[k + 1..close]) } else { String::new() };
            params = inner.split(',').map(|p| py_strip(p).to_string()).collect();
        }
    }
    let kinds: Vec<&str> = args.iter().map(|a| arg_kind(a)).collect();
    if kinds.contains(&"expr") {
        return (false, "expressions: re-grade");
    }
    for (j, kd) in kinds.iter().enumerate() {
        let p = params.get(j).map(|s| s.as_str()).unwrap_or("");
        let floating = FLOATING.is_match(p) && !p.contains('*');
        if *kd == "float" && !DOUBLE.is_match(p) {
            return (false, "a floating constant to a float / non-double parameter: re-grade");
        }
        if (*kd == "int" || *kd == "string") && floating {
            return (false, "an integer constant to a floating parameter: re-grade");
        }
    }
    (true, if args.is_empty() { "no arguments: safe" } else { "constants: safe" })
}

/// Per call of `callee` inside the original's function `func`: its site, the pushes since the previous call (or
/// the start) and the `add esp, N` right after it.
fn call_evidence(x: &Ctx, capstone: &str, names: &crate::names::Names, func: Option<i64>, callee: Option<&str>) -> Result<Vec<String>> {
    let (Some(func), Some(callee)) = (func, callee) else { return Ok(vec![]) };
    let Some(to) = names.by_name.iter().find(|n| n.0 == callee).and_then(|n| n.1.iter().min().copied()) else {
        return Ok(vec![format!("{callee}: no address known")]);
    };
    let db = x.p.store_path();
    let syms = crate::with_db(&db, |c| store::facts_of(c, &db, "symbol", None, |f| f.lo == func && f.s("skind") == Some("func") && !f.rule.starts_with("M.")))?;
    let Some(sym) = syms.iter().next() else { return Ok(vec![]) };
    let img = crate::image(&x.p.target(None).map_err(err)?.path)?;
    let fills = crate::toolchain::of(&x.p.toolchain_key()).map(|t| t.fill_forms().iter().map(|f| f.to_vec()).collect()).unwrap_or_default();
    let lines = crate::x86::x86_disasm(capstone, &img.read(sym.lo as u32, (sym.hi - sym.lo).max(0) as usize), sym.lo as u32, fills)?;
    let (mut out, mut pushes) = (vec![], 0);
    for (i, (addr, _, text, _)) in lines.iter().enumerate() {
        let op = text.split_whitespace().next().unwrap_or("");
        if op == "call" {
            let low = text.to_lowercase();
            if low.contains(&format!("{to:#x}")) || low.contains(&format!("0x{to:x}")) {
                let nxt = lines.get(i + 1).map(|l| l.2.as_str()).unwrap_or("");
                let clean = match ADD_ESP.captures(nxt) {
                    Some(m) => {
                        let v = crate::cliread::parse_addr(&m[1]).unwrap_or(0);
                        format!("add esp,{} ({} args)", &m[1], v.div_euclid(4))
                    }
                    None => "no add esp after".into(),
                };
                out.push(format!("original {}: {pushes} pushes since the previous call, {clean}", fmt_addr(*addr as i64)));
            }
            pushes = 0;
        } else if op == "push" {
            pushes += 1;
        }
    }
    if out.is_empty() {
        out.push(format!("original: no call of {callee} in {}", fmt_addr(func)));
    }
    Ok(out)
}

// ------------------------------------------------------------------------------------------------ the command

/// The include spelling of h (`d2`, `d2.h`, `include/d2.h`) when the include directory holds it.
fn resolve_header(root: &str, h: &str) -> Option<String> {
    let base = Path::new(h).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let name = if h.ends_with(".h") { base } else { format!("{base}.h") };
    Path::new(&py_path(&format!("{root}/include/{name}"))).exists().then_some(name)
}

/// --trial: the unit's text with the includes (and without the head's duplicates, as --write would leave it)
/// compiled by the toolchain into build/obj/trial/ (the files removed after), and each function of the unit graded
/// against the original as G.grade grades its code: byte when M.match's compare matches, else shape or draft by the
/// instruction diff over the extent and slot its grade row read. (address, name, code grade now, in the trial), or
/// the compiler's first error.
#[allow(clippy::type_complexity)]
fn trial_grades(p: &Project, capstone: &str, unit: &crate::plan::Tu, text: &str) -> Result<Result<Vec<(i64, String, String, String)>, String>> {
    let root = p.root.to_string_lossy().into_owned();
    let db = p.store_path();
    let tools = crate::vc6::Tools::of(p);
    if !tools.available() {
        return Ok(Err("the toolchain is not available".into()));
    }
    let flags = crate::plan::compile_flags(p, &unit.target, &unit.unit).map_err(err)?;
    let (src, obj) = (format!("build/trial/{}-headers.c", unit.unit), format!("build/obj/trial/{}-headers.obj", unit.unit));
    let full = |r: &str| py_path(&format!("{root}/{r}"));
    for r in [&src, &obj] {
        if let Some(d) = Path::new(&full(r)).parent() {
            let _ = std::fs::create_dir_all(d);
        }
    }
    let _ = std::fs::remove_file(full(&obj));
    std::fs::write(full(&src), text).map_err(err)?;
    let res = tools.compile(&src, &obj, &flags, &["include".to_string()], &root).map_err(err)?;
    let data = std::fs::read(full(&obj));
    for r in [&src, &obj] {
        let _ = std::fs::remove_file(full(r));
    }
    if !res.ok {
        return Ok(Err(res.diags.iter().find(|d| d.severity == "error").map(|d| format!("{}({}): {} {}", d.file, d.line, d.code, d.message))
            .unwrap_or_else(|| "does not compile".into())));
    }
    let o = crate::coff::Obj::parse(&data.map_err(err)?).map_err(err)?;
    let index = o.function_index();
    let img = crate::image(&p.target(None).map_err(err)?.path)?;
    let tc = crate::toolchain::of(&p.toolchain_key()).ok_or_else(|| err("no toolchain"))?;
    let fill_forms: Vec<Vec<u8>> = tc.fill_forms().iter().map(|f| f.to_vec()).collect();
    let fills: HashSet<Vec<u8>> = fill_forms.iter().cloned().collect();
    let forms = crate::compare::fill_order(&fill_forms);
    let env = crate::diffclass::Env { dll: capstone, img: &img, range: (img.base as i64, img.end() as i64), fills: &fills, forms: &forms };
    let starts = crate::asmcmd::all_starts(&db, &img)?;
    let relocs: Option<Vec<u32>> = if img.relocations().is_empty() {
        None
    } else {
        let mut v: Vec<u32> = crate::with_db(&db, |c| store::facts_of(c, &db, "ref", None, |f| f.s("rkind") == Some("reloc")))?.iter().map(|f| f.lo as u32).collect();
        v.sort_unstable();
        (!v.is_empty()).then_some(v)
    };
    let mut out = vec![];
    for r in crate::queues::function_grades(&db)?.iter().filter(|r| r["unit"].as_str() == Some(unit.unit.as_str())) {
        let (a, name) = (r["addr"].as_i64().unwrap_or(0), r["name"].as_str().unwrap_or("").to_string());
        let now = r["code"].as_str().unwrap_or("").to_string();
        let Some(&k) = index.get(&name) else {
            out.push((a, name, now, "none".into()));
            continue;
        };
        let code = o.function_code(k);
        let next = starts.get(starts.partition_point(|&x| x <= a)).copied().unwrap_or(img.end() as i64) as u32;
        let grade = if crate::compare::compare(&img, &code, a as u32, relocs.as_deref(), next, &forms).matched() {
            "byte"
        } else {
            let d = &r["dist"];
            let (cd, cm) = code.code();
            let size = crate::diffclass::code_size(&env, cd, cm, a as u32).map_err(err)?;
            let extent = d.get("extent").and_then(|v| v.as_i64()).unwrap_or(size);
            let slot = d.get("slot").and_then(|v| v.as_i64()).unwrap_or(extent.max(next as i64 - a));
            let orig = crate::diffclass::original(&env, a as u32, extent, slot, tc.function_alignment() as i64).map_err(err)?;
            if crate::diffclass::function_verdict(&env, &o, &code, a as u32, &orig).map_err(err)?.shape { "shape" } else { "draft" }
        };
        out.push((a, name, now, grade.to_string()));
    }
    out.sort();
    Ok(Ok(out))
}

/// `dcp headers conflicts UNIT HEADER.. [--write] [--trial] [--at LINE]`: (the lines, the exit status).
#[pyfunction]
#[pyo3(signature = (project, capstone, unit, headers, write, at, try_grades=false))]
pub fn headers_conflicts(project: PyRef<'_, crate::project::PyProject>, capstone: &str, unit: &str, headers: Vec<String>, write: bool, at: Option<i64>,
                         try_grades: bool) -> Result<(Vec<String>, i32)> {
    let p = &project.p;
    let root = p.root.to_string_lossy().into_owned();
    let mut out = vec![];
    if frontend::library(Some(&p.cfg)).is_none() {
        out.push(record(&[("error", s(frontend::NOT_FOUND))]));
        return Ok((out, 2));
    }
    let mut hdrs = vec![];
    for h in &headers {
        match resolve_header(&root, h) {
            Some(r) => hdrs.push(r),
            None => {
                out.push(record(&[("unit", s(unit)), ("header", s(h.clone())), ("error", s("no such header in the unit's include directories"))]));
                return Ok((out, 2));
            }
        }
    }
    crate::pystore::st_open(&p.store_path(), &p.main_uri())?;
    let scan = frontend::scan(&root, p.input_hash("src").map_err(err)?.as_deref()).map_err(err)?;
    let x = Ctx { p, t: Texts { root: root.clone(), front: Front::of(&root).map_err(err)?, scan: Some(scan.clone()) }, scan };
    let an = match analyse(&x, capstone, unit, &hdrs, at)? {
        Ok(a) => a,
        Err(e) => {
            out.push(record(&[("unit", s(unit)), ("error", s(e))]));
            return Ok((out, 2));
        }
    };
    let db = p.store_path();
    // an exempt finding is listed with its marker but counts nowhere: the line is the original's or VC6's business
    let count = |k: &str| an.items.iter().filter(|i| i.kind == k && i.exempt.is_none()).count() as i64;
    let mut head: Vec<(&str, Tok)> = vec![("unit", s(unit)), ("headers", s(hdrs.join(",")))];
    head.extend(ORDER.iter().map(|k| (*k, Tok::I(count(k)))));
    if !an.vc6 {
        head.push(("vc6_trial", s("unavailable")));
    }
    out.push(record(&head));
    let mut regrade: BTreeMap<i64, BTreeSet<&str>> = BTreeMap::new();
    for kind in ORDER {
        for i in an.items.iter().filter(|i| i.kind == kind) {
            out.push(format!("  {}", record(&[("kind", s(i.kind)), ("name", os(i.name.clone())), ("at", s(i.at.clone())),
                                              (if kind == "call" { "decl" } else { "header" }, os(i.other.clone())),
                                              ("exempt", os(i.exempt.map(|m| m.to_string())))])));
            if !i.msg.is_empty() && kind != "duplicate" {
                out.push(format!("    {}", i.msg));
            }
            let (a_, b_) = if kind == "clash" { ("first: ", "second:") } else { ("ours:  ", if kind == "call" { "decl:  " } else { "header:" }) };
            if !i.ours.is_empty() {
                out.push(format!("    {a_} {}", i.ours));
            }
            if !i.theirs.is_empty() {
                out.push(format!("    {b_} {}", i.theirs));
            }
            for ev in &i.evidence {
                out.push(format!("    {ev}"));
            }
            if !i.sites.is_empty() {
                let more = if i.sites.len() > 8 { format!(" (+{})", i.sites.len() - 8) } else { String::new() };
                out.push(format!("    sites: {}{more}", i.sites.iter().take(8).cloned().collect::<Vec<_>>().join(", ")));
            }
            for f in i.func.iter().chain(&i.fns) {
                if matches!(kind, "supersedes" | "call" | "vc6" | "prototyped" | "other") {
                    regrade.entry(*f).or_default().insert(kind);
                }
            }
        }
    }
    out.push(record(&[("regrade", Tok::I(regrade.len() as i64))]));
    for (f, kinds) in &regrade {
        let r = crate::asmcmd::find_function(&db, &fmt_addr(*f))?;
        let get = |k: &str| r.as_ref().and_then(|r| r.get(k)).and_then(|v| v.as_str()).map(|v| v.to_string());
        out.push(format!("  {}", record(&[("fn", Tok::I(*f)), ("name", os(get("name"))), ("code", os(get("code"))),
                                          ("why", s(kinds.iter().copied().collect::<Vec<_>>().join(",")))])));
    }
    let dropped = count("duplicate");
    if an.added > 0 || dropped > 0 {
        // VC6 /O2: the declaration set of a unit alone moves code generation (gildegold: removing uncalled
        // prototypes flipped byte matches to shape)
        let mut fns = vec![];
        for (addr, name) in &an.unit.functions {
            if let Some(addr) = addr {
                let r = crate::asmcmd::find_function(&db, name)?;
                fns.push((*addr, name.clone(), r.and_then(|r| r.get("code").and_then(|v| v.as_str()).map(|v| v.to_string()))));
            }
        }
        fns.sort_by_key(|f| (match f.2.as_deref() { Some("byte") => 0, Some("shape") => 1, _ => 2 }, f.0));
        let n = |c: &str| fns.iter().filter(|f| f.2.as_deref() == Some(c)).count() as i64;
        out.push(record(&[("warning", s("declaration-set")), ("added", Tok::I(an.added as i64)), (if write { "dropped" } else { "duplicates" }, Tok::I(dropped)),
                          ("functions", Tok::I(fns.len() as i64)), ("byte", Tok::I(n("byte"))), ("shape", Tok::I(n("shape")))])
                 + "  (the unit's declaration set changes: VC6 /O2 can move code by it alone; re-grade every function of the unit, byte ones first; \
                    the byte and shape ones follow; --trial grades them)");
        for (addr, name, code) in &fns {
            if matches!(code.as_deref(), Some("byte" | "shape")) {
                out.push(format!("  {}", record(&[("fn", Tok::I(*addr)), ("name", s(name.clone())), ("code", os(code.clone()))])));
            }
        }
    }
    let blocking: i64 = BLOCKING.iter().map(|k| count(k)).sum();
    let mut drop: BTreeMap<i64, HashSet<String>> = BTreeMap::new();
    for i in an.items.iter().filter(|i| i.kind == "duplicate") {
        let ln: i64 = i.at.rsplit(':').next().and_then(|n| n.parse().ok()).unwrap_or(0);
        drop.entry(ln).or_default().extend(i.name.clone());
    }
    let mut falls = 0;
    if try_grades {
        // the declaration set's effect itself: the unit compiled as --write would leave it, every function graded
        let t = trial(&x, unit, &hdrs, &drop, at).map_err(err)?;
        match trial_grades(p, capstone, &t.unit, &t.new.replace(TRIAL_MARK, ""))? {
            Err(e) => {
                out.push(record(&[("trial", s("failed")), ("why", s(e))]));
                falls = 1;
            }
            Ok(gs) => {
                let rank = |c: &str| ["none", "draft", "shape", "byte"].iter().position(|x| *x == c).unwrap_or(0);
                let fell: Vec<_> = gs.iter().filter(|g| rank(&g.3) < rank(&g.2)).collect();
                let rose: Vec<_> = gs.iter().filter(|g| rank(&g.3) > rank(&g.2)).collect();
                falls = fell.len();
                out.push(record(&[("trial", s("compiled")), ("functions", Tok::I(gs.len() as i64)), ("falls", Tok::I(fell.len() as i64)),
                                  ("rises", Tok::I(rose.len() as i64)), ("same", Tok::I((gs.len() - fell.len() - rose.len()) as i64))])
                         + "  (the unit with the includes, as --write would leave it, compiled and each function's code graded; nothing written)");
                for (what, gs) in [("fall", fell), ("rise", rose)] {
                    for (a, name, now, then) in gs {
                        out.push(format!("  {}", record(&[(what, Tok::I(*a)), ("name", s(name.clone())), ("code", s(now.clone())), ("trial", s(then.clone()))])));
                    }
                }
            }
        }
    }
    if !write {
        return Ok((out, if blocking > 0 || falls > 0 { 1 } else { 0 }));
    }
    if blocking > 0 {
        out.push(record(&[("write", s("refused")), ("why", s(format!("{blocking} conflicts left; only includes and duplicates are written")))]));
        return Ok((out, 1));
    }
    let t = trial(&x, unit, &hdrs, &drop, at).map_err(err)?;
    let mut rd = Reader { root: root.clone(), memo: HashMap::new() };
    let left: Vec<&Group> = t.new_errors(&mut rd).into_iter().filter(|g| t.exemption(g, &mut rd).is_none()).collect();
    let vleft = vc6_new(&t.vc6);
    if !left.is_empty() || !vleft.is_empty() {
        out.push(record(&[("write", s("refused")), ("why", s(format!("without the duplicates the trial has {} new errors", left.len() + vleft.len()))),
                          ("at", Tok::I(t.pos as i64 + 1))])
                 + "  (the includes went before the file's line `at`; --at LINE puts them elsewhere)");
        for g in left.iter().take(10) {
            out.push(format!("  {}", fmt_group(g)));
        }
        for d in vleft.iter().take(10) {
            out.push(format!("  vc6 {}:{}: {}", d.file, d.line, d.msg));
        }
        return Ok((out, 1));
    }
    std::fs::write(py_path(&format!("{root}/{}", t.unit.file)), t.new.replace(TRIAL_MARK, "")).map_err(err)?;
    out.push(record(&[("write", s(t.unit.file.clone())), ("included", s(hdrs.join(","))), ("at", Tok::I(t.pos as i64 + 1)),
                      ("dropped", Tok::I(drop.values().map(|v| v.len() as i64).sum())), ("lines", Tok::I(drop.len() as i64))])
             + "  (dcp build, then dcp check and re-grade the unit)");
    Ok((out, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(xs: &[&str]) -> HashSet<String> {
        xs.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn dropping_declarators() {
        assert_eq!(drop_names("extern int a, b, c;  /* 0x600000 */", &set(&["b"])), Some("extern int a, c;  /* 0x600000 */".into()));
        assert_eq!(drop_names("extern int *a, b;", &set(&["a"])), Some("extern int b;".into()));
        assert_eq!(drop_names("extern int a;  /* 0x600000, the count */", &set(&["a"])), None);
        assert_eq!(drop_names("int f(int x);", &set(&["f"])), Some("int f(int x);".into()));
        assert_eq!(drop_line("int f(int x);", &set(&["f"]), &set(&["f"])), None);
        assert_eq!(drop_names("  extern char buf[16], n;", &set(&["n"])), Some("  extern char buf[16];".into()));
    }

    #[test]
    fn dropping_from_multi_name_lines() {
        assert_eq!(drop_names("extern int a, *b, c[3];  /* 0x1 */", &set(&["b"])), Some("extern int a, c[3];  /* 0x1 */".into()));
        assert_eq!(drop_names("extern int a, *b, c[3];  /* 0x1 */", &set(&["a"])), Some("extern int *b, c[3];  /* 0x1 */".into()));
        assert_eq!(drop_names("extern int a, *b;  /* 0x1 */", &set(&["a", "b"])), None);
        assert_eq!(drop_names("extern int x; extern char *y, z;", &set(&["x"])), Some("extern char *y, z;".into()));
        assert_eq!(drop_line("int f(void);  /* 0x1 */", &set(&["f"]), &set(&["f"])), None);
    }

    /// The declared names and the include position need a parse (libclang): skipped without one.
    #[test]
    fn declared_names_and_include_pos() {
        if frontend::library(None).is_none() {
            return;
        }
        let root = std::env::temp_dir().join(format!("dcp-headers-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let r = root.to_string_lossy().into_owned();
        let x = Texts { root: r.clone(), front: Front::of(&r).unwrap(), scan: None };
        let names = |text: &str| x.declared_names("h.c", text);
        assert_eq!(names("extern int a, *b, c[3];
"), [("a".to_string(), 1), ("b".to_string(), 1), ("c".to_string(), 1)]);
        let text = "#include \"a.h\"
extern int x;
static int tab[] = {
  1,
  x
};
#include \"late.h\"
";
        assert_eq!(include_pos(&x, "h.c", text, &set(&["x"])), 2);
        assert_eq!(include_pos(&x, "h.c", text, &set(&["y"])), 7);
        let text = "#include \"a.h\"
extern int x;
/* the table,
   of x */ static int *px =
  &x;
#include \"late.h\"
";
        assert_eq!(include_pos(&x, "h.c", text, &set(&["x"])), 2); // not inside the comment, not inside the statement
    }

    /// The file-scope declarations lint repeats (needs libclang): data definitions as externs, K&R definitions with
    /// an empty body and their default-promoted prototype, function definitions as prototypes.
    #[test]
    fn file_scope_declarations() {
        if frontend::library(None).is_none() {
            return;
        }
        let root = std::env::temp_dir().join(format!("dcp-decls-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let r = root.to_string_lossy().into_owned();
        let x = Texts { root: r.clone(), front: Front::of(&r).unwrap(), scan: None };
        let ds = x.file_scope_decls("src/u/head.c", "int a = 1, *b;\nstatic int c;\nextern struct S s[];\ntypedef int T;\n\
                                     static int f(void) { return 0; }\nint g(x) int x; { return x; }\nint h(void);\n\
                                     struct Q { int q; };\nchar *k(char *s)\n{\n    return s;\n}\n", None);
        let got: Vec<(&str, &str, &str)> = ds.iter().map(|d| (d.kind.as_str(), d.name.as_str(), d.stmt.as_str())).collect();
        assert_eq!(got, [("ddef", "a", "extern int a;"), ("ddef", "b", "extern int *b;"), ("extern", "s", "extern struct S s[];"),
                         ("knr", "g", "int g(x) int x; {}"), ("proto", "h", "int h(void);"), ("fdef", "k", "char *k(char *s);")]);
        assert!(ds.iter().all(|d| &d.stmt[d.at..d.at + d.name.len()] == d.name));
        // a K&R definition compares as its default-promoted prototype (`int f()` and `int f(int, int)` agree with it)
        let ds = x.file_scope_decls("src/u/f.c", "int f(x, y, p, q) short x; unsigned char y; float p; char *q;\n{\n}\n", None);
        assert!(ds.len() == 1 && ds[0].kind == "knr" && ds[0].proto == "int f(int x, int y, double p, char *q);");
    }

    /// A function's span runs from its address comment to the last line of its definition (an end of 0: open).
    #[test]
    fn function_spans() {
        let spans = Spans { by: [("src/net.c".to_string(), vec![(13, 17, 0x10001000), (24, 0, 0x10001020)])].into_iter().collect() };
        assert_eq!((spans.at("src/net.c", 13), spans.at("src/net.c", 17)), (Some(0x10001000), Some(0x10001000)));
        assert_eq!((spans.at("src/net.c", 12), spans.at("src/net.c", 18)), (None, None));
        assert_eq!((spans.at("src/net.c", 26), spans.at("src/other.c", 13)), (Some(0x10001020), None));
    }

    #[test]
    fn includes_go_after_the_last() {
        assert_eq!(after_includes("#include \"a.h\"\n#include <b.h>\nint x;\n"), 2);
        assert_eq!(after_includes("int x;\n"), 0);
        assert_eq!(insert_includes("a\nb", &["h.h".to_string()], 1), format!("a\n#include \"h.h\"{TRIAL_MARK}\nb"));
    }

    #[test]
    fn call_arguments_and_classes() {
        assert_eq!(call_args("x = f(1, \"a,b\", g(2, 3));\n", 1, "f").unwrap(), ["1", "\"a,b\"", "g(2, 3)"]);
        assert_eq!(call_args("f();\n", 1, "f").unwrap(), Vec::<String>::new());
        assert_eq!(call_args("g();\n", 1, "f"), None);
        assert_eq!(arg_kind("(int)5"), "int");
        assert_eq!(arg_kind("1.5f"), "float");
        assert_eq!(arg_kind("2e3"), "float");
        assert_eq!(arg_kind("'a'"), "int");
        assert_eq!(arg_kind("\"s\""), "string");
        assert_eq!(arg_kind("x + 1"), "expr");
        assert_eq!(call_class(Some("f(1, 2);"), 1, "f", None), (true, "constants: safe"));
        assert_eq!(call_class(Some("f(1.5);"), 1, "f", None), (false, "a floating constant to a float / non-double parameter: re-grade"));
        assert_eq!(call_class(Some("f(a);"), 1, "f", None), (false, "expressions: re-grade"));
    }
}
