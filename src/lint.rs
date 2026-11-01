//! The declaration checker's reading of the sources (source/lint.py is its Python face and documents M5..M7):
//! a file's file-scope declarations as the all-declarations unit repeats them, its macro lines, the names it
//! defines and uses (the header order), its system includes; the all-declarations unit built from the scan's
//! pieces; the M5 lines of a run of clang over it. Offsets are byte offsets; the `at` of a declaration goes to
//! Python in characters.

use crate::error::Result;
use crate::srcscan::{py_space, py_strip, py_words, Src};
use crate::clang::FileModel;
use pyo3::prelude::*;

use regex::Regex;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::LazyLock;

type Lc = (i64, i64);

fn is_w(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

static IDENTS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z_]\w*").unwrap());
static IDENT_AT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\A[A-Za-z_]\w*").unwrap());
static DECL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\A\s*((?:[A-Za-z_]\w*[\s\*]+)+?)\b([A-Za-z_]\w*)\s*\(").unwrap());
static FUNCPTR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\(\s*(?:__cdecl|__stdcall|__fastcall|WINAPI|CALLBACK|APIENTRY|PASCAL)?\s*\*+\s*(?:const\s+)?([A-Za-z_]\w*)\s*\)").unwrap()
});
static BRACKETS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\[[^\]]*\]").unwrap());
static LEAD_EXTERN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\A\s*extern\b").unwrap());
static TAGREF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(?:struct|union|enum)\s+[A-Za-z_]\w*").unwrap());
static TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(struct|union)\s+([A-Za-z_]\w*)").unwrap());
static SYSINC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^[ \t]*#[ \t]*include[ \t]*<([^>]+)>").unwrap());
static EXEMPT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"@(original|vc6)\b").unwrap());

/// The exemption marker a source line carries (`@original why`, `@vc6 why`: the line's diagnostics are the
/// original's or VC6's business, not clang's), the first of the line; None when it carries none. A diagnostic group
/// is exempt when any of its lines carries one (M6, `dcp headers conflicts`).
pub(crate) fn exemption(line: &str) -> Option<&'static str> {
    EXEMPT.captures(line).map(|c| if &c[1] == "vc6" { "@vc6" } else { "@original" })
}
static CROSS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A(?:conflicting types for|redeclaration of|redefinition of|typedef redefinition with different types) ('(\w+)'|\()").unwrap()
});
static CC_END: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s*\b(__cdecl|__stdcall|__fastcall|WINAPI|CALLBACK|APIENTRY|PASCAL)\z").unwrap());
const COPY: &str = "@dcp-copy";
const CHECK: &str = "@dcp-check";

// ------------------------------------------------------------------------------------------------ one file

/// A declaration of the front end's model (cparse.model `decls`): a function's ("f") or a data declarator's.
pub(crate) struct MDecl {
    f: bool,
    name: String,
    stat: bool,
    start: Lc,
    npos: Lc,
    body: Option<Lc>,
    knr: Option<Vec<(String, Option<String>)>>,
    kind: String, // a datum's def / extern
    init: bool,   // a datum's initialiser (a function's: K&R parameters, as Python's truth of the list)
}

pub(crate) fn mdecls(decls: &[crate::clang::Decl]) -> Vec<MDecl> {
    use crate::clang::Decl;
    decls
        .iter()
        .map(|d| match d {
            Decl::F(name, stat, ws, n, _, body, knr) => MDecl {
                f: true, name: name.clone(), stat: *stat, start: *ws, npos: *n, body: *body, knr: knr.clone(), kind: String::new(),
                init: knr.as_ref().is_some_and(|k| !k.is_empty()),
            },
            Decl::V(name, stat, ws, n, _, kind, init, _) => MDecl {
                f: false, name: name.clone(), stat: *stat, start: *ws, npos: *n, body: None, knr: None, kind: kind.clone(), init: *init,
            },
        })
        .collect()
}

/// One file-scope declaration or definition as the all-declarations unit repeats it (lint.Decl).
#[derive(Clone, PartialEq)]
pub(crate) struct Decl {
    pub(crate) file: String,
    pub(crate) line: i64,
    pub(crate) last: i64,
    pub(crate) name: String,
    pub(crate) kind: String, // proto | extern | fdef | knr | ddef
    pub(crate) stmt: String,
    pub(crate) at: usize, // byte offset of the name in stmt
    pub(crate) init: bool,
    pub(crate) proto: String,
}

impl Decl {
    pub(crate) fn func(&self) -> bool {
        matches!(self.kind.as_str(), "proto" | "fdef" | "knr")
    }

    fn definition(&self) -> bool {
        matches!(self.kind.as_str(), "fdef" | "knr" | "ddef")
    }

    pub(crate) fn spelling(&self) -> String {
        let s = match self.stmt.strip_suffix(" {}") {
            Some(s) => s,
            None => self.stmt.trim_end_matches(';'),
        };
        py_strip(s.strip_prefix("extern ").unwrap_or(s)).to_string()
    }

    fn where_(&self) -> String {
        format!("{}:{}", self.file, self.line)
    }

    fn renamed(&self, new: &str) -> String {
        let (s, k) = if self.proto.is_empty() { (&self.stmt, Some(self.at).filter(|&a| a != usize::MAX)) } else { (&self.proto, name_at(&self.proto, &self.name)) };
        match k {
            Some(k) => format!("{}{}{}", &s[..k], new, &s[k + self.name.len()..]),
            None => {
                // Python's offset -1: s[:-1] + new + s[len(name) - 1:]
                let cs: Vec<char> = s.chars().collect();
                let a: String = cs[..cs.len().saturating_sub(1)].iter().collect();
                let b: String = cs[self.name.chars().count().saturating_sub(1).min(cs.len())..].iter().collect();
                format!("{a}{new}{b}")
            }
        }
    }

}

/// lint._name_at: the offset of the declared name in a collapsed declaration: the occurrence followed by a
/// declarator end, else the first whole-word one.
fn name_at(stmt: &str, name: &str) -> Option<usize> {
    if name.is_empty() {
        return None;
    }
    let found: Vec<usize> = {
        let mut v = vec![];
        let mut pos = 0;
        while let Some(i) = stmt[pos..].find(name) {
            v.push(pos + i);
            pos += i + name.chars().next().map(|c| c.len_utf8()).unwrap_or(1);
        }
        v
    };
    let before = |i: usize| stmt[..i].chars().last().is_none_or(|c| !is_w(c));
    for &i in &found {
        let rest = stmt[i + name.len()..].trim_start_matches(py_space);
        if before(i) && rest.chars().next().is_none_or(|c| "([);,=".contains(c)) {
            return Some(i);
        }
    }
    found.into_iter().find(|&i| before(i) && stmt[i + name.len()..].chars().next().is_none_or(|c| !is_w(c)))
}

/// lint.DECLARATOR_LEAD's start in t: the trailing run of white space, `*`, `(` and qualifier words.
fn declarator_lead(t: &str) -> usize {
    let mut p = t.len();
    'outer: loop {
        if let Some(c) = t[..p].chars().last() {
            if py_space(c) || c == '*' || c == '(' {
                p -= c.len_utf8();
                continue;
            }
        }
        for kw in ["const", "volatile", "__cdecl", "__stdcall", "__fastcall", "far", "near"] {
            if t[..p].ends_with(kw) {
                let s = p - kw.len();
                if t[..s].chars().last().is_none_or(|c| !is_w(c)) && t[p..].chars().next().is_none_or(|c| !is_w(c)) {
                    p = s;
                    continue 'outer;
                }
            }
        }
        return p;
    }
}

fn depth_of(c: char) -> i32 {
    match c {
        '(' | '[' | '{' => 1,
        ')' | ']' | '}' => -1,
        _ => 0,
    }
}

/// t cut at its first `=` at depth 0 (an initialiser).
fn cut_init(t: &str) -> &str {
    let mut d = 0;
    for (j, c) in t.char_indices() {
        d += depth_of(c);
        if c == '=' && d == 0 {
            return &t[..j];
        }
    }
    t
}

fn declarator_name(chunk: &str) -> Option<String> {
    if let Some(c) = FUNCPTR.captures(chunk) {
        return Some(c[1].to_string());
    }
    let s = BRACKETS.replace_all(chunk, "");
    IDENTS.find_iter(&s).last().map(|m| m.as_str().to_string())
}

/// lint._data_decls: (name, `extern` declaration) per declarator of a data statement (without its `;`).
fn data_decls(head: &str) -> Option<Vec<(String, String)>> {
    let mut chunks = vec![];
    let (mut d, mut cur) = (0, 0);
    for (j, c) in head.char_indices() {
        if c == ',' && d == 0 {
            chunks.push(&head[cur..j]);
            cur = j + 1;
        } else {
            d += depth_of(c);
        }
    }
    chunks.push(&head[cur..]);
    let mut cut: Vec<String> = chunks.iter().map(|c| cut_init(c).to_string()).collect();
    let names: Vec<String> = cut.iter().map(|c| declarator_name(c)).collect::<Option<_>>()?;
    let k = name_at(&cut[0], &names[0])?;
    let pos = declarator_lead(&cut[0][..k]);
    let base = LEAD_EXTERN.replace(&cut[0][..pos], "").into_owned();
    cut[0] = cut[0][pos..].to_string();
    Some(names.into_iter().zip(cut).map(|(n, ch)| (n, py_words(&format!("extern {base} {ch}")) + ";")).collect())
}

/// lint.file_scope_decls over a file's text (src) and its model's declarations.
pub(crate) fn file_decls(rel: &str, src: &Src, decls: &[MDecl]) -> Vec<Decl> {
    let code = src.code.as_str();
    let cb = code.as_bytes();
    let off = |lc: Lc| src.offset(lc.0, lc.1);
    let mut stmts: Vec<(Lc, Vec<&MDecl>)> = vec![];
    let mut at: HashMap<Lc, usize> = HashMap::new();
    for d in decls {
        match at.get(&d.start) {
            Some(&i) => stmts[i].1.push(d),
            None => {
                at.insert(d.start, stmts.len());
                stmts.push((d.start, vec![d]));
            }
        }
    }
    let kept = |d: &MDecl| !d.stat && IDENT_AT.find(&code[off(d.npos).min(code.len())..]).is_some_and(|m| m.as_str() == d.name);
    let mut out = vec![];
    let decl = |line, last, name: &str, kind: &str, stmt: String, at: Option<usize>, init, proto: String| Decl {
        file: rel.to_string(), line, last, name: name.to_string(), kind: kind.to_string(), at: at.unwrap_or(usize::MAX), stmt, init, proto,
    };
    for (start, group) in &stmts {
        let s = off(*start);
        if !group.iter().any(|d| kept(d)) {
            continue;
        }
        let line = src.line_of(s);
        let g0 = group[0];
        if g0.f && g0.body.is_some() {
            // a definition
            if !kept(g0) {
                continue;
            }
            let (name, brace) = (&g0.name, off(g0.body.unwrap()));
            let p = code[off(g0.npos).min(code.len())..].find('(').map(|i| i + off(g0.npos));
            let mut k = p;
            if let Some(p) = p {
                let (mut j, mut depth) = (p, 0i32);
                while j < brace {
                    depth += (cb[j] == b'(') as i32 - (cb[j] == b')') as i32;
                    j += 1;
                    if depth == 0 {
                        break;
                    }
                }
                k = Some(j);
            }
            let k_ = k.unwrap_or(0);
            if p.is_none() || py_strip(&code[k_.min(brace)..brace]).is_empty() {
                let stmt = py_words(&code[s..brace]) + ";";
                let a = name_at(&stmt, name);
                out.push(decl(line, src.line_of(brace), name, "fdef", stmt, a, false, String::new()));
                continue;
            }
            let p = p.unwrap();
            let (head, between) = (&code[s..k_], &code[k_..brace]);
            let mut types: HashMap<String, String> = HashMap::new();
            for dd in between.split(';') {
                if py_strip(dd).is_empty() {
                    continue;
                }
                for (n, x) in data_decls(dd).unwrap_or_default() {
                    let x = x.strip_prefix("extern ").unwrap_or(&x).trim_end_matches(';').to_string();
                    types.insert(n, py_words(&x));
                }
            }
            let params: Vec<String> = g0.knr.as_deref().unwrap_or(&[]).iter()
                .map(|(n, promote)| match promote {
                    Some(t) => format!("{t} {n}"),
                    None => types.get(n).cloned().unwrap_or_else(|| format!("int {n}")),
                })
                .collect();
            let ps = if params.is_empty() { "void".to_string() } else { params.join(", ") };
            let proto = py_words(&format!("{}({})", &code[s..p], ps)) + ";";
            let fh = py_words(head);
            let a = name_at(&fh, name);
            out.push(decl(line, src.line_of(brace), name, "knr", py_words(&format!("{head} {between}")) + " {}", a, false, proto));
            continue;
        }
        // the `;` that ends the statement, the depth-0 commas before it (read from the text)
        let (mut e, mut depth, mut commas) = (s, 0i32, vec![]);
        while e < cb.len() {
            match cb[e] {
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth -= 1,
                b',' if depth == 0 => commas.push(e),
                b';' if depth == 0 => break,
                _ => {}
            }
            e += 1;
        }
        let last = src.line_of(e);
        let n0 = off(g0.npos).max(s).min(code.len());
        let base_end = s + declarator_lead(&code[s..n0]);
        let mut bounds = vec![base_end];
        bounds.extend(commas.iter().map(|c| c + 1));
        bounds.push(e + 1);
        let texts: Vec<&str> = bounds.windows(2).map(|w| cut_init(&code[w[0]..(w[1] - 1).max(w[0])])).collect();
        if texts.len() != group.len() {
            continue; // the text and the front end disagree (a declarator from a macro)
        }
        let base = &code[s..base_end];
        if g0.f {
            for (d, t) in group.iter().zip(&texts) {
                if !kept(d) {
                    continue;
                }
                let stmt = if group.len() > 1 { py_words(&format!("{base} {t}")) + ";" } else { py_words(&code[s..e]) + ";" };
                let a = match DECL.captures(&stmt) {
                    Some(c) if &c[2] == d.name => Some(c.get(2).unwrap().start()),
                    _ => name_at(&stmt, &d.name),
                };
                out.push(decl(line, last, &d.name, "proto", stmt, a, false, String::new()));
            }
            continue;
        }
        let init = group.iter().any(|d| d.init);
        let base = LEAD_EXTERN.replace(base, "").into_owned();
        for (d, t) in group.iter().zip(&texts) {
            if !kept(d) {
                continue;
            }
            let x = py_words(&format!("extern {base} {t}")) + ";";
            if !d.f && d.kind == "extern" {
                let x = if group.len() == 1 { py_words(&code[s..e]) + ";" } else { x };
                let a = name_at(&x, &d.name);
                out.push(decl(line, last, &d.name, "extern", x, a, false, String::new()));
            } else {
                let a = name_at(&x, &d.name);
                out.push(decl(line, last, &d.name, "ddef", x, a, init, String::new()));
            }
        }
    }
    out
}

/// What the all-declarations unit reads of one file as one target's compile sees it.
#[derive(Default)]
pub(crate) struct FileLint {
    decls: Vec<Decl>,
    macros: Vec<(String, i64, String)>, // name, line, `#define` line (comments blanked, continuations joined)
    defined: HashSet<String>,           // typedefs, tags with a body, macros
    used: HashSet<String>,              // identifiers of its live code (a tag's name not counted)
}

/// One file's FileLint from its text, its model's declarations, macro definitions (name, line, start, end
/// offsets), types, macros and dead ranges.
pub(crate) fn file_lint(rel: &str, src: &Src, m: &FileModel) -> Result<FileLint> {
    let decls = mdecls(&m.decls);
    let defines = &m.defines;
    let code = src.code.as_str();
    let macros = defines
        .iter()
        .map(|(n, _, l, c, el, ec)| {
            let (s, e) = (src.offset(*l, *c), src.offset(*el, *ec));
            let rest = &code[(s + n.len()).min(e)..e];
            (n.clone(), *l, format!("#define {n}{}", rest.replace("\\\n", " ")))
        })
        .collect();
    let defined: HashSet<String> = m.types.iter().map(|t| t.1.clone()).chain(m.macros.iter().map(|m| m.1.clone())).collect();
    let dead = &m.dead;
    let dead: HashSet<i64> = dead.iter().flat_map(|&(a, b)| a..=b).collect();
    // srcscan.live_code: directives and skipped ranges blanked
    let mut live = String::with_capacity(code.len());
    let mut cont = false;
    for (n, ln) in code.split('\n').enumerate() {
        if n > 0 {
            live.push('\n');
        }
        let directive = cont || ln.trim_start_matches(py_space).starts_with('#');
        cont = directive && ln.trim_end_matches(py_space).ends_with('\\');
        if directive || dead.contains(&(n as i64 + 1)) {
            live.extend(std::iter::repeat_n(' ', ln.chars().count()));
        } else {
            live.push_str(ln);
        }
    }
    let live = TAGREF.replace_all(&live, " ");
    let used = IDENTS.find_iter(&live).map(|m| m.as_str()).filter(|w| !defined.contains(*w)).map(|w| w.to_string()).collect();
    Ok(FileLint { decls: file_decls(rel, src, &decls), macros, defined, used })
}

/// A file's `#include <..>` names.
pub(crate) fn system_includes(text: &str) -> Vec<String> {
    SYSINC.captures_iter(text).map(|c| py_strip(&c[1]).to_string()).collect()
}

// ------------------------------------------------------------------------------------------------ the unit

/// The all-declarations unit: its text and what its lines stand for (lint.AllDecls).
#[pyclass(frozen)]
pub struct AllDecls {
    #[pyo3(get)]
    text: String,
    every: Vec<Decl>,                    // every declaration of the headers and the sources
    defs: HashMap<String, usize>,        // name -> the definition every other declaration is compared with
    copies: Vec<usize>,                  // copy id - 1 -> the declaration renamed __dcp_<id>
    checks: Vec<(usize, usize)>,         // check id - 1 -> (declaration, its definition)
    macros: HashMap<String, String>,     // macro name -> file:line of the header that defines it (first)
}

impl AllDecls {
    pub(crate) fn text(&self) -> &str {
        &self.text
    }
}

/// lint.header_order: the headers in an order that defines a name before the headers that use it.
fn header_order(headers: &[String], info: &HashMap<&str, &FileLint>) -> Vec<String> {
    let empty = FileLint::default();
    let get = |h: &str| info.get(h).copied().unwrap_or(&empty);
    let mut provider: HashMap<&str, &str> = HashMap::new();
    for h in headers {
        let mut ns: Vec<&String> = get(h).defined.iter().collect();
        ns.sort();
        for n in ns {
            provider.entry(n.as_str()).or_insert(h.as_str());
        }
    }
    let deps: HashMap<&str, BTreeSet<&str>> = headers
        .iter()
        .map(|h| (h.as_str(), get(h).used.iter().filter_map(|n| provider.get(n.as_str()).copied()).filter(|d| d != h).collect()))
        .collect();
    let (mut out, mut seen): (Vec<String>, HashSet<&str>) = (vec![], HashSet::new());
    for h in headers {
        if seen.contains(h.as_str()) {
            continue;
        }
        seen.insert(h);
        let mut stack: Vec<(&str, Vec<&str>, usize)> = vec![(h, deps[h.as_str()].iter().copied().collect(), 0)];
        while let Some((cur, ds, i)) = stack.last_mut() {
            let mut next = None;
            while *i < ds.len() {
                let d = ds[*i];
                *i += 1;
                if !seen.contains(d) {
                    next = Some(d);
                    break;
                }
            }
            match next {
                None => {
                    out.push(cur.to_string());
                    stack.pop();
                }
                Some(n) => {
                    seen.insert(n);
                    stack.push((n, deps.get(n).map(|s| s.iter().copied().collect()).unwrap_or_default(), 0));
                }
            }
        }
    }
    out
}

/// lint.alldecls over the scan's pieces (srcscan.native_view's ids): headers (include/X.h not private, sorted),
/// srcs (src/**/*.c in the walk's order), the target whose compile the unit stands for.
#[pyfunction]
pub fn lint_alldecls(ids: Vec<u64>, target: Option<String>, headers: Vec<String>, srcs: Vec<String>) -> Result<AllDecls> {
    let pieces = crate::srcscan::pieces_by_rel(&ids)?;
    let empty = FileLint::default();
    let lint_of = |rel: &str| pieces.get(rel).and_then(|p| p.lint_for(&target)).unwrap_or(&empty);
    let info: HashMap<&str, &FileLint> = headers.iter().map(|h| (h.as_str(), lint_of(h))).collect();
    let headers = header_order(&headers, &info);
    let mut every: Vec<Decl> = headers.iter().flat_map(|h| lint_of(h).decls.iter().filter(|d| !d.definition()).cloned()).collect();
    let nh = every.len();
    let mut sources: Vec<(&str, std::ops::Range<usize>, &[(String, i64, String)])> = vec![];
    for rel in &srcs {
        let fl = lint_of(rel);
        let a = every.len();
        every.extend(fl.decls.iter().cloned());
        sources.push((rel, a..every.len(), &fl.macros));
    }
    let mut defs: HashMap<String, usize> = HashMap::new();
    for (_, r, _) in &sources {
        for i in r.clone() {
            let d = &every[i];
            if d.definition() {
                let better = match defs.get(&d.name) {
                    None => true,
                    Some(&c) => every[c].kind == "ddef" && d.kind == "ddef" && d.init && !every[c].init,
                };
                if better {
                    defs.insert(d.name.clone(), i);
                }
            }
        }
    }
    let chosen: HashSet<usize> = defs.values().copied().collect();
    let spellings: Vec<String> = every.iter().map(|d| d.spelling()).collect();
    let compared: HashSet<usize> = (0..every.len())
        .filter(|&i| defs.get(&every[i].name).is_some_and(|&r| !chosen.contains(&i) && spellings[i] != spellings[r]))
        .collect();
    let need_def: HashSet<&str> = compared.iter().map(|&i| every[i].name.as_str()).collect();
    let mut sysinc: Vec<String> = vec![];
    for f in headers.iter().chain(srcs.iter()) {
        for n in pieces.get(f.as_str()).map(|p| p.sysinc()).unwrap_or(&[]) {
            if !sysinc.contains(n) {
                sysinc.push(n.clone());
            }
        }
    }
    if let Some(i) = sysinc.iter().position(|n| n == "winsock2.h") {
        let w = sysinc.remove(i);
        sysinc.insert(0, w);
    }
    if !sysinc.iter().any(|n| n == "windows.h") {
        let at = if sysinc.first().is_some_and(|n| n == "winsock2.h") { 1 } else { 0 };
        sysinc.insert(at, "windows.h".to_string());
    }
    let mut lines: Vec<String> = sysinc.iter().map(|n| format!("#if __has_include(<{n}>)\n#include <{n}>\n#endif")).collect();
    let tags: BTreeSet<String> = every.iter().flat_map(|d| TAG.find_iter(&d.stmt).map(|m| m.as_str().to_string()).collect::<Vec<_>>()).collect();
    lines.extend(tags.iter().map(|t| format!("{t};")));
    lines.extend(headers.iter().map(|h| format!("#include \"{}\"", h.rsplit('/').next().unwrap_or(h))));
    let mut copies: Vec<usize> = vec![];
    let mut copy_of: HashMap<usize, usize> = HashMap::new();
    let copy = |i: usize, lines: &mut Vec<String>, copies: &mut Vec<usize>, copy_of: &mut HashMap<usize, usize>| {
        copies.push(i);
        let k = copies.len();
        copy_of.insert(i, k);
        lines.push(format!("#line {k} \"{COPY}\""));
        lines.push(every[i].renamed(&format!("__dcp_{k}")));
    };
    for i in 0..nh {
        if compared.contains(&i) {
            copy(i, &mut lines, &mut copies, &mut copy_of);
        }
    }
    let mut knr_done: HashSet<&str> = HashSet::new();
    for definitions in [false, true] {
        for (rel, r, macros) in &sources {
            let mine: Vec<usize> = r.clone().filter(|&i| every[i].definition() == definitions).collect();
            if mine.is_empty() {
                continue;
            }
            let mut avail: HashMap<&str, (i64, &str)> = HashMap::new();
            for (name, line, text) in macros.iter() {
                avail.insert(name, (*line, text));
            }
            let mut used: HashMap<&str, (i64, &str)> = HashMap::new();
            let mut todo: Vec<&str> = mine.iter().flat_map(|&i| IDENTS.find_iter(&every[i].stmt).map(|m| m.as_str())).collect();
            while let Some(w) = todo.pop() {
                if let Some(&(line, text)) = avail.get(w) {
                    if !used.contains_key(w) {
                        used.insert(w, (line, text));
                        todo.extend(IDENTS.find_iter(&text["#define ".len().min(text.len())..]).map(|m| m.as_str()).filter(|x| !used.contains_key(x)));
                    }
                }
            }
            let mut used: Vec<(&str, (i64, &str))> = used.into_iter().collect();
            used.sort_by(|a, b| a.1 .0.cmp(&b.1 .0).then(a.0.cmp(b.0))); // by place: the text is the cache key
            for (name, (line, text)) in &used {
                lines.push(format!("#pragma push_macro(\"{name}\")"));
                lines.push(format!("#undef {name}"));
                lines.push(format!("#line {line} \"{rel}\""));
                lines.push(text.to_string());
            }
            for &i in &mine {
                let d = &every[i];
                if !(d.kind == "knr" && knr_done.contains(d.name.as_str())) {
                    if d.kind == "knr" {
                        knr_done.insert(&every[i].name);
                    }
                    lines.push(format!("#line {} \"{rel}\"", d.line));
                    lines.push(d.stmt.clone());
                }
                if compared.contains(&i) || (chosen.contains(&i) && need_def.contains(every[i].name.as_str())) {
                    copy(i, &mut lines, &mut copies, &mut copy_of);
                }
            }
            for (name, _) in used.iter().rev() {
                lines.push(format!("#undef {name}"));
                lines.push(format!("#pragma pop_macro(\"{name}\")"));
            }
        }
    }
    let mut checks = vec![];
    for i in 0..every.len() {
        if compared.contains(&i) {
            let r = defs[&every[i].name];
            checks.push((i, r));
            let k = checks.len();
            lines.push(format!("#line {k} \"{CHECK}\""));
            lines.push(format!("typedef char __dcp_c{k}[__builtin_types_compatible_p(__typeof__(&__dcp_{}), __typeof__(&__dcp_{})) ? 1 : -1];",
                               copy_of[&i], copy_of[&r]));
        }
    }
    let mut macros: HashMap<String, String> = HashMap::new();
    for h in &headers {
        for (name, line, _) in &lint_of(h).macros {
            macros.entry(name.clone()).or_insert_with(|| format!("{h}:{line}"));
        }
    }
    let mut text = lines.join("\n");
    text.push('\n');
    Ok(AllDecls { text, every, defs, copies, checks, macros })
}

// ------------------------------------------------------------------------------------------------ M5

use crate::clang::CDiag as Diag;

fn fmt_group(g: &[Diag]) -> String {
    let d = &g[0];
    let mut s = format!("{}:{}: {}", d.file, d.line, d.msg);
    if !d.flag.is_empty() {
        s += &format!(" [{}]", d.flag);
    }
    for n in &g[1..] {
        s += &format!(" / note {}:{}: {}", n.file, n.line, n.msg);
    }
    s
}

/// lint.Lines: the exemptions (`@original`, `@vc6`) of the files' lines.
struct Lines {
    root: std::path::PathBuf,
    memo: HashMap<String, FileLines>,
}

/// A file's text (newlines normalised as fsmemo.read_text) and its line starts.
struct FileLines {
    text: String,
    starts: Vec<usize>,
}

impl FileLines {
    fn read(p: &std::path::Path) -> FileLines {
        let text = match std::fs::read(p) {
            Ok(b) => String::from_utf8_lossy(&b).replace("\r\n", "\n").replace('\r', "\n"),
            Err(_) => String::new(),
        };
        let starts = if text.is_empty() && !p.is_file() { vec![] } else { std::iter::once(0).chain(memchr::memchr_iter(b'\n', text.as_bytes()).map(|i| i + 1)).collect() };
        FileLines { text, starts }
    }

    /// Line n (from 1), None past the file.
    fn line(&self, n: i64) -> Option<&str> {
        if n < 1 || n as usize > self.starts.len() {
            return None;
        }
        let s = self.starts[n as usize - 1];
        let e = self.starts.get(n as usize).map(|&e| e - 1).unwrap_or(self.text.len());
        Some(&self.text[s..e])
    }
}

impl Lines {
    fn file(&mut self, file: &str) -> &FileLines {
        if !self.memo.contains_key(file) {
            let p = self.root.join(file);
            let inside = !file.split(['/', '\\']).any(|c| c == "..") && !std::path::Path::new(file).is_absolute();
            let v = if inside && p.is_file() { FileLines::read(&p) } else { FileLines { text: String::new(), starts: vec![] } };
            self.memo.insert(file.to_string(), v);
        }
        &self.memo[file]
    }

    fn exempt(&mut self, file: &str, line: i64) -> bool {
        self.file(file).line(line).and_then(exemption).is_some()
    }

    fn exempt_decl(&mut self, d: &Decl) -> bool {
        (d.line..=d.last).any(|n| self.exempt(&d.file, n))
    }
}

fn locs(ws: &[String]) -> String {
    let mut s = ws.iter().take(8).cloned().collect::<Vec<_>>().join(", ");
    if ws.len() > 8 {
        s += &format!(" (+{})", ws.len() - 8);
    }
    s
}

fn locs_of(ds: &[&Decl]) -> String {
    locs(&ds.iter().map(|d| d.where_()).collect::<Vec<_>>())
}

fn by_spelling(ds: &[&Decl]) -> String {
    let mut groups: Vec<(String, Vec<&Decl>)> = vec![];
    for d in ds {
        let sp = d.spelling();
        match groups.iter_mut().find(|g| g.0 == sp) {
            Some(g) => g.1.push(d),
            None => groups.push((sp, vec![d])),
        }
    }
    groups.iter().map(|(sp, g)| format!("`{sp}` at {}", locs_of(g))).collect::<Vec<_>>().join("; ")
}

/// lint._cast_view: the cast macro that gives a unit its own view of a symbol.
fn cast_view(d: &Decl) -> Option<String> {
    let s = d.spelling();
    let k = name_at(&s, &d.name)?;
    if d.func() {
        let ret = py_strip(&s[..k]);
        let rest = py_strip(&s[k + d.name.len()..]);
        let (ret, inner) = match CC_END.captures(ret) {
            Some(c) => (&ret[..c.get(0).unwrap().start()], format!("({} *)", &c[1])),
            None => (ret, "(*)".to_string()),
        };
        return Some(format!("#define {}_X (({ret} {inner}{rest}){})", d.name, d.name));
    }
    if s[k..].contains(['[', '(']) {
        return None;
    }
    Some(format!("#define {}_X (*({} *)&{})", d.name, py_strip(&s[..k]), d.name))
}

/// lint.cross_conflicts: the M5 lines of one run of clang over the all-declarations unit (diags: its
/// diagnostics as JSON text; root: the project, for the exemptions).
pub fn lint_cross(ad: &AllDecls, diags: Vec<Diag>, root: &str) -> Result<Vec<String>> {
    let mut lines = Lines { root: std::path::PathBuf::from(root), memo: HashMap::new() };
    let mut groups: Vec<Vec<Diag>> = vec![];
    for d in diags {
        if d.kind == "note" && !groups.is_empty() {
            groups.last_mut().unwrap().push(d);
        } else {
            groups.push(vec![d]);
        }
    }
    let every = &ad.every;
    let (mut bad_copy, mut negative, mut bad_check) = (HashSet::new(), HashSet::new(), HashSet::new());
    let mut errlines: HashSet<(String, i64)> = HashSet::new();
    let mut header_errs: BTreeMap<String, Vec<Diag>> = BTreeMap::new();
    let mut cross: Vec<&Vec<Diag>> = vec![];
    for g in &groups {
        let d = &g[0];
        if d.kind != "error" {
            continue;
        }
        for x in g {
            if x.file == COPY {
                bad_copy.insert(x.line);
            }
        }
        if d.file == CHECK {
            if d.msg.contains("negative size") { negative.insert(d.line) } else { bad_check.insert(d.line) };
            continue;
        }
        if d.file == COPY {
            continue;
        }
        if CROSS.is_match(&d.msg) {
            cross.push(g);
            continue;
        }
        errlines.insert((d.file.clone(), d.line));
        if d.file.starts_with("include/") {
            header_errs.entry(d.file.clone()).or_default().push(d.clone());
        }
    }
    let copy_id: HashMap<usize, i64> = ad.copies.iter().enumerate().map(|(k, &i)| (i, k as i64 + 1)).collect();
    let mut out = vec![];
    // per symbol with a definition: every spelling compared with it
    #[derive(Default)]
    struct V {
        disagree: Vec<usize>,
        unknown: Vec<usize>,
        agree: Vec<usize>,
        undecided: bool,
    }
    let mut verdicts: BTreeMap<&str, V> = BTreeMap::new();
    for (k, &(d, r)) in ad.checks.iter().enumerate() {
        let k = k as i64 + 1;
        let v = verdicts.entry(every[d].name.as_str()).or_default();
        if bad_copy.contains(&copy_id[&r]) {
            v.undecided = true;
        }
        if bad_copy.contains(&copy_id[&d]) || bad_check.contains(&k) {
            v.unknown.push(d);
        } else if negative.contains(&k) {
            v.disagree.push(d);
        } else {
            v.agree.push(d);
        }
    }
    let mut decided: HashSet<&str> = HashSet::new();
    let mut by_name: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, d) in every.iter().enumerate() {
        by_name.entry(d.name.as_str()).or_default().push(i);
    }
    let ds = |is: &[usize]| is.iter().map(|&i| &every[i]).collect::<Vec<&Decl>>();
    for (name, v) in &verdicts {
        let r = ad.defs[*name];
        let rd = &every[r];
        if v.undecided {
            continue; // its definition uses a type of its unit: clang's pairs decide below
        }
        decided.insert(name);
        let rs = rd.spelling();
        let mut agree: Vec<usize> = by_name[name].iter().copied().filter(|&i| i != r && every[i].spelling() == rs).collect();
        agree.extend(&v.agree);
        let exempt: Vec<usize> = v.disagree.iter().copied().filter(|&i| every[i].file.starts_with("src/") && lines.exempt_decl(&every[i])).collect();
        let dis: Vec<usize> = v.disagree.iter().copied().filter(|&i| !exempt.iter().any(|&e| every[e] == every[i])).collect();
        if dis.is_empty() {
            continue;
        }
        let unit = if rd.file.starts_with("src/") {
            std::path::Path::new(&rd.file).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()
        } else {
            "?".to_string()
        };
        let mut s = format!("{}: {name} declared unlike its definition {} (unit {unit}) `{rs}`", every[dis[0]].where_(), rd.where_());
        if !rd.proto.is_empty() {
            s += &format!(" (as a prototype `{}`)", &rd.proto[..rd.proto.len() - 1]);
        }
        s += &format!(": disagree={} {}; agree={}", dis.len(), by_spelling(&ds(&dis)), agree.len());
        if !agree.is_empty() {
            s += &format!(" {}", locs_of(&ds(&agree)));
        }
        if !v.unknown.is_empty() {
            s += &format!("; unknown={} {} (a type of its unit)", v.unknown.len(), locs_of(&ds(&v.unknown)));
        }
        if !exempt.is_empty() {
            s += &format!("; exempt={} {}", exempt.len(), locs_of(&ds(&exempt)));
        }
        let broken: Vec<usize> = dis.iter().copied().filter(|&i| (every[i].line..=every[i].last).any(|n| errlines.contains(&(every[i].file.clone(), n)))).collect();
        if !broken.is_empty() {
            s += &format!(" / {} has an error of its own here: its verdict may be clang's recovery", locs_of(&ds(&broken)));
        }
        let marked: Vec<usize> = dis.iter().copied().filter(|&i| every[i].file.starts_with("include/") && lines.exempt_decl(&every[i])).collect();
        if let Some(&m) = marked.first() {
            let view = cast_view(&every[m]);
            let sp = if rd.proto.is_empty() { format!("{rs};") } else { rd.proto.clone() };
            s += &format!(" / the @original spelling is in a header ({}): a header repeats the definition's spelling `{sp}` (unit {unit}); a unit's own view goes in its head region as a cast macro",
                          every[m].where_());
            if let Some(view) = view {
                s += &format!(": `{view} /* @original why */`");
            }
        }
        out.push(s);
    }
    // clang's pairs: symbols without a definition (or one with a type of its unit), tags and typedefs
    let mut at2: HashMap<(&str, i64), usize> = HashMap::new();
    let mut at3: HashMap<(&str, i64, &str), usize> = HashMap::new();
    for (i, d) in every.iter().enumerate() {
        at2.entry((d.file.as_str(), d.line)).or_insert(i);
        at3.entry((d.file.as_str(), d.line, d.name.as_str())).or_insert(i);
    }
    let mut rd_lines: HashMap<String, FileLines> = HashMap::new();
    let mut spelling = |x: &Diag, name: Option<&str>| -> Option<String> {
        let hit = name.and_then(|n| at3.get(&(x.file.as_str(), x.line, n))).or_else(|| at2.get(&(x.file.as_str(), x.line)));
        if let Some(&i) = hit {
            return Some(every[i].spelling());
        }
        let ls = rd_lines.entry(x.file.clone()).or_insert_with(|| FileLines::read(&std::path::Path::new(root).join(&x.file)));
        if let Some(l) = ls.line(x.line) {
            let f = py_words(l);
            let f = py_strip(f.split("/*").next().unwrap_or(""));
            return Some(f.strip_prefix("extern ").unwrap_or(f).trim_end_matches(';').to_string());
        }
        None
    };
    let mut pairs: BTreeMap<String, Vec<(&Vec<Diag>, Option<String>)>> = BTreeMap::new();
    for g in &cross {
        let d = &g[0];
        let name = if CROSS.captures(&d.msg).is_some_and(|c| c.get(2).is_some()) { d.name.clone() } else { None };
        if name.as_deref().is_some_and(|n| decided.contains(n)) {
            continue;
        }
        if g.iter().any(|x| errlines.contains(&(x.file.clone(), x.line))) {
            continue; // one side does not compile: clang's recovery, not a disagreement
        }
        if g.len() > 1 {
            let a = spelling(d, name.as_deref());
            if a.is_some() && a == spelling(&g[1], name.as_deref()) && !a.as_deref().unwrap_or("{").contains('{') {
                continue; // textually one declaration: a recovery artefact
            }
        }
        let in_headers = g.iter().all(|x| x.file.starts_with("include/"));
        let mut hint = None;
        if g.iter().any(|x| lines.exempt(&x.file, x.line)) {
            if !in_headers {
                continue;
            }
            let r = name.as_deref().and_then(|n| ad.defs.get(n)).map(|&r| &every[r]);
            let mut h = " / the @original spelling is in a header: two headers that cannot be included together; ".to_string();
            if let Some(r) = r {
                let sp = if r.proto.is_empty() { format!("{};", r.spelling()) } else { r.proto.clone() };
                h += &format!("a header repeats the definition's spelling `{sp}` (unit {}), ", r.file.split('/').nth(1).unwrap_or(""));
            }
            h += "a unit's own view goes in its head region as a cast macro (`#define name_X ((T (*)(..))name) /* @original why */`)";
            hint = Some(h);
        }
        pairs.entry(name.unwrap_or_else(|| "?".to_string())).or_default().push((g, hint));
    }
    for (name, ps) in &pairs {
        let xs: Vec<Option<usize>> = ps.iter().map(|(g, _)| at3.get(&(g[0].file.as_str(), g[0].line, name.as_str())).copied()).collect();
        let first = if ps[0].0.len() > 1 { at3.get(&(ps[0].0[1].file.as_str(), ps[0].0[1].line, name.as_str())).copied() } else { None };
        let mut hints: Vec<&str> = vec![];
        for (_, h) in ps {
            if let Some(h) = h {
                if !hints.contains(&h.as_str()) {
                    hints.push(h);
                }
            }
        }
        let hints = hints.concat();
        if by_name.contains_key(name.as_str()) && first.is_some() && xs.iter().all(|x| x.is_some()) {
            let mut dis: Vec<usize> = vec![];
            for x in xs.into_iter().flatten() {
                if !dis.iter().any(|&d| every[d] == every[x]) {
                    dis.push(x);
                }
            }
            let first = first.unwrap();
            let r = ad.defs.get(name.as_str()).copied();
            let agree: Vec<usize> = by_name[name.as_str()].iter().copied()
                .filter(|&i| !dis.iter().any(|&d| every[d] == every[i]) && i != first && Some(i) != r).collect();
            let mut s = format!("{}: {name} declared differently", every[dis[0]].where_());
            match r {
                Some(r) => s += &format!(" (its definition {} `{}` uses a type of its unit: not compared)", every[r].where_(), every[r].spelling()),
                None => s += ", no definition in src/",
            }
            s += &format!(": against its first declaration {} `{}`: disagree={} {}; agree={}", every[first].where_(), every[first].spelling(),
                          dis.len(), by_spelling(&ds(&dis)), agree.len());
            if !agree.is_empty() {
                s += &format!(" {}", locs_of(&ds(&agree)));
            }
            s += &format!(" (clang: {}){hints}", ps[0].0[0].msg);
            out.push(s);
        } else if ps.len() == 1 {
            out.push(fmt_group(ps[0].0) + &hints);
        } else {
            out.push(format!("{}:{}: {name}: {} conflicts: {}{hints}", ps[0].0[0].file, ps[0].0[0].line, ps.len(),
                             ps.iter().map(|(g, _)| fmt_group(g)).collect::<Vec<_>>().join(" | ")));
        }
    }
    for (h, es) in &header_errs {
        let mut e = es[0].clone();
        let text = spelling(&e, None).unwrap_or_default();
        let mut clash: Vec<String> = vec![];
        let mut seen: HashSet<&str> = HashSet::new();
        for w in IDENTS.find_iter(&text).map(|m| m.as_str()) {
            if !seen.insert(w) {
                continue;
            }
            if let Some(at) = ad.macros.get(w) {
                if !at.starts_with(&format!("{h}:")) {
                    clash.push(format!("{w} is a macro of {at}"));
                }
            }
        }
        if !clash.is_empty() {
            e.msg = format!("{} ({})", e.msg, clash.iter().take(3).cloned().collect::<Vec<_>>().join("; "));
        }
        let advice = if !clash.is_empty() {
            "a macro of another header rewrites its text: the two headers cannot be included together; keep one spelling of the name (the macro or the declaration)"
        } else {
            "it is included after the system headers the sources include and the headers that define the names it uses: include or declare what it uses"
        };
        out.push(format!("{}:{}: {h} does not compile in the all-declarations unit ({} errors, first: {}): its declarations are not compared and their conflicts hidden; {advice}",
                         e.file, e.line, es.len(), e.msg));
    }
    Ok(out)
}

// ------------------------------------------------------------------------------------------------ M6, M7

/// The M6 lines (a unit's errors) and M7 calls (file, line, `callee() at line N` / `callee (undeclared) at
/// line N`) of the units' diagnostics (each unit's list as JSON text), a group with an exempt line left out
/// (lint.lint's loop; lint.call_of).
pub fn lint_units(diags: Vec<Vec<Diag>>, root: &str) -> Result<(Vec<String>, Vec<(String, i64, String)>)> {
    let mut lines = Lines { root: std::path::PathBuf::from(root), memo: HashMap::new() };
    let (mut errors, mut calls) = (vec![], vec![]);
    for ds in diags {
        let mut groups: Vec<Vec<Diag>> = vec![];
        for d in ds {
            if d.kind == "note" && !groups.is_empty() {
                groups.last_mut().unwrap().push(d);
            } else {
                groups.push(vec![d]);
            }
        }
        for g in &groups {
            if g.iter().any(|x| lines.exempt(&x.file, x.line)) {
                continue;
            }
            let d = &g[0];
            if d.kind == "error" {
                errors.push(fmt_group(g));
            } else if d.kind == "warning" {
                let callee = d.name.as_deref().filter(|n| !n.is_empty()).unwrap_or("?");
                if d.flag == "-Wdeprecated-non-prototype" && d.msg.starts_with("passing arguments") {
                    calls.push((d.file.clone(), d.line, format!("{callee}() at line {}", d.line)));
                } else if d.flag == "-Wimplicit-function-declaration" {
                    calls.push((d.file.clone(), d.line, format!("{callee} (undeclared) at line {}", d.line)));
                }
            }
        }
    }
    Ok((errors, calls))
}
