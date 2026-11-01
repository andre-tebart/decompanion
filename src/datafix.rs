//! The data tooling (`dcp data map`, `dcp data fix`): a reading view of a unit's data and the rewrites that answer
//! the data checks (every rewrite answers one conflict and is verified by a build).
//!
//! The model (data_model): every data declaration of the sources with an address (the scan's) joined with the facts
//! of its address: the `global` symbol M.data.site / .content / .draft placed (level, extent, section kind, size)
//! and the next start of any symbol after it (the room it has); the conflicts D1 / D4 / D5 at it.
//!
//! The fixes, each the answer the check itself names:
//!   D5  a tentative definition `T x;` in the original's uninitialised data gets `= 0` (a pointer or a basic type)
//!       or `= {0}` (anything else: an array, a struct, a typedef the scan cannot see through; C allows braces
//!       around a scalar initialiser too), so VC6 places it in its unit's .bss in declaration order instead of
//!       LINK's common area.
//!   D1  an array whose extent overlaps the next symbol: its first dimension shrinks to the room up to that symbol,
//!       when the room is a whole number of elements; `extern` declarations of the same name with the old
//!       dimension follow.
//!   D4  the definitions of one unit and section kind not in address order (VC6 places them in definition order):
//!       the longest run already in address order stays, every other definition moves in front of the definition
//!       that follows it in address order (or behind the last one before it), with its own-line comment and
//!       trailing comment (also one that runs on over the following lines); a non-static definition that moves
//!       below its old place leaves `extern T x;` there for the uses in between; a definition that would move above
//!       a type, macro or declaration it uses (defined in between) is left for a human (the move would not compile;
//!       move that one first). A statement with several declarators is left for a human.
//! A fix that the scan cannot apply exactly (no such statement, no array, a room that is no whole number of
//! elements, several declarators) is listed as `manual` with the reason.
//!
//! `--write` trial-compiles each unit's edits first (Trial): the unit's edited text into build/trial/, one compiler
//! run into build/obj/trial/, every function of the unit compared as M.match compares it. A unit's edits are
//! accepted together when the unit compiles and keeps every byte match; else each group is tried alone and the
//! groups that pass on their own are tried together, then added one at a time while the unit stays whole.
//! Positions are in characters, as Python's str offsets were.

use crate::error::{Error, Result};
use crate::cliread::{record, Tok};
use crate::clang::{Decl, FileModel};
use crate::project::{py_path, Project};
use crate::readability::Source;
use crate::srcscan::{py_space, py_strip};
use crate::store::{self, SFact};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};

const BASIC: &[&str] = &["char", "short", "int", "long", "float", "double", "unsigned", "signed", "void", "__int8", "__int16", "__int32",
                         "__int64", "BYTE", "WORD", "DWORD", "BOOL", "UINT", "ULONG", "LONG", "HANDLE", "HWND"];
const SKIP: &[&str] = &["static", "const", "volatile", "extern", "register"];
pub const CHECKS: [&str; 3] = ["D5", "D1", "D4"];
const C_WORDS: &[&str] = &["auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum", "extern",
                           "float", "for", "goto", "if", "int", "long", "register", "return", "short", "signed", "sizeof", "static",
                           "struct", "switch", "typedef", "union", "unsigned", "void", "volatile", "while", "__int8", "__int16",
                           "__int32", "__int64", "__cdecl", "__stdcall", "__fastcall", "__declspec"];
const LEVEL: [&str; 4] = ["open", "declared", "derived", "proven"];

static IDENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z_]\w*").unwrap());

fn err(e: impl std::fmt::Display) -> Error {
    Error::runtime(e.to_string())
}

fn s(x: impl Into<String>) -> Tok {
    Tok::S(x.into())
}

fn chars(v: &[char]) -> String {
    v.iter().collect()
}

/// The char index of a byte offset of s.
fn char_index(s: &str, byte: usize) -> usize {
    s[..byte].chars().count()
}

// ------------------------------------------------------------------------------------------------ the model

#[derive(Clone)]
pub struct DataDef {
    pub unit: String,
    pub name: String,
    pub file: String,
    pub line: i64,
    pub kind: String, // def | extern
    pub addr: i64,
    pub statik: bool,
    pub level: String,   // proven / declared, from the `global` symbol at addr
    pub extent: String,  // site / content / draft
    pub section: String, // data / rdata / bss / common, the object's section kind
    pub size: Option<i64>,
    pub next_start: Option<i64>,
    pub conflicts: Vec<(String, String)>, // (check, message) of the errors at it
    pub warnings: Vec<(String, String)>,  // (check, message) of the warnings at it
}

fn vstr(f: &SFact, k: &str) -> String {
    match f.value.get(k) {
        None | Some(serde_json::Value::Null) => "-".into(),
        Some(serde_json::Value::String(x)) => x.clone(),
        Some(v) => v.to_string(),
    }
}

/// Every data declaration of the current target with an address, joined with its facts (module docs).
pub fn data_model(p: &Project, scan: &crate::frontend::Scan) -> Result<Vec<DataDef>> {
    let db = p.store_path();
    let default = p.targets[0].name.clone();
    let mut out = vec![];
    for part in &scan.parts {
        for (file, line, unit, name, kind, addrs, _, statik) in &part.data {
            let a = addrs.iter().find(|(t, _)| t.as_deref().unwrap_or(&default) == p.target_name).map(|x| x.1 as i64);
            if let Some(a) = a {
                out.push(DataDef { unit: unit.clone(), name: name.clone(), file: file.clone(), line: *line, kind: kind.clone(), addr: a,
                                   statik: *statik, level: "-".into(), extent: "-".into(), section: "-".into(), size: None,
                                   next_start: None, conflicts: vec![], warnings: vec![] });
            }
        }
    }
    let img = crate::image(&p.target(None).map_err(err)?.path)?;
    let code: Vec<(i64, i64)> = img.sections.iter().filter(|s| s.holds_code()).map(|s| (s.va as i64, s.end() as i64)).collect();
    let syms = crate::with_db(&db, |c| store::facts_of(c, &db, "symbol", None, |_| true))?;
    let mut glob: HashMap<i64, Rc<SFact>> = HashMap::new();
    let mut starts: BTreeSet<i64> = BTreeSet::new();
    for f in syms.iter() {
        let sk = f.s("skind");
        if sk == Some("unknown.data") || code.iter().any(|&(lo, hi)| lo <= f.lo && f.lo < hi) {
            continue;
        }
        starts.insert(f.lo);
        if sk == Some("global") {
            glob.entry(f.lo).or_insert_with(|| f.clone());
        }
    }
    let mut by_addr: HashMap<i64, Vec<(String, String, String, String)>> = HashMap::new();
    for (sev, check, lo, _, msg, a, _) in crate::pystore::st_conflicts(&db, None, None)? {
        if CHECKS.contains(&check.as_str()) || check == "M.data.content" {
            by_addr.entry(lo).or_default().push((sev, check, msg, a));
        }
    }
    for d in &mut out {
        if let Some(g) = glob.get(&d.addr).filter(|_| d.kind == "def") {
            d.level = LEVEL[g.level as usize].into();
            d.extent = vstr(g, "extent");
            d.section = vstr(g, "kind");
            d.size = (g.s("extent") != Some("draft") || g.hi - g.lo > 1).then_some(g.hi - g.lo);
        }
        d.next_start = starts.range(d.addr + 1..).next().copied();
        for (sev, check, msg, a) in by_addr.get(&d.addr).into_iter().flatten() {
            if *a == format!("src:{}:{}", d.file, d.line) || check == "D4" {
                let x = (check.clone(), msg.clone());
                if sev == "error" || sev == "bug" { d.conflicts.push(x) } else { d.warnings.push(x) }
            }
        }
    }
    Ok(out)
}

// ------------------------------------------------------------------------------------------------ statements

/// The texts of the files a run reads, each lexed once: a run touches many definitions of few files.
pub struct Files {
    root: String,
    scan: Option<Rc<crate::frontend::Scan>>, // None: no models (every file read from its text alone)
    texts: HashMap<String, (Source, bool)>, // the lexed text, whether the file is UTF-8 (else cp1252)
}

impl Files {
    pub fn new(root: &str, scan: Option<Rc<crate::frontend::Scan>>) -> Files {
        Files { root: root.into(), scan, texts: HashMap::new() }
    }

    fn path(&self, rel: &str) -> String {
        py_path(&format!("{}/{rel}", self.root))
    }

    fn src(&mut self, rel: &str) -> &Source {
        if !self.texts.contains_key(rel) {
            let b = std::fs::read(self.path(rel)).unwrap_or_default();
            let (t, utf8) = match String::from_utf8(b.clone()) {
                Ok(t) => (t.replace("\r\n", "\n").replace('\r', "\n"), true),
                Err(_) => (crate::vc6::cp1252(&b), false),
            };
            self.texts.insert(rel.into(), (Source::new(&t), utf8));
        }
        &self.texts[rel].0
    }

    pub fn text(&mut self, rel: &str) -> &[char] {
        &self.src(rel).text
    }

    /// The front end's model of the file (the scan's) when the text is the file as the scan read it, else None.
    fn model(&mut self, rel: &str) -> Option<Arc<FileModel>> {
        let ours = chars(self.text(rel));
        let disk = crate::fsmemo::read_text(&self.path(rel)).ok()?;
        let scan = self.scan.as_ref()?;
        (disk == ours).then(|| scan.models.get(rel).cloned().unwrap_or_default())
    }

    /// The file's bytes for a new text, in the file's own encoding.
    fn encode(&self, rel: &str, text: &[char]) -> Vec<u8> {
        if self.texts.get(rel).is_none_or(|x| x.1) {
            return chars(text).into_bytes();
        }
        const HIGH: [u32; 32] = [0x20AC, 0xFFFD, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0xFFFD,
                                 0x017D, 0xFFFD, 0xFFFD, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A,
                                 0x0153, 0xFFFD, 0x017E, 0x0178];
        text.iter().map(|&c| {
            let u = c as u32;
            if u < 0x80 || (0xA0..0x100).contains(&u) {
                u as u8
            } else {
                HIGH.iter().position(|&h| h == u && h != 0xFFFD).map(|i| 0x80 + i as u8).unwrap_or(b'?')
            }
        }).collect()
    }
}

/// The offset before the white space that ends at off.
fn end_before(text: &[char], mut off: usize) -> usize {
    while off > 0 && py_space(text[off - 1]) {
        off -= 1;
    }
    off
}

fn find(text: &[char], c: char, from: usize) -> Option<usize> {
    text.get(from..)?.iter().position(|&x| x == c).map(|i| i + from)
}

fn rfind(text: &[char], c: char, to: usize) -> Option<usize> {
    text[..to.min(text.len())].iter().rposition(|&x| x == c)
}

#[derive(Clone, Copy)]
pub struct Stmt {
    start: usize, // the block: own-line comment above, the statement, its trailing comment, newline
    end: usize,
    s0: usize, // the statement itself
    s1: usize, // just past its `;`
}

/// The declaration statement starting on `line` of `rel` (1-based), with its block (module docs).
fn statement_at(files: &mut Files, rel: &str, line: i64) -> Option<Stmt> {
    let src = files.src(rel);
    let (text, code) = (&src.text, &src.code);
    let starts = &src.line_starts;
    if line < 1 || line as usize > starts.len() {
        return None;
    }
    let mut s0 = starts[line as usize - 1];
    while s0 < code.len() && matches!(code[s0], ' ' | '\t') {
        s0 += 1;
    }
    let (mut depth, mut i) = (0i64, s0);
    while i < code.len() {
        match code[i] {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ';' if depth == 0 => break,
            _ => {}
        }
        i += 1;
    }
    if i >= code.len() {
        return None;
    }
    let s1 = i + 1;
    let eol = find(text, '\n', s1).unwrap_or(text.len());
    let mut after = s1;
    for (cs, ce, _) in &src.comments {
        // a trailing comment may run on over the following lines
        if s1 <= *cs && *cs < eol {
            after = after.max(*ce);
        }
    }
    let mut end = find(text, '\n', after).map(|e| e + 1).unwrap_or(text.len());
    if !py_strip(&chars(&code[after.min(end)..end])).is_empty() {
        end = s1; // code after the `;` on its line: the block ends at the `;`
    }
    let mut start = starts[line as usize - 1];
    let k = end_before(text, start);
    let own = src.comments.iter().enumerate().filter(|(_, (cs, _, _))| {
        let bol = rfind(text, '\n', *cs).map(|x| x + 1).unwrap_or(0);
        py_strip(&chars(&text[bol..*cs])).is_empty()
    }).filter(|(_, (_, ce, _))| *ce == k).map(|(i, _)| i).last();
    if let Some(ci) = own {
        if text[k..start].iter().filter(|&&c| c == '\n').count() <= 1 {
            start = rfind(text, '\n', src.comments[ci].0).map(|x| x + 1).unwrap_or(0);
        }
    }
    Some(Stmt { start, end, s0, s1 })
}

struct Declarator {
    name_end: usize,
    dims: Vec<String>,
    before: String, // the statement's text before the name (the type)
    has_init: bool,
    count: usize, // declarators in the statement
    end: usize,   // the end of the whole declarator (before a `,` `;` or `=` at the statement's top level)
    aggregate: Option<bool>,
}

/// The declarator of `name` in a statement: the name where the front end's model has it (its type's class too),
/// else its first whole-word occurrence; its dimensions and its end read from the text.
fn declarator(files: &mut Files, rel: &str, st: &Stmt, name: &str) -> Option<Declarator> {
    let m = files.model(rel);
    let src = files.src(rel);
    let seg: Vec<char> = src.code[st.s0..st.s1].to_vec();
    let group: Vec<(&String, (i64, i64), Option<bool>)> = m.as_ref().map(|m| {
        m.decls.iter().filter_map(|d| match d {
            Decl::V(n, _, start, npos, _, _, _, agg) => {
                let o = src.offset(start.0, start.1);
                (st.s0 <= o && o < st.s1).then_some((n, *npos, *agg))
            }
            _ => None,
        }).collect()
    }).unwrap_or_default();
    let (start, aggregate, count) = match group.iter().find(|d| d.0 == name) {
        Some(hit) => (src.offset(hit.1 .0, hit.1 .1) as i64 - st.s0 as i64, hit.2, Some(group.len())),
        None => {
            let segs = chars(&seg);
            let re = Regex::new(&format!(r"\b{}\b", regex::escape(name))).ok()?;
            let mm = re.find(&segs)?;
            (char_index(&segs, mm.start()) as i64, None, None)
        }
    };
    let start = start.max(0) as usize;
    let name_end = start + name.chars().count();
    let (mut k, mut dims) = (name_end as i64, vec![]);
    loop {
        let mut j = k.max(0) as usize;
        while j < seg.len() && matches!(seg[j], ' ' | '\t' | '\n') {
            j += 1;
        }
        if j < seg.len() && seg[j] == '[' {
            match find(&seg, ']', j) {
                Some(e) => {
                    dims.push(py_strip(&chars(&seg[j + 1..e])).to_string());
                    k = e as i64 + 1;
                }
                None => {
                    dims.push(py_strip(&chars(&seg[j + 1..seg.len().saturating_sub(1).max(j + 1)])).to_string());
                    k = 0;
                }
            }
            continue;
        }
        break;
    }
    let k = k.max(0) as usize;
    let (mut depth, mut commas, mut end, mut init) = (0i64, 0usize, None, false);
    for (j, &c) in seg.iter().enumerate() {
        if matches!(c, ',' | ';' | '=') && depth == 0 && j >= k && end.is_none() {
            end = Some(j);
            init = c == '=';
        }
        if matches!(c, '(' | '[' | '{') {
            depth += 1;
        }
        if matches!(c, ')' | ']' | '}') {
            depth -= 1;
        }
        if c == ',' && depth == 0 {
            commas += 1;
        }
    }
    let mut end = end.unwrap_or(seg.len().saturating_sub(1));
    while end > k && matches!(seg[end - 1], ' ' | '\t' | '\n') {
        end -= 1;
    }
    let count = count.filter(|&c| c > 0).unwrap_or(commas + 1);
    Some(Declarator { name_end: st.s0 + name_end, dims, before: chars(&seg[..start.min(seg.len())]), has_init: init, count, end: st.s0 + end,
                      aggregate })
}

// ------------------------------------------------------------------------------------------------ the edits

#[derive(Clone)]
pub struct Edit {
    pub file: String,
    pub at: usize,     // offset in the original text
    pub remove: usize, // characters removed at `at`
    pub insert: String,
    pub why: String, // one line: the check and the symbol
    pub unit: String,
    pub group: String, // the edits that stand or fall together (a D4 move: its removal and insertion)
}

type Edits = (Vec<Edit>, Vec<String>);

fn d5_edits(files: &mut Files, model: &[DataDef]) -> Edits {
    let (mut edits, mut manual) = (vec![], vec![]);
    for d in model {
        if !d.conflicts.iter().any(|c| c.0 == "D5") {
            continue;
        }
        let dc = statement_at(files, &d.file, d.line).and_then(|st| declarator(files, &d.file, &st, &d.name));
        let Some(dc) = dc else {
            manual.push(format!("D5 {} {}:{}: the statement is not found", d.name, d.file, d.line));
            continue;
        };
        if dc.has_init {
            manual.push(format!("D5 {} {}:{}: it has an initialiser already", d.name, d.file, d.line));
            continue;
        }
        let words: HashSet<&str> = IDENT.find_iter(&dc.before).map(|m| m.as_str()).filter(|w| !SKIP.contains(w)).collect();
        let scalar = match dc.aggregate {
            Some(a) => !a,
            None => dc.dims.is_empty() && (dc.before.contains('*') || dc.before.contains('(') || (!words.is_empty() && words.iter().all(|w| BASIC.contains(w)))),
        };
        let init = if scalar { " = 0" } else { " = {0}" };
        edits.push(Edit { file: d.file.clone(), at: dc.end, remove: 0, insert: init.into(), why: format!("D5 {}{} ({:#x})", d.name, init.trim(), d.addr),
                          unit: d.unit.clone(), group: format!("D5 {}", d.name) });
    }
    (edits, manual)
}

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_numeric() && c.to_digit(10).is_some())
}

fn d1_edits(files: &mut Files, model: &[DataDef]) -> Edits {
    let (mut edits, mut manual) = (vec![], vec![]);
    let mut externs: HashMap<&str, Vec<&DataDef>> = HashMap::new();
    for d in model.iter().filter(|d| d.kind == "extern") {
        externs.entry(&d.name).or_default().push(d);
    }
    for d in model {
        if d.kind != "def" || !d.conflicts.iter().any(|c| c.0 == "D1") {
            continue;
        }
        let (Some(size), Some(next)) = (d.size, d.next_start) else {
            manual.push(format!("D1 {} {}:{}: no size or next symbol known", d.name, d.file, d.line));
            continue;
        };
        let room = next - d.addr;
        let dc = statement_at(files, &d.file, d.line).and_then(|st| declarator(files, &d.file, &st, &d.name));
        let Some(dc) = dc else {
            manual.push(format!("D1 {} {}:{}: the statement is not found", d.name, d.file, d.line));
            continue;
        };
        if dc.dims.is_empty() || !is_digits(&dc.dims[0]) {
            manual.push(format!("D1 {} {}:{}: {size} bytes, room {room}: no array with a literal first dimension to shrink", d.name, d.file, d.line));
            continue;
        }
        let old: i64 = dc.dims[0].parse().unwrap_or(0);
        let elem = if old != 0 { size.div_euclid(old) } else { 0 };
        if elem == 0 || size.rem_euclid(old) != 0 || room.rem_euclid(elem) != 0 || room.div_euclid(elem) < 1 {
            manual.push(format!("D1 {} {}:{}: {size} bytes in {old} elements, room {room} is no whole number of elements", d.name, d.file, d.line));
            continue;
        }
        let new = room / elem;
        if new >= old {
            manual.push(format!("D1 {} {}:{}: room {room} holds {new} elements, not fewer than {old}", d.name, d.file, d.line));
            continue;
        }
        let dim_edit = |files: &mut Files, rel: &str, name_end: usize| -> Option<(usize, usize)> {
            let code = &files.src(rel).code;
            let b = find(code, '[', name_end)?;
            Some((b + 1, find(code, ']', b)? - b - 1))
        };
        if let Some((at, remove)) = dim_edit(files, &d.file, dc.name_end) {
            edits.push(Edit { file: d.file.clone(), at, remove, insert: new.to_string(),
                              why: format!("D1 {}[{old}] -> [{new}] ({:#x}, room {room})", d.name, d.addr), unit: d.unit.clone(), group: format!("D1 {}", d.name) });
        }
        for x in externs.get(d.name.as_str()).into_iter().flatten() {
            let xd = statement_at(files, &x.file, x.line).and_then(|st| declarator(files, &x.file, &st, &d.name));
            if let Some(xd) = xd.filter(|xd| xd.dims.first() == Some(&old.to_string())) {
                if let Some((at, remove)) = dim_edit(files, &x.file, xd.name_end) {
                    edits.push(Edit { file: x.file.clone(), at, remove, insert: new.to_string(),
                                      why: format!("D1 {} extern [{old}] -> [{new}] ({}:{})", d.name, x.file, x.line), unit: d.unit.clone(),
                                      group: format!("D1 {}", d.name) });
                }
            }
        }
    }
    (edits, manual)
}

/// Indices of one longest strictly increasing subsequence of seq (patience sorting, n log n).
pub fn lis(seq: &[i64]) -> HashSet<usize> {
    let (mut tails, mut tail_idx): (Vec<i64>, Vec<usize>) = (vec![], vec![]);
    let mut prev: Vec<Option<usize>> = vec![None; seq.len()];
    for (i, &v) in seq.iter().enumerate() {
        let k = tails.partition_point(|&t| t < v);
        if k == tails.len() {
            tails.push(v);
            tail_idx.push(i);
        } else {
            tails[k] = v;
            tail_idx[k] = i;
        }
        prev[i] = if k > 0 { Some(tail_idx[k - 1]) } else { None };
    }
    let mut out = HashSet::new();
    let mut i = tail_idx.last().copied();
    while let Some(x) = i {
        out.insert(x);
        i = prev[x];
    }
    out
}

/// The first of `idents` that the (comment-blanked) code defines or declares: a macro, a typedef name, a struct /
/// union / enum tag, an enum constant, a variable or function declaration. None when none is.
fn defined_in(code: &str, idents: &BTreeSet<String>) -> Option<String> {
    for x in idents {
        let e = regex::escape(x);
        let pats = [format!(r"#\s*define\s+{e}\b"),
                    format!(r"\btypedef\b[^;]*?\b{e}\s*(?:\[[^\]]*\]\s*)*;"), format!(r"\btypedef\b[^;]*\(\s*\*\s*{e}\s*\)"),
                    format!(r"\b(?:struct|union|enum)\s+{e}\s*\{{"), format!(r"\}}\s*{e}\s*[;,]"),
                    format!(r"[{{,]\s*{e}\s*(?:=[^,}}]*)?[,}}]"),
                    format!(r"\b[A-Za-z_][\w \t\*]*\b{e}\s*(?:\[[^\]]*\]\s*)*(?:=|;|,|\()")];
        if pats.iter().any(|p| Regex::new(p).is_ok_and(|r| r.is_match(code))) {
            return Some(x.clone());
        }
    }
    None
}

/// The comment-blanked code of the unit from position a (file, offset) up to position b, in the order of the
/// unit's files (a before b).
fn between(files: &mut Files, order: &[String], a: (&str, usize), b: (&str, usize)) -> String {
    let rank = |f: &str| order.iter().position(|x| x == f).unwrap_or(0);
    let ((fa, oa), (fb, ob)) = (a, b);
    if fa == fb {
        let c = &files.src(fa).code;
        return chars(&c[oa.min(ob).min(c.len())..ob.min(c.len())]);
    }
    let mut parts = vec![chars(&files.src(fa).code[oa..])];
    for f in &order[rank(fa) + 1..rank(fb)] {
        parts.push(chars(&files.src(f).code));
    }
    parts.push(chars(&files.src(fb).code[..ob]));
    parts.join("\n")
}

/// The first of `idents` (by name) the unit defines or declares from position a (file, offset) up to position b, in
/// the unit's order: a macro, typedef, tag, enum constant or declaration of the files' models starting on a line in
/// between; the text (defined_in over `between`) when a file has no model.
fn defined_between(files: &mut Files, order: &[String], a: (&str, usize), b: (&str, usize), idents: &BTreeSet<String>) -> Option<String> {
    let rank = |f: &str| order.iter().position(|x| x == f).unwrap_or(0);
    let ((fa, oa), (fb, ob)) = (a, b);
    let seq: Vec<String> = if fa == fb {
        vec![fa.to_string()]
    } else {
        std::iter::once(fa.to_string()).chain(order[rank(fa) + 1..rank(fb)].iter().cloned()).chain(std::iter::once(fb.to_string())).collect()
    };
    let mut found: BTreeSet<String> = BTreeSet::new();
    for f in &seq {
        let Some(m) = files.model(f) else {
            let code = between(files, order, a, b);
            return defined_in(&code, idents);
        };
        let src = files.src(f);
        let lo = if f == fa { src.line_of(oa) as i64 } else { 1 };
        let hi = if f == fb { src.line_of(ob) as i64 } else { i64::MAX };
        let names = m.types.iter().map(|(l, n)| (*l, n))
            .chain(m.macros.iter().map(|(l, n, _)| (*l, n)))
            .chain(m.decls.iter().map(|d| match d {
                Decl::F(n, _, st, ..) | Decl::V(n, _, st, ..) => (st.0, n),
            }));
        found.extend(names.filter(|(l, n)| lo <= *l && *l < hi && idents.contains(*n)).map(|(_, n)| n.clone()));
    }
    found.into_iter().next()
}

/// unit_order: unit -> its files in TU order (one: src/<unit>.c).
fn d4_edits(files: &mut Files, model: &[DataDef], unit_order: &HashMap<String, Vec<String>>) -> Edits {
    let (mut edits, mut manual) = (vec![], vec![]);
    let mut groups: BTreeMap<(String, String), Vec<&DataDef>> = BTreeMap::new();
    for d in model.iter().filter(|d| d.kind == "def" && matches!(d.section.as_str(), "data" | "rdata" | "bss")) {
        groups.entry((d.unit.clone(), d.section.clone())).or_default().push(d);
    }
    let flagged: HashSet<&str> = model.iter().filter(|d| d.conflicts.iter().any(|c| c.0 == "D4")).map(|d| d.unit.as_str()).collect();
    let empty = vec![];
    for ((unit, _), mut ds) in groups {
        if !flagged.contains(unit.as_str()) {
            continue;
        }
        let order = unit_order.get(&unit).unwrap_or(&empty);
        let n = order.len();
        let rank = |f: &str| order.iter().position(|x| x == f).unwrap_or(n);
        let known = |f: &str| order.iter().any(|x| x == f);
        ds.sort_by_key(|d| (rank(&d.file), d.line));
        let addrs: Vec<i64> = ds.iter().map(|d| d.addr).collect();
        let mut sorted = addrs.clone();
        sorted.sort();
        if addrs == sorted {
            continue;
        }
        let keep = lis(&addrs);
        let mut anchors: Vec<&DataDef> = (0..ds.len()).filter(|i| keep.contains(i)).map(|i| ds[i]).collect();
        anchors.sort_by_key(|d| d.addr);
        let mut moved: Vec<&DataDef> = (0..ds.len()).filter(|i| !keep.contains(i)).map(|i| ds[i]).collect();
        moved.sort_by_key(|d| d.addr);
        for d in moved {
            let st = statement_at(files, &d.file, d.line);
            let dc = st.and_then(|st| declarator(files, &d.file, &st, &d.name));
            let (Some(st), Some(dc)) = (st, dc) else {
                manual.push(format!("D4 {} {}:{}: the statement is not found", d.name, d.file, d.line));
                continue;
            };
            if dc.count > 1 {
                manual.push(format!("D4 {} {}:{}: a statement with several declarators", d.name, d.file, d.line));
                continue;
            }
            let later = anchors.iter().find(|a| a.addr > d.addr).copied();
            let t = later.unwrap_or(anchors[anchors.len() - 1]);
            let Some(tst) = statement_at(files, &t.file, t.line) else {
                manual.push(format!("D4 {} {}:{}: the statement of {} ({}:{}) is not found", d.name, d.file, d.line, t.name, t.file, t.line));
                continue;
            };
            let at = if later.is_some() { tst.start } else { tst.end };
            let up = (rank(&t.file), at) < (rank(&d.file), st.start);
            if up && known(&t.file) && known(&d.file) {
                let code = chars(&files.src(&d.file).code[st.s0..st.s1]);
                let used: BTreeSet<String> = IDENT.find_iter(&code).map(|m| m.as_str()).filter(|w| !C_WORDS.contains(w) && *w != d.name)
                    .map(|w| w.to_string()).collect();
                if let Some(x) = defined_between(files, order, (&t.file, at), (&d.file, st.start), &used) {
                    manual.push(format!("D4 {} {}:{}: it uses {x}, which the unit defines between {} (before {}) and its place; move {x} up first",
                                        d.name, d.file, d.line, t.file, t.name));
                    continue;
                }
            }
            let text = files.text(&d.file);
            let mut block = chars(&text[st.start..st.end]);
            if !block.ends_with('\n') {
                block.push('\n');
            }
            // moving down past its uses: a non-static definition leaves its declaration behind (`extern T x[n];`, no
            // storage, so the unit's placement is unchanged); a static one has no such declaration in C
            let stay = if (rank(&t.file), at) > (rank(&d.file), st.start) && !d.statik {
                format!("extern {};\n", chars(&text[st.s0..dc.end]))
            } else {
                String::new()
            };
            edits.push(Edit { file: d.file.clone(), at: st.start, remove: st.end - st.start, insert: stay, why: format!("D4 {} ({:#x}) moves", d.name, d.addr),
                              unit: unit.clone(), group: format!("D4 {}", d.name) });
            edits.push(Edit { file: t.file.clone(), at, remove: 0, insert: block,
                              why: format!("D4 {} ({:#x}) {} {} ({:#x}, {}:{})", d.name, d.addr, if later.is_some() { "before" } else { "after" }, t.name,
                                           t.addr, t.file, t.line),
                              unit: unit.clone(), group: format!("D4 {}", d.name) });
        }
    }
    (edits, manual)
}

/// The new texts of the files the edits touch (edits on the original offsets; at one offset a removal goes before
/// an insertion, so an inserted block never falls into a removed one, and insertions keep the order the edits list
/// them in).
fn apply(files: &mut Files, edits: &[&Edit]) -> BTreeMap<String, Vec<char>> {
    let mut out = BTreeMap::new();
    let rels: BTreeSet<&str> = edits.iter().map(|e| e.file.as_str()).collect();
    for rel in rels {
        let mut text = files.text(rel).to_vec();
        let mut es: Vec<(usize, &&Edit)> = edits.iter().enumerate().filter(|(_, e)| e.file == rel).collect();
        es.sort_by_key(|(k, e)| (e.at, if e.remove == 0 { 0 } else { 1 }, *k));
        for (_, e) in es.iter().rev() {
            let at = e.at.min(text.len());
            let end = (e.at + e.remove).min(text.len());
            text.splice(at..end, e.insert.chars());
        }
        out.insert(rel.to_string(), text);
    }
    out
}

/// address -> unit of every function graded byte.
fn byte_functions(db: &str) -> Result<HashMap<i64, String>> {
    let fs = crate::with_db(db, |c| store::facts_of(c, db, "grade", None, |f| f.s("of") == Some("function") && f.s("code") == Some("byte")))?;
    Ok(fs.iter().map(|f| (f.lo, f.s("unit").unwrap_or("").to_string())).collect())
}

fn failed_units(db: &str) -> Result<BTreeSet<String>> {
    let fs = crate::with_db(db, |c| store::facts_of(c, db, "build", None, |f| f.value.get("ok").and_then(|v| v.as_bool()) == Some(false)))?;
    Ok(fs.iter().map(|f| f.s("tu").unwrap_or("").to_string()).collect())
}

// ------------------------------------------------------------------------------------------------ trial compiles

static TRIAL: AtomicUsize = AtomicUsize::new(0);

/// Compiles units with edits that are not written yet and compares their functions with the image (module docs).
/// Nothing touches the sources or the store.
struct Trial<'a> {
    p: &'a Project,
    root: String,
    img: Rc<crate::pe::Image>,
    tools: crate::vc6::Tools,
    units: HashMap<String, crate::plan::Tu>,
    relocs: Option<Vec<u32>>,
    starts: Vec<u32>,
    sources: HashMap<String, Vec<Rc<SFact>>>,
    byte: HashMap<String, HashSet<i64>>,
    forms: Vec<Vec<u8>>,
}

/// One trial compile's outcome: the object's path, else the compiler's first error.
struct Compiled {
    src: String,
    obj: String,
    error: Option<String>,
}

impl<'a> Trial<'a> {
    fn new(p: &'a Project) -> Result<Trial<'a>> {
        let db = p.store_path();
        let root = p.root.to_string_lossy().into_owned();
        let img = crate::image(&p.target(None).map_err(err)?.path)?;
        let units = crate::plan::plan(p).map_err(err)?.iter().map(|t| (t.unit.clone(), t.clone())).collect();
        let (relocs, starts, srcs) = crate::with_db(&db, |c| {
            let los = |kind: &str, keep: &dyn Fn(&SFact) -> bool| store::facts_of(c, &db, kind, None, keep).map(|fs| fs.iter().map(|f| f.lo).collect::<Vec<i64>>());
            let relocs = los("ref", &|f| f.s("rkind") == Some("reloc"));
            let mut starts: Vec<i64> = los("start", &|_| true)?;
            starts.extend(los("symbol", &|f| matches!(f.s("skind"), Some("func" | "thunk")) && f.level > store::OPEN)?);
            let srcs = store::facts_of(c, &db, "source", None, |f| &*f.rule == "L.src" && f.s("what") == Some("func"))?;
            Ok((relocs?, starts, srcs))
        })?;
        let mut relocs: Vec<u32> = relocs.into_iter().map(|x| x as u32).collect();
        relocs.sort_unstable();
        let relocs = (!relocs.is_empty() && !img.relocations().is_empty()).then_some(relocs);
        let mut starts: Vec<u32> = starts.into_iter().map(|x| x as u32).collect();
        starts.extend(img.sections.iter().filter(|s| s.holds_code()).map(|s| s.end()));
        starts.sort_unstable();
        starts.dedup();
        let mut sources: HashMap<String, Vec<Rc<SFact>>> = HashMap::new();
        for f in srcs.iter() {
            sources.entry(f.s("unit").unwrap_or("").to_string()).or_default().push(f.clone());
        }
        let mut byte: HashMap<String, HashSet<i64>> = HashMap::new();
        for (a, u) in byte_functions(&db)? {
            byte.entry(u).or_default().insert(a);
        }
        let forms = crate::toolchain::of(&p.toolchain_key()).map(|t| t.fill_forms().iter().map(|f| f.to_vec()).collect::<Vec<_>>()).unwrap_or_default();
        Ok(Trial { p, root, img, tools: crate::vc6::Tools::of(p), units, relocs, starts, sources, byte, forms: crate::compare::fill_order(&forms) })
    }

    /// For each (unit, its files' new texts): (whether the unit compiles and keeps every byte match, why not).
    /// The compiles run on threads, the compares here.
    fn verdicts(&self, files: &mut Files, jobs: &[(&str, BTreeMap<String, Vec<char>>)]) -> Result<Vec<(bool, String)>> {
        let mut texts = vec![];
        for (unit, new) in jobs {
            let a = &self.units[*unit];
            let text = match new.get(&a.file) { Some(t) => chars(t), None => chars(files.text(&a.file)) };
            let k = TRIAL.fetch_add(1, Ordering::Relaxed);
            let flags = crate::plan::compile_flags(self.p, &a.target, unit).map_err(err)?;
            texts.push((format!("build/trial/{unit}-{k}.c"), format!("build/obj/trial/{unit}-{k}.obj"), text, flags));
        }
        let (root, tools) = (&self.root, &self.tools);
        let done: Vec<Compiled> = crate::compile_threads(&texts, |(src, obj, text, flags)| {
            let full = |r: &str| py_path(&format!("{root}/{r}"));
            for r in [src, obj] {
                if let Some(d) = std::path::Path::new(&full(r)).parent() {
                    let _ = std::fs::create_dir_all(d);
                }
            }
            let error = match std::fs::write(full(src), text.as_bytes()).map_err(|e| e.to_string())
                .and_then(|_| tools.compile(src, obj, flags, &["include".to_string()], root)) {
                Err(e) => Some(e),
                Ok(r) if !r.ok => Some(r.diags.iter().find(|d| d.severity == "error")
                    .map(|d| format!("{}({}): {} {}", d.file, d.line, d.code, d.message)).unwrap_or_else(|| "does not compile".into())),
                Ok(_) => None,
            };
            Compiled { src: full(src), obj: full(obj), error }
        });
        let mut out = vec![];
        for ((unit, _), c) in jobs.iter().zip(done) {
            let got = match &c.error {
                Some(e) => Err(e.clone()),
                None => self.matches(unit, &c.obj),
            };
            for f in [&c.src, &c.obj] {
                let _ = std::fs::remove_file(f);
            }
            out.push(match got {
                Err(e) => (false, e),
                Ok(got) => {
                    let need = self.byte.get(*unit).cloned().unwrap_or_default();
                    let lost: Vec<i64> = need.iter().filter(|a| !got.contains(a)).copied().collect();
                    match lost.iter().min() {
                        None => (true, String::new()),
                        Some(first) => (false, format!("loses {} byte match(es), first {first:#x} (a definition here changes how this unit's code \
                                                        reaches it: the original may define it in another unit)", lost.len())),
                    }
                }
            });
        }
        Ok(out)
    }

    /// The addresses of the unit that byte-match with the object at obj.
    fn matches(&self, unit: &str, obj: &str) -> Result<HashSet<i64>, String> {
        let data = std::fs::read(obj).map_err(|e| format!("{obj}: {e}"))?;
        let o = crate::coff::Obj::parse(&data)?;
        let index = o.function_index();
        let mut out = HashSet::new();
        for s in self.sources.get(unit).into_iter().flatten() {
            let Some(&k) = index.get(s.s("symbol").unwrap_or("")) else { continue };
            let code = o.function_code(k);
            let lo = s.lo as u32;
            let i = self.starts.partition_point(|&x| x <= lo);
            let next = self.starts.get(i).copied().unwrap_or(self.img.end());
            let c = crate::compare::compare(&self.img, &code, lo, self.relocs.as_deref(), next, &self.forms);
            if c.matched() {
                out.insert(s.lo);
            }
        }
        Ok(out)
    }

    /// Per unit: (the accepted edits, why each rejected group fell).
    fn judge(&self, files: &mut Files, units: &[(String, Vec<&'a Edit>)]) -> Result<Vec<(Vec<&'a Edit>, Vec<String>)>> {
        let all: Vec<(&str, BTreeMap<String, Vec<char>>)> = units.iter().map(|(u, es)| (u.as_str(), apply(files, es))).collect();
        let first = self.verdicts(files, &all)?;
        let mut out: Vec<Option<(Vec<&Edit>, Vec<String>)>> = vec![None; units.len()];
        // the groups of the units that fail as a whole, each tried alone
        let mut groups: Vec<Vec<(String, Vec<&Edit>)>> = vec![vec![]; units.len()];
        let mut alone_jobs = vec![];
        for (i, ((u, es), (ok, _))) in units.iter().zip(&first).enumerate() {
            if *ok {
                out[i] = Some((es.clone(), vec![]));
                continue;
            }
            for e in es {
                let key = if e.group.is_empty() { e.why.clone() } else { e.group.clone() };
                match groups[i].iter_mut().find(|g| g.0 == key) {
                    Some(g) => g.1.push(*e),
                    None => groups[i].push((key, vec![*e])),
                }
            }
            for (gi, (_, ges)) in groups[i].iter().enumerate() {
                alone_jobs.push((i, gi, u.as_str(), ges.clone()));
            }
        }
        let jobs: Vec<(&str, BTreeMap<String, Vec<char>>)> = alone_jobs.iter().map(|(_, _, u, es)| (*u, apply(files, es))).collect();
        let alone = self.verdicts(files, &jobs)?;
        let mut verdict_of: HashMap<(usize, usize), (bool, String)> = HashMap::new();
        for ((i, gi, _, _), v) in alone_jobs.iter().zip(alone) {
            verdict_of.insert((*i, *gi), v);
        }
        for i in 0..units.len() {
            if out[i].is_some() {
                continue;
            }
            let u = units[i].0.as_str();
            let gs = &groups[i];
            let good: Vec<usize> = (0..gs.len()).filter(|gi| verdict_of[&(i, *gi)].0).collect();
            let mut rejected: Vec<String> = (0..gs.len()).filter(|gi| !verdict_of[&(i, *gi)].0).map(|gi| format!("{}: {}", gs[gi].0, verdict_of[&(i, gi)].1)).collect();
            let edits_of = |gis: &[usize]| -> Vec<&'a Edit> { gis.iter().flat_map(|&g| gs[g].1.iter().copied()).collect() };
            if !good.is_empty() {
                let together = edits_of(&good);
                let t = apply(files, &together);
                if self.verdicts(files, &[(u, t)])?[0].0 {
                    out[i] = Some((together, rejected));
                    continue;
                }
            }
            let mut kept: Vec<usize> = vec![];
            for &g in &good {
                // the good groups interfere: add them one at a time
                let mut with = kept.clone();
                with.push(g);
                let t = apply(files, &edits_of(&with));
                if self.verdicts(files, &[(u, t)])?[0].0 {
                    kept.push(g);
                } else {
                    rejected.push(format!("{}: passes alone, not together with the others", gs[g].0));
                }
            }
            out[i] = Some((edits_of(&kept), rejected));
        }
        Ok(out.into_iter().map(|x| x.unwrap()).collect())
    }
}

// ------------------------------------------------------------------------------------------------ the commands

fn scan_of(p: &Project) -> Result<Rc<crate::frontend::Scan>> {
    let tree = p.input_hash("src").map_err(err)?;
    crate::frontend::scan(&p.root.to_string_lossy(), tree.as_deref()).map_err(err)
}

/// `dcp data map [UNIT]`: (the lines, the exit status).
pub fn data_map(p: &crate::project::Project, unit: Option<String>, externs: bool) -> Result<(Vec<String>, i32)> {
    crate::pystore::st_open(&p.store_path(), &p.main_uri())?;
    let model = data_model(p, &*scan_of(p)?)?;
    let mut out = vec![];
    let Some(unit) = unit.filter(|u| !u.is_empty()) else {
        let mut per: Vec<(&str, Vec<&DataDef>)> = vec![];
        for d in &model {
            match per.iter_mut().find(|x| x.0 == d.unit) {
                Some(x) => x.1.push(d),
                None => per.push((&d.unit, vec![d])),
            }
        }
        out.push(record(&[("target", s(p.target_name.clone())), ("units", Tok::I(per.len() as i64)), ("declarations", Tok::I(model.len() as i64)),
                          ("conflicts", Tok::I(model.iter().map(|d| d.conflicts.len() as i64).sum()))]));
        per.sort_by_key(|x| x.1.iter().map(|d| d.addr).min());
        for (u, ds) in per {
            let defs: Vec<&&DataDef> = ds.iter().filter(|d| d.kind == "def").collect();
            let sec = |k: &str| defs.iter().filter(|d| d.section == k).count() as i64;
            let mut checks: BTreeMap<&str, usize> = BTreeMap::new();
            for d in &ds {
                for (c, _) in &d.conflicts {
                    *checks.entry(c).or_default() += 1;
                }
            }
            let checks = checks.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(",");
            out.push(format!("  {}", record(&[("unit", s(u)), ("defs", Tok::I(defs.len() as i64)),
                                              ("externs", Tok::I(ds.iter().filter(|d| d.kind == "extern").count() as i64)), ("data", Tok::I(sec("data"))),
                                              ("rdata", Tok::I(sec("rdata"))), ("bss", Tok::I(sec("bss"))), ("common", Tok::I(sec("common"))),
                                              ("proven", Tok::I(defs.iter().filter(|d| d.level == "proven").count() as i64)),
                                              ("conflicts", if checks.is_empty() { Tok::No } else { s(checks) })])));
        }
        return Ok((out, 0));
    };
    let mut ds: Vec<&DataDef> = model.iter().filter(|d| d.unit == unit && (d.kind == "def" || externs)).collect();
    ds.sort_by(|a, b| (a.addr, &a.file).cmp(&(b.addr, &b.file)));
    if ds.is_empty() {
        out.push(record(&[("unit", s(unit)), ("error", s("no data declarations with an address"))]));
        return Ok((out, 1));
    }
    out.push(record(&[("unit", s(unit)), ("declarations", Tok::I(ds.len() as i64))]));
    for d in ds {
        let room = d.next_start.map(|n| n - d.addr);
        let over = match (d.size, room) { (Some(sz), Some(r)) if sz != 0 && sz > r => Some(sz - r), _ => None };
        let oi = |x: Option<i64>| x.map(Tok::I).unwrap_or(Tok::No);
        out.push(format!("  {}", record(&[("at", Tok::I(d.addr)), ("name", s(d.name.clone())), ("kind", if d.kind != "def" { s(d.kind.clone()) } else { Tok::No }),
                                          ("section", s(d.section.clone())), ("size", oi(d.size)), ("room", oi(room)), ("over", oi(over)),
                                          ("level", s(d.level.clone())), ("by", s(d.extent.clone())), ("static", if d.statik { Tok::B(true) } else { Tok::No }),
                                          ("src", s(format!("{}:{}", d.file, d.line)))])));
        for (c, m) in &d.conflicts {
            out.push(format!("    {c}: {m}"));
        }
    }
    Ok((out, 0))
}

/// `dcp data fix` (data_fix): `sync()` builds and refreshes the store, `emit(line)` prints a line.
#[allow(clippy::too_many_arguments)]
pub fn data_fix(p: &Project, checks: Option<String>, unit: Option<String>, write: bool, limit: usize, verbose: bool,
                    sync: &mut dyn FnMut() -> Result<()>, emit: &mut dyn FnMut(String) -> Result<()>) -> Result<i32> {
    let mut say = |line: String| emit(line);
    let checks: Vec<String> = match &checks {
        Some(c) if !c.is_empty() => c.split(',').map(|x| x.trim().to_uppercase()).collect(),
        _ => CHECKS.iter().map(|c| c.to_string()).collect(),
    };
    let bad: Vec<&str> = checks.iter().filter(|c| !CHECKS.contains(&c.as_str())).map(|c| c.as_str()).collect();
    if !bad.is_empty() {
        say(record(&[("error", s(format!("unknown check {} (known: {})", bad.join(","), CHECKS.join(","))))]))?;
        return Ok(2);
    }
    let db = p.store_path();
    let root = p.root.to_string_lossy().into_owned();
    let mut status = 0;
    for check in &checks {
        let t0 = std::time::Instant::now();
        sync()?; // the data checks read the objects: they must be the sources' own
        let scan = scan_of(p)?;
        let model = data_model(p, &scan)?;
        let mut files = Files::new(&root, Some(scan));
        let (mut edits, mut manual) = match check.as_str() {
            "D5" => d5_edits(&mut files, &model),
            "D1" => d1_edits(&mut files, &model),
            _ => {
                let order: HashMap<String, Vec<String>> = crate::plan::plan(p).map_err(err)?.iter().map(|a| (a.unit.clone(), vec![a.file.clone()])).collect();
                d4_edits(&mut files, &model, &order)
            }
        };
        if let Some(u) = unit.as_deref().filter(|u| !u.is_empty()) {
            edits.retain(|x| x.unit == u);
            let tag = format!(" src/{u}.c:");
            manual.retain(|m| m.contains(&tag));
        }
        let units: BTreeSet<&str> = edits.iter().map(|x| x.unit.as_str()).collect();
        say(record(&[("check", s(check.clone())), ("edits", Tok::I(edits.len() as i64)), ("units", Tok::I(units.len() as i64)),
                     ("manual", Tok::I(manual.len() as i64)), ("write", Tok::B(write))]))?;
        for x in edits.iter().take(if verbose { usize::MAX } else { limit }) {
            if !x.why.ends_with("moves") {
                say(format!("  edit {}  {}", x.why, x.file))?;
            }
        }
        for m in &manual {
            say(format!("  manual {m}"))?;
        }
        if !write || edits.is_empty() {
            continue;
        }
        // trial compiles decide; only accepted edits are written, then one build
        let before = byte_functions(&db)?;
        let trial = Trial::new(p)?;
        let per: Vec<(String, Vec<&Edit>)> = units.iter().map(|u| (u.to_string(), edits.iter().filter(|x| x.unit == *u).collect())).collect();
        let verdicts = trial.judge(&mut files, &per)?;
        let mut accepted: Vec<&Edit> = verdicts.iter().flat_map(|v| v.0.iter().copied()).collect();
        for ((u, _), v) in per.iter().zip(&verdicts) {
            for why in &v.1 {
                say(format!("  rejected {}  {why}", record(&[("unit", s(u.clone()))])))?;
            }
        }
        let t1 = t0.elapsed();
        let new = apply(&mut files, &accepted);
        for (rel, text) in &new {
            std::fs::write(files.path(rel), files.encode(rel, text)).map_err(err)?;
        }
        sync()?;
        let failed = failed_units(&db)?;
        let now = byte_functions(&db)?;
        let still = before.keys().filter(|a| !now.contains_key(a)).count();
        let before_units: HashSet<&String> = before.values().collect();
        if still > 0 || (!failed.is_empty() && failed.iter().any(|f| !before_units.contains(f))) {
            for rel in new.keys() {
                // the trial missed something: the batch goes back
                let old = files.text(rel).to_vec();
                std::fs::write(files.path(rel), files.encode(rel, &old)).map_err(err)?;
            }
            sync()?;
            let failed = if failed.is_empty() { "-".to_string() } else { failed.iter().cloned().collect::<Vec<_>>().join(",") };
            say(format!("  reverted {}", record(&[("edits", Tok::I(accepted.len() as i64)),
                                                   ("why", s(format!("after writing, {still} byte match(es) lost, failed units: {failed}")))])))?;
            accepted.clear();
            status = 1;
        }
        let groups: HashSet<&str> = accepted.iter().map(|x| x.group.as_str()).collect();
        let now = byte_functions(&db)?;
        say(record(&[("check", s(check.clone())), ("applied", Tok::I(groups.len() as i64)),
                     ("rejected", Tok::I(verdicts.iter().map(|v| v.1.len() as i64).sum())),
                     ("byte_lost", Tok::I(before.keys().filter(|a| !now.contains_key(a)).count() as i64)),
                     ("trial_ms", Tok::I(t1.as_millis() as i64)), ("ms", Tok::I(t0.elapsed().as_millis() as i64))]))?;
    }
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(name: &str, files: &[(&str, &str)]) -> (String, Files) {
        let root = std::env::temp_dir().join(format!("dcp-datafix-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (rel, text) in files {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        let r = root.to_string_lossy().into_owned();
        (r.clone(), Files::new(&r, None))
    }

    fn def(name: &str, line: i64, addr: i64, check: &str, section: &str) -> DataDef {
        DataDef { unit: "u".into(), name: name.into(), file: "src/u.c".into(), line, kind: "def".into(), addr, statik: false, level: "-".into(),
                  extent: "-".into(), section: section.into(), size: None, next_start: None, conflicts: vec![(check.into(), "x".into())], warnings: vec![] }
    }

    fn sub(f: &mut Files, rel: &str, a: usize, b: usize) -> String {
        chars(&f.text(rel)[a..b])
    }

    #[test]
    fn statement_block_and_declarators() {
        let (_, mut f) = tree("stmt", &[("src/u.c", "int a;  /* 0x600000, a comment that runs on\n           over a second line */\n\
                                                    /* 0x600010, the table */\nvoid (*handlers[4])(unsigned char *);\n\
                                                    int b = 5, c;  /* 0x600020, 0x600024 */\n")]);
        let st = statement_at(&mut f, "src/u.c", 1).unwrap();
        assert_eq!(sub(&mut f, "src/u.c", st.start, st.end), "int a;  /* 0x600000, a comment that runs on\n           over a second line */\n");
        let st2 = statement_at(&mut f, "src/u.c", 4).unwrap();
        assert!(sub(&mut f, "src/u.c", st2.start, st2.end).starts_with("/* 0x600010, the table */\nvoid (*handlers")); // the comment above moves too
        let dc = declarator(&mut f, "src/u.c", &st2, "handlers").unwrap();
        assert!(dc.dims == ["4"] && !dc.has_init);
        assert_eq!(sub(&mut f, "src/u.c", st2.s0, dc.end), "void (*handlers[4])(unsigned char *)");
        let st3 = statement_at(&mut f, "src/u.c", 5).unwrap();
        let (b, c) = (declarator(&mut f, "src/u.c", &st3, "b").unwrap(), declarator(&mut f, "src/u.c", &st3, "c").unwrap());
        assert!(b.has_init && !c.has_init && b.count == 2);
    }

    #[test]
    fn d5_initialisers() {
        let (_, mut f) = tree("d5", &[("src/u.c", "int a;\nAIOBJ *p;\nAIOBJ o;\nchar s[8];\nvoid (*fp)(void);\n")]);
        let model: Vec<DataDef> = ["a", "p", "o", "s", "fp"].iter().enumerate().map(|(i, n)| def(n, i as i64 + 1, 0x600001 + i as i64, "D5", "-")).collect();
        let (edits, manual) = d5_edits(&mut f, &model);
        assert!(manual.is_empty());
        let new = apply(&mut f, &edits.iter().collect::<Vec<_>>());
        assert_eq!(chars(&new["src/u.c"]), "int a = 0;\nAIOBJ *p = 0;\nAIOBJ o = {0};\nchar s[8] = {0};\nvoid (*fp)(void) = 0;\n");
    }

    #[test]
    fn insertions_at_one_place_keep_their_order() {
        let (_, mut f) = tree("order", &[("a.c", "x\ny\n")]);
        let e = |at, remove, insert: &str| Edit { file: "a.c".into(), at, remove, insert: insert.into(), why: String::new(), unit: "u".into(), group: String::new() };
        let edits = [e(2, 0, "1\n"), e(2, 0, "2\n"), e(0, 2, "")];
        assert_eq!(chars(&apply(&mut f, &edits.iter().collect::<Vec<_>>())["a.c"]), "1\n2\ny\n");
    }

    /// The init_PlayerProfile case: the definition sorts between two in the head, but its typedef stands further
    /// down, between the two places: a manual case, no edit (the move would not compile).
    #[test]
    fn d4_does_not_move_a_definition_above_its_type() {
        let (_, mut f) = tree("d4", &[("src/u.c", "int a = 0;  /* 0x600000 */\nint b = 0;  /* 0x600020 */\nint e = 0;  /* 0x600028 */\n\
                                                  typedef struct { int a; } INIT_PLAYER;\nINIT_PLAYER prof = {0};  /* 0x600010 */\n\
                                                  /* 0x401000, f */\nvoid f(void)\n{\n}\n\
                                                  int c = 0;  /* 0x600030 */\nint d = 0;  /* 0x600008 */\n\
                                                  /* 0x401100, g */\nvoid g(void)\n{\n}\n")]);
        let model = [def("a", 1, 0x600000, "D4", "bss"), def("b", 2, 0x600020, "D4", "bss"), def("e", 3, 0x600028, "D4", "bss"),
                     def("prof", 5, 0x600010, "D4", "bss"), def("c", 10, 0x600030, "D4", "bss"), def("d", 11, 0x600008, "D4", "bss")];
        let order = HashMap::from([("u".to_string(), vec!["src/u.c".to_string()])]); // the run a, b, e, c stays: prof and d move up
        let (edits, manual) = d4_edits(&mut f, &model, &order);
        assert!(manual.iter().any(|m| m.contains(" prof ") && m.contains("INIT_PLAYER")), "{manual:?}");
        let moved: HashSet<&str> = edits.iter().map(|e| e.group.as_str()).collect();
        assert!(!moved.contains("D4 prof") && moved.contains("D4 d")); // `int` needs nothing from in between
    }

    /// An object's size runs to the next symbol, padding included: the least size drops what the alignment of that
    /// end may have added (at most 7 bytes at an 8-aligned end).
    #[test]
    fn least_size() {
        use crate::rules::least;
        assert_eq!(least(Some(0x10), 8), 1); // int x = 0; followed by an 8-aligned symbol
        assert_eq!(least(Some(0x10), 6), 5); // ends at 0x16: 2-aligned, at most 1 byte padding
        assert_eq!(least(Some(0x11), 6), 6); // ends at an odd offset: no padding
        assert_eq!(least(None, 8), 8);
    }

    /// M.data.content: `float x = 1.75f;` whose next symbol is 8-aligned has an object size of 8 (4 bytes of padding)
    /// and a least size of 1: every zero byte from byte 1 on may be padding and is masked.
    #[test]
    fn content_masks_possible_padding() {
        use crate::rules::{least, padding_masked};
        let data = [0, 0, 0xe0, 0x3f, 0, 0, 0, 0]; // 1.75f, then 4 zero bytes of padding
        assert_eq!(padding_masked(&data, &[0; 8], least(Some(0x18), 8) as usize), [0, 1, 0, 0, 1, 1, 1, 1]);
        let data2 = [0, 0, 0xe0, 0x3f, 0, 0, 0, 0x40]; // a nonzero byte in the possible padding is the symbol's own: compared
        assert_eq!(padding_masked(&data2, &[0; 8], 1)[7], 0);
    }

    #[test]
    fn longest_increasing_run() {
        let k = lis(&[5, 1, 2, 9, 3, 4]);
        let mut v: Vec<usize> = k.into_iter().collect();
        v.sort();
        assert_eq!(v, [1, 2, 4, 5]);
        assert!(lis(&[]).is_empty());
    }

    #[test]
    fn what_the_code_defines() {
        let ids = |xs: &[&str]| xs.iter().map(|x| x.to_string()).collect::<BTreeSet<_>>();
        assert_eq!(defined_in("#define N 4\nint a[N];", &ids(&["N"])), Some("N".into()));
        assert_eq!(defined_in("typedef struct { int x; } T;", &ids(&["T"])), Some("T".into()));
        assert_eq!(defined_in("enum { A, B = 2 };", &ids(&["B"])), Some("B".into()));
        assert_eq!(defined_in("x = y + 1;", &ids(&["y"])), None);
    }
}
