//! One file's part of the source scan (ledger/srcscan.py is its Python face, which documents the layout of the
//! sources and the address comments). The front end's model of the file (source/cparse.py: model) gives the
//! function definitions, the data declarators, the macro definitions, the casts, and the comments and literals
//! (clang_tokenize); this module reads the address comments and the macros' bodies. Offsets are byte offsets of
//! the file's text; the model's (line, column in characters) positions are mapped to them.

use crate::layout::{ScanRef, ScanView};
use pyo3::exceptions::PyRuntimeError;
use crate::clang::FileModel;
use pyo3::prelude::*;

use regex::Regex;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, Weak};

type Addrs = Vec<(Option<String>, u64)>;
type Lc = (i64, i64);

/// str.isspace: Unicode white space and the separators U+001C..U+001F.
pub(crate) fn py_space(c: char) -> bool {
    c.is_whitespace() || ('\x1c'..='\x1f').contains(&c)
}

pub(crate) fn py_strip(s: &str) -> &str {
    s.trim_matches(py_space)
}

/// " ".join(s.split())
pub(crate) fn py_words(s: &str) -> String {
    s.split(py_space).filter(|x| !x.is_empty()).collect::<Vec<_>>().join(" ")
}

const ADDR_ITEM: &str = r"(?:[A-Za-z][A-Za-z0-9_-]*:)?0x[0-9a-fA-F]+";
static LEAD_ADDRS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"\A\s*({ADDR_ITEM})((?:\s*[,/]\s*{ADDR_ITEM})*)")).unwrap());
static ONE_ADDR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:([A-Za-z][A-Za-z0-9_-]*):)?(0x[0-9a-fA-F]+)").unwrap());
pub(crate) static UNLINKED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)\A\s*unlinked\b\s*,?\s*(.*)").unwrap());
static DEEP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"@deep\b[ \t]*(.*?)[ \t]*(?:\*/|\n|\z)").unwrap());
static STUCK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"@stuck\b[ \t]*(.*?)[ \t]*(?:\*/|\n|\z)").unwrap());
static ROUGH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"@rough\b").unwrap());
static TAGS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"@(?:deep|stuck|rough)\b").unwrap());
static DESCRIBED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)\A\s*(?:[A-Za-z][A-Za-z0-9_-]*:)?(0x[0-9a-fA-F]+)\b\s*(.*)").unwrap());
static MORE_ADDRS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A(?:\s*[,/]\s*(?:[A-Za-z][A-Za-z0-9_-]*:)?0x[0-9a-fA-F]+)*").unwrap());
static SPACES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());
static WORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\w+").unwrap());
const TYPEP: &str = r"[^()]*(?:\([^()]*\)[^()]*)*";
const NUM: &str = r"(0[xX][0-9a-fA-F]+|\d+)[uUlL]*";
static VIEW_BYTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"\A\(\s*\*\s*\({TYPEP}\)\s*\(\s*\(\s*(?:unsigned\s+|signed\s+)?char\s*\*\s*\)\s*(&\s*)?([A-Za-z_]\w*)\s*\+\s*{NUM}\s*\)\s*\)\z"
    ))
    .unwrap()
});
static VIEW_WHOLE: LazyLock<Regex> = LazyLock::new(|| Regex::new(&format!(r"\A\(\s*\*\s*\({TYPEP}\)\s*&\s*([A-Za-z_]\w*)\s*\)\z")).unwrap());
static VIEW_ALIAS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\A([A-Za-z_]\w*)\z").unwrap());
static DEREF_OBJ: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\(\s*\*\s*\(\s*[A-Za-z_]").unwrap());
// srcscan.PTR_CAST; its lookahead after the literal is the consumed `[^\w.]|\z` after the group `all` (a search
// goes on at the group's end), its lookbehind before the literal always holds (a `(`, `)` or a space is there)
const TYPE: &str = r"(?:(?:const|volatile|unsigned|signed|struct|union|enum)\s+)*[A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*";
const CC: &str = r"(?:__cdecl|__stdcall|__fastcall|WINAPI|CALLBACK|APIENTRY|PASCAL)";
static PTR_CAST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(?P<all>\(\s*{TYPE}\s*(?:(?:\*\s*(?:(?:const|volatile)\b\s*)?)+|\**\s*\(\s*{CC}?\s*\*+\s*\)\s*\([^()]*\)\s*)\)(?:\s*\((?:\s*{TYPE}\s*\))?)*\s*(?P<lit>0[xX][0-9a-fA-F]+|\d+)[uUlL]*)(?:[^\w.]|\z)"
    ))
    .unwrap()
});

/// srcscan.lead_addrs: the addresses a comment starts with; and where they end.
pub(crate) fn lead_addrs(body: &str) -> (Addrs, usize) {
    match LEAD_ADDRS.find(body) {
        None => (vec![], 0),
        Some(m) => (
            ONE_ADDR
                .captures_iter(m.as_str())
                .map(|c| (c.get(1).map(|t| t.as_str().to_string()), u64::from_str_radix(&c[2][2..], 16).unwrap_or(u64::MAX)))
                .collect(),
            m.end(),
        ),
    }
}

/// srcscan.literal_value: a C integer literal's digits (hex, octal with a leading 0, decimal).
fn literal_value(s: &str) -> Option<u64> {
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).ok()
    } else if s.len() > 1 && s.starts_with('0') {
        u64::from_str_radix(s, 8).ok()
    } else {
        s.parse().ok()
    }
}

/// text before the first @deep / @stuck / @rough
fn before_tags(s: &str) -> &str {
    TAGS.find(s).map(|m| &s[..m.start()]).unwrap_or(s)
}

/// srcscan.assign: a comment's addresses over n declarators.
fn assign(addrs: &Addrs, n: usize) -> Vec<Addrs> {
    if n == 1 {
        return vec![addrs.clone()];
    }
    let mut by: Vec<(Option<String>, Vec<u64>)> = vec![];
    for (t, a) in addrs {
        match by.iter_mut().find(|x| &x.0 == t) {
            Some(x) => x.1.push(*a),
            None => by.push((t.clone(), vec![*a])),
        }
    }
    if by.iter().any(|x| x.1.len() != n) {
        return vec![vec![]; n];
    }
    (0..n).map(|j| by.iter().map(|(t, v)| (t.clone(), v[j])).collect()).collect()
}

/// srcscan's placeholder: an identifier that spells an address (PLACEHOLDER_ADDR: a match is always a whole word;
/// its three forms in the order the expression tries them, the shortest prefix first).
/// PLACEHOLDER_ADDR.fullmatch of a name: the address it spells when the whole name is a placeholder.
pub(crate) fn placeholder_whole(w: &str) -> Option<u64> {
    (!w.is_empty() && w.chars().all(|c| c.is_alphanumeric() || c == '_')).then(|| placeholder(w)).flatten()
}

fn placeholder(w: &str) -> Option<u64> {
    let first = w.chars().next()?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }
    let hex = |s: &str, lower: bool, upper: bool| {
        s.bytes().all(|c| c.is_ascii_digit() || (lower && (b'a'..=b'f').contains(&c)) || (upper && (b'A'..=b'F').contains(&c)))
    };
    let at = |pat: &'static str| w.match_indices(pat).map(|(i, _)| i).filter(|&i| i >= first.len_utf8()).collect::<Vec<_>>();
    // Unk([0-9a-f]{5,8}|[0-9A-F]{5,8})(?:[A-Z][A-Za-z]*)?
    for p in at("Unk") {
        let h = &w[p + 3..];
        for (lower, upper) in [(true, false), (false, true)] {
            for n in (5..=8).rev() {
                if h.len() >= n && h.is_char_boundary(n) && hex(&h[..n], lower, upper) {
                    let rest = &h[n..];
                    let suffix = rest.is_empty()
                        || (rest.as_bytes()[0].is_ascii_uppercase() && rest.bytes().all(|c| c.is_ascii_alphabetic()));
                    if suffix {
                        return u64::from_str_radix(&h[..n], 16).ok();
                    }
                }
            }
        }
    }
    // (?:FUN_|DAT_|PTR_|LAB_)([0-9a-fA-F]{5,8})
    let mut tagged: Vec<usize> = ["FUN_", "DAT_", "PTR_", "LAB_"].iter().flat_map(|t| at(t)).collect();
    tagged.sort();
    for p in tagged {
        let h = &w[p + 4..];
        if (5..=8).contains(&h.len()) && hex(h, true, true) {
            return u64::from_str_radix(h, 16).ok();
        }
    }
    // _((?=[0-9a-fA-F]*\d)[0-9a-fA-F]{6,8})
    for p in at("_") {
        let h = &w[p + 1..];
        if (6..=8).contains(&h.len()) && hex(h, true, true) && h.bytes().any(|c| c.is_ascii_digit()) {
            return u64::from_str_radix(h, 16).ok();
        }
    }
    None
}

/// A file's text with its comments (the model's), its code (comments and literals blanked) and its lines.
pub(crate) struct Src<'a> {
    text: &'a str,
    pub(crate) code: String,
    starts: Vec<usize>,
    comments: Vec<(usize, usize, &'a str)>, // start, end, body
    cstarts: Vec<usize>,
    own: HashMap<usize, usize>, // end -> index of every comment that starts its line
}

impl<'a> Src<'a> {
    pub(crate) fn new(text: &'a str, comments: &[(i64, i64, i64, i64)], strings: &[(i64, i64, i64, i64)]) -> Self {
        let starts: Vec<usize> = std::iter::once(0).chain(memchr::memchr_iter(b'\n', text.as_bytes()).map(|i| i + 1)).collect();
        let mut s = Src { text, code: String::new(), starts, comments: vec![], cstarts: vec![], own: HashMap::new() };
        let mut code = text.as_bytes().to_vec();
        let mut blank = |a: usize, b: usize| {
            for c in &mut code[a..b] {
                if *c != b'\n' {
                    *c = b' ';
                }
            }
        };
        for &(l, c, el, ec) in strings {
            blank(s.offset(l, c), s.offset(el, ec));
        }
        for &(l, c, el, ec) in comments {
            let (a, b) = (s.offset(l, c), s.offset(el, ec));
            blank(a, b);
            let t = &text[a..b];
            let body = if t.starts_with("/*") { t.get(2..t.len().saturating_sub(2)).unwrap_or("") } else { t.get(2..).unwrap_or("") };
            s.comments.push((a, b, body));
        }
        s.code = String::from_utf8(code).unwrap_or_default();
        s.cstarts = s.comments.iter().map(|c| c.0).collect();
        for (i, &(a, b, _)) in s.comments.iter().enumerate() {
            let bol = text[..a].rfind('\n').map(|x| x + 1).unwrap_or(0);
            if py_strip(&text[bol..a]).is_empty() {
                s.own.insert(b, i);
            }
        }
        s
    }

    /// The byte offset of a (line, column in characters) position, both from 1 (Source.offset).
    pub(crate) fn offset(&self, line: i64, col: i64) -> usize {
        let k = (line.min(self.starts.len() as i64) - 1).max(0) as usize;
        let ls = self.starts[k];
        let n = (col - 1).max(0) as usize;
        self.text[ls..].char_indices().nth(n).map(|(i, _)| ls + i).unwrap_or(self.text.len())
    }

    pub(crate) fn line_of(&self, off: usize) -> i64 {
        self.starts.partition_point(|&s| s <= off) as i64
    }

    /// The offset before the white space that ends at off (Source.end_before).
    fn end_before(&self, off: usize) -> usize {
        let t = &self.text[..off];
        t.trim_end_matches(py_space).len()
    }

    fn char_at(&self, s: &str, i: usize) -> Option<char> {
        s.get(i..).and_then(|x| x.chars().next())
    }

    /// Source._attach: the address comment of the statement s..i split over its n declarators, and `unlinked`.
    fn attach(&self, s: usize, i: usize, n: usize, skip: &HashSet<usize>) -> (Vec<Addrs>, bool) {
        let code = self.code.as_bytes();
        let eol = memchr::memchr(b'\n', &code[s..]).map(|x| x + s);
        let mut after = i;
        while after < self.text.len() && matches!(self.text.as_bytes()[after], b' ' | b'\t') {
            after += 1;
        }
        let (mut addrs, mut unlinked) = (vec![], false);
        for ci in self.cstarts.partition_point(|&c| c < s)..self.cstarts.len() {
            let cs = self.cstarts[ci];
            let first_line = eol.is_none_or(|e| cs < e);
            if !(first_line || (i <= cs && cs <= after)) {
                if cs > after {
                    break;
                }
                continue;
            }
            if skip.contains(&ci) {
                continue;
            }
            if cs >= i && memchr::memchr(b';', &code[i..cs]).is_some() {
                continue; // behind a later statement of this line: that one's comment
            }
            let body = self.comments[ci].2;
            addrs = lead_addrs(body).0;
            unlinked = unlinked || UNLINKED.is_match(body);
            if !addrs.is_empty() {
                break;
            }
        }
        if addrs.is_empty() {
            if let Some(&k) = self.own.get(&self.end_before(s)) {
                if !skip.contains(&k) {
                    let body = self.comments[k].2;
                    addrs = lead_addrs(body).0;
                    unlinked = unlinked || UNLINKED.is_match(body);
                }
            }
        }
        (assign(&addrs, n), unlinked)
    }
}

// (file, line, unit, name, addrs, unlinked, what), (deep, stuck, rough, comment line, static, end line, targets)
/// The function definitions with a body of a file's model: name -> start line, column, end line, column (the last
/// one with a body; G.grade's readability).
pub(crate) type Defs = HashMap<String, (i64, i64, Option<i64>, Option<i64>)>;

/// One file's scan as the native rules read it.
pub(crate) struct Piece {
    view: ScanView,
    rel: String,
    defs: Defs,
    lint: Vec<(Option<String>, crate::lint::FileLint)>, // per target's view of the file
    sysinc: Vec<String>,                                // its `#include <..>` names
}

impl Piece {
    pub(crate) fn lint_for(&self, target: &Option<String>) -> Option<&crate::lint::FileLint> {
        self.lint.iter().find(|(t, _)| t == target).map(|x| &x.1)
    }

    pub(crate) fn sysinc(&self) -> &[String] {
        &self.sysinc
    }
}

/// A file's piece, held by the Python scan that holds the file's scan (srcscan.Scan.native); the native rules
/// name it by its id (native_view). digest: the hash of the items the native rules read of it (the scan's
/// input hash: srcscan.Scan.digest).
#[pyclass(frozen)]
pub struct ScanPiece {
    #[pyo3(get)]
    id: u64,
    #[pyo3(get)]
    digest: String,
    _piece: Arc<Piece>,
}

static HELD: LazyLock<Mutex<HashMap<u64, Weak<Piece>>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT: AtomicU64 = AtomicU64::new(1);

impl ScanPiece {
    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
}

fn hold(p: Piece) -> ScanPiece {
    use sha2::{Digest, Sha256};
    let v = &p.view;
    let rows = format!("{}\0{:?}{:?}{:?}{:?}{:?}{:?}{:?}{:?}{:?}", p.rel, v.functions, v.placeholders, v.ptrcasts, v.data, v.items.fns, v.items.datas,
                       v.items.views, v.items.errors, { let mut d: Vec<_> = p.defs.iter().collect(); d.sort_by(|a, b| a.0.cmp(b.0)); d });
    let digest = Sha256::digest(rows.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    let piece = Arc::new(p);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let mut h = HELD.lock().unwrap_or_else(|e| e.into_inner());
    if h.len() > 4096 {
        h.retain(|_, w| w.strong_count() > 0);
    }
    h.insert(id, Arc::downgrade(&piece));
    ScanPiece { id, digest, _piece: piece }
}

fn pieces(ids: &[u64]) -> PyResult<Vec<Arc<Piece>>> {
    let h = HELD.lock().unwrap_or_else(|e| e.into_inner());
    ids.iter()
        .map(|id| h.get(id).and_then(|w| w.upgrade()).ok_or_else(|| PyRuntimeError::new_err(format!("scan piece {id} is no longer held"))))
        .collect()
}

/// rel -> the piece of the file, of the pieces named.
pub(crate) fn pieces_by_rel(ids: &[u64]) -> PyResult<HashMap<String, Arc<Piece>>> {
    Ok(pieces(ids)?.into_iter().map(|p| (p.rel.clone(), p)).collect())
}

/// The scan a ScanRef names: its pieces joined, its own errors after theirs.
pub(crate) fn view(r: &ScanRef) -> PyResult<ScanView> {
    let mut v = ScanView::default();
    for p in pieces(&r.pieces)? {
        v.extend(&p.view);
    }
    v.items.errors.extend_from_slice(&r.errors);
    Ok(v)
}

/// file -> its Defs, of the files a ScanRef names.
pub(crate) fn defs(r: &ScanRef) -> PyResult<HashMap<String, Defs>> {
    Ok(pieces(&r.pieces)?.iter().map(|p| (p.rel.clone(), p.defs.clone())).collect())
}

pub(crate) type FnRow = ((String, i64, String, String, Addrs, bool, String), (Option<String>, Option<String>, bool, i64, bool, i64, Vec<String>));
pub(crate) type DataRow = (String, i64, String, String, String, Addrs, bool, bool);
pub(crate) type ViewRow = (String, i64, String, String, String, u64, Addrs, bool);
pub(crate) type ErrRow = (String, i64, String, String);

/// One file's part of the scan: the rows of srcscan's dataclasses (macros, described, functions, data, ptrcasts,
/// views, rawobj, errors, placeholders) and the file's piece.
pub(crate) struct FilePart {
    pub macros: Vec<(String, String)>,
    pub described: Vec<u64>,
    pub functions: Vec<FnRow>,
    pub data: Vec<DataRow>,
    pub ptrcasts: Vec<(String, i64, String, u64)>,
    pub views: Vec<ViewRow>,
    pub rawobj: Vec<String>,
    pub errors: Vec<ErrRow>,
    pub placeholders: Vec<(String, i64, String, u64)>,
    pub piece: ScanPiece,
}

/// scan_file of a model: views as (target or None, its model of the file); none: the model is the only view.
pub(crate) fn scan_file_rs(rel: &str, text: &str, model: &FileModel, views: &[(Option<String>, &FileModel)]) -> PyResult<FilePart> {
    let sf = Src::new(text, &model.comments, &model.strings);
    let defines: Vec<(String, bool, i64, usize, usize)> =
        model.defines.iter().map(|(n, fl, l, c, el, ec)| { let s = sf.offset(*l, *c); (n.clone(), *fl, *l, s, sf.offset(*el, *ec)) }).collect();
    let mut macros: Vec<(String, String)> = vec![];
    for (name, fl, _, s, e) in &defines {
        if *fl {
            let rest = &text[(s + name.len()).min(*e)..*e];
            let k = rest.find(')').map(|k| k + 1).unwrap_or(0);
            macros.push((name.clone(), py_strip(&rest[k..]).to_string()));
        }
    }
    let mut described: Vec<u64> = vec![];
    for &(_, _, body) in &sf.comments {
        if let Some(m) = DESCRIBED.captures(body) {
            let rest = before_tags(m.get(2).unwrap().as_str());
            let rest = &rest[MORE_ADDRS.find(rest).map(|x| x.end()).unwrap_or(0)..];
            if !rest.trim_matches(|c| " \t\r\n,.-:;*/".contains(c)).is_empty() {
                described.extend(lead_addrs(body).0.into_iter().map(|x| x.1));
            }
        }
    }
    let unit = std::path::Path::new(rel).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let in_src = rel.starts_with("src/");
    let is_unit = in_src && rel.ends_with(".c") && !rel[4..].contains('/');
    let mut errors: Vec<ErrRow> = vec![];
    let err = |errors: &mut Vec<ErrRow>, line: i64, check: &str, msg: String| errors.push((rel.to_string(), line, check.to_string(), msg));
    if in_src && rel.ends_with(".c") && !is_unit {
        err(&mut errors, 1, "L.src", format!("unexpected source file {rel}: a unit is one file, src/<unit>.c"));
    }
    // the definitions of every target's view of the file, with the targets that hold each
    let mut defs: BTreeMap<Lc, (String, bool, Option<Lc>, Vec<String>)> = BTreeMap::new();
    let views: Vec<(Option<String>, &FileModel)> = if views.is_empty() { vec![(None, model)] } else { views.to_vec() };
    for (t, m) in &views {
        let mut ends: HashMap<Lc, Option<Lc>> = HashMap::new();
        for d in &m.decls {
            if let crate::clang::Decl::F(_, _, ws, _, e, Some(_), _) = d {
                ends.insert(*ws, *e);
            }
        }
        for (line, col, name, stat) in m.defs.iter().cloned() {
            let e = defs.entry((line, col)).or_insert_with(|| (name, stat, ends.get(&(line, col)).copied().flatten(), vec![]));
            if let Some(t) = t {
                e.3.push(t.clone());
            }
        }
    }
    let mut skip: HashSet<usize> = HashSet::new();
    let mut functions: Vec<FnRow> = vec![];
    for ((line, col), (fname, fstatic, end, ts)) in defs {
        if !is_unit {
            err(&mut errors, line, "L.src", format!("function {fname} defined outside a unit file (src/<unit>.c)"));
            continue;
        }
        let k = sf.own.get(&sf.end_before(sf.offset(line, col))).copied();
        let body = k.map(|k| sf.comments[k].2).unwrap_or("");
        let (addrs, lead_end) = lead_addrs(body);
        let um = UNLINKED.captures(body);
        if addrs.is_empty() && um.is_none() {
            err(&mut errors, line, "L.src", format!("function {fname}: no address comment (`/* 0x..., what */`, `/* unlinked, why */`) directly above its definition"));
            continue;
        }
        let k = k.unwrap();
        skip.insert(k);
        let what = match &um {
            Some(c) => c.get(1).unwrap().as_str(),
            None => &body[lead_end..],
        };
        let what = py_strip(py_strip(what).trim_start_matches(','));
        let what = py_strip(&SPACES.replace_all(before_tags(what), " ")).to_string();
        let deep = DEEP.captures(body).map(|c| py_strip(&c[1]).to_string());
        let stuck = STUCK.captures(body).map(|c| py_strip(&c[1]).to_string());
        let unlinked = um.is_some() && addrs.is_empty();
        functions.push(((rel.to_string(), line, unit.clone(), fname, addrs, unlinked, what),
                        (deep, stuck, ROUGH.is_match(body), sf.line_of(sf.comments[k].0), fstatic, end.map(|e| e.0).unwrap_or(0), ts)));
    }
    // the data declarators, one address comment per statement (Source.model_data)
    let vars = &model.vars;
    let mut stmts: Vec<(Lc, Vec<&(i64, i64, i64, i64, String, String, bool)>)> = vec![];
    let mut at: HashMap<Lc, usize> = HashMap::new();
    for v in vars {
        match at.get(&(v.0, v.1)) {
            Some(&i) => stmts[i].1.push(v),
            None => {
                at.insert((v.0, v.1), stmts.len());
                stmts.push(((v.0, v.1), vec![v]));
            }
        }
    }
    let mut data: Vec<DataRow> = vec![];
    for ((line, col), ds) in &stmts {
        let s = sf.offset(*line, *col);
        let e = ds.iter().map(|d| sf.offset(d.2, d.3)).max().unwrap_or(s);
        let mut j = e;
        while let Some(c) = sf.char_at(&sf.code, j).filter(|&c| py_space(c)) {
            j += c.len_utf8();
        }
        let i = if sf.code.as_bytes().get(j) == Some(&b';') { j + 1 } else { e };
        let (per, unlinked) = sf.attach(s, i, ds.len(), &skip);
        for (k, d) in ds.iter().enumerate() {
            data.push((rel.to_string(), sf.line_of(s), unit.clone(), d.4.clone(), d.5.clone(), per[k].clone(), unlinked, d.6));
        }
    }
    // the integer literals cast to a pointer type: the front end's in code, PTR_CAST over the macros' bodies
    let mut ptrcasts: Vec<(String, i64, String, u64)> = vec![];
    let close = |t: String| {
        let n = t.matches('(').count() as i64 - t.matches(')').count() as i64;
        t + &")".repeat(n.max(0) as usize)
    };
    for (line, col, el, ec, lit) in model.casts.iter().cloned() {
        if let Some(v) = literal_value(lit.trim_end_matches(['u', 'U', 'l', 'L'])) {
            let t = py_words(&text[sf.offset(line, col)..sf.offset(el, ec).max(sf.offset(line, col))]);
            ptrcasts.push((rel.to_string(), line, close(t), v));
        }
    }
    for (_, _, _, s, e) in &defines {
        let body = &sf.code[*s..(*e).max(*s)];
        let mut pos = 0;
        while let Some(c) = PTR_CAST.captures_at(body, pos) {
            let all = c.name("all").unwrap();
            pos = all.end();
            if let Some(v) = literal_value(c.name("lit").unwrap().as_str()) {
                ptrcasts.push((rel.to_string(), sf.line_of(s + all.start()), close(py_words(all.as_str())), v));
            }
        }
    }
    // the object-like one-line macros: views, raw dereferencing ones (srcscan.view_macros)
    let mut vrows: Vec<ViewRow> = vec![];
    let mut rawobj: Vec<String> = vec![];
    for (name, fl, line, s, e) in &defines {
        if *fl {
            continue;
        }
        let body = py_strip(&sf.code[(s + name.len()).min(*e)..*e]);
        if body.is_empty() || body.contains('\n') {
            continue;
        }
        let bol = sf.offset(*line, 1);
        let eol = memchr::memchr(b'\n', &text.as_bytes()[bol..]).map(|x| x + bol).unwrap_or(text.len());
        let addrs = sf.comments.iter().filter(|c| bol <= c.0 && c.0 < eol).map(|c| lead_addrs(c.2).0).find(|a| !a.is_empty()).unwrap_or_default();
        let view = if let Some(v) = VIEW_BYTE.captures(body) {
            Some((v[2].to_string(), literal_value(&v[3]), false))
        } else if let Some(v) = VIEW_WHOLE.captures(body) {
            Some((v[1].to_string(), Some(0), false))
        } else {
            VIEW_ALIAS.captures(body).map(|v| (v[1].to_string(), Some(0), true))
        };
        match view {
            Some((container, Some(offset), alias)) if !addrs.is_empty() => {
                vrows.push((rel.to_string(), *line, unit.clone(), name.clone(), container, offset, addrs, alias));
            }
            _ if DEREF_OBJ.is_match(body) => {
                rawobj.push(name.clone());
                if !addrs.is_empty() {
                    err(&mut errors, *line, "L15", format!("{name} has an address comment but is no view: write it (*(T *)((char *)&CONTAINER + OFFSET)) with a byte offset"));
                }
            }
            _ => {}
        }
    }
    let mut seen: HashSet<&str> = HashSet::new();
    let mut placeholders: Vec<(String, i64, String, u64)> = vec![];
    for m in WORD.find_iter(&sf.code) {
        let w = m.as_str();
        if seen.contains(w) {
            continue;
        }
        if let Some(v) = placeholder(w) {
            seen.insert(w);
            placeholders.push((rel.to_string(), sf.line_of(m.start()), w.to_string(), v));
        }
    }
    let ad = |a: &Addrs| a.iter().map(|(t, x)| (t.clone(), *x as i64)).collect::<Vec<_>>();
    let mut defs_of: Defs = HashMap::new();
    for d in &model.decls {
        if let crate::clang::Decl::F(name, _, (l, c), _, e, Some(_), _) = d {
            defs_of.insert(name.clone(), (*l, *c, e.map(|e| e.0), e.map(|e| e.1)));
        }
    }
    let view = ScanView {
        functions: functions.iter().filter(|(a, _)| !a.4.is_empty()).map(|(a, b)| (a.0.clone(), b.3, b.5, ad(&a.4))).collect(),
        placeholders: placeholders.iter().map(|x| (x.0.clone(), x.1, x.2.clone(), format!("{:x}", x.3))).collect(),
        ptrcasts: ptrcasts.iter().map(|x| (x.0.clone(), x.1, x.2.clone(), format!("{:x}", x.3))).collect(),
        data: data.iter().map(|d| (d.0.clone(), d.1, d.4.clone(), d.3.clone(), ad(&d.5))).collect(),
        items: crate::layout::ScanItems {
            fns: functions.iter().map(|(a, b)| (a.0.clone(), a.1, b.3, b.5, a.2.clone(), a.3.clone(), b.4, ad(&a.4), b.0.clone(), b.1.clone(), b.2, a.6.clone())).collect(),
            datas: data.iter().map(|d| (d.0.clone(), d.1, d.2.clone(), d.3.clone(), d.4.clone(), d.7, ad(&d.5))).collect(),
            views: vrows.iter().map(|v| (v.0.clone(), v.1, v.2.clone(), v.3.clone(), v.4.clone(), v.5 as i64, v.7, ad(&v.6))).collect(),
            errors: errors.iter().map(|e| (e.2.clone(), e.0.clone(), e.1, e.3.clone())).collect(),
        },
    };
    let lint = views.iter().map(|(t, m)| Ok((t.clone(), crate::lint::file_lint(rel, &sf, m)?))).collect::<PyResult<Vec<_>>>()?;
    let piece = hold(Piece { view, rel: rel.to_string(), defs: defs_of, lint, sysinc: crate::lint::system_includes(text) });
    Ok(FilePart { macros, described, functions, data, ptrcasts, views: vrows, rawobj, errors, placeholders, piece })
}

#[cfg(test)]
pub(crate) mod tests {
    //! One text scanned alone, as a file no unit holds is (libclang's model of it): skipped without libclang.
    use super::*;

    pub(crate) fn scan_alone(rel: &str, text: &str) -> Option<FilePart> {
        crate::frontend::library(None)?;
        let root = std::env::temp_dir().join(format!("dcp-srcscan-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let r = root.to_string_lossy().into_owned();
        let front = crate::frontend::Front::of(&r).unwrap();
        let path = crate::project::py_path(&format!("{r}/{rel}"));
        let m = crate::frontend::parse_model(&r, &path, &front.args(&[]), text, false).unwrap();
        let model = m.files.into_iter().find(|(x, _)| x == rel).map(|x| x.1).unwrap_or_default();
        Some(scan_file_rs(rel, text, &model, &[]).unwrap())
    }

    #[test]
    fn ptr_casts() {
        // the names the code uses are declared on the first line (an expression with an undeclared name has no cast
        // for the front end: clang's recovery drops it)
        let text = "/* 0x5de460, registers the exit callback */ int atexit(void (*)(void)); char *p, *t; \
                    struct foo **q; void (__cdecl *r)(int); unsigned s; int u, full_data_6f242c, ai_OptionsFile; char *w; int U_I(unsigned);\n\
                    #define CB ((void (*)(void))0x5de471)\n\
                    #if 0\nchar *dead = (char *)0x401234;\n#endif\n\
                    int f(void)\n{\n\
                    \x20   atexit((void (*)(void))0x5de470);\n\
                    \x20   p = (char *)0x6f242c;\n\
                    \x20   q = (struct foo **)(unsigned)(0x6f2430u);\n\
                    \x20   r = (void (__cdecl *)(int))(0x401000);\n\
                    \x20   s = U_I((unsigned)&full_data_6f242c);\n\
                    \x20   t = (char *)(unsigned)&ai_OptionsFile;\n\
                    \x20   u = (int)0x5de470;\n\
                    \x20   w = \"(char *)0x5de470\";  /* (char *)0x5de470 */\n\
                    \x20   return 0;\n}\n";
        let Some(part) = scan_alone("src/sfx.c", text) else { return };
        let mut got: Vec<(i64, u64, String)> = part.ptrcasts.iter().map(|c| (c.1, c.3, c.2.clone())).collect();
        got.sort();
        assert_eq!(got, [(2, 0x5de471, "(void (*)(void))0x5de471".to_string()), (8, 0x5de470, "(void (*)(void))0x5de470".to_string()),
                         (9, 0x6f242c, "(char *)0x6f242c".to_string()), (10, 0x6f2430, "(struct foo **)(unsigned)(0x6f2430u)".to_string()),
                         (11, 0x401000, "(void (__cdecl *)(int))(0x401000)".to_string())]);
    }

    #[test]
    fn views() {
        let text = "#define rec_Count (*(int *)((char *)&records + 0x4))  /* 0x10002004 */\n\
                    #define rec_Names (*(char (*)[2][8])((char *)table + 8))  /* 0x10002008 */\n\
                    #define rec_All (*(int (*)[4])&records)  /* 0x10002000 */\n\
                    #define rec_Alias records  /* 0x10002000 */\n\
                    #define rec_Bad (*(int *)((char *)&records + 0x8))  /* 0x1000200c */\n\
                    #define rec_Elem (*(int *)(table + 1))  /* 0x10002004 */\n\
                    #define LOCAL (*(int *)&p)\n\
                    #define SIZE 0x10  /* 0x10, the record size */\n";
        let Some(part) = scan_alone("include/views.h", text) else { return };
        let got: Vec<(&str, &str, u64, Vec<(Option<String>, u64)>, bool)> =
            part.views.iter().map(|v| (v.3.as_str(), v.4.as_str(), v.5, v.6.clone(), v.7)).collect();
        let a = |x: u64| vec![(None, x)];
        assert_eq!(got, [("rec_Count", "records", 4, a(0x10002004), false), ("rec_Names", "table", 8, a(0x10002008), false),
                         ("rec_All", "records", 0, a(0x10002000), false), ("rec_Alias", "records", 0, a(0x10002000), true),
                         ("rec_Bad", "records", 8, a(0x1000200c), false)]);
        assert_eq!(part.rawobj, ["rec_Elem", "LOCAL"]);
        assert_eq!(part.errors.iter().map(|e| (e.2.as_str(), e.1)).collect::<Vec<_>>(), [("L15", 6)]); // an address comment, no byte offset
    }

    /// `ai_Unk7603a0B` is the view B of 0x7603a0 (an upper-case suffix after lower-case hex); a comment behind the
    /// second statement of a line is that statement's, not the first's.
    #[test]
    fn placeholders_and_shared_comments() {
        let Some(part) = scan_alone("src/u.c", "int x = ai_Unk7603a0B + ai_Unk430100C + FUN_0040100a + DAT_7603A0 + x_abcdef_123456 + y_abcdef;\n") else { return };
        assert_eq!(part.placeholders.iter().map(|p| p.3).collect::<Vec<_>>(), [0x7603a0, 0x430100, 0x40100a, 0x7603a0, 0x123456]);
        let part = scan_alone("src/u.c", "extern char *a; extern char *b;  /* 0x10002000 */\n").unwrap();
        let got: Vec<(&str, Vec<(Option<String>, u64)>)> = part.data.iter().map(|d| (d.3.as_str(), d.5.clone())).collect();
        assert_eq!(got, [("a", vec![]), ("b", vec![(None, 0x10002000)])]);
    }
}
