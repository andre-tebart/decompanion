//! Readability (docs/mental-model.md §9): H against its own standard, whatever the original was; no claim about I.
//! The rules Q1..Q6 and Q8 on a function's text, over srcscan.Source's lexing: comments and strings blanked for
//! the code tests. Positions are in characters. (Q7, the calls without a declaration, is the consistency
//! convention of §8.8: the experiment's, grade.rs.)

use regex::Regex;
use std::collections::HashSet;
use std::sync::OnceLock;

/// srcscan.Source: the text, its code with strings and comments blanked, its comments (start, end, body).
pub struct Source {
    pub text: Vec<char>,
    pub code: Vec<char>,
    pub comments: Vec<(usize, usize, String)>,
    pub line_starts: Vec<usize>,
}

impl Source {
    pub fn new(text: &str) -> Source {
        let t: Vec<char> = text.chars().collect();
        let n = t.len();
        let mut code = t.clone();
        let mut comments = vec![];
        let mut i = 0;
        while i < n {
            // TOKEN: a "..." or '...' literal on one line, a // comment, a /* */ comment; else the next position
            let end = match t[i] {
                q @ ('"' | '\'') => {
                    let mut j = i + 1;
                    loop {
                        if j >= n || t[j] == '\n' {
                            break None;
                        }
                        if t[j] == '\\' {
                            if j + 1 >= n {
                                break None;
                            }
                            j += 2;
                            continue;
                        }
                        if t[j] == q {
                            break Some(j + 1);
                        }
                        j += 1;
                    }
                }
                '/' if i + 1 < n && t[i + 1] == '/' => {
                    let mut j = i + 2;
                    while j < n && t[j] != '\n' {
                        j += 1;
                    }
                    comments.push((i, j, t[i + 2..j].iter().collect()));
                    Some(j)
                }
                '/' if i + 1 < n && t[i + 1] == '*' => {
                    let mut j = i + 2;
                    let mut e = None;
                    while j + 1 < n {
                        if t[j] == '*' && t[j + 1] == '/' {
                            e = Some(j + 2);
                            break;
                        }
                        j += 1;
                    }
                    if let Some(e) = e {
                        comments.push((i, e, t[i + 2..e - 2].iter().collect()));
                    }
                    e
                }
                _ => None,
            };
            match end {
                Some(e) => {
                    for c in code.iter_mut().take(e).skip(i) {
                        if *c != '\n' {
                            *c = ' ';
                        }
                    }
                    i = e;
                }
                None => i += 1,
            }
        }
        let mut line_starts = vec![0];
        line_starts.extend(t.iter().enumerate().filter(|(_, c)| **c == '\n').map(|(i, _)| i + 1));
        Source { text: t, code, comments, line_starts }
    }

    pub fn line_of(&self, off: usize) -> usize {
        self.line_starts.partition_point(|&s| s <= off)
    }

    /// The offset of a (line, column) position, both from 1.
    pub fn offset(&self, line: i64, col: i64) -> usize {
        let l = (line.min(self.line_starts.len() as i64) - 1).max(0) as usize;
        (self.line_starts[l] as i64 + col - 1).max(0) as usize
    }
}

macro_rules! re {
    ($name:ident, $pat:expr) => {
        fn $name() -> &'static Regex {
            static R: OnceLock<Regex> = OnceLock::new();
            R.get_or_init(|| Regex::new($pat).unwrap())
        }
    };
}

re!(deref_cast_re, r"\*\s*\(\s*(?:const\s+|volatile\s+|unsigned\s+|signed\s+|struct\s+|union\s+|enum\s+)*[A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*\s*\*+\s*(?:const\s*)?\)");

// Q4's offset pointers: a pointer made from an object plus a byte offset, the raw access spelt in two steps
// (`T *p = (T *)((char *)e + 0xc2); *p`, `(T *)(ev + 4)`, `(char *)&obj + 8`): cast to a pointer of (an object,
// itself maybe cast: group 1) plus a literal (group 2), or a byte pointer of an object plus a literal
re!(offset_cast_re, r"\(\s*(?:const\s+|volatile\s+|unsigned\s+|signed\s+|struct\s+|union\s+|enum\s+)*[A-Za-z_]\w*\s*\*+\s*\)\s*\(\s*(\(\s*(?:const\s+|unsigned\s+|signed\s+)*[A-Za-z_]\w*\s*\*+\s*\)\s*)?&?\s*[A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)*\s*\+\s*(0[xX][0-9a-fA-F]+|\d+)[uUlL]*\s*\)");
re!(byte_offset_re, r"\(\s*(?:const\s+)?(?:unsigned\s+|signed\s+)?char\s*\*\s*\)\s*&?\s*[A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)*\s*\+\s*(?:0[xX][0-9a-fA-F]+|\d+)");

/// The offset pointers of a function's code (offset_cast_re, byte_offset_re) that no `*(T *)` dereference already
/// counts: a cast right after a `*` is that dereference, a byte offset inside a cast one is the same access. A
/// typed pointer one past itself (`(char *)(hdr + 1)`, the payload after a header) is no offset.
fn offset_pointers(code: &str) -> usize {
    let mut spans: Vec<(usize, usize)> = vec![];
    let mut n = 0;
    for c in offset_cast_re().captures_iter(code) {
        let m = c.get(0).unwrap();
        spans.push((m.start(), m.end()));
        let past_one = c.get(1).is_none() && literal_value(&c[2]) == Some(1);
        if !past_one && !code[..m.start()].trim_end().ends_with('*') {
            n += 1;
        }
    }
    for m in byte_offset_re().find_iter(code) {
        if !spans.iter().any(|&(a, b)| a <= m.start() && m.end() <= b) {
            n += 1;
        }
    }
    n
}

const Q4_VIEW: &str = "a typed field, struct or symbol instead; a datum read as another type is a view: \
`#define NAME (*(T *)&datum)  /* 0xADDR */`, `(*(T *)((char *)&datum + OFF))` or `(*(T *)(array + N))` with the address comment \
on its line; `(*(T *)datum)` reads through the datum's value and stays raw";

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// IDENT.findall: the words (maximal runs of word characters) that start with a letter or `_`.
fn idents(code: &str) -> Vec<&str> {
    let mut out = vec![];
    let mut start: Option<usize> = None;
    for (i, c) in code.char_indices().chain(std::iter::once((code.len(), ' '))) {
        match (start, is_word(c)) {
            (None, true) => start = Some(i),
            (Some(s), false) => {
                let b = code.as_bytes()[s];
                if b.is_ascii_alphabetic() || b == b'_' {
                    out.push(&code[s..i]);
                }
                start = None;
            }
            _ => {}
        }
    }
    out
}

/// MARKER.finditer's group 1: the marker words standing as whole words.
fn markers(text: &str, out: &mut HashSet<String>) {
    for w in ["ROUGH", "SKELETON", "TODO", "FIXME", "XXX"] {
        for (i, _) in text.match_indices(w) {
            let before = text[..i].chars().next_back();
            let after = text[i + w.len()..].chars().next();
            if !before.is_some_and(is_word) && !after.is_some_and(is_word) {
                out.insert(w.to_string());
                break;
            }
        }
    }
}

fn is_hex(c: char) -> bool {
    c.is_ascii_hexdigit()
}

/// grade.PLACEHOLDER.search(w) for an identifier.
pub fn is_placeholder(w: &str) -> bool {
    if w.is_ascii() {
        return is_placeholder_ascii(w.as_bytes());
    }
    is_placeholder_chars(w)
}

/// is_placeholder of an ASCII word, without allocating.
fn is_placeholder_ascii(c: &[u8]) -> bool {
    let n = c.len();
    let hex = |x: &u8| x.is_ascii_hexdigit();
    let digit = |x: &u8| x.is_ascii_digit();
    if c.windows(7).any(|s| &s[..3] == b"Unk" && s[3..].iter().all(hex)) {
        return true;
    }
    let all_word = c.iter().all(|x| x.is_ascii_alphanumeric() || *x == b'_');
    if n >= 7 && all_word && (c[0].is_ascii_alphabetic() || c[0] == b'_') && c[n - 6..].iter().all(hex) && c.iter().any(digit) {
        return true;
    }
    if let Some(r) = c.strip_prefix(b"param_") {
        if !r.is_empty() && r.iter().all(digit) {
            return true;
        }
    }
    if let Some(p) = c.windows(3).position(|s| s == b"Var") {
        let (pre, post) = (&c[..p], &c[p + 3..]);
        if (1..=3).contains(&pre.len()) && pre.iter().all(|x| x.is_ascii_lowercase()) && !post.is_empty() && post.iter().all(digit) {
            return true;
        }
    }
    if let Some(r) = c.strip_prefix(b"local_") {
        if !r.is_empty() && r.iter().all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(x)) {
            return true;
        }
    }
    let u = c.strip_prefix(b"_").unwrap_or(c);
    for p in [&b"DAT_"[..], b"PTR_", b"FUN_", b"LAB_"] {
        if let Some(r) = u.strip_prefix(p) {
            if !r.is_empty() && r.iter().all(hex) {
                return true;
            }
        }
    }
    if let Some(r) = c.strip_prefix(b"unk") {
        let r = r.strip_prefix(b"_").unwrap_or(r);
        if (1..=8).contains(&r.len()) && r.iter().all(hex) {
            return true;
        }
    }
    false
}

fn is_placeholder_chars(w: &str) -> bool {
    let c: Vec<char> = w.chars().collect();
    // Unk + 4 hex digits anywhere
    for i in 0..c.len().saturating_sub(2) {
        if c[i] == 'U' && c[i + 1] == 'n' && c[i + 2] == 'k' && c.len() >= i + 7 && c[i + 3..i + 7].iter().all(|&x| is_hex(x)) {
            return true;
        }
    }
    let all_word = c.iter().all(|&x| is_word(x));
    let n = c.len();
    // ^(?=.*\d)[A-Za-z_]\w*?[0-9a-fA-F]{6}$
    if n >= 7 && all_word && (c[0].is_ascii_alphabetic() || c[0] == '_') && c[n - 6..].iter().all(|&x| is_hex(x))
        && c.iter().any(|x| x.is_ascii_digit()) {
        return true;
    }
    let digits = |s: &[char]| !s.is_empty() && s.iter().all(|x| x.is_ascii_digit());
    let hexes = |s: &[char]| !s.is_empty() && s.iter().all(|&x| is_hex(x));
    if let Some(r) = w.strip_prefix("param_") {
        if digits(&r.chars().collect::<Vec<_>>()) {
            return true;
        }
    }
    // ^[a-z]{1,3}Var\d+$
    if let Some(p) = w.find("Var") {
        let pre: Vec<char> = w[..p].chars().collect();
        let post: Vec<char> = w[p + 3..].chars().collect();
        if (1..=3).contains(&pre.len()) && pre.iter().all(|x| x.is_ascii_lowercase()) && digits(&post) {
            return true;
        }
    }
    if let Some(r) = w.strip_prefix("local_") {
        let r: Vec<char> = r.chars().collect();
        if !r.is_empty() && r.iter().all(|x| x.is_ascii_digit() || ('a'..='f').contains(x)) {
            return true;
        }
    }
    let u = w.strip_prefix('_').unwrap_or(w);
    for p in ["DAT_", "PTR_", "FUN_", "LAB_"] {
        if let Some(r) = u.strip_prefix(p) {
            if hexes(&r.chars().collect::<Vec<_>>()) {
                return true;
            }
        }
    }
    if let Some(r) = w.strip_prefix("unk") {
        let r = r.strip_prefix('_').unwrap_or(r);
        let r: Vec<char> = r.chars().collect();
        if (1..=8).contains(&r.len()) && hexes(&r) {
            return true;
        }
    }
    false
}

/// grade.LITERAL.finditer: the integer literals (group 1) of the code.
fn literals(code: &[char]) -> Vec<String> {
    let n = code.len();
    let mut out = vec![];
    let mut i = 0;
    while i < n {
        let prev_ok = i == 0 || !(is_word(code[i - 1]) || code[i - 1] == '.');
        if !prev_ok || !code[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let mut e = i;
        while e < n && is_word(code[e]) {
            e += 1;
        }
        if e < n && code[e] == '.' {
            i = e;
            continue;
        }
        let w = &code[i..e];
        // (0[xX][0-9a-fA-F]+|\d+)[uUlL]*, the whole word
        let suffix = |k: usize| w[k..].iter().all(|c| matches!(c, 'u' | 'U' | 'l' | 'L'));
        let mut got = None;
        if w.len() > 2 && w[0] == '0' && (w[1] == 'x' || w[1] == 'X') {
            let mut k = 2;
            while k < w.len() && is_hex(w[k]) {
                k += 1;
            }
            if k > 2 && suffix(k) {
                got = Some(k);
            }
        }
        if got.is_none() {
            let mut k = 0;
            while k < w.len() && w[k].is_ascii_digit() {
                k += 1;
            }
            if k > 0 && suffix(k) {
                got = Some(k);
            }
        }
        if let Some(k) = got {
            out.push(w[..k].iter().collect());
        }
        i = e;
    }
    out
}

fn literal_value(s: &str) -> Option<u128> {
    if s.starts_with("0x") || s.starts_with("0X") {
        u128::from_str_radix(&s[2..], 16).ok()
    } else if s.len() > 1 && s.starts_with('0') {
        u128::from_str_radix(s, 8).ok()
    } else {
        s.parse::<u128>().ok()
    }
}

/// What readability reads of one function besides its file.
pub struct Fn<'a> {
    pub name: &'a str,
    pub comment: i64,
    pub end: i64, // 0: none
    pub rough: bool,
    pub def: Option<(i64, i64, Option<(i64, i64)>)>, // the front end's definition: start, end
}

pub struct Context<'a> {
    pub raw: &'a HashSet<String>,
    pub described: &'a HashSet<i64>,
    pub range: (i64, i64),
}

/// grade.readability: (readable | draft, the failing rules) of one function, its file lexed (None: the file is gone).
pub fn readability(src: Option<&Source>, f: &Fn, addr: i64, cx: &Context) -> (String, Vec<String>) {
    let Some(s) = src else { return ("draft".into(), vec!["the source is gone".into()]) };
    let Some((sl, sc, e)) = f.def else { return ("draft".into(), vec!["definition not found by the parser".into()]) };
    let off = s.offset(sl, sc);
    let end = match e {
        Some((el, ec)) => s.offset(el, ec),
        None => s.code.len(),
    };
    let codev: &[char] = if off < end.min(s.code.len()) { &s.code[off..end.min(s.code.len())] } else { &[] };
    let code: String = codev.iter().collect();
    let mut fails = vec![];
    if is_placeholder(f.name) {
        fails.push(format!("Q1 name: {} is a placeholder", f.name));
    }
    let words = idents(&code);
    let mut idents: Vec<&str> = words.iter().copied().filter(|w| *w != f.name && is_placeholder(w)).collect::<HashSet<_>>().into_iter().collect();
    idents.sort();
    if !idents.is_empty() {
        let mut t = format!("Q2 identifiers: {}", idents[..idents.len().min(8)].join(", "));
        if idents.len() > 8 {
            t += &format!(" (+{} more)", idents.len() - 8);
        }
        fails.push(t);
    }
    let (lo, hi) = cx.range;
    let mut lits: Vec<String> = vec![];
    for l in literals(codev) {
        let Some(v) = literal_value(&l) else { continue };
        if lo as u128 <= v && v < hi as u128 && !lits.contains(&l) {
            lits.push(l);
        }
    }
    if !lits.is_empty() {
        fails.push(format!("Q3 addresses: {}", lits[..lits.len().min(6)].join(", ")));
    }
    let casts = deref_cast_re().find_iter(&code).count();
    let offsets = offset_pointers(&code);
    let mut macros: Vec<&str> = words.iter().copied().filter(|w| cx.raw.contains(*w)).collect::<HashSet<_>>().into_iter().collect();
    macros.sort();
    if casts > 0 || offsets > 0 || !macros.is_empty() {
        let mut parts = vec![];
        if casts > 0 {
            parts.push(format!("{casts} x `*(T *)`"));
        }
        if offsets > 0 {
            parts.push(format!("{offsets} x offset pointer `(T *)((char *)p + N)`"));
        }
        parts.extend(macros.iter().map(|m| format!("macro {m}")));
        fails.push(format!("Q4 raw access: {} ({Q4_VIEW})", parts.join(", ")));
    }
    // the comments are in offset order: the first that starts on the comment line, the ones inside the definition
    let from = |o: usize| s.comments.partition_point(|c| c.0 < o);
    let first = match f.comment {
        l if l >= 1 && (l as usize) <= s.line_starts.len() => {
            let lo = s.line_starts[l as usize - 1];
            let hi = s.line_starts.get(l as usize).copied().unwrap_or(usize::MAX);
            s.comments.get(from(lo)).filter(|c| c.0 < hi).map(|c| c.2.as_str()).unwrap_or("")
        }
        _ => "",
    };
    let mut texts: Vec<&str> = vec![first];
    if off < end {
        texts.extend(s.comments[from(off)..from(end)].iter().map(|c| c.2.as_str()));
    }
    texts.push(&code);
    let mut found = HashSet::new();
    for t in &texts {
        markers(t, &mut found);
    }
    let mut marks: Vec<String> = found.into_iter().collect();
    marks.sort();
    if f.rough {
        marks.push("@rough".into());
    }
    if !marks.is_empty() {
        fails.push(format!("Q5 markers: {}", marks.join(", ")));
    }
    if !cx.described.contains(&addr) {
        fails.push("Q6 described: no text after the address at the definition, nor at the declaration in its owner header (include/<unit>.h)".into());
    }
    (if fails.is_empty() { "readable" } else { "draft" }.into(), fails)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn q4_offset_pointers() {
        // a match-base session's spellings: the raw access in two steps
        assert_eq!(offset_pointers("unsigned short *goodId = (unsigned short *)((char *)e + 0xc2); r = f(*goodId);"), 1);
        assert_eq!(offset_pointers("int *handle = (int *)((char *)e + 0xb0); duration = (int *)(r + 4);"), 2);
        assert_eq!(offset_pointers("unsigned char *stepCount = (unsigned char *)e + 0xba;"), 1);
        assert_eq!(offset_pointers("p = (AITIME *)(e->rec + 0x10); q = (char *)&obj + 8;"), 2);
        // a dereference cast is counted by `*(T *)` already, its operand is no second access
        assert_eq!(offset_pointers("x = *(int *)(ev + 0x84) + *(short *)((char *)&obj + 2);"), 0);
        // typed accesses and pointer arithmetic without a cast stay readable
        assert_eq!(offset_pointers("e->end = net_Time; p = list + 4; q = (char *)name; n = (int)(a + 4);"), 0);
        // the payload after a header: a typed pointer one past itself
        assert_eq!(offset_pointers("slot = (int *)(p + 1); d->data = (char *)(d + 1); v->items = (SBDATA *)(v + 1);"), 0);
        assert_eq!(offset_pointers("s = (char *)((char *)map + 1);"), 1);
    }
}
