//! Declarations: decl/*.dcl, the typed state a human writes about addresses that have no source yet (ledger/decl.py
//! is its Python face and documents the grammar), and the loader rules L.decl / L.decl.start.
//!
//! native_inputs of the rules: {"targets": [names, the default first], "target": the current one}.

use crate::error::Result;
use crate::image;
use crate::rules::Ctx;
use crate::store::Out;
use regex::Regex;
use rusqlite::Connection;
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::sync::LazyLock;

static IDENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").unwrap());
static UNIT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_.\-]*$").unwrap());
static HEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^0x[0-9a-fA-F]+$").unwrap());
static PATH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"^[^\s"]+$"#).unwrap());
/// a product of argument indexes (a0: the first stack argument) and constants: `a2`, `a1*a2`, `0x60`, `4*a1`
static EXPR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(?:a\d{1,2}|\d+|0x[0-9a-fA-F]+)(?:\*(?:a\d{1,2}|\d+|0x[0-9a-fA-F]+))*$").unwrap());
static LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:(?P<target>[A-Za-z][A-Za-z0-9_-]*):)?(?P<lo>0x[0-9a-fA-F]+)(?:\.\.(?P<hi>0x[0-9a-fA-F]+))?(?:\s+(?P<body>.*?))?\s*$").unwrap()
});
/// build/tu.py LINE: a `#line N "file"` directive.
static LINE_DIRECTIVE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?m)^[ \t]*#[ \t]*line[ \t]+(\d+)(?:[ \t]+"((?:\\.|[^"\\])*)")?"#).unwrap());

#[derive(Clone, Copy, PartialEq)]
enum Shape {
    Addr,
    Unit,
    Ident,
    Path,
    Expr,
    Choice(&'static [&'static str]),
}

struct Spec {
    kind: &'static str,
    words: &'static [Shape],
    required: &'static [(&'static str, Shape)],
    optional: &'static [(&'static str, Shape)],
    range: bool,
}

/// decl.KINDS (the docs are the Python's).
const KINDS: &[Spec] = &[
    Spec { kind: "boundary", words: &[Shape::Choice(&["start", "end"])], required: &[("tu", Shape::Unit)],
           optional: &[("by", Shape::Choice(&["leaked", "tag", "guess"]))], range: false },
    Spec { kind: "bytes", words: &[Shape::Choice(&["dead"])], required: &[], optional: &[], range: true },
    Spec { kind: "jumptable", words: &[], required: &[("fn", Shape::Addr)], optional: &[], range: true },
    Spec { kind: "idxtable", words: &[], required: &[("fn", Shape::Addr)], optional: &[], range: true },
    Spec { kind: "foreign", words: &[], required: &[("kind", Shape::Ident)], optional: &[], range: true },
    Spec { kind: "name", words: &[Shape::Ident], required: &[], optional: &[], range: false },
    Spec { kind: "fptr", words: &[], required: &[], optional: &[], range: true },
    Spec { kind: "start", words: &[], required: &[], optional: &[], range: false },
    Spec { kind: "libunit", words: &[], required: &[("tu", Shape::Unit), ("lib", Shape::Path)], optional: &[], range: true },
    Spec { kind: "file", words: &[], required: &[("tu", Shape::Unit), ("path", Shape::Path)], optional: &[], range: false },
    Spec { kind: "writes", words: &[], required: &[("ptr", Shape::Expr), ("size", Shape::Expr)], optional: &[], range: false },
];

fn spec(kind: &str) -> Option<&'static Spec> {
    KINDS.iter().find(|s| s.kind == kind)
}

/// A key's value: an address or a word.
#[derive(Clone, Debug, PartialEq)]
pub enum KeyVal {
    Int(i64),
    Str(String),
}

impl KeyVal {
    pub fn s(&self) -> &str {
        match self {
            KeyVal::Str(s) => s,
            KeyVal::Int(_) => "",
        }
    }
    pub fn i(&self) -> i64 {
        match self {
            KeyVal::Int(i) => *i,
            KeyVal::Str(_) => 0,
        }
    }
}

/// decl.Decl: one declaration line.
#[derive(Clone, Debug, PartialEq)]
pub struct Decl {
    pub lo: i64,
    pub hi: i64,
    pub kind: String,
    pub words: Vec<String>,
    pub keys: Vec<(String, KeyVal)>, // in the line's order
    pub reason: String,
    pub target: Option<String>,
    pub file: String,
    pub line: i64,
}

impl Decl {
    pub fn by(&self) -> String {
        format!("decl:{}:{}", self.file, self.line)
    }
    pub fn key(&self, name: &str) -> Option<&KeyVal> {
        self.keys.iter().find(|k| k.0 == name).map(|k| &k.1)
    }
    fn sort_key(&self, order: &HashMap<String, usize>, default: &str) -> (usize, i64) {
        (*order.get(self.target.as_deref().unwrap_or(default)).unwrap_or(&order.len()), self.lo)
    }
    /// The canonical spelling (what `dcp decl add` writes).
    pub fn text(&self) -> String {
        let range = spec(&self.kind).is_some_and(|s| s.range);
        let mut s = self.target.as_ref().map(|t| format!("{t}:")).unwrap_or_default() + &format!("{:#010x}", self.lo);
        if range {
            s += &format!("..{:#010x}", self.hi);
        }
        let mut parts = vec![s, self.kind.clone()];
        parts.extend(self.words.iter().cloned());
        let mut keys: Vec<&(String, KeyVal)> = self.keys.iter().collect();
        keys.sort_by(|a, b| a.0.cmp(&b.0));
        for (k, v) in keys {
            parts.push(match v {
                KeyVal::Int(i) => format!("{k}={i:#010x}"),
                KeyVal::Str(s) => format!("{k}={s}"),
            });
        }
        parts.join(" ") + " -- " + &self.reason
    }
}

/// repr() of a str, as Python spells it.
pub(crate) fn py_repr(s: &str) -> String {
    let q = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut out = String::from(q);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == q => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push(q);
    out
}

/// repr() of bytes, as Python spells it.
pub(crate) fn py_bytes_repr(b: &[u8]) -> String {
    let q = if b.contains(&b'\'') && !b.contains(&b'"') { b'"' } else { b'\'' };
    let mut out = String::from("b");
    out.push(q as char);
    for &c in b {
        match c {
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            c if c == q => {
                out.push('\\');
                out.push(c as char);
            }
            0x20..=0x7e => out.push(c as char),
            c => out.push_str(&format!("\\x{c:02x}")),
        }
    }
    out.push(q as char);
    out
}

fn value(kind: &str, key: &str, shape: Shape, v: &str) -> Result<KeyVal, String> {
    Ok(match shape {
        Shape::Addr => {
            if !HEX.is_match(v) {
                return Err(format!("{kind}: {key}={v} is not a hex address"));
            }
            KeyVal::Int(i64::from_str_radix(&v[2..], 16).map_err(|e| e.to_string())?)
        }
        Shape::Unit => {
            if !UNIT.is_match(v) {
                return Err(format!("{kind}: {key}={v} is not a unit name ([A-Za-z_][A-Za-z0-9_.-]*)"));
            }
            KeyVal::Str(v.into())
        }
        Shape::Ident => {
            if !IDENT.is_match(v) {
                return Err(format!("{kind}: {key}={v} is not an identifier"));
            }
            KeyVal::Str(v.into())
        }
        Shape::Path => {
            if !PATH.is_match(v) {
                return Err(format!("{kind}: {key}={v} is not a path (no blanks, no quotes)"));
            }
            KeyVal::Str(v.into())
        }
        Shape::Expr => {
            if !EXPR.is_match(v) {
                return Err(format!("{kind}: {key}={v} is not an argument (a0, a1, ...), a number or a product of them (a1*a2)"));
            }
            KeyVal::Str(v.into())
        }
        Shape::Choice(c) => {
            if !c.contains(&v) {
                return Err(format!("{kind}: {key}={v} is not one of {}", c.join("|")));
            }
            KeyVal::Str(v.into())
        }
    })
}

fn py_strip(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace() || ('\x1c'..='\x1f').contains(&c))
}

/// decl.parse_line: one declaration line (no comment, not blank); Err the reason it is malformed.
pub fn parse_line(text: &str, file: &str, line: i64) -> Result<Decl, String> {
    let Some((head, reason)) = text.split_once(" -- ") else {
        if text.trim_end().ends_with(" --") || py_strip(text).ends_with("--") {
            return Err("missing reason after `--`".into());
        }
        return Err("missing reason (` -- why` ends every declaration)".into());
    };
    let reason = py_strip(reason);
    if reason.is_empty() {
        return Err("missing reason after `--`".into());
    }
    let h = py_strip(head);
    let m = LINE.captures(h).ok_or_else(|| format!("cannot parse {}: expected [TARGET:]ADDR[..END] KIND ...", py_repr(h)))?;
    let lo = i64::from_str_radix(&m["lo"][2..], 16).map_err(|e| e.to_string())?;
    let body: Vec<&str> = m.name("body").map(|b| b.as_str().split_whitespace().collect()).unwrap_or_default();
    let Some((&kind, args)) = body.split_first() else { return Err("missing kind".into()) };
    let Some(sp) = spec(kind) else {
        let mut known: Vec<&str> = KINDS.iter().map(|s| s.kind).collect();
        known.sort();
        return Err(format!("unknown kind {} (known: {})", py_repr(kind), known.join(", ")));
    };
    let hi = if sp.range {
        let Some(h) = m.name("hi") else { return Err(format!("{kind} declares a range: ADDR..END")) };
        let hi = i64::from_str_radix(&h.as_str()[2..], 16).map_err(|e| e.to_string())?;
        if hi <= lo {
            return Err(format!("empty range {lo:#x}..{hi:#x}"));
        }
        hi
    } else {
        if m.name("hi").is_some() {
            return Err(format!("{kind} declares a point: ADDR, not a range"));
        }
        lo + 1
    };
    let (mut words, mut keys): (Vec<String>, Vec<(String, KeyVal)>) = (vec![], vec![]);
    for a in args {
        if let Some((k, v)) = a.split_once('=') {
            let shape = sp.required.iter().chain(sp.optional).find(|x| x.0 == k).map(|x| x.1)
                .ok_or_else(|| format!("{kind}: unknown key {}", py_repr(k)))?;
            if keys.iter().any(|x| x.0 == k) {
                return Err(format!("{kind}: key {} given twice", py_repr(k)));
            }
            keys.push((k.to_string(), value(kind, k, shape, v)?));
        } else {
            words.push(a.to_string());
        }
    }
    if words.len() != sp.words.len() {
        let want = sp.words.iter().map(|w| match w {
            Shape::Choice(c) => c.join("|"),
            _ => "IDENT".to_string(),
        }).collect::<Vec<_>>().join(" ");
        let got = if words.is_empty() { "nothing".to_string() } else { words.join(" ") };
        return Err(format!("{kind}: expects {}, got {got}", if want.is_empty() { "no words".to_string() } else { want }));
    }
    for (w, shape) in words.iter().zip(sp.words) {
        match shape {
            Shape::Ident if !IDENT.is_match(w) => return Err(format!("{kind}: {} is not an identifier", py_repr(w))),
            Shape::Choice(c) if !c.contains(&w.as_str()) => return Err(format!("{kind}: {} is not one of {}", py_repr(w), c.join("|"))),
            _ => {}
        }
    }
    for (k, _) in sp.required {
        if !keys.iter().any(|x| x.0 == *k) {
            return Err(format!("{kind}: missing {k}="));
        }
    }
    Ok(Decl { lo, hi, kind: kind.into(), words, keys, reason: reason.into(), target: m.name("target").map(|t| t.as_str().into()), file: file.into(), line })
}

/// decl.LoadError: (file, line, lo or None, message, target or None).
#[derive(Clone, Debug, PartialEq)]
pub struct LoadError {
    pub file: String,
    pub line: i64,
    pub lo: Option<i64>,
    pub message: String,
    pub target: Option<String>,
}

fn read_lines(p: &std::path::Path) -> Vec<String> {
    let t = std::fs::read(p).map(|b| String::from_utf8_lossy(&b).replace("\r\n", "\n").replace('\r', "\n")).unwrap_or_default();
    let mut v: Vec<String> = t.split('\n').map(|s| s.to_string()).collect();
    if v.last().is_some_and(|l| l.is_empty()) {
        v.pop();
    }
    v
}

/// decl/*.dcl of a project, sorted.
pub fn files(root: &str) -> Vec<std::path::PathBuf> {
    let mut out: Vec<std::path::PathBuf> = std::fs::read_dir(std::path::Path::new(root).join("decl"))
        .map(|rd| rd.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.extension().is_some_and(|x| x == "dcl") && p.is_file()).collect())
        .unwrap_or_default();
    out.sort_by_key(|p| p.to_string_lossy().to_lowercase());
    out
}

fn rel(root: &str, p: &std::path::Path) -> String {
    match p.strip_prefix(root) {
        Ok(r) => r.to_string_lossy().replace('\\', "/"),
        Err(_) => p.to_string_lossy().replace('\\', "/"),
    }
}

/// decl.load: every declaration of the files (all targets) and the errors: malformed lines, unknown targets,
/// lines out of order, duplicate keys (across files too).
pub fn load(paths: &[std::path::PathBuf], root: &str, targets: &[String]) -> (Vec<Decl>, Vec<LoadError>) {
    let default = targets.first().cloned().unwrap_or_default();
    let order: HashMap<String, usize> = targets.iter().enumerate().map(|(i, t)| (t.clone(), i)).collect();
    let (mut out, mut errors) = (vec![], vec![]);
    let mut seen: HashMap<(String, i64, String, String), String> = HashMap::new();
    for path in paths {
        let rel = rel(root, path);
        let mut prev: Option<Decl> = None;
        for (n, raw) in read_lines(path).iter().enumerate() {
            let n = n as i64 + 1;
            let s = py_strip(raw);
            if s.is_empty() || s.starts_with('#') {
                continue;
            }
            let d = match parse_line(s, &rel, n) {
                Ok(d) => d,
                Err(e) => {
                    let head = py_strip(s.split_once(" -- ").map(|x| x.0).unwrap_or(s));
                    let t = LINE.captures(head).and_then(|m| m.name("target").map(|t| t.as_str().to_string())).filter(|t| order.contains_key(t));
                    errors.push(LoadError { file: rel.clone(), line: n, lo: None, message: e, target: t });
                    continue;
                }
            };
            if let Some(t) = &d.target {
                if !order.contains_key(t) {
                    errors.push(LoadError { file: rel.clone(), line: n, lo: Some(d.lo), message: format!("unknown target {} (targets: {})", py_repr(t), targets.join(", ")), target: None });
                    continue;
                }
            }
            if let Some(p) = &prev {
                if d.sort_key(&order, &default) < p.sort_key(&order, &default) {
                    let first = |x: &Decl| x.text().split(' ').next().unwrap_or("").to_string();
                    errors.push(LoadError { file: rel.clone(), line: n, lo: Some(d.lo),
                                            message: format!("out of order: {} after line {} ({}); the file is sorted by target, address", first(&d), p.line, first(p)),
                                            target: Some(d.target.clone().unwrap_or(default.clone())) });
                }
            }
            prev = Some(d.clone());
            let k = (d.target.clone().unwrap_or(default.clone()), d.lo, d.kind.clone(), d.words.first().cloned().unwrap_or_default());
            match seen.get(&k) {
                Some(at) => {
                    let mut what = vec![d.kind.clone()];
                    what.extend(d.words.iter().cloned());
                    errors.push(LoadError { file: rel.clone(), line: n, lo: Some(d.lo), message: format!("duplicate {} at {:#x} (also {at})", what.join(" "), d.lo),
                                            target: Some(d.target.clone().unwrap_or(default.clone())) });
                }
                None => {
                    seen.insert(k, format!("{rel}:{n}"));
                }
            }
            out.push(d);
        }
    }
    (out, errors)
}

/// unit -> its `libunit` declaration (of one target; the first per unit).
pub fn lib_units<'a>(decls: &'a [Decl], target: &str, default: &str) -> BTreeMap<String, &'a Decl> {
    let mut out = BTreeMap::new();
    for d in decls {
        if d.kind == "libunit" && d.target.as_deref().unwrap_or(default) == target {
            out.entry(d.key("tu").map(|k| k.s().to_string()).unwrap_or_default()).or_insert(d);
        }
    }
    out
}

// ------------------------------------------------------------------------------------------------ Python's face


/// decl.insert: d's canonical line into the sorted file at path, after the last declaration whose sort key is
/// not larger (before the first larger one when there is none; at the end of an empty file); its line number.
pub fn insert(path: &std::path::Path, d: &Decl, targets: &[String]) -> std::io::Result<i64> {
    let default = targets.first().cloned().unwrap_or_default();
    let order: HashMap<String, usize> = targets.iter().enumerate().map(|(i, t)| (t.clone(), i)).collect();
    let key = d.sort_key(&order, &default);
    let mut lines = if path.exists() { read_lines(path) } else { vec![] };
    let (mut after, mut before) = (None, None);
    for (i, raw) in lines.iter().enumerate() {
        let s = py_strip(raw);
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        let Ok(o) = parse_line(s, "", 0) else { continue };
        if o.sort_key(&order, &default) <= key {
            after = Some(i);
        } else if before.is_none() {
            before = Some(i);
        }
    }
    let at = after.map(|a| a + 1).or(before).unwrap_or(lines.len());
    lines.insert(at, d.text());
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, lines.join("\n") + "\n")?;
    Ok(at as i64 + 1)
}

// ------------------------------------------------------------------------------------------------ the rules

fn inputs(ctx: &Ctx) -> Result<(Vec<String>, String)> {
    Ok((ctx.inputs.targets.clone(), ctx.inputs.target.clone()))
}

/// The declarations of the project (decl.load over decl/*.dcl).
pub(crate) fn project_decls(ctx: &Ctx) -> Result<(Vec<Decl>, Vec<LoadError>, Vec<String>, String)> {
    let (targets, target) = inputs(ctx)?;
    let (ds, es) = load(&files(&ctx.root), &ctx.root, &targets);
    Ok((ds, es, targets, target))
}

/// L.decl: every declaration line of the current target as one declared fact; the lines' errors.
pub fn l_decl(ctx: &Ctx, _db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    let (decls, errors, targets, target) = project_decls(ctx)?;
    let default = targets.first().cloned().unwrap_or_default();
    let base = img.base as i64;
    let inimg = |a: i64| img.in_image(a as u32) && a >= 0;
    for e in &errors {
        if e.target.as_deref().unwrap_or(&default) != target {
            continue;
        }
        let lo = e.lo.filter(|&l| inimg(l)).unwrap_or(base);
        out.conflict("error", "L.decl", lo, lo + 1, format!("{}:{}: {}", e.file, e.line, e.message), &format!("decl:{}:{}", e.file, e.line));
    }
    let code = crate::layout::code_ranges(&img);
    let mut file_of: HashMap<String, String> = HashMap::new();
    for d in &decls {
        if d.target.as_deref().unwrap_or(&default) != target {
            continue;
        }
        let by = d.by();
        let (s_lo, s_hi) = (img.section_of(d.lo as u32), img.section_of((d.hi - 1) as u32));
        if s_lo.is_none() || s_lo.map(|s| s.index) != s_hi.map(|s| s.index) {
            let at = if inimg(d.lo) { d.lo } else { base };
            out.conflict("error", "L.decl", at, at + 1, format!("{}:{}: {:#x}..{:#x} is not inside one section of the image", d.file, d.line, d.lo, d.hi), &by);
            continue;
        }
        let is_code = code.iter().any(|&(a, b)| a <= d.lo && d.lo < b);
        let name = d.file.rsplit('/').next().unwrap_or("");
        if (name == "text.dcl" && !is_code) || (name == "data.dcl" && is_code) {
            out.conflict("error", "L.decl", d.lo, d.lo + 1,
                         format!("{}:{}: {:#x} lies in {}; text.dcl holds code sections, data.dcl the rest", d.file, d.line, d.lo, s_lo.unwrap().name), &by);
        }
        let ks = |k: &str| d.key(k).map(|v| v.s().to_string()).unwrap_or_default();
        match d.kind.as_str() {
            "boundary" => {
                let mut v = json!({"side": d.words[0], "tu": ks("tu")});
                if d.key("by").is_some() {
                    v["named_by"] = json!(ks("by"));
                }
                out.declared(d.lo, d.lo + 1, "boundary", v, &by, &d.reason);
            }
            "bytes" => out.declared(d.lo, d.hi, "symbol", json!({"skind": "dead", "extent": "declared"}), &by, &d.reason),
            "jumptable" | "idxtable" => out.declared(d.lo, d.hi, "symbol", json!({"skind": d.kind, "fn": d.key("fn").map(|v| v.i()).unwrap_or(0),
                                                                                     "extent": "declared"}), &by, &d.reason),
            "foreign" => out.declared(d.lo, d.hi, "symbol", json!({"skind": "foreign", "what": ks("kind"), "extent": "declared"}), &by, &d.reason),
            "fptr" => out.declared(d.lo, d.hi, "symbol", json!({"skind": "fptr", "extent": "declared"}), &by, &d.reason),
            "name" => out.declared(d.lo, d.lo + 1, "name", json!({"name": d.words[0], "origin": "decl"}), &by, &d.reason),
            // read by S.extent (the function's summary); checked here
            "writes" => {
                let p = ks("ptr");
                if !(p.len() > 1 && p.starts_with('a') && p[1..].bytes().all(|b| b.is_ascii_digit())) {
                    out.conflict("error", "L.decl", d.lo, d.lo + 1, format!("{}:{}: writes ptr={p}: the pointer is one argument (a0, a1, ...)", d.file, d.line), &by);
                }
                if !is_code {
                    out.conflict("error", "L.decl", d.lo, d.lo + 1, format!("{}:{}: writes at {:#x}: not a function (outside every code section)", d.file, d.line, d.lo), &by);
                }
            }
            "file" => {
                let path = ks("path");
                let mut want: Vec<u8> = path.chars().map(|c| c as u32 as u8).collect();
                want.push(0);
                let have = img.read(d.lo as u32, want.len());
                if have != want {
                    out.conflict("error", "L.decl", d.lo, d.lo + 1, format!("{}:{}: the image holds {} at {:#x}, not the declared file name {}", d.file, d.line,
                                                                             py_bytes_repr(&have), d.lo, py_bytes_repr(&want)), &by);
                }
                let tu = ks("tu");
                if let Some(f) = file_of.get(&tu) {
                    out.conflict("error", "L.decl", d.lo, d.lo + 1, format!("{}:{}: unit {tu} already has the file name {f}", d.file, d.line), &by);
                }
                file_of.entry(tu.clone()).or_insert(path.clone());
                let src = std::path::Path::new(&ctx.root).join("src").join(format!("{tu}.c"));
                if src.exists() {
                    let text = std::fs::read(&src).map(|b| String::from_utf8_lossy(&b).replace("\r\n", "\n").replace('\r', "\n")).unwrap_or_default();
                    let named: Vec<String> = LINE_DIRECTIVE.captures_iter(&text).filter_map(|m| m.get(2).map(|g| g.as_str().replace("\\\\", "\\"))).collect();
                    if !named.contains(&path) {
                        let esc = path.replace('\\', "\\\\");
                        out.conflict("error", "L.decl", d.lo, d.lo + 1,
                                     format!("{}:{}: src/{tu}.c names no file {path} in a `#line` directive (its __FILE__ is the file's own name): add `#line 1 \"{esc}\"` at its top",
                                             d.file, d.line), &by);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// L.decl.start: the current target's `start` lines inside a code section, as declared starts.
pub fn l_decl_start(ctx: &Ctx, _db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    let (decls, _, targets, target) = project_decls(ctx)?;
    let default = targets.first().cloned().unwrap_or_default();
    let code = crate::layout::code_ranges(&img);
    for d in &decls {
        if d.kind == "start" && d.target.as_deref().unwrap_or(&default) == target && code.iter().any(|&(a, b)| a <= d.lo && d.lo < b) {
            out.declared(d.lo, d.lo + 1, "start", json!({"skind": "func", "how": "decl"}), &d.by(), &d.reason);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grammar() {
        let d = parse_line("exe:0x10001000..0x10001010 jumptable fn=0x10000ff0 -- a table", "decl/text.dcl", 3).unwrap();
        assert_eq!((d.lo, d.hi, d.kind.as_str(), d.target.as_deref(), d.key("fn"), d.by()), (0x10001000, 0x10001010, "jumptable", Some("exe"),
                   Some(&KeyVal::Int(0x10000ff0)), "decl:decl/text.dcl:3".to_string()));
        assert_eq!(d.text(), "exe:0x10001000..0x10001010 jumptable fn=0x10000ff0 -- a table");
        let b = parse_line("0x10008cb0 boundary start tu=dllmain by=guess -- DllMain", "", 0).unwrap();
        assert_eq!(b.text(), "0x10008cb0 boundary start by=guess tu=dllmain -- DllMain");
        let w = parse_line("0x430bd0 writes size=a1*a2 ptr=a0 -- vfs_fread", "", 0).unwrap();
        assert_eq!(w.text(), "0x00430bd0 writes ptr=a0 size=a1*a2 -- vfs_fread");
        for (line, err) in [
            ("0x1 start", "missing reason (` -- why` ends every declaration)"),
            ("0x1 start --", "missing reason after `--`"),
            ("0x1 frob -- x", "unknown kind 'frob' (known: boundary, bytes, file, foreign, fptr, idxtable, jumptable, libunit, name, start, writes)"),
            ("0x1 writes ptr=a0 -- x", "writes: missing size="),
            ("0x1 writes ptr=a0 size=a1+a2 -- x", "writes: size=a1+a2 is not an argument (a0, a1, ...), a number or a product of them (a1*a2)"),
            ("0x1 bytes dead -- x", "bytes declares a range: ADDR..END"),
            ("0x2..0x1 bytes dead -- x", "empty range 0x2..0x1"),
            ("0x1..0x2 start -- x", "start declares a point: ADDR, not a range"),
            ("0x1 boundary middle tu=a -- x", "boundary: 'middle' is not one of start|end"),
            ("0x1 boundary start -- x", "boundary: missing tu="),
            ("0x1 boundary start tu=a tu=b -- x", "boundary: key 'tu' given twice"),
            ("0x1 name -- x", "name: expects IDENT, got nothing"),
            ("0x1..0x2 jumptable fn=12 -- x", "jumptable: fn=12 is not a hex address"),
            ("zz start -- x", "cannot parse 'zz start': expected [TARGET:]ADDR[..END] KIND ..."),
        ] {
            assert_eq!(parse_line(line, "", 0).unwrap_err(), err, "{line}");
        }
    }

    #[test]
    fn load_order_duplicates_targets() {
        let dir = std::env::temp_dir().join(format!("dcp-decl-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("decl")).unwrap();
        std::fs::write(dir.join("decl/text.dcl"), "# c\n0x20 start -- b\n0x10 start -- a\n0x10 start -- dup\nxbox:0x5 start -- t\n0x30 frob -- x\n").unwrap();
        let root = dir.to_string_lossy().into_owned();
        let (ds, es) = load(&files(&root), &root, &["exe".into()]);
        assert_eq!(ds.len(), 3);
        let m: Vec<(i64, &str)> = es.iter().map(|e| (e.line, e.message.as_str())).collect();
        assert_eq!(m[0], (3, "out of order: 0x00000010 after line 2 (0x00000020); the file is sorted by target, address"));
        assert_eq!(m[1].0, 4);
        assert!(m[1].1.starts_with("duplicate start at 0x10 (also decl/text.dcl:3)"));
        assert_eq!(m[2], (5, "unknown target 'xbox' (targets: exe)"));
        assert_eq!(m[3].0, 6);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn good_lines_round_trip() {
        let k = |pairs: &[(&str, KeyVal)]| pairs.iter().map(|(a, b)| (a.to_string(), b.clone())).collect::<Vec<_>>();
        let s = |v: &str| KeyVal::Str(v.into());
        for (line, kind, lo, hi, words, keys, target) in [
            ("0x10008cb0 boundary start tu=dllmain by=guess -- the dll's entry points", "boundary", 0x10008cb0, 0x10008cb1, vec!["start"],
             k(&[("tu", s("dllmain")), ("by", s("guess"))]), None),
            ("server:0x10008d20 boundary end tu=dllmain -- next unit", "boundary", 0x10008d20, 0x10008d21, vec!["end"], k(&[("tu", s("dllmain"))]), Some("server")),
            ("0x10001000..0x10001010 bytes dead -- unreachable tail", "bytes", 0x10001000, 0x10001010, vec!["dead"], k(&[]), None),
            ("0x10001000..0x10001004 idxtable fn=0x10000ff0 -- byte index", "idxtable", 0x10001000, 0x10001004, vec![], k(&[("fn", KeyVal::Int(0x10000ff0))]), None),
            ("0x10001000..0x10001100 foreign kind=masm -- hand-written asm", "foreign", 0x10001000, 0x10001100, vec![], k(&[("kind", s("masm"))]), None),
            ("0x10001000 name NetInit -- leaked by a log string", "name", 0x10001000, 0x10001001, vec!["NetInit"], k(&[]), None),
            ("0x10001000..0x10001008 fptr -- two handlers", "fptr", 0x10001000, 0x10001008, vec![], k(&[]), None),
            ("exe:0x401000 start -- reached through a computed jump", "start", 0x401000, 0x401001, vec![], k(&[]), Some("exe")),
            ("0x5de460..0x5de480 libunit lib=mss32.lib tu=mss32lib -- mss32.lib's code member", "libunit", 0x5de460, 0x5de480, vec![],
             k(&[("lib", s("mss32.lib")), ("tu", s("mss32lib"))]), None),
            (r"0x5fbd94 file tu=d3_interface path=D:\develop\Units\d3\d3_interface.c -- its __FILE__", "file", 0x5fbd94, 0x5fbd95, vec![],
             k(&[("tu", s("d3_interface")), ("path", s(r"D:\develop\Units\d3\d3_interface.c"))]), None),
        ] {
            let d = parse_line(line, "", 0).unwrap();
            assert_eq!((d.kind.as_str(), d.lo, d.hi, d.words.iter().map(|w| w.as_str()).collect::<Vec<_>>(), &d.keys, d.target.as_deref()),
                       (kind, lo, hi, words, &keys, target), "{line}");
            let mut back = parse_line(&d.text(), "", 0).unwrap(); // the canonical spelling parses back to the same declaration
            back.keys.sort_by(|a, b| a.0.cmp(&b.0));
            let mut sorted = d.clone();
            sorted.keys.sort_by(|a, b| a.0.cmp(&b.0));
            assert_eq!(back, sorted);
        }
    }

    #[test]
    fn bad_lines() {
        for (line, msg) in [
            ("0x10001000 boundary start tu=x --   ", "missing reason"),
            ("0x10001000 boundary start tu=x color=red -- x", "unknown key"),
            ("0x10001000 boundary start tu=x by=hunch -- x", "not one of"),
            ("0x10001000 name 9lives -- x", "identifier"),
            ("0x10001000 -- x", "missing kind"),
            ("0x10001000 file tu=x path=\"a.c\" -- x", "not a path"),
            ("0x10001000 file path=a.c -- x", "missing tu="),
        ] {
            assert!(parse_line(line, "", 0).unwrap_err().contains(msg), "{line}");
        }
    }

    #[test]
    fn load_and_insert() {
        let dir = std::env::temp_dir().join(format!("dcp-decl2-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("decl")).unwrap();
        let t: Vec<String> = vec!["tiny".into(), "other".into()];
        std::fs::write(dir.join("decl/text.dcl"), "# comment\n\n0x10002000 start -- b\n0x10001000 start -- a: out of order\n0x10002000 start -- again\n\
            0x10003000 frob -- unknown kind\nnope:0x10004000 start -- unknown target\nother:0x10000000 start -- the second target sorts after\n\
            0x10005000 start -- a default-target line after another target's\n").unwrap();
        let root = dir.to_string_lossy().into_owned();
        let (ds, es) = load(&files(&root), &root, &t);
        let at = |n: i64, m: &str| es.iter().any(|e| e.line == n && e.message.contains(m));
        assert!(at(4, "out of order") && at(5, "duplicate") && at(6, "unknown kind") && at(7, "unknown target") && at(9, "out of order"));
        assert!(!es.iter().any(|e| e.line == 8));
        assert_eq!(ds.iter().map(|d| d.line).collect::<Vec<_>>(), [3, 4, 5, 8, 9]);
        assert_eq!(ds[0].by(), "decl:decl/text.dcl:3");
        let f = dir.join("ins.dcl");
        std::fs::write(&f, "# header\n0x10001000 start -- a\n0x10003000 start -- c\nother:0x10000000 start -- o\n").unwrap();
        let ins = |line: &str| insert(&f, &parse_line(line, "", 0).unwrap(), &t).unwrap();
        assert_eq!([ins("0x10002000 start -- b"), ins("0x10000000 start -- first"), ins("other:0x20000000 start -- last"),
                    ins("0x10003000 boundary start tu=u -- same address, after")], [3, 2, 7, 6]);
        assert_eq!(read_lines(&f), ["# header", "0x10000000 start -- first", "0x10001000 start -- a", "0x10002000 start -- b", "0x10003000 start -- c",
                                    "0x10003000 boundary start tu=u -- same address, after", "other:0x10000000 start -- o", "other:0x20000000 start -- last"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reprs() {
        assert_eq!(py_repr("a'b"), "\"a'b\"");
        assert_eq!(py_bytes_repr(b"c:\\x\x00"), "b'c:\\\\x\\x00'");
    }
}
