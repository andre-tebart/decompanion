//! The reading commands (cli_read.py is their face): disasm, dump, refs, layout literals, layout fptrs, layout
//! starts. One record per line, key=value tokens, addresses 0x%08x, counts before lists; every line is a fact of the
//! store, a byte of the image, or a line of the sources. Each command returns the lines it prints (and an error
//! for stderr when it has nothing to show).

use crate::layoutview::View;
use crate::names::Names;
use crate::project::{py_path, Project};
use crate::store::{self, SFact};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::rc::Rc;

// ------------------------------------------------------------------------------------------------ the record

/// A value of a key=value token (cli.tok).
pub enum Tok {
    No,
    B(bool),
    I(i64),
    R(i64, i64),
    S(String),
}

pub fn fmt_addr(a: i64) -> String {
    if a < 0 { format!("-{:#09x}", -a) } else { format!("{a:#010x}") }
}

pub fn tok(v: &Tok) -> String {
    match v {
        Tok::No => "-".into(),
        Tok::B(b) => if *b { "yes" } else { "no" }.into(),
        Tok::I(i) => if *i >= 0x100000 { fmt_addr(*i) } else { i.to_string() },
        Tok::R(a, b) => format!("{}..{}", fmt_addr(*a), fmt_addr(*b)),
        Tok::S(s) => if s.contains(' ') || s.is_empty() { crate::decl::py_repr(s) } else { s.clone() },
    }
}

pub fn record(kv: &[(&str, Tok)]) -> String {
    kv.iter().map(|(k, v)| format!("{k}={}", tok(v))).collect::<Vec<_>>().join("  ")
}

fn s(x: impl Into<String>) -> Tok {
    Tok::S(x.into())
}

fn os(x: Option<impl Into<String>>) -> Tok {
    x.map(|v| Tok::S(v.into())).unwrap_or(Tok::No)
}

fn oi(x: Option<i64>) -> Tok {
    x.map(Tok::I).unwrap_or(Tok::No)
}

/// Python's `{x:.Ng}`.
pub fn fmt_g(x: f64, prec: usize) -> String {
    if x.is_nan() {
        return "nan".into();
    }
    if x.is_infinite() {
        return if x > 0.0 { "inf" } else { "-inf" }.into();
    }
    if x == 0.0 {
        return if x.is_sign_negative() { "-0" } else { "0" }.into();
    }
    let p = prec.max(1);
    let sci = format!("{:.*e}", p - 1, x);
    let (mant, exp) = sci.split_once('e').unwrap();
    let e: i32 = exp.parse().unwrap();
    let strip = |t: &str| -> String {
        if t.contains('.') { t.trim_end_matches('0').trim_end_matches('.').to_string() } else { t.to_string() }
    };
    if e < -4 || e >= p as i32 {
        format!("{}e{}{:02}", strip(mant), if e < 0 { '-' } else { '+' }, e.abs())
    } else {
        strip(&format!("{:.*}", (p as i32 - 1 - e).max(0) as usize, x))
    }
}

/// int(s, 16) for 0x..., else int(s, 0).
pub fn parse_addr(s: &str) -> Result<i64, String> {
    let t = s.trim();
    let bad = || format!("invalid literal for int(): {}", crate::decl::py_repr(t));
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return i64::from_str_radix(&h.replace('_', ""), 16).map_err(|_| bad());
    }
    if t.len() > 1 && t.starts_with('0') {
        return Err(bad());
    }
    t.replace('_', "").parse().map_err(|_| bad())
}

fn parse_range(s: &str) -> Result<(i64, i64), String> {
    match s.split_once("..") {
        Some((a, b)) => Ok((parse_addr(a)?, parse_addr(b)?)),
        None => {
            let a = parse_addr(s)?;
            Ok((a, a + 1))
        }
    }
}

/// str.splitlines.
fn splitlines(t: &str) -> Vec<&str> {
    let mut out = vec![];
    let mut start = 0;
    let mut it = t.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        let brk = matches!(c, '\n' | '\r' | '\x0b' | '\x0c' | '\x1c' | '\x1d' | '\x1e' | '\u{85}' | '\u{2028}' | '\u{2029}');
        if brk {
            out.push(&t[start..i]);
            let mut next = i + c.len_utf8();
            if c == '\r' {
                if let Some(&(j, '\n')) = it.peek() {
                    it.next();
                    next = j + 1;
                }
            }
            start = next;
        }
    }
    if start < t.len() {
        out.push(&t[start..]);
    }
    out
}

/// A text as Path.read_text(errors="replace") reads it (UTF-8, universal newlines).
fn read_text_locale(p: &str) -> String {
    crate::fsmemo::read_text(p).unwrap_or_default()
}

fn latin1(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

// ------------------------------------------------------------------------------------------------ the project

struct Reader<'a> {
    p: &'a Project,
    db: String,
    img: Rc<crate::pe::Image>,
    names: Names,
    capstone: String,
    fills: Vec<Vec<u8>>,
}

impl<'a> Reader<'a> {
    fn open(p: &'a Project, capstone: &str) -> PyResult<Reader<'a>> {
        let db = p.store_path();
        let main = p.main_uri();
        crate::pystore::st_open(&db, &main)?;
        let path = p.target(None).map_err(PyRuntimeError::new_err)?.path.clone();
        let img = crate::image(&path)?;
        let names = Names::build(&db, &main, &path)?;
        let fills = crate::toolchain::of(&p.toolchain_key()).map(|t| t.fill_forms().iter().map(|f| f.to_vec()).collect()).unwrap_or_default();
        Ok(Reader { p, db, img, names, capstone: capstone.into(), fills })
    }

    fn facts(&self, kind: &str) -> PyResult<Vec<Rc<SFact>>> {
        crate::with_db(&self.db, |c| store::facts_of(c, &self.db, kind, None, |_| true))
    }

    /// The facts of a kind intersecting [lo, hi), in the store's order.
    fn facts_in(&self, kind: &str, lo: i64, hi: i64) -> PyResult<Vec<Rc<SFact>>> {
        crate::with_db(&self.db, |c| store::facts_of(c, &self.db, kind, None, |f| f.hi > lo && f.lo < hi))
    }

    /// An address from `0xADDR`, a name the ledger knows, or a placeholder spelling one.
    fn resolve(&self, key: &str) -> Result<Option<i64>, String> {
        let k = key.trim();
        if k.to_lowercase().starts_with("0x") {
            return parse_addr(k).map(Some);
        }
        if let Some((_, hits)) = self.names.by_name.iter().find(|x| x.0 == k) {
            return Ok(hits.iter().min().copied());
        }
        Ok(crate::srcscan::placeholder_whole(k).map(|v| v as i64))
    }

    fn all_starts(&self) -> PyResult<Vec<i64>> {
        crate::asmcmd::all_starts(&self.db, &self.img)
    }

    /// The walked or placed function / thunk symbol covering a (not the match phase's).
    fn walk_func(&self, a: i64) -> PyResult<Option<Rc<SFact>>> {
        Ok(self.facts_in("symbol", a, a + 1)?.into_iter()
            .find(|f| matches!(f.s("skind"), Some("func" | "thunk")) && !f.rule.starts_with("M.") && f.level > store::OPEN))
    }

    fn disasm(&self, code: &[u8], va: i64) -> PyResult<Vec<(u32, u32, String, bool)>> {
        crate::x86::x86_disasm(&self.capstone, code, va as u32, self.fills.clone())
    }

    fn name(&self, a: i64) -> Option<String> {
        self.names.name_of(a).map(|s| s.to_string())
    }

    fn annotate(&self, text: &str) -> PyResult<String> {
        self.names.annotate(text)
    }
}

const LEVEL: [&str; 4] = ["open", "declared", "derived", "proven"];

type Out = (Vec<String>, Option<String>);

// ------------------------------------------------------------------------------------------------ disasm

fn disasm(r: &Reader, addr: Option<&str>, len: Option<&str>) -> PyResult<Out> {
    let mut out = vec![];
    let Some(addr) = addr else { return Ok((out, Some("ADDR (or --ours NAME) is required".into()))) };
    let target = &r.p.target_name;
    let a = r.resolve(addr).map_err(PyRuntimeError::new_err)?;
    let Some(mut a) = a.filter(|&a| r.img.section_of(a as u32).is_some()) else {
        return Ok((out, Some(format!("{addr}: no such address or name in target {target}"))));
    };
    let func = r.walk_func(a)?;
    let mut hi = if let Some(l) = len {
        if let Some(e) = l.strip_prefix("..") { parse_addr(e) } else { parse_addr(l).map(|n| a + n) }.map_err(PyRuntimeError::new_err)?
    } else if let Some(f) = &func {
        f.hi
    } else {
        let ss = r.all_starts()?;
        let i = ss.partition_point(|&x| x <= a);
        ss.get(i).copied().unwrap_or(a + 0x40).min(a + 0x400)
    };
    let sec = r.img.section_of(a as u32).unwrap();
    hi = hi.min(sec.end() as i64);
    let lines = match &func {
        Some(f) if f.lo < a => {
            let ls: Vec<_> = r.disasm(&r.img.read(f.lo as u32, (hi - f.lo).max(0) as usize), f.lo)?.into_iter().filter(|l| l.0 as i64 >= a).collect();
            if let Some(first) = ls.first() {
                if first.0 as i64 != a {
                    out.push(format!("note: {} is inside an instruction of {}: the listing starts at the next instruction, {}", fmt_addr(a),
                                     r.name(f.lo).unwrap_or_else(|| fmt_addr(f.lo)), fmt_addr(first.0 as i64)));
                    a = first.0 as i64;
                }
            }
            ls
        }
        _ => r.disasm(&r.img.read(a as u32, (hi - a).max(0) as usize), a)?,
    };
    let starts: BTreeSet<i64> = r.all_starts()?.into_iter().collect();
    out.push(record(&[("target", s(target.clone())), ("disasm", Tok::R(a, hi)), ("section", s(sec.name.clone())),
                      ("function", func.as_ref().map(|f| Tok::R(f.lo, f.hi)).unwrap_or(Tok::No)),
                      ("name", func.as_ref().and_then(|f| r.name(f.lo)).map(Tok::S).unwrap_or(Tok::No)), ("instructions", Tok::I(lines.len() as i64))]));
    let mut end = a;
    for (la, size, text, fill) in &lines {
        let la = *la as i64;
        if starts.contains(&la) {
            let hows: BTreeSet<String> = r.facts_in("start", la, la + 1)?.iter().filter_map(|f| f.s("how")).filter(|h| !h.is_empty()).map(|h| h.to_string()).collect();
            let hows = if hows.is_empty() { "symbol".to_string() } else { hows.into_iter().collect::<Vec<_>>().join(",") };
            out.push(format!("-- {}  {}  start: {hows}", fmt_addr(la), r.name(la).unwrap_or_else(|| "-".into())));
        }
        let raw = crate::fsmemo::hex(&r.img.read(la as u32, *size as usize));
        out.push(format!("   {}  {:<16} {}{}", fmt_addr(la), raw, r.annotate(text)?, if *fill { "   ; fill" } else { "" }));
        end = la + *size as i64;
    }
    if end < hi {
        out.push(format!("   {}  ({} bytes do not decode)", fmt_addr(end), hi - end));
    }
    Ok((out, None))
}

fn disasm_ours(r: &Reader, key: &str) -> PyResult<Out> {
    let Some(row) = crate::asmcmd::find_function(&r.db, key)? else {
        return Ok((vec![], Some(format!("--ours {key}: no compiled function of that name or address (dcp build)"))));
    };
    let unit = row["unit"].as_str().unwrap_or("").to_string();
    let name = row["name"].as_str().unwrap_or("").to_string();
    let addr = row["addr"].as_i64().unwrap_or(0);
    let tus = crate::compile::tu_rows(&r.db)?;
    let Some(t) = tus.get(&unit).filter(|t| t.ok) else { return Ok((vec![], Some(format!("unit {unit} has no object (dcp build)")))) };
    let root = r.p.root.to_string_lossy().into_owned();
    let obj = std::fs::read(crate::compile::obj_path(&root, &t.obj_hash)).ok().and_then(|d| crate::coff::Obj::parse(&d).ok());
    let Some((obj, k)) = obj.and_then(|o| o.function_index().get(&name).copied().map(|k| (o, k))) else {
        return Ok((vec![], Some(format!("the object of unit {unit} defines no {name}"))));
    };
    let code = obj.function_code(k);
    let relocs: BTreeMap<u32, String> = code.relocs.iter()
        .map(|(off, rel)| (*off, obj.symbol_at(rel.symbol_index).map(|s| crate::coff::undecorate(&s.name)).unwrap_or_else(|| "?".into()))).collect();
    let lines = r.disasm(&code.data, addr)?;
    let mut out = vec![record(&[("target", s(r.p.target_name.clone())), ("ours", s(name)), ("unit", s(unit)), ("at", Tok::I(addr)),
                                ("size", Tok::I(code.data.len() as i64)), ("relocations", Tok::I(relocs.len() as i64)), ("code", os(row["code"].as_str()))])];
    for (la, size, text, fill) in lines {
        let o = (la as i64 - addr) as u32;
        let hit: Vec<&str> = relocs.range(o..o + size).map(|x| x.1.as_str()).collect();
        let tail = if hit.is_empty() { String::new() } else { format!("   ; reloc {}", hit.join(", ")) };
        let bytes = crate::fsmemo::hex(&code.data[o as usize..((o + size) as usize).min(code.data.len())]);
        out.push(format!("   {}  {:<16} {text}{tail}{}", fmt_addr(la as i64), bytes, if fill { "   ; fill" } else { "" }));
    }
    Ok((out, None))
}

// ------------------------------------------------------------------------------------------------ dump

fn printable(b: u8) -> char {
    if (0x20..=0x7e).contains(&b) || b >= 0xa0 { b as char } else { '.' }
}

fn dump(r: &Reader, addr: &str, len: Option<&str>, strings: bool, dwords: bool, floats: bool) -> PyResult<Out> {
    let target = r.p.target_name.clone();
    let a = r.resolve(addr).map_err(PyRuntimeError::new_err)?;
    let Some(a) = a.filter(|&a| r.img.in_image(a as u32)) else {
        return Ok((vec![], Some(format!("{addr}: no such address or name in target {target}"))));
    };
    let n = match len { Some(l) => parse_addr(l).map_err(PyRuntimeError::new_err)?, None => 0x40 };
    let sec = r.img.section_of(a as u32);
    let mut hi = a + n;
    let mut note = None;
    if let Some(sec) = sec {
        if hi > sec.end() as i64 {
            hi = sec.end() as i64;
            note = Some(format!("at the end of {}", sec.name));
        }
    }
    let data = r.img.read(a as u32, (hi - a).max(0) as usize);
    let off = r.img.off(a as u32).map(|x| x.0);
    let mut out = vec![record(&[("target", s(target)), ("dump", Tok::R(a, hi)), ("section", s(sec.map(|x| x.name.clone()).unwrap_or_else(|| "(headers)".into()))),
                                ("rva", s(format!("{:#x}", a - r.img.base as i64))), ("file_off", os(off.map(|o| format!("{o:#x}")))), ("clipped", os(note))])];
    let raw_end = sec.map(|x| (x.va + x.raw_size) as i64).unwrap_or(hi);
    let mut starts: BTreeMap<i64, Vec<Rc<SFact>>> = BTreeMap::new();
    for f in r.facts_in("symbol", a, hi)? {
        if !f.rule.starts_with("M.") {
            starts.entry(f.lo.max(a)).or_default().push(f);
        }
    }
    let mut row = a;
    while row < hi {
        let chunk = &data[(row - a) as usize..((row - a + 16) as usize).min(data.len())];
        let mut tags = vec![];
        for s_ in row..row + chunk.len() as i64 {
            for f in starts.get(&s_).into_iter().flatten() {
                let nm = r.name(f.lo);
                tags.push(format!("{}@{:#x}{}{}", crate::setup::py_str(f.value.get("skind")), f.lo, nm.map(|n| format!("={n}")).unwrap_or_default(),
                                  if f.lo < a { format!("..{:#x}", f.hi) } else { String::new() }));
            }
        }
        let hx = chunk.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
        let asc: String = chunk.iter().map(|&b| printable(b)).collect();
        out.push(format!("{}  {:<47}  |{:<16}|{}{}", fmt_addr(row), hx, asc, if tags.is_empty() { String::new() } else { format!("  {}", tags.join(" ")) },
                         if row >= raw_end { "  (no file data)" } else { "" }));
        row += 16;
    }
    if strings {
        let mut k = 0usize;
        while k < data.len() {
            if data[k] != 0 && (k == 0 || data[k - 1] == 0) {
                let st = r.img.cstr((a + k as i64) as u32);
                if !st.is_empty() && st.iter().all(|&c| (0x20..=0x7e).contains(&c) || matches!(c, 9 | 10 | 13) || c >= 0xa0) {
                    out.push(format!("  {}", record(&[("string", Tok::I(a + k as i64)), ("length", Tok::I(st.len() as i64)), ("text", s(latin1(st)))])));
                }
                k += st.len().max(1);
                continue;
            }
            k += 1;
        }
    }
    if dwords {
        let mut k = 0usize;
        while k + 3 < data.len() {
            let u = u32::from_le_bytes([data[k], data[k + 1], data[k + 2], data[k + 3]]);
            let f = f32::from_le_bytes([data[k], data[k + 1], data[k + 2], data[k + 3]]) as f64;
            let name = if r.img.in_image(u) { r.names.label_of(u as i64)? } else { None };
            out.push(format!("  {}", record(&[("at", Tok::I(a + k as i64)), ("u32", s(format!("{u:#010x}"))), ("i32", s((u as i32).to_string())),
                                              ("f32", s(fmt_g(f, 7))), ("name", os(name))])));
            k += 4;
        }
    }
    if floats {
        let mut k = 0usize;
        while k + 3 < data.len() {
            let f = f32::from_le_bytes([data[k], data[k + 1], data[k + 2], data[k + 3]]) as f64;
            let d = (k + 8 <= data.len() && (a + k as i64) % 8 == 0).then(|| f64::from_le_bytes(data[k..k + 8].try_into().unwrap()));
            out.push(format!("  {}", record(&[("at", Tok::I(a + k as i64)), ("f32", s(fmt_g(f, 7))), ("f64", os(d.map(|d| fmt_g(d, 15))))])));
            k += 4;
        }
    }
    Ok((out, None))
}

// ------------------------------------------------------------------------------------------------ refs

/// src/**/*.c, src/**/*.h, include/**/*.h, as sorted(rglob) gives them per directory.
fn source_files(root: &str) -> Vec<String> {
    let mut out = vec![];
    for (d, pats) in [("src", vec!["*.c".to_string(), "*.h".to_string()]), ("include", vec!["*.h".to_string()])] {
        let base = py_path(&format!("{root}/{d}"));
        if Path::new(&base).exists() {
            let mut fs: Vec<String> = crate::fsmemo::walk(&base, &pats).into_iter().map(|x| x.1).collect();
            fs.sort_by_key(|p| p.to_lowercase().replace('\\', "\u{1}"));
            fs.dedup();
            out.extend(fs);
        }
    }
    out
}

fn refs(r: &Reader, what: &str) -> PyResult<Out> {
    let mut out = vec![];
    let target = r.p.target_name.clone();
    let root = r.p.root.to_string_lossy().into_owned();
    let a = r.resolve(what).map_err(PyRuntimeError::new_err)?;
    let mut idents: BTreeSet<String> = BTreeSet::new();
    match a {
        None => {
            out.push(record(&[("target", s(target)), ("refs", s(what)), ("address", Tok::No)]) + "  (no address: searching the sources for the name)");
            idents.insert(what.to_string());
        }
        Some(a) => {
            idents.extend(r.names.all_at.get(&a).into_iter().flatten().map(|x| x.0.clone()));
            if !what.to_lowercase().starts_with("0x") {
                idents.insert(what.to_string());
            }
            let src = r.facts_in("source", a, a + 1)?.into_iter().find(|f| f.lo == a && &*f.rule == "L.src");
            if let Some(f) = &src {
                idents.insert(f.s("symbol").unwrap_or("").to_string());
            }
            let sym = match r.walk_func(a)? {
                Some(f) => Some(f),
                None => r.facts_in("symbol", a, a + 1)?.into_iter().find(|f| !f.rule.starts_with("M.")),
            };
            let unit = r.facts_in("unit", a, a + 1)?.into_iter().find(|f| f.value.get("status").is_some());
            out.push(record(&[("target", s(target)), ("refs", s(what)), ("address", Tok::I(a)), ("name", os(r.name(a))),
                              ("origin", os(r.names.at.get(&a).map(|x| x.1.clone()))), ("symbol", os(sym.as_ref().and_then(|f| f.s("skind").map(|x| x.to_string())))),
                              ("extent", sym.as_ref().map(|f| Tok::R(f.lo, f.hi)).unwrap_or(Tok::No)),
                              ("level", os(sym.as_ref().map(|f| LEVEL[f.level as usize]))), ("unit", os(unit.as_ref().and_then(|f| f.s("tu").map(|x| x.to_string()))))]));
            if let Some(f) = &src {
                let file = f.s("file").unwrap_or("");
                let path = py_path(&format!("{root}/{file}"));
                let first = if Path::new(&path).exists() { read_text_locale(&path).split('\n').next().unwrap_or("").trim().to_string() } else { String::new() };
                out.push(format!("  {}", record(&[("definition", s(format!("{file}:{}", crate::setup::py_str(f.value.get("line"))))),
                                                  ("symbol", s(f.s("symbol").unwrap_or(""))), ("comment", s(first))])));
            }
            for f in r.facts_in("name", a, a + 1)?.iter().filter(|f| f.lo == a) {
                out.push(format!("  {}", record(&[("named", s(f.s("name").unwrap_or(""))), ("origin", os(f.s("origin"))), ("level", s(LEVEL[f.level as usize])),
                                                  ("by", s(f.by.clone()))])));
            }
            for f in r.facts_in("start", a, a + 1)?.iter().filter(|f| f.lo == a) {
                out.push(format!("  {}", record(&[("start", os(f.s("how"))), ("level", s(LEVEL[f.level as usize])), ("by", s(f.by.clone()))])));
            }
            let drafts = crate::with_db(&r.db, |c| crate::names::draft_values(c, &r.p.main_uri()))?;
            if let Some(d) = drafts.iter().find(|d| d["start"].as_i64() == Some(a)) {
                let name = d["name"].as_str().filter(|n| !n.is_empty());
                out.push(format!("  {}  (dcp draft {a:#x} --show)", record(&[("analyzer", s(d["analyzer"].as_str().unwrap_or(""))), ("draft", os(name)),
                                                                              ("size", oi(d["size"].as_i64())), ("source", s(d["source"].as_str().unwrap_or("")))])));
            }
            let (lo, hi) = match &sym { Some(f) if f.lo == a => (f.lo, f.hi), _ => (a, a + 1) };
            let all_refs = r.facts("ref")?;
            let to_of = |f: &SFact| f.value.get("to").and_then(|v| v.as_i64()).unwrap_or(-1);
            let mut refs_to: Vec<&Rc<SFact>> = all_refs.iter().filter(|f| to_of(f) == a || (lo <= to_of(f) && to_of(f) < hi && !(lo <= f.lo && f.lo < hi))).collect();
            let mut refs_from: Vec<Rc<SFact>> = if hi > lo + 1 { r.facts_in("ref", lo, hi)? } else { vec![] };
            out.push(format!("  refs_to={}  refs_from={}", refs_to.len(), refs_from.len()));
            refs_to.sort_by_key(|f| f.lo);
            for f in refs_to {
                let func = r.walk_func(f.lo)?;
                out.push(format!("  {}", record(&[("ref_to", os(f.s("rkind"))), ("site", Tok::I(f.lo)), ("to", Tok::I(to_of(f))), ("fn", oi(func.as_ref().map(|x| x.lo))),
                                                  ("fn_name", os(func.as_ref().and_then(|x| r.name(x.lo))))])));
            }
            refs_from.sort_by(|x, y| (x.lo, x.s("rkind")).cmp(&(y.lo, y.s("rkind"))));
            for f in refs_from {
                out.push(format!("  {}", record(&[("ref_from", os(f.s("rkind"))), ("site", Tok::I(f.lo)), ("to", Tok::I(to_of(&f))),
                                                  ("name", os(r.names.label_of(to_of(&f))?))])));
            }
        }
    }
    let words = (!idents.is_empty()).then(|| regex::Regex::new(&format!(r"\b({})\b", idents.iter().map(|i| regex::escape(i)).collect::<Vec<_>>().join("|"))).unwrap());
    let num = a.map(|a| regex::Regex::new(&format!(r"(?i)\b0x0*{a:x}\b")).unwrap());
    let mut hits = 0;
    let rel_of = |p: &str| Path::new(p).strip_prefix(&root).map(|x| x.to_string_lossy().replace('\\', "/")).unwrap_or_else(|_| p.to_string());
    let mut scan_file = |path: &str, out: &mut Vec<String>| {
        let rel = rel_of(path);
        for (i, line) in splitlines(&read_text_locale(path)).iter().enumerate() {
            if words.as_ref().is_some_and(|w| w.is_match(line)) || num.as_ref().is_some_and(|n| n.is_match(line)) {
                out.push(format!("  {rel}:{}: {}", i + 1, line.trim()));
                hits += 1;
            }
        }
    };
    for path in source_files(&root) {
        scan_file(&path, &mut out);
    }
    for path in crate::decl::files(&root) {
        scan_file(&py_path(&path.to_string_lossy()), &mut out);
    }
    out.push(format!("  source_lines={hits}  names={}", if idents.is_empty() { "-".to_string() } else { idents.into_iter().collect::<Vec<_>>().join(",") }));
    Ok((out, None))
}

// ------------------------------------------------------------------------------------------------ layout literals

struct Target {
    section: String,
    kind: &'static str,
    users: BTreeSet<i64>,
    sites: i64,
    data_refs: i64,
    size: Option<i64>,
    writable: bool,
}

/// {target address: its record} of every data address a code site refers to: through base relocations when the image
/// has them, else through the walk's memory operands and immediates; a string counts once; import slots skipped.
fn literal_targets(r: &Reader, v: &View) -> PyResult<BTreeMap<i64, Target>> {
    let img = &r.img;
    let code: Vec<(i64, i64)> = img.sections.iter().filter(|s| s.holds_code()).map(|s| (s.va as i64, s.end() as i64)).collect();
    let use_reloc = !img.relocations().is_empty();
    let mut strings: Vec<(i64, i64)> = v.syms.iter().filter(|f| f.s("skind") == Some("string")).map(|f| (f.lo, f.hi)).collect();
    strings.sort();
    let mut skip: Vec<(i64, i64)> = v.syms.iter().filter(|f| f.s("skind") == Some("iat")).map(|f| (f.lo, f.hi)).collect();
    skip.sort();
    let refs = r.facts("ref")?;
    let mut ops: Vec<(i64, i64, Option<i64>)> = refs.iter().filter(|f| f.s("rkind") == Some("operand")).map(|f| (f.lo, f.hi, f.value.get("size").and_then(|x| x.as_i64()))).collect();
    ops.sort();
    let operand_size = |site: i64| {
        let j = ops.partition_point(|o| o.0 <= site);
        (j > 0 && ops[j - 1].0 <= site && site < ops[j - 1].1).then(|| ops[j - 1].2).flatten()
    };
    let mut out: BTreeMap<i64, Target> = BTreeMap::new();
    for f in &refs {
        let rk = f.s("rkind").unwrap_or("");
        if !(if use_reloc { rk == "reloc" } else { rk == "operand" || rk == "immediate" }) {
            continue;
        }
        let mut t = f.value.get("to").and_then(|x| x.as_i64()).unwrap_or(0);
        let Some(sec) = img.section_of(t as u32) else { continue };
        if sec.holds_code() || skip.iter().any(|&(lo, hi)| lo <= t && t < hi) {
            continue;
        }
        let i = strings.partition_point(|s| s.0 <= t);
        let mut kind = "data";
        if i > 0 && strings[i - 1].0 <= t && t < strings[i - 1].1 {
            t = strings[i - 1].0;
            kind = "string";
        }
        let rec = out.entry(t).or_insert_with(|| Target { section: sec.name.clone(), kind, users: BTreeSet::new(), sites: 0, data_refs: 0, size: None,
                                                          writable: sec.writable() });
        if code.iter().any(|&(lo, hi)| lo <= f.lo && f.lo < hi) {
            if let Some(func) = v.container(f.lo) {
                rec.users.insert(func.lo);
                rec.sites += 1;
                if let Some(sz) = operand_size(f.lo).filter(|&z| z != 0) {
                    if rec.size.is_none() {
                        rec.size = Some(sz);
                    }
                }
            }
        } else {
            rec.data_refs += 1;
        }
    }
    Ok(out)
}

fn layout_literals(r: &Reader, v: &View, what: Option<&str>) -> PyResult<Out> {
    let (glo, ghi, _) = v.game;
    let mut unit = None;
    let (lo, hi) = match what {
        None => (glo, ghi),
        Some(w) if w.to_lowercase().starts_with("0x") => parse_range(w).map_err(PyRuntimeError::new_err)?,
        Some(w) => match v.units.iter().find(|u| u.tu == w) {
            Some(u) => {
                unit = Some(u.tu.clone());
                (u.lo, u.hi)
            }
            None => return Ok((vec![], Some(format!("no unit {} (dcp layout units), and not a range 0xLO..0xHI", crate::decl::py_repr(w))))),
        },
    };
    let targets = literal_targets(r, v)?;
    let utu = |a: Option<i64>| a.and_then(|a| v.unit_index(a)).map(|i| v.units[i].tu.clone());
    let pooled = |r_: &Target| r_.data_refs == 0 && !r_.users.is_empty() && (r_.kind == "string" || !r_.writable);
    let fns: Vec<i64> = v.funcs.iter().map(|f| f.lo).filter(|&a| lo <= a && a < hi).collect();
    let mine: Vec<i64> = targets.iter().filter(|(_, x)| x.users.iter().any(|&u| lo <= u && u < hi)).map(|(t, _)| *t).collect();
    let secs: BTreeSet<&str> = mine.iter().map(|t| targets[t].section.as_str()).collect();
    let mut out = vec![record(&[("target", s(r.p.target_name.clone())), ("literals", Tok::R(lo, hi)), ("unit", os(unit)), ("functions", Tok::I(fns.len() as i64)),
                                ("targets", Tok::I(mine.len() as i64)),
                                ("sections", if secs.is_empty() { Tok::No } else { s(secs.iter().copied().collect::<Vec<_>>().join(",")) })])];
    let mut by_first: HashMap<i64, Vec<i64>> = HashMap::new();
    for (t, x) in &targets {
        if !x.users.is_empty() && pooled(x) {
            by_first.entry(*x.users.iter().next().unwrap()).or_default().push(*t);
        }
    }
    for fs in &fns {
        let mut own = by_first.get(fs).cloned().unwrap_or_default();
        own.sort();
        let osecs: BTreeSet<&str> = own.iter().map(|t| targets[t].section.as_str()).collect();
        for sec in osecs {
            let ts: Vec<i64> = own.iter().copied().filter(|t| targets[t].section == sec).collect();
            let earlier: Vec<i64> = targets.iter().filter(|(_, x)| x.section == sec && pooled(x) && *x.users.iter().next().unwrap() < *fs).map(|(t, _)| *t).collect();
            let top = earlier.iter().max().copied();
            let jump = top.map(|m| ts[0] - m);
            let gap: BTreeSet<i64> = match top {
                Some(m) => targets.iter().filter(|(t, x)| x.section == sec && pooled(x) && m < **t && **t < ts[0]).map(|(_, x)| *x.users.iter().next().unwrap()).collect(),
                None => BTreeSet::new(),
            };
            let gap: Vec<i64> = gap.into_iter().collect();
            let mut between = gap.iter().take(4).map(|g| format!("{}({})", fmt_addr(*g), utu(Some(*g)).unwrap_or_else(|| "-".into()))).collect::<Vec<_>>().join(",");
            if gap.len() > 4 {
                between += &format!(",+{}", gap.len() - 4);
            }
            let jump = jump.map(|j| if j < 0 { format!("-{:#x}", -j) } else { format!("+{j:#x}") });
            out.push(format!("  {}", record(&[("fn", Tok::I(*fs)), ("unit", os(utu(Some(*fs)))), ("section", s(sec)), ("first_used", Tok::I(ts.len() as i64)),
                                              ("block", Tok::R(ts[0], ts[ts.len() - 1] + 1)), ("jump", os(jump)),
                                              ("between", if between.is_empty() { Tok::No } else { s(between) })])));
        }
    }
    for t in &mine {
        let x = &targets[t];
        let first = *x.users.iter().next().unwrap();
        let mut kv: Vec<(&str, Tok)> = vec![("lit", Tok::I(*t)), ("section", s(x.section.clone())), ("kind", s(x.kind)), ("first", Tok::I(first)),
                                            ("first_unit", os(utu(Some(first)))), ("first_in_range", Tok::B(lo <= first && first < hi)),
                                            ("users", Tok::I(x.users.len() as i64)), ("data_refs", if x.data_refs == 0 { Tok::No } else { Tok::I(x.data_refs) }),
                                            ("pooled", Tok::B(pooled(x)))];
        if x.kind == "string" {
            kv.push(("text", s(latin1(&r.img.cstr(*t as u32).iter().take(48).copied().collect::<Vec<_>>()))));
        } else if !x.writable && matches!(x.size, Some(4) | Some(8)) {
            let raw = r.img.read(*t as u32, x.size.unwrap() as usize);
            let val = if raw.len() == 4 { f32::from_le_bytes(raw[..4].try_into().unwrap()) as f64 } else { f64::from_le_bytes(raw[..8].try_into().unwrap()) };
            kv.push(("value", s(fmt_g(val, 9))));
        }
        out.push(format!("  {}", record(&kv)));
    }
    // unit blocks and interleaving among the units touching the range and their neighbours
    let mut blocks: Vec<((usize, String), (i64, i64, i64))> = vec![];
    for (t, x) in &targets {
        if !pooled(x) {
            continue;
        }
        let Some(i) = v.unit_index(*x.users.iter().next().unwrap()) else { continue };
        let k = (i, x.section.clone());
        match blocks.iter_mut().find(|b| b.0 == k) {
            Some(b) => b.1 = (b.1 .0.min(*t), b.1 .1.max(t + 1), b.1 .2 + 1),
            None => blocks.push((k, (*t, t + 1, 1))),
        }
    }
    let mut near: BTreeSet<usize> = v.units.iter().enumerate().filter(|(_, u)| u.lo < hi && lo < u.hi).map(|(i, _)| i).collect();
    let extra: Vec<usize> = near.iter().flat_map(|&i| [i.checked_sub(1), (i + 1 < v.units.len()).then_some(i + 1)]).flatten().collect();
    near.extend(extra);
    let mut sorted_blocks = blocks.clone();
    sorted_blocks.sort_by(|a, b| (&a.0 .1, a.1 .0).cmp(&(&b.0 .1, b.1 .0)));
    for ((i, sec), (blo, bhi, n)) in sorted_blocks {
        if !near.contains(&i) {
            continue;
        }
        let mut inter: Vec<&str> = blocks.iter().filter(|((j, s2), (c, d, _))| *s2 == sec && *j != i && *c < bhi && blo < *d).map(|((j, _), _)| v.units[*j].tu.as_str()).collect();
        inter.sort();
        out.push(format!("  {}", record(&[("unit_block", s(v.units[i].tu.clone())), ("section", s(sec)), ("range", Tok::R(blo, bhi)), ("literals", Tok::I(n)),
                                          ("interleaves", if inter.is_empty() { Tok::No } else { s(inter.join(",")) })])));
    }
    Ok((out, None))
}

// ------------------------------------------------------------------------------------------------ layout fptrs, starts

fn layout_fptrs(r: &Reader, v: &View, what: Option<&str>) -> PyResult<Out> {
    let starts: BTreeSet<i64> = r.all_starts()?.into_iter().collect();
    let (mut by_site, mut by_target) = (None, None);
    match what {
        None => {}
        Some(w) if w.to_lowercase().starts_with("0x") => {
            let (lo, hi) = parse_range(w).map_err(PyRuntimeError::new_err)?;
            if r.img.section_of(lo as u32).is_some_and(|s| s.holds_code()) { by_target = Some((lo, hi)) } else { by_site = Some((lo, hi)) }
        }
        Some(w) => match v.units.iter().find(|u| u.tu == w) {
            Some(u) => by_target = Some((u.lo, u.hi)),
            None => return Ok((vec![], Some(format!("no unit {} (dcp layout units), and not a range 0xLO..0xHI", crate::decl::py_repr(w))))),
        },
    }
    let mut rows: Vec<(i64, String, i64)> = vec![];
    for f in r.facts("ref")? {
        let to = f.value.get("to").and_then(|x| x.as_i64()).unwrap_or(-1);
        if f.s("rkind") != Some("reloc") || !starts.contains(&to) {
            continue;
        }
        let Some(sec) = r.img.section_of(f.lo as u32) else { continue };
        if sec.holds_code() {
            continue;
        }
        rows.push((f.lo, sec.name.clone(), to));
    }
    rows.sort();
    let mut prev: HashMap<String, i64> = HashMap::new();
    let mut lines = vec![];
    for (site, sec, to) in rows {
        let delta = prev.get(&sec).map(|p| site - p);
        prev.insert(sec.clone(), site);
        if by_site.is_some_and(|(lo, hi)| !(lo <= site && site < hi)) || by_target.is_some_and(|(lo, hi)| !(lo <= to && to < hi)) {
            continue;
        }
        lines.push(record(&[("site", Tok::I(site)), ("section", s(sec)), ("to", Tok::I(to)), ("name", os(r.name(to))),
                            ("unit", os(v.unit_index(to).map(|i| v.units[i].tu.clone()))), ("delta", oi(delta))]));
    }
    let mut out = vec![record(&[("target", s(r.p.target_name.clone())), ("fptrs", Tok::I(lines.len() as i64)), ("what", os(what))])];
    out.extend(lines.into_iter().map(|l| format!("  {l}")));
    Ok((out, None))
}

fn layout_starts(r: &Reader, v: &View, range: Option<&str>) -> PyResult<Out> {
    let (glo, ghi, _) = v.game;
    let (lo, hi) = match range { Some(x) => parse_range(x).map_err(PyRuntimeError::new_err)?, None => (glo, ghi) };
    let mut starts: BTreeMap<i64, BTreeSet<String>> = BTreeMap::new();
    for (a, fs) in &v.starts {
        for f in fs {
            starts.entry(*a).or_default().insert(f.s("how").unwrap_or("").to_string());
        }
    }
    let mut inner: BTreeSet<i64> = BTreeSet::new();
    for f in &v.funcs {
        starts.entry(f.lo).or_default();
        inner.extend(f.value.get("inner").and_then(|x| x.as_array()).into_iter().flatten().filter_map(|x| x.as_i64()));
    }
    let keys: Vec<i64> = starts.keys().copied().filter(|a| !inner.contains(a)).collect();
    let mut callers: HashMap<i64, i64> = HashMap::new();
    for f in r.facts("ref")? {
        if matches!(f.s("rkind"), Some("call" | "tail" | "immediate" | "reloc" | "operand")) {
            *callers.entry(f.value.get("to").and_then(|x| x.as_i64()).unwrap_or(-1)).or_default() += 1;
        }
    }
    let mut ends: BTreeSet<i64> = keys.iter().copied().collect();
    ends.extend(r.img.sections.iter().filter(|s| s.holds_code()).map(|s| s.end() as i64));
    let ends: Vec<i64> = ends.into_iter().collect();
    let fn_at: HashMap<i64, (i64, i64)> = v.funcs.iter().map(|f| (f.lo, (f.lo, f.hi))).collect();
    let rows: Vec<i64> = keys.iter().copied().filter(|&a| lo <= a && a < hi).collect();
    let mut out = vec![record(&[("target", s(r.p.target_name.clone())), ("starts", Tok::I(rows.len() as i64)), ("range", Tok::R(lo, hi)), ("game", Tok::R(glo, ghi))])];
    for a in rows {
        let nxt = ends.get(ends.partition_point(|&x| x <= a)).copied().unwrap_or(hi);
        let hows: Vec<&str> = starts[&a].iter().map(|h| h.as_str()).filter(|h| !h.is_empty()).collect();
        let fill = v.fills.get(&a).and_then(|x| x.get("pre")).map(|x| crate::setup::py_str(Some(x)));
        out.push(record(&[("start", Tok::I(a)), ("how", s(if hows.is_empty() { "symbol".to_string() } else { hows.join(",") })),
                          ("callers", Tok::I(callers.get(&a).copied().unwrap_or(0))), ("size", Tok::I(nxt - a)),
                          ("extent", fn_at.get(&a).map(|x| Tok::R(x.0, x.1)).unwrap_or(Tok::No)), ("fill", os(fill)),
                          ("unit", os(v.unit_index(a).map(|i| v.units[i].tu.clone()))), ("drafted", Tok::B(v.sources.contains_key(&a))),
                          ("analyzed", Tok::B(v.drafted.contains(&a))), ("name", os(r.name(a)))]));
    }
    Ok((out, None))
}

/// The body comment of a draft skeleton: the disassembly of the walk's extent at a (at most 0x400 bytes).
fn skeleton(r: &Reader, a: i64) -> PyResult<Out> {
    let func = r.walk_func(a)?;
    let hi = func.as_ref().map(|f| f.hi).unwrap_or(a + 0x40).min(a + 0x400);
    let mut out = vec![format!("    /* disassembly ({} bytes):", hi - a)];
    for (la, _, text, _) in r.disasm(&r.img.read(a as u32, (hi - a).max(0) as usize), a)? {
        out.push(format!("       {:#010x}  {}", la, r.annotate(&text)?).replace("*/", "* /"));
    }
    if let Some(f) = func.filter(|f| f.hi > hi) {
        out.push(format!("       ... {} more bytes: dcp disasm {a:#x}", f.hi - hi));
    }
    Ok((out, None))
}

// ------------------------------------------------------------------------------------------------ Python's face

/// One reading command: (the lines it prints, the error it prints instead when there is nothing to show).
/// `cmd`: disasm | disasm-ours | dump | refs | literals | fptrs | starts; `args`: its arguments by name.
#[pyfunction]
#[pyo3(signature = (project, capstone, cmd, args))]
pub fn read_command(project: PyRef<'_, crate::project::PyProject>, capstone: &str, cmd: &str, args: HashMap<String, Option<String>>) -> PyResult<Out> {
    let r = Reader::open(&project.p, capstone)?;
    let arg = |k: &str| args.get(k).cloned().flatten();
    let flag = |k: &str| arg(k).is_some_and(|v| v == "1");
    let view = || View::load(&r.db, &r.p.main_uri(), &r.p.target(None).map(|t| t.path.clone()).unwrap_or_default());
    match cmd {
        "disasm" => disasm(&r, arg("addr").as_deref(), arg("len").as_deref()),
        "disasm-ours" => disasm_ours(&r, &arg("name").unwrap_or_default()),
        "dump" => dump(&r, &arg("addr").unwrap_or_default(), arg("len").as_deref(), flag("str"), flag("dword"), flag("float")),
        "refs" => refs(&r, &arg("what").unwrap_or_default()),
        "literals" => layout_literals(&r, &view()?, arg("what").as_deref()),
        "fptrs" => layout_fptrs(&r, &view()?, arg("what").as_deref()),
        "starts" => layout_starts(&r, &view()?, arg("range").as_deref()),
        "skeleton" => skeleton(&r, parse_addr(&arg("addr").unwrap_or_default()).map_err(PyRuntimeError::new_err)?),
        _ => Err(PyRuntimeError::new_err(format!("no reading command {cmd}"))),
    }
}

/// An address from `0xADDR`, a name the ledger knows, or a placeholder spelling one; None when it is none of them.
pub fn resolve_key(p: &Project, key: &str) -> PyResult<Option<i64>> {
    Reader::open(p, "")?.resolve(key).map_err(pyo3::exceptions::PyValueError::new_err)
}

/// The body comment of a draft skeleton at a (the disassembly of the walk's extent).
pub fn skeleton_lines(p: &Project, capstone: &str, a: i64) -> PyResult<Vec<String>> {
    Ok(skeleton(&Reader::open(p, capstone)?, a)?.0)
}

#[pyfunction]
pub fn read_resolve(project: PyRef<'_, crate::project::PyProject>, key: &str) -> PyResult<Option<i64>> {
    Reader::open(&project.p, "")?.resolve(key).map_err(pyo3::exceptions::PyValueError::new_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_formats() {
        assert_eq!(fmt_g(1.5, 7), "1.5");
        assert_eq!(fmt_g(0.1, 7), "0.1");
        assert_eq!(fmt_g(1e20, 7), "1e+20");
        assert_eq!(fmt_g(1.0 / 3.0, 9), "0.333333333");
        assert_eq!(fmt_g(123456789.0, 7), "1.234568e+08");
        assert_eq!(fmt_g(0.0001, 7), "0.0001");
        assert_eq!(fmt_g(0.00001, 7), "1e-05");
        assert_eq!(tok(&Tok::I(0x401000)), "0x00401000");
        assert_eq!(tok(&Tok::I(12)), "12");
        assert_eq!(tok(&Tok::S("a b".into())), "'a b'");
        assert_eq!(splitlines("a\r\nb\rc\n"), ["a", "b", "c"]);
        assert_eq!(parse_addr("0x10").unwrap(), 16);
        assert_eq!(parse_addr("64").unwrap(), 64);
    }
}
