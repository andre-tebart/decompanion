//! The native layout rules (rules/layout.py keeps their criteria as docstrings).

use crate::rules::Ctx;
use crate::store::{self, Out, SFact, DECLARED, OPEN};
use crate::image;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use rusqlite::Connection;
use std::collections::{HashMap, HashSet};

fn err(e: rusqlite::Error) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

// ------------------------------------------------------------------------------------------------ the game code

/// layout.code_ranges: the code sections, sorted.
pub fn code_ranges(img: &crate::pe::Image) -> Vec<(i64, i64)> {
    let mut rs: Vec<(i64, i64)> = img.sections.iter().filter(|s| s.holds_code())
        .map(|s| (s.va as i64, s.va as i64 + s.vsize.max(1) as i64)).collect();
    rs.sort();
    rs
}

/// layout.lib_starts_of: placed library members (unit lib:...) and import thunks among symbol facts.
pub fn lib_starts_of(facts: &[std::rc::Rc<SFact>]) -> Vec<i64> {
    facts.iter().filter(|f| match f.s("skind") {
        Some("thunk") => true,
        Some("func") => f.s("unit").is_some_and(|u| u.starts_with("lib:")),
        _ => false,
    }).map(|f| f.lo).collect()
}

/// layout.game_range without its level: (lo, hi) of the game code.
pub fn game_range(img: &crate::pe::Image, lib_starts: &[i64]) -> (i64, i64) {
    let rs = code_ranges(img);
    if rs.is_empty() {
        return (img.base as i64, img.base as i64);
    }
    let lo = rs[0].0;
    match lib_starts.iter().filter(|&&a| rs.iter().any(|&(l, h)| l <= a && a < h)).min() {
        Some(&m) => (lo, m),
        None => (lo, rs[rs.len() - 1].1),
    }
}

// ------------------------------------------------------------------------------------------------ the drafts

/// An analyzer's function (analyzers/base.Entry, the fields L9 reads; the pseudocode is skipped unread).
#[derive(Default, serde::Deserialize)]
#[serde(default)]
struct Draft {
    start: i64,
    name: String,
    size: Option<i64>,
    ranges: Vec<(i64, i64)>,
    source: String,
    analyzer: String,
}

/// ledger/drafts.entries: every draft blob, the main store's first (ctx.main: a worktree's overlay), sorted by start.
fn drafts(ctx: &Ctx, db: &Connection) -> PyResult<Vec<Draft>> {
    let mut sources = vec![];
    if !ctx.main.is_empty() {
        let attached: bool = db.query_row("SELECT count(*) FROM pragma_database_list WHERE name='main_store'", [], |r| r.get::<_, i64>(0))
            .map_err(err)? > 0;
        if !attached {
            db.execute("ATTACH DATABASE ? AS main_store", [&ctx.main]).map_err(err)?;
        }
        sources.push("main_store.blob");
    }
    sources.push("blob");
    let mut by_hash: Vec<Draft> = vec![];
    let mut at: HashMap<String, usize> = HashMap::new();
    for t in sources {
        let mut st = db.prepare(&format!("SELECT hash, data FROM {t} WHERE kind='drafts'")).map_err(err)?;
        let mut q = st.query([]).map_err(err)?;
        while let Some(r) = q.next().map_err(err)? {
            let h: String = r.get(0).map_err(err)?;
            let d: Draft = serde_json::from_slice(r.get_ref(1).map_err(err)?.as_blob().map_err(|e| PyRuntimeError::new_err(e.to_string()))?)
                .map_err(|e| PyRuntimeError::new_err(format!("drafts: {e}")))?;
            match at.get(&h) {
                Some(&i) => by_hash[i] = d,
                None => {
                    at.insert(h, by_hash.len());
                    by_hash.push(d);
                }
            }
        }
    }
    let mut by_start: HashMap<i64, Draft> = HashMap::new();
    for d in by_hash {
        by_start.insert(d.start, d);
    }
    let mut out: Vec<Draft> = by_start.into_values().collect();
    out.sort_by_key(|d| d.start);
    Ok(out)
}

// ------------------------------------------------------------------------------------------------ L9

/// L9.analyzer.span: an analyzer's function of the game code whose body holds one of our starts other than its entry.
pub fn l9_analyzer_span(ctx: &Ctx, db: &Connection, out: &mut Out) -> PyResult<()> {
    let img = image(&ctx.image)?;
    // our_starts: {start: how} (a later fact of the same start wins), function / thunk symbols above open
    let mut ours: HashMap<i64, String> = HashMap::new();
    for f in store::facts(db, &ctx.db, "start", &ctx.needed, |_| true).map_err(err)? {
        ours.insert(f.lo, f.s("how").unwrap_or("").to_string());
    }
    let symbols = store::facts(db, &ctx.db, "symbol", &ctx.needed, |_| true).map_err(err)?;
    let mut inner: HashSet<i64> = HashSet::new();
    for f in &symbols {
        if matches!(f.s("skind"), Some("func") | Some("thunk")) && f.level > OPEN {
            ours.entry(f.lo).or_insert_with(|| "symbol".to_string());
            if let Some(a) = f.value.get("inner").and_then(|v| v.as_array()) {
                inner.extend(a.iter().filter_map(|x| x.as_i64()));
            }
        }
    }
    let mut keys: Vec<i64> = ours.keys().copied().filter(|a| !inner.contains(a)).collect();
    keys.sort();
    let (glo, ghi) = game_range(&img, &lib_starts_of(&symbols));
    for e in drafts(ctx, db)? {
        if !(glo <= e.start && e.start < ghi) {
            continue;
        }
        let mut hits = vec![];
        for &(lo, hi) in &e.ranges {
            let mut i = keys.partition_point(|&k| k < lo);
            while i < keys.len() && keys[i] < hi {
                if keys[i] != e.start {
                    hits.push(keys[i]);
                }
                i += 1;
            }
        }
        if hits.is_empty() {
            continue;
        }
        hits.sort();
        let listed: Vec<String> = hits.iter().take(6).map(|a| format!("{:#x} ({})", a, ours[a])).collect();
        let more = if hits.len() > 6 { format!(" (+{} more)", hits.len() - 6) } else { String::new() };
        let size = e.size.map(|s| s.to_string()).unwrap_or_else(|| "None".to_string());
        let name = if e.name.is_empty() { "-" } else { &e.name };
        let hi = e.ranges.iter().map(|r| r.1).max().unwrap_or(0);
        out.conflict("warn", "L9", e.start, hi,
                     format!("{}'s function {:#x} ({name}, {size} bytes) spans our start{} {}{more}: its draft holds more than one function",
                             e.analyzer, e.start, if hits.len() > 1 { "s" } else { "" }, listed.join(", ")),
                     &format!("decl:analyzer:{}:{}", e.analyzer, e.source));
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ L.src.extent

/// Python's bisect.bisect_right on any list (claimed's starts: the symbols sorted, then the regions sorted, the
/// whole not sorted; the search must probe as Python's does).
fn py_bisect_right(a: &[i64], x: i64) -> usize {
    let (mut lo, mut hi) = (0, a.len());
    while lo < hi {
        let mid = (lo + hi) / 2;
        if x < a[mid] {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    lo
}

/// L.src.extent: a sourced function no other function covers owns its code up to the next stop, less the fill.
pub fn l_src_extent(ctx: &Ctx, db: &Connection, out: &mut Out) -> PyResult<()> {
    let img = image(&ctx.image)?;
    let extra: serde_json::Value = serde_json::from_str(&ctx.extra).unwrap_or(serde_json::Value::Null);
    let align = extra["function_alignment"].as_i64().unwrap_or(1).max(1);
    let forms = crate::compare::fill_order(&ctx.fill_forms);
    let code: Vec<(i64, i64)> = img.sections.iter().filter(|s| s.holds_code()).map(|s| (s.va as i64, s.end() as i64)).collect();
    let in_code = |a: i64| code.iter().any(|&(lo, hi)| lo <= a && a < hi);
    let fs = |kind: &str| store::facts(db, &ctx.db, kind, &ctx.needed, |_| true).map_err(err);
    let symbols = fs("symbol")?;
    let sources = fs("source")?;
    let mut claimed: Vec<(i64, i64)> = symbols.iter().filter(|f| f.level > OPEN).map(|f| (f.lo, f.hi)).collect();
    claimed.sort();
    let mut regions: Vec<(i64, i64)> = fs("region")?.iter().map(|f| (f.lo, f.hi)).collect();
    regions.sort();
    claimed.extend(regions);
    let mut stops: Vec<i64> = fs("start")?.iter().map(|f| f.lo).collect();
    stops.extend(fs("boundary")?.iter().map(|f| f.lo));
    stops.extend(claimed.iter().map(|c| c.0));
    stops.extend(code.iter().map(|c| c.1));
    stops.sort();
    stops.dedup();
    let los: Vec<i64> = claimed.iter().map(|c| c.0).collect();
    let is_match = |f: &SFact| &*f.rule == "M.match" && f.s("what") == Some("match");
    let mut ends: Vec<i64> = symbols.iter().filter(|f| f.level > OPEN && in_code(f.lo)).map(|f| f.hi).collect();
    ends.extend(sources.iter().filter(|f| is_match(f)).map(|f| f.hi));
    let match_hi: HashMap<i64, i64> = sources.iter().filter(|f| is_match(f)).map(|f| (f.lo, f.hi)).collect();
    let mut pad: HashMap<i64, i64> = HashMap::new();
    for f in symbols.iter().filter(|f| &*f.rule == "M.match") {
        if *match_hi.get(&f.lo).unwrap_or(&f.hi) > f.hi {
            pad.insert(f.hi, match_hi[&f.lo]);
        }
    }
    // the facts are in (lo, ...) order already: the sort by lo keeps it
    for s in sources.iter().filter(|f| &*f.rule == "L.src" && f.s("what") == Some("func")) {
        let a = s.lo;
        if !in_code(a) {
            continue;
        }
        let i = py_bisect_right(&los, a) as i64 - 1;
        if i >= 0 && claimed[(i - 8).max(0) as usize..=i as usize].iter().any(|&(lo, hi)| lo <= a && a < hi) {
            continue; // the walk, a match or a library member owns it already
        }
        let j = stops.partition_point(|&x| x <= a);
        let end = if j < stops.len() { stops[j] } else { a };
        if end <= a {
            continue;
        }
        let data = img.read(a as u32, (end - a) as usize);
        let mut cut = data.len();
        for k in data.len().saturating_sub((align - 1) as usize)..data.len() {
            if crate::compare::is_fill(&data[k..], &forms) {
                cut = k;
                break;
            }
        }
        if cut == 0 {
            continue;
        }
        let v = &s.value;
        out.fact(a, a + cut as i64, "symbol", serde_json::json!({"skind": "func", "extent": "source", "name": v["symbol"],
                                                                  "unit": v["unit"], "file": v["file"]}), DECLARED);
        if cut < data.len() {
            out.fact(a + cut as i64, end, "symbol", serde_json::json!({"skind": "fill", "extent": "source"}), DECLARED);
        }
    }
    // the gap after any claimed code up to the next stop: a match's proven padding, then alignment fill
    ends.sort();
    ends.dedup();
    for e in ends {
        let j = stops.partition_point(|&x| x < e);
        let stop = if j < stops.len() { stops[j] } else { e };
        if stop <= e || stop > e + align - 1 {
            continue;
        }
        let p = (*pad.get(&e).unwrap_or(&e)).min(stop);
        if p > e {
            out.fact(e, p, "symbol", serde_json::json!({"skind": "fill", "extent": "matched"}), DECLARED);
        }
        if stop > p && crate::compare::is_fill(&img.read(p as u32, (stop - p) as usize), &forms) {
            out.fact(p, stop, "symbol", serde_json::json!({"skind": "fill", "extent": "source"}), DECLARED);
        }
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ the source scan

/// srcscan's items as native_inputs hands them over (srcscan.native_view): values as hex text (a placeholder
/// may spell more digits than any integer type holds).
#[derive(Default, serde::Deserialize)]
#[serde(default)]
struct ScanView {
    functions: Vec<(String, i64, i64, Vec<(Option<String>, i64)>)>, // file, comment line, end line, addrs
    placeholders: Vec<(String, i64, String, String)>,              // file, line, ident, value
    ptrcasts: Vec<(String, i64, String, String)>,                  // file, line, text, value
    data: Vec<(String, i64, String, String, Vec<(Option<String>, i64)>)>, // file, line, kind, name, addrs
}

/// What the scan rules get from Python: the targets (the default first), the current one, the images' paths.
#[derive(Default, serde::Deserialize)]
#[serde(default)]
struct ScanInputs {
    targets: Vec<String>,
    target: String,
    images: HashMap<String, String>,
    scan: ScanView,
}

thread_local! {
    // the latest scan inputs as parsed, by their text (L5, A1 and L13 of one refresh get the same text)
    static SCAN: std::cell::RefCell<Option<(String, std::rc::Rc<ScanInputs>)>> = const { std::cell::RefCell::new(None) };
}

fn scan_inputs(ctx: &Ctx) -> PyResult<std::rc::Rc<ScanInputs>> {
    if let Some(x) = SCAN.with(|s| s.borrow().as_ref().filter(|(t, _)| *t == ctx.extra).map(|(_, x)| x.clone())) {
        return Ok(x);
    }
    let x: ScanInputs = serde_json::from_str(&ctx.extra).map_err(|e| PyRuntimeError::new_err(format!("{}: native inputs: {e}", ctx.rule)))?;
    let x = std::rc::Rc::new(x);
    SCAN.with(|s| *s.borrow_mut() = Some((ctx.extra.clone(), x.clone())));
    Ok(x)
}

/// A hex value of the scan: its number when it is one (None past u64).
fn hex_value(s: &str) -> Option<u64> {
    u64::from_str_radix(s, 16).ok()
}

/// srcscan.Spans: (file, line) -> the value of the span holding the line.
struct Spans<V> {
    by: HashMap<String, Vec<(i64, i64, V)>>,
}

impl<V> Spans<V> {
    fn new(items: impl IntoIterator<Item = (String, i64, i64, V)>) -> Spans<V> {
        let mut by: HashMap<String, Vec<(i64, i64, V)>> = HashMap::new();
        for (f, lo, hi, v) in items {
            by.entry(f).or_default().push((lo, hi, v));
        }
        for xs in by.values_mut() {
            xs.sort_by_key(|x| x.0); // stable, as sorted(key=)
        }
        Spans { by }
    }
    fn at(&self, file: &str, line: i64) -> Option<&V> {
        let xs = self.by.get(file)?;
        let k = xs.partition_point(|x| x.0 <= line) as i64 - 1;
        if k < 0 {
            return None;
        }
        let x = &xs[k as usize];
        if x.1 != 0 && line > x.1 {
            return None;
        }
        Some(&x.2)
    }
}

/// layout.line_targets: (file, line) -> the targets a line belongs to (None: every target).
fn line_targets(sc: &ScanView, targets: &[String]) -> Spans<Vec<String>> {
    Spans::new(sc.functions.iter().filter(|f| !f.3.is_empty()).map(|f| {
        let mut ts: Vec<String> = f.3.iter().map(|(t, _)| t.clone().unwrap_or_else(|| targets[0].clone())).collect();
        ts.sort();
        ts.dedup();
        (f.0.clone(), f.1, f.2, ts)
    }))
}

/// srcscan.address_for: the address of a (target or None, address) list for one target.
fn address_for(addrs: &[(Option<String>, i64)], target: &str, default: &str) -> Option<i64> {
    addrs.iter().find(|(t, _)| t.as_deref().unwrap_or(default) == target).map(|x| x.1)
}

fn section_at(img: &crate::pe::Image, v: Option<u64>) -> bool {
    v.is_some_and(|v| v <= u32::MAX as u64 && img.section_of(v as u32).is_some())
}

// ------------------------------------------------------------------------------------------------ L5

/// L5.placeholder: an identifier that spells an address names a function start (or an address of a target).
pub fn l5_placeholder(ctx: &Ctx, db: &Connection, out: &mut Out) -> PyResult<()> {
    let img = image(&ctx.image)?;
    let x = scan_inputs(ctx)?;
    let names = &x.targets;
    let mut starts: HashSet<i64> = store::los(db, &ctx.db, "start", &ctx.needed, |_| true).map_err(err)?.into_iter().collect();
    for f in store::facts(db, &ctx.db, "symbol", &ctx.needed, |f| f.s("skind") == Some("func")).map_err(err)? {
        if let Some(a) = f.value.get("inner").and_then(|v| v.as_array()) {
            starts.extend(a.iter().filter_map(|x| x.as_i64()));
        }
    }
    let code = code_ranges(&img);
    let cur = &x.target;
    let default = names.first() == Some(cur);
    let owners = line_targets(&x.scan, names);
    let mut images: HashMap<&str, std::rc::Rc<crate::pe::Image>> = HashMap::new();
    for (file, line, ident, hex) in &x.scan.placeholders {
        let v = hex_value(hex);
        let by = format!("src:{file}:{line}");
        let mine: &[String] = owners.at(file, *line).filter(|m| !m.is_empty()).map(|m| m.as_slice()).unwrap_or(names);
        if mine.contains(cur) && section_at(&img, v) {
            let v = v.unwrap() as i64;
            if code.iter().any(|&(lo, hi)| lo <= v && v < hi) && !starts.contains(&v) {
                out.conflict("error", "L5", v, v + 1, format!("{file}:{line}: {ident}: no function starts at 0x{hex}"), &by);
            }
        } else if default {
            let mut anywhere = false;
            for t in mine {
                let im = match images.get(t.as_str()) {
                    Some(i) => i.clone(),
                    None => {
                        let path = x.images.get(t).ok_or_else(|| PyRuntimeError::new_err(format!("L5: no image of target {t}")))?;
                        let i = image(path)?;
                        images.insert(t, i.clone());
                        i
                    }
                };
                if section_at(&im, v) {
                    anywhere = true;
                    break;
                }
            }
            if !anywhere {
                let listed: Vec<&str> = names.iter().filter(|n| mine.contains(n)).map(|s| s.as_str()).collect();
                let base = img.base as i64;
                out.conflict("error", "L5", base, base + 1,
                             format!("{file}:{line}: {ident}: 0x{hex} is not an address of {} (a dropped or extra digit?)", listed.join(", ")),
                             &by);
            }
        }
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ A1 / L13

const NAME_ORIGINS: [&str; 4] = ["source", "decl", "export", "entry"];

type Sym = (i64, i64, std::rc::Rc<SFact>);

/// layout.what_is_at: what the facts know at address a (its names, else the symbol containing it).
fn what_is_at(a: i64, names: &HashMap<i64, Vec<std::rc::Rc<SFact>>>, syms: &[Sym]) -> String {
    let name_of = |x: i64| -> Vec<String> {
        let mut fs: Vec<&std::rc::Rc<SFact>> = names.get(&x).map(|v| v.iter().collect()).unwrap_or_default();
        let rank = |f: &SFact| f.s("origin").and_then(|o| NAME_ORIGINS.iter().position(|n| *n == o)).unwrap_or(NAME_ORIGINS.len());
        fs.sort_by(|p, q| (rank(p), p.s("name").unwrap_or("")).cmp(&(rank(q), q.s("name").unwrap_or(""))));
        let mut out: Vec<String> = vec![];
        for f in fs {
            let n = f.s("name").unwrap_or("").to_string();
            if !out.contains(&n) {
                out.push(n);
            }
        }
        out
    };
    let own = name_of(a);
    if !own.is_empty() {
        return format!("the name {}", own[..own.len().min(3)].join(" / "));
    }
    let i = syms.partition_point(|s| s.0 <= a) as i64 - 1;
    let mut j = i;
    while j >= 0 && j > i - 8 {
        let (lo, hi, f) = &syms[j as usize];
        if *lo <= a && a < *hi {
            let nm = name_of(*lo);
            let sk = f.s("skind").unwrap_or("symbol");
            let mut s = format!("the {sk} {:#x}..{:#x}", lo, hi);
            if let Some(n) = nm.first() {
                s += &format!(" ({n})");
            }
            if a != *lo {
                s += &format!(" +{:#x}", a - lo);
            }
            return s;
        }
        j -= 1;
    }
    "nothing known".to_string()
}

fn sorted_syms(facts: Vec<std::rc::Rc<SFact>>) -> Vec<Sym> {
    let mut v: Vec<Sym> = facts.into_iter().map(|f| (f.lo, f.hi, f)).collect();
    v.sort_by_key(|s| (s.0, s.1));
    v
}

fn names_by_lo(db: &Connection, ctx: &Ctx, keep: impl Fn(&SFact) -> bool) -> PyResult<HashMap<i64, Vec<std::rc::Rc<SFact>>>> {
    let mut names: HashMap<i64, Vec<std::rc::Rc<SFact>>> = HashMap::new();
    for f in store::facts(db, &ctx.db, "name", &ctx.needed, keep).map_err(err)? {
        names.entry(f.lo).or_default().push(f);
    }
    Ok(names)
}

/// A1.addr.cast: an integer literal cast to a pointer whose value lies in the current target's image.
pub fn a1_addr_cast(ctx: &Ctx, db: &Connection, out: &mut Out) -> PyResult<()> {
    let img = image(&ctx.image)?;
    let x = scan_inputs(ctx)?;
    if x.scan.ptrcasts.is_empty() {
        return Ok(());
    }
    let owners = line_targets(&x.scan, &x.targets);
    let names = names_by_lo(db, ctx, |_| true)?;
    let syms = sorted_syms(store::facts(db, &ctx.db, "symbol", &ctx.needed, |f| f.level > OPEN).map_err(err)?);
    let (base, end) = (img.base as u64, img.end() as u64);
    for (file, line, text, hex) in &x.scan.ptrcasts {
        let mine: &[String] = owners.at(file, *line).filter(|m| !m.is_empty()).map(|m| m.as_slice()).unwrap_or(&x.targets);
        let Some(v) = hex_value(hex).filter(|v| base <= *v && *v < end) else { continue };
        if !mine.contains(&x.target) {
            continue;
        }
        let v = v as i64;
        let what = what_is_at(v, &names, &syms);
        let hint = match what.strip_prefix("the name ") {
            Some(n) => format!("reference {} by name", n.split(" / ").next().unwrap_or("")),
            None => "declare the object at that address and reference it by name".to_string(),
        };
        out.conflict("error", "A1", v, v + 1,
                     format!("{file}:{line}: `{text}` casts the image address 0x{hex} to a pointer; the image has {what} there: {hint} \
                              (a relinked image places it elsewhere)"),
                     &format!("src:{file}:{line}"));
    }
    Ok(())
}

const TABLE_KINDS: [&str; 3] = ["jumptable", "idxtable", "fptr"];

/// L13.data.code: a data declaration of the sources at a known function start or inside a known function.
pub fn l13_data_code(ctx: &Ctx, db: &Connection, out: &mut Out) -> PyResult<()> {
    let x = scan_inputs(ctx)?;
    let syms = store::facts(db, &ctx.db, "symbol", &ctx.needed, |_| true).map_err(err)?;
    let funcs = sorted_syms(syms.iter().filter(|f| f.s("skind") == Some("func") && f.level > DECLARED).cloned().collect());
    let mut tables: Vec<(i64, i64)> = syms.iter()
        .filter(|f| f.s("skind").is_some_and(|k| TABLE_KINDS.contains(&k)) && f.level >= DECLARED).map(|f| (f.lo, f.hi)).collect();
    tables.sort();
    let mut starts: HashSet<i64> = store::los(db, &ctx.db, "start", &ctx.needed, |f| f.level > DECLARED).map_err(err)?.into_iter().collect();
    starts.extend(funcs.iter().map(|f| f.0));
    if funcs.is_empty() && starts.is_empty() {
        return Ok(());
    }
    let at = |a: i64| -> Option<&Sym> {
        let i = funcs.partition_point(|f| f.0 <= a) as i64 - 1;
        if i >= 0 && funcs[i as usize].0 <= a && a < funcs[i as usize].1 { Some(&funcs[i as usize]) } else { None }
    };
    let data_names: HashSet<&str> = x.scan.data.iter().map(|d| d.3.as_str()).collect();
    let names = names_by_lo(db, ctx, |f| !data_names.contains(f.s("name").unwrap_or("")))?;
    let default = x.targets.first().cloned().unwrap_or_default();
    for (file, line, kind, name, addrs) in &x.scan.data {
        let Some(a) = address_for(addrs, &x.target, &default) else { continue };
        let fnx = at(a);
        if fnx.is_none() && !starts.contains(&a) {
            continue;
        }
        if tables.iter().any(|&(lo, hi)| lo <= a && a < hi) {
            continue;
        }
        let what = what_is_at(fnx.map(|f| f.0).unwrap_or(a), &names, &funcs);
        let place = match fnx {
            Some(f) if f.0 != a => format!("+{:#x} inside", a - f.0),
            _ => "the start of".to_string(),
        };
        let rng = fnx.map(|f| format!(" {:#x}..{:#x}", f.0, f.1)).unwrap_or_default();
        out.conflict2("error", "L13", a, a + 1,
                      format!("{file}:{line}: data {} {name} at {:#x} lies at {place} the function{rng} ({what}): declare it as a function \
                               (or fix the address)", if kind == "def" { "definition" } else { "extern" }, a),
                      &format!("src:{file}:{line}"), fnx.map(|f| f.2.by.as_str()).unwrap_or(""));
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ L.unit.extent

pub struct Unit {
    pub tu: String,
    pub lo: i64,
    pub hi: i64,
    pub start_level: i64,
    pub end_level: i64,
    pub start_by: String,
    pub end_by: String,
    pub named_by: Option<String>,
}

pub type Bound = (i64, String, String, String, Option<String>); // addr, side, tu, by, named_by
pub type SrcFn = (i64, String, String, String);                 // addr, unit, name, by
pub type Issue = (String, i64, i64, String, String, String);     // check, lo, hi, message, a, b

fn issue(lo: i64, hi: i64, message: String, a: &str, b: &str) -> Issue {
    ("L7".to_string(), lo, hi, message, a.to_string(), b.to_string())
}

type Placed = (String, (i64, i64, String, Option<String>)); // tu, (addr, level, by, named_by)

fn find(t: &[Placed], tu: &str) -> Option<usize> {
    t.iter().position(|e| e.0 == tu)
}

/// layout.compute_units: the units of the game code (lo, hi, level of hi) and the L7 issues.
pub fn compute_units(game: (i64, i64, i64), bounds: &[Bound], srcs: &[SrcFn], func_starts: &[i64]) -> (Vec<Unit>, Vec<Issue>) {
    let (glo, ghi, glevel) = game;
    let mut issues = vec![];
    // the start and end boundaries by unit, in insertion order (dicts)
    let mut starts: Vec<Placed> = vec![];
    let mut ends: Vec<Placed> = vec![];
    let mut bs: Vec<&Bound> = bounds.iter().collect();
    bs.sort_by(|a, b| (a.0, &a.1, &a.2).cmp(&(b.0, &b.1, &b.2)));
    for b in bs {
        let table = if b.1 == "start" { &mut starts } else { &mut ends };
        if let Some(i) = find(table, &b.2) {
            let prev = &table[i].1;
            issues.push(issue(b.0, b.0 + 1, format!("unit {} has two {} boundaries: {:#x} and {:#x}", b.2, b.1, prev.0, b.0), &prev.2, &b.3));
            continue;
        }
        table.push((b.2.clone(), (b.0, DECLARED, b.3.clone(), b.4.clone())));
    }
    let mut ss: Vec<&SrcFn> = srcs.iter().collect();
    ss.sort_by_key(|s| s.0);
    let mut first_src: Vec<(&str, &SrcFn)> = vec![];
    for s in ss {
        if glo <= s.0 && s.0 < ghi && !first_src.iter().any(|(u, _)| *u == s.1) {
            first_src.push((&s.1, s));
        }
    }
    for (u, s) in first_src {
        if find(&starts, u).is_none() {
            starts.push((u.to_string(), (s.0, DECLARED, s.3.clone(), None)));
        }
    }
    for (tu, e) in &ends {
        if find(&starts, tu).is_none() {
            issues.push(issue(e.0, e.0 + 1, format!("end boundary of unit {tu}, which has no start boundary and no source"), &e.2, ""));
        }
    }
    let mut order = starts.clone();
    order.sort_by(|a, b| (a.1 .0, &a.0).cmp(&(b.1 .0, &b.0)));
    let mut srcs_by_unit: HashMap<&str, HashSet<i64>> = HashMap::new();
    for s in srcs {
        srcs_by_unit.entry(&s.1).or_default().insert(s.0);
    }
    let mut units: Vec<Unit> = vec![];
    let mut seen_at: HashMap<i64, String> = HashMap::new();
    let mut fs = func_starts.to_vec();
    fs.sort();
    let no_srcs = HashSet::new();
    for (i, (tu, (a, lvl, by, named))) in order.iter().enumerate() {
        let a = *a;
        if !(glo <= a && a < ghi) {
            issues.push(issue(a, a + 1, format!("unit {tu} starts at {:#x}, outside the game code {:#x}..{:#x}", a, glo, ghi), by, ""));
            continue;
        }
        if let Some(other) = seen_at.get(&a) {
            issues.push(issue(a, a + 1, format!("units {other} and {tu} start at the same address"), by, ""));
            continue;
        }
        seen_at.insert(a, tu.clone());
        let nxt = order[i + 1..].iter().find(|(_, v)| v.0 > a && glo <= v.0 && v.0 < ghi);
        let (mut hi, elvl, eby);
        if let Some(j) = find(&ends, tu) {
            let e = &ends[j].1;
            (hi, elvl, eby) = (e.0, DECLARED, e.2.clone());
            if let Some((nt, nv)) = nxt {
                if hi > nv.0 {
                    issues.push(issue(nv.0, hi, format!("unit {tu} ends at {:#x}, after unit {nt} starts at {:#x}", hi, nv.0), &eby, &nv.2));
                }
            }
        } else if let Some((nt, nv)) = nxt {
            (hi, elvl, eby) = (nv.0, nv.1, format!("start of {nt}"));
        } else {
            hi = ghi;
            eby = "end of the game code".to_string();
            let k = fs.partition_point(|&x| x < a);
            let mine = srcs_by_unit.get(tu.as_str()).unwrap_or(&no_srcs);
            elvl = if fs[k..].iter().filter(|&&x| x < ghi).all(|x| mine.contains(x)) { glevel.min(crate::store::DERIVED) } else { OPEN };
        }
        if hi > ghi {
            let eb = find(&ends, tu).map(|j| ends[j].1 .2.clone()).unwrap_or_default();
            issues.push(issue(ghi, hi, format!("unit {tu} runs to {:#x}, into the library code at {:#x}", hi, ghi), &eb, ""));
            hi = ghi;
        }
        if hi <= a {
            issues.push(issue(a, a + 1, format!("unit {tu} has an empty extent {:#x}..{:#x}", a, hi), by, ""));
            continue;
        }
        units.push(Unit { tu: tu.clone(), lo: a, hi, start_level: *lvl, end_level: elvl, start_by: by.clone(), end_by: eby,
                          named_by: named.clone() });
    }
    for s in srcs {
        if !(glo <= s.0 && s.0 < ghi) {
            continue;
        }
        let i = units.partition_point(|u| u.lo <= s.0) as i64 - 1;
        let u = if i >= 0 && s.0 < units[i as usize].hi { Some(&units[i as usize]) } else { None };
        match u {
            None => issues.push(issue(s.0, s.0 + 1, format!("function of unit {} ({}) lies outside every unit extent", s.1, s.2), &s.3, "")),
            Some(u) if u.tu != s.1 => issues.push(issue(s.0, s.0 + 1,
                format!("function of unit {} ({}) lies in unit {} {:#x}..{:#x}", s.1, s.2, u.tu, u.lo, u.hi), &s.3, &u.start_by)),
            _ => {}
        }
    }
    (units, issues)
}

type UnitRow = (String, i64, i64, i64, i64, String, String, Option<String>);

/// compute_units for Python (layoutview's proposals): units as (tu, lo, hi, start level, end level, start_by,
/// end_by, named_by), issues as (check, lo, hi, message, a, b).
#[pyfunction]
#[pyo3(name = "compute_units")]
pub fn py_compute_units(game: (i64, i64, i64), bounds: Vec<Bound>, srcs: Vec<SrcFn>, func_starts: Vec<i64>) -> (Vec<UnitRow>, Vec<Issue>) {
    let (units, issues) = compute_units(game, &bounds, &srcs, &func_starts);
    (units.into_iter().map(|u| (u.tu, u.lo, u.hi, u.start_level, u.end_level, u.start_by, u.end_by, u.named_by)).collect(), issues)
}

const LEVEL_NAMES: [&str; 4] = ["open", "declared", "derived", "proven"];

/// L.unit.extent: the units of the game code as `unit` facts, the L7 issues of their computation.
pub fn l_unit_extent(ctx: &Ctx, db: &Connection, out: &mut Out) -> PyResult<()> {
    let img = image(&ctx.image)?;
    let extra: serde_json::Value = serde_json::from_str(&ctx.extra).unwrap_or(serde_json::Value::Null);
    let libs: HashSet<&str> = extra["libs"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect()).unwrap_or_default();
    let fs = |kind: &str| store::facts(db, &ctx.db, kind, &ctx.needed, |_| true).map_err(err);
    let syms = fs("symbol")?;
    let lib_starts = lib_starts_of(&syms);
    let (glo, ghi) = game_range(&img, &lib_starts);
    let code = code_ranges(&img);
    let glevel = if lib_starts.iter().any(|&a| code.iter().any(|&(l, h)| l <= a && a < h)) { crate::store::DERIVED }
                 else { crate::store::PROVEN };
    let funcs: Vec<i64> = sorted_syms(syms.iter().filter(|f| f.s("skind") == Some("func") && f.level > OPEN).cloned().collect())
        .iter().map(|f| f.0).filter(|&lo| glo <= lo && lo < ghi).collect();
    let srcs: Vec<SrcFn> = fs("source")?.iter().filter(|f| f.s("what") == Some("func"))
        .map(|f| (f.lo, f.s("unit").unwrap_or("").to_string(), f.s("symbol").unwrap_or("").to_string(), f.by.clone()))
        .filter(|s| !libs.contains(s.1.as_str())).collect();
    let bounds: Vec<Bound> = fs("boundary")?.iter()
        .map(|f| (f.lo, f.s("side").unwrap_or("").to_string(), f.s("tu").unwrap_or("").to_string(), f.by.clone(),
                  f.s("named_by").map(|s| s.to_string()))).collect();
    let (units, issues) = compute_units((glo, ghi, glevel), &bounds, &srcs, &funcs);
    for (check, lo, hi, message, a, b) in issues {
        out.conflict2("error", &check, lo, hi, message, &a, &b);
    }
    let mut unknown: Vec<(i64, i64)> = syms.iter().filter(|f| f.s("skind") == Some("unknown.code")).map(|f| (f.lo, f.hi)).collect();
    unknown.sort();
    let mut dead: Vec<(i64, i64)> = syms.iter().filter(|f| &*f.rule == "L.decl" && matches!(f.s("skind"), Some("dead") | Some("foreign")))
        .map(|f| (f.lo, f.hi)).collect();
    dead.sort();
    let mut walks: Vec<i64> = vec![];
    {
        let mut st = db.prepare_cached("SELECT c.lo FROM conflict c JOIN run r ON r.id=c.run_id WHERE r.current=1 AND r.rule=? AND c.check_id='C.walk'")
            .map_err(err)?;
        for r in &ctx.needed {
            for lo in st.query_map([r], |row| row.get::<_, i64>(0)).map_err(err)? {
                walks.push(lo.map_err(err)?);
            }
        }
    }
    walks.sort();
    let sourced: HashSet<i64> = srcs.iter().map(|s| s.0).collect();
    let overlap = |ranges: &[(i64, i64)], u: &Unit| -> i64 {
        ranges.iter().filter(|&&(a, b)| a < u.hi && b > u.lo).map(|&(a, b)| (b.min(u.hi) - a.max(u.lo)).max(0)).sum()
    };
    for u in &units {
        let open_bytes = overlap(&unknown, u);
        let n_walk = walks.partition_point(|&x| x < u.hi) as i64 - walks.partition_point(|&x| x < u.lo) as i64;
        let inside: Vec<i64> = funcs.iter().copied().filter(|&a| u.lo <= a && a < u.hi).collect();
        let inside_set: HashSet<i64> = inside.iter().copied().collect();
        let extra: HashSet<i64> = srcs.iter().map(|s| s.0).filter(|&a| u.lo <= a && a < u.hi && !inside_set.contains(&a)).collect();
        let status = if u.start_level >= DECLARED && u.end_level >= DECLARED && open_bytes == 0 && n_walk == 0 { "separated" } else { "open" };
        let mut v = serde_json::json!({
            "tu": u.tu, "status": status, "start_level": LEVEL_NAMES[u.start_level as usize], "end_level": LEVEL_NAMES[u.end_level as usize],
            "start_by": u.start_by, "end_by": u.end_by, "open_bytes": open_bytes, "dead_bytes": overlap(&dead, u),
            "walk_conflicts": n_walk, "functions": inside.len() + extra.len(),
            "sourced": inside.iter().filter(|a| sourced.contains(a)).count() + extra.len()});
        if let Some(n) = u.named_by.as_ref().filter(|n| !n.is_empty()) {
            v["named_by"] = serde_json::json!(n);
        }
        out.fact(u.lo, u.hi, "unit", v, u.start_level.min(u.end_level).min(DECLARED));
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ M1

/// M1.baseline: every function of the current target in ledger/grades.tsv keeps its grades.
pub fn m1_baseline(ctx: &Ctx, db: &Connection, out: &mut Out) -> PyResult<()> {
    let img = image(&ctx.image)?;
    let extra: serde_json::Value = serde_json::from_str(&ctx.extra).unwrap_or(serde_json::Value::Null);
    let target = extra["target"].as_str().unwrap_or("");
    let rank = |c: &str| extra["code_rank"].get(c).and_then(|r| r.as_i64());
    let path = std::path::Path::new(&ctx.root).join("ledger").join("grades.tsv");
    let text = std::fs::read(&path).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
    // parse_baseline: the last line of an address wins
    let mut base: std::collections::BTreeMap<i64, Vec<String>> = std::collections::BTreeMap::new();
    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') || line.starts_with("target\t") {
            continue;
        }
        let mut f: Vec<String> = line.split('\t').map(|s| s.to_string()).collect();
        while f.len() < 8 {
            f.push(String::new());
        }
        let Some(a) = py_int16(&f[1]) else { continue };
        if f[0] == target {
            base.insert(a, f);
        }
    }
    let mut now: HashMap<i64, std::rc::Rc<SFact>> = HashMap::new();
    for f in store::facts(db, &ctx.db, "grade", &ctx.needed, |f| f.s("of") == Some("function")).map_err(err)? {
        now.insert(f.lo, f);
    }
    for (a, r) in &base {
        let (name, code, readability) = (&r[2], &r[4], &r[5]);
        let mut falls = vec![];
        match now.get(a) {
            None => falls.push(format!("graded {code} + {readability} in the baseline, no grade now (its source is gone?)")),
            Some(g) => {
                let nc = g.s("code").unwrap_or("");
                if let (Some(b), Some(n)) = (rank(code), rank(nc)) {
                    if n < b {
                        falls.push(format!("code {code} -> {nc}"));
                    }
                }
                if readability == "readable" && g.s("readability") != Some("readable") {
                    falls.push("readability readable -> draft".to_string());
                }
            }
        }
        let at = if img.base as i64 <= *a && *a < img.end() as i64 { *a } else { img.base as i64 };
        for what in falls {
            out.conflict("error", "M1", at, at + 1, format!("{name} at {:#x}: {what} (baseline ledger/grades.tsv)", a), "");
        }
    }
    Ok(())
}

/// int(s, 16) as Python reads it: surrounding whitespace, a sign, a 0x prefix and _ between digits allowed.
fn py_int16(s: &str) -> Option<i64> {
    let t = s.trim();
    let (neg, t) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    if t.is_empty() || t.starts_with('_') || t.ends_with('_') || t.contains("__") {
        return None;
    }
    let v = i64::from_str_radix(&t.replace('_', ""), 16).ok()?;
    Some(if neg { -v } else { v })
}

// ------------------------------------------------------------------------------------------------ L1 / L4 / L10 / L14

/// layout.game_units: the game units of L.unit.extent facts (library members have no status), by address.
fn game_units(facts: &[std::rc::Rc<SFact>]) -> Vec<Unit> {
    let lvl = |s: Option<&str>| LEVEL_NAMES.iter().position(|n| Some(*n) == s).unwrap_or(0) as i64;
    let mut out: Vec<Unit> = facts.iter().filter(|f| f.value.get("status").is_some()).map(|f| Unit {
        tu: f.s("tu").unwrap_or("").to_string(), lo: f.lo, hi: f.hi, start_level: lvl(f.s("start_level")), end_level: lvl(f.s("end_level")),
        start_by: f.s("start_by").unwrap_or("").to_string(), end_by: f.s("end_by").unwrap_or("").to_string(),
        named_by: f.s("named_by").map(|s| s.to_string()),
    }).collect();
    out.sort_by_key(|u| u.lo);
    out
}

/// layout.unit_index: the index of the unit holding a.
fn unit_at(units: &[Unit], a: i64) -> Option<usize> {
    let i = units.partition_point(|u| u.lo <= a) as i64 - 1;
    if i >= 0 && a < units[i as usize].hi { Some(i as usize) } else { None }
}

/// L1.src.start: the address of a sourced function is the start of a function (or unknown code).
pub fn l1_src_start(ctx: &Ctx, db: &Connection, out: &mut Out) -> PyResult<()> {
    let syms = sorted_syms(store::facts(db, &ctx.db, "symbol", &ctx.needed, |f| f.level > OPEN).map_err(err)?);
    for s in store::facts(db, &ctx.db, "source", &ctx.needed, |f| f.s("what") == Some("func")).map_err(err)? {
        let a = s.lo;
        let i = syms.partition_point(|x| x.0 <= a) as i64 - 1;
        let mut hit = None;
        let mut j = i;
        while j >= 0 && j > i - 8 {
            let (lo, hi, f) = &syms[j as usize];
            if *lo <= a && a < *hi {
                hit = Some(f);
                break;
            }
            j -= 1;
        }
        let Some(hit) = hit else { continue };
        if hit.lo == a {
            continue;
        }
        let sk = hit.s("skind");
        if sk == Some("func") && hit.value.get("inner").and_then(|v| v.as_array()).is_some_and(|v| v.iter().any(|x| x.as_i64() == Some(a))) {
            continue;
        }
        let v = &s.value;
        let line = match v.get("comment") {
            Some(c) => c.clone(),
            None => v["line"].clone(),
        };
        let line = match &line {
            serde_json::Value::Null => "None".to_string(),
            serde_json::Value::String(s) => s.clone(),
            x => x.to_string(),
        };
        out.conflict2("error", "L1", a, a + 1,
                      format!("{}:{line}: {} starts at {:#x}, inside the {} {:#x}..{:#x}", s.s("file").unwrap_or(""), s.s("symbol").unwrap_or(""),
                              a, sk.unwrap_or("None"), hit.lo, hit.hi), &s.by, &hit.by);
    }
    Ok(())
}

/// layout.boundary_issues: L4 over declared boundaries, the starts, the functions and the fill (sorted).
pub fn boundary_issues(bounds: &[Bound], starts: &HashSet<i64>, funcs: &[(i64, i64)], fills: &[(i64, i64)], game_hi: i64) -> Vec<Issue> {
    let mut out = vec![];
    for b in bounds {
        let (a, side, tu, by) = (b.0, &b.1, &b.2, &b.3);
        if side == "end" && a == game_hi {
            continue;
        }
        if let Some(&(lo, hi)) = fills.iter().find(|&&(lo, hi)| lo <= a && a < hi) {
            out.push(("L4".into(), a, a + 1, format!("{side} boundary of {tu} inside fill {:#x}..{:#x} (the unit starts at the function after it, {:#x})", lo, hi, hi),
                      by.clone(), String::new()));
            continue;
        }
        let i = funcs.partition_point(|f| f.0 <= a) as i64 - 1;
        let f = if i >= 0 { Some(funcs[i as usize]) } else { None };
        if let Some((lo, hi)) = f.filter(|&(lo, hi)| lo < a && a < hi && !starts.contains(&a)) {
            out.push(("L4".into(), a, a + 1, format!("{side} boundary of {tu} inside the function {:#x}..{:#x}", lo, hi), by.clone(), String::new()));
            continue;
        }
        if !starts.contains(&a) && !f.is_some_and(|f| f.0 == a) {
            out.push(("L4".into(), a, a + 1, format!("{side} boundary of {tu} at {:#x}, where no function starts", a), by.clone(), String::new()));
        }
    }
    out
}

/// boundary_issues for Python (layoutview's proposals): issues as (check, lo, hi, message, a, b).
#[pyfunction]
#[pyo3(name = "boundary_issues")]
pub fn py_boundary_issues(bounds: Vec<Bound>, starts: HashSet<i64>, funcs: Vec<(i64, i64)>, fills: Vec<(i64, i64)>, game_hi: i64) -> Vec<Issue> {
    boundary_issues(&bounds, &starts, &funcs, &fills, game_hi)
}

fn bounds_of(facts: &[std::rc::Rc<SFact>]) -> Vec<Bound> {
    facts.iter().map(|f| (f.lo, f.s("side").unwrap_or("").to_string(), f.s("tu").unwrap_or("").to_string(), f.by.clone(),
                          f.s("named_by").map(|s| s.to_string()))).collect()
}

/// L4.boundary: a declared boundary lies at a function start, never inside fill or strictly inside a function.
pub fn l4_boundary(ctx: &Ctx, db: &Connection, out: &mut Out) -> PyResult<()> {
    let img = image(&ctx.image)?;
    let syms = store::facts(db, &ctx.db, "symbol", &ctx.needed, |_| true).map_err(err)?;
    let funcs: Vec<(i64, i64)> = sorted_syms(syms.iter().filter(|f| f.s("skind") == Some("func") && f.level > OPEN).cloned().collect())
        .iter().map(|f| (f.0, f.1)).collect();
    let mut fills: Vec<(i64, i64)> = syms.iter().filter(|f| f.s("skind") == Some("fill")).map(|f| (f.lo, f.hi)).collect();
    fills.sort();
    let mut starts: HashSet<i64> = store::los(db, &ctx.db, "start", &ctx.needed, |_| true).map_err(err)?.into_iter().collect();
    for f in syms.iter().filter(|f| f.s("skind") == Some("func")) {
        if let Some(a) = f.value.get("inner").and_then(|v| v.as_array()) {
            starts.extend(a.iter().filter_map(|x| x.as_i64()));
        }
    }
    let (_, ghi) = game_range(&img, &lib_starts_of(&syms));
    let bounds = bounds_of(&store::facts(db, &ctx.db, "boundary", &ctx.needed, |_| true).map_err(err)?);
    for (check, lo, hi, message, a, b) in boundary_issues(&bounds, &starts, &funcs, &fills, ghi) {
        out.conflict2("error", &check, lo, hi, message, &a, &b);
    }
    Ok(())
}

/// L10.unexplained: code inside a game unit's extent no source explains, though a source claims it.
pub fn l10_unexplained(ctx: &Ctx, db: &Connection, out: &mut Out) -> PyResult<()> {
    let units = game_units(&store::facts(db, &ctx.db, "unit", &ctx.needed, |_| true).map_err(err)?);
    let syms = store::facts(db, &ctx.db, "symbol", &ctx.needed, |_| true).map_err(err)?;
    let mut walk: HashMap<i64, std::rc::Rc<SFact>> = HashMap::new();
    for f in syms.iter().filter(|f| &*f.rule == "S.codewalk" && f.s("skind") == Some("func")) {
        walk.insert(f.lo, f.clone());
    }
    let owned: HashSet<i64> = syms.iter().filter(|f| &*f.rule == "L.src.extent" && f.s("skind") == Some("func")).map(|f| f.lo).collect();
    let sources = store::facts(db, &ctx.db, "source", &ctx.needed, |_| true).map_err(err)?;
    let mut matched: HashMap<i64, std::rc::Rc<SFact>> = HashMap::new();
    for f in sources.iter().filter(|f| f.s("what") == Some("match")) {
        matched.insert(f.lo, f.clone());
    }
    let mut dead: Vec<(i64, i64)> = syms.iter().filter(|f| &*f.rule == "L.decl" && matches!(f.s("skind"), Some("dead") | Some("foreign")))
        .map(|f| (f.lo, f.hi)).collect();
    dead.sort();
    for s in sources.iter().filter(|f| &*f.rule == "L.src" && f.s("what") == Some("func")) {
        let Some(i) = unit_at(&units, s.lo) else { continue };
        let (w, m) = (walk.get(&s.lo), matched.get(&s.lo));
        let (file, sym) = (s.s("file").unwrap_or(""), s.s("symbol").unwrap_or(""));
        if w.is_none() && m.is_none() && !owned.contains(&s.lo) {
            out.conflict("warn", "L10", s.lo, s.lo + 1,
                         format!("unit {}: {file} ({sym}) owns no bytes: the walk does not know its start and it does not byte-match, so its \
                                  code stays open", units[i].tu), &s.by);
            continue;
        }
        let (Some(w), Some(m)) = (w, m) else { continue };
        if w.hi <= m.hi {
            continue;
        }
        let left = w.hi - m.hi - dead.iter().filter(|&&(a, b)| a < w.hi && b > m.hi).map(|&(a, b)| (b.min(w.hi) - a.max(m.hi)).max(0)).sum::<i64>();
        if left > 0 {
            out.conflict2("warn", "L10", m.hi, w.hi,
                          format!("unit {}: the walk of {:#x} ({sym}) runs to {:#x}, its byte-matched compile ends at {:#x}: {left} bytes of walked \
                                   code no source explains (a missed start, or dead code to declare `bytes dead`)", units[i].tu, s.lo, w.hi, m.hi),
                          &w.by, &m.by);
        }
    }
    Ok(())
}

/// A unit as L14 reads it: (tu, lo, hi, start_by).
pub type UnitExt = (String, i64, i64, String);
/// A library unit: (tu, lo, hi, by) of its `libunit` declaration.
pub type LibUnit = (String, i64, i64, String);

/// layout.outside_unit_issues: L14 over the game units, the sourced functions, the units with a declared
/// boundary, the game code and the library units (sorted by unit).
pub fn outside_unit_issues(units: &[UnitExt], srcs: &[SrcFn], declared: &HashSet<String>, game: (i64, i64), libs: &[LibUnit]) -> Vec<Issue> {
    let (glo, ghi) = game;
    let mut out = vec![];
    let ext: HashMap<&str, &UnitExt> = units.iter().map(|u| (u.0.as_str(), u)).collect();
    for (tu, lo, hi, by) in libs {
        if *lo < ghi && glo < *hi {
            out.push(("L14".into(), *lo, *hi, format!("library unit {tu} declares the member range {:#x}..{:#x}, inside the game code {:#x}..{:#x}",
                                                      lo, hi, glo, ghi), by.clone(), String::new()));
        }
    }
    for (a, unit, name, sby) in srcs {
        let a = *a;
        if let Some((_, lo, hi, by)) = libs.iter().find(|l| l.0 == *unit) {
            if !(*lo <= a && a < *hi) {
                out.push(("L14".into(), a, a + 1, format!("function of library unit {unit} ({name}) at {:#x} lies outside its declared member \
                                                           range {:#x}..{:#x}", a, lo, hi), sby.clone(), by.clone()));
            }
            continue;
        }
        let Some(u) = ext.get(unit.as_str()) else { continue };
        if !declared.contains(unit) || (u.1 <= a && a < u.2) || (glo <= a && a < ghi) {
            continue;
        }
        out.push(("L14".into(), a, a + 1, format!("function of unit {unit} ({name}) at {:#x} lies outside the unit's declared extent {:#x}..{:#x}",
                                                  a, u.1, u.2), sby.clone(), u.3.clone()));
    }
    out
}

/// outside_unit_issues for Python (its tests).
#[pyfunction]
#[pyo3(name = "outside_unit_issues")]
pub fn py_outside_unit_issues(units: Vec<UnitExt>, srcs: Vec<SrcFn>, declared: HashSet<String>, game: (i64, i64), mut libs: Vec<LibUnit>) -> Vec<Issue> {
    libs.sort();
    outside_unit_issues(&units, &srcs, &declared, game, &libs)
}

/// L14.unit.outside: a sourced function of a declared unit (or a library unit) outside its extent.
pub fn l14_unit_outside(ctx: &Ctx, db: &Connection, out: &mut Out) -> PyResult<()> {
    let img = image(&ctx.image)?;
    let extra: serde_json::Value = serde_json::from_str(&ctx.extra).unwrap_or(serde_json::Value::Null);
    let mut libs: Vec<LibUnit> = extra["libs"].as_object().map(|m| m.iter().map(|(k, v)| {
        (k.clone(), v[0].as_i64().unwrap_or(0), v[1].as_i64().unwrap_or(0), v[2].as_str().unwrap_or("").to_string())
    }).collect()).unwrap_or_default();
    libs.sort();
    let syms = store::facts(db, &ctx.db, "symbol", &ctx.needed, |_| true).map_err(err)?;
    let game = game_range(&img, &lib_starts_of(&syms));
    let declared: HashSet<String> = store::facts(db, &ctx.db, "boundary", &ctx.needed, |_| true).map_err(err)?
        .iter().map(|f| f.s("tu").unwrap_or("").to_string()).collect();
    let units: Vec<UnitExt> = game_units(&store::facts(db, &ctx.db, "unit", &ctx.needed, |_| true).map_err(err)?)
        .into_iter().map(|u| (u.tu, u.lo, u.hi, u.start_by)).collect();
    let srcs: Vec<SrcFn> = store::facts(db, &ctx.db, "source", &ctx.needed, |f| f.s("what") == Some("func") && f.by.starts_with("src:"))
        .map_err(err)?.iter().map(|s| (s.lo, s.s("unit").unwrap_or("").to_string(), s.s("symbol").unwrap_or("").to_string(), s.by.clone())).collect();
    for (check, lo, hi, message, a, b) in outside_unit_issues(&units, &srcs, &declared, game, &libs) {
        out.conflict2("error", &check, lo, hi, message, &a, &b);
    }
    Ok(())
}
