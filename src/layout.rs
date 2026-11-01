//! The native layout rules (rules/layout.py keeps their criteria as docstrings).

use crate::error::{Error, Result};
use crate::rules::Ctx;
use crate::store::{self, Out, Claim, Support, DECLARED, OPEN};
use crate::image;
use rusqlite::Connection;
use std::collections::{HashMap, HashSet};

fn err(e: rusqlite::Error) -> Error {
    Error::runtime(e.to_string())
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
pub fn lib_starts_of(facts: &[std::rc::Rc<Claim>]) -> Vec<i64> {
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
    seeded: bool, // made by the tool at one of our starts on our request: no claim of the tool's
}

/// ledger/drafts.entries: every draft blob, the main store's first (ctx.main: a worktree's overlay), sorted by start.
fn drafts(ctx: &Ctx, db: &Connection) -> Result<Vec<Draft>> {
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
            let d: Draft = serde_json::from_slice(r.get_ref(1).map_err(err)?.as_blob().map_err(|e| Error::runtime(e.to_string()))?)
                .map_err(|e| Error::runtime(format!("drafts: {e}")))?;
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
pub fn l9_analyzer_span(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    // our_starts: {start: how} (a later fact of the same start wins), function / thunk symbols above open
    let mut ours: HashMap<i64, String> = HashMap::new();
    for f in store::claims(db, &ctx.db, "start", &ctx.needed, |_| true).map_err(err)? {
        ours.insert(f.lo, f.s("how").unwrap_or("").to_string());
    }
    let symbols = store::claims(db, &ctx.db, "symbol", &ctx.needed, |_| true).map_err(err)?;
    let mut inner: HashSet<i64> = HashSet::new();
    for f in &symbols {
        if matches!(f.s("skind"), Some("func") | Some("thunk")) && f.support > OPEN {
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
        out.finding("warn", "L9", e.start, hi,
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
pub fn l_src_extent(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    let align = ctx.inputs.function_alignment.max(1);
    let forms = crate::compare::fill_order(&ctx.fill_forms);
    let code: Vec<(i64, i64)> = img.sections.iter().filter(|s| s.holds_code()).map(|s| (s.va as i64, s.end() as i64)).collect();
    let in_code = |a: i64| code.iter().any(|&(lo, hi)| lo <= a && a < hi);
    let fs = |kind: &str| store::claims(db, &ctx.db, kind, &ctx.needed, |_| true).map_err(err);
    let symbols = fs("symbol")?;
    let sources = fs("source")?;
    let mut claimed: Vec<(i64, i64)> = symbols.iter().filter(|f| f.support > OPEN).map(|f| (f.lo, f.hi)).collect();
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
    let is_match = |f: &Claim| &*f.rule == "M.match" && f.s("what") == Some("match");
    let mut ends: Vec<i64> = symbols.iter().filter(|f| f.support > OPEN && in_code(f.lo)).map(|f| f.hi).collect();
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
        out.claim(a, a + cut as i64, "symbol", serde_json::json!({"skind": "func", "extent": "source", "name": v["symbol"],
                                                                  "unit": v["unit"], "file": v["file"]}), DECLARED);
        if cut < data.len() {
            out.claim(a + cut as i64, end, "symbol", serde_json::json!({"skind": "fill", "extent": "source"}), DECLARED);
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
            out.claim(e, p, "symbol", serde_json::json!({"skind": "fill", "extent": "matched"}), DECLARED);
        }
        if stop > p && crate::compare::is_fill(&img.read(p as u32, (stop - p) as usize), &forms) {
            out.claim(p, stop, "symbol", serde_json::json!({"skind": "fill", "extent": "source"}), DECLARED);
        }
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ the source scan

/// The source scan's items the native rules read (one file's: srcscan.rs Piece; the scan's: the pieces of its
/// files joined): values as hex text (a placeholder may spell more digits than any integer type holds).
#[derive(Default, Clone)]
pub(crate) struct ScanView {
    pub(crate) functions: Vec<(String, i64, i64, Vec<(Option<String>, i64)>)>, // file, comment line, end line, addrs
    pub(crate) placeholders: Vec<(String, i64, String, String)>,              // file, line, ident, value
    pub(crate) ptrcasts: Vec<(String, i64, String, String)>,                  // file, line, text, value
    pub(crate) data: Vec<(String, i64, String, String, Vec<(Option<String>, i64)>)>, // file, line, kind, name, addrs
    pub(crate) items: ScanItems, // L.src's
}

impl ScanView {
    pub(crate) fn extend(&mut self, o: &ScanView) {
        self.functions.extend_from_slice(&o.functions);
        self.placeholders.extend_from_slice(&o.placeholders);
        self.ptrcasts.extend_from_slice(&o.ptrcasts);
        self.data.extend_from_slice(&o.data);
        self.items.fns.extend_from_slice(&o.items.fns);
        self.items.datas.extend_from_slice(&o.items.datas);
        self.items.views.extend_from_slice(&o.items.views);
        self.items.errors.extend_from_slice(&o.items.errors);
    }
}

/// The scan as native_inputs names it (srcscan.native_view): its files' pieces (srcscan.rs ScanPiece ids) in
/// file order, the errors of the whole scan (L16) after theirs.
#[derive(Default, serde::Deserialize)]
#[serde(default)]
pub(crate) struct ScanRef {
    pub(crate) pieces: Vec<u64>,
    pub(crate) errors: Vec<(String, String, i64, String)>,
}

struct ScanInputs {
    targets: Vec<String>,
    target: String,
    images: HashMap<String, String>,
    scan: ScanView,
}

thread_local! {
    // the latest scan inputs as parsed, by their text (L5, A1 and L13 of one refresh get the same text)
    static SCAN: std::cell::RefCell<Option<((Vec<u64>, String), std::rc::Rc<ScanInputs>)>> = const { std::cell::RefCell::new(None) };
}

fn scan_inputs(ctx: &Ctx) -> Result<std::rc::Rc<ScanInputs>> {
    let i = &ctx.inputs;
    let key = (i.scan.pieces.clone(), i.target.clone());
    if let Some(x) = SCAN.with(|s| s.borrow().as_ref().filter(|(k, _)| *k == key).map(|(_, x)| x.clone())) {
        return Ok(x);
    }
    let scan = crate::srcscan::view(&i.scan)?;
    let x = std::rc::Rc::new(ScanInputs { targets: i.targets.clone(), target: i.target.clone(), images: i.images.clone(), scan });
    SCAN.with(|s| *s.borrow_mut() = Some((key, x.clone())));
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
pub fn l5_placeholder(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    let x = scan_inputs(ctx)?;
    let names = &x.targets;
    let mut starts: HashSet<i64> = store::los(db, &ctx.db, "start", &ctx.needed, |_| true).map_err(err)?.into_iter().collect();
    for f in store::claims(db, &ctx.db, "symbol", &ctx.needed, |f| f.s("skind") == Some("func")).map_err(err)? {
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
                out.finding("error", "L5", v, v + 1, format!("{file}:{line}: {ident}: no function starts at 0x{hex}"), &by);
            }
        } else if default {
            let mut anywhere = false;
            for t in mine {
                let im = match images.get(t.as_str()) {
                    Some(i) => i.clone(),
                    None => {
                        let path = x.images.get(t).ok_or_else(|| Error::runtime(format!("L5: no image of target {t}")))?;
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
                out.finding("error", "L5", base, base + 1,
                             format!("{file}:{line}: {ident}: 0x{hex} is not an address of {} (a dropped or extra digit?)", listed.join(", ")),
                             &by);
            }
        }
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ A1 / L13

const NAME_ORIGINS: [&str; 4] = ["source", "decl", "export", "entry"];

type Sym = (i64, i64, std::rc::Rc<Claim>);

/// layout.what_is_at: what the facts know at address a (its names, else the symbol containing it).
fn what_is_at(a: i64, names: &HashMap<i64, Vec<std::rc::Rc<Claim>>>, syms: &[Sym]) -> String {
    let name_of = |x: i64| -> Vec<String> {
        let mut fs: Vec<&std::rc::Rc<Claim>> = names.get(&x).map(|v| v.iter().collect()).unwrap_or_default();
        let rank = |f: &Claim| f.s("origin").and_then(|o| NAME_ORIGINS.iter().position(|n| *n == o)).unwrap_or(NAME_ORIGINS.len());
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

fn sorted_syms(facts: Vec<std::rc::Rc<Claim>>) -> Vec<Sym> {
    let mut v: Vec<Sym> = facts.into_iter().map(|f| (f.lo, f.hi, f)).collect();
    v.sort_by_key(|s| (s.0, s.1));
    v
}

fn names_by_lo(db: &Connection, ctx: &Ctx, keep: impl Fn(&Claim) -> bool) -> Result<HashMap<i64, Vec<std::rc::Rc<Claim>>>> {
    let mut names: HashMap<i64, Vec<std::rc::Rc<Claim>>> = HashMap::new();
    for f in store::claims(db, &ctx.db, "name", &ctx.needed, keep).map_err(err)? {
        names.entry(f.lo).or_default().push(f);
    }
    Ok(names)
}

/// A1.addr.cast: an integer literal cast to a pointer whose value lies in the current target's image.
pub fn a1_addr_cast(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    let x = scan_inputs(ctx)?;
    if x.scan.ptrcasts.is_empty() {
        return Ok(());
    }
    let owners = line_targets(&x.scan, &x.targets);
    let names = names_by_lo(db, ctx, |_| true)?;
    let syms = sorted_syms(store::claims(db, &ctx.db, "symbol", &ctx.needed, |f| f.support > OPEN).map_err(err)?);
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
        out.finding("error", "A1", v, v + 1,
                     format!("{file}:{line}: `{text}` casts the image address 0x{hex} to a pointer; the image has {what} there: {hint} \
                              (a relinked image places it elsewhere)"),
                     &format!("src:{file}:{line}"));
    }
    Ok(())
}

const TABLE_KINDS: [&str; 3] = ["jumptable", "idxtable", "fptr"];

/// L13.data.code: a data declaration of the sources at a known function start or inside a known function.
pub fn l13_data_code(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let x = scan_inputs(ctx)?;
    let syms = store::claims(db, &ctx.db, "symbol", &ctx.needed, |_| true).map_err(err)?;
    let funcs = sorted_syms(syms.iter().filter(|f| f.s("skind") == Some("func") && f.support > DECLARED).cloned().collect());
    let mut tables: Vec<(i64, i64)> = syms.iter()
        .filter(|f| f.s("skind").is_some_and(|k| TABLE_KINDS.contains(&k)) && f.support >= DECLARED).map(|f| (f.lo, f.hi)).collect();
    tables.sort();
    let mut starts: HashSet<i64> = store::los(db, &ctx.db, "start", &ctx.needed, |f| f.support > DECLARED).map_err(err)?.into_iter().collect();
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
        out.finding2("error", "L13", a, a + 1,
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
    pub start_support: Support,
    pub end_support: Support,
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

type Placed = (String, (i64, Support, String, Option<String>)); // tu, (addr, support, by, named_by)

fn find(t: &[Placed], tu: &str) -> Option<usize> {
    t.iter().position(|e| e.0 == tu)
}

/// layout.compute_units: the units of the game code (lo, hi, level of hi) and the L7 issues.
pub fn compute_units(game: (i64, i64, Support), bounds: &[Bound], srcs: &[SrcFn], func_starts: &[i64]) -> (Vec<Unit>, Vec<Issue>) {
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
        units.push(Unit { tu: tu.clone(), lo: a, hi, start_support: *lvl, end_support: elvl, start_by: by.clone(), end_by: eby,
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



/// L.unit.extent: the units of the game code as `unit` facts, the L7 issues of their computation.
pub fn l_unit_extent(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    let (decls, _, targets, target) = crate::decl::project_decls(ctx)?;
    let lib_decls = crate::decl::lib_units(&decls, &target, targets.first().map(|s| s.as_str()).unwrap_or(""));
    let libs: HashSet<&str> = lib_decls.keys().map(|s| s.as_str()).collect();
    let fs = |kind: &str| store::claims(db, &ctx.db, kind, &ctx.needed, |_| true).map_err(err);
    let syms = fs("symbol")?;
    let lib_starts = lib_starts_of(&syms);
    let (glo, ghi) = game_range(&img, &lib_starts);
    let code = code_ranges(&img);
    let glevel = if lib_starts.iter().any(|&a| code.iter().any(|&(l, h)| l <= a && a < h)) { crate::store::DERIVED }
                 else { crate::store::OBSERVED };
    let funcs: Vec<i64> = sorted_syms(syms.iter().filter(|f| f.s("skind") == Some("func") && f.support > OPEN).cloned().collect())
        .iter().map(|f| f.0).filter(|&lo| glo <= lo && lo < ghi).collect();
    let srcs: Vec<SrcFn> = fs("source")?.iter().filter(|f| f.s("what") == Some("func"))
        .map(|f| (f.lo, f.s("unit").unwrap_or("").to_string(), f.s("symbol").unwrap_or("").to_string(), f.by.clone()))
        .filter(|s| !libs.contains(s.1.as_str())).collect();
    let bounds: Vec<Bound> = fs("boundary")?.iter()
        .map(|f| (f.lo, f.s("side").unwrap_or("").to_string(), f.s("tu").unwrap_or("").to_string(), f.by.clone(),
                  f.s("named_by").map(|s| s.to_string()))).collect();
    let (units, issues) = compute_units((glo, ghi, glevel), &bounds, &srcs, &funcs);
    for (check, lo, hi, message, a, b) in issues {
        out.finding2("error", &check, lo, hi, message, &a, &b);
    }
    let mut unknown: Vec<(i64, i64)> = syms.iter().filter(|f| f.s("skind") == Some("unknown.code")).map(|f| (f.lo, f.hi)).collect();
    unknown.sort();
    let mut dead: Vec<(i64, i64)> = syms.iter().filter(|f| &*f.rule == "L.decl" && matches!(f.s("skind"), Some("dead") | Some("foreign")))
        .map(|f| (f.lo, f.hi)).collect();
    dead.sort();
    let mut walks: Vec<i64> = vec![];
    {
        let mut st = db.prepare_cached("SELECT c.lo FROM finding c JOIN run r ON r.id=c.run_id WHERE r.current=1 AND r.rule=? AND c.check_id='C.walk'")
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
        let status = unit_status(u.start_support, u.end_support, open_bytes, n_walk);
        let mut v = serde_json::json!({
            "tu": u.tu, "status": status, "start_support": u.start_support.name(), "end_support": u.end_support.name(),
            "start_by": u.start_by, "end_by": u.end_by, "open_bytes": open_bytes, "dead_bytes": overlap(&dead, u),
            "walk_conflicts": n_walk, "functions": inside.len() + extra.len(),
            "sourced": inside.iter().filter(|a| sourced.contains(a)).count() + extra.len()});
        if let Some(n) = u.named_by.as_ref().filter(|n| !n.is_empty()) {
            v["named_by"] = serde_json::json!(n);
        }
        out.claim(u.lo, u.hi, "unit", v, u.start_support.min(u.end_support).min(DECLARED));
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ M1

/// M1.baseline: every function of the current target in ledger/grades.tsv keeps its grades.
pub fn m1_baseline(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    let target = ctx.inputs.target.as_str();
    let rank = |c: &str| ctx.inputs.code_rank.get(c).copied();
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
    // the experiment's outcome and the readability of every graded function, now
    let mut now: HashMap<i64, std::rc::Rc<Claim>> = HashMap::new();
    for f in store::claims(db, &ctx.db, "experiment", &ctx.needed, |f| f.s("of") == Some("function")).map_err(err)? {
        now.insert(f.lo, f);
    }
    let read: HashMap<i64, std::rc::Rc<Claim>> = store::claims(db, &ctx.db, "readability", &ctx.needed, |f| f.s("of") == Some("function"))
        .map_err(err)?.into_iter().map(|f| (f.lo, f)).collect();
    for (a, r) in &base {
        let (name, code, readability) = (&r[2], &r[4], &r[5]);
        let mut falls = vec![];
        match now.get(a) {
            None => falls.push(format!("graded {code} + {readability} in the baseline, no grade now (its source is gone?)")),
            Some(g) => {
                let nc = g.s("outcome").unwrap_or("");
                if let (Some(b), Some(n)) = (rank(code), rank(nc)) {
                    if n < b {
                        falls.push(format!("code {code} -> {nc}"));
                    }
                }
                if readability == "readable" && read.get(a).and_then(|q| q.s("grade")) != Some("readable") {
                    falls.push("readability readable -> draft".to_string());
                }
            }
        }
        let at = if img.base as i64 <= *a && *a < img.end() as i64 { *a } else { img.base as i64 };
        for what in falls {
            out.finding("error", "M1", at, at + 1, format!("{name} at {:#x}: {what} (baseline ledger/grades.tsv)", a), "");
        }
    }
    // the debt (§8.6): every declared regression is listed, never a gate failure, while the target holds no more
    // than the gate's max_debt of them (when [gate] max_debt sets one)
    let debts: Vec<crate::queues::Debt> = crate::queues::debts(&text).into_iter().filter(|d| d.target == target).collect();
    for d in &debts {
        let at = if img.base as i64 <= d.addr && d.addr < img.end() as i64 { d.addr } else { img.base as i64 };
        let waits = if d.waits_for.is_empty() { "names nothing it waits for".to_string() } else { format!("waits for {}", d.waits_for) };
        out.finding("warn", "M1.debt", at, at + 1, format!("{} at {:#x}: debt {} -> {}, witness {}: {}; {waits} (dcp debt list)", d.name, d.addr, d.was,
                                                           d.now, d.witness, d.why), "");
    }
    let max = ctx.inputs.max_debt;
    if max >= 0 && debts.len() as i64 > max {
        out.finding("error", "M1.debt", img.base as i64, img.base as i64 + 1,
                    format!("{} debt items, more than the gate's max_debt {max} ([gate] max_debt): win some back first (dcp debt list)", debts.len()), "");
    }
    Ok(())
}

/// int(s, 16) as Python reads it: surrounding whitespace, a sign, a 0x prefix and _ between digits allowed.
pub(crate) fn py_int16(s: &str) -> Option<i64> {
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
pub(crate) fn game_units(facts: &[std::rc::Rc<Claim>]) -> Vec<Unit> {
    let lvl = |s: Option<&str>| s.and_then(Support::parse).unwrap_or(OPEN);
    let mut out: Vec<Unit> = facts.iter().filter(|f| f.value.get("status").is_some()).map(|f| Unit {
        tu: f.s("tu").unwrap_or("").to_string(), lo: f.lo, hi: f.hi, start_support: lvl(f.s("start_support")), end_support: lvl(f.s("end_support")),
        start_by: f.s("start_by").unwrap_or("").to_string(), end_by: f.s("end_by").unwrap_or("").to_string(),
        named_by: f.s("named_by").map(|s| s.to_string()),
    }).collect();
    out.sort_by_key(|u| u.lo);
    out
}

/// layout.unit_index: the index of the unit holding a.
pub(crate) fn unit_at(units: &[Unit], a: i64) -> Option<usize> {
    let i = units.partition_point(|u| u.lo <= a) as i64 - 1;
    if i >= 0 && a < units[i as usize].hi { Some(i as usize) } else { None }
}

/// L1.src.start: the address of a sourced function is the start of a function (or unknown code).
pub fn l1_src_start(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let syms = sorted_syms(store::claims(db, &ctx.db, "symbol", &ctx.needed, |f| f.support > OPEN).map_err(err)?);
    for s in store::claims(db, &ctx.db, "source", &ctx.needed, |f| f.s("what") == Some("func")).map_err(err)? {
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
        out.finding2("error", "L1", a, a + 1,
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

pub(crate) fn bounds_of(facts: &[std::rc::Rc<Claim>]) -> Vec<Bound> {
    facts.iter().map(|f| (f.lo, f.s("side").unwrap_or("").to_string(), f.s("tu").unwrap_or("").to_string(), f.by.clone(),
                          f.s("named_by").map(|s| s.to_string()))).collect()
}

/// L4.boundary: a declared boundary lies at a function start, never inside fill or strictly inside a function.
pub fn l4_boundary(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    let syms = store::claims(db, &ctx.db, "symbol", &ctx.needed, |_| true).map_err(err)?;
    let funcs: Vec<(i64, i64)> = sorted_syms(syms.iter().filter(|f| f.s("skind") == Some("func") && f.support > OPEN).cloned().collect())
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
    let bounds = bounds_of(&store::claims(db, &ctx.db, "boundary", &ctx.needed, |_| true).map_err(err)?);
    for (check, lo, hi, message, a, b) in boundary_issues(&bounds, &starts, &funcs, &fills, ghi) {
        out.finding2("error", &check, lo, hi, message, &a, &b);
    }
    Ok(())
}

/// L10.unexplained: code inside a game unit's extent no source explains, though a source claims it.
pub fn l10_unexplained(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let units = game_units(&store::claims(db, &ctx.db, "unit", &ctx.needed, |_| true).map_err(err)?);
    let syms = store::claims(db, &ctx.db, "symbol", &ctx.needed, |_| true).map_err(err)?;
    let mut walk: HashMap<i64, std::rc::Rc<Claim>> = HashMap::new();
    for f in syms.iter().filter(|f| &*f.rule == "S.codewalk" && f.s("skind") == Some("func")) {
        walk.insert(f.lo, f.clone());
    }
    let owned: HashSet<i64> = syms.iter().filter(|f| &*f.rule == "L.src.extent" && f.s("skind") == Some("func")).map(|f| f.lo).collect();
    let sources = store::claims(db, &ctx.db, "source", &ctx.needed, |_| true).map_err(err)?;
    let mut matched: HashMap<i64, std::rc::Rc<Claim>> = HashMap::new();
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
            out.finding("warn", "L10", s.lo, s.lo + 1,
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
            out.finding2("warn", "L10", m.hi, w.hi,
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

/// separated when both boundaries are at least declared, no open byte and no C.walk conflict lies inside the unit;
/// else open.
pub fn unit_status(start_support: Support, end_support: Support, open_bytes: i64, walk_conflicts: i64) -> &'static str {
    if start_support >= DECLARED && end_support >= DECLARED && open_bytes == 0 && walk_conflicts == 0 { "separated" } else { "open" }
}

/// L14.unit.outside: a sourced function of a declared unit (or a library unit) outside its extent.
pub fn l14_unit_outside(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    let (decls, _, targets, target) = crate::decl::project_decls(ctx)?;
    let mut libs: Vec<LibUnit> = crate::decl::lib_units(&decls, &target, targets.first().map(|s| s.as_str()).unwrap_or(""))
        .into_iter().map(|(k, d)| (k, d.lo, d.hi, d.by())).collect();
    libs.sort();
    let syms = store::claims(db, &ctx.db, "symbol", &ctx.needed, |_| true).map_err(err)?;
    let game = game_range(&img, &lib_starts_of(&syms));
    let declared: HashSet<String> = store::claims(db, &ctx.db, "boundary", &ctx.needed, |_| true).map_err(err)?
        .iter().map(|f| f.s("tu").unwrap_or("").to_string()).collect();
    let units: Vec<UnitExt> = game_units(&store::claims(db, &ctx.db, "unit", &ctx.needed, |_| true).map_err(err)?)
        .into_iter().map(|u| (u.tu, u.lo, u.hi, u.start_by)).collect();
    let srcs: Vec<SrcFn> = store::claims(db, &ctx.db, "source", &ctx.needed, |f| f.s("what") == Some("func") && f.by.starts_with("src:"))
        .map_err(err)?.iter().map(|s| (s.lo, s.s("unit").unwrap_or("").to_string(), s.s("symbol").unwrap_or("").to_string(), s.by.clone())).collect();
    for (check, lo, hi, message, a, b) in outside_unit_issues(&units, &srcs, &declared, game, &libs) {
        out.finding2("error", &check, lo, hi, message, &a, &b);
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ L.src

type Addrs = Vec<(Option<String>, i64)>;

/// srcscan's items L.src reads: every function, datum, view, error of the scan.
#[derive(Default, Clone)]
pub(crate) struct ScanItems {
    // file, line, comment line, end line, unit, name, static, addrs, deep, stuck, rough, what
    pub(crate) fns: Vec<(String, i64, i64, i64, String, String, bool, Addrs, Option<String>, Option<String>, bool, String)>,
    // file, line, unit, name, kind, static, addrs
    pub(crate) datas: Vec<(String, i64, String, String, String, bool, Addrs)>,
    // file, line, unit, name, container, offset, alias, addrs
    pub(crate) views: Vec<(String, i64, String, String, String, i64, bool, Addrs)>,
    // check, file, line, message
    pub(crate) errors: Vec<(String, String, i64, String)>,
}

/// L.src: the address comments of the sources for the current target (facts source / name / start, the errors).
pub fn l_src(ctx: &Ctx, _db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    let x = scan_inputs(ctx)?;
    let targets = &x.targets;
    let default = targets.first().cloned().unwrap_or_default();
    let cur = &x.target;
    let base = img.base as i64;
    let in_image = |a: i64| base <= a && a < img.end() as i64;
    let sc = &x.scan.items;
    let err = |out: &mut Out, check: &str, lo: i64, msg: String, a: &str, b: &str| out.finding2("error", check, lo, lo + 1, msg, a, b);
    if *cur == default {
        for (check, file, line, message) in &sc.errors {
            err(out, check, base, format!("{file}:{line}: {message}"), &format!("src:{file}:{line}"), "");
        }
    }
    let code = code_ranges(&img);
    let mut defs_at: std::collections::BTreeMap<i64, Vec<String>> = std::collections::BTreeMap::new();
    // (name, unit of a static or None) -> address -> by
    let mut names_at: HashMap<(String, Option<String>), Vec<(i64, String)>> = HashMap::new();
    let mut name_at = |key: (String, Option<String>), a: i64, by: &str| {
        let at = names_at.entry(key).or_default();
        match at.iter_mut().find(|(x, _)| *x == a) {
            Some(e) => e.1 = by.to_string(),
            None => at.push((a, by.to_string())),
        }
    };
    let mut data_at: HashMap<(String, Option<String>), i64> = HashMap::new();
    let unknown_prefix = |out: &mut Out, addrs: &Addrs, by: &str| {
        if *cur != default {
            return;
        }
        let mut bad: Vec<&str> = addrs.iter().filter_map(|(t, _)| t.as_deref()).filter(|t| !targets.iter().any(|x| x == t)).collect();
        bad.sort();
        bad.dedup();
        for t in bad {
            err(out, "L.src", base, format!("{}: unknown target prefix {t}: (targets: {})", &by[4..], targets.join(", ")), by, "");
        }
    };
    let decl = |out: &mut Out, a: i64, kind: &str, v: serde_json::Value, by: &str, reason: &str| out.declared(a, a + 1, kind, v, by, reason);
    for (file, line, cline, end, unit, name, stat, addrs, deep, stuck, rough, what) in &sc.fns {
        let by = format!("src:{file}:{cline}");
        unknown_prefix(out, addrs, &by);
        let Some(a) = address_for(addrs, cur, &default) else { continue };
        if !code.iter().any(|&(lo, hi)| lo <= a && a < hi) {
            let at = if in_image(a) { a } else { base };
            err(out, "L.src", at, format!("{file}: function {name} at {:#x}, outside every code section", a), &by, "");
            continue;
        }
        let mut v = serde_json::json!({"file": file, "line": line, "comment": cline, "end": end, "unit": unit, "symbol": name, "what": "func"});
        if let Some(d) = deep {
            v["deep"] = serde_json::json!(d);
        }
        if let Some(s) = stuck {
            v["stuck"] = serde_json::json!(s);
        }
        if *rough {
            v["rough"] = serde_json::json!(true);
        }
        let reason = if what.is_empty() { "address comment" } else { what.as_str() };
        defs_at.entry(a).or_default().push(by.clone());
        name_at((name.clone(), if *stat { Some(unit.clone()) } else { None }), a, &by);
        decl(out, a, "source", v, &by, reason);
        decl(out, a, "name", serde_json::json!({"name": name, "origin": "source"}), &by, reason);
        decl(out, a, "start", serde_json::json!({"skind": "func", "how": "source"}), &by, reason);
    }
    for (file, line, unit, name, kind, stat, addrs) in &sc.datas {
        let by = format!("src:{file}:{line}");
        unknown_prefix(out, addrs, &by);
        let Some(a) = address_for(addrs, cur, &default) else { continue };
        if !in_image(a) {
            err(out, "L.src", base, format!("{file}:{line}: {name} at {:#x}, outside the image", a), &by, "");
            continue;
        }
        let reason = format!("data address comment ({kind})");
        let key = (name.clone(), if *stat { Some(unit.clone()) } else { None });
        name_at(key.clone(), a, &by);
        if kind == "def" {
            defs_at.entry(a).or_default().push(by.clone());
            decl(out, a, "source", serde_json::json!({"file": file, "line": line, "unit": unit, "symbol": name, "what": "data"}), &by, &reason);
        }
        decl(out, a, "name", serde_json::json!({"name": name, "origin": "source"}), &by, &reason);
        data_at.entry(key).or_insert(a);
    }
    let mut pending = vec![];
    for v in &sc.views {
        let by = format!("src:{}:{}", v.0, v.1);
        unknown_prefix(out, &v.7, &by);
        if let Some(a) = address_for(&v.7, cur, &default) {
            pending.push((v, a, by));
        }
    }
    while !pending.is_empty() {                        // a view may be the container of another view
        let mut rest = vec![];
        let n = pending.len();
        for (v, a, by) in pending {
            let (file, line, unit, name, container, offset, _, _) = v;
            let ca = data_at.get(&(container.clone(), Some(unit.clone()))).or_else(|| data_at.get(&(container.clone(), None))).copied();
            let Some(ca) = ca else {
                rest.push((v, a, by));
                continue;
            };
            if ca + offset != a {
                err(out, "L15", a, format!("{file}:{line}: view {name} at {:#x}, but {container} ({:#x}) + {} is {:#x}", a, ca,
                                           crate::x86::py_hex(*offset), ca + offset), &by, "");
                continue;
            }
            data_at.entry((name.clone(), None)).or_insert(a);
            name_at((name.clone(), None), a, &by);
            decl(out, a, "name", serde_json::json!({"name": name, "origin": "source", "view": container}), &by,
                 &format!("view of {container} +{}", crate::x86::py_hex(*offset)));
        }
        if rest.len() == n {
            for (v, a, by) in &rest {
                if !v.6 {                              // an alias of no data declaration is no view
                    err(out, "L15", *a, format!("{}:{}: view {}: its container {} has no data declaration with an address", v.0, v.1, v.3, v.4), by, "");
                }
            }
            break;
        }
        pending = rest;
    }
    for (a, bys) in &defs_at {
        if bys.len() > 1 {
            err(out, "L.src", *a, format!("{} definitions at {:#x}: {}", bys.len(), a, bys.iter().map(|b| &b[4..]).collect::<Vec<_>>().join(", ")),
                &bys[0], &bys[1]);
        }
    }
    let mut names_at: Vec<_> = names_at.into_iter().collect();
    names_at.sort_by(|x, y| (&x.0 .0, x.0 .1.as_deref().unwrap_or("")).cmp(&(&y.0 .0, y.0 .1.as_deref().unwrap_or(""))));
    for ((name, _), at) in &names_at {
        if at.len() > 1 {
            let mut s = at.clone();
            s.sort();
            err(out, "N2", s[0].0, format!("{name} at {} addresses: {}", s.len(), s.iter().map(|x| format!("{:#x}", x.0)).collect::<Vec<_>>().join(", ")),
                &s[0].1, &s[1].1);
        }
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ L3, L6, L8, R5

/// A literal (L.analyze's lit evidence): its range, its first user, its section, the data sections' references.
#[derive(Clone)]
pub struct Lit {
    pub lo: i64,
    pub hi: i64,
    pub first: i64,
    pub section: String,
    pub data_refs: i64,
}

/// A leaked source path (L.analyze's leak evidence) at a function.
#[derive(Clone)]
pub struct Leak {
    pub func: i64,
    pub path: String,
    pub stem: String,
    pub header: bool,
}

pub fn lits_of(ev: &[std::rc::Rc<Claim>]) -> Vec<Lit> {
    ev.iter().filter(|f| f.s("ekind") == Some("lit")).map(|f| Lit {
        lo: f.lo, hi: f.hi, first: f.value.get("first").and_then(|v| v.as_i64()).unwrap_or(0), section: f.s("section").unwrap_or("").to_string(),
        data_refs: f.value.get("data_refs").and_then(|v| v.as_i64()).unwrap_or(0),
    }).collect()
}

pub fn leaks_of(ev: &[std::rc::Rc<Claim>]) -> Vec<Leak> {
    ev.iter().filter(|f| f.s("ekind") == Some("leak")).map(|f| Leak {
        func: f.lo, path: crate::setup::py_str(f.value.get("path")), stem: crate::setup::py_str(f.value.get("stem")),
        header: f.value.get("header").is_some_and(|h| h.as_bool() == Some(true) || h.as_i64().is_some_and(|n| n != 0)),
    }).collect()
}

fn issue_of(check: &str, lo: i64, hi: i64, message: String, a: &str, b: &str) -> Issue {
    (check.to_string(), lo, hi, message, a.to_string(), b.to_string())
}

/// L3 (B-LIT contradiction): in one data section the literals, in address order, have first users whose units
/// never go backwards (a literal reached from a data section is skipped).
pub fn lit_issues(units: &[Unit], lits: &[Lit]) -> Vec<Issue> {
    let mut out = vec![];
    // section -> the literals no data section reaches, in first-seen order of the sections
    let mut by_sec: Vec<(String, Vec<&Lit>)> = vec![];
    for l in lits.iter().filter(|l| l.data_refs == 0) {
        match by_sec.iter_mut().find(|x| x.0 == l.section) {
            Some(x) => x.1.push(l),
            None => by_sec.push((l.section.clone(), vec![l])),
        }
    }
    for (sec, mut ls) in by_sec {
        ls.sort_by_key(|l| l.lo);
        let mut top: Option<(usize, &Lit)> = None;
        let mut reported: HashSet<(usize, usize)> = HashSet::new();
        for l in ls {
            let Some(i) = unit_at(units, l.first) else { continue };
            if let Some((t, tl)) = top {
                if i < t && reported.insert((i, t)) {
                    out.push(issue_of("L3", l.lo, l.hi,
                                      format!("literal at {:#x} ({sec}) is first used by {:#x} in unit {}, but the earlier literal at {:#x} is first used by {:#x} in the later unit {}",
                                              l.lo, l.first, units[i].tu, tl.lo, tl.first, units[t].tu), &units[i].start_by, &units[t].start_by));
                }
            }
            if top.is_none_or(|(t, _)| i > t) {
                top = Some((i, l));
            }
        }
    }
    out
}

/// L8: the leaked .c / .cpp paths referenced by the functions of one unit name one file.
pub fn leak_issues(units: &[Unit], leaks: &[Leak]) -> Vec<Issue> {
    // unit -> stem -> (fn, path), the first leak of a stem kept
    let mut per: Vec<(usize, Vec<(&str, i64, &str)>)> = vec![];
    for l in leaks.iter().filter(|l| !l.header) {
        let Some(i) = unit_at(units, l.func) else { continue };
        let e = match per.iter().position(|x| x.0 == i) {
            Some(k) => &mut per[k].1,
            None => {
                per.push((i, vec![]));
                &mut per.last_mut().unwrap().1
            }
        };
        if !e.iter().any(|x| x.0 == l.stem) {
            e.push((&l.stem, l.func, &l.path));
        }
    }
    let mut out = vec![];
    for (i, mut stems) in per {
        if stems.len() > 1 {
            stems.sort_by_key(|x| x.1);
            let u = &units[i];
            out.push(issue_of("L8", u.lo, u.hi,
                              format!("unit {} holds functions that leak {} source files: {}", u.tu, stems.len(),
                                      stems.iter().map(|(_, f, p)| format!("{p} ({f:#x})")).collect::<Vec<_>>().join(", ")), &u.start_by, ""));
        }
    }
    out
}

fn emit(out: &mut Out, issues: Vec<Issue>) {
    for (check, lo, hi, message, a, b) in issues {
        out.finding2("error", &check, lo, hi, message, &a, &b);
    }
}

/// L3.lit.order: the literals' first users never go back to an earlier unit within a data section.
pub fn l3_lit_order(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let units = game_units(&store::claims(db, &ctx.db, "unit", &ctx.needed, |_| true).map_err(err)?);
    let ev = store::claims(db, &ctx.db, "evidence", &ctx.needed, |f| f.s("ekind") == Some("lit")).map_err(err)?;
    emit(out, lit_issues(&units, &lits_of(&ev)));
    Ok(())
}

/// L8.leak: the leaked .c / .cpp paths of one unit's functions name one file.
pub fn l8_leak(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let units = game_units(&store::claims(db, &ctx.db, "unit", &ctx.needed, |_| true).map_err(err)?);
    let ev = store::claims(db, &ctx.db, "evidence", &ctx.needed, |f| f.s("ekind") == Some("leak")).map_err(err)?;
    emit(out, leak_issues(&units, &leaks_of(&ev)));
    Ok(())
}

/// L6.declared: every declaration re-checked against the computed facts.
pub fn l6_declared(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    let code = code_ranges(&img);
    let symbols = store::claims(db, &ctx.db, "symbol", &ctx.needed, |_| true).map_err(err)?;
    let starts_all = store::claims(db, &ctx.db, "start", &ctx.needed, |_| true).map_err(err)?;
    let mut mine: Vec<(bool, std::rc::Rc<Claim>)> = symbols.iter().filter(|f| &*f.rule == "L.decl").map(|f| (false, f.clone())).collect();
    mine.extend(starts_all.iter().filter(|f| &*f.rule == "L.decl").map(|f| (true, f.clone())));
    if mine.is_empty() {
        return Ok(());
    }
    let other: Vec<&std::rc::Rc<Claim>> = symbols.iter().filter(|f| &*f.rule != "L.decl" && f.support > OPEN).collect();
    let mut funcs: Vec<&std::rc::Rc<Claim>> = other.iter().copied().filter(|f| f.s("skind") == Some("func")).collect();
    funcs.sort_by_key(|f| (f.lo, f.hi));
    let tables: Vec<&std::rc::Rc<Claim>> = other.iter().copied().filter(|f| matches!(f.s("skind"), Some("jumptable" | "idxtable"))).collect();
    let starts: HashSet<i64> = starts_all.iter().filter(|f| &*f.rule != "L.decl").map(|f| f.lo).collect();
    let all_refs = store::claims(db, &ctx.db, "ref", &ctx.needed, |_| true).map_err(err)?;
    let refs: Vec<&std::rc::Rc<Claim>> = all_refs.iter().filter(|r| matches!(r.s("rkind"), Some("call" | "jmp" | "tail" | "immediate"))).collect();
    let mut relocs: HashMap<i64, i64> = HashMap::new();
    for r in all_refs.iter().filter(|r| r.s("rkind") == Some("reloc")) {
        relocs.insert(r.lo, r.value.get("to").and_then(|v| v.as_i64()).unwrap_or(0));
    }
    let covering = |lo: i64, hi: i64| funcs.iter().copied().filter(move |f| f.lo < hi && lo < f.hi);
    let to = |r: &Claim| r.value.get("to").and_then(|v| v.as_i64()).unwrap_or(0);
    for (is_start, d) in &mine {
        let sk = d.s("skind").unwrap_or("");
        if *is_start {
            let inner = |f: &Claim| f.value.get("inner").and_then(|v| v.as_array()).is_some_and(|a| a.iter().any(|x| x.as_i64() == Some(d.lo)));
            if let Some(hit) = covering(d.lo, d.hi).find(|f| f.lo < d.lo && !inner(f)) {
                out.finding2("error", "L6", d.lo, d.hi, format!("declared start {:#x} lies inside the function {:#x}..{:#x}", d.lo, hit.lo, hit.hi), &d.by, &hit.by);
            }
            continue;
        }
        match sk {
            "dead" | "foreign" => {
                for f in covering(d.lo, d.hi) {
                    out.finding2("error", "L6", d.lo.max(f.lo), d.hi.min(f.hi),
                                  format!("declared {sk} bytes {:#x}..{:#x} are code of the function {:#x}..{:#x}", d.lo, d.hi, f.lo, f.hi), &d.by, &f.by);
                }
                for r in &refs {
                    let t = to(r);
                    if d.lo <= t && t < d.hi {
                        out.finding2("error", "L6", t, t + 1, format!("declared {sk} bytes {:#x}..{:#x} are reached by the {} at {:#x}", d.lo, d.hi,
                                                                          r.s("rkind").unwrap_or(""), r.lo), &d.by, &r.by);
                    }
                }
            }
            "jumptable" | "idxtable" => {
                let fnv = d.value.get("fn").and_then(|v| v.as_i64()).unwrap_or(0);
                if !starts.contains(&fnv) {
                    out.finding("error", "L6", d.lo, d.hi, format!("declared {sk} {:#x}..{:#x}: no function starts at fn={fnv:#x}", d.lo, d.hi), &d.by);
                }
                for f in covering(d.lo, d.hi) {
                    out.finding2("error", "L6", d.lo.max(f.lo), d.hi.min(f.hi),
                                  format!("declared {sk} {:#x}..{:#x} lies inside the code of the function {:#x}..{:#x}", d.lo, d.hi, f.lo, f.hi), &d.by, &f.by);
                }
                for t in &tables {
                    let tfn = t.value.get("fn").and_then(|v| v.as_i64());
                    if t.lo < d.hi && d.lo < t.hi && (t.lo, t.hi, tfn) != (d.lo, d.hi, Some(fnv)) {
                        out.finding2("error", "L6", t.lo.max(d.lo), t.hi.min(d.hi),
                                      format!("declared {sk} {:#x}..{:#x} fn={fnv:#x}, the walk finds {} {:#x}..{:#x} fn={:#x}", d.lo, d.hi,
                                              t.s("skind").unwrap_or(""), t.lo, t.hi, tfn.unwrap_or(0)), &d.by, &t.by);
                    }
                }
            }
            "fptr" => {
                let mut a = d.lo;
                while a <= d.hi - 4 {
                    if !relocs.get(&a).is_some_and(|&t| code.iter().any(|&(lo, hi)| lo <= t && t < hi)) {
                        out.finding("error", "L6", a, a + 4, format!("declared fptr {:#x}..{:#x}: the dword at {a:#x} is not a relocated code address", d.lo, d.hi), &d.by);
                        break;
                    }
                    a += 4;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// M.bytes.declared (R5): declared dead or foreign bytes inside a game unit belong to it (a source fact).
pub fn m_bytes_declared(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let units = game_units(&store::claims(db, &ctx.db, "unit", &ctx.needed, |_| true).map_err(err)?);
    for f in store::claims(db, &ctx.db, "symbol", &ctx.needed, |_| true).map_err(err)? {
        let sk = f.s("skind").unwrap_or("");
        if &*f.rule != "L.decl" || !matches!(sk, "dead" | "foreign") {
            continue;
        }
        let (i, j) = (unit_at(&units, f.lo), unit_at(&units, f.hi - 1));
        if i.is_none() && j.is_none() {
            out.finding("warn", "M.bytes.declared", f.lo, f.hi, format!("declared {sk} bytes {:#x}..{:#x} lie in no unit", f.lo, f.hi), &f.by);
            continue;
        }
        if i != j {
            out.finding("error", "M.bytes.declared", f.lo, f.hi, format!("declared {sk} bytes {:#x}..{:#x} cross a unit boundary", f.lo, f.hi), &f.by);
            continue;
        }
        let v = serde_json::json!({"what": sk, "unit": units[i.unwrap()].tu, "decl": f.by});
        out.claim_reason(f.lo, f.hi, "source", v, f.support.min(DECLARED), f.reason.clone());
    }
    Ok(())
}

#[cfg(test)]
mod tests_2b {
    use crate::pe::testpe::{build, BASE, TEXT};
    use crate::rules::testkit::{of, Kit};
    use serde_json::json;

    fn unit(tu: &str, lo: i64, hi: i64) -> (i64, i64, &'static str, serde_json::Value, crate::store::Support) {
        (lo, hi, "unit", json!({"tu": tu, "status": "x", "start_support": "declared", "end_support": "declared", "start_by": format!("decl:{tu}"), "end_by": ""}), crate::store::DECLARED)
    }

    #[test]
    fn leak_paths_keep_their_directories() {
        let caps = |s: &str| -> Vec<(String, String)> {
            super::LEAK.captures_iter(s).map(|m| {
                let m = m.unwrap();
                (m[1].to_string(), m[2].to_string())
            }).collect()
        };
        assert_eq!(caps(r"c:\src\net\net.c"), [(r"c:\src\net\net.c".to_string(), "net".to_string())]);
        assert_eq!(caps("assert in d:/game/ai_main.cpp line"), [("d:/game/ai_main.cpp".to_string(), "ai_main".to_string())]);
        assert!(caps("%s.c").is_empty());
    }

    #[test]
    fn declared_bytes_leaks_and_rechecks() {
        let k = Kit::new(&build(None));
        let t = (BASE + TEXT) as i64;
        k.put("L.unit.extent", &[unit("a", t, t + 0x30), unit("b", t + 0x30, t + 0x60)]);
        k.put("L.decl", &[(t + 0x10, t + 0x20, "symbol", json!({"skind": "dead"}), crate::store::DECLARED), (t + 0x2c, t + 0x34, "symbol", json!({"skind": "foreign"}), crate::store::DECLARED)]);
        let (rows, c) = k.run("M.bytes.declared", &["L.decl", "L.unit.extent"], "");
        assert_eq!(of(&rows, "source"), vec![(t + 0x10, t + 0x20, json!({"what": "dead", "unit": "a", "decl": "rule:L.decl@1"}))]);
        assert_eq!(c.iter().map(|x| (x.severity.as_str(), x.message.as_str())).collect::<Vec<_>>(),
                   [("error", &*format!("declared foreign bytes {:#x}..{:#x} cross a unit boundary", t + 0x2c, t + 0x34))]);
        k.put("L.analyze", &[(t + 0x10, t + 0x11, "evidence", json!({"ekind": "leak", "path": "c:/a.c", "stem": "a", "header": false, "string": 1}), crate::store::DERIVED),
                             (t + 0x20, t + 0x21, "evidence", json!({"ekind": "leak", "path": "c:/b.c", "stem": "b", "header": false, "string": 2}), crate::store::DERIVED),
                             (t + 0x40, t + 0x41, "evidence", json!({"ekind": "leak", "path": "c:/x.h", "stem": "x", "header": true, "string": 3}), crate::store::DERIVED)]);
        let (_, c) = k.run("L8.leak", &["L.analyze", "L.unit.extent"], "");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].message, format!("unit a holds functions that leak 2 source files: c:/a.c ({:#x}), c:/b.c ({:#x})", t + 0x10, t + 0x20));
        k.put("S.codewalk", &[(t + 0x18, t + 0x28, "symbol", json!({"skind": "func"}), crate::store::REPRODUCED)]);
        for r in ["S.crt.code", "S.thunk", "S.relocs", "S.sections"] {
            k.put(r, &[]);
        }
        let (_, c) = k.run("L6.declared", &["L.decl", "S.codewalk", "S.crt.code", "S.thunk", "S.relocs", "S.sections"], "");
        assert_eq!(c.iter().map(|x| (x.lo - t, x.hi - t)).collect::<Vec<_>>(), [(0x18, 0x20)]);
    }
}

// ------------------------------------------------------------------------------------------------ L.analyzer, L.analyze

/// L.analyzer: every draft of the analyzer whose entry lies in a code section (and the analyzer made on its own)
/// is a declared function start.
pub fn l_analyzer(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    let code = code_ranges(&img);
    for e in drafts(ctx, db)? {
        if code.iter().any(|&(lo, hi)| lo <= e.start && e.start < hi) && !e.seeded {
            let mut v = serde_json::json!({"skind": "func", "how": e.analyzer});
            if !e.name.is_empty() {
                v["name"] = serde_json::json!(e.name);
            }
            if let Some(s) = e.size {
                v["size"] = serde_json::json!(s);
            }
            out.declared(e.start, e.start + 1, "start", v, &format!("decl:analyzer:{}:{}", e.analyzer, e.source), &format!("{} analysis", e.analyzer));
        }
    }
    Ok(())
}

/// layout.LEAK: a path with a .c / .cpp / .h suffix in a string (an __FILE__).
static LEAK: std::sync::LazyLock<fancy_regex::Regex> =
    std::sync::LazyLock::new(|| fancy_regex::Regex::new(r"(?i)(?<![%\w])((?:[a-z]:)?[\w.\\/ -]*?([\w-]{2,})\.(cpp|c|h))(?![\w.])").unwrap());

/// L.analyze: boundary evidence (lit, leak, fill) once per image.
pub fn l_analyze(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    use crate::store::{DERIVED, REPRODUCED};
    let img = image(&ctx.image)?;
    let tc = crate::toolchain::of(&ctx.inputs.toolchain).ok_or_else(|| Error::runtime("L.analyze: no toolchain"))?;
    let fs = |kind: &str| store::claims(db, &ctx.db, kind, &ctx.needed, |_| true).map_err(err);
    let secs: Vec<(i64, i64, String)> = fs("section")?.iter().map(|f| (f.lo, f.hi, f.s("name").unwrap_or("").to_string())).collect();
    let code = code_ranges(&img);
    let in_code = |a: i64| code.iter().any(|&(lo, hi)| lo <= a && a < hi);
    let syms = fs("symbol")?;
    let mut funcs: Vec<&std::rc::Rc<Claim>> = syms.iter().filter(|f| f.s("skind") == Some("func") && f.support > OPEN).collect();
    funcs.sort_by_key(|f| (f.lo, f.hi));
    let at = |a: i64| {
        let i = funcs.partition_point(|f| f.lo <= a);
        (i > 0 && a < funcs[i - 1].hi).then(|| funcs[i - 1])
    };
    let strings: Vec<&std::rc::Rc<Claim>> = syms.iter().filter(|f| f.s("skind") == Some("string")).collect();
    let mut users: HashMap<i64, std::collections::BTreeSet<i64>> = HashMap::new();
    let mut data_refs: HashMap<i64, i64> = HashMap::new();
    for r in fs("ref")?.iter().filter(|r| r.s("rkind") == Some("reloc")) {
        let t = r.value.get("to").and_then(|v| v.as_i64()).unwrap_or(-1);
        let i = strings.partition_point(|s| s.lo <= t);
        if i == 0 || !(strings[i - 1].lo <= t && t < strings[i - 1].hi) {
            continue;
        }
        let s = strings[i - 1];
        if in_code(r.lo) {
            if let Some(f) = at(r.lo) {
                users.entry(s.lo).or_default().insert(f.lo);
            }
        } else {
            *data_refs.entry(s.lo).or_insert(0) += 1;
        }
    }
    let mut fn_at: HashMap<i64, &std::rc::Rc<Claim>> = HashMap::new();
    for f in &funcs {
        fn_at.insert(f.lo, f);
    }
    for s in &strings {
        let us: Vec<&std::rc::Rc<Claim>> = users.get(&s.lo).into_iter().flatten().map(|a| fn_at[a]).collect();
        let Some(first) = us.first() else { continue };
        let lvl = us.iter().map(|u| u.support).chain([s.support, DERIVED]).min().unwrap();
        let sec = secs.iter().find(|(lo, hi, _)| *lo <= s.lo && s.lo < *hi).map(|x| x.2.clone()).unwrap_or_default();
        out.claim(s.lo, s.hi, "evidence", serde_json::json!({"ekind": "lit", "first": first.lo, "users": us.len(), "data_refs": data_refs.get(&s.lo).copied().unwrap_or(0),
                                                            "section": sec}), lvl);
        let text: String = img.cstr(s.lo as u32).iter().map(|&c| c as char).collect();
        for m in LEAK.captures_iter(&text) {
            let m = m.map_err(|e| Error::runtime(format!("L.analyze: {e}")))?;
            let path = m.get(1).unwrap().as_str().trim_matches(|c: char| c.is_whitespace() || ('\x1c'..='\x1f').contains(&c));
            let stem = m.get(2).unwrap().as_str().to_lowercase();
            let header = m.get(3).unwrap().as_str().eq_ignore_ascii_case("h");
            for u in &us {
                out.claim(u.lo, u.lo + 1, "evidence", serde_json::json!({"ekind": "leak", "path": path, "stem": stem, "header": header, "string": s.lo}),
                         lvl.min(u.support).min(REPRODUCED));
            }
        }
    }
    let mut ends: HashSet<i64> = HashSet::new();
    let mut fills: HashMap<i64, &std::rc::Rc<Claim>> = HashMap::new();
    let mut opens: HashSet<i64> = HashSet::new();
    for f in &syms {
        if f.support > OPEN && f.s("skind") != Some("fill") {
            ends.insert(f.hi);
        }
        if f.s("skind") == Some("fill") {
            fills.insert(f.hi, f);
        }
        if f.support == OPEN {
            opens.insert(f.hi);
        }
    }
    for f in &funcs {
        if !in_code(f.lo) {
            continue;
        }
        let v = if let Some(fl) = fills.get(&f.lo) {
            let pre = tc.fill_origin(&img.read(fl.lo as u32, (fl.hi - fl.lo) as usize));
            serde_json::json!({"ekind": "fill", "pre": pre, "run": fl.hi - fl.lo})
        } else if ends.contains(&f.lo) {
            serde_json::json!({"ekind": "fill", "pre": "none", "run": 0})
        } else if opens.contains(&f.lo) {
            serde_json::json!({"ekind": "fill", "pre": "unknown", "run": 0})
        } else {
            continue;
        };
        out.claim(f.lo, f.lo + 1, "evidence", v, f.support.min(DERIVED));
    }
    Ok(())
}

#[cfg(test)]
mod tests_pure {
    use super::*;

    fn u(tu: &str, lo: i64, hi: i64, start_by: &str, end_by: &str) -> Unit {
        Unit { tu: tu.into(), lo, hi, start_support: DECLARED, end_support: DECLARED, start_by: start_by.into(), end_by: end_by.into(), named_by: None }
    }

    fn src(addr: i64, unit: &str, name: &str, by: &str) -> SrcFn {
        (addr, unit.into(), name.into(), by.into())
    }

    #[test]
    fn literal_order() {
        let units = [u("a", 0x1000, 0x1100, "decl:a", "x"), u("b", 0x1100, 0x1200, "decl:b", "x")];
        let lit = |lo: i64, first: i64, data_refs: i64| Lit { lo, hi: lo + 4, first, section: ".data".into(), data_refs };
        let ok = vec![lit(0x2000, 0x1000, 0), lit(0x2004, 0x1150, 0)];
        assert!(lit_issues(&units, &ok).is_empty());
        let mut bad = ok.clone();
        bad.push(lit(0x2008, 0x1010, 0));
        let issues = lit_issues(&units, &bad);
        assert_eq!(issues.iter().map(|i| i.0.as_str()).collect::<Vec<_>>(), ["L3"]);
        assert!(issues[0].3.contains("unit a"), "{}", issues[0].3);
        let mut table = ok.clone();
        table.push(lit(0x2008, 0x1010, 2)); // reached from data: no evidence
        assert!(lit_issues(&units, &table).is_empty());
    }

    #[test]
    fn leaked_files() {
        let units = [u("a", 0x1000, 0x1100, "decl:a", "x")];
        let leak = |func: i64, path: &str, stem: &str, header: bool| Leak { func, path: path.into(), stem: stem.into(), header };
        let issues = leak_issues(&units, &[leak(0x1000, "a.c", "a", false), leak(0x1050, "b.c", "b", false), leak(0x1060, "a.h", "a", true)]);
        assert_eq!(issues.iter().map(|i| i.0.as_str()).collect::<Vec<_>>(), ["L8"]);
        assert!(issues[0].3.contains("2 source files"), "{}", issues[0].3);
    }

    #[test]
    fn unit_states() {
        assert_eq!(unit_status(DECLARED, DECLARED, 0, 0), "separated");
        assert_eq!(unit_status(DECLARED, DECLARED, 3, 0), "open");
        assert_eq!(unit_status(DECLARED, DECLARED, 0, 1), "open");
        assert_eq!(unit_status(DECLARED, OPEN, 0, 0), "open");
    }

    #[test]
    fn outside_the_unit() {
        let units: Vec<UnitExt> = vec![("sfx".into(), 0x42b720, 0x42c3b0, "decl:decl/text.dcl:47".into()),
                                       ("open".into(), 0x42c3b0, 0x42d000, "src:src/open.c:1".into())];
        let srcs = [src(0x42b720, "sfx", "sfx_Open", "src:src/sfx.c:3"),
                    src(0x5de460, "sfx", "MSS_auto_cleanup", "src:src/sfx.c:9"), // library code: L14
                    src(0x5de470, "open", "other", "src:src/open.c:3"),         // no declared boundary
                    src(0x42c400, "sfx", "inside", "src:src/sfx.c:15"),         // game code: L7's case
                    src(0x5de480, "lib", "x", "src:src/lib.c:3")];              // no unit extent
        let declared: HashSet<String> = ["sfx".to_string()].into_iter().collect();
        let issues = outside_unit_issues(&units, &srcs, &declared, (0x401000, 0x5dd3e0), &[]);
        assert_eq!(issues.iter().map(|i| (i.0.as_str(), i.1)).collect::<Vec<_>>(), [("L14", 0x5de460)]);
        assert!(issues[0].3.contains("function of unit sfx (MSS_auto_cleanup) at 0x5de460 lies outside the unit's declared extent 0x42b720..0x42c3b0"),
                "{}", issues[0].3);
        assert_eq!((issues[0].4.as_str(), issues[0].5.as_str()), ("src:src/sfx.c:9", "decl:decl/text.dcl:47"));
        // a library unit is checked against its member range: inside is fine, outside is L14, a member range inside
        // the game code is L14 too
        let srcs = [src(0x5de460, "mss32lib", "MSS_auto_cleanup", "src:src/mss32lib.c:3"),
                    src(0x5de470, "mss32lib", "mss_AutoCleanupExit", "src:src/mss32lib.c:9"),
                    src(0x5de490, "mss32lib", "beyond", "src:src/mss32lib.c:15")];
        let lib: LibUnit = ("mss32lib".into(), 0x5de460, 0x5de480, "decl:decl/text.dcl:188".into());
        let issues = outside_unit_issues(&[], &srcs, &HashSet::new(), (0x401000, 0x5dd3e0), &[lib]);
        assert_eq!(issues.iter().map(|i| (i.0.as_str(), i.1)).collect::<Vec<_>>(), [("L14", 0x5de490)]);
        assert!(issues[0].3.contains("outside its declared member range 0x5de460..0x5de480"), "{}", issues[0].3);
        let inside: LibUnit = ("wrong".into(), 0x401000, 0x401010, "decl:decl/text.dcl:1".into());
        let issues = outside_unit_issues(&[], &[], &HashSet::new(), (0x401000, 0x5dd3e0), &[inside]);
        assert_eq!(issues.iter().map(|i| i.0.as_str()).collect::<Vec<_>>(), ["L14"]);
        assert!(issues[0].3.contains("inside the game code"), "{}", issues[0].3);
    }
}
