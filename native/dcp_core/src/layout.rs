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
