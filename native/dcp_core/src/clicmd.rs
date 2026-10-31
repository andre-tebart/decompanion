//! The read side of cli.py's commands (the Python face refreshes the rules first, then prints these lines): the
//! setup report, why, facts, conflicts, rules, map, the build summary, fn, target list, decl add, layout next /
//! units / unit propose. One record per line, key=value tokens, addresses 0x%08x, intervals lo..hi (hi
//! exclusive), sorted by address, counts before lists; --json gives the same records as JSON lines.

use crate::cliread::{fmt_addr, record, tok, Tok};
use crate::project::{py_path, Project, PyProject};
use crate::store::{self, SFact};
use crate::with_db;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use rusqlite::OptionalExtension;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::rc::Rc;

const LEVELS: [&str; 4] = ["open", "declared", "derived", "proven"];

/// (lines, error for stderr as `dcp CMD: error`, exit code).
type Out = (Vec<String>, Option<String>, i32);

fn err(e: impl std::fmt::Display) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

fn s(x: impl Into<String>) -> Tok {
    Tok::S(x.into())
}

fn os(x: Option<impl Into<String>>) -> Tok {
    x.map(|v| Tok::S(v.into())).unwrap_or(Tok::No)
}

fn level(l: i64) -> &'static str {
    LEVELS.get(l as usize).copied().unwrap_or("open")
}

/// fmt_range: one address when the interval is one byte.
fn fmt_range(lo: i64, hi: i64) -> String {
    if hi > lo + 1 { format!("{lo:#010x}..{hi:#010x}") } else { format!("{lo:#010x}") }
}

/// Python's int(s, 16) for 0x-prefixed text, else int(s, 0).
pub fn parse_addr(s: &str) -> Result<i64, String> {
    let t = s.trim();
    let bad = || format!("invalid literal for int() with base 0: {}", crate::decl::py_repr(t));
    let (neg, body) = match t.strip_prefix('-') {
        Some(b) => (true, b),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let lower = body.to_lowercase().replace('_', "");
    let v = if let Some(h) = lower.strip_prefix("0x") {
        i64::from_str_radix(h, 16).map_err(|_| bad())?
    } else if let Some(o) = lower.strip_prefix("0o") {
        i64::from_str_radix(o, 8).map_err(|_| bad())?
    } else if let Some(b) = lower.strip_prefix("0b") {
        i64::from_str_radix(b, 2).map_err(|_| bad())?
    } else if lower.len() > 1 && lower.starts_with('0') && lower.chars().any(|c| c != '0') {
        return Err(bad());
    } else {
        lower.parse::<i64>().map_err(|_| bad())?
    };
    Ok(if neg { -v } else { v })
}

fn parse_range(s: &str) -> Result<(i64, i64), String> {
    match s.split_once("..") {
        Some((a, b)) => Ok((parse_addr(a)?, parse_addr(b)?)),
        None => parse_addr(s).map(|a| (a, a + 1)),
    }
}

fn value_err(e: String) -> PyErr {
    PyValueError::new_err(e)
}

// ------------------------------------------------------------------------------------------------ values

/// str() of a JSON value as Python spells the decoded object.
fn py_str(v: &Value) -> String {
    match v {
        Value::String(x) => x.clone(),
        v => py_repr(v),
    }
}

/// repr() of a JSON value as Python spells the decoded object.
fn py_repr(v: &Value) -> String {
    match v {
        Value::Null => "None".into(),
        Value::Bool(b) => if *b { "True" } else { "False" }.into(),
        Value::Number(n) => match n.as_i64() {
            Some(i) => i.to_string(),
            None => {
                let mut o = String::new();
                crate::store::canon(&mut o, v);
                o
            }
        },
        Value::String(x) => crate::decl::py_repr(x),
        Value::Array(a) => format!("[{}]", a.iter().map(py_repr).collect::<Vec<_>>().join(", ")),
        Value::Object(m) => format!("{{{}}}", m.iter().map(|(k, x)| format!("{}: {}", crate::decl::py_repr(k), py_repr(x))).collect::<Vec<_>>().join(", ")),
    }
}

/// fact.fmt_value: a value of a fact as `dcp facts` spells it.
fn fmt_value(v: &Value) -> String {
    match v {
        Value::Bool(b) => if *b { "yes" } else { "no" }.into(),
        Value::Number(n) if n.as_i64().is_some() => {
            let i = n.as_i64().unwrap();
            if i >= 0x1000 { format!("{i:#x}") } else { i.to_string() }
        }
        Value::Array(a) => a.iter().map(fmt_value).collect::<Vec<_>>().join(","),
        Value::String(x) if x.contains(' ') || x.is_empty() => crate::decl::py_repr(x),
        v => py_str(v),
    }
}

/// Fact.line: the one-line spelling `dcp facts` prints.
pub fn fact_line(kind: &str, f: &SFact) -> String {
    let vals: Vec<String> = f.value.as_object().map(|m| m.iter().map(|(k, v)| format!("{k}={}", fmt_value(v))).collect()).unwrap_or_default();
    let mut out = format!("{}  {kind}  {}  {}  by={}", fmt_range(f.lo, f.hi), vals.join("  "), level(f.level), f.by);
    if let Some(r) = f.reason.as_ref().filter(|r| !r.is_empty()) {
        out += &format!("  reason={}", crate::decl::py_repr(r));
    }
    out
}

/// A conflict row (severity, check, lo, hi, message, a, b).
type ConflictRow = (String, String, i64, i64, String, String, String);

/// Conflict.line.
pub fn conflict_line(c: &ConflictRow) -> String {
    let mut out = format!("{}  {}  {}  {}", c.0, c.1, fmt_range(c.2, c.3), c.4);
    if !c.5.is_empty() {
        out += &format!("  a={}", c.5);
    }
    if !c.6.is_empty() {
        out += &format!("  b={}", c.6);
    }
    out
}

fn conflicts(db: &str, severity: Option<String>) -> PyResult<Vec<ConflictRow>> {
    crate::pystore::st_conflicts(db, severity, None)
}

fn severity_counts(c: &[ConflictRow]) -> String {
    let mut n: BTreeMap<&str, usize> = BTreeMap::new();
    for x in c {
        *n.entry(x.0.as_str()).or_default() += 1;
    }
    n.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("  ")
}

/// Facts of current runs, of one kind or all, intersecting [lo, hi): (kind, fact), sorted by (lo, hi, kind, value).
fn facts_in(db: &str, kind: Option<&str>, lo: i64, hi: i64) -> PyResult<Vec<(String, SFact)>> {
    let mut q = String::from("SELECT f.id, r.rule, f.lo, f.hi, f.kind, f.value, f.level, f.by, f.reason FROM fact f \
                              JOIN run r ON r.id = f.run_id WHERE r.current=1 AND f.hi>? AND f.lo<?");
    let mut args: Vec<rusqlite::types::Value> = vec![lo.into(), hi.into()];
    if let Some(k) = kind {
        q.push_str(" AND f.kind=?");
        args.push(k.to_string().into());
    }
    q.push_str(" ORDER BY f.lo, f.hi, f.kind, f.value");
    with_db(db, |c| {
        let mut st = c.prepare(&q)?;
        let rows = st.query_map(rusqlite::params_from_iter(args.iter()), row_fact)?;
        rows.collect()
    })
}

fn row_fact(r: &rusqlite::Row) -> rusqlite::Result<(String, SFact)> {
    let text: String = r.get(5)?;
    Ok((r.get(4)?, SFact {
        id: r.get(0)?, rule: Rc::from(r.get::<_, String>(1)?.as_str()), lo: r.get(2)?, hi: r.get(3)?,
        value: serde_json::from_str(&text).unwrap_or(Value::Null), text, level: r.get(6)?, by: r.get(7)?, reason: r.get(8)?,
    }))
}

/// The fact of a row id.
fn fact_by_id(db: &str, id: i64) -> PyResult<Option<(String, SFact)>> {
    with_db(db, |c| {
        c.query_row("SELECT f.id, r.rule, f.lo, f.hi, f.kind, f.value, f.level, f.by, f.reason FROM fact f JOIN run r ON r.id = f.run_id \
                     WHERE f.id=?", [id], row_fact).optional()
    })
}

fn all(db: &str, kind: &str) -> PyResult<store::Facts> {
    with_db(db, |c| store::facts_of(c, db, kind, None, |_| true))
}

fn opened(p: &Project) -> PyResult<String> {
    let db = p.store_path();
    crate::pystore::st_open(&db, &p.main_uri())?;
    Ok(db)
}

/// The image of a target, checked as config.Project.image checks it (the file exists, its sha256 is the
/// declared one).
fn image_of(p: &Project, name: Option<&str>) -> Result<Rc<crate::pe::Image>, String> {
    let t = p.target(name)?;
    if !Path::new(&t.path).exists() {
        return Err(format!("target {}: {} does not exist", t.name, t.path));
    }
    let img = Python::attach(|_| crate::image(&t.path)).map_err(|e| e.to_string())?;
    if !t.sha256.is_empty() {
        let sha = crate::fsmemo::sha256(&t.path).map_err(|e| e.to_string())?;
        if sha != t.sha256 {
            return Err(format!("target {}: {} has sha256 {sha}, the declared one is {}", t.name, t.path, t.sha256));
        }
    }
    Ok(img)
}

fn checked_image(p: &Project) -> PyResult<Rc<crate::pe::Image>> {
    image_of(p, None).map_err(crate::project::cfg_err)
}

// ------------------------------------------------------------------------------------------------ ordered JSON

/// A value of a record: printed as a key=value token, or written as JSON (insertion order kept).
#[derive(Clone)]
enum J {
    Null,
    B(bool),
    I(i64),
    S(String),
    R(i64, i64), // a pair: a range in a record, a list in JSON
    L(Vec<J>),
    O(Vec<(String, J)>),
    V(Value), // a stored value as it is
}

impl J {
    fn tok(&self) -> Tok {
        match self {
            J::Null => Tok::No,
            J::B(b) => Tok::B(*b),
            J::I(i) => Tok::I(*i),
            J::S(x) => Tok::S(x.clone()),
            J::R(a, b) => Tok::R(*a, *b),
            J::L(l) => {
                let j: Vec<String> = l.iter().map(|x| tok(&x.tok())).collect();
                Tok::S(if j.is_empty() { "-".into() } else { j.join(",") })
            }
            J::O(_) => Tok::S(self.json()),
            J::V(v) => match v {
                Value::Null => Tok::No,
                Value::Bool(b) => Tok::B(*b),
                Value::Number(n) if n.as_i64().is_some() => Tok::I(n.as_i64().unwrap()),
                Value::String(x) => Tok::S(x.clone()),
                Value::Array(a) => J::L(a.iter().cloned().map(J::V).collect()).tok(),
                v => Tok::S(py_str(v)),
            },
        }
    }

    fn put(&self, out: &mut String) {
        match self {
            J::Null => out.push_str("null"),
            J::B(b) => out.push_str(if *b { "true" } else { "false" }),
            J::I(i) => out.push_str(&i.to_string()),
            J::S(x) => crate::put_str(out, x),
            J::R(a, b) => out.push_str(&format!("[{a}, {b}]")),
            J::L(l) => {
                out.push('[');
                for (i, x) in l.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    x.put(out);
                }
                out.push(']');
            }
            J::O(m) => {
                out.push('{');
                for (i, (k, x)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    crate::put_str(out, k);
                    out.push_str(": ");
                    x.put(out);
                }
                out.push('}');
            }
            J::V(v) => put_value(out, v),
        }
    }

    /// json.dumps with the default separators.
    fn json(&self) -> String {
        let mut o = String::new();
        self.put(&mut o);
        o
    }
}

/// A stored value in json.dumps' default spelling (keys as stored).
fn put_value(out: &mut String, v: &Value) {
    match v {
        Value::Array(a) => J::L(a.iter().cloned().map(J::V).collect()).put(out),
        Value::Object(m) => J::O(m.iter().map(|(k, x)| (k.clone(), J::V(x.clone()))).collect()).put(out),
        Value::String(x) => crate::put_str(out, x),
        v => crate::store::canon(out, v),
    }
}

fn rec_line(kv: &[(String, J)]) -> String {
    kv.iter().map(|(k, v)| format!("{k}={}", tok(&v.tok()))).collect::<Vec<_>>().join("  ")
}

fn o(kv: Vec<(&str, J)>) -> Vec<(String, J)> {
    kv.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

fn get(r: &[(String, J)], k: &str) -> J {
    r.iter().find(|x| x.0 == k).map(|x| x.1.clone()).unwrap_or(J::Null)
}

// ------------------------------------------------------------------------------------------------ report

/// The analyzer lines of `dcp report`: how many functions have drafts, the export's state, the starts only the
/// analyzer has (and where they lie), the game-code starts only we have, L9 (an analyzer's function spanning one of
/// our starts).
fn analyzer_lines(p: &Project, db: &str, verbose: bool, out: &mut Vec<String>) -> PyResult<()> {
    let v = crate::session::view_of(p)?;
    let mut ents: BTreeMap<i64, Value> = BTreeMap::new();
    for e in with_db(db, |c| crate::names::draft_values(c, &p.main_uri()))? {
        if let Some(a) = e.get("start").and_then(|x| x.as_i64()) {
            ents.insert(a, e);
        }
    }
    let (glo, ghi, _) = v.game;
    let mut ours: BTreeMap<i64, String> = BTreeMap::new();
    for (a, fs) in &v.starts {
        if let Some(h) = fs.iter().filter(|f| &*f.rule != "L.analyzer").filter_map(|f| f.s("how")).next() {
            ours.insert(*a, h.to_string());
        }
    }
    let mut inner: HashSet<i64> = HashSet::new();
    for f in &v.funcs {
        ours.entry(f.lo).or_insert_with(|| "symbol".into());
        inner.extend(f.value.get("inner").and_then(|x| x.as_array()).into_iter().flatten().filter_map(|x| x.as_i64()));
    }
    for f in v.syms.iter().filter(|f| f.s("skind") == Some("thunk")) {
        ours.entry(f.lo).or_insert_with(|| "thunk".into());
    }
    ours.retain(|a, _| !inner.contains(a));
    let mut a_only: Vec<(i64, &Value, String)> = vec![];
    for (a, en) in &ents {
        if ours.contains_key(a) || inner.contains(a) {
            continue;
        }
        let place = match v.container(*a) {
            Some(f) => format!("inside {:#x}", f.lo),
            None => crate::pystore::st_bytemap_at(db, *a)?.map(|r| r.2).unwrap_or_else(|| "-".into()),
        };
        a_only.push((*a, en, place));
    }
    let mut o_only: Vec<(i64, &String)> = ours.iter().filter(|(a, _)| glo <= **a && **a < ghi && !ents.contains_key(a)).map(|(a, h)| (*a, h)).collect();
    let l9: Vec<ConflictRow> = conflicts(db, None)?.into_iter().filter(|c| c.1 == "L9").collect();
    let game: Vec<i64> = v.funcs.iter().map(|f| f.lo).filter(|a| glo <= *a && *a < ghi).collect();
    let state = crate::analyzers::state(p)?;
    let key = crate::analyzers::Analyzer::of(p).map_err(crate::project::cfg_err)?.key;
    out.push(record(&[("analyzer", s(key)), ("drafts", Tok::I(ents.len() as i64)), ("export", s(state)), ("game_functions", Tok::I(game.len() as i64)),
                      ("with_draft", Tok::I(game.iter().filter(|a| ents.contains_key(a)).count() as i64)), ("analyzer_only", Tok::I(a_only.len() as i64)),
                      ("ours_only", Tok::I(o_only.len() as i64)), ("l9", Tok::I(l9.len() as i64))]));
    let mut place: BTreeMap<&str, usize> = BTreeMap::new();
    for (_, _, w) in &a_only {
        *place.entry(w.split(' ').next().unwrap_or("")).or_default() += 1;
    }
    if !place.is_empty() {
        out.push(format!("  analyzer_only by place: {}", place.iter().map(|(k, n)| format!("{k}={n}")).collect::<Vec<_>>().join("  ")));
    }
    if ents.is_empty() {
        // no drafts at all: every start is ours only, a list says nothing
        o_only.clear();
    }
    let most = a_only.len().max(o_only.len()).max(l9.len());
    let n = if verbose { usize::MAX } else { 20 };
    for (a, en, w) in a_only.iter().take(n) {
        let name = en.get("name").and_then(|x| x.as_str()).filter(|x| !x.is_empty()).map(|x| x.to_string());
        let size = en.get("size").and_then(|x| x.as_i64()).map(Tok::I).unwrap_or(Tok::No);
        out.push(format!("  {}", record(&[("analyzer_only", Tok::I(*a)), ("name", os(name)), ("size", size), ("where", s(w.clone())),
                                          ("game", Tok::B(glo <= *a && *a < ghi))])));
    }
    for (a, how) in o_only.iter().take(n) {
        out.push(format!("  {}", record(&[("ours_only", Tok::I(*a)), ("how", s((*how).clone()))])));
    }
    out.extend(l9.iter().take(n).map(|c| format!("  {}", conflict_line(c))));
    if !verbose && most > 20 {
        out.push("  (-v lists all)".into());
    }
    Ok(())
}

/// The setup report of the current target (`dcp setup`, `dcp report`).
#[pyfunction]
pub fn report_command(project: PyRef<'_, PyProject>, verbose: bool) -> PyResult<Vec<String>> {
    let p = &project.p;
    let db = opened(p)?;
    let img = checked_image(p)?;
    let t = p.target(None).map_err(err)?;
    let sha = crate::fsmemo::sha256(&t.path).map_err(err)?;
    let file = Path::new(&t.path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let mut out = vec![format!("target={}  file={file}  sha256={}  base={}  entry={}  {}  linker={}.{}  sections={}", p.target_name, &sha[..16],
                               fmt_addr(img.base as i64), fmt_addr(img.entry as i64), if img.is_dll { "dll" } else { "exe" },
                               img.linker_version.0, img.linker_version.1, img.sections.len())];
    let decl = p.toolchain_decl(None).map_err(err)?;
    let ds = |k: &str| match &decl[k] {
        Value::String(x) if !x.is_empty() => x.clone(),
        Value::Array(a) if !a.is_empty() => a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" "),
        _ => "-".into(),
    };
    let rich = with_db(&db, |c| store::facts_of(c, &db, "toolchain", Some(&["S.rich".to_string()]), |_| true))?;
    let rich = match rich.first() {
        Some(f) => {
            let n = |k: &str| f.value.get(k).and_then(|x| x.as_array()).map_or(0, |a| a.len());
            format!("  rich: compilers={} linkers={} (dcp toolchain)", n("compilers"), n("linkers"))
        }
        None => "  rich: none".into(),
    };
    let r = |x: String| crate::decl::py_repr(&x);
    out.push(format!("toolchain: compiler={} linker={} cflags={} root={}{rich}", r(ds("compiler")), r(ds("linker")), r(ds("cflags")), r(ds("root"))));
    // bytes per section per class and level, sections in map order
    let rows = with_db(&db, |c| crate::pystore::bytemap_rows(c, &db, None, None))?;
    let secs: HashMap<i64, String> = all(&db, "section")?.iter().map(|f| (f.id, f.s("name").unwrap_or("").to_string())).collect();
    let mut by_sec: Vec<(String, Vec<(String, i64)>, [i64; 4])> = vec![];
    for (lo, hi, cls, lvl, _, _, _, sec) in rows {
        let name = sec.and_then(|x| secs.get(&x).cloned()).unwrap_or_else(|| "(headers)".into());
        let i = match by_sec.iter().position(|x| x.0 == name) {
            Some(i) => i,
            None => {
                by_sec.push((name, vec![], [-1; 4]));
                by_sec.len() - 1
            }
        };
        let e = &mut by_sec[i];
        match e.1.iter_mut().find(|x| x.0 == cls) {
            Some(x) => x.1 += hi - lo,
            None => e.1.push((cls, hi - lo)),
        }
        let l = (lvl as usize).min(3);
        e.2[l] = e.2[l].max(0) + hi - lo;
    }
    for (name, mut classes, levels) in by_sec {
        let lv: Vec<String> = (0..4).rev().filter(|&l| levels[l] >= 0).map(|l| format!("{}={:#x}", LEVELS[l], levels[l])).collect();
        classes.sort_by_key(|x| -x.1);
        out.push(format!("section {name}: {}", lv.join("  ")));
        out.push(format!("  {}", classes.iter().map(|(k, v)| format!("{k}={v:#x}")).collect::<Vec<_>>().join("  ")));
    }
    let unit_facts = all(&db, "unit")?;
    let lib_units: BTreeSet<(String, String)> = unit_facts.iter().filter(|f| f.value.get("lib").is_some())
        .map(|f| (f.s("lib").unwrap_or("").to_string(), f.s("tu").unwrap_or("").to_string())).collect();
    let units: HashSet<&String> = lib_units.iter().map(|x| &x.1).collect();
    let mut libs: Vec<(&str, usize)> = vec![];
    for (lib, _) in &lib_units {
        match libs.iter_mut().find(|x| x.0 == lib) {
            Some(x) => x.1 += 1,
            None => libs.push((lib, 1)),
        }
    }
    let funcs: Vec<Rc<SFact>> = all(&db, "symbol")?.into_iter().filter(|f| f.s("skind") == Some("func") && !f.rule.starts_with("M.")).collect();
    let n_at = |l: i64| funcs.iter().filter(|f| f.level == l).count();
    out.push(format!("functions: {} (proven {}, derived {}); library members placed: {} {}", funcs.len(), n_at(store::PROVEN), n_at(store::DERIVED),
                     units.len(), libs.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("  ")));
    for f in all(&db, "name")?.iter().filter(|f| matches!(f.s("origin"), Some("export" | "entry"))) {
        out.push(format!("  {} {} at {}", f.s("origin").unwrap_or(""), f.s("name").unwrap_or(""), fmt_addr(f.lo)));
    }
    let game: Vec<&Rc<SFact>> = unit_facts.iter().filter(|f| f.value.get("status").is_some()).collect();
    if !game.is_empty() {
        let mut c: BTreeMap<String, usize> = BTreeMap::new();
        for f in &game {
            *c.entry(py_str(&f.value["status"])).or_default() += 1;
        }
        out.push(format!("units: {}  {}  (dcp layout units)", game.len(), c.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("  ")));
    }
    analyzer_lines(p, &db, verbose, &mut out)?;
    let mut waiting: Vec<(&str, Vec<String>)> = vec![];
    for r in crate::engine::order(None)? {
        let ins: Vec<String> = r.inputs.iter().map(|x| x.to_string()).collect();
        let w = p.waiting_for(&ins).map_err(err)?;
        if !w.is_empty() {
            waiting.push((r.id, w));
        }
    }
    if !waiting.is_empty() {
        let mut ids: Vec<&str> = waiting.iter().map(|x| x.0).collect();
        ids.sort();
        let mut on: Vec<&String> = vec![];
        for w in waiting.iter().flat_map(|x| &x.1) {
            if !on.contains(&w) {
                on.push(w);
            }
        }
        out.push(record(&[("waiting", Tok::I(waiting.len() as i64)), ("rules", s(ids.join(","))),
                          ("on", s(on.iter().map(|x| x.as_str()).collect::<Vec<_>>().join(",")))]) + "  (their facts are missing until declared)");
    }
    let conf = conflicts(&db, None)?;
    out.push(format!("conflicts: {}", if conf.is_empty() { "0".into() } else { severity_counts(&conf) }));
    Ok(out)
}

// ------------------------------------------------------------------------------------------------ why / facts / conflicts / map

/// `dcp why ADDR|NAME...`: everything known about an address: the byte map row, every fact that covers it,
/// references to and from it. Exit 1 when a name is unknown.
#[pyfunction]
pub fn why_command(project: PyRef<'_, PyProject>, keys: Vec<String>, refs: bool) -> PyResult<Out> {
    let p = &project.p;
    let db = opened(p)?;
    let img = checked_image(p)?;
    let t = &p.target_name;
    let mut out = vec![];
    let mut missing = 0;
    let mut ref_facts: Option<store::Facts> = None;
    for key in &keys {
        let a = match parse_addr(key) {
            Ok(a) => a,
            Err(_) => match crate::cliread::resolve_key(p, key)? {
                Some(a) => a,
                None => {
                    out.push(format!("name={key}  target={t}  unknown (no address or name the ledger knows)"));
                    missing += 1;
                    continue;
                }
            },
        };
        let Some(row) = crate::pystore::st_bytemap_at(&db, a)? else {
            out.push(format!("addr={}  target={t}  not in the image", fmt_addr(a)));
            continue;
        };
        let (lo, hi, cls, lvl, sym, ..) = row;
        let off = match img.section_of(a as u32) {
            Some(sec) => format!("  section={}  off=+{:#x}", sec.name, a - sec.va as i64),
            None => "  (headers)".into(),
        };
        out.push(format!("addr={}  target={t}{off}  cls={cls}  level={}  owner={}", fmt_addr(a), level(lvl), fmt_range(lo, hi)));
        let facts = facts_in(&db, None, a, a + 1)?;
        let mut probed: Vec<&SFact> = facts.iter().filter(|(k, f)| k == "toolchain" && f.value.get("flag").is_some()).map(|x| &x.1).collect();
        if let Some(first) = probed.first().copied() {
            probed.sort_by(|x, y| py_str(&x.value["group"]).cmp(&py_str(&y.value["group"])));
            out.push(format!("  {}  toolchain probe  {}  (dcp toolchain)  by={}", fmt_range(first.lo, first.hi),
                             probed.iter().map(|f| format!("{}={}", py_str(&f.value["flag"]), level(f.level))).collect::<Vec<_>>().join(" "), first.by));
        }
        for (k, f) in &facts {
            if k == "toolchain" && f.value.get("flag").is_some() {
                continue;
            }
            if k == "toolchain" && f.value.get("compilers").is_some() {
                let n = |x: &str| f.value.get(x).and_then(|v| v.as_array()).map_or(0, |a| a.len());
                out.push(format!("  {}  toolchain  compilers={}  linkers={}  (dcp toolchain)  {}  by={}", fmt_range(f.lo, f.hi), n("compilers"),
                                 n("linkers"), level(f.level), f.by));
                continue;
            }
            out.push(format!("  {}", fact_line(k, f)));
        }
        let (mut to, mut from): (Vec<Rc<SFact>>, Vec<(String, SFact)>) = (vec![], vec![]);
        if let Some((_, symf)) = sym.map(|id| fact_by_id(&db, id)).transpose()?.flatten() {
            if ref_facts.is_none() {
                ref_facts = Some(all(&db, "ref")?);
            }
            to = ref_facts.as_ref().unwrap().iter().filter(|f| {
                let x = f.value.get("to").and_then(|v| v.as_i64()).unwrap_or(-1);
                symf.lo <= x && x < symf.hi
            }).cloned().collect();
            from = facts_in(&db, Some("ref"), symf.lo, symf.hi)?;
        }
        if refs {
            let tgt = |f: &SFact| fmt_addr(f.value.get("to").and_then(|v| v.as_i64()).unwrap_or(0));
            for f in &to {
                out.push(format!("  ref->  {} from={} to={}  by={}", py_str(&f.value["rkind"]), fmt_addr(f.lo), tgt(f), f.by));
            }
            for (_, f) in &from {
                out.push(format!("  ref<-  {} at={} to={}  by={}", py_str(&f.value["rkind"]), fmt_addr(f.lo), tgt(f), f.by));
            }
        } else {
            out.push(format!("  refs: to={} from={}  (--refs lists them)", to.len(), from.len()));
        }
    }
    Ok((out, None, if missing > 0 { 1 } else { 0 }))
}

/// `dcp facts RANGE [--kind K] [--json]`.
#[pyfunction]
#[pyo3(signature = (project, range, kind, json))]
pub fn facts_command(project: PyRef<'_, PyProject>, range: &str, kind: Option<String>, json: bool) -> PyResult<Vec<String>> {
    let p = &project.p;
    let db = opened(p)?;
    let (lo, hi) = parse_range(range).map_err(value_err)?;
    let facts = facts_in(&db, kind.as_deref().filter(|k| !k.is_empty()), lo, hi)?;
    if json {
        return Ok(facts.iter().map(|(k, f)| {
            let v = serde_json::json!({"lo": f.lo, "hi": f.hi, "kind": k, "value": f.value, "level": level(f.level), "by": f.by, "reason": f.reason});
            let mut o = String::new();
            crate::store::canon(&mut o, &v);
            o
        }).collect());
    }
    let mut out = vec![format!("target={}  facts={}  range={}{}", p.target_name, facts.len(), fmt_range(lo, hi),
                               kind.filter(|k| !k.is_empty()).map(|k| format!("  kind={k}")).unwrap_or_default())];
    out.extend(facts.iter().map(|(k, f)| fact_line(k, f)));
    Ok(out)
}

/// `dcp conflicts [--severity S] [--json]`.
#[pyfunction]
#[pyo3(signature = (project, severity, json))]
pub fn conflicts_command(project: PyRef<'_, PyProject>, severity: Option<String>, json: bool) -> PyResult<Vec<String>> {
    let p = &project.p;
    let db = opened(p)?;
    let conf = conflicts(&db, severity)?;
    if json {
        return Ok(conf.iter().map(|c| {
            let v = serde_json::json!({"severity": c.0, "check": c.1, "lo": c.2, "hi": c.3, "message": c.4, "a": c.5, "b": c.6});
            let mut o = String::new();
            crate::store::canon(&mut o, &v);
            o
        }).collect());
    }
    let mut out = vec![format!("target={}  conflicts={}{}", p.target_name, conf.len(),
                               if conf.is_empty() { String::new() } else { format!("  {}", severity_counts(&conf)) })];
    out.extend(conf.iter().map(conflict_line));
    Ok(out)
}

/// `dcp map [RANGE]`: the byte map rows of a range (default: the image).
#[pyfunction]
#[pyo3(signature = (project, range))]
pub fn map_command(project: PyRef<'_, PyProject>, range: Option<String>) -> PyResult<Vec<String>> {
    let p = &project.p;
    let db = opened(p)?;
    let (lo, hi) = match range.filter(|r| !r.is_empty()) {
        Some(r) => parse_range(&r).map_err(value_err)?,
        None => {
            let img = checked_image(p)?;
            (img.base as i64, img.end() as i64)
        }
    };
    let rows = crate::pystore::st_bytemap_rows(&db, Some(lo), Some(hi))?;
    let mut out = vec![format!("target={}  rows={}  range={}", p.target_name, rows.len(), fmt_range(lo, hi))];
    for (rlo, rhi, cls, lvl, sym, unit, _, _) in rows {
        let f = sym.map(|id| fact_by_id(&db, id)).transpose()?.flatten();
        let name = f.as_ref().and_then(|(_, f)| f.value.get("name")).map(py_str).unwrap_or_default();
        let ut = match unit.map(|id| fact_by_id(&db, id)).transpose()?.flatten() {
            Some((_, u)) => format!("  unit={}", py_str(&u.value["tu"])),
            None => String::new(),
        };
        let extra = match f.as_ref().and_then(|(_, f)| f.value.get("text")) {
            Some(Value::String(x)) => format!("  text={}", crate::decl::py_repr(x)),
            Some(v) => format!("  text={}", py_repr(v)),
            None => String::new(),
        };
        out.push(format!("{}  {:>7}  {cls:<14} {:<9} {name}{ut}{extra}", fmt_range(rlo, rhi), rhi - rlo, level(lvl)));
    }
    Ok(out)
}

// ------------------------------------------------------------------------------------------------ rules

/// `dcp rules [-v]`: the rule graph in order with each rule's run state.
#[pyfunction]
pub fn rules_command(project: PyRef<'_, PyProject>, verbose: bool) -> PyResult<Vec<String>> {
    let p = &project.p;
    let db = opened(p)?;
    let mut rows = vec![];
    for r in crate::engine::order(None)? {
        let cur = crate::pystore::st_current_run(&db, r.id)?;
        let (n, ms) = match &cur {
            Some(c) => crate::pystore::st_run_stats(&db, c.0)?,
            None => (0, 0),
        };
        let ins: Vec<String> = r.inputs.iter().map(|x| x.to_string()).collect();
        rows.push((r, cur.is_some(), ms, n, p.waiting_for(&ins).map_err(err)?));
    }
    let mut out = vec![record(&[("target", s(p.target_name.clone())), ("rules", Tok::I(rows.len() as i64)),
                                ("current", Tok::I(rows.iter().filter(|x| x.1 && x.4.is_empty()).count() as i64)),
                                ("waiting", Tok::I(rows.iter().filter(|x| !x.4.is_empty()).count() as i64))])];
    for (r, cur, ms, n, waits) in &rows {
        let state = if !waits.is_empty() { "waiting" } else if *cur { "current" } else { "missing" };
        let needs = crate::engine::resolve_needs(r)?.join(",");
        out.push(format!("{:<18} v{:<3} {:<9} {state:<8} {ms:>6} ms {n:>6} facts  needs={}  inputs={}{}", r.id, r.version, level(r.ceiling),
                         if needs.is_empty() { "-".into() } else { needs }, if r.inputs.is_empty() { "-".into() } else { r.inputs.join(",") },
                         if r.loader { "  loader" } else { "" }));
        if !waits.is_empty() {
            out.push(format!("    waiting: {}  (dcp status)", waits.join(", ")));
        }
        if verbose {
            out.extend(r.doc.split('\n').map(|l| format!("    {l}")));
        }
    }
    Ok(out)
}

// ------------------------------------------------------------------------------------------------ build / check

/// `dcp build`'s summary of one target after its compile: (units, compiled, removed, ms) of the compile; `units`
/// lists every unit's build row, not only the failed ones. (lines, failed).
#[pyfunction]
pub fn build_summary(project: PyRef<'_, PyProject>, compile: (i64, i64, i64, i64), units: bool) -> PyResult<(Vec<String>, bool)> {
    let p = &project.p;
    let db = opened(p)?;
    let mut builds = all(&db, "build")?;
    builds.sort_by(|a, b| py_str(&a.value["tu"]).cmp(&py_str(&b.value["tu"])));
    let ok = |f: &SFact| f.value.get("ok").and_then(|x| x.as_bool()).unwrap_or(false);
    let bad: Vec<&Rc<SFact>> = builds.iter().filter(|f| !ok(f)).collect();
    let (n, compiled, removed, ms) = compile;
    let mut out = vec![record(&[("target", s(p.target_name.clone())), ("units", Tok::I(n)), ("compiled", Tok::I(compiled)), ("failed", Tok::I(bad.len() as i64)),
                                ("fresh", Tok::I(n - compiled)), ("removed", Tok::I(removed)), ("ms", Tok::I(ms))])];
    let shown: Vec<&Rc<SFact>> = if units { builds.iter().collect() } else { bad.clone() };
    for f in shown {
        let v = &f.value;
        let errors = v.get("errors").and_then(|x| x.as_array()).cloned().unwrap_or_default();
        out.push(format!("  {}", rec_line(&o(vec![("tu", J::V(v["tu"].clone())), ("at", J::I(f.lo)), ("ok", J::V(v["ok"].clone())),
                                                  ("obj", J::V(v.get("obj").cloned().unwrap_or(Value::Null))),
                                                  ("functions", J::V(v.get("functions").cloned().unwrap_or(Value::Null))),
                                                  ("warnings", J::V(v.get("warnings").cloned().unwrap_or(Value::from(0)))), ("errors", J::I(errors.len() as i64)),
                                                  ("flags", J::V(v.get("flags").cloned().unwrap_or(Value::Null)))]))));
        out.extend(errors.iter().take(10).map(|x| format!("    {}", py_str(x))));
    }
    let rows = crate::queues::function_grades(&db)?;
    if !rows.is_empty() {
        let mut c: BTreeMap<(String, String), usize> = BTreeMap::new();
        for r in &rows {
            let g = |k: &str| r.get(k).map(py_str).unwrap_or_default();
            *c.entry((g("code"), g("readability"))).or_default() += 1;
        }
        out.push(format!("  grades: {}", c.iter().map(|((a, b), v)| format!("{a}+{b}={v}")).collect::<Vec<_>>().join("  ")));
    }
    Ok((out, !bad.is_empty()))
}

/// `dcp check`'s conflict part of one target: the counts line, the bug / error lines (and with `strict` the
/// warnings); (lines, reasons so far).
#[pyfunction]
pub fn check_conflicts(project: PyRef<'_, PyProject>, strict: bool) -> PyResult<(Vec<String>, Vec<String>)> {
    let p = &project.p;
    let db = opened(p)?;
    let conf = conflicts(&db, None)?;
    let bad: Vec<&ConflictRow> = conf.iter().filter(|c| c.0 == "bug" || c.0 == "error").collect();
    let mut out = vec![format!("check target={}: {}", p.target_name, if conf.is_empty() { "no conflicts".into() } else { severity_counts(&conf) })];
    out.extend(bad.iter().map(|c| conflict_line(c)));
    let mut reasons = vec![];
    if !bad.is_empty() {
        reasons.push(format!("errors={}", bad.len()));
    }
    if strict {
        out.extend(conf.iter().filter(|c| c.0 == "warn").map(conflict_line));
        if !conf.is_empty() && bad.is_empty() {
            reasons.push(format!("strict={}", conf.len()));
        }
    }
    Ok((out, reasons))
}

/// The session gate of one target after its build (`dcp session start` / `wrap`): no open toolchain or libs
/// obligation, no failed unit, no bug / error conflict, and (built, the toolchain installed) the full link resolves.
/// (lines unless `quiet`, good, the link's ok (None: skipped), its undrafted externals).
#[pyfunction]
pub fn gate_target(project: PyRef<'_, PyProject>, units: i64, quiet: bool) -> PyResult<(Vec<String>, bool, Option<bool>, Option<usize>)> {
    let p = &project.p;
    let db = opened(p)?;
    let obls = crate::decide::gate_records(p)?;
    let builds = all(&db, "build")?;
    let bad: Vec<String> = builds.iter().filter(|f| !f.value.get("ok").and_then(|x| x.as_bool()).unwrap_or(false)).map(|f| py_str(&f.value["tu"])).collect();
    let errors: Vec<ConflictRow> = conflicts(&db, None)?.into_iter().filter(|c| c.0 == "bug" || c.0 == "error").collect();
    let link = if !builds.is_empty() && p.toolchain_available() { Some(crate::matchcmd::link_lines(p)?) } else { None };
    let good = obls.is_empty() && bad.is_empty() && errors.is_empty() && link.as_ref().is_none_or(|l| l.1);
    let mut out = vec![];
    if !quiet {
        out.push(format!("  {}", record(&[("target", s(p.target_name.clone())), ("built", Tok::I(units)), ("failed", os(Some(bad.join(",")).filter(|x| !x.is_empty()))),
                                          ("errors", Tok::I(errors.len() as i64)),
                                          ("link", s(match &link { None => "skipped", Some(l) if l.1 => "ok", Some(_) => "failed" })),
                                          ("undrafted", link.as_ref().map(|l| Tok::I(l.3 as i64)).unwrap_or(Tok::No)),
                                          ("obligations", if obls.is_empty() { Tok::No } else { Tok::I(obls.len() as i64) }), ("gate", s(if good { "ok" } else { "FAIL" }))])));
        out.extend(obls.iter().map(|o| format!("    {o}")));
        out.extend(errors.iter().take(10).map(|c| format!("    {}", conflict_line(c))));
        out.extend(link.iter().flat_map(|l| l.4.iter().cloned()));
    }
    Ok((out, good, link.as_ref().map(|l| l.1), link.as_ref().map(|l| l.3)))
}

// ------------------------------------------------------------------------------------------------ fn

/// `dcp fn KEY`: one function of the sources, a record with its file and lines (its address comment to the end of its
/// definition), then that text. KEY is a function name or an address of the target.
#[pyfunction]
pub fn fn_command(project: PyRef<'_, PyProject>, key: &str) -> PyResult<Out> {
    let p = &project.p;
    let root = p.root.to_string_lossy().into_owned();
    let src = p.input_hash("src").map_err(err)?.unwrap_or_default();
    let sc = crate::frontend::scan(&root, Some(&src)).map_err(err)?;
    let a = if key.to_lowercase().starts_with("0x") { parse_addr(key).ok() } else { None };
    let default = p.targets[0].name.clone();
    let addr_of = |addrs: &[(Option<String>, u64)]| addrs.iter().find(|(t, _)| t.as_deref().unwrap_or(&default) == p.target_name).map(|x| x.1 as i64);
    let hits: Vec<&crate::srcscan::FnRow> = sc.functions().filter(|f| f.0 .3 == key || (a.is_some() && addr_of(&f.0 .4) == a)).collect();
    if hits.is_empty() {
        return Ok((vec![], Some(format!("no function {key} in the sources (target {})", p.target_name)), 1));
    }
    let mut out = vec![];
    for ((file, _, unit, name, addrs, ..), (.., comment_line, _, end_line, _)) in hits {
        let text = crate::fsmemo::read_text(&py_path(&format!("{root}/{file}"))).map_err(err)?;
        let lines: Vec<&str> = text.split('\n').collect();
        let last = if *end_line > 0 { *end_line as usize } else { lines.len() };
        out.push(record(&[("fn", addr_of(addrs).map(Tok::I).unwrap_or(Tok::No)), ("name", s(name.clone())), ("unit", s(unit.clone())),
                          ("at", s(format!("{file}:{comment_line}-{last}")))]));
        let first = (*comment_line as usize).saturating_sub(1);
        out.extend(lines[first.min(lines.len())..last.min(lines.len())].iter().map(|l| l.to_string()));
    }
    Ok((out, None, 0))
}

// ------------------------------------------------------------------------------------------------ targets

/// `dcp target list [--json]`.
#[pyfunction]
pub fn target_list(project: PyRef<'_, PyProject>, json: bool) -> PyResult<Vec<String>> {
    let p = &project.p;
    let mut rows = vec![];
    for (i, t) in p.targets.iter().enumerate() {
        let isa = match &t.isa {
            Some(x) => x.clone(),
            None => match image_of(p, Some(&t.name)) {
                Ok(img) => format!("{}(machine)", img.default_isa().map(|x| x.to_string()).unwrap_or_else(|| "None".into())),
                Err(_) => "-".into(), // missing file or sha256 mismatch: the list still prints
            },
        };
        let store = format!("build/{}.sqlite", t.name);
        rows.push(o(vec![("target", J::S(t.name.clone())), ("default", J::B(i == 0)), ("path", J::S(t.path.replace('\\', "/"))),
                         ("sha256", J::S(t.sha256.chars().take(16).collect())), ("image", t.image.clone().map(J::S).unwrap_or(J::Null)),
                         ("isa", J::S(isa)), ("exists", J::B(Path::new(&t.path).exists())), ("store", J::S(store.clone())),
                         ("store_exists", J::B(p.root.join(&store).exists())), ("form", J::S(if t.legacy { "legacy" } else { "list" }.into()))]));
    }
    if json {
        return Ok(rows.iter().map(|r| {
            let m: serde_json::Map<String, Value> = r.iter().map(|(k, x)| (k.clone(), match x {
                J::S(v) => Value::String(v.clone()),
                J::B(b) => Value::Bool(*b),
                _ => Value::Null,
            })).collect();
            let mut o = String::new();
            crate::store::canon(&mut o, &Value::Object(m));
            o
        }).collect());
    }
    let mut out = vec![format!("targets={}  default={}", rows.len(), p.targets[0].name)];
    out.extend(rows.iter().map(|r| rec_line(r)));
    Ok(out)
}

// ------------------------------------------------------------------------------------------------ decl add

/// `dcp decl add LINE`: the declaration inserted in address order; (lines, error, exit code, (target, producer)
/// of the new line: the caller refreshes that target and reports its conflicts with `decl_conflicts`).
#[pyfunction]
#[allow(clippy::type_complexity)]
pub fn decl_add(project: PyRef<'_, PyProject>, line: &str) -> PyResult<(Vec<String>, Option<String>, i32, Option<(String, String)>)> {
    let p = &project.p;
    let fail = |m: String| Ok((vec![], Some(m), 1, None));
    let targets: Vec<String> = p.targets.iter().map(|t| t.name.clone()).collect();
    let default = targets[0].clone();
    let mut d = match crate::decl::parse_line(line.trim(), "", 0) {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    if d.target.is_none() && p.target_name != default {
        d.target = Some(p.target_name.clone());
    }
    let tname = d.target.clone().unwrap_or(default.clone());
    if !targets.contains(&tname) {
        return fail(format!("unknown target {} (targets: {})", crate::decl::py_repr(&tname), targets.join(", ")));
    }
    let img = image_of(p, Some(&tname)).map_err(crate::project::cfg_err)?;
    let Some(sec) = img.section_of(d.lo as u32) else {
        return fail(format!("{:#x} is not in a section of {tname}", d.lo));
    };
    if d.target.as_deref() == Some(default.as_str()) {
        d.target = None; // a bare address is the default target
    }
    let fname = if sec.holds_code() { "text.dcl" } else { "data.dcl" };
    let root = p.root.to_string_lossy().into_owned();
    let (existing, _) = crate::decl::load(&crate::decl::files(&root), &root, &targets);
    let key = |x: &crate::decl::Decl| (x.target.clone().unwrap_or(default.clone()), x.lo, x.kind.clone(), x.words.first().cloned().unwrap_or_default());
    if let Some(dup) = existing.iter().find(|x| key(x) == key(&d)) {
        return fail(format!("duplicate of {}:{}: {}", dup.file, dup.line, dup.text()));
    }
    let path = p.root.join("decl").join(fname);
    let n = crate::decl::insert(&path, &d, &targets).map_err(err)?;
    crate::fsmemo::new_epoch();
    let rel = format!("decl/{fname}");
    Ok((vec![format!("added {rel}:{n}  {}", d.text())], None, 0, Some((tname, format!("decl:{rel}:{n}")))))
}

/// The conflicts a producer takes part in (after `dcp decl add` refreshed the target); exit 1 on a bug or error.
#[pyfunction]
pub fn decl_conflicts(project: PyRef<'_, PyProject>, by: &str) -> PyResult<(Vec<String>, i32)> {
    let db = opened(&project.p)?;
    let mine: Vec<ConflictRow> = conflicts(&db, None)?.into_iter().filter(|c| c.5 == by || c.6 == by).collect();
    let bad = mine.iter().any(|c| c.0 == "bug" || c.0 == "error");
    Ok((mine.iter().map(conflict_line).collect(), if bad { 1 } else { 0 }))
}

// ------------------------------------------------------------------------------------------------ layout

/// The first `count` open items of the game code from `start` (layoutview.rs next_records), as ordered records.
fn next_records(v: &crate::layoutview::View, count: usize, start: Option<i64>) -> PyResult<Vec<Vec<(String, J)>>> {
    Ok(v.next_items(count, start)?.into_iter().map(|r| {
        let mut rec = o(vec![("addr", J::I(r.addr)), ("kind", J::S(r.kind.into())), ("size", J::I(r.size)), ("next_start", J::I(r.next_start)),
                             ("unit", r.unit.map(J::S).unwrap_or(J::Null)), ("unit_status", r.unit_status.map(J::S).unwrap_or(J::Null)),
                             ("analyzed", J::B(r.analyzed))]);
        if let Some((lo, hi)) = r.extent {
            rec.push(("extent".into(), J::R(lo, hi)));
        }
        let lines: Vec<J> = r.lines.into_iter().map(|(what, kv)| {
            J::L(vec![J::S(what.into()), J::O(kv.into_iter().map(|(k, x)| (k.to_string(), lv(x))).collect())])
        }).collect();
        rec.push(("lines".into(), J::L(lines)));
        rec
    }).collect())
}

fn lv(x: crate::layoutview::LVal) -> J {
    use crate::layoutview::LVal;
    match x {
        LVal::Null => J::Null,
        LVal::B(b) => J::B(b),
        LVal::I(i) => J::I(i),
        LVal::S(s) => J::S(s),
        LVal::R(a, b) => J::R(a, b),
        LVal::L(l) => J::L(l.into_iter().map(J::S).collect()),
        LVal::V(v) => J::V(v),
    }
}

/// `dcp layout next [-n N] [--start ADDR] [--json]`.
#[pyfunction]
#[pyo3(signature = (project, n, start, json))]
pub fn layout_next(project: PyRef<'_, PyProject>, n: usize, start: Option<String>, json: bool) -> PyResult<Vec<String>> {
    let p = &project.p;
    opened(p)?;
    let v = crate::session::view_of(p)?;
    let start = start.filter(|x| !x.is_empty()).map(|x| parse_addr(&x)).transpose().map_err(value_err)?;
    let recs = next_records(&v, n, start)?;
    if json {
        return Ok(recs.into_iter().map(|r| J::O(r).json()).collect());
    }
    let mut out = vec![];
    if let Some((line, over)) = crate::session::session_clock(&p.root.to_string_lossy(), crate::session::MINUTES) {
        out.push(line + if over { "  (session over: finish or revert the function in progress, then wrap up)" } else { "" });
    }
    let und = v.undrafted_items();
    out.push(record(&[("target", s(p.target_name.clone())), ("game", Tok::R(v.game.0, v.game.1)), ("units", Tok::I(v.units.len() as i64)),
                      ("undrafted_in_units", Tok::I(und.len() as i64)), ("shown", Tok::I(recs.len() as i64))]));
    if recs.is_empty() {
        out.push("nothing open: every function of the game code has a source".into());
        return Ok(out);
    }
    for r in &recs {
        out.push(rec_line(&["addr", "kind", "size", "next_start", "unit", "unit_status", "analyzed"].iter()
            .map(|k| ((if *k == "addr" { "next" } else { k }).to_string(), get(r, k))).collect::<Vec<_>>()));
        if let J::L(lines) = get(r, "lines") {
            for l in lines {
                if let J::L(pair) = l {
                    if let (J::S(what), J::O(kv)) = (&pair[0], &pair[1]) {
                        out.push(format!("  {what}  {}", rec_line(kv)));
                    }
                }
            }
        }
    }
    Ok(out)
}

/// `dcp layout units [-v] [--json]`: the unit table.
#[pyfunction]
#[pyo3(signature = (project, verbose, json))]
pub fn layout_units(project: PyRef<'_, PyProject>, verbose: bool, json: bool) -> PyResult<Vec<String>> {
    let p = &project.p;
    let db = opened(p)?;
    let v = crate::session::view_of(p)?;
    let rows: Vec<Vec<(String, J)>> = v.unit_table().into_iter().map(|r| r.into_iter().map(|(k, x)| (k.to_string(), lv(x))).collect()).collect();
    if json {
        return Ok(rows.into_iter().map(|r| J::O(r).json()).collect());
    }
    let (glo, ghi, glevel) = v.game;
    let range = |r: &[(String, J)]| match get(r, "range") {
        J::R(a, b) => (a, b),
        _ => (0, 0),
    };
    let covered: i64 = rows.iter().map(|r| range(r).1 - range(r).0).sum();
    let status = |r: &[(String, J)]| match get(r, "status") {
        J::V(Value::String(x)) | J::S(x) => x,
        _ => String::new(),
    };
    let lib: BTreeSet<String> = all(&db, "unit")?.iter().filter(|f| f.value.get("lib").is_some()).map(|f| py_str(&f.value["tu"])).collect();
    let mut out = vec![record(&[("target", s(p.target_name.clone())), ("units", Tok::I(rows.len() as i64)),
                                ("separated", Tok::I(rows.iter().filter(|r| status(r) == "separated").count() as i64)),
                                ("open", Tok::I(rows.iter().filter(|r| status(r) == "open").count() as i64)), ("game", Tok::R(glo, ghi)),
                                ("game_end", s(level(glevel))), ("unassigned", Tok::I((ghi - glo) - covered)), ("library_members", Tok::I(lib.len() as i64))])];
    let (und, conf, sc) = if verbose {
        let root = p.root.to_string_lossy().into_owned();
        let src = p.input_hash("src").map_err(err)?.unwrap_or_default();
        (v.undrafted_items(), conflicts(&db, None)?, Some(crate::frontend::scan(&root, Some(&src)).map_err(err)?))
    } else {
        (vec![], vec![], None)
    };
    for r in &rows {
        let mut row: Vec<(String, J)> = ["unit", "range", "status", "start", "end", "named_by", "open_bytes", "functions", "sourced", "undrafted"].iter()
            .map(|k| (k.to_string(), get(r, k))).collect();
        let leaks = get(r, "leaks");
        row.push(("leaks".into(), if matches!(&leaks, J::L(l) if l.is_empty()) { J::Null } else { leaks }));
        out.push(rec_line(&row));
        if !verbose {
            continue;
        }
        out.push(format!("  {}", rec_line(&["start_by", "end_by", "dead_bytes", "walk_conflicts"].iter().map(|k| (k.to_string(), get(r, k))).collect::<Vec<_>>())));
        let (lo, hi) = range(r);
        let mine: Vec<i64> = und.iter().copied().filter(|a| lo <= *a && *a < hi).collect();
        out.extend(mine.iter().take(8).map(|a| format!("  {}  (L2)", record(&[("undrafted", Tok::I(*a))]))));
        if mine.len() > 8 {
            out.push(format!("  ... {} more undrafted (L2): dcp layout next --start {:#010x} -n N", mine.len() - 8, mine[8]));
        }
        out.extend(conf.iter().filter(|c| matches!(c.1.as_str(), "L10" | "C.walk" | "M.bytes.declared") && lo <= c.2 && c.2 < hi)
            .map(|c| format!("  {}", conflict_line(c))));
        let unit = match get(r, "unit") {
            J::V(Value::String(x)) | J::S(x) => x,
            _ => String::new(),
        };
        if let Some(sc) = &sc {
            for ((file, _, u, name, _, unlinked, what), _) in sc.functions() {
                if *unlinked && *u == unit {
                    out.push(format!("  {}", record(&[("unlinked", s(name.clone())), ("file", s(file.clone())),
                                                      ("why", os(Some(what.clone()).filter(|w| !w.is_empty())))])));
                }
            }
        }
    }
    Ok(out)
}

/// `dcp layout unit propose RANGE --name N --why W [--by B] [--dry-run]`: the proposal checked (L3 / L4 / L7 / L8 on
/// the units as it would make them) and, unless refused or a dry run, its boundary lines written; (lines, error,
/// exit code, written: the caller refreshes and prints `propose_verdict`).
#[pyfunction]
#[pyo3(signature = (project, range, name, why, by, dry_run))]
pub fn propose_command(project: PyRef<'_, PyProject>, range: &str, name: &str, why: &str, by: Option<String>, dry_run: bool)
    -> PyResult<(Vec<String>, Option<String>, i32, bool)> {
    let p = &project.p;
    opened(p)?;
    let (lo, hi) = if range.contains("..") {
        let (a, b) = parse_range(range).map_err(value_err)?;
        (a, Some(b))
    } else {
        (parse_addr(range).map_err(value_err)?, None)
    };
    static UNIT: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"^[A-Za-z_][A-Za-z0-9_.\-]*$").unwrap());
    if !UNIT.is_match(name) {
        return Ok((vec![], Some(format!("{} is not a unit name", crate::decl::py_repr(name))), 1, false));
    }
    let v = crate::session::view_of(p)?;
    if let Some(b) = v.bounds.iter().find(|b| b.2 == name && b.1 == "start") {
        return Ok((vec![], Some(format!("unit {name} already starts at {:#x} ({})", b.0, b.3)), 1, false));
    }
    let pr = v.proposal(lo, hi, name);
    let by_tok = by.clone().map(Tok::S).unwrap_or(Tok::No);
    let mut out = vec![record(&[("proposal", s(name)), ("range", Tok::R(pr.lo, pr.end)), ("functions", Tok::I(pr.table.len() as i64)),
                                ("drafted", Tok::I(pr.table.iter().filter(|t| t.drafted).count() as i64)), ("new_issues", Tok::I(pr.new.len() as i64)),
                                ("by", by_tok), ("why", s(why))])];
    for t in &pr.table {
        out.push(format!("  {}", rec_line(&o(vec![("fn", J::I(t.lo)), ("size", J::I(t.size)), ("fill", t.fill.clone().map(J::V).unwrap_or(J::Null)),
                                                  ("drafted", J::B(t.drafted)), ("literals", J::I(t.lits)), ("first_literal", t.first_lit.map(J::I).unwrap_or(J::Null)),
                                                  ("leaks", if t.leaks.is_empty() { J::Null } else { J::L(t.leaks.iter().cloned().map(J::S).collect()) })]))));
    }
    for i in &pr.new {
        out.push(format!("  issue  error  {}  {}  {}", i.0, fmt_range(i.1, i.2), i.3));
    }
    if !pr.new.is_empty() {
        out.push(format!("refused: {} error(s); nothing written", pr.new.len()));
        return Ok((out, None, 1, false));
    }
    if dry_run {
        out.push("dry run: nothing written".into());
        return Ok((out, None, 0, false));
    }
    let targets: Vec<String> = p.targets.iter().map(|t| t.name.clone()).collect();
    let prefix = (p.target_name != targets[0]).then(|| p.target_name.clone());
    let path = p.root.join("decl").join("text.dcl");
    for (addr, side) in &pr.lines {
        let mut keys = vec![("tu".to_string(), crate::decl::KeyVal::Str(name.into()))];
        if let Some(b) = by.as_ref().filter(|_| *side == "start") {
            keys.push(("by".into(), crate::decl::KeyVal::Str(b.clone())));
        }
        let d = crate::decl::Decl { lo: *addr, hi: addr + 1, kind: "boundary".into(), words: vec![side.to_string()], keys, reason: why.into(),
                                    target: prefix.clone(), file: String::new(), line: 0 };
        let n = crate::decl::insert(&path, &d, &targets).map_err(err)?;
        out.push(format!("added decl/text.dcl:{n}  {}", d.text()));
    }
    crate::fsmemo::new_epoch();
    Ok((out, None, 0, true))
}

/// The verdict on a written proposal after the refresh: its own errors apart from the others'; exit 1 on its own.
#[pyfunction]
pub fn propose_verdict(project: PyRef<'_, PyProject>, name: &str) -> PyResult<(Vec<String>, i32)> {
    let p = &project.p;
    let db = opened(p)?;
    let text = crate::fsmemo::read_text(&py_path(&p.root.join("decl").join("text.dcl").to_string_lossy())).map_err(err)?;
    let bys: HashSet<String> = text.lines().enumerate().filter(|(_, l)| format!("{l} ").contains(&format!("tu={name} ")))
        .map(|(i, _)| format!("decl:decl/text.dcl:{}", i + 1)).collect();
    let bad: Vec<ConflictRow> = conflicts(&db, None)?.into_iter().filter(|c| c.0 == "bug" || c.0 == "error").collect();
    let mine: Vec<&ConflictRow> = bad.iter().filter(|c| bys.contains(&c.5) || bys.contains(&c.6)).collect();
    let mut out = vec![record(&[("proposal", s(if mine.is_empty() { "ok" } else { "FAIL" })), ("proposal_errors", Tok::I(mine.len() as i64)),
                                ("other_errors", Tok::I((bad.len() - mine.len()) as i64))])
        + if bad.len() > mine.len() { "  (the other errors are not the proposal's: dcp check lists them)" } else { "" }];
    out.extend(mine.iter().map(|c| conflict_line(c)));
    Ok((out, if mine.is_empty() { 0 } else { 1 }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_and_values() {
        assert_eq!(parse_addr("0x10").unwrap(), 16);
        assert_eq!(parse_addr(" 42 ").unwrap(), 42);
        assert_eq!(parse_addr("0").unwrap(), 0);
        assert!(parse_addr("010").is_err() && parse_addr("udp_Init").is_err());
        assert_eq!(parse_range("0x10..0x20").unwrap(), (16, 32));
        assert_eq!(parse_range("0x10").unwrap(), (16, 17));
        assert_eq!((fmt_range(16, 17), fmt_range(16, 32)), ("0x00000010".to_string(), "0x00000010..0x00000020".to_string()));
        let v: Value = serde_json::from_str(r#"{"a": 4096, "b": [1, "x y"], "c": true, "d": "", "e": {"k": null}}"#).unwrap();
        let f = SFact { id: 1, rule: Rc::from("r"), lo: 0x1000, hi: 0x1004, text: String::new(), value: v, level: 2, by: "rule:r@1".into(), reason: Some("why".into()) };
        assert_eq!(fact_line("symbol", &f), "0x00001000..0x00001004  symbol  a=0x1000  b=1,'x y'  c=yes  d=''  e={'k': None}  derived  by=rule:r@1  reason='why'");
        assert_eq!(J::O(o(vec![("a", J::R(1, 2)), ("b", J::V(serde_json::json!({"x": "é"})))])).json().replace('\\', "/"), r#"{"a": [1, 2], "b": {"x": "/u00e9"}}"#);
    }
}
