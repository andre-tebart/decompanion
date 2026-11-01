//! The grades as the commands read them (the `grade` facts of G.grade): the queues, the shards, the baseline
//! (ledger/grades.py is its face, and keeps the source edits of the level ladder: set_level, auto_clear).
//!
//! Queues (units are the separated game units of L.unit.extent, a unit's functions the grade facts of its
//! functions):
//!   base   every function below shape + readable without a level tag. Every code draft comes before any
//!          readability-only work: first the draft functions, units with the fewest drafts first, then the
//!          functions at shape / byte that are not readable, units with the fewest such functions first; address
//!          order inside a unit.
//!   deep   every function with @deep or @stuck, plus every function below byte + readable of a unit whose base
//!          work is done. Units by the total distance (differing instructions) of their items, smallest first;
//!          inside a unit the closest function first; @stuck functions after everything else. An escalated function
//!          that is byte already and only fails readability (a Q-only item) waits behind its unit's byte work and
//!          is the names queue's.
//!   names  the Q-only deep functions (level deep or stuck, code byte, not readable), the deep queue's unit order.
//! Shards: a unit belongs to the shard k of N with the largest sha1("<unit start>:<k>") (rendezvous hashing).
//!
//! The baseline ledger/grades.tsv: target, address, name, unit, code, readability, level, accepted (a header
//! line; sorted by target in config order, then address).

use crate::pystore::json_py;
use crate::store;
use crate::with_db;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyList;
use serde_json::{Map, Value};
use std::rc::Rc;
use sha1::{Digest, Sha1};

const CODE: [&str; 3] = ["draft", "shape", "byte"];
pub const HEADER: &str = "target\taddress\tname\tunit\tcode\treadability\tlevel\taccepted";

fn rank(code: &str) -> Option<usize> {
    CODE.iter().position(|c| *c == code)
}

type Row = Map<String, Value>;

fn s<'a>(r: &'a Row, k: &str) -> &'a str {
    r.get(k).and_then(|v| v.as_str()).unwrap_or("")
}

/// The function grade rows (the value with addr and by), by address.
pub fn function_grades(db: &str) -> PyResult<Rc<Vec<Row>>> {
    store::derived(db, "grades.function", || function_rows(db))
}

fn function_rows(db: &str) -> PyResult<Vec<Row>> {
    let facts = with_db(db, |c| store::facts_of(c, db, "grade", None, |f| f.s("of") == Some("function")))?;
    let mut out: Vec<Row> = facts.iter().map(|f| {
        let mut m = f.value.as_object().cloned().unwrap_or_default();
        m.insert("addr".into(), Value::from(f.lo));
        m.insert("by".into(), Value::String(f.by.clone()));
        m
    }).collect();
    out.sort_by_key(|r| r["addr"].as_i64());
    Ok(out)
}

pub fn unit_grades(db: &str) -> PyResult<Rc<Vec<Row>>> {
    store::derived(db, "grades.unit", || unit_rows(db))
}

fn unit_rows(db: &str) -> PyResult<Vec<Row>> {
    let facts = with_db(db, |c| store::facts_of(c, db, "grade", None, |f| f.s("of") == Some("unit")))?;
    let mut out: Vec<Row> = facts.iter().map(|f| {
        let mut m = f.value.as_object().cloned().unwrap_or_default();
        m.insert("lo".into(), Value::from(f.lo));
        m.insert("hi".into(), Value::from(f.hi));
        m
    }).collect();
    out.sort_by_key(|r| r["lo"].as_i64());
    Ok(out)
}

/// The game units of L.unit.extent: (tu, lo, status), by address.
fn game_units(db: &str) -> PyResult<Vec<(String, i64, String)>> {
    let facts = with_db(db, |c| store::facts_of(c, db, "unit", None, |f| f.value.get("status").is_some()))?;
    let mut out: Vec<(String, i64, String)> = facts.iter().map(|f| (f.s("tu").unwrap_or("").into(), f.lo, f.s("status").unwrap_or("").into())).collect();
    out.sort_by_key(|u| u.1);
    Ok(out)
}

fn below_shape(r: &Row) -> bool {
    s(r, "code") == "draft" || s(r, "readability") != "readable"
}

fn below_byte(r: &Row) -> bool {
    s(r, "code") != "byte" || s(r, "readability") != "readable"
}

fn q_only(r: &Row) -> bool {
    matches!(s(r, "level"), "deep" | "stuck") && s(r, "code") == "byte" && s(r, "readability") != "readable"
}

fn has_level(r: &Row) -> bool {
    r.get("level").is_some_and(|v| !matches!(v, Value::Null) && v.as_str() != Some("") && v.as_bool() != Some(false))
}

fn dist(r: &Row) -> i64 {
    r.get("dist").and_then(|d| d.get("ins")).and_then(|v| v.as_i64()).unwrap_or(0)
}

/// The shard of a unit among n: rendezvous hashing of its start address.
pub fn shard_owner(start: i64, n: i64) -> i64 {
    let mut best: Option<(Vec<u8>, i64)> = None;
    for k in 0..n {
        let d = Sha1::digest(format!("{start:#010x}:{k}").as_bytes()).to_vec();
        if best.as_ref().is_none_or(|(b, _)| d > *b) {
            best = Some((d, k));
        }
    }
    best.map(|b| b.1).unwrap_or(0)
}

fn tagged(r: &Row, unit: &str, section: &str) -> Row {
    let mut m = r.clone();
    m.insert("queue_unit".into(), Value::String(unit.into()));
    m.insert("section".into(), Value::String(section.into()));
    m
}

/// The items of the base / deep / names queue in order (module docstring).
pub fn queue(db: &str, which: &str, shard: Option<(i64, i64)>, unit: Option<&str>) -> PyResult<Rc<Vec<Row>>> {
    store::derived(db, &format!("queue {which} {shard:?} {unit:?}"), || queue_rows(db, which, shard, unit))
}

fn queue_rows(db: &str, which: &str, shard: Option<(i64, i64)>, unit: Option<&str>) -> PyResult<Vec<Row>> {
    let rows = function_grades(db)?;
    let mut by_unit: Vec<(String, Vec<&Row>)> = vec![];
    for r in rows.iter() {
        let u = s(r, "unit");
        match by_unit.iter_mut().find(|x| x.0 == u) {
            Some(x) => x.1.push(r),
            None => by_unit.push((u.to_string(), vec![r])),
        }
    }
    let of = |tu: &str| by_unit.iter().find(|x| x.0 == tu).map(|x| x.1.clone());
    let mut units: Vec<(String, i64, String)> = game_units(db)?.into_iter().filter(|u| u.2 == "separated" && of(&u.0).is_some()).collect();
    if let Some(name) = unit {
        units.retain(|u| u.0 == name);
    } else if let Some((k, n)) = shard {
        units.retain(|u| shard_owner(u.1, n) == k);
    }
    if which == "base" {
        let (mut drafts, mut reads): (Vec<(usize, i64, Vec<Row>)>, Vec<(usize, i64, Vec<Row>)>) = (vec![], vec![]);
        for (tu, lo, _) in &units {
            let base: Vec<&Row> = of(tu).unwrap().into_iter().filter(|r| below_shape(r) && !has_level(r)).collect();
            let d: Vec<Row> = base.iter().filter(|r| s(r, "code") == "draft").map(|r| tagged(r, tu, "draft")).collect();
            let rd: Vec<Row> = base.iter().filter(|r| s(r, "code") != "draft").map(|r| tagged(r, tu, "read")).collect();
            if !d.is_empty() {
                drafts.push((d.len(), *lo, d));
            }
            if !rd.is_empty() {
                reads.push((rd.len(), *lo, rd));
            }
        }
        drafts.sort_by_key(|x| (x.0, x.1));
        reads.sort_by_key(|x| (x.0, x.1));
        return Ok(drafts.into_iter().chain(reads).flat_map(|x| x.2).collect());
    }
    let mut per: Vec<(i64, i64, i64, Vec<Row>)> = vec![];
    for (tu, lo, _) in &units {
        let rs = of(tu).unwrap();
        let base_left = rs.iter().any(|r| below_shape(r) && !has_level(r));
        let all: Vec<&Row> = rs.iter().copied().filter(|r| matches!(s(r, "level"), "deep" | "stuck") || (!base_left && below_byte(r))).collect();
        let byte_items: Vec<&Row> = all.iter().copied().filter(|r| !q_only(r)).collect();
        let mut items: Vec<&Row> = if which == "names" {
            all.iter().copied().filter(|r| q_only(r)).collect()
        } else if !byte_items.is_empty() {
            byte_items.clone()
        } else {
            all.iter().copied().filter(|r| q_only(r)).collect()
        };
        items.sort_by_key(|r| (dist(r), r["addr"].as_i64()));
        if !items.is_empty() {
            let tagged_items = items.iter().map(|r| tagged(r, tu, if s(r, "level") == "stuck" { "stuck" } else { "deep" })).collect();
            per.push((if byte_items.is_empty() { 1 } else { 0 }, byte_items.iter().map(|r| dist(r)).sum(), *lo, tagged_items));
        }
    }
    per.sort_by_key(|x| (x.0, x.1, x.2));
    let flat: Vec<Row> = per.into_iter().flat_map(|x| x.3).collect();
    let (stuck, rest): (Vec<Row>, Vec<Row>) = flat.into_iter().partition(|r| s(r, "section") == "stuck");
    Ok(rest.into_iter().chain(stuck).collect())
}

/// 'k/N' -> (k, N); 'off' -> None.
pub fn parse_shard(text: &str) -> Result<Option<(i64, i64)>, String> {
    let t = text.trim();
    if t == "off" {
        return Ok(None);
    }
    let bad = || format!("a shard is k/N with 0 <= k < N (or off), not {}", crate::decl::py_repr(t));
    let (k, n) = t.split_once('/').ok_or_else(bad)?;
    let digits = |x: &str| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit());
    if !digits(k) || !digits(n) {
        return Err(bad());
    }
    let (k, n): (i64, i64) = (k.parse().map_err(|_| bad())?, n.parse().map_err(|_| bad())?);
    if !(0 <= k && k < n) {
        return Err(bad());
    }
    Ok(Some((k, n)))
}

/// True when every clause of the reason (split at `;` `,` `.` and the word `and`) speaks of missing or unwritten
/// statements, bodies, calls, branches, loops, cases, code or lines: reconstruction is base work.
pub fn only_missing_statements(reason: &str) -> bool {
    use std::sync::LazyLock;
    static SPLIT: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"[;,.]|\band\b").unwrap());
    static MISSING: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(?i)\b(missing|absent|lacks?|lacking|reconstruct\w*|unwritten|not\s+(?:yet\s+)?written|add(?:ed)?)\b").unwrap()
    });
    static STATEMENTS: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(?i)\b(statements?|bod(?:y|ies)|calls?|branch(?:es)?|loops?|cases?|code|lines?)\b").unwrap()
    });
    let clauses: Vec<&str> = SPLIT.split(reason).map(|c| c.trim()).filter(|c| !c.is_empty()).collect();
    !clauses.is_empty() && clauses.iter().all(|c| MISSING.is_match(c) && STATEMENTS.is_match(c))
}

/// The words of a reason that admit a part of the function not read against the original yet (not reconciled, not
/// checked, not compared, not verified, hard to judge): reading the whole function is base work. A word for what the
/// code does (`the parameter is not read`, `cm_SendUnchecked`) is no admission: only these phrasings count.
pub fn admits_unread(reason: &str) -> Option<String> {
    use std::sync::LazyLock;
    static UNREAD: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(?i)\b(un(?:reconciled|checked|verified|examined|compared)|not\s+(?:yet\s+|been\s+|fully\s+)*(?:reconciled|checked|verified|examined|compared)|not\s+yet\s+(?:read|looked\s+at)|(?:did|could|have|has)\s+not\s+(?:yet\s+)?(?:read|check|compare|reconcile)|left\s+unread|unread\s+(?:part|rest|tail|span|half|code|hunks?)|hard\s+to\s+judge)\b").unwrap()
    });
    UNREAD.find(reason).map(|m| m.as_str().split_whitespace().collect::<Vec<_>>().join(" "))
}

// ------------------------------------------------------------------------------------------------ the baseline

/// One baseline entry: name, unit, code, readability, level, accepted.
#[derive(Clone, Default)]
pub struct Entry {
    pub name: String,
    pub unit: String,
    pub code: String,
    pub readability: String,
    pub level: String,
    pub accepted: String,
}

/// (target, address) -> entry of a ledger/grades.tsv text, in file order (a later line of one key replaces the
/// earlier one in its place).
pub fn parse_baseline(text: &str) -> Vec<((String, i64), Entry)> {
    let mut out: Vec<((String, i64), Entry)> = vec![];
    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') || line.starts_with("target\t") {
            continue;
        }
        let mut f: Vec<&str> = line.split('\t').collect();
        while f.len() < 8 {
            f.push("");
        }
        let Some(a) = crate::layout::py_int16(f[1]) else { continue };
        let e = Entry { name: f[2].into(), unit: f[3].into(), code: f[4].into(), readability: f[5].into(), level: f[6].into(), accepted: f[7].into() };
        let key = (f[0].to_string(), a);
        match out.iter_mut().find(|x| x.0 == key) {
            Some(x) => x.1 = e,
            None => out.push((key, e)),
        }
    }
    out
}

/// What fell from a baseline entry to the current grade (None: the function has no grade any more).
pub fn falls(base: &Entry, now: Option<(&str, &str)>) -> Vec<String> {
    let Some((code, readability)) = now else {
        return vec![format!("graded {} + {} in the baseline, no grade now (its source is gone?)", base.code, base.readability)];
    };
    let mut out = vec![];
    if let (Some(b), Some(n)) = (rank(&base.code), rank(code)) {
        if n < b {
            out.push(format!("code {} -> {code}", base.code));
        }
    }
    if base.readability == "readable" && readability != "readable" {
        out.push("readability readable -> draft".into());
    }
    out
}

fn grade_of(code: &str, readability: &str) -> String {
    format!("{code}+{readability}")
}

/// A grade row at or above `code+readability` in both dimensions.
pub fn at_least(code: &str, readability: &str, grade: &str) -> bool {
    let (gc, gr) = grade.split_once('+').unwrap_or((grade, ""));
    rank(code).map(|x| x as i64).unwrap_or(-1) >= rank(gc).map(|x| x as i64).unwrap_or(-1) && (gr != "readable" || readability == "readable")
}

/// The accepted column: `byte+readable -> shape+readable at 897b411: why` (the reason's whitespace runs as one space).
pub fn accept_note(before: &str, after: &str, commit: &str, why: &str) -> String {
    format!("{before} -> {after} at {commit}: {}", why.split_whitespace().collect::<Vec<_>>().join(" "))
}

/// The grade an accepted fall came from (None for an empty or unreadable column).
pub fn note_from(note: &str) -> Option<String> {
    use std::sync::LazyLock;
    static ACCEPTED: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"^(\w+\+\w+) -> (\w+\+\w+) at (\S+): (.*)$").unwrap());
    ACCEPTED.captures(note).map(|c| c[1].to_string())
}

fn render(rows: &[(String, i64, Entry)]) -> String {
    let mut out = String::from(HEADER);
    out.push('\n');
    for (t, a, r) in rows {
        out.push_str(&[t.as_str(), &format!("{a:#010x}"), &r.name, &r.unit, &r.code, &r.readability, &r.level, &r.accepted].join("\t"));
        out.push('\n');
    }
    out
}

fn entry_of(r: &Row) -> Entry {
    let level = match r.get("level") {
        Some(Value::String(x)) => x.clone(),
        _ => String::new(),
    };
    Entry { name: s(r, "name").into(), unit: s(r, "unit").into(), code: s(r, "code").into(), readability: s(r, "readability").into(), level,
            accepted: String::new() }
}

/// ledger/grades.tsv from the current grades of every target ((name, store) in config order). An accepted column
/// of the old text is kept while the function stays below the grade it fell from; with accept_falls every fall
/// against the old text is written with a note `.. at COMMIT: promote --accept-falls`.
pub fn baseline_text(targets: &[(String, String)], old: &str, accept_falls: bool, commit: &str) -> PyResult<String> {
    let base = parse_baseline(old);
    let mut rows = vec![];
    for (t, db) in targets {
        for r in function_grades(db)?.iter() {
            let a = r["addr"].as_i64().unwrap_or(0);
            let mut e = entry_of(&r);
            if let Some((_, o)) = base.iter().find(|x| x.0 .0 == *t && x.0 .1 == a) {
                let src = note_from(&o.accepted);
                if let Some(g) = &src {
                    if !at_least(&e.code, &e.readability, g) {
                        e.accepted = o.accepted.clone();
                    }
                }
                if accept_falls && !falls(o, Some((&e.code, &e.readability))).is_empty() {
                    e.accepted = accept_note(&src.unwrap_or_else(|| grade_of(&o.code, &o.readability)), &grade_of(&e.code, &e.readability), commit,
                                             "promote --accept-falls");
                }
            }
            rows.push((t.clone(), a, e));
        }
    }
    Ok(render(&rows))
}

/// The falls of a target's function grades against a baseline text.
pub fn regressions(target: &str, db: &str, text: &str) -> PyResult<Vec<String>> {
    let mut base: Vec<(i64, Entry)> = parse_baseline(text).into_iter().filter(|x| x.0 .0 == target).map(|x| (x.0 .1, x.1)).collect();
    base.sort_by_key(|x| x.0);
    let now: std::collections::HashMap<i64, Row> = function_grades(db)?.iter().cloned().map(|r| (r["addr"].as_i64().unwrap_or(0), r)).collect();
    let mut out = vec![];
    for (a, r) in base {
        let n = now.get(&a).map(|x| (s(x, "code"), s(x, "readability")));
        for what in falls(&r, n) {
            out.push(format!("{a:#010x} {}: {what}", r.name));
        }
    }
    Ok(out)
}

/// git's answer in a checkout, '' when git fails.
fn git(root: &str, args: &[&str]) -> String {
    match std::process::Command::new("git").args(args).current_dir(root).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        _ => String::new(),
    }
}

// ------------------------------------------------------------------------------------------------ Python's face

fn rows_py<'py>(py: Python<'py>, rows: Vec<Row>) -> PyResult<Bound<'py, PyList>> {
    PyList::new(py, rows.into_iter().map(|r| json_py(py, &Value::Object(r))).collect::<PyResult<Vec<_>>>()?)
}

#[pyfunction]
pub fn grades_function<'py>(py: Python<'py>, db: &str) -> PyResult<Bound<'py, PyList>> {
    rows_py(py, (*function_grades(db)?).clone())
}

/// The baseline text with one function's entry lowered to code + readability and its accepted column set.
#[pyfunction]
pub fn grades_accept(text: &str, target: &str, addr: i64, code: &str, readability: &str, note: &str) -> String {
    let rows: Vec<(String, i64, Entry)> = parse_baseline(text).into_iter().map(|((t, a), mut e)| {
        if t == target && a == addr {
            e.code = code.into();
            e.readability = readability.into();
            e.accepted = note.into();
        }
        (t, a, e)
    }).collect();
    render(&rows)
}

#[pyfunction]
pub fn grades_regressions(target: &str, db: &str, text: &str) -> PyResult<Vec<String>> {
    regressions(target, db, text)
}

/// The short hash of HEAD ('-' outside a git checkout).
#[pyfunction]
pub fn grades_commit_of(root: &str) -> String {
    let h = git(root, &["rev-parse", "--short", "HEAD"]).trim().to_string();
    if h.is_empty() { "-".into() } else { h }
}

/// ledger/grades.tsv at a git revision ('' when it has none).
#[pyfunction]
pub fn grades_baseline_at(root: &str, rev: &str) -> String {
    git(root, &["show", &format!("{rev}:ledger/grades.tsv")])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_order() {
        use crate::rules::testkit::Kit;
        use serde_json::json;
        let k = Kit::new(&crate::pe::testpe::build(None));
        let units = [("a", 0x1000, 0x2000, "separated"), ("b", 0x2000, 0x3000, "separated"), ("c", 0x3000, 0x4000, "separated"), ("open", 0x4000, 0x5000, "open")];
        let uf: Vec<(i64, i64, &str, Value, i64)> = units.iter().map(|&(tu, lo, hi, status)| {
            (lo, hi, "unit", json!({"tu": tu, "status": status, "start_level": "declared", "end_level": "declared", "start_by": "x", "end_by": "y"}), 1)
        }).collect();
        let funcs = [(0x1000, "a1", "a", "draft", "draft", "", 9), (0x1100, "a2", "a", "draft", "readable", "", 3), (0x1200, "a3", "a", "shape", "draft", "", 2),
                     (0x2000, "b1", "b", "draft", "draft", "", 50), (0x2100, "b2", "b", "byte", "readable", "", 0),
                     (0x3000, "c1", "c", "shape", "readable", "", 7), (0x3100, "c2", "c", "byte", "draft", "deep", 0),
                     (0x3200, "c3", "c", "draft", "draft", "stuck", 4), (0x4000, "o1", "open", "draft", "draft", "", 1)];
        let gf: Vec<(i64, i64, &str, Value, i64)> = funcs.iter().map(|&(a, n, u, code, q, lvl, d)| {
            (a, a + 1, "grade", json!({"of": "function", "name": n, "unit": u, "file": format!("src/{u}.c"), "code": code, "readability": q, "level": lvl,
                                       "failing": [], "dist": {"ins": d, "bytes": d, "size": 1, "orig": 1}}), 1)
        }).collect();
        k.put("L.unit.extent", &uf);
        k.put("G.grade", &gf);
        let names = |which: &str, shard: Option<(i64, i64)>| -> Vec<(String, String)> {
            queue(&k.db, which, shard, None).unwrap().iter().map(|r| (s(r, "name").to_string(), s(r, "section").to_string())).collect()
        };
        let pairs = |v: &[(&str, &str)]| -> Vec<(String, String)> { v.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect() };
        // every code draft first (unit b has 1 draft, a has 2), then the readability work; the open unit is left out
        assert_eq!(names("base", None), pairs(&[("b1", "draft"), ("a1", "draft"), ("a2", "draft"), ("a3", "read")]));
        // c has no base item left: its byte work (c1) first, the Q-only c2 waits, the stuck c3 last
        assert_eq!(names("deep", None), pairs(&[("c1", "deep"), ("c3", "stuck")]));
        assert_eq!(names("names", None).iter().map(|x| x.0.as_str()).collect::<Vec<_>>(), ["c2"]);
        let mut got: Vec<String> = (0..2).flat_map(|i| names("base", Some((i, 2)))).map(|x| x.0).collect();
        got.sort();
        let mut all: Vec<String> = names("base", None).into_iter().map(|x| x.0).collect();
        all.sort();
        assert_eq!(got, all);
    }

    #[test]
    fn accepted_column() {
        // an old 7-column file parses (empty accepted column); accept lowers one entry and notes it, every other line stays
        let old = "target\taddress\tname\tunit\tcode\treadability\tlevel\nt\t0x10001000\tf\tu\tbyte\treadable\t\nt\t0x10001010\tg\tu\tshape\tdraft\tdeep\n";
        assert_eq!(parse_baseline(old)[0].1.accepted, "");
        let note = accept_note("byte+readable", "shape+readable", "abc1234", "a VC6\tdeclaration-set\ntie-break");
        assert_eq!(note, "byte+readable -> shape+readable at abc1234: a VC6 declaration-set tie-break");
        let new = grades_accept(old, "t", 0x10001000, "shape", "readable", &note);
        assert_eq!(new, format!("{HEADER}\nt\t0x10001000\tf\tu\tshape\treadable\t\t{note}\nt\t0x10001010\tg\tu\tshape\tdraft\tdeep\t\n"));
        let b = &parse_baseline(&new)[0].1;
        assert_eq!((b.code.as_str(), b.accepted.as_str()), ("shape", note.as_str()));
        assert!(falls(b, Some(("shape", "readable"))).is_empty()); // M1 holds it at shape
        assert_eq!(falls(b, Some(("draft", "readable"))), ["code shape -> draft"]);
        assert!(falls(&parse_baseline(old)[1].1, Some(("byte", "draft"))).is_empty());
        assert!(at_least("byte", "readable", "byte+readable") && !at_least("shape", "readable", "byte+readable") && !at_least("byte", "draft", "shape+readable"));
    }

    #[test]
    fn shards_baseline_and_reasons() {
        assert_eq!(parse_shard("1/3").unwrap(), Some((1, 3)));
        assert_eq!(parse_shard("off").unwrap(), None);
        assert!(parse_shard("3/3").is_err() && parse_shard("x").is_err());
        let owners: Vec<i64> = (0..20).map(|i| shard_owner(0x401000 + i * 0x100, 4)).collect();
        assert!(owners.iter().all(|&k| (0..4).contains(&k)) && owners.iter().any(|&k| k != owners[0]));
        let text = format!("{HEADER}\nexe\t0x00401000\tf\tbio\tbyte\treadable\t\t\nexe\t0x00401040\tg\tbio\tshape\tdraft\tdeep\n");
        let b = parse_baseline(&text);
        assert_eq!(b.len(), 2);
        assert_eq!(b[1].1.level, "deep");
        assert_eq!(falls(&b[0].1, Some(("shape", "readable"))), ["code byte -> shape"]);
        assert!(falls(&b[0].1, None)[0].contains("no grade now"));
        assert!(at_least("byte", "readable", "shape+readable") && !at_least("shape", "draft", "shape+readable"));
        let n = accept_note("byte+readable", "shape+readable", "897b411", "a\tb\n c");
        assert_eq!(n, "byte+readable -> shape+readable at 897b411: a b c");
        assert_eq!(note_from(&n).as_deref(), Some("byte+readable"));
        assert!(only_missing_statements("missing calls; the loop body is not yet written"));
        assert!(!only_missing_statements("register allocation differs"));
    }
}

// ------------------------------------------------------------------------------------------------ the level ladder

/// Write `@<level> reason` into the address comment of a function (the comment that starts on `line` of `rel`),
/// replacing a @deep or @stuck tag already there; no level removes either tag. What was done.
pub fn set_level(root: &str, rel: &str, level: Option<&str>, reason: Option<&str>, line: i64) -> Result<String, String> {
    use std::sync::LazyLock;
    // the tag and its reason run to the end of the comment (written last, below): a reason may hold `*`, `/`, `(...)`
    // and line breaks
    static TAG: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(?:\A|\s)\s*@(deep|stuck)\b").unwrap());
    let path = crate::project::py_path(&format!("{root}/{rel}"));
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?.replace("\r\n", "\n");
    let src = crate::readability::Source::new(&text);
    let tx = &src.text;
    let own = |cs: usize| tx[..cs].iter().rposition(|&c| c == '\n').map(|i| i + 1).unwrap_or(0);
    let c = src.comments.iter().find(|(cs, _, _)| src.line_of(*cs) as i64 == line && tx[own(*cs)..*cs].iter().all(|c| crate::srcscan::py_space(*c)));
    let Some((cs, ce, body)) = c.filter(|c| !crate::srcscan::lead_addrs(&c.2).0.is_empty() || crate::srcscan::UNLINKED.is_match(&c.2)) else {
        return Err(format!("{rel}:{line}: no function's address comment there"));
    };
    let raw: String = tx[*cs..*ce].iter().collect();
    let tag = TAG.captures(body);
    let old = tag.as_ref().map(|c| if &c[1] == "deep" { "@deep" } else { "@stuck" });
    let cut = tag.as_ref().and_then(|c| c.get(0)).map(|m| m.start()).unwrap_or(body.len());
    let stripped = body[..cut].trim_end_matches(crate::srcscan::py_space).to_string();
    let (new_body, action) = match level {
        None => match old {
            None => return Ok("no @deep or @stuck tag".into()),
            Some(o) => (stripped, format!("{o} removed")),
        },
        Some(l) => {
            let reason = crate::srcscan::py_strip(&reason.unwrap_or("").replace("*/", "* /")).to_string();
            let action = match old {
                None => format!("@{l} added"),
                Some(o) if o == format!("@{l}") => format!("@{l} reason replaced"),
                Some(o) => format!("{o} -> @{l}"),
            };
            (format!("{stripped} @{l} {reason}"), action)
        }
    };
    let new_raw = if raw.starts_with("/*") { format!("/*{new_body} */") } else { format!("//{new_body}") };
    let out: String = tx[..*cs].iter().collect::<String>() + &new_raw + &tx[*ce..].iter().collect::<String>();
    crate::edit::write(&path, &out)?;
    Ok(action)
}

/// The line of a graded function's address comment.
fn comment_line(r: &Row) -> i64 {
    r.get("comment").and_then(|v| v.as_i64()).filter(|&c| c != 0).unwrap_or(1)
}

/// Remove the level tag of every function that reached byte + readable; one line per change.
#[pyfunction]
pub fn grades_auto_clear(project: PyRef<'_, crate::project::PyProject>) -> PyResult<Vec<String>> {
    let p = &project.p;
    let root = p.root.to_string_lossy().into_owned();
    let mut out = vec![];
    for r in function_grades(&p.store_path())?.iter() {
        let s = |k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let level = r.get("level").is_some_and(|v| !v.is_null() && v.as_str() != Some(""));
        if level && s("code") == "byte" && s("readability") == "readable" {
            let action = set_level(&root, &s("file"), None, None, comment_line(&r)).map_err(PyValueError::new_err)?;
            out.push(format!("auto-clear {}: {} is byte + readable, {action}", s("file"), s("name")));
        }
    }
    Ok(out)
}

/// The instruction-count difference allocation explains: max(SIZE_INS, the original's count / SIZE_PER). Measured on
/// gildegold (2026-10-31): the 173 shape functions (allocation, slots, frame, order only) differ by at most 7
/// instructions (d3_MatInverse 429 vs 436, gm_Mix 33 vs 27), and 166 of them by none; extra saved registers
/// (push / pop pairs), a spill or a register-held constant add a few instructions, an encoding change none.
pub const SIZE_INS: i64 = 12;
pub const SIZE_PER: i64 = 100;

/// The refusal of a deep escalation whose instruction count differs from the original's beyond what allocation
/// explains (ours, the original's, the allowance), or None.
pub fn size_unexplained(ours: i64, orig: i64) -> Option<(i64, i64, i64)> {
    let allow = SIZE_INS.max(orig / SIZE_PER);
    ((ours - orig).abs() > allow).then_some((ours, orig, allow))
}

/// `dcp escalate|stuck NAME --why` (`--clear`): (the lines, the error for stderr, the exit status). A deep
/// escalation of a function below byte is refused while its instruction count differs from the original's beyond
/// size_unexplained's allowance (missing or wrong statements: base work), unless `size_explained` says why
/// allocation explains it (recorded in the reason).
#[pyfunction]
#[pyo3(signature = (project, level, name, clear, why, capstone=None, size_explained=None))]
#[allow(clippy::too_many_arguments)]
pub fn level_command(project: PyRef<'_, crate::project::PyProject>, level: &str, name: &str, clear: bool, why: Option<String>,
                     capstone: Option<String>, size_explained: Option<String>) -> PyResult<(Vec<String>, Option<String>, i32)> {
    let p = &project.p;
    let Some(r) = crate::asmcmd::find_function(&p.store_path(), name)? else {
        return Ok((vec![], Some(format!("no graded function {name} (dcp build first)")), 1));
    };
    let s = |k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let root = p.root.to_string_lossy().into_owned();
    let line = r.as_object().map(comment_line).unwrap_or(1);
    let action = if clear {
        set_level(&root, &s("file"), None, None, line)
    } else {
        let why = why.unwrap_or_default();
        if why.trim().is_empty() {
            return Ok((vec![], Some("a reason is required".into()), 1));
        }
        if level == "deep" && only_missing_statements(&why) {
            return Ok((vec![], Some("refused: the reason names only missing statements; reconstruction is base work (say which leads were tried and what \
                                     is left)".into()), 1));
        }
        if let Some(w) = admits_unread(&why).filter(|_| level == "deep") {
            return Ok((vec![], Some(format!("refused: the reason admits a part not read against the original (`{w}`); reading and reconciling the \
                                             whole function is base work: finish it, then escalate what is left")), 1));
        }
        let mut why = why;
        if let (true, Some(cap)) = (level == "deep" && s("code") != "byte", capstone.as_deref()) {
            // a function without an object (no reading) has no size to judge
            if let Ok(rd) = crate::asmcmd::reading(p, cap, r.clone(), None)? {
                let (ours, orig) = (rd.la.len() as i64, rd.lb.len() as i64);
                if let Some((o, t, allow)) = size_unexplained(ours, orig) {
                    match size_explained.as_deref().map(str::trim).filter(|x| !x.is_empty()) {
                        None => return Ok((vec![], Some(format!(
                            "refused: ours has {o} instructions, the original {t} ({:+}; allocation explains at most {allow}: max({SIZE_INS}, 1/{SIZE_PER} \
                             of the original's)); a size difference beyond that is missing or wrong statements, and reconstruction is base work \
                             (a difference allocation does cause: --size-explained \"why\")", o - t)), 1)),
                        Some(x) => why = format!("{why} (size: {o} vs {t} instructions, explained: {x})"),
                    }
                }
            }
        }
        set_level(&root, &s("file"), Some(level), Some(&why), line)
    }.map_err(PyValueError::new_err)?;
    let addr = r.get("addr").and_then(|v| v.as_i64()).unwrap_or(0);
    let rec = crate::cliread::record(&[("fn", crate::cliread::Tok::I(addr)), ("name", crate::cliread::Tok::S(s("name"))),
                                       ("file", crate::cliread::Tok::S(s("file"))), ("action", crate::cliread::Tok::S(action))]);
    Ok((vec![rec], None, 0))
}

#[cfg(test)]
mod level_tests {
    use super::*;

    #[test]
    fn level_ladder() {
        assert!(only_missing_statements("missing statements"));
        assert!(only_missing_statements("the loop body is unwritten; two calls are missing"));
        assert!(!only_missing_statements("register choice ebx/esi after the spell pass; missing statements"));
        // a match-base report: the part after +0x5c7 was admitted as not reconciled and escalate took it
        assert_eq!(admits_unread("frame 0x3bc vs 0x3b8. The part after +0x5c7 (summary page) is not yet reconciled and is hard to judge").as_deref(),
                   Some("not yet reconciled"));
        assert_eq!(admits_unread("the store order and the 0x5a paths unverified").as_deref(), Some("unverified"));
        assert_eq!(size_unexplained(436, 429), None); // the largest difference of a shape function on gildegold
        assert_eq!(size_unexplained(1205, 1226), Some((1205, 1226, 12))); // main_Unk5384e0, 4277 vs 4402 bytes
        assert_eq!((size_unexplained(3030, 3000), size_unexplained(3031, 3000)), (None, Some((3031, 3000, 30))));
        assert_eq!(admits_unread("bpp is not read; cm_SendMoveGoodsUnchecked's slots; read to the end, only ebx/esi left"), None);
        let dir = std::env::temp_dir().join(format!("dcp-level-{}", std::process::id()));
        let root = dir.to_string_lossy().into_owned();
        crate::edit::write(&format!("{root}/src/u.c"), "int x;  /* 0x10002000 */\n\n/* 0x10001000, does it */\nvoid f(void)\n{\n}\n").unwrap();
        assert!(set_level(&root, "src/u.c", Some("deep"), Some("the data comment"), 1).is_err());
        assert_eq!(set_level(&root, "src/u.c", Some("deep"), Some("slot order after vargen"), 3).unwrap(), "@deep added");
        assert!(crate::edit::read(&format!("{root}/src/u.c")).contains("\n/* 0x10001000, does it @deep slot order after vargen */\n"));
        assert_eq!(set_level(&root, "src/u.c", Some("stuck"), Some("every lead tried"), 3).unwrap(), "@deep -> @stuck");
        let text = crate::edit::read(&format!("{root}/src/u.c"));
        if let Some(part) = crate::srcscan::tests::scan_alone("src/u.c", &text) {
            let f = &part.functions[0];
            assert_eq!((f.1 .1.as_deref(), f.1 .0.as_deref(), f.0 .6.as_str(), f.1 .3), (Some("every lead tried"), None, "does it", 3));
        }
        assert_eq!(set_level(&root, "src/u.c", None, None, 3).unwrap(), "@stuck removed");
        assert_eq!(crate::edit::read(&format!("{root}/src/u.c")), "int x;  /* 0x10002000 */\n\n/* 0x10001000, does it */\nvoid f(void)\n{\n}\n");
        // a reason with `*`, `/`, `(...)` and a line break, on a comment of several lines: escalate, replace, clear
        // gives the comment back exactly (a match-base report: clear stopped at the first `*` and left the rest)
        let orig = "/* 0x10001000, steps the shot:\n   fall = step * g. Returns 1 while it flies. */\nvoid f(void)\n{\n}\n";
        crate::edit::write(&format!("{root}/src/u.c"), orig).unwrap();
        let why = "body reconstructed (354 ins): fall = step * g and perMass = step / mass;\n   the [esp+0x18] / ebx choice is left";
        assert_eq!(set_level(&root, "src/u.c", Some("deep"), Some(why), 1).unwrap(), "@deep added");
        let tagged = crate::edit::read(&format!("{root}/src/u.c"));
        assert!(tagged.contains(&format!("while it flies. @deep {why} */\nvoid f")), "{tagged}");
        assert_eq!(set_level(&root, "src/u.c", Some("deep"), Some("x * y (z)"), 1).unwrap(), "@deep reason replaced");
        assert!(crate::edit::read(&format!("{root}/src/u.c")).contains("while it flies. @deep x * y (z) */\nvoid f"));
        assert_eq!(set_level(&root, "src/u.c", Some("deep"), Some(why), 1).unwrap(), "@deep reason replaced");
        assert_eq!(set_level(&root, "src/u.c", None, None, 1).unwrap(), "@deep removed");
        assert_eq!(crate::edit::read(&format!("{root}/src/u.c")), orig);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
