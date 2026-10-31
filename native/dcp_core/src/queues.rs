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
use pyo3::types::{PyDict, PyList};
use serde_json::{Map, Value};
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
pub fn function_grades(db: &str) -> PyResult<Vec<Row>> {
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

fn unit_grades(db: &str) -> PyResult<Vec<Row>> {
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
pub fn queue(db: &str, which: &str, shard: Option<(i64, i64)>, unit: Option<&str>) -> PyResult<Vec<Row>> {
    let rows = function_grades(db)?;
    let mut by_unit: Vec<(String, Vec<&Row>)> = vec![];
    for r in &rows {
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
        for r in function_grades(db)? {
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
    let now: std::collections::HashMap<i64, Row> = function_grades(db)?.into_iter().map(|r| (r["addr"].as_i64().unwrap_or(0), r)).collect();
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
    rows_py(py, function_grades(db)?)
}

#[pyfunction]
pub fn grades_unit<'py>(py: Python<'py>, db: &str) -> PyResult<Bound<'py, PyList>> {
    rows_py(py, unit_grades(db)?)
}

#[pyfunction]
#[pyo3(signature = (db, which, shard=None, unit=None))]
pub fn grades_queue<'py>(py: Python<'py>, db: &str, which: &str, shard: Option<(i64, i64)>, unit: Option<&str>) -> PyResult<Bound<'py, PyList>> {
    rows_py(py, queue(db, which, shard, unit)?)
}

#[pyfunction]
pub fn grades_parse_shard(text: &str) -> PyResult<Option<(i64, i64)>> {
    parse_shard(text).map_err(PyValueError::new_err)
}

#[pyfunction]
pub fn grades_shard_owner(start: i64, n: i64) -> i64 {
    shard_owner(start, n)
}

#[pyfunction]
pub fn grades_only_missing_statements(reason: &str) -> bool {
    only_missing_statements(reason)
}

/// (target, address) -> {name, unit, code, readability, level, accepted} of a baseline text.
#[pyfunction]
pub fn grades_parse_baseline<'py>(py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    for ((t, a), e) in parse_baseline(text) {
        let v = PyDict::new(py);
        for (k, x) in [("name", &e.name), ("unit", &e.unit), ("code", &e.code), ("readability", &e.readability), ("level", &e.level),
                       ("accepted", &e.accepted)] {
            v.set_item(k, x)?;
        }
        d.set_item((t, a), v)?;
    }
    Ok(d)
}

/// What fell from a baseline row (code, readability) to the current grade (None: no grade any more).
#[pyfunction]
pub fn grades_falls(code: &str, readability: &str, now: Option<(String, String)>) -> Vec<String> {
    let base = Entry { code: code.into(), readability: readability.into(), ..Default::default() };
    falls(&base, now.as_ref().map(|(c, r)| (c.as_str(), r.as_str())))
}

#[pyfunction]
pub fn grades_at_least(code: &str, readability: &str, grade: &str) -> bool {
    at_least(code, readability, grade)
}

#[pyfunction]
pub fn grades_accept_note(before: &str, after: &str, commit: &str, why: &str) -> String {
    accept_note(before, after, commit, why)
}

#[pyfunction]
pub fn grades_note_from(note: &str) -> Option<String> {
    note_from(note)
}

#[pyfunction]
pub fn grades_baseline_text(targets: Vec<(String, String)>, old: &str, accept_falls: bool, commit: &str) -> PyResult<String> {
    baseline_text(&targets, old, accept_falls, commit)
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
