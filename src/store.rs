//! The store's facts in memory: the native core holds the facts of every
//! current run of a store, decoded once when the run is first seen; SQLite stays the store of record (every run
//! is written there when it is recorded). A run never changes after it is recorded (a new output is a new run, an
//! unchanged one keeps its run and facts), so memory is keyed by the run's identity (id, time) and the run table
//! says what is current: each read lists the current runs (one small query), loads the runs memory does not hold
//! (recorded by Python, by another process, or before this process started) and drops the ones no longer current.
//! Reads give Store.facts' order: (lo, hi, the value's stored text), ties in run order, then row order.
//! Also the output a native rule builds (facts and conflicts in record order).

use crate::error::Result;
use crate::{put_str, ConflictRow, Row};
use rusqlite::Connection;
use serde_json::Value;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::rc::Rc;

/// The store's tables (ledger/store.py opens a store with them).
pub const SCHEMA_VERSION: &str = "1";
pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS input (key TEXT PRIMARY KEY, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS run (
    id INTEGER PRIMARY KEY, rule TEXT NOT NULL, version TEXT NOT NULL, code_hash TEXT NOT NULL,
    input_hash TEXT NOT NULL, out_hash TEXT NOT NULL DEFAULT '', current INTEGER NOT NULL DEFAULT 0,
    ms INTEGER NOT NULL DEFAULT 0, at REAL NOT NULL DEFAULT 0, UNIQUE(rule, input_hash));
CREATE TABLE IF NOT EXISTS fact (
    id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL, lo INTEGER NOT NULL, hi INTEGER NOT NULL, kind TEXT NOT NULL,
    value TEXT NOT NULL, level INTEGER NOT NULL, by TEXT NOT NULL, reason TEXT);
CREATE INDEX IF NOT EXISTS fact_kind_lo ON fact (kind, lo);
CREATE INDEX IF NOT EXISTS fact_run ON fact (run_id);
CREATE TABLE IF NOT EXISTS conflict (
    id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL, severity TEXT NOT NULL, check_id TEXT NOT NULL,
    lo INTEGER NOT NULL, hi INTEGER NOT NULL, message TEXT NOT NULL, a TEXT NOT NULL DEFAULT '', b TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS conflict_run ON conflict (run_id);
CREATE TABLE IF NOT EXISTS blob (hash TEXT PRIMARY KEY, kind TEXT NOT NULL, data BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS blob_kind ON blob (kind);
CREATE TABLE IF NOT EXISTS bytemap (
    lo INTEGER PRIMARY KEY, hi INTEGER NOT NULL, cls TEXT NOT NULL, level INTEGER NOT NULL,
    symbol INTEGER, unit INTEGER, source INTEGER, section INTEGER);
CREATE TABLE IF NOT EXISTS tu (
    unit TEXT PRIMARY KEY, amalg TEXT NOT NULL, src_hash TEXT NOT NULL, flags TEXT NOT NULL, flags_hash TEXT NOT NULL,
    include_hash TEXT NOT NULL, obj_hash TEXT NOT NULL, ok INTEGER NOT NULL, log TEXT NOT NULL, diags TEXT NOT NULL,
    at REAL NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS include_set (key TEXT PRIMARY KEY, files TEXT NOT NULL);
";

pub const OPEN: i64 = 0;
pub const DECLARED: i64 = 1;
pub const DERIVED: i64 = 2;
pub const PROVEN: i64 = 3;

pub struct SFact {
    pub id: i64, // the fact's row
    pub rule: Rc<str>,
    pub lo: i64,
    pub hi: i64,
    pub text: String, // the stored value (canonical): Store.facts' third sort key
    pub value: Value,
    pub level: i64,
    pub by: String,
    pub reason: Option<String>,
}

impl SFact {
    pub fn s(&self, key: &str) -> Option<&str> {
        self.value.get(key).and_then(|v| v.as_str())
    }
}

pub type Facts = Vec<Rc<SFact>>;

/// One recorded run's facts by kind, in row order.
pub(crate) struct RunFacts {
    pub(crate) rule: String,
    pub(crate) by_kind: HashMap<String, Facts>,
}

impl RunFacts {
    /// Its facts by row id (with their kind): what a run recorded again in place keeps.
    fn by_id(&self) -> HashMap<i64, (&str, &Rc<SFact>)> {
        self.by_kind.iter().flat_map(|(k, v)| v.iter().map(move |f| (f.id, (k.as_str(), f)))).collect()
    }
}

thread_local! {
    // store path -> (run id, run time) -> its facts
    static MEM: RefCell<HashMap<String, HashMap<(i64, u64), Rc<RunFacts>>>> = RefCell::new(HashMap::new());
    // (store path, what) -> (the current runs it was made of, the value)
    static MADE: RefCell<HashMap<(String, String), (Vec<(i64, u64)>, Rc<dyn std::any::Any>)>> = RefCell::new(HashMap::new());
}

/// The identity of the store's current runs: (id, time) of each, by id.
pub fn runs_key(db: &Connection) -> rusqlite::Result<Vec<(i64, u64)>> {
    let mut st = db.prepare_cached("SELECT id, at FROM run WHERE current=1 ORDER BY id")?;
    let rows = st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, f64>(1)?.to_bits())))?;
    rows.collect()
}

/// A value made from the store's current facts (`what` names it with everything else it depends on), made once per
/// state of the current runs: a run's facts never change under its (id, time), so the same runs give the same value.
pub fn derived<T: 'static>(db_path: &str, what: &str, make: impl FnOnce() -> Result<T>) -> Result<Rc<T>> {
    let key = crate::with_db(db_path, |c| runs_key(c))?;
    let id = (db_path.to_string(), what.to_string());
    let hit = MADE.with(|m| m.borrow().get(&id).filter(|e| e.0 == key).and_then(|e| e.1.clone().downcast::<T>().ok()));
    if let Some(v) = hit {
        return Ok(v);
    }
    let v = Rc::new(make()?);
    MADE.with(|m| m.borrow_mut().insert(id, (key, v.clone() as Rc<dyn std::any::Any>)));
    Ok(v)
}

/// A run's facts read from the store. `before`: the same run as memory held it before it was recorded again in
/// place (record_run writes only the facts that changed): a row with the same id and content is that fact.
fn load_run(db: &Connection, rid: i64, rule: &str, before: Option<&RunFacts>) -> rusqlite::Result<RunFacts> {
    let rule_rc: Rc<str> = Rc::from(rule);
    let known = before.map(|b| b.by_id()).unwrap_or_default();
    let mut st = db.prepare_cached("SELECT id, kind, lo, hi, value, level, by, reason FROM fact WHERE run_id=? ORDER BY id")?;
    let mut q = st.query([rid])?;
    let mut by_kind: HashMap<String, Facts> = HashMap::new();
    while let Some(r) = q.next()? {
        let id: i64 = r.get(0)?;
        let kind: String = r.get(1)?;
        let (lo, hi, level): (i64, i64, i64) = (r.get(2)?, r.get(3)?, r.get(5)?);
        let text = r.get_ref(4)?.as_str()?;
        let by = r.get_ref(6)?.as_str()?;
        let reason = r.get_ref(7)?.as_str_or_null()?;
        let same = known.get(&id).filter(|(k, f)| {
            *k == kind && f.lo == lo && f.hi == hi && f.level == level && f.text == text && f.by == by && f.reason.as_deref() == reason
        });
        let f = match same {
            Some((_, f)) => (*f).clone(),
            None => {
                let value: Value = serde_json::from_str(text).unwrap_or(Value::Null);
                Rc::new(SFact { id, rule: rule_rc.clone(), lo, hi, text: text.to_string(), value, level, by: by.to_string(),
                                reason: reason.map(|s| s.to_string()) })
            }
        };
        by_kind.entry(kind).or_default().push(f);
    }
    Ok(RunFacts { rule: rule.to_string(), by_kind })
}

/// The run memory holds for this store and run id when it is the one of time `at` (the run as the store has it).
pub(crate) fn held_run(db_path: &str, run_id: i64, at: f64) -> Option<Rc<RunFacts>> {
    MEM.with(|m| m.borrow().get(db_path).and_then(|h| h.get(&(run_id, at.to_bits())).cloned()))
}

/// A run as just written (its facts with their row ids), held as the store now has it: the next reader needs
/// no read of the store.
pub(crate) fn put_run(db_path: &str, run_id: i64, at: f64, run: RunFacts) {
    MEM.with(|m| {
        let mut m = m.borrow_mut();
        let held = m.entry(db_path.to_string()).or_default();
        held.retain(|k, _| k.0 != run_id);
        held.insert((run_id, at.to_bits()), Rc::new(run));
    })
}

/// The current runs of the store in run order, each with its facts (loaded if memory does not hold it yet).
fn current(db: &Connection, db_path: &str) -> rusqlite::Result<Vec<Rc<RunFacts>>> {
    let runs: Vec<(i64, String, f64)> = {
        let mut st = db.prepare_cached("SELECT id, rule, at FROM run WHERE current=1 ORDER BY id")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        rows.collect::<Result<_, _>>()?
    };
    MEM.with(|m| {
        let mut m = m.borrow_mut();
        let held = m.entry(db_path.to_string()).or_default();
        let live: std::collections::HashSet<(i64, u64)> = runs.iter().map(|(id, _, at)| (*id, at.to_bits())).collect();
        // the runs no longer current by their id: one recorded again in place is read against its earlier facts
        let mut gone: HashMap<i64, Rc<RunFacts>> = HashMap::new();
        held.retain(|k, v| {
            if live.contains(k) {
                return true;
            }
            gone.insert(k.0, v.clone());
            false
        });
        let mut out = Vec::with_capacity(runs.len());
        for (id, rule, at) in &runs {
            let key = (*id, at.to_bits());
            if !held.contains_key(&key) {
                let before = gone.get(id).filter(|b| b.rule == *rule).map(|b| &**b);
                held.insert(key, Rc::new(load_run(db, *id, rule, before)?));
            }
            out.push(held[&key].clone());
        }
        Ok(out)
    })
}

/// Facts of one kind of the current runs of `rules` that `keep` selects, in Store.facts' order.
pub fn facts(db: &Connection, db_path: &str, kind: &str, rules: &[String], keep: impl Fn(&SFact) -> bool) -> rusqlite::Result<Facts> {
    facts_of(db, db_path, kind, Some(rules), keep)
}

/// Facts of one kind of the current runs (of `rules`, None: of every rule) that `keep` selects, in Store.facts'
/// order.
pub fn facts_of(db: &Connection, db_path: &str, kind: &str, rules: Option<&[String]>, keep: impl Fn(&SFact) -> bool) -> rusqlite::Result<Facts> {
    let mut out: Facts = Vec::new();
    for run in current(db, db_path)? {
        if rules.is_some_and(|rules| !rules.iter().any(|r| *r == run.rule)) {
            continue;
        }
        if let Some(v) = run.by_kind.get(kind) {
            out.extend(v.iter().filter(|f| keep(f)).cloned());
        }
    }
    // stable: equal (lo, hi, text) keep run order, then row order
    out.sort_by(|a, b| (a.lo, a.hi, &a.text).cmp(&(b.lo, b.hi, &b.text)));
    Ok(out)
}

/// The addresses (lo) of the facts `keep` selects, unordered: what a rule reads of facts it only locates.
pub fn los(db: &Connection, db_path: &str, kind: &str, rules: &[String], keep: impl Fn(&SFact) -> bool) -> rusqlite::Result<Vec<i64>> {
    let mut out = Vec::new();
    for run in current(db, db_path)? {
        if !rules.iter().any(|r| *r == run.rule) {
            continue;
        }
        if let Some(v) = run.by_kind.get(kind) {
            out.extend(v.iter().filter(|f| keep(f)).map(|f| f.lo));
        }
    }
    Ok(out)
}

// ------------------------------------------------------------------------------------------------ canonical

/// float.__repr__: the shortest round-trip digits, positional for exponents -4 .. 15, else d.ddde+XX.
pub fn py_float(out: &mut String, f: f64) {
    if f.is_nan() {
        out.push_str("NaN");
        return;
    }
    if f.is_infinite() {
        out.push_str(if f > 0.0 { "Infinity" } else { "-Infinity" });
        return;
    }
    let sci = format!("{:e}", f); // shortest round-trip digits: "-1.5e-5", "3e0"
    let (mant, exp) = sci.split_once('e').unwrap();
    let exp: i32 = exp.parse().unwrap();
    let neg = mant.starts_with('-');
    let digits: String = mant.chars().filter(|c| c.is_ascii_digit()).collect();
    if neg {
        out.push('-');
    }
    if (-4..16).contains(&exp) {
        if exp >= 0 {
            let int_len = exp as usize + 1;
            if digits.len() <= int_len {
                out.push_str(&digits);
                for _ in digits.len()..int_len {
                    out.push('0');
                }
                out.push_str(".0");
            } else {
                out.push_str(&digits[..int_len]);
                out.push('.');
                out.push_str(&digits[int_len..]);
            }
        } else {
            out.push_str("0.");
            for _ in 0..(-exp - 1) {
                out.push('0');
            }
            out.push_str(&digits);
        }
    } else {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        let _ = write!(out, "e{}{:02}", if exp < 0 { '-' } else { '+' }, exp.abs());
    }
}

/// fact.canonical of a JSON value (serde_json's map is ordered by key: sort_keys).
pub fn canon(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                let _ = write!(out, "{}", i);
            } else if let Some(u) = n.as_u64() {
                let _ = write!(out, "{}", u);
            } else {
                py_float(out, n.as_f64().unwrap_or(0.0));
            }
        }
        Value::String(s) => put_str(out, s),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canon(out, x);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                put_str(out, k);
                out.push(':');
                canon(out, x);
            }
            out.push('}');
        }
    }
}

// ------------------------------------------------------------------------------------------------ output

/// What a native rule yields: facts (stamped `rule:<id>@<version>` unless a producer is given) and conflicts.
pub struct Out {
    pub by: String,
    pub rows: Vec<Row>,
    pub conflicts: Vec<ConflictRow>,
}

impl Out {
    pub fn new(rule: &str, version: &str) -> Out {
        Out { by: format!("rule:{rule}@{version}"), rows: vec![], conflicts: vec![] }
    }

    pub fn fact(&mut self, lo: i64, hi: i64, kind: &str, value: Value, level: i64) {
        let mut text = String::new();
        canon(&mut text, &value);
        self.rows.push(Row { lo, hi, kind: kind.to_string(), value: text, level, by: self.by.clone(), reason: None });
    }

    /// A fact with a reason (one resting on a declared premise carries the premise's).
    pub fn fact_reason(&mut self, lo: i64, hi: i64, kind: &str, value: Value, level: i64, reason: Option<String>) {
        let mut text = String::new();
        canon(&mut text, &value);
        self.rows.push(Row { lo, hi, kind: kind.to_string(), value: text, level, by: self.by.clone(), reason });
    }

    /// A declared fact of a loader rule: its producer a line of typed state (src:<file>:<line>), with a reason.
    pub fn declared(&mut self, lo: i64, hi: i64, kind: &str, value: Value, by: &str, reason: &str) {
        let mut text = String::new();
        canon(&mut text, &value);
        self.rows.push(Row { lo, hi, kind: kind.to_string(), value: text, level: DECLARED, by: by.to_string(), reason: Some(reason.to_string()) });
    }

    pub fn conflict(&mut self, severity: &str, check: &str, lo: i64, hi: i64, message: String, a: &str) {
        self.conflict2(severity, check, lo, hi, message, a, "");
    }

    /// A conflict naming the producers of both facts.
    pub fn conflict2(&mut self, severity: &str, check: &str, lo: i64, hi: i64, message: String, a: &str, b: &str) {
        self.conflicts.push(ConflictRow {
            severity: severity.to_string(),
            check: check.to_string(),
            lo,
            hi,
            message,
            a: a.to_string(),
            b: b.to_string(),
        });
    }

    /// Facts and conflicts in record_run's order (stable: equal keys keep their yield order).
    pub fn sorted(mut self) -> (Vec<Row>, Vec<ConflictRow>) {
        self.rows.sort_by(|a, b| (a.lo, a.hi, &a.kind, &a.value).cmp(&(b.lo, b.hi, &b.kind, &b.value)));
        self.conflicts.sort_by(|x, y| (x.lo, x.hi, &x.check, &x.message).cmp(&(y.lo, y.hi, &y.check, &y.message)));
        (self.rows, self.conflicts)
    }
}
