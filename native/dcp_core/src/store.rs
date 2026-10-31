//! The store's facts for native rules: the current runs' facts of a kind, as ledger/store.py's Store.facts gives
//! them (sorted by lo, hi, the value's stored text; ties in run order, then row order), decoded once per run and
//! kept while the run stays current; and the output a native rule builds (facts and conflicts in record order).

use crate::{put_str, ConflictRow, Row};
use rusqlite::Connection;
use serde_json::Value;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::rc::Rc;

pub const OPEN: i64 = 0;
pub const DECLARED: i64 = 1;
pub const DERIVED: i64 = 2;
pub const PROVEN: i64 = 3;

pub struct SFact {
    pub rule: Rc<str>,
    pub lo: i64,
    pub hi: i64,
    pub value: Value,
    pub level: i64,
    pub by: String,
}

impl SFact {
    pub fn s(&self, key: &str) -> Option<&str> {
        self.value.get(key).and_then(|v| v.as_str())
    }
}

type Decoded = Rc<Vec<(i64, i64, String, Rc<SFact>)>>;

type Merged = Rc<Vec<Rc<SFact>>>;

thread_local! {
    // (db, run id, run at, kind) -> the run's facts of that kind
    static RUNS: RefCell<HashMap<(String, i64, u64, String), Decoded>> = RefCell::new(HashMap::new());
    // (db, kind, the chosen runs) -> their facts merged in order (most rules of a refresh read the same)
    static MERGED: RefCell<HashMap<(String, String, Vec<(i64, u64)>), Merged>> = RefCell::new(HashMap::new());
}

/// The current runs of the store: (id, rule, at).
pub fn current_runs(db: &Connection) -> rusqlite::Result<Vec<(i64, String, f64)>> {
    let mut st = db.prepare_cached("SELECT id, rule, at FROM run WHERE current=1")?;
    let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
    rows.collect()
}

/// Facts of one kind of the current runs of `rules`, in Store.facts' order.
pub fn facts(db: &Connection, db_path: &str, kind: &str, rules: &[String]) -> rusqlite::Result<Merged> {
    let runs = current_runs(db)?;
    let chosen: Vec<&(i64, String, f64)> = runs.iter().filter(|(_, r, _)| rules.iter().any(|x| x == r)).collect();
    let mkey = (db_path.to_string(), kind.to_string(), chosen.iter().map(|(rid, _, at)| (*rid, at.to_bits())).collect::<Vec<_>>());
    if let Some(hit) = MERGED.with(|m| m.borrow().get(&mkey).cloned()) {
        return Ok(hit);
    }
    let mut decoded = Vec::with_capacity(chosen.len());
    for (rid, rule, at) in &chosen {
        let key = (db_path.to_string(), *rid, at.to_bits(), kind.to_string());
        let hit = RUNS.with(|m| m.borrow().get(&key).cloned());
        let got = match hit {
            Some(g) => g,
            None => {
                let rule_rc: Rc<str> = Rc::from(rule.as_str());
                let mut st = db.prepare_cached("SELECT lo, hi, value, level, by FROM fact WHERE run_id=? AND kind=?")?;
                let mut v = Vec::new();
                let mut q = st.query(rusqlite::params![rid, kind])?;
                while let Some(r) = q.next()? {
                    let text: String = r.get(2)?;
                    let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                    let f = SFact { rule: rule_rc.clone(), lo: r.get(0)?, hi: r.get(1)?, value, level: r.get(3)?, by: r.get(4)? };
                    v.push((f.lo, f.hi, text, Rc::new(f)));
                }
                let g: Decoded = Rc::new(v);
                RUNS.with(|m| {
                    let mut m = m.borrow_mut();
                    if m.len() > 4096 {
                        m.clear();
                    }
                    m.insert(key, g.clone());
                });
                g
            }
        };
        decoded.push(got);
    }
    // (lo, hi, value text) by reference, ties in run then row order: a stable sort of the runs' rows in that order
    let mut rows: Vec<&(i64, i64, String, Rc<SFact>)> = decoded.iter().flat_map(|g| g.iter()).collect();
    rows.sort_by(|a, b| (a.0, a.1, &a.2).cmp(&(b.0, b.1, &b.2)));
    let merged: Merged = Rc::new(rows.into_iter().map(|r| r.3.clone()).collect());
    let live: std::collections::HashSet<(i64, u64)> = runs.iter().map(|(rid, _, at)| (*rid, at.to_bits())).collect();
    MERGED.with(|m| {
        let mut m = m.borrow_mut();
        m.retain(|k, _| k.2.iter().all(|x| live.contains(x)));
        if m.len() > 256 {
            m.clear();
        }
        m.insert(mkey, merged.clone());
    });
    Ok(merged)
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

    pub fn conflict(&mut self, severity: &str, check: &str, lo: i64, hi: i64, message: String, a: &str) {
        self.conflicts.push(ConflictRow {
            severity: severity.to_string(),
            check: check.to_string(),
            lo,
            hi,
            message,
            a: a.to_string(),
            b: String::new(),
        });
    }

    /// Facts and conflicts in record_run's order (stable: equal keys keep their yield order).
    pub fn sorted(mut self) -> (Vec<Row>, Vec<ConflictRow>) {
        self.rows.sort_by(|a, b| (a.lo, a.hi, &a.kind, &a.value).cmp(&(b.lo, b.hi, &b.kind, &b.value)));
        self.conflicts.sort_by(|x, y| (x.lo, x.hi, &x.check, &x.message).cmp(&(y.lo, y.hi, &y.check, &y.message)));
        (self.rows, self.conflicts)
    }
}
