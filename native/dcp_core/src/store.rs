//! The store's facts for native rules: the current runs' facts of a kind, as ledger/store.py's Store.facts gives
//! them (sorted by lo, hi, the value's stored text; ties in run order, then row order), decoded once per run and
//! kept while the run stays current; and the output a native rule builds (facts and conflicts in record order).

use crate::{put_str, ConflictRow, Row};
use rusqlite::Connection;
use serde_json::Value;
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

pub type Facts = Vec<Rc<SFact>>;

fn query_sql(cols: &str, rules: &[String], cond: &str, order: bool) -> String {
    let marks = vec!["?"; rules.len()].join(",");
    format!(
        "SELECT {cols} FROM fact f JOIN run r ON r.id = f.run_id WHERE r.current = 1 AND f.kind = ? AND r.rule IN ({marks}){}{}",
        if cond.is_empty() { String::new() } else { format!(" AND ({cond})") },
        if order { " ORDER BY f.lo, f.hi, f.value, r.id, f.id" } else { "" }
    )
}

/// Facts of one kind of the current runs of `rules`, in Store.facts' order: by (lo, hi, the value's stored text),
/// ties in run order, then row order. `cond`: an SQL condition on the fact `f` / its run `r` that selects what the
/// rule reads (SQLite's JSON functions on f.value: `json_extract(f.value, '$.skind') = 'func'`), so the rest is
/// never decoded.
pub fn facts_where(db: &Connection, kind: &str, rules: &[String], cond: &str) -> rusqlite::Result<Facts> {
    let mut st = db.prepare_cached(&query_sql("r.rule, f.lo, f.hi, f.value, f.level, f.by", rules, cond, true))?;
    let mut args: Vec<&dyn rusqlite::ToSql> = vec![&kind];
    for r in rules {
        args.push(r);
    }
    let mut q = st.query(args.as_slice())?;
    let mut out = Vec::new();
    let mut last_rule: Option<Rc<str>> = None;
    while let Some(r) = q.next()? {
        let rule: String = r.get(0)?;
        let rc = match &last_rule {
            Some(x) if **x == *rule => x.clone(),
            _ => {
                let x: Rc<str> = Rc::from(rule.as_str());
                last_rule = Some(x.clone());
                x
            }
        };
        let text: String = r.get(3)?;
        let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        out.push(Rc::new(SFact { rule: rc, lo: r.get(1)?, hi: r.get(2)?, value, level: r.get(4)?, by: r.get(5)? }));
    }
    Ok(out)
}

/// The addresses (lo) of the facts a condition selects, unordered: what a rule reads of facts it only locates.
pub fn los_where(db: &Connection, kind: &str, rules: &[String], cond: &str) -> rusqlite::Result<Vec<i64>> {
    let mut st = db.prepare_cached(&query_sql("f.lo", rules, cond, false))?;
    let mut args: Vec<&dyn rusqlite::ToSql> = vec![&kind];
    for r in rules {
        args.push(r);
    }
    let rows = st.query_map(args.as_slice(), |r| r.get(0))?;
    rows.collect()
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
