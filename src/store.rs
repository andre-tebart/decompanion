//! The claims (docs/mental-model.md §3): `(range, kind, value, support, by, why)`, each a statement about the
//! original I made by one rule run. Here: their support, what question their kind answers, and the store's claims in
//! memory: the native core holds the claims of every current run of a store, decoded once when the run is first
//! seen; SQLite stays the store of record (every run is written there when it is recorded). A run never changes
//! after it is recorded (a new output is a new run, an unchanged one keeps its run and claims), so memory is keyed
//! by the run's identity (id, time) and the run table says what is current: each read lists the current runs (one
//! small query), loads the runs memory does not hold (recorded by another process, or before this process started)
//! and drops the ones no longer current. Reads give the order (lo, hi, the value's stored text), ties in run order,
//! then row order. Also the output a native rule builds (claims and findings in record order).

use crate::error::Result;
use crate::{put_str, ClaimRow, Finding};
use rusqlite::Connection;
use serde_json::Value;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::rc::Rc;

/// The store's tables. A store of another schema is rebuilt (storedb.rs open): every table is recomputed.
pub const SCHEMA_VERSION: &str = "2";
pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS input (key TEXT PRIMARY KEY, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS run (
    id INTEGER PRIMARY KEY, rule TEXT NOT NULL, version TEXT NOT NULL, code_hash TEXT NOT NULL,
    input_hash TEXT NOT NULL, out_hash TEXT NOT NULL DEFAULT '', current INTEGER NOT NULL DEFAULT 0,
    ms INTEGER NOT NULL DEFAULT 0, at REAL NOT NULL DEFAULT 0, UNIQUE(rule, input_hash));
CREATE TABLE IF NOT EXISTS claim (
    id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL, lo INTEGER NOT NULL, hi INTEGER NOT NULL, kind TEXT NOT NULL,
    value TEXT NOT NULL, support INTEGER NOT NULL, by TEXT NOT NULL, reason TEXT);
CREATE INDEX IF NOT EXISTS claim_kind_lo ON claim (kind, lo);
CREATE INDEX IF NOT EXISTS claim_run ON claim (run_id);
CREATE TABLE IF NOT EXISTS finding (
    id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL, severity TEXT NOT NULL, check_id TEXT NOT NULL,
    lo INTEGER NOT NULL, hi INTEGER NOT NULL, message TEXT NOT NULL, a TEXT NOT NULL DEFAULT '', b TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS finding_run ON finding (run_id);
CREATE TABLE IF NOT EXISTS blob (hash TEXT PRIMARY KEY, kind TEXT NOT NULL, data BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS blob_kind ON blob (kind);
CREATE TABLE IF NOT EXISTS answer (
    lo INTEGER PRIMARY KEY, hi INTEGER NOT NULL, owner TEXT NOT NULL, support INTEGER NOT NULL,
    symbol INTEGER, unit INTEGER, source INTEGER, section INTEGER);
CREATE TABLE IF NOT EXISTS tu (
    unit TEXT PRIMARY KEY, amalg TEXT NOT NULL, src_hash TEXT NOT NULL, flags TEXT NOT NULL, flags_hash TEXT NOT NULL,
    include_hash TEXT NOT NULL, obj_hash TEXT NOT NULL, ok INTEGER NOT NULL, log TEXT NOT NULL, diags TEXT NOT NULL,
    at REAL NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS include_set (key TEXT PRIMARY KEY, files TEXT NOT NULL);
";

/// How hard a claim is to overturn (docs/mental-model.md §3), by where it comes from:
/// - `Open`: nothing is known (the catch-all S.unknown).
/// - `Declared`: H through φ, or an external tool's analysis: only our word supports it.
/// - `Derived`: an analysis of I under a named convention (VC6 fill, LINK order, the walk's W1..W5): overturned
///   where the convention does not hold (an exception).
/// - `Observed`: read from I under its format's spec (the section table, base relocations, exports).
/// - `Reproduced`: a passing experiment (a byte match, a placed library member, a discriminating probe).
///
/// `Observed` and `Reproduced` are the top rank: overturning either means a rule has a bug (`is_top`). The order
/// derived here (Open < Declared < Derived < Observed < Reproduced) breaks the tie for the answer only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Support {
    Open = 0,
    Declared = 1,
    Derived = 2,
    Observed = 3,
    Reproduced = 4,
}

pub const OPEN: Support = Support::Open;
pub const DECLARED: Support = Support::Declared;
pub const DERIVED: Support = Support::Derived;
pub const OBSERVED: Support = Support::Observed;
pub const REPRODUCED: Support = Support::Reproduced;

impl Support {
    pub const ALL: [Support; 5] = [OPEN, DECLARED, DERIVED, OBSERVED, REPRODUCED];

    /// The stored code (the `support` column).
    pub fn code(self) -> i64 {
        self as i64
    }

    pub fn from_code(c: i64) -> Support {
        Support::ALL.get(c as usize).copied().unwrap_or(OPEN)
    }

    /// The rank of §3: open 0, declared 1, derived 2, observed and reproduced 3.
    pub fn rank(self) -> i64 {
        (self as i64).min(3)
    }

    /// Overturning it means a rule has a bug: two top claims that disagree are a `bug` finding.
    pub fn is_top(self) -> bool {
        self.rank() == 3
    }

    pub fn name(self) -> &'static str {
        ["open", "declared", "derived", "observed", "reproduced"][self as usize]
    }

    pub fn parse(s: &str) -> Option<Support> {
        Support::ALL.iter().copied().find(|x| x.name() == s)
    }
}

impl std::fmt::Display for Support {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl rusqlite::ToSql for Support {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(rusqlite::types::ToSqlOutput::from(self.code()))
    }
}

impl rusqlite::types::FromSql for Support {
    fn column_result(v: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        v.as_i64().map(Support::from_code)
    }
}

/// The structural questions of §2: what a claim of a kind answers. Each has at most one answer per byte (the
/// answer: the covering claims at their highest support, answers.rs).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Question {
    /// which section holds the byte (`section`)
    Section,
    /// which object owns the byte: function, datum, string, table, fill, a format region (`symbol`, `region`), and
    /// which object of H that is (`source`)
    Owner,
    /// does a function start here (`start`)
    Start,
    /// which unit produces the byte (`unit`, and a unit's edges: `boundary`)
    Unit,
    /// is the field at this address a reference, and to what (`ref`)
    Ref,
    /// which toolchain built the byte (`toolchain`)
    Toolchain,
}

impl Question {
    pub const ALL: [Question; 6] = [Question::Section, Question::Owner, Question::Start, Question::Unit, Question::Ref, Question::Toolchain];

    pub fn name(self) -> &'static str {
        match self {
            Question::Section => "section",
            Question::Owner => "owner",
            Question::Start => "start",
            Question::Unit => "unit",
            Question::Ref => "ref",
            Question::Toolchain => "toolchain",
        }
    }

    pub fn parse(s: &str) -> Option<Question> {
        Question::ALL.iter().copied().find(|q| q.name() == s)
    }

    /// The kinds whose claims answer it.
    pub fn kinds(self) -> &'static [&'static str] {
        match self {
            Question::Section => &["section"],
            Question::Owner => &["symbol", "region", "source"],
            Question::Start => &["start"],
            Question::Unit => &["unit", "boundary"],
            Question::Ref => &["ref"],
            Question::Toolchain => &["toolchain"],
        }
    }
}

/// What a stored kind is in the model. Most kinds are claims answering a question; the rest are kept in the same
/// runs but are no claims about I.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Claim(Question),
    /// φ: an object of H (or of the toolchain's libraries, or a name the image itself holds) at an address of I
    /// (`name`): phi.rs
    Phi,
    /// an experiment's result over one object (`experiment`: G.grade, the outcome byte / shape / draft)
    Experiment,
    /// H against its own standard (`readability`: G.grade), no claim about I (§9)
    Readability,
    /// H's build state (`build`: one per unit)
    Build,
    /// a rule's intermediate result, read by other rules (`evidence`)
    Aux,
}

pub fn role(kind: &str) -> Role {
    match kind {
        "name" => Role::Phi,
        "experiment" => Role::Experiment,
        "readability" => Role::Readability,
        "build" => Role::Build,
        "evidence" => Role::Aux,
        k => Question::ALL.iter().copied().find(|q| q.kinds().contains(&k)).map(Role::Claim).unwrap_or(Role::Aux),
    }
}

pub struct Claim {
    pub id: i64, // the claim's row
    pub rule: Rc<str>,
    pub lo: i64,
    pub hi: i64,
    pub text: String, // the stored value (canonical): the third sort key
    pub value: Value,
    pub support: Support,
    pub by: String,
    pub reason: Option<String>,
}

impl Claim {
    pub fn s(&self, key: &str) -> Option<&str> {
        self.value.get(key).and_then(|v| v.as_str())
    }
}

pub type Claims = Vec<Rc<Claim>>;

/// One recorded run's facts by kind, in row order.
pub(crate) struct RunClaims {
    pub(crate) rule: String,
    pub(crate) by_kind: HashMap<String, Claims>,
}

impl RunClaims {
    /// Its facts by row id (with their kind): what a run recorded again in place keeps.
    fn by_id(&self) -> HashMap<i64, (&str, &Rc<Claim>)> {
        self.by_kind.iter().flat_map(|(k, v)| v.iter().map(move |f| (f.id, (k.as_str(), f)))).collect()
    }
}

thread_local! {
    // store path -> (run id, run time) -> its facts
    static MEM: RefCell<HashMap<String, HashMap<(i64, u64), Rc<RunClaims>>>> = RefCell::new(HashMap::new());
    // store path -> (the current runs, as runs_key lists them, at the last read; those runs with their facts)
    static LISTED: RefCell<HashMap<String, (Vec<(i64, u64)>, Vec<Rc<RunClaims>>)>> = RefCell::new(HashMap::new());
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
fn load_run(db: &Connection, rid: i64, rule: &str, before: Option<&RunClaims>) -> rusqlite::Result<RunClaims> {
    let rule_rc: Rc<str> = Rc::from(rule);
    let known = before.map(|b| b.by_id()).unwrap_or_default();
    let mut st = db.prepare_cached("SELECT id, kind, lo, hi, value, support, by, reason FROM claim WHERE run_id=? ORDER BY id")?;
    let mut q = st.query([rid])?;
    let mut by_kind: HashMap<String, Claims> = HashMap::new();
    while let Some(r) = q.next()? {
        let id: i64 = r.get(0)?;
        let kind: String = r.get(1)?;
        let (lo, hi, support): (i64, i64, Support) = (r.get(2)?, r.get(3)?, r.get(5)?);
        let text = r.get_ref(4)?.as_str()?;
        let by = r.get_ref(6)?.as_str()?;
        let reason = r.get_ref(7)?.as_str_or_null()?;
        let same = known.get(&id).filter(|(k, f)| {
            *k == kind && f.lo == lo && f.hi == hi && f.support == support && f.text == text && f.by == by && f.reason.as_deref() == reason
        });
        let f = match same {
            Some((_, f)) => (*f).clone(),
            None => {
                let value: Value = serde_json::from_str(text).unwrap_or(Value::Null);
                Rc::new(Claim { id, rule: rule_rc.clone(), lo, hi, text: text.to_string(), value, support, by: by.to_string(),
                                reason: reason.map(|s| s.to_string()) })
            }
        };
        by_kind.entry(kind).or_default().push(f);
    }
    Ok(RunClaims { rule: rule.to_string(), by_kind })
}

/// The run memory holds for this store and run id when it is the one of time `at` (the run as the store has it).
pub(crate) fn held_run(db_path: &str, run_id: i64, at: f64) -> Option<Rc<RunClaims>> {
    MEM.with(|m| m.borrow().get(db_path).and_then(|h| h.get(&(run_id, at.to_bits())).cloned()))
}

/// A run as just written (its facts with their row ids), held as the store now has it: the next reader needs
/// no read of the store.
pub(crate) fn put_run(db_path: &str, run_id: i64, at: f64, run: RunClaims) {
    MEM.with(|m| {
        let mut m = m.borrow_mut();
        let held = m.entry(db_path.to_string()).or_default();
        held.retain(|k, _| k.0 != run_id);
        held.insert((run_id, at.to_bits()), Rc::new(run));
    });
    LISTED.with(|l| l.borrow_mut().remove(db_path));
}

/// The current runs of the store in run order, each with its facts (loaded if memory does not hold it yet). Every
/// read lists the current runs; when they are the ones of the last read (runs_key: a run's facts never change under
/// its (id, time)), the runs of that read are the answer, else memory is brought to the listed runs.
fn current(db: &Connection, db_path: &str) -> rusqlite::Result<Vec<Rc<RunClaims>>> {
    let key = runs_key(db)?;
    if let Some(out) = LISTED.with(|l| l.borrow().get(db_path).filter(|e| e.0 == key).map(|e| e.1.clone())) {
        return Ok(out);
    }
    let out = current_load(db, db_path)?;
    LISTED.with(|l| l.borrow_mut().insert(db_path.to_string(), (key, out.clone())));
    Ok(out)
}

/// current's full read: the current runs with their rules, memory brought to them.
fn current_load(db: &Connection, db_path: &str) -> rusqlite::Result<Vec<Rc<RunClaims>>> {
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
        let mut gone: HashMap<i64, Rc<RunClaims>> = HashMap::new();
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

/// Claims of one kind of the current runs of `rules` that `keep` selects, in Store.facts' order.
pub fn claims(db: &Connection, db_path: &str, kind: &str, rules: &[String], keep: impl Fn(&Claim) -> bool) -> rusqlite::Result<Claims> {
    claims_of(db, db_path, kind, Some(rules), keep)
}

/// Claims of one kind of the current runs (of `rules`, None: of every rule) that `keep` selects, in Store.facts'
/// order.
pub fn claims_of(db: &Connection, db_path: &str, kind: &str, rules: Option<&[String]>, keep: impl Fn(&Claim) -> bool) -> rusqlite::Result<Claims> {
    let mut out: Claims = Vec::new();
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
pub fn los(db: &Connection, db_path: &str, kind: &str, rules: &[String], keep: impl Fn(&Claim) -> bool) -> rusqlite::Result<Vec<i64>> {
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

/// What a native rule yields: claims (stamped `rule:<id>@<version>` unless a producer is given) and findings.
pub struct Out {
    pub by: String,
    pub rows: Vec<ClaimRow>,
    pub findings: Vec<Finding>,
}

impl Out {
    pub fn new(rule: &str, version: &str) -> Out {
        Out { by: format!("rule:{rule}@{version}"), rows: vec![], findings: vec![] }
    }

    pub fn claim(&mut self, lo: i64, hi: i64, kind: &str, value: Value, support: Support) {
        let mut text = String::new();
        canon(&mut text, &value);
        self.rows.push(ClaimRow { lo, hi, kind: kind.to_string(), value: text, support, by: self.by.clone(), reason: None });
    }

    /// A claim with a reason (one resting on a declared premise carries the premise's).
    pub fn claim_reason(&mut self, lo: i64, hi: i64, kind: &str, value: Value, support: Support, reason: Option<String>) {
        let mut text = String::new();
        canon(&mut text, &value);
        self.rows.push(ClaimRow { lo, hi, kind: kind.to_string(), value: text, support, by: self.by.clone(), reason });
    }

    /// A declared claim of a loader rule: its producer a line of H or φ (src:<file>:<line>, decl:<file>:<line>), with
    /// a reason.
    pub fn declared(&mut self, lo: i64, hi: i64, kind: &str, value: Value, by: &str, reason: &str) {
        let mut text = String::new();
        canon(&mut text, &value);
        self.rows.push(ClaimRow { lo, hi, kind: kind.to_string(), value: text, support: DECLARED, by: by.to_string(), reason: Some(reason.to_string()) });
    }

    pub fn finding(&mut self, severity: &str, check: &str, lo: i64, hi: i64, message: String, a: &str) {
        self.finding2(severity, check, lo, hi, message, a, "");
    }

    /// A finding naming the producers of both claims (a contradiction's two sides). An ill-formed check is never
    /// below error (registry::floor: H that is no program or φ that is no mapping fails the gate).
    pub fn finding2(&mut self, severity: &str, check: &str, lo: i64, hi: i64, message: String, a: &str, b: &str) {
        self.findings.push(Finding {
            severity: crate::registry::floor(check, severity).to_string(),
            check: check.to_string(),
            lo,
            hi,
            message,
            a: a.to_string(),
            b: b.to_string(),
        });
    }

    /// Claims and findings in record_run's order (stable: equal keys keep their yield order).
    pub fn sorted(mut self) -> (Vec<ClaimRow>, Vec<Finding>) {
        self.rows.sort_by(|a, b| (a.lo, a.hi, &a.kind, &a.value).cmp(&(b.lo, b.hi, &b.kind, &b.value)));
        self.findings.sort_by(|x, y| (x.lo, x.hi, &x.check, &x.message).cmp(&(y.lo, y.hi, &y.check, &y.message)));
        (self.rows, self.findings)
    }
}
