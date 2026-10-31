//! dcp_core: the native core of decompanion (docs/plan.md, section 20).
//!
//! N0: the store's write path. `record_run` writes a finished rule run as ledger/store.py's Store.record_run
//! does (same SQL, same out_hash), on its own connection to the project's store (WAL: beside Python's).
//! `canonical` and `out_hash` are fact.canonical and the run hash, byte for byte: the shadow mode of the engine
//! compares them with Python's for every rule's output.

mod analyzers;
mod asmcmd;
mod clang;
mod clicmd;
mod cliread;
mod coff;
mod decl;
mod crt;
mod dialect;
mod draft;
mod datafix;
mod decide;
mod compare;
mod compile;
mod cs;
mod diffclass;
mod edit;
mod difflib;
mod engine;
mod fsmemo;
mod frontend;
mod headers;
mod init;
mod grade;
mod libcand;
mod link;
mod lint;
mod lintrun;
mod matchcmd;
mod mrules;
mod names;
mod layout;
mod layoutview;
mod pe;
mod plan;
mod probe;
mod project;
mod pyimage;
mod pystore;
mod queues;
mod readability;
mod registry;
mod rename;
mod rules;
mod session;
mod setup;
mod srcscan;
mod store;
mod tomledit;
mod toolchain;
mod units;
mod vc6;
mod walk;
mod wt;
mod x86;

/// The test run's time budget: a watchdog started before the test harness's main fails the run (exit 1) when it is
/// still going after 2 s (DCP_TEST_BUDGET_MS overrides, 0 turns it off; the `--ignored` tier of real installations
/// has none). Compile time is not counted.
#[cfg(test)]
mod budget {
    extern "C" fn start() {
        if std::env::args().any(|a| a == "--ignored" || a == "--include-ignored") {
            return;
        }
        let ms: u64 = std::env::var("DCP_TEST_BUDGET_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(2000);
        if ms == 0 {
            return;
        }
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(ms));
            eprintln!("
cargo test: over its budget of {ms} ms (DCP_TEST_BUDGET_MS): the run fails");
            std::process::exit(1);
        });
    }

    #[used]
    #[cfg_attr(windows, unsafe(link_section = ".CRT$XCU"))]
    #[cfg_attr(not(windows), unsafe(link_section = ".init_array"))]
    static START: extern "C" fn() = start;
}

use pyo3::exceptions::{PyRuntimeError, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};
use rusqlite::{params, Connection};
use std::rc::Rc;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

// ------------------------------------------------------------------------------------------------ canonical

/// A string as json.dumps(ensure_ascii=True) spells it, quotes included.
pub(crate) fn put_str(out: &mut String, s: &str) {
    out.push('"');
    // runs of printable ASCII other than `"` and `\` go over as they are
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let j = i + b[i..].iter().position(|&c| !(0x20..=0x7e).contains(&c) || c == b'"' || c == b'\\').unwrap_or(b.len() - i);
        out.push_str(&s[i..j]);
        if j == b.len() {
            break;
        }
        let ch = s[j..].chars().next().unwrap();
        i = j + ch.len_utf8();
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    let _ = write!(out, "\\u{:04x}", u);
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A Python value as fact.canonical spells it: json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True).
pub(crate) fn put_value(out: &mut String, v: &Bound<'_, PyAny>) -> PyResult<()> {
    if v.is_none() {
        out.push_str("null");
    } else if v.is_instance_of::<PyBool>() {
        out.push_str(if v.extract::<bool>()? { "true" } else { "false" });
    } else if v.is_instance_of::<PyInt>() {
        match v.extract::<i64>() {
            Ok(i) => {
                let _ = write!(out, "{}", i);
            }
            Err(_) => out.push_str(&v.call_method0("__index__")?.str()?.to_cow()?),
        }
    } else if v.is_instance_of::<PyFloat>() {
        // float.__repr__, as json.dumps writes a float (nan / inf as NaN / Infinity)
        let f: f64 = v.extract()?;
        if f.is_nan() {
            out.push_str("NaN");
        } else if f.is_infinite() {
            out.push_str(if f > 0.0 { "Infinity" } else { "-Infinity" });
        } else {
            let py = v.py();
            out.push_str(&PyFloat::new(py, f).repr()?.to_cow()?);
        }
    } else if let Ok(s) = v.cast::<PyString>() {
        put_str(out, &s.to_cow()?);
    } else if let Ok(d) = v.cast::<PyDict>() {
        let mut items: Vec<(String, Bound<'_, PyAny>)> = Vec::with_capacity(d.len());
        for (k, x) in d.iter() {
            let key = if let Ok(s) = k.cast::<PyString>() {
                s.to_cow()?.into_owned()
            } else {
                return Err(PyTypeError::new_err(format!("canonical: a dict key that is no str: {}", k.repr()?)));
            };
            items.push((key, x));
        }
        items.sort_by(|a, b| a.0.cmp(&b.0));
        out.push('{');
        for (i, (k, x)) in items.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            put_str(out, k);
            out.push(':');
            put_value(out, x)?;
        }
        out.push('}');
    } else if let Ok(l) = v.cast::<PyList>() {
        out.push('[');
        for (i, x) in l.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            put_value(out, &x)?;
        }
        out.push(']');
    } else if let Ok(t) = v.cast::<PyTuple>() {
        out.push('[');
        for (i, x) in t.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            put_value(out, &x)?;
        }
        out.push(']');
    } else {
        return Err(PyTypeError::new_err(format!("canonical: no JSON spelling for {}", v.get_type().name()?)));
    }
    Ok(())
}

#[pyfunction]
fn canonical(v: &Bound<'_, PyAny>) -> PyResult<String> {
    let mut out = String::new();
    put_value(&mut out, v)?;
    Ok(out)
}

// ------------------------------------------------------------------------------------------------ runs

/// One fact of a run as record_run writes it.
pub(crate) struct Row {
    pub lo: i64,
    pub hi: i64,
    pub kind: String,
    pub value: String, // canonical(value)
    pub level: i64,
    pub by: String,
    pub reason: Option<String>,
}

pub(crate) struct ConflictRow {
    pub severity: String,
    pub check: String,
    pub lo: i64,
    pub hi: i64,
    pub message: String,
    pub a: String,
    pub b: String,
}

pub(crate) fn rows_of(facts: &Bound<'_, PyList>) -> PyResult<Vec<Row>> {
    let mut rows = Vec::with_capacity(facts.len());
    for f in facts.iter() {
        let mut value = String::new();
        put_value(&mut value, &f.getattr("value")?)?;
        rows.push(Row {
            lo: f.getattr("lo")?.extract()?,
            hi: f.getattr("hi")?.extract()?,
            kind: f.getattr("kind")?.getattr("value")?.extract()?,
            value,
            level: f.getattr("level")?.extract()?,
            by: f.getattr("by")?.extract()?,
            reason: f.getattr("reason")?.extract()?,
        });
    }
    // record_run's order: by fact.key() = (lo, hi, kind, canonical(value))
    rows.sort_by(|a, b| (a.lo, a.hi, &a.kind, &a.value).cmp(&(b.lo, b.hi, &b.kind, &b.value)));
    Ok(rows)
}

pub(crate) fn conflicts_of(conflicts: &Bound<'_, PyList>) -> PyResult<Vec<ConflictRow>> {
    let mut rows = Vec::with_capacity(conflicts.len());
    for c in conflicts.iter() {
        rows.push(ConflictRow {
            severity: c.getattr("severity")?.getattr("value")?.extract()?,
            check: c.getattr("check")?.extract()?,
            lo: c.getattr("lo")?.extract()?,
            hi: c.getattr("hi")?.extract()?,
            message: c.getattr("message")?.extract()?,
            a: c.getattr("a")?.extract()?,
            b: c.getattr("b")?.extract()?,
        });
    }
    rows.sort_by(|x, y| (x.lo, x.hi, &x.check, &x.message).cmp(&(y.lo, y.hi, &y.check, &y.message)));
    Ok(rows)
}

/// store.sha256(*parts): each part followed by a NUL.
pub(crate) fn hash_parts<'a>(parts: impl Iterator<Item = String>) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update([0u8]);
    }
    let d = h.finalize();
    let mut s = String::with_capacity(64);
    for b in d.iter() {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// The out_hash of a run: sha256 over canonical(key + (level, by, reason)) of each fact in key order, then
/// canonical((lo, hi, check, severity, message)) of each conflict in (lo, hi, check, message) order.
pub(crate) fn run_hash(rows: &[Row], conflicts: &[ConflictRow]) -> String {
    let facts = rows.iter().map(|r| {
        let mut s = String::from("[");
        let _ = write!(s, "{},{},", r.lo, r.hi);
        put_str(&mut s, &r.kind);
        s.push(',');
        put_str(&mut s, &r.value);
        let _ = write!(s, ",{},", r.level);
        put_str(&mut s, &r.by);
        s.push(',');
        put_str(&mut s, r.reason.as_deref().unwrap_or(""));
        s.push(']');
        s
    });
    let confl = conflicts.iter().map(|c| {
        let mut s = String::from("[");
        let _ = write!(s, "{},{},", c.lo, c.hi);
        put_str(&mut s, &c.check);
        s.push(',');
        put_str(&mut s, &c.severity);
        s.push(',');
        put_str(&mut s, &c.message);
        s.push(']');
        s
    });
    hash_parts(facts.chain(confl))
}

#[pyfunction]
fn out_hash(facts: &Bound<'_, PyList>, conflicts: &Bound<'_, PyList>) -> PyResult<String> {
    Ok(run_hash(&rows_of(facts)?, &conflicts_of(conflicts)?))
}

thread_local! {
    static CONNS: RefCell<HashMap<String, Connection>> = RefCell::new(HashMap::new());
}

pub(crate) fn with_db<T>(path: &str, f: impl FnOnce(&mut Connection) -> rusqlite::Result<T>) -> PyResult<T> {
    CONNS.with(|c| {
        let mut map = c.borrow_mut();
        if !map.contains_key(path) {
            let db = Connection::open(path).map_err(|e| PyRuntimeError::new_err(format!("{path}: {e}")))?;
            db.busy_timeout(std::time::Duration::from_secs(10))
                .and_then(|_| db.pragma_update(None, "journal_mode", "WAL"))
                .and_then(|_| db.pragma_update(None, "synchronous", "NORMAL"))
                .map_err(|e| PyRuntimeError::new_err(format!("{path}: {e}")))?;
            map.insert(path.to_string(), db);
        }
        let db = map.get_mut(path).unwrap();
        f(db).map_err(|e| PyRuntimeError::new_err(format!("{path}: {e}")))
    })
}

/// f over the items on the machine's threads (an external process each, typically), results in the items' order.
pub(crate) fn compile_threads<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).min(items.len().max(1));
    let next = std::sync::atomic::AtomicUsize::new(0);
    let out: std::sync::Mutex<Vec<Option<R>>> = std::sync::Mutex::new((0..items.len()).map(|_| None).collect());
    std::thread::scope(|s| {
        for _ in 0..n {
            s.spawn(|| loop {
                let k = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if k >= items.len() {
                    break;
                }
                let r = f(&items[k]);
                out.lock().unwrap()[k] = Some(r);
            });
        }
    });
    out.into_inner().unwrap().into_iter().map(|r| r.unwrap()).collect()
}

/// Close this thread's connection to a store (its file is replaced or removed).
pub(crate) fn forget_conn(path: &str) {
    CONNS.with(|c| c.borrow_mut().remove(path));
}

/// The store's native connection for code that reports Python errors itself (a native rule).
pub(crate) fn with_conn<T>(path: &str, f: impl FnOnce(&mut Connection) -> PyResult<T>) -> PyResult<T> {
    with_db(path, |_| Ok(()))?;
    CONNS.with(|c| f(c.borrow_mut().get_mut(path).unwrap()))
}

type FactKey = (i64, i64, String, String, i64, String, Option<String>);
type ConflictKey = (String, String, i64, i64, String, String, String);

/// Make a run's facts the given rows, writing only the difference: the facts the run holds that the rows do not
/// are deleted, the rows it does not hold are inserted (a line move changes the facts of the functions below it,
/// not the 26k of the sources).
fn sync_facts(tx: &rusqlite::Transaction, run_id: i64, rows: &[Row]) -> rusqlite::Result<()> {
    let mut have: HashMap<FactKey, std::collections::VecDeque<i64>> = HashMap::new();
    {
        let mut st = tx.prepare("SELECT id, lo, hi, kind, value, level, by, reason FROM fact WHERE run_id=? ORDER BY id")?;
        let mut q = st.query([run_id])?;
        while let Some(r) = q.next()? {
            let k: FactKey = (r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?);
            have.entry(k).or_default().push_back(r.get(0)?);
        }
    }
    let mut add = Vec::new();
    for r in rows {
        let k: FactKey = (r.lo, r.hi, r.kind.clone(), r.value.clone(), r.level, r.by.clone(), r.reason.clone());
        match have.get_mut(&k).and_then(|q| q.pop_front()) {
            Some(_) => {}
            None => add.push(r),
        }
    }
    {
        let mut st = tx.prepare("DELETE FROM fact WHERE id=?")?;
        for ids in have.values() {
            for id in ids {
                st.execute([id])?;
            }
        }
    }
    let mut st = tx.prepare("INSERT INTO fact (run_id, lo, hi, kind, value, level, by, reason) VALUES (?,?,?,?,?,?,?,?)")?;
    for r in add {
        st.execute(params![run_id, r.lo, r.hi, r.kind, r.value, r.level, r.by, r.reason])?;
    }
    Ok(())
}

/// sync_facts against the run as memory holds it (the store's rows of the run, with their ids): no read of the
/// store; the run as written, for memory.
fn sync_facts_held(tx: &rusqlite::Transaction, run_id: i64, rows: &[Row], held: &store::RunFacts) -> rusqlite::Result<store::RunFacts> {
    type Key<'a> = (i64, i64, &'a str, &'a str, i64, &'a str, Option<&'a str>);
    let mut have: rustc_hash::FxHashMap<Key, std::collections::VecDeque<&Rc<store::SFact>>> = Default::default();
    let mut all: Vec<(&str, &Rc<store::SFact>)> = held.by_kind.iter().flat_map(|(k, v)| v.iter().map(move |f| (k.as_str(), f))).collect();
    all.sort_by_key(|(_, f)| f.id);
    for (kind, f) in &all {
        have.entry((f.lo, f.hi, kind, &f.text, f.level, &f.by, f.reason.as_deref())).or_default().push_back(f);
    }
    let rule: Rc<str> = Rc::from(held.rule.as_str());
    let mut by_kind: HashMap<String, store::Facts> = HashMap::new();
    let mut add = Vec::new();
    for r in rows {
        match have.get_mut(&(r.lo, r.hi, r.kind.as_str(), r.value.as_str(), r.level, r.by.as_str(), r.reason.as_deref())).and_then(|q| q.pop_front()) {
            Some(f) => by_kind.entry(r.kind.clone()).or_default().push(f.clone()),
            None => add.push(r),
        }
    }
    {
        let mut st = tx.prepare_cached("DELETE FROM fact WHERE id=?")?;
        for q in have.values() {
            for f in q {
                st.execute([f.id])?;
            }
        }
    }
    let mut st = tx.prepare_cached("INSERT INTO fact (run_id, lo, hi, kind, value, level, by, reason) VALUES (?,?,?,?,?,?,?,?)")?;
    for r in add {
        st.execute(params![run_id, r.lo, r.hi, r.kind, r.value, r.level, r.by, r.reason])?;
        by_kind.entry(r.kind.clone()).or_default().push(Rc::new(fact_of(tx.last_insert_rowid(), &rule, r)));
    }
    for v in by_kind.values_mut() {
        v.sort_by_key(|f| f.id);
    }
    Ok(store::RunFacts { rule: held.rule.clone(), by_kind })
}

/// A written row as memory holds a fact.
fn fact_of(id: i64, rule: &Rc<str>, r: &Row) -> store::SFact {
    store::SFact { id, rule: rule.clone(), lo: r.lo, hi: r.hi, text: r.value.clone(), value: serde_json::from_str(&r.value).unwrap_or(serde_json::Value::Null),
                   level: r.level, by: r.by.clone(), reason: r.reason.clone() }
}

/// The same for a run's conflicts (M.lint's thousands of M7 lines are the same from one run to the next).
fn sync_conflicts(tx: &rusqlite::Transaction, run_id: i64, confl: &[ConflictRow]) -> rusqlite::Result<()> {
    let mut have: rustc_hash::FxHashMap<ConflictKey, std::collections::VecDeque<i64>> = Default::default();
    {
        let mut st = tx.prepare("SELECT id, severity, check_id, lo, hi, message, a, b FROM conflict WHERE run_id=? ORDER BY id")?;
        let mut q = st.query([run_id])?;
        while let Some(r) = q.next()? {
            let k: ConflictKey = (r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?);
            have.entry(k).or_default().push_back(r.get(0)?);
        }
    }
    let mut add = Vec::new();
    for c in confl {
        let k: ConflictKey = (c.severity.clone(), c.check.clone(), c.lo, c.hi, c.message.clone(), c.a.clone(), c.b.clone());
        match have.get_mut(&k).and_then(|q| q.pop_front()) {
            Some(_) => {}
            None => add.push(c),
        }
    }
    {
        let mut st = tx.prepare("DELETE FROM conflict WHERE id=?")?;
        for ids in have.values() {
            for id in ids {
                st.execute([id])?;
            }
        }
    }
    let mut st = tx.prepare("INSERT INTO conflict (run_id, severity, check_id, lo, hi, message, a, b) VALUES (?,?,?,?,?,?,?,?)")?;
    for c in add {
        st.execute(params![run_id, c.severity, c.check, c.lo, c.hi, c.message, c.a, c.b])?;
    }
    Ok(())
}

fn drop_runs(tx: &rusqlite::Transaction, rule: &str, keep: Option<i64>) -> rusqlite::Result<()> {
    let old: Vec<i64> = {
        let mut st = tx.prepare("SELECT id FROM run WHERE rule=?")?;
        st.query_map([rule], |r| r.get(0))?.collect::<Result<_, _>>()?
    };
    for oid in old {
        if Some(oid) == keep {
            continue;
        }
        tx.execute("DELETE FROM fact WHERE run_id=?", [oid])?;
        tx.execute("DELETE FROM conflict WHERE run_id=?", [oid])?;
        tx.execute("DELETE FROM run WHERE id=?", [oid])?;
    }
    Ok(())
}

/// A run written as Store.record_run writes it, on the store's native connection: (run id, out_hash). `rows` and
/// `confl` must be in record order (Out::sorted). Only the latest run of a rule is kept. An unchanged output
/// (out_hash) keeps the run and its facts and takes the new key; a changed one is written into the rule's
/// current run, only the facts and conflicts that differ (sync_facts), with a new time (a reader that holds the
/// run by (id, time) reads it again). `shortcuts` false (DCP_NO_SHORTCUTS, bench --verify's fresh recompute):
/// a new run written whole.
pub(crate) fn write_run(
    db: &mut Connection,
    db_path: &str,
    rule: &str,
    version: &str,
    code_hash: &str,
    input_hash: &str,
    rows: &[Row],
    confl: &[ConflictRow],
    ms: i64,
    shortcuts: bool,
) -> rusqlite::Result<(i64, String)> {
    let out = run_hash(rows, confl);
    let at = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0);
    let tx = db.transaction()?;
    let cur: Option<(i64, String, f64)> = if shortcuts {
        tx.query_row("SELECT id, out_hash, at FROM run WHERE rule=? AND current=1", [rule], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).ok()
    } else {
        None
    };
    let run_id;
    let mut written: Option<store::RunFacts> = None; // the run's facts as the store now has them, when known
    match cur {
        Some((id, h, _)) if h == out => {
            run_id = id;
            drop_runs(&tx, rule, Some(run_id))?;
            tx.execute("UPDATE run SET version=?, code_hash=?, input_hash=?, ms=? WHERE id=?",
                       params![version, code_hash, input_hash, ms, run_id])?;
            sync_conflicts(&tx, run_id, confl)?;
        }
        Some((id, _, cur_at)) => {
            run_id = id;
            drop_runs(&tx, rule, Some(run_id))?;
            match store::held_run(db_path, run_id, cur_at) {
                Some(held) => written = Some(sync_facts_held(&tx, run_id, rows, &held)?),
                None => sync_facts(&tx, run_id, rows)?,
            }
            sync_conflicts(&tx, run_id, confl)?;
            tx.execute("UPDATE run SET version=?, code_hash=?, input_hash=?, out_hash=?, current=1, ms=?, at=? WHERE id=?",
                       params![version, code_hash, input_hash, out, ms, at, run_id])?;
        }
        None => {
            drop_runs(&tx, rule, None)?;
            tx.execute(
                "INSERT INTO run (rule, version, code_hash, input_hash, out_hash, current, ms, at) VALUES (?,?,?,?,?,1,?,?)",
                params![rule, version, code_hash, input_hash, out, ms, at],
            )?;
            run_id = tx.last_insert_rowid();
            let mut st = tx.prepare("INSERT INTO fact (run_id, lo, hi, kind, value, level, by, reason) VALUES (?,?,?,?,?,?,?,?)")?;
            let rc: Rc<str> = Rc::from(rule);
            let mut by_kind: HashMap<String, store::Facts> = HashMap::new();
            for r in rows {
                st.execute(params![run_id, r.lo, r.hi, r.kind, r.value, r.level, r.by, r.reason])?;
                by_kind.entry(r.kind.clone()).or_default().push(Rc::new(fact_of(tx.last_insert_rowid(), &rc, r)));
            }
            written = Some(store::RunFacts { rule: rule.to_string(), by_kind });
            let mut st = tx.prepare("INSERT INTO conflict (run_id, severity, check_id, lo, hi, message, a, b) VALUES (?,?,?,?,?,?,?,?)")?;
            for c in confl {
                st.execute(params![run_id, c.severity, c.check, c.lo, c.hi, c.message, c.a, c.b])?;
            }
        }
    }
    tx.commit()?;
    if let Some(w) = written {
        store::put_run(db_path, run_id, at, w);
    }
    Ok((run_id, out))
}

/// Store.record_run in native code: (run id, out_hash). `shortcuts` false is DCP_NO_SHORTCUTS (always write).
#[pyfunction]
#[pyo3(signature = (db_path, rule, version, code_hash, input_hash, facts, conflicts, ms, shortcuts=true))]
fn record_run(
    py: Python<'_>,
    db_path: &str,
    rule: &str,
    version: &str,
    code_hash: &str,
    input_hash: &str,
    facts: &Bound<'_, PyList>,
    conflicts: &Bound<'_, PyList>,
    ms: i64,
    shortcuts: bool,
) -> PyResult<(i64, String)> {
    let rows = rows_of(facts)?;
    let confl = conflicts_of(conflicts)?;
    py.detach(|| with_db(db_path, |db| write_run(db, db_path, rule, version, code_hash, input_hash, &rows, &confl, ms, shortcuts)))
}

// ------------------------------------------------------------------------------------------------ objects, image

thread_local! {
    // a target's binary: the project checks its sha256 against the declaration on every open (a mismatch is
    // fatal), so the bytes behind a path do not change while it is in use; memory holds the parsed image by path
    static IMAGES: RefCell<HashMap<String, std::rc::Rc<pe::Image>>> = RefCell::new(HashMap::new());
}

/// The image at path, parsed once.
pub(crate) fn image(path: &str) -> PyResult<std::rc::Rc<pe::Image>> {
    if let Some(i) = IMAGES.with(|m| m.borrow().get(path).cloned()) {
        return Ok(i);
    }
    let data = std::fs::read(path).map_err(|e| PyRuntimeError::new_err(format!("{path}: {e}")))?;
    let img = std::rc::Rc::new(pe::Image::parse(data).map_err(|e| PyRuntimeError::new_err(format!("{path}: {e}")))?);
    IMAGES.with(|m| m.borrow_mut().insert(path.to_string(), img.clone()));
    Ok(img)
}

pub(crate) type ObjIndex = std::rc::Rc<(coff::Obj, HashMap<String, usize>)>;

thread_local! {
    // build/obj/<content hash>.obj -> the parsed object: a compiled object never changes (a new compile is a new
    // file), so memory holds it by that identity, as it holds a recorded run's facts; `live` drops the others
    static OBJS: RefCell<HashMap<String, ObjIndex>> = RefCell::new(HashMap::new());
}

/// The object at path (build/obj/<content hash>.obj) with its function index, parsed once; None when the file
/// is missing (C.read_object).
pub(crate) fn object_if(path: &str) -> PyResult<Option<ObjIndex>> {
    if let Some(o) = OBJS.with(|m| m.borrow().get(path).cloned()) {
        return Ok(Some(o));
    }
    match std::fs::read(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(PyRuntimeError::new_err(format!("{path}: {e}"))),
        Ok(_) => object(path).map(Some),
    }
}

/// The object at path (build/obj/<content hash>.obj) with its function index, parsed once.
pub(crate) fn object(path: &str) -> PyResult<ObjIndex> {
    if let Some(o) = OBJS.with(|m| m.borrow().get(path).cloned()) {
        return Ok(o);
    }
    let data = std::fs::read(path).map_err(|e| PyRuntimeError::new_err(format!("{path}: {e}")))?;
    let obj = coff::Obj::parse(&data).map_err(|e| PyRuntimeError::new_err(format!("{path}: {e}")))?;
    let idx = obj.function_index();
    let o: ObjIndex = std::rc::Rc::new((obj, idx));
    OBJS.with(|m| m.borrow_mut().insert(path.to_string(), o.clone()));
    Ok(o)
}

/// Keep only the objects of `paths` in memory (the current build's objects).
pub(crate) fn live_objects(paths: &std::collections::HashSet<String>) {
    OBJS.with(|m| m.borrow_mut().retain(|k, _| paths.contains(k)));
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(canonical, m)?)?;
    m.add_class::<project::PyProject>()?;
    m.add_class::<names::Names>()?;
    m.add_function(wrap_pyfunction!(link::link_classify, m)?)?;
    m.add_function(wrap_pyfunction!(probe::probe_run, m)?)?;
    m.add_function(wrap_pyfunction!(libcand::libs_candidates_lines, m)?)?;
    m.add_class::<pyimage::PeImage>()?;
    m.add_function(wrap_pyfunction!(pyimage::pe_open, m)?)?;
    m.add_function(wrap_pyfunction!(cliread::read_command, m)?)?;
    m.add_function(wrap_pyfunction!(cliread::read_resolve, m)?)?;
    m.add_function(wrap_pyfunction!(datafix::data_map, m)?)?;
    m.add_function(wrap_pyfunction!(datafix::data_fix, m)?)?;
    m.add_function(wrap_pyfunction!(headers::headers_conflicts, m)?)?;
    m.add_function(wrap_pyfunction!(draft::draft_command, m)?)?;
    m.add_function(wrap_pyfunction!(rename::rename_pairs, m)?)?;
    m.add_function(wrap_pyfunction!(rename::rename_command, m)?)?;
    m.add_function(wrap_pyfunction!(units::unit_create, m)?)?;
    m.add_function(wrap_pyfunction!(units::unit_join, m)?)?;
    m.add_function(wrap_pyfunction!(units::unit_rename, m)?)?;
    m.add_function(wrap_pyfunction!(frontend::clang_library, m)?)?;
    m.add_function(wrap_pyfunction!(queues::grades_auto_clear, m)?)?;
    m.add_function(wrap_pyfunction!(queues::level_command, m)?)?;
    m.add_function(wrap_pyfunction!(clicmd::report_command, m)?)?;
    m.add_function(wrap_pyfunction!(clicmd::why_command, m)?)?;
    m.add_function(wrap_pyfunction!(clicmd::facts_command, m)?)?;
    m.add_function(wrap_pyfunction!(clicmd::conflicts_command, m)?)?;
    m.add_function(wrap_pyfunction!(clicmd::map_command, m)?)?;
    m.add_function(wrap_pyfunction!(clicmd::rules_command, m)?)?;
    m.add_function(wrap_pyfunction!(clicmd::build_summary, m)?)?;
    m.add_function(wrap_pyfunction!(clicmd::check_conflicts, m)?)?;
    m.add_function(wrap_pyfunction!(clicmd::fn_command, m)?)?;
    m.add_function(wrap_pyfunction!(clicmd::target_list, m)?)?;
    m.add_function(wrap_pyfunction!(clicmd::decl_add, m)?)?;
    m.add_function(wrap_pyfunction!(clicmd::decl_conflicts, m)?)?;
    m.add_function(wrap_pyfunction!(clicmd::layout_next, m)?)?;
    m.add_function(wrap_pyfunction!(clicmd::layout_units, m)?)?;
    m.add_function(wrap_pyfunction!(clicmd::propose_command, m)?)?;
    m.add_function(wrap_pyfunction!(clicmd::propose_verdict, m)?)?;
    m.add_function(wrap_pyfunction!(matchcmd::grade_command, m)?)?;
    m.add_function(wrap_pyfunction!(matchcmd::next_command, m)?)?;
    m.add_function(wrap_pyfunction!(matchcmd::asmdiff_command, m)?)?;
    m.add_function(wrap_pyfunction!(matchcmd::diffclass_command, m)?)?;
    m.add_function(wrap_pyfunction!(matchcmd::promote_command, m)?)?;
    m.add_function(wrap_pyfunction!(matchcmd::accept_command, m)?)?;
    m.add_function(wrap_pyfunction!(matchcmd::link_command, m)?)?;
    m.add_function(wrap_pyfunction!(matchcmd::probe_report, m)?)?;
    m.add_function(wrap_pyfunction!(matchcmd::lint_plan, m)?)?;
    m.add_function(wrap_pyfunction!(matchcmd::lint_not_found, m)?)?;
    m.add_function(wrap_pyfunction!(matchcmd::lint_command, m)?)?;
    m.add_function(wrap_pyfunction!(wt::wt_command, m)?)?;
    m.add_function(wrap_pyfunction!(decide::decide_status, m)?)?;
    m.add_function(wrap_pyfunction!(decide::decide_gate, m)?)?;
    m.add_function(wrap_pyfunction!(decide::decide_toolchain_view, m)?)?;
    m.add_function(wrap_pyfunction!(decide::decide_toolchain_declare, m)?)?;
    m.add_function(wrap_pyfunction!(decide::decide_toolchain_after, m)?)?;
    m.add_function(wrap_pyfunction!(decide::decide_libs_declare, m)?)?;
    m.add_function(wrap_pyfunction!(decide::decide_libs_after, m)?)?;
    m.add_function(wrap_pyfunction!(decide::decide_analyzer_declare, m)?)?;
    m.add_function(wrap_pyfunction!(init::init_project, m)?)?;
    m.add_function(wrap_pyfunction!(init::target_add, m)?)?;
    m.add_function(wrap_pyfunction!(init::skills_install, m)?)?;
    m.add_function(wrap_pyfunction!(session::session_dirty, m)?)?;
    m.add_function(wrap_pyfunction!(session::session_head, m)?)?;
    m.add_function(wrap_pyfunction!(session::session_state, m)?)?;
    m.add_function(wrap_pyfunction!(session::session_save, m)?)?;
    m.add_function(wrap_pyfunction!(session::session_clock, m)?)?;
    m.add_function(wrap_pyfunction!(session::session_record, m)?)?;
    m.add_function(wrap_pyfunction!(session::session_overview, m)?)?;
    m.add_function(wrap_pyfunction!(session::session_report, m)?)?;
    m.add_function(wrap_pyfunction!(analyzers::analyzer_step, m)?)?;
    m.add_function(wrap_pyfunction!(analyzers::analyzer_available, m)?)?;
    m.add_function(wrap_pyfunction!(analyzers::analyzer_default, m)?)?;
    m.add_function(wrap_pyfunction!(analyzers::analyzer_keys, m)?)?;
    m.add_function(wrap_pyfunction!(lintrun::lint_available, m)?)?;
    m.add_function(wrap_pyfunction!(compile::compile_ensure, m)?)?;
    m.add_function(wrap_pyfunction!(plan::plan_scan_units, m)?)?;
    m.add_class::<frontend::ScanObj>()?;
    m.add_function(wrap_pyfunction!(frontend::front_scan, m)?)?;
    m.add_function(wrap_pyfunction!(queues::grades_function, m)?)?;
    m.add_function(wrap_pyfunction!(queues::grades_regressions, m)?)?;
    m.add_function(wrap_pyfunction!(queues::grades_baseline_at, m)?)?;
    m.add_function(wrap_pyfunction!(engine::engine_run, m)?)?;
    m.add_function(wrap_pyfunction!(engine::engine_order, m)?)?;
    m.add("RuleError", m.py().get_type::<engine::RuleError>())?;
    m.add_function(wrap_pyfunction!(project::config_targets, m)?)?;
    m.add_function(wrap_pyfunction!(project::config_target_name_of, m)?)?;
    m.add_function(wrap_pyfunction!(project::config_is_target_name, m)?)?;
    m.add("ConfigError", m.py().get_type::<project::ConfigError>())?;
    m.add_class::<pystore::StoredFact>()?;
    m.add_function(wrap_pyfunction!(pystore::st_facts, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_fact, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_conflicts, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_open, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_close, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_meta, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_meta_json, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_set_meta, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_main_meta, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_note_input, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_current_run, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_find_run, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_make_current, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_runs, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_run_stats, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_blob, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_blob_json, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_put_blob, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_put_blob_json, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_drop_blobs, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_blobs, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_tus, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_tu_keys, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_put_tu, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_drop_tu, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_tu_hash, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_include_set, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_put_include_set, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_ensure_bytemap, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_bytemap_at, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_bytemap_rows, m)?)?;
    m.add_function(wrap_pyfunction!(pystore::st_summary, m)?)?;
    m.add_function(wrap_pyfunction!(fsmemo::fs_new_epoch, m)?)?;
    m.add_function(wrap_pyfunction!(fsmemo::fs_epoch, m)?)?;
    m.add_function(wrap_pyfunction!(fsmemo::fs_exists, m)?)?;
    m.add_function(wrap_pyfunction!(fsmemo::fs_walk, m)?)?;
    m.add_function(wrap_pyfunction!(fsmemo::fs_read_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(fsmemo::fs_read_text, m)?)?;
    m.add_function(wrap_pyfunction!(fsmemo::fs_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(fsmemo::fs_tree_hash, m)?)?;
    m.add_function(wrap_pyfunction!(fsmemo::fs_attach, m)?)?;
    m.add_function(wrap_pyfunction!(fsmemo::fs_flush, m)?)?;
    m.add_function(wrap_pyfunction!(fsmemo::fs_forget_all, m)?)?;
    m.add_function(wrap_pyfunction!(out_hash, m)?)?;
    m.add_function(wrap_pyfunction!(record_run, m)?)?;
    m.add_function(wrap_pyfunction!(store::store_schema, m)?)?;
    m.add_class::<clang::Unit>()?;
    m.add_class::<srcscan::ScanPiece>()?;
    m.add_class::<lint::AllDecls>()?;
    m.add_function(wrap_pyfunction!(decl::decl_parse_line, m)?)?;
    m.add_function(wrap_pyfunction!(decl::decl_load, m)?)?;
    m.add_function(wrap_pyfunction!(decl::decl_text, m)?)?;
    m.add_function(wrap_pyfunction!(decl::decl_insert, m)?)?;
    Ok(())
}
