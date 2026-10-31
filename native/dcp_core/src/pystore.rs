//! The derived-state store as Python sees it (ledger/store.py is its face): one SQLite file per target
//! (build/<target>.sqlite) holding every rule run, its facts and conflicts, content-addressed blobs, the translation
//! units' compile keys, and the materialised byte map. The connection is the core's (the one the native rules
//! use); a worktree's store reads the main checkout's store through an overlay (main_store, read-only).
//!
//! Facts come back as StoredFact objects, made once per fact row: a run's facts never change after it is recorded,
//! and a run recorded again in place keeps its unchanged rows (store.rs holds them), so the object of an unchanged
//! row is the one made before.

use crate::store::{self, py_float, SFact, SCHEMA, SCHEMA_VERSION};
use crate::{hash_parts, put_value, with_db};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

/// Attach the main checkout's store (a read-only file: URI) when this connection has not yet.
fn ensure_main(db: &Connection, main: &str) -> rusqlite::Result<bool> {
    if main.is_empty() {
        return Ok(false);
    }
    let attached: i64 = db.query_row("SELECT count(*) FROM pragma_database_list WHERE name='main_store'", [], |r| r.get(0))?;
    if attached == 0 {
        db.execute("ATTACH DATABASE ? AS main_store", [main])?;
    }
    Ok(true)
}

// ------------------------------------------------------------------------------------------------ facts as objects

/// A fact of the store: Fact's fields, its row id and the rule of its run (ledger/store.py StoredFact).
#[pyclass(frozen, name = "StoredFact", module = "decompanion")]
pub struct StoredFact {
    #[pyo3(get)]
    id: i64,
    #[pyo3(get)]
    run: String,
    #[pyo3(get)]
    lo: i64,
    #[pyo3(get)]
    hi: i64,
    #[pyo3(get)]
    kind: Py<PyAny>,
    #[pyo3(get)]
    value: Py<PyAny>,
    #[pyo3(get)]
    level: Py<PyAny>,
    #[pyo3(get)]
    by: String,
    #[pyo3(get)]
    reason: Option<String>,
    text: String,
}

#[pymethods]
impl StoredFact {
    /// The fact itself (StoredFact.fact: this object has Fact's fields).
    #[getter]
    fn fact(slf: Py<Self>) -> Py<Self> {
        slf
    }

    #[getter]
    fn size(&self) -> i64 {
        self.hi - self.lo
    }

    fn key(&self, py: Python<'_>) -> PyResult<(i64, i64, String, String)> {
        Ok((self.lo, self.hi, self.kind.bind(py).getattr("value")?.extract()?, self.text.clone()))
    }

    /// The one-line spelling `dcp facts` prints (Fact.line).
    fn line(slf: &Bound<'_, Self>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        Ok(fact_module(py)?.getattr("Fact")?.getattr("line")?.call1((slf,))?.unbind())
    }

    fn __eq__(&self, other: &Bound<'_, PyAny>) -> bool {
        match other.cast::<StoredFact>() {
            Ok(o) => {
                let o = o.get();
                (self.id, &self.run, self.lo, self.hi, &self.text, &self.by, &self.reason) == (o.id, &o.run, o.lo, o.hi, &o.text, &o.by, &o.reason)
            }
            Err(_) => false,
        }
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(format!("StoredFact(id={}, run={:?}, lo={:#x}, hi={:#x}, kind={}, value={}, level={}, by={:?})", self.id, self.run, self.lo, self.hi,
                   self.kind.bind(py).str()?, self.text, self.level.bind(py).str()?, self.by))
    }
}

thread_local! {
    static FACT_MOD: RefCell<Option<Py<PyModule>>> = const { RefCell::new(None) };
    static KINDS: RefCell<HashMap<String, Py<PyAny>>> = RefCell::new(HashMap::new());
    static LEVELS: RefCell<Vec<Py<PyAny>>> = const { RefCell::new(Vec::new()) };
    // the object made for a fact row (by the address of the core's fact, which it keeps alive)
    static OBJECTS: RefCell<HashMap<usize, (Rc<SFact>, Py<StoredFact>)>> = RefCell::new(HashMap::new());
    // (store, run id, run time) -> the run holds facts of a kind the byte map is made of
    static MAPS: RefCell<HashMap<(String, i64, u64), bool>> = RefCell::new(HashMap::new());
}

fn fact_module(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    if let Some(m) = FACT_MOD.with(|m| m.borrow().as_ref().map(|m| m.clone_ref(py))) {
        return Ok(m.into_bound(py));
    }
    let m = py.import("decompanion.ledger.fact")?;
    FACT_MOD.with(|c| *c.borrow_mut() = Some(m.clone().unbind()));
    Ok(m)
}

fn kind_obj(py: Python<'_>, kind: &str) -> PyResult<Py<PyAny>> {
    if let Some(k) = KINDS.with(|k| k.borrow().get(kind).map(|o| o.clone_ref(py))) {
        return Ok(k);
    }
    let k = fact_module(py)?.getattr("Kind")?.call1((kind,))?.unbind();
    KINDS.with(|m| m.borrow_mut().insert(kind.to_string(), k.clone_ref(py)));
    Ok(k)
}

fn level_obj(py: Python<'_>, level: i64) -> PyResult<Py<PyAny>> {
    if LEVELS.with(|l| l.borrow().is_empty()) {
        let cls = fact_module(py)?.getattr("Level")?;
        let all: Vec<Py<PyAny>> = (0..4).map(|i| cls.call1((i,)).map(|o| o.unbind())).collect::<PyResult<_>>()?;
        LEVELS.with(|l| *l.borrow_mut() = all);
    }
    LEVELS.with(|l| l.borrow().get(level as usize).map(|o| o.clone_ref(py)))
        .ok_or_else(|| PyRuntimeError::new_err(format!("no level {level}")))
}

/// A JSON value as json.loads gives it.
pub(crate) fn json_py<'py>(py: Python<'py>, v: &Value) -> PyResult<Bound<'py, PyAny>> {
    use pyo3::IntoPyObject;
    Ok(match v {
        Value::Null => py.None().into_bound(py),
        Value::Bool(b) => b.into_pyobject(py)?.to_owned().into_any(),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.into_pyobject(py)?.into_any()
            } else if let Some(u) = n.as_u64() {
                u.into_pyobject(py)?.into_any()
            } else {
                n.as_f64().unwrap_or(0.0).into_pyobject(py)?.into_any()
            }
        }
        Value::String(s) => s.into_pyobject(py)?.into_any(),
        Value::Array(a) => {
            let l = PyList::empty(py);
            for x in a {
                l.append(json_py(py, x)?)?;
            }
            l.into_any()
        }
        Value::Object(m) => {
            let d = PyDict::new(py);
            for (k, x) in m {
                d.set_item(k, json_py(py, x)?)?;
            }
            d.into_any()
        }
    })
}

fn make(py: Python<'_>, kind: &str, f: &SFact) -> PyResult<Py<StoredFact>> {
    Py::new(py, StoredFact {
        id: f.id, run: f.rule.to_string(), lo: f.lo, hi: f.hi, kind: kind_obj(py, kind)?, value: json_py(py, &f.value)?.unbind(),
        level: level_obj(py, f.level)?, by: f.by.clone(), reason: f.reason.clone(), text: f.text.clone(),
    })
}

/// The object of a fact the core holds (made once per fact).
fn object(py: Python<'_>, kind: &str, f: &Rc<SFact>) -> PyResult<Py<StoredFact>> {
    let key = Rc::as_ptr(f) as usize;
    if let Some(o) = OBJECTS.with(|m| m.borrow().get(&key).map(|(_, o)| o.clone_ref(py))) {
        return Ok(o);
    }
    let o = make(py, kind, f)?;
    OBJECTS.with(|m| {
        let mut m = m.borrow_mut();
        if m.len() > 2_000_000 {
            m.clear();
        }
        m.insert(key, (f.clone(), o.clone_ref(py)));
    });
    Ok(o)
}

fn row_fact(r: &rusqlite::Row) -> rusqlite::Result<(String, SFact)> {
    let text: String = r.get(5)?;
    Ok((r.get(4)?, SFact {
        id: r.get(0)?, rule: Rc::from(r.get::<_, String>(1)?.as_str()), lo: r.get(2)?, hi: r.get(3)?,
        value: serde_json::from_str(&text).unwrap_or(Value::Null), text, level: r.get(6)?, by: r.get(7)?, reason: r.get(8)?,
    }))
}

/// Store.facts: facts of current runs, optionally of one kind, intersecting [lo, hi), produced by the given
/// rules; sorted by (lo, hi, kind, value).
#[pyfunction]
#[pyo3(signature = (path, kind=None, lo=None, hi=None, rules=None))]
pub fn st_facts<'py>(py: Python<'py>, path: &str, kind: Option<String>, lo: Option<i64>, hi: Option<i64>, rules: Option<Vec<String>>)
    -> PyResult<Bound<'py, PyList>> {
    let rules = rules.filter(|r| !r.is_empty());
    if let (Some(kind), None, None) = (&kind, lo, hi) {
        let facts = with_db(path, |db| store::facts_of(db, path, kind, rules.as_deref(), |_| true))?;
        let objs: Vec<Py<StoredFact>> = facts.iter().map(|f| object(py, kind, f)).collect::<PyResult<_>>()?;
        return PyList::new(py, objs);
    }
    let mut q = String::from("SELECT f.id, r.rule, f.lo, f.hi, f.kind, f.value, f.level, f.by, f.reason FROM fact f \
                              JOIN run r ON r.id = f.run_id WHERE r.current=1");
    let mut args: Vec<rusqlite::types::Value> = vec![];
    if let Some(k) = &kind {
        q.push_str(" AND f.kind=?");
        args.push(k.clone().into());
    }
    if let Some(lo) = lo {
        q.push_str(" AND f.hi>?");
        args.push(lo.into());
    }
    if let Some(hi) = hi {
        q.push_str(" AND f.lo<?");
        args.push(hi.into());
    }
    if let Some(rules) = &rules {
        q.push_str(&format!(" AND r.rule IN ({})", vec!["?"; rules.len()].join(",")));
        args.extend(rules.iter().map(|r| r.clone().into()));
    }
    q.push_str(" ORDER BY f.lo, f.hi, f.kind, f.value");
    let rows: Vec<(String, SFact)> = with_db(path, |db| {
        let mut st = db.prepare(&q)?;
        let rows = st.query_map(rusqlite::params_from_iter(args.iter()), row_fact)?;
        rows.collect()
    })?;
    let objs: Vec<Py<StoredFact>> = rows.iter().map(|(k, f)| make(py, k, f)).collect::<PyResult<_>>()?;
    PyList::new(py, objs)
}

/// Store.fact: the fact of a row id (None when there is none).
#[pyfunction]
pub fn st_fact(py: Python<'_>, path: &str, fid: i64) -> PyResult<Option<Py<StoredFact>>> {
    let row = with_db(path, |db| {
        db.query_row("SELECT f.id, r.rule, f.lo, f.hi, f.kind, f.value, f.level, f.by, f.reason FROM fact f \
                      JOIN run r ON r.id=f.run_id WHERE f.id=?", [fid], row_fact).optional()
    })?;
    row.map(|(k, f)| make(py, &k, &f)).transpose()
}

/// Store.conflicts: (severity, check, lo, hi, message, a, b) of current runs (of the given rules), by address.
#[pyfunction]
#[pyo3(signature = (path, severity=None, rules=None))]
pub fn st_conflicts(path: &str, severity: Option<String>, rules: Option<Vec<String>>) -> PyResult<Vec<(String, String, i64, i64, String, String, String)>> {
    let mut q = String::from("SELECT c.severity, c.check_id, c.lo, c.hi, c.message, c.a, c.b FROM conflict c JOIN run r ON r.id=c.run_id \
                              WHERE r.current=1");
    let mut args: Vec<String> = vec![];
    if let Some(s) = severity.filter(|s| !s.is_empty()) {
        q.push_str(" AND c.severity=?");
        args.push(s);
    }
    if let Some(rules) = rules.filter(|r| !r.is_empty()) {
        q.push_str(&format!(" AND r.rule IN ({})", vec!["?"; rules.len()].join(",")));
        args.extend(rules);
    }
    q.push_str(" ORDER BY c.lo, c.hi, c.check_id, c.message");
    with_db(path, |db| {
        let mut st = db.prepare(&q)?;
        let rows = st.query_map(rusqlite::params_from_iter(args.iter()), |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?))
        })?;
        rows.collect()
    })
}

// ------------------------------------------------------------------------------------------------ open, meta, runs

/// Open (or create) the store at path: the tables when the schema version differs, an error for a store of
/// another schema; the main checkout's store attached when `main` (a file: URI) is given.
#[pyfunction]
pub fn st_open(path: &str, main: &str) -> PyResult<()> {
    if let Some(d) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(d).map_err(|e| PyRuntimeError::new_err(format!("{path}: {e}")))?;
    }
    let v = with_db(path, |db| {
        let v: Option<String> = match db.query_row("SELECT value FROM meta WHERE key='schema'", [], |r| r.get(0)).optional() {
            Ok(v) => v,
            Err(_) => None, // a new store: no meta table yet
        };
        if v.as_deref() != Some(SCHEMA_VERSION) {
            db.execute_batch(SCHEMA)?;
        }
        let v: Option<String> = db.query_row("SELECT value FROM meta WHERE key='schema'", [], |r| r.get(0)).optional()?;
        if v.is_none() {
            db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('schema', ?)", [SCHEMA_VERSION])?;
        }
        ensure_main(db, main)?;
        Ok(v)
    })?;
    match v {
        Some(v) if v != SCHEMA_VERSION => Err(PyRuntimeError::new_err(format!("{path}: store schema {v}, this code wants {SCHEMA_VERSION}: delete build/"))),
        _ => Ok(()),
    }
}

/// Close this thread's connection to the store (its file is about to be replaced or removed).
#[pyfunction]
pub fn st_close(path: &str) {
    crate::forget_conn(path);
}

#[pyfunction]
pub fn st_meta(path: &str, key: &str) -> PyResult<Option<String>> {
    with_db(path, |db| db.query_row("SELECT value FROM meta WHERE key=?", [key], |r| r.get(0)).optional())
}

#[pyfunction]
pub fn st_set_meta(path: &str, key: &str, value: &str) -> PyResult<()> {
    with_db(path, |db| db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", [key, value]).map(|_| ()))
}

#[pyfunction]
pub fn st_main_meta(path: &str, main: &str, key: &str) -> PyResult<Option<String>> {
    with_db(path, |db| {
        if !ensure_main(db, main)? {
            return Ok(None);
        }
        db.query_row("SELECT value FROM main_store.meta WHERE key=?", [key], |r| r.get(0)).optional()
    })
}

#[pyfunction]
pub fn st_note_input(path: &str, key: &str, hash: &str) -> PyResult<()> {
    with_db(path, |db| db.execute("INSERT OR REPLACE INTO input (key, hash) VALUES (?, ?)", [key, hash]).map(|_| ()))
}

/// (id, input_hash, out_hash) of the rule's current run in this store.
#[pyfunction]
pub fn st_current_run(path: &str, rule: &str) -> PyResult<Option<(i64, String, String)>> {
    with_db(path, |db| {
        db.query_row("SELECT id, input_hash, out_hash FROM run WHERE rule=? AND current=1", [rule], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).optional()
    })
}

/// A run of this rule with these inputs, in this store or the main store: (where, id, out_hash).
#[pyfunction]
pub fn st_find_run(path: &str, main: &str, rule: &str, input_hash: &str) -> PyResult<Option<(String, i64, String)>> {
    with_db(path, |db| find_run(db, main, rule, input_hash))
}

pub(crate) fn find_run(db: &Connection, main: &str, rule: &str, input_hash: &str) -> rusqlite::Result<Option<(String, i64, String)>> {
    let row: Option<(i64, String)> = db.query_row("SELECT id, out_hash FROM run WHERE rule=? AND input_hash=?", [rule, input_hash],
                                                  |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
    if let Some((id, out)) = row {
        return Ok(Some(("main".into(), id, out)));
    }
    if ensure_main(db, main)? {
        let row: Option<(i64, String)> = db.query_row("SELECT id, out_hash FROM main_store.run WHERE rule=? AND input_hash=?", [rule, input_hash],
                                                      |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
        if let Some((id, out)) = row {
            return Ok(Some(("main_store".into(), id, out)));
        }
    }
    Ok(None)
}

/// Make the run current in this store, copying it from the main store if it lives there. Returns the local id.
#[pyfunction]
pub fn st_make_current(path: &str, main: &str, rule: &str, place: &str, run_id: i64) -> PyResult<i64> {
    with_db(path, |db| make_current(db, main, rule, place, run_id))
}

pub(crate) fn make_current(db: &Connection, main: &str, rule: &str, place: &str, mut run_id: i64) -> rusqlite::Result<i64> {
    if place == "main_store" {
        ensure_main(db, main)?;
        db.execute("INSERT INTO run (rule, version, code_hash, input_hash, out_hash, ms, at) \
                    SELECT rule, version, code_hash, input_hash, out_hash, ms, at FROM main_store.run WHERE id=?", [run_id])?;
        let new_id = db.last_insert_rowid();
        db.execute("INSERT INTO fact (run_id, lo, hi, kind, value, level, by, reason) \
                    SELECT ?, lo, hi, kind, value, level, by, reason FROM main_store.fact WHERE run_id=?", [new_id, run_id])?;
        db.execute("INSERT INTO conflict (run_id, severity, check_id, lo, hi, message, a, b) \
                    SELECT ?, severity, check_id, lo, hi, message, a, b FROM main_store.conflict WHERE run_id=?", [new_id, run_id])?;
        run_id = new_id;
    }
    db.execute("UPDATE run SET current=0 WHERE rule=? AND id<>?", params![rule, run_id])?;
    db.execute("UPDATE run SET current=1 WHERE id=?", [run_id])?;
    Ok(run_id)
}

/// [(rule, version, input_hash, out_hash, current, ms, at)] of every run in this store.
#[pyfunction]
pub fn st_runs(path: &str) -> PyResult<Vec<(String, String, String, String, i64, i64, f64)>> {
    with_db(path, |db| {
        let mut st = db.prepare("SELECT rule, version, input_hash, out_hash, current, ms, at FROM run ORDER BY rule")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)))?;
        rows.collect()
    })
}

/// (facts, ms) of a run.
#[pyfunction]
pub fn st_run_stats(path: &str, run_id: i64) -> PyResult<(i64, i64)> {
    with_db(path, |db| {
        let n: i64 = db.query_row("SELECT COUNT(*) FROM fact WHERE run_id=?", [run_id], |r| r.get(0))?;
        let ms: i64 = db.query_row("SELECT ms FROM run WHERE id=?", [run_id], |r| r.get(0)).optional()?.unwrap_or(0);
        Ok((n, ms))
    })
}

// ------------------------------------------------------------------------------------------------ blobs

#[pyfunction]
pub fn st_blob<'py>(py: Python<'py>, path: &str, main: &str, hash: &str) -> PyResult<Option<Bound<'py, PyBytes>>> {
    let data: Option<Vec<u8>> = with_db(path, |db| {
        let row: Option<Vec<u8>> = db.query_row("SELECT data FROM blob WHERE hash=?", [hash], |r| r.get(0)).optional()?;
        if row.is_none() && ensure_main(db, main)? {
            return db.query_row("SELECT data FROM main_store.blob WHERE hash=?", [hash], |r| r.get(0)).optional();
        }
        Ok(row)
    })?;
    Ok(data.map(|d| PyBytes::new(py, &d)))
}

/// Store a blob: content-addressed blobs never change (INSERT OR IGNORE); one keyed by something else is
/// replaced when `replace`.
#[pyfunction]
pub fn st_put_blob(path: &str, hash: &str, kind: &str, data: &[u8], replace: bool) -> PyResult<()> {
    let verb = if replace { "INSERT OR REPLACE" } else { "INSERT OR IGNORE" };
    with_db(path, |db| db.execute(&format!("{verb} INTO blob (hash, kind, data) VALUES (?, ?, ?)"), params![hash, kind, data]).map(|_| ()))
}

/// A JSON blob's value (None when there is no such blob).
#[pyfunction]
pub fn st_blob_json<'py>(py: Python<'py>, path: &str, main: &str, hash: &str) -> PyResult<Option<Bound<'py, PyAny>>> {
    let data = st_blob(py, path, main, hash)?;
    data.map(|d| json_py(py, &serde_json::from_slice(d.as_bytes()).unwrap_or(Value::Null))).transpose()
}

/// A value stored as its canonical JSON.
#[pyfunction]
pub fn st_put_blob_json(path: &str, hash: &str, kind: &str, value: &Bound<'_, PyAny>) -> PyResult<()> {
    let mut s = String::new();
    put_value(&mut s, value)?;
    st_put_blob(path, hash, kind, s.as_bytes(), false)
}

#[pyfunction]
pub fn st_drop_blobs(path: &str, kind: &str) -> PyResult<()> {
    with_db(path, |db| db.execute("DELETE FROM blob WHERE kind=?", [kind]).map(|_| ()))
}

/// Every blob of one kind, main store first, the overlay's own replacing it: {hash: data}.
#[pyfunction]
pub fn st_blobs<'py>(py: Python<'py>, path: &str, main: &str, kind: &str) -> PyResult<Bound<'py, PyDict>> {
    let rows: Vec<(String, Vec<u8>)> = with_db(path, |db| {
        let mut out = vec![];
        let mut sources = vec![];
        if ensure_main(db, main)? {
            sources.push("main_store.blob");
        }
        sources.push("blob");
        for s in sources {
            let mut st = db.prepare(&format!("SELECT hash, data FROM {s} WHERE kind=?"))?;
            let rows = st.query_map([kind], |r| Ok((r.get(0)?, r.get(1)?)))?;
            for r in rows {
                out.push(r?);
            }
        }
        Ok(out)
    })?;
    let d = PyDict::new(py);
    for (h, data) in rows {
        d.set_item(h, PyBytes::new(py, &data))?;
    }
    Ok(d)
}

// ------------------------------------------------------------------------------------------------ translation units

const TU_COLS: [&str; 11] = ["unit", "amalg", "src_hash", "flags", "flags_hash", "include_hash", "obj_hash", "ok", "log", "diags", "at"];
const TU_KEYS: [&str; 7] = ["unit", "amalg", "src_hash", "flags_hash", "include_hash", "obj_hash", "ok"];

fn tu_rows<'py>(py: Python<'py>, path: &str, cols: &[&str]) -> PyResult<Bound<'py, PyDict>> {
    let rows: Vec<Vec<rusqlite::types::Value>> = with_db(path, |db| {
        let mut st = db.prepare(&format!("SELECT {} FROM tu ORDER BY unit", cols.join(", ")))?;
        let rows = st.query_map([], |r| (0..cols.len()).map(|i| r.get::<_, rusqlite::types::Value>(i)).collect())?;
        rows.collect()
    })?;
    let out = PyDict::new(py);
    for row in rows {
        let d = PyDict::new(py);
        for (c, v) in cols.iter().zip(row) {
            use rusqlite::types::Value as V;
            let o: Bound<'py, PyAny> = match (*c, v) {
                ("flags" | "diags", V::Text(t)) => json_py(py, &serde_json::from_str(&t).unwrap_or(Value::Null))?,
                ("ok", V::Integer(i)) => pyo3::types::PyBool::new(py, i != 0).to_owned().into_any(),
                (_, V::Integer(i)) => i.into_pyobject(py)?.into_any(),
                (_, V::Real(f)) => f.into_pyobject(py)?.into_any(),
                (_, V::Text(t)) => t.into_pyobject(py)?.into_any(),
                (_, V::Blob(b)) => PyBytes::new(py, &b).into_any(),
                (_, V::Null) => py.None().into_bound(py),
            };
            d.set_item(*c, o)?;
        }
        out.set_item(d.get_item("unit")?.unwrap(), d)?;
    }
    Ok(out)
}

/// unit -> its tu row (flags and diags decoded).
#[pyfunction]
pub fn st_tus<'py>(py: Python<'py>, path: &str) -> PyResult<Bound<'py, PyDict>> {
    tu_rows(py, path, &TU_COLS)
}

/// unit -> its tu row's keys and outcome only (no log, flags or diagnostics).
#[pyfunction]
pub fn st_tu_keys<'py>(py: Python<'py>, path: &str) -> PyResult<Bound<'py, PyDict>> {
    tu_rows(py, path, &TU_KEYS)
}

#[pyfunction]
pub fn st_put_tu(path: &str, row: &Bound<'_, PyDict>) -> PyResult<()> {
    let s = |k: &str| -> PyResult<String> { row.get_item(k)?.ok_or_else(|| PyRuntimeError::new_err(format!("tu row without {k}")))?.extract() };
    let canon = |k: &str| -> PyResult<String> {
        let v = row.get_item(k)?.ok_or_else(|| PyRuntimeError::new_err(format!("tu row without {k}")))?;
        let mut out = String::new();
        put_value(&mut out, &PyList::new(row.py(), v.try_iter()?.collect::<PyResult<Vec<_>>>()?)?.into_any())?;
        Ok(out)
    };
    let ok = row.get_item("ok")?.map(|v| v.is_truthy()).transpose()?.unwrap_or(false) as i64;
    let at: f64 = match row.get_item("at")? {
        Some(v) => v.extract()?,
        None => std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0),
    };
    let vals = (s("unit")?, s("amalg")?, s("src_hash")?, canon("flags")?, s("flags_hash")?, s("include_hash")?, s("obj_hash")?, ok, s("log")?, canon("diags")?, at);
    with_db(path, |db| {
        db.execute("INSERT OR REPLACE INTO tu (unit, amalg, src_hash, flags, flags_hash, include_hash, obj_hash, ok, log, diags, at) \
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                   params![vals.0, vals.1, vals.2, vals.3, vals.4, vals.5, vals.6, vals.7, vals.8, vals.9, vals.10]).map(|_| ())
    })
}

#[pyfunction]
pub fn st_drop_tu(path: &str, unit: &str) -> PyResult<()> {
    with_db(path, |db| db.execute("DELETE FROM tu WHERE unit=?", [unit]).map(|_| ()))
}

/// The hash of every tu row's inputs and outcome: the `objects` input of the match rules.
#[pyfunction]
pub fn st_tu_hash(path: &str) -> PyResult<String> {
    tu_hash(path)
}

pub(crate) fn tu_hash(path: &str) -> PyResult<String> {
    let rows: Vec<String> = with_db(path, |db| {
        let mut st = db.prepare("SELECT unit, src_hash, flags_hash, include_hash, obj_hash, ok, diags FROM tu ORDER BY unit")?;
        let rows = st.query_map([], |r| {
            let v = Value::Array(vec![
                Value::String(r.get(0)?), Value::String(r.get(1)?), Value::String(r.get(2)?), Value::String(r.get(3)?),
                Value::String(r.get(4)?), Value::from(r.get::<_, i64>(5)?), Value::String(r.get(6)?),
            ]);
            let mut s = String::new();
            store::canon(&mut s, &v);
            Ok(s)
        })?;
        rows.collect()
    })?;
    Ok(hash_parts(rows.into_iter()))
}

#[pyfunction]
pub fn st_include_set(path: &str, key: &str) -> PyResult<Option<Vec<String>>> {
    let t: Option<String> = with_db(path, |db| db.query_row("SELECT files FROM include_set WHERE key=?", [key], |r| r.get(0)).optional())?;
    Ok(t.map(|t| serde_json::from_str(&t).unwrap_or_default()))
}

#[pyfunction]
pub fn st_put_include_set(path: &str, key: &str, files: Vec<String>) -> PyResult<()> {
    let mut s = String::new();
    store::canon(&mut s, &Value::Array(files.into_iter().map(Value::String).collect()));
    with_db(path, |db| db.execute("INSERT OR REPLACE INTO include_set (key, files) VALUES (?, ?)", [key, &s]).map(|_| ()))
}

// ------------------------------------------------------------------------------------------------ the byte map

type MapRow = (i64, i64, String, i64, Option<i64>, Option<i64>, Option<i64>, Option<i64>);

/// The fact of one group that owns each cut, cuts visited in address order: among the facts covering the address
/// the highest level, then the highest lo, then the highest hi (equal keys: the later fact).
struct Sweep {
    items: Vec<Rc<SFact>>,
    i: usize,
    active: Vec<Rc<SFact>>,
}

impl Sweep {
    fn new(mut items: Vec<Rc<SFact>>) -> Sweep {
        items.sort_by_key(|f| (f.lo, f.hi));
        Sweep { items, i: 0, active: vec![] }
    }

    fn at(&mut self, a: i64) -> Option<Rc<SFact>> {
        while self.i < self.items.len() && self.items[self.i].lo <= a {
            self.active.push(self.items[self.i].clone());
            self.i += 1;
        }
        self.active.retain(|f| f.hi > a);
        let mut best: Option<&Rc<SFact>> = None;
        for f in &self.active {
            if best.is_none_or(|b| (f.level, f.lo, f.hi) >= (b.level, b.lo, b.hi)) {
                best = Some(f);
            }
        }
        best.cloned()
    }
}

/// Rebuild the byte map when the symbol / region / section / unit / source facts changed. Returns the hash: of the
/// current runs (id and time) that hold such facts; the map rows name fact ids, so a run recorded again changes it
/// although its output is the same.
pub(crate) fn ensure_bytemap(db: &mut Connection, path: &str) -> rusqlite::Result<String> {
    let runs: Vec<(String, i64, f64)> = {
        let mut st = db.prepare_cached("SELECT rule, id, at FROM run WHERE current=1 ORDER BY rule")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        rows.collect::<Result<_, _>>()?
    };
    let mut parts = vec!["bytemap.v2".to_string()];
    for (rule, rid, at) in &runs {
        let key = (path.to_string(), *rid, at.to_bits());
        let has = match MAPS.with(|m| m.borrow().get(&key).copied()) {
            Some(h) => h,
            None => {
                let h = db.query_row("SELECT 1 FROM fact WHERE run_id=? AND kind IN ('section','region','symbol','unit','source') LIMIT 1",
                                     [rid], |_| Ok(())).optional()?.is_some();
                MAPS.with(|m| m.borrow_mut().insert(key, h));
                h
            }
        };
        if has {
            let mut s = format!("{rule}={rid}@");
            py_float(&mut s, *at);
            parts.push(s);
        }
    }
    let h = hash_parts(parts.into_iter());
    let cur: Option<String> = db.query_row("SELECT value FROM meta WHERE key='bytemap'", [], |r| r.get(0)).optional()?;
    if cur.as_deref() == Some(h.as_str()) {
        return Ok(h);
    }
    let get = |k: &str| store::facts_of(db, path, k, None, |_| true);
    let mut symbols = get("symbol")?;
    symbols.extend(get("region")?);
    let (sections, units, sources) = (get("section")?, get("unit")?, get("source")?);
    let mut cuts: Vec<i64> = [&symbols, &sections, &units, &sources].iter().flat_map(|g| g.iter().flat_map(|f| [f.lo, f.hi])).collect();
    cuts.sort_unstable();
    cuts.dedup();
    let (mut isym, mut isec, mut iunit, mut isrc) = (Sweep::new(symbols), Sweep::new(sections), Sweep::new(units), Sweep::new(sources));
    let mut rows: Vec<MapRow> = vec![];
    for w in cuts.windows(2) {
        let (a, b) = (w[0], w[1]);
        let (s, sec, u, src) = (isym.at(a), isec.at(a), iunit.at(a), isrc.at(a));
        let Some(s) = s else { continue };
        // a symbol names its skind, a region (no skind) what it is
        let cls = match (s.value.get("skind"), s.value.get("what")) {
            (Some(k), _) => k.as_str().unwrap_or("").to_string(),
            (None, w) => format!("region.{}", w.and_then(|w| w.as_str()).unwrap_or("")),
        };
        rows.push((a, b, cls, s.level, Some(s.id), u.map(|f| f.id), src.map(|f| f.id), sec.map(|f| f.id)));
    }
    let tx = db.transaction()?;
    tx.execute("DELETE FROM bytemap", [])?;
    {
        let mut st = tx.prepare("INSERT INTO bytemap (lo, hi, cls, level, symbol, unit, source, section) VALUES (?,?,?,?,?,?,?,?)")?;
        for r in &rows {
            st.execute(params![r.0, r.1, r.2, r.3, r.4, r.5, r.6, r.7])?;
        }
    }
    tx.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('bytemap', ?)", [&h])?;
    tx.commit()?;
    Ok(h)
}

#[pyfunction]
pub fn st_ensure_bytemap(path: &str) -> PyResult<String> {
    with_db(path, |db| ensure_bytemap(db, path))
}

fn map_row(r: &rusqlite::Row) -> rusqlite::Result<MapRow> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?))
}

/// The byte map row holding addr (the map built first when its facts changed).
#[pyfunction]
pub fn st_bytemap_at(path: &str, addr: i64) -> PyResult<Option<MapRow>> {
    with_db(path, |db| {
        ensure_bytemap(db, path)?;
        db.query_row("SELECT lo, hi, cls, level, symbol, unit, source, section FROM bytemap WHERE lo<=? ORDER BY lo DESC LIMIT 1", [addr], map_row)
            .optional()
    })
}

/// The byte map rows intersecting [lo, hi) (the map built first when its facts changed).
#[pyfunction]
#[pyo3(signature = (path, lo=None, hi=None))]
pub fn st_bytemap_rows(path: &str, lo: Option<i64>, hi: Option<i64>) -> PyResult<Vec<MapRow>> {
    with_db(path, |db| bytemap_rows(db, path, lo, hi))
}

pub(crate) fn bytemap_rows(db: &mut Connection, path: &str, lo: Option<i64>, hi: Option<i64>) -> rusqlite::Result<Vec<MapRow>> {
    ensure_bytemap(db, path)?;
    let (lo, hi) = (lo.unwrap_or(i64::MIN), hi.unwrap_or(i64::MAX));
    let mut st = db.prepare_cached("SELECT lo, hi, cls, level, symbol, unit, source, section FROM bytemap WHERE hi>? AND lo<? ORDER BY lo")?;
    let rows = st.query_map([lo, hi], map_row)?;
    rows.collect()
}

/// Bytes per section per class and per level: ({section: {class: bytes}}, {section: {level: bytes}}), sections in
/// map order.
#[pyfunction]
pub fn st_summary<'py>(py: Python<'py>, path: &str) -> PyResult<(Bound<'py, PyDict>, Bound<'py, PyDict>)> {
    const LEVEL_NAMES: [&str; 4] = ["open", "declared", "derived", "proven"];
    let (rows, secs) = with_db(path, |db| {
        let rows = bytemap_rows(db, path, None, None)?;
        let secs: HashMap<i64, String> = store::facts_of(db, path, "section", None, |_| true)?.iter()
            .map(|f| (f.id, f.value.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string())).collect();
        Ok((rows, secs))
    })?;
    let (by_sec, by_level) = (PyDict::new(py), PyDict::new(py));
    for (lo, hi, cls, level, _, _, _, sec) in rows {
        let name = sec.and_then(|s| secs.get(&s)).map(|s| s.as_str()).unwrap_or("(headers)");
        for (d, k) in [(&by_sec, cls.as_str()), (&by_level, LEVEL_NAMES.get(level as usize).copied().unwrap_or("open"))] {
            let inner = match d.get_item(name)? {
                Some(x) => x.cast_into::<PyDict>()?,
                None => {
                    let x = PyDict::new(py);
                    d.set_item(name, &x)?;
                    x
                }
            };
            let n: i64 = inner.get_item(k)?.map(|v| v.extract()).transpose()?.unwrap_or(0);
            inner.set_item(k, n + hi - lo)?;
        }
    }
    Ok((by_sec, by_level))
}
