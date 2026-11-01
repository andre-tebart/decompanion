//! The derived-state store as Python sees it (ledger/store.py is its face): one SQLite file per target
//! (build/<target>.sqlite) holding every rule run, its facts and conflicts, content-addressed blobs, the translation
//! units' compile keys, and the materialised byte map. The connection is the core's (the one the native rules
//! use); a worktree's store reads the main checkout's store through an overlay (main_store, read-only).
//!
//! Facts come back as StoredFact objects, made once per fact row: a run's facts never change after it is recorded,
//! and a run recorded again in place keeps its unchanged rows (store.rs holds them), so the object of an unchanged
//! row is the one made before.

use crate::error::{Error, Result};
use crate::store::{self, py_float, SFact, SCHEMA, SCHEMA_VERSION};
use crate::{hash_parts, with_db};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

/// Attach the main checkout's store (a read-only file: URI) when this connection has not yet.
pub(crate) fn ensure_main(db: &Connection, main: &str) -> rusqlite::Result<bool> {
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

    /// The one-line spelling `dcp facts` prints.
    fn line(&self, py: Python<'_>) -> PyResult<String> {
        let f = SFact { id: self.id, rule: Rc::from(self.run.as_str()), lo: self.lo, hi: self.hi, text: self.text.clone(),
                        value: serde_json::from_str(&self.text).unwrap_or(Value::Null), level: self.level.bind(py).extract()?, by: self.by.clone(),
                        reason: self.reason.clone() };
        let kind: String = self.kind.bind(py).getattr("value")?.extract()?;
        Ok(crate::clicmd::fact_line(&kind, &f))
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

pub(crate) fn level_obj(py: Python<'_>, level: i64) -> PyResult<Py<PyAny>> {
    if LEVELS.with(|l| l.borrow().is_empty()) {
        let cls = fact_module(py)?.getattr("Level")?;
        let all: Vec<Py<PyAny>> = (0..4).map(|i| cls.call1((i,)).map(|o| o.unbind())).collect::<PyResult<_>>()?;
        LEVELS.with(|l| *l.borrow_mut() = all);
    }
    LEVELS.with(|l| l.borrow().get(level as usize).map(|o| o.clone_ref(py)))
        .ok_or_else(|| Error::runtime(format!("no level {level}")).into())
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

/// A Python value (None, bool, int, float, str, list, tuple, dict with str keys) as JSON data.
pub(crate) fn py_value(v: &Bound<'_, PyAny>) -> PyResult<Value> {
    use pyo3::types::{PyBool, PyFloat, PyInt, PyString, PyTuple};
    Ok(if v.is_none() {
        Value::Null
    } else if let Ok(b) = v.cast::<PyBool>() {
        Value::Bool(b.is_true())
    } else if v.is_instance_of::<PyInt>() {
        match v.extract::<i64>() {
            Ok(i) => Value::from(i),
            Err(_) => Value::from(v.extract::<u64>()?),
        }
    } else if v.is_instance_of::<PyFloat>() {
        Value::from(v.extract::<f64>()?)
    } else if let Ok(s) = v.cast::<PyString>() {
        Value::String(s.extract::<String>()?)
    } else if let Ok(d) = v.cast::<PyDict>() {
        let mut m = serde_json::Map::new();
        for (k, x) in d.iter() {
            m.insert(k.str()?.extract::<String>()?, py_value(&x)?);
        }
        Value::Object(m)
    } else if v.is_instance_of::<PyList>() || v.is_instance_of::<PyTuple>() {
        Value::Array(v.try_iter()?.map(|x| py_value(&x?)).collect::<PyResult<_>>()?)
    } else {
        Value::String(v.str()?.extract::<String>()?)
    })
}

fn make(py: Python<'_>, kind: &str, f: &SFact) -> PyResult<Py<StoredFact>> {
    Py::new(py, StoredFact {
        id: f.id, run: f.rule.to_string(), lo: f.lo, hi: f.hi, kind: kind_obj(py, kind)?, value: json_py(py, &f.value)?.unbind(),
        level: level_obj(py, f.level)?, by: f.by.clone(), reason: f.reason.clone(), text: f.text.clone(),
    })
}

/// The object of a fact the core holds (made once per fact).
pub(crate) fn object(py: Python<'_>, kind: &str, f: &Rc<SFact>) -> PyResult<Py<StoredFact>> {
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
pub fn st_conflicts(path: &str, severity: Option<String>, rules: Option<Vec<String>>) -> Result<Vec<(String, String, i64, i64, String, String, String)>> {
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
pub fn st_open(path: &str, main: &str) -> Result<()> {
    if let Some(d) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(d).map_err(|e| Error::runtime(format!("{path}: {e}")))?;
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
        Some(v) if v != SCHEMA_VERSION => Err(Error::runtime(format!("{path}: store schema {v}, this code wants {SCHEMA_VERSION}: delete build/"))),
        _ => Ok(()),
    }
}

/// Close this thread's connection to the store (its file is about to be replaced or removed).
#[pyfunction]
pub fn st_close(path: &str) {
    crate::forget_conn(path);
}

#[pyfunction]
pub fn st_meta(path: &str, key: &str) -> Result<Option<String>> {
    with_db(path, |db| db.query_row("SELECT value FROM meta WHERE key=?", [key], |r| r.get(0)).optional())
}

#[pyfunction]
pub fn st_set_meta(path: &str, key: &str, value: &str) -> Result<()> {
    with_db(path, |db| db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", [key, value]).map(|_| ()))
}

#[pyfunction]
pub fn st_main_meta(path: &str, main: &str, key: &str) -> Result<Option<String>> {
    with_db(path, |db| {
        if !ensure_main(db, main)? {
            return Ok(None);
        }
        db.query_row("SELECT value FROM main_store.meta WHERE key=?", [key], |r| r.get(0)).optional()
    })
}

/// (id, input_hash, out_hash) of the rule's current run in this store.
#[pyfunction]
pub fn st_current_run(path: &str, rule: &str) -> Result<Option<(i64, String, String)>> {
    with_db(path, |db| {
        db.query_row("SELECT id, input_hash, out_hash FROM run WHERE rule=? AND current=1", [rule], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).optional()
    })
}

/// A run of this rule with these inputs, in this store or the main store: (where, id, out_hash).
#[pyfunction]
pub fn st_find_run(path: &str, main: &str, rule: &str, input_hash: &str) -> Result<Option<(String, i64, String)>> {
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
pub fn st_make_current(path: &str, main: &str, rule: &str, place: &str, run_id: i64) -> Result<i64> {
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

/// (facts, ms) of a run.
#[pyfunction]
pub fn st_run_stats(path: &str, run_id: i64) -> Result<(i64, i64)> {
    with_db(path, |db| {
        let n: i64 = db.query_row("SELECT COUNT(*) FROM fact WHERE run_id=?", [run_id], |r| r.get(0))?;
        let ms: i64 = db.query_row("SELECT ms FROM run WHERE id=?", [run_id], |r| r.get(0)).optional()?.unwrap_or(0);
        Ok((n, ms))
    })
}

// ------------------------------------------------------------------------------------------------ blobs

/// Store a blob: content-addressed blobs never change (INSERT OR IGNORE); one keyed by something else is
/// replaced when `replace`.
#[pyfunction]
pub fn st_put_blob(path: &str, hash: &str, kind: &str, data: &[u8], replace: bool) -> Result<()> {
    let verb = if replace { "INSERT OR REPLACE" } else { "INSERT OR IGNORE" };
    with_db(path, |db| db.execute(&format!("{verb} INTO blob (hash, kind, data) VALUES (?, ?, ?)"), params![hash, kind, data]).map(|_| ()))
}

#[pyfunction]
pub fn st_drop_blobs(path: &str, kind: &str) -> Result<()> {
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


pub(crate) fn tu_hash(path: &str) -> Result<String> {
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
pub fn st_ensure_bytemap(path: &str) -> Result<String> {
    with_db(path, |db| ensure_bytemap(db, path))
}

fn map_row(r: &rusqlite::Row) -> rusqlite::Result<MapRow> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?))
}

/// The byte map row holding addr (the map built first when its facts changed).
#[pyfunction]
pub fn st_bytemap_at(path: &str, addr: i64) -> Result<Option<MapRow>> {
    with_db(path, |db| {
        ensure_bytemap(db, path)?;
        db.query_row("SELECT lo, hi, cls, level, symbol, unit, source, section FROM bytemap WHERE lo<=? ORDER BY lo DESC LIMIT 1", [addr], map_row)
            .optional()
    })
}

/// The byte map rows intersecting [lo, hi) (the map built first when its facts changed).
#[pyfunction]
#[pyo3(signature = (path, lo=None, hi=None))]
pub fn st_bytemap_rows(path: &str, lo: Option<i64>, hi: Option<i64>) -> Result<Vec<MapRow>> {
    with_db(path, |db| bytemap_rows(db, path, lo, hi))
}

pub(crate) fn bytemap_rows(db: &mut Connection, path: &str, lo: Option<i64>, hi: Option<i64>) -> rusqlite::Result<Vec<MapRow>> {
    ensure_bytemap(db, path)?;
    let (lo, hi) = (lo.unwrap_or(i64::MIN), hi.unwrap_or(i64::MAX));
    let mut st = db.prepare_cached("SELECT lo, hi, cls, level, symbol, unit, source, section FROM bytemap WHERE hi>? AND lo<? ORDER BY lo")?;
    let rows = st.query_map([lo, hi], map_row)?;
    rows.collect()
}
