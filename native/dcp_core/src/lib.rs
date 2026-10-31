//! dcp_core: the native core of decompanion (docs/plan.md, section 20).
//!
//! N0: the store's write path. `record_run` writes a finished rule run as ledger/store.py's Store.record_run
//! does (same SQL, same out_hash), on its own connection to the project's store (WAL: beside Python's).
//! `canonical` and `out_hash` are fact.canonical and the run hash, byte for byte: the shadow mode of the engine
//! compares them with Python's for every rule's output.

use pyo3::exceptions::{PyRuntimeError, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

// ------------------------------------------------------------------------------------------------ canonical

/// A string as json.dumps(ensure_ascii=True) spells it, quotes included.
fn put_str(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
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
fn put_value(out: &mut String, v: &Bound<'_, PyAny>) -> PyResult<()> {
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
struct Row {
    lo: i64,
    hi: i64,
    kind: String,
    value: String, // canonical(value)
    level: i64,
    by: String,
    reason: Option<String>,
}

struct ConflictRow {
    severity: String,
    check: String,
    lo: i64,
    hi: i64,
    message: String,
    a: String,
    b: String,
}

fn rows_of(facts: &Bound<'_, PyList>) -> PyResult<Vec<Row>> {
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

fn conflicts_of(conflicts: &Bound<'_, PyList>) -> PyResult<Vec<ConflictRow>> {
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
fn hash_parts<'a>(parts: impl Iterator<Item = String>) -> String {
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
fn run_hash(rows: &[Row], conflicts: &[ConflictRow]) -> String {
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

fn with_db<T>(path: &str, f: impl FnOnce(&mut Connection) -> rusqlite::Result<T>) -> PyResult<T> {
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
    py.detach(|| {
        let out = run_hash(&rows, &confl);
        let at = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0);
        with_db(db_path, |db| {
            let tx = db.transaction()?;
            let same: Option<i64> = if shortcuts {
                tx.query_row(
                    "SELECT id FROM run WHERE rule=? AND current=1 AND out_hash=?",
                    params![rule, out],
                    |r| r.get(0),
                )
                .ok()
            } else {
                None
            };
            let run_id;
            if let Some(id) = same {
                run_id = id;
                let old: Vec<i64> = {
                    let mut st = tx.prepare("SELECT id FROM run WHERE rule=? AND id<>?")?;
                    st.query_map(params![rule, run_id], |r| r.get(0))?.collect::<Result<_, _>>()?
                };
                for oid in old {
                    tx.execute("DELETE FROM fact WHERE run_id=?", [oid])?;
                    tx.execute("DELETE FROM conflict WHERE run_id=?", [oid])?;
                    tx.execute("DELETE FROM run WHERE id=?", [oid])?;
                }
                tx.execute(
                    "UPDATE run SET version=?, code_hash=?, input_hash=?, ms=? WHERE id=?",
                    params![version, code_hash, input_hash, ms, run_id],
                )?;
                tx.execute("DELETE FROM conflict WHERE run_id=?", [run_id])?;
            } else {
                let old: Vec<i64> = {
                    let mut st = tx.prepare("SELECT id FROM run WHERE rule=?")?;
                    st.query_map([rule], |r| r.get(0))?.collect::<Result<_, _>>()?
                };
                for oid in old {
                    tx.execute("DELETE FROM fact WHERE run_id=?", [oid])?;
                    tx.execute("DELETE FROM conflict WHERE run_id=?", [oid])?;
                    tx.execute("DELETE FROM run WHERE id=?", [oid])?;
                }
                tx.execute(
                    "INSERT INTO run (rule, version, code_hash, input_hash, out_hash, current, ms, at) VALUES (?,?,?,?,?,1,?,?)",
                    params![rule, version, code_hash, input_hash, out, ms, at],
                )?;
                run_id = tx.last_insert_rowid();
                {
                    let mut st = tx.prepare(
                        "INSERT INTO fact (run_id, lo, hi, kind, value, level, by, reason) VALUES (?,?,?,?,?,?,?,?)",
                    )?;
                    for r in &rows {
                        st.execute(params![run_id, r.lo, r.hi, r.kind, r.value, r.level, r.by, r.reason])?;
                    }
                }
            }
            {
                let mut st = tx.prepare(
                    "INSERT INTO conflict (run_id, severity, check_id, lo, hi, message, a, b) VALUES (?,?,?,?,?,?,?,?)",
                )?;
                for c in &confl {
                    st.execute(params![run_id, c.severity, c.check, c.lo, c.hi, c.message, c.a, c.b])?;
                }
            }
            tx.commit()?;
            Ok((run_id, out))
        })
    })
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(canonical, m)?)?;
    m.add_function(wrap_pyfunction!(out_hash, m)?)?;
    m.add_function(wrap_pyfunction!(record_run, m)?)?;
    Ok(())
}
