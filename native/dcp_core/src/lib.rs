//! dcp_core: the native core of decompanion (docs/plan.md, section 20).
//!
//! N0: the store's write path. `record_run` writes a finished rule run as ledger/store.py's Store.record_run
//! does (same SQL, same out_hash), on its own connection to the project's store (WAL: beside Python's).
//! `canonical` and `out_hash` are fact.canonical and the run hash, byte for byte: the shadow mode of the engine
//! compares them with Python's for every rule's output.

mod coff;
mod compare;
mod cs;
mod lde;
mod pe;
mod rules;
mod store;

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
pub(crate) fn put_str(out: &mut String, s: &str) {
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

/// The store's native connection for code that reports Python errors itself (a native rule).
pub(crate) fn with_conn<T>(path: &str, f: impl FnOnce(&mut Connection) -> PyResult<T>) -> PyResult<T> {
    with_db(path, |_| Ok(()))?;
    CONNS.with(|c| f(c.borrow_mut().get_mut(path).unwrap()))
}

/// A run written as Store.record_run writes it, on the store's native connection: (run id, out_hash). `rows` and
/// `confl` must be in record order (sort_rows / sort_conflicts). `shortcuts` false is DCP_NO_SHORTCUTS.
pub(crate) fn write_run(
    db: &mut Connection,
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
    let same: Option<i64> = if shortcuts {
        tx.query_row("SELECT id FROM run WHERE rule=? AND current=1 AND out_hash=?", params![rule, out], |r| r.get(0)).ok()
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
        tx.execute("UPDATE run SET version=?, code_hash=?, input_hash=?, ms=? WHERE id=?",
                   params![version, code_hash, input_hash, ms, run_id])?;
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
        let mut st = tx.prepare("INSERT INTO fact (run_id, lo, hi, kind, value, level, by, reason) VALUES (?,?,?,?,?,?,?,?)")?;
        for r in rows {
            st.execute(params![run_id, r.lo, r.hi, r.kind, r.value, r.level, r.by, r.reason])?;
        }
    }
    {
        let mut st = tx.prepare("INSERT INTO conflict (run_id, severity, check_id, lo, hi, message, a, b) VALUES (?,?,?,?,?,?,?,?)")?;
        for c in confl {
            st.execute(params![run_id, c.severity, c.check, c.lo, c.hi, c.message, c.a, c.b])?;
        }
    }
    tx.commit()?;
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
    py.detach(|| with_db(db_path, |db| write_run(db, rule, version, code_hash, input_hash, &rows, &confl, ms, shortcuts)))
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

/// The shadow of match.compiled_functions' compares: for each (object path, C name, address, next start) the
/// compare of that function, or None when the object defines no function of that name: (size, diffs, tail_ok,
/// tail, abs_ours, abs_image, sites_ok, missing_sites, code_len, the relocated offsets with their kinds).
#[pyfunction]
fn compare_functions(
    py: Python<'_>,
    image_path: &str,
    fill_forms: Vec<Vec<u8>>,
    use_relocs: bool,
    items: Vec<(String, String, u32, u32)>,
) -> PyResult<Vec<Py<PyAny>>> {
    let img = image(image_path)?;
    let sites = if use_relocs { Some(img.relocations()) } else { None };
    let forms = compare::fill_order(&fill_forms);
    let mut out = Vec::with_capacity(items.len());
    let mut objs: HashMap<String, std::rc::Rc<(coff::Obj, HashMap<String, usize>)>> = HashMap::new();
    for (path, name, addr, next) in items {
        if !objs.contains_key(&path) {
            objs.insert(path.clone(), object(&path)?);
        }
        let o = objs[&path].clone();
        let Some(&k) = o.1.get(&name) else {
            out.push(py.None());
            continue;
        };
        let code = o.0.function_code(k);
        let c = compare::compare(&img, &code, addr, sites.as_deref(), next, &forms);
        let relocs: Vec<(u32, u8, u32)> = code.relocs.iter().map(|(off, r)| (*off, r.kind_width().0, r.kind_width().1)).collect();
        let t = (c.size, c.diffs, c.tail_ok, c.tail, c.abs_ours, c.abs_image, c.sites_ok, c.missing_sites, code.code_len, relocs);
        out.push(t.into_pyobject(py)?.into_any().unbind());
    }
    Ok(out)
}

/// The length decoder against capstone: `random` random byte strings (a fixed seed; the fast path must give
/// capstone's length wherever it answers, and must not answer where capstone does not decode), then each blob of
/// `blobs` decoded whole both ways. (random checked, fast answers, mismatches with examples, blobs differing).
#[pyfunction]
fn lde_selftest(dll: &str, random: usize, blobs: Vec<Vec<u8>>) -> PyResult<(usize, usize, Vec<String>, usize)> {
    let mut state: u64 = 0x9e3779b97f4a7c15;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let (mut fast, mut bad) = (0usize, Vec::new());
    for _ in 0..random {
        let mut b = [0u8; 16];
        for x in b.iter_mut() {
            *x = next() as u8;
        }
        if let Some(n) = lde::length(&b) {
            fast += 1;
            let c = cs::one(dll, &b, 0x401000).map_err(PyRuntimeError::new_err)?;
            if c != Some(n) {
                bad.push(format!("{:02x?}: tables {n}, capstone {c:?}", &b[..n.max(c.unwrap_or(0)).min(16)]));
            }
        }
    }
    let mut differ = 0;
    for blob in &blobs {
        let a = lde::lengths(dll, blob, 0x401000).map_err(PyRuntimeError::new_err)?;
        let c = cs::lengths(dll, blob, 0x401000).map_err(PyRuntimeError::new_err)?;
        if a != c {
            differ += 1;
            let k = a.iter().zip(c.iter()).position(|(x, y)| x != y).unwrap_or(a.len().min(c.len()));
            let at = a.get(k).or(c.get(k)).map(|x| (x.0 - 0x401000) as usize).unwrap_or(0);
            bad.push(format!("blob: tables {:?} capstone {:?} at +{:#x}: {:02x?}", a.get(k), c.get(k), at,
                             &blob[at..(at + 12).min(blob.len())]));
        }
    }
    bad.truncate(20);
    Ok((random, fast, bad, differ))
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(canonical, m)?)?;
    m.add_function(wrap_pyfunction!(out_hash, m)?)?;
    m.add_function(wrap_pyfunction!(record_run, m)?)?;
    m.add_function(wrap_pyfunction!(compare_functions, m)?)?;
    m.add_function(wrap_pyfunction!(rules::run_rule, m)?)?;
    m.add_function(wrap_pyfunction!(lde_selftest, m)?)?;
    m.add_function(wrap_pyfunction!(rules::py_aligned_sites, m)?)?;
    m.add_function(wrap_pyfunction!(rules::py_least_size, m)?)?;
    m.add_function(wrap_pyfunction!(rules::py_padding_masked, m)?)?;
    Ok(())
}
