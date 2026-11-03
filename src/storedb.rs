//! The derived-state store: one SQLite file per target
//! (build/<target>.sqlite) holding every rule run, its facts and conflicts, content-addressed blobs, the translation
//! units' compile keys, and the materialised byte map. The connection is the core's (the one the native rules
//! use); a worktree's store reads the main checkout's store through an overlay (main_store, read-only).
//!
//! Claims come back as the core's Claim values (store.rs holds the facts of the current runs).

use crate::error::{Error, Result};
use crate::store::{self, Claim, SCHEMA, SCHEMA_VERSION};
use crate::{hash_parts, with_db};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;
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

// ------------------------------------------------------------------------------------------------ facts

fn row_fact(r: &rusqlite::Row) -> rusqlite::Result<(String, Claim)> {
    let text: String = r.get(5)?;
    Ok((r.get(4)?, Claim {
        id: r.get(0)?, rule: Rc::from(r.get::<_, String>(1)?.as_str()), lo: r.get(2)?, hi: r.get(3)?,
        value: serde_json::from_str(&text).unwrap_or(Value::Null), text, support: r.get(6)?, by: r.get(7)?, reason: r.get(8)?,
    }))
}

/// Claims of current runs, optionally of one kind, intersecting [lo, hi), produced by the given rules: (kind,
/// fact), sorted by (lo, hi, kind, value).
pub fn st_facts(path: &str, kind: Option<&str>, lo: Option<i64>, hi: Option<i64>, rules: Option<&[String]>) -> Result<Vec<(String, Rc<Claim>)>> {
    let rules = rules.filter(|r| !r.is_empty());
    if let (Some(kind), None, None) = (kind, lo, hi) {
        let facts = with_db(path, |db| store::claims_of(db, path, kind, rules, |_| true))?;
        return Ok(facts.iter().map(|f| (kind.to_string(), f.clone())).collect());
    }
    let mut q = String::from("SELECT f.id, r.rule, f.lo, f.hi, f.kind, f.value, f.support, f.by, f.reason FROM claim f \n                              JOIN run r ON r.id = f.run_id WHERE r.current=1");
    let mut args: Vec<rusqlite::types::Value> = vec![];
    if let Some(k) = kind {
        q.push_str(" AND f.kind=?");
        args.push(k.to_string().into());
    }
    if let Some(lo) = lo {
        q.push_str(" AND f.hi>?");
        args.push(lo.into());
    }
    if let Some(hi) = hi {
        q.push_str(" AND f.lo<?");
        args.push(hi.into());
    }
    if let Some(rules) = rules {
        q.push_str(&format!(" AND r.rule IN ({})", vec!["?"; rules.len()].join(",")));
        args.extend(rules.iter().map(|r| r.clone().into()));
    }
    q.push_str(" ORDER BY f.lo, f.hi, f.kind, f.value");
    let rows: Vec<(String, Claim)> = with_db(path, |db| {
        let mut st = db.prepare(&q)?;
        let rows = st.query_map(rusqlite::params_from_iter(args.iter()), row_fact)?;
        rows.collect()
    })?;
    Ok(rows.into_iter().map(|(k, f)| (k, Rc::new(f))).collect())
}

/// The fact of a row id (None when there is none): (kind, fact).
#[cfg(test)]
pub fn st_fact(path: &str, fid: i64) -> Result<Option<(String, Claim)>> {
    with_db(path, |db| {
        db.query_row("SELECT f.id, r.rule, f.lo, f.hi, f.kind, f.value, f.support, f.by, f.reason FROM claim f \n                      JOIN run r ON r.id=f.run_id WHERE f.id=?", [fid], row_fact).optional()
    })
}

/// The findings: (severity, check, lo, hi, message, a, b) of current runs (of the given rules), by address.
pub fn st_findings(path: &str, severity: Option<String>, rules: Option<Vec<String>>) -> Result<Vec<(String, String, i64, i64, String, String, String)>> {
    let mut q = String::from("SELECT c.severity, c.check_id, c.lo, c.hi, c.message, c.a, c.b FROM finding c JOIN run r ON r.id=c.run_id \
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

/// Open (or create) the store at path: the tables when the schema version differs; a store of schema 1 (facts,
/// conflicts, the byte map) loses its runs, which every rule recomputes, and keeps what is no rule's output (the
/// compiled units, the analyzer's drafts and other blobs); an error for a store of an unknown schema. The main
/// checkout's store attached when `main` (a file: URI) is given.
pub fn st_open(path: &str, main: &str) -> Result<()> {
    if let Some(d) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(d).map_err(|e| Error::runtime(format!("{path}: {e}")))?;
    }
    let v = with_db(path, |db| {
        let mut v: Option<String> = match db.query_row("SELECT value FROM meta WHERE key='schema'", [], |r| r.get(0)).optional() {
            Ok(v) => v,
            Err(_) => None, // a new store: no meta table yet
        };
        if v.as_deref() == Some("1") {
            db.execute_batch("DROP TABLE IF EXISTS fact; DROP TABLE IF EXISTS conflict; DROP TABLE IF EXISTS bytemap; DELETE FROM run;
                              DELETE FROM meta WHERE key IN ('bytemap', 'schema');")?;
            v = None;
        }
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
pub fn st_close(path: &str) {
    crate::forget_conn(path);
}

pub fn st_meta(path: &str, key: &str) -> Result<Option<String>> {
    with_db(path, |db| db.query_row("SELECT value FROM meta WHERE key=?", [key], |r| r.get(0)).optional())
}

pub fn st_set_meta(path: &str, key: &str, value: &str) -> Result<()> {
    with_db(path, |db| db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", [key, value]).map(|_| ()))
}

pub fn st_main_meta(path: &str, main: &str, key: &str) -> Result<Option<String>> {
    with_db(path, |db| {
        if !ensure_main(db, main)? {
            return Ok(None);
        }
        db.query_row("SELECT value FROM main_store.meta WHERE key=?", [key], |r| r.get(0)).optional()
    })
}

/// (id, input_hash, out_hash) of the rule's current run in this store.
pub fn st_current_run(path: &str, rule: &str) -> Result<Option<(i64, String, String)>> {
    with_db(path, |db| {
        db.query_row("SELECT id, input_hash, out_hash FROM run WHERE rule=? AND current=1", [rule], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).optional()
    })
}

/// A run of this rule with these inputs, in this store or the main store: (where, id, out_hash).
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
pub fn st_make_current(path: &str, main: &str, rule: &str, place: &str, run_id: i64) -> Result<i64> {
    with_db(path, |db| make_current(db, main, rule, place, run_id))
}

pub(crate) fn make_current(db: &Connection, main: &str, rule: &str, place: &str, mut run_id: i64) -> rusqlite::Result<i64> {
    if place == "main_store" {
        ensure_main(db, main)?;
        db.execute("INSERT INTO run (rule, version, code_hash, input_hash, out_hash, ms, at) \
                    SELECT rule, version, code_hash, input_hash, out_hash, ms, at FROM main_store.run WHERE id=?", [run_id])?;
        let new_id = db.last_insert_rowid();
        db.execute("INSERT INTO claim (run_id, lo, hi, kind, value, support, by, reason) \
                    SELECT ?, lo, hi, kind, value, support, by, reason FROM main_store.claim WHERE run_id=?", [new_id, run_id])?;
        db.execute("INSERT INTO finding (run_id, severity, check_id, lo, hi, message, a, b) \
                    SELECT ?, severity, check_id, lo, hi, message, a, b FROM main_store.finding WHERE run_id=?", [new_id, run_id])?;
        run_id = new_id;
    }
    db.execute("UPDATE run SET current=0 WHERE rule=? AND id<>?", params![rule, run_id])?;
    db.execute("UPDATE run SET current=1 WHERE id=?", [run_id])?;
    Ok(run_id)
}

/// The current runs of rules the core no longer has (a rule removed or renamed): no longer current, so that their
/// claims and findings leave the answers and the gate. Returns how many.
pub fn st_retire(path: &str, live: &[&str]) -> Result<usize> {
    with_db(path, |db| {
        let q = format!("UPDATE run SET current=0 WHERE current=1 AND rule NOT IN ({})", vec!["?"; live.len()].join(","));
        db.execute(&q, rusqlite::params_from_iter(live.iter()))
    })
}

/// (facts, ms) of a run.
pub fn st_run_stats(path: &str, run_id: i64) -> Result<(i64, i64)> {
    with_db(path, |db| {
        let n: i64 = db.query_row("SELECT COUNT(*) FROM claim WHERE run_id=?", [run_id], |r| r.get(0))?;
        let ms: i64 = db.query_row("SELECT ms FROM run WHERE id=?", [run_id], |r| r.get(0)).optional()?.unwrap_or(0);
        Ok((n, ms))
    })
}

// ------------------------------------------------------------------------------------------------ blobs

/// Store a blob: content-addressed blobs never change (INSERT OR IGNORE); one keyed by something else is
/// replaced when `replace`.
pub fn st_put_blob(path: &str, hash: &str, kind: &str, data: &[u8], replace: bool) -> Result<()> {
    let verb = if replace { "INSERT OR REPLACE" } else { "INSERT OR IGNORE" };
    with_db(path, |db| db.execute(&format!("{verb} INTO blob (hash, kind, data) VALUES (?, ?, ?)"), params![hash, kind, data]).map(|_| ()))
}

pub fn st_drop_blobs(path: &str, kind: &str) -> Result<()> {
    with_db(path, |db| db.execute("DELETE FROM blob WHERE kind=?", [kind]).map(|_| ()))
}

/// Every blob of one kind, main store first, the overlay's own replacing it: {hash: data}.
#[cfg(test)]
pub fn st_blobs(path: &str, main: &str, kind: &str) -> Result<std::collections::HashMap<String, Vec<u8>>> {
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
    Ok(rows.into_iter().collect())
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

#[cfg(test)]
mod tests {
    /// A store of schema 1 opens as schema 2: its runs are gone (the rules recompute them), what no rule makes stays.
    #[test]
    fn schema_1_store_keeps_its_blobs_and_units() {
        let dir = std::env::temp_dir().join(format!("dcp-schema1-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("old.sqlite").to_string_lossy().into_owned();
        let _ = std::fs::remove_file(&path);
        {
            let c = rusqlite::Connection::open(&path).unwrap();
            c.execute_batch("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT); INSERT INTO meta VALUES ('schema', '1'), ('lint', 'x');
                CREATE TABLE run (id INTEGER PRIMARY KEY, rule TEXT NOT NULL, version TEXT NOT NULL, code_hash TEXT NOT NULL,
                    input_hash TEXT NOT NULL, out_hash TEXT NOT NULL DEFAULT '', current INTEGER NOT NULL DEFAULT 0,
                    ms INTEGER NOT NULL DEFAULT 0, at REAL NOT NULL DEFAULT 0, UNIQUE(rule, input_hash));
                INSERT INTO run (rule, version, code_hash, input_hash, current) VALUES ('S.sections', '1', 'c', 'i', 1);
                CREATE TABLE fact (id INTEGER PRIMARY KEY, run_id INTEGER, lo INTEGER, hi INTEGER, kind TEXT, value TEXT, level INTEGER, by TEXT, reason TEXT);
                CREATE TABLE conflict (id INTEGER PRIMARY KEY, run_id INTEGER);
                CREATE TABLE blob (hash TEXT PRIMARY KEY, kind TEXT NOT NULL, data BLOB NOT NULL);
                INSERT INTO blob VALUES ('h', 'drafts', x'00');").unwrap();
        }
        super::st_open(&path, "").unwrap();
        let (runs, blobs, schema, lint) = crate::with_db(&path, |c| Ok((
            c.query_row("SELECT count(*) FROM run", [], |r| r.get::<_, i64>(0))?,
            c.query_row("SELECT count(*) FROM blob", [], |r| r.get::<_, i64>(0))?,
            c.query_row("SELECT value FROM meta WHERE key='schema'", [], |r| r.get::<_, String>(0))?,
            c.query_row("SELECT value FROM meta WHERE key='lint'", [], |r| r.get::<_, String>(0))?,
        ))).unwrap();
        assert_eq!((runs, blobs, schema.as_str(), lint.as_str()), (0, 1, crate::store::SCHEMA_VERSION, "x"));
        crate::forget_conn(&path);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod tests_retire {
    use crate::rules::testkit::Kit;
    use serde_json::json;

    /// A rule the core no longer has (M8.reloc, folded into G.grade) leaves the current runs: its findings must not
    /// stay in the gate.
    #[test]
    fn retire_runs_of_rules_gone() {
        let k = Kit::new(&crate::pe::testpe::build(None));
        k.put("L.src", &[(0x1000, 0x1001, "name", json!({"name": "f", "origin": "source"}), crate::store::DECLARED)]);
        k.put("M8.reloc", &[(0x1000, 0x1001, "name", json!({"name": "g", "origin": "source"}), crate::store::DECLARED)]);
        let current = || super::st_findings(&k.db, None, None).unwrap().len() + crate::with_db(&k.db, |db| {
            db.query_row("SELECT COUNT(*) FROM run WHERE current=1", [], |r| r.get::<_, i64>(0))
        }).unwrap() as usize;
        assert_eq!(current(), 2);
        assert_eq!(super::st_retire(&k.db, &["L.src", "G.grade"]).unwrap(), 1);
        assert_eq!(current(), 1);
        assert_eq!(super::st_retire(&k.db, &["L.src"]).unwrap(), 0);
    }
}
