//! The derived-state store: one SQLite file per target
//! (build/<target>.sqlite) holding every rule run, its facts and conflicts, content-addressed blobs, the translation
//! units' compile keys, and the materialised byte map. The connection is the core's (the one the native rules
//! use); a worktree's store reads the main checkout's store through an overlay (main_store, read-only).
//!
//! Claims come back as the core's Claim values (store.rs holds the facts of the current runs).

use crate::error::{Error, Result};
use crate::store::{self, py_float, Claim, SCHEMA, SCHEMA_VERSION};
use crate::{hash_parts, with_db};
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

// ------------------------------------------------------------------------------------------------ facts

thread_local! {
    // (store, run id, run time) -> the run holds facts of a kind the byte map is made of
    static MAPS: RefCell<HashMap<(String, i64, u64), bool>> = RefCell::new(HashMap::new());
}

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

/// Store.conflicts: (severity, check, lo, hi, message, a, b) of current runs (of the given rules), by address.
pub fn st_conflicts(path: &str, severity: Option<String>, rules: Option<Vec<String>>) -> Result<Vec<(String, String, i64, i64, String, String, String)>> {
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
pub fn st_blobs(path: &str, main: &str, kind: &str) -> Result<HashMap<String, Vec<u8>>> {
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

// ------------------------------------------------------------------------------------------------ the byte map

type MapRow = (i64, i64, String, store::Support, Option<i64>, Option<i64>, Option<i64>, Option<i64>);

/// The fact of one group that owns each cut, cuts visited in address order: among the facts covering the address
/// the highest support, then the highest lo, then the highest hi (equal keys: the later fact).
struct Sweep {
    items: Vec<Rc<Claim>>,
    i: usize,
    active: Vec<Rc<Claim>>,
}

impl Sweep {
    fn new(mut items: Vec<Rc<Claim>>) -> Sweep {
        items.sort_by_key(|f| (f.lo, f.hi));
        Sweep { items, i: 0, active: vec![] }
    }

    fn at(&mut self, a: i64) -> Option<Rc<Claim>> {
        while self.i < self.items.len() && self.items[self.i].lo <= a {
            self.active.push(self.items[self.i].clone());
            self.i += 1;
        }
        self.active.retain(|f| f.hi > a);
        let mut best: Option<&Rc<Claim>> = None;
        for f in &self.active {
            if best.is_none_or(|b| (f.support, f.lo, f.hi) >= (b.support, b.lo, b.hi)) {
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
                let h = db.query_row("SELECT 1 FROM claim WHERE run_id=? AND kind IN ('section','region','symbol','unit','source') LIMIT 1",
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
    let cur: Option<String> = db.query_row("SELECT value FROM meta WHERE key='answers'", [], |r| r.get(0)).optional()?;
    if cur.as_deref() == Some(h.as_str()) {
        return Ok(h);
    }
    let get = |k: &str| store::claims_of(db, path, k, None, |_| true);
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
        rows.push((a, b, cls, s.support, Some(s.id), u.map(|f| f.id), src.map(|f| f.id), sec.map(|f| f.id)));
    }
    let tx = db.transaction()?;
    tx.execute("DELETE FROM answer", [])?;
    {
        let mut st = tx.prepare("INSERT INTO answer (lo, hi, owner, support, symbol, unit, source, section) VALUES (?,?,?,?,?,?,?,?)")?;
        for r in &rows {
            st.execute(params![r.0, r.1, r.2, r.3, r.4, r.5, r.6, r.7])?;
        }
    }
    tx.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('answers', ?)", [&h])?;
    tx.commit()?;
    Ok(h)
}

#[cfg(test)]
pub fn st_ensure_bytemap(path: &str) -> Result<String> {
    with_db(path, |db| ensure_bytemap(db, path))
}

fn map_row(r: &rusqlite::Row) -> rusqlite::Result<MapRow> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?))
}

/// The byte map row holding addr (the map built first when its facts changed).
pub fn st_bytemap_at(path: &str, addr: i64) -> Result<Option<MapRow>> {
    with_db(path, |db| {
        ensure_bytemap(db, path)?;
        db.query_row("SELECT lo, hi, owner, support, symbol, unit, source, section FROM answer WHERE lo<=? ORDER BY lo DESC LIMIT 1", [addr], map_row)
            .optional()
    })
}

/// The byte map rows intersecting [lo, hi) (the map built first when its facts changed).
pub fn st_bytemap_rows(path: &str, lo: Option<i64>, hi: Option<i64>) -> Result<Vec<MapRow>> {
    with_db(path, |db| bytemap_rows(db, path, lo, hi))
}

pub(crate) fn bytemap_rows(db: &mut Connection, path: &str, lo: Option<i64>, hi: Option<i64>) -> rusqlite::Result<Vec<MapRow>> {
    ensure_bytemap(db, path)?;
    let (lo, hi) = (lo.unwrap_or(i64::MIN), hi.unwrap_or(i64::MAX));
    let mut st = db.prepare_cached("SELECT lo, hi, owner, support, symbol, unit, source, section FROM answer WHERE hi>? AND lo<? ORDER BY lo")?;
    let rows = st.query_map([lo, hi], map_row)?;
    rows.collect()
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
