//! The answers: for every byte of the image and each byte-level question, the value
//! the covering claims agree on at their highest support. Kept as the store's `answer` table: one row per run of
//! bytes with the same answers, naming the claims that give the owner (a symbol or a region), the unit, the H object
//! (the `source` claim) and the section. Made again only when a run holding such claims changed.

use crate::error::Result;
use crate::store::{self, canon_float, Claim, Question, Support};
use crate::{hash_parts, with_db};
use rusqlite::{params, Connection, OptionalExtension};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

/// One run of bytes [lo, hi) with the same answers: the owner (a symbol's skind, `region.<what>` for a region of the
/// format) at its support, and the claims behind each answer (row ids).
#[derive(Clone, Debug)]
pub struct Answer {
    pub lo: i64,
    pub hi: i64,
    pub owner: String,
    pub support: Support,
    pub symbol: Option<i64>,
    pub unit: Option<i64>,
    pub source: Option<i64>,
    pub section: Option<i64>,
}

thread_local! {
    // (store, run id, run time) -> the run holds claims the answers are made of
    static HOLDS: RefCell<HashMap<(String, i64, u64), bool>> = RefCell::new(HashMap::new());
}

/// The claim of one question that answers each cut, cuts visited in address order: among the claims covering the
/// address the highest support, then the highest lo, then the highest hi (equal keys: the later claim).
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

/// The kinds the answer table is made of: the owner's, the unit's and the section's claims.
const KINDS: [&str; 5] = ["section", "region", "symbol", "unit", "source"];

/// Make the answers again when the claims they are made of changed. Returns the hash: of the current runs (id and
/// time) that hold such claims; the rows name claim ids, so a run recorded again changes it although its output is
/// the same.
pub(crate) fn ensure(db: &mut Connection, path: &str) -> rusqlite::Result<String> {
    let runs: Vec<(String, i64, f64)> = {
        let mut st = db.prepare_cached("SELECT rule, id, at FROM run WHERE current=1 ORDER BY rule")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        rows.collect::<Result<_, _>>()?
    };
    let mut parts = vec!["answers.v1".to_string()];
    for (rule, rid, at) in &runs {
        let key = (path.to_string(), *rid, at.to_bits());
        let has = match HOLDS.with(|m| m.borrow().get(&key).copied()) {
            Some(h) => h,
            None => {
                let q = format!("SELECT 1 FROM claim WHERE run_id=? AND kind IN ({}) LIMIT 1",
                                KINDS.iter().map(|k| format!("'{k}'")).collect::<Vec<_>>().join(","));
                let h = db.query_row(&q, [rid], |_| Ok(())).optional()?.is_some();
                HOLDS.with(|m| m.borrow_mut().insert(key, h));
                h
            }
        };
        if has {
            let mut s = format!("{rule}={rid}@");
            canon_float(&mut s, *at);
            parts.push(s);
        }
    }
    let h = hash_parts(parts.into_iter());
    let cur: Option<String> = db.query_row("SELECT value FROM meta WHERE key='answers'", [], |r| r.get(0)).optional()?;
    if cur.as_deref() == Some(h.as_str()) {
        return Ok(h);
    }
    let get = |k: &str| store::claims_of(db, path, k, None, |_| true);
    let mut owners = get("symbol")?;
    owners.extend(get("region")?);
    let (sections, units, sources) = (get("section")?, get("unit")?, get("source")?);
    let mut cuts: Vec<i64> = [&owners, &sections, &units, &sources].iter().flat_map(|g| g.iter().flat_map(|f| [f.lo, f.hi])).collect();
    cuts.sort_unstable();
    cuts.dedup();
    let (mut iown, mut isec, mut iunit, mut isrc) = (Sweep::new(owners), Sweep::new(sections), Sweep::new(units), Sweep::new(sources));
    let mut rows: Vec<Answer> = vec![];
    for w in cuts.windows(2) {
        let (a, b) = (w[0], w[1]);
        let (s, sec, u, src) = (iown.at(a), isec.at(a), iunit.at(a), isrc.at(a));
        let Some(s) = s else { continue };
        // a symbol names its skind, a region (no skind) what it is
        let owner = match (s.value.get("skind"), s.value.get("what")) {
            (Some(k), _) => k.as_str().unwrap_or("").to_string(),
            (None, w) => format!("region.{}", w.and_then(|w| w.as_str()).unwrap_or("")),
        };
        rows.push(Answer { lo: a, hi: b, owner, support: s.support, symbol: Some(s.id), unit: u.map(|f| f.id), source: src.map(|f| f.id),
                           section: sec.map(|f| f.id) });
    }
    let tx = db.transaction()?;
    tx.execute("DELETE FROM answer", [])?;
    {
        let mut st = tx.prepare("INSERT INTO answer (lo, hi, owner, support, symbol, unit, source, section) VALUES (?,?,?,?,?,?,?,?)")?;
        for r in &rows {
            st.execute(params![r.lo, r.hi, r.owner, r.support, r.symbol, r.unit, r.source, r.section])?;
        }
    }
    tx.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('answers', ?)", [&h])?;
    tx.commit()?;
    Ok(h)
}

#[cfg(test)]
pub fn ensure_at(path: &str) -> Result<String> {
    with_db(path, |db| ensure(db, path))
}

fn row(r: &rusqlite::Row) -> rusqlite::Result<Answer> {
    Ok(Answer { lo: r.get(0)?, hi: r.get(1)?, owner: r.get(2)?, support: r.get(3)?, symbol: r.get(4)?, unit: r.get(5)?, source: r.get(6)?,
                section: r.get(7)? })
}

/// The answers at addr (made first when their claims changed).
pub fn at(path: &str, addr: i64) -> Result<Option<Answer>> {
    with_db(path, |db| {
        ensure(db, path)?;
        db.query_row("SELECT lo, hi, owner, support, symbol, unit, source, section FROM answer WHERE lo<=? ORDER BY lo DESC LIMIT 1", [addr], row)
            .optional()
            .map(|a| a.filter(|a| addr < a.hi))
    })
}

/// The answers intersecting [lo, hi) (made first when their claims changed).
pub fn rows(path: &str, lo: Option<i64>, hi: Option<i64>) -> Result<Vec<Answer>> {
    with_db(path, |db| rows_db(db, path, lo, hi))
}

pub(crate) fn rows_db(db: &mut Connection, path: &str, lo: Option<i64>, hi: Option<i64>) -> rusqlite::Result<Vec<Answer>> {
    ensure(db, path)?;
    let (lo, hi) = (lo.unwrap_or(i64::MIN), hi.unwrap_or(i64::MAX));
    let mut st = db.prepare_cached("SELECT lo, hi, owner, support, symbol, unit, source, section FROM answer WHERE hi>? AND lo<? ORDER BY lo")?;
    let rows = st.query_map([lo, hi], row)?;
    rows.collect()
}

/// Every answer at one address, question by question: the claims of each question covering it, highest support
/// first (the first is the answer; the rest stack under it), for `dcp why`.
pub fn stacked(db: &Connection, path: &str, addr: i64) -> Result<Vec<(Question, Vec<(String, Rc<Claim>)>)>> {
    let mut out = vec![];
    for q in Question::ALL {
        let mut cs: Vec<(String, Rc<Claim>)> = vec![];
        for k in q.kinds() {
            let claims = store::claims_of(db, path, k, None, |f| f.lo <= addr && addr < f.hi).map_err(|e| crate::error::Error::runtime(e.to_string()))?;
            cs.extend(claims.into_iter().map(|c| (k.to_string(), c)));
        }
        // the highest support first, then the narrowest
        cs.sort_by(|a, b| b.1.support.cmp(&a.1.support).then((a.1.hi - a.1.lo).cmp(&(b.1.hi - b.1.lo))));
        out.push((q, cs));
    }
    Ok(out)
}
