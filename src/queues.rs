//! The grades as the commands read them (the `grade` facts of G.grade): the queues, the shards, the baseline
//!.
//!
//! Queues (units are the separated game units of L.unit.extent, a unit's functions the grade facts of its
//! functions):
//!   base   every function below shape + readable without a @deep / @stuck tag (a @hard one is base work). Every
//!          code draft comes before any readability-only work: first the draft functions, units with the fewest
//!          drafts first, then the functions at shape / byte that are not readable, units with the fewest such
//!          functions first; address order inside a unit.
//! Tiers (docs/mental-model.md §7): every base item is easy or hard, for workers of different strength. Easy: a
//! readability-only item of an original at most `[queue] easy_read_max_bytes`, or a code draft of an original at
//! most `easy_max_bytes` whose instruction distance is at most `easy_max_dist`. Everything else is hard, and so
//! is every function a worker handed up with @hard (`dcp escalate --hard`), and every deep item.
//!   deep   every function with @deep or @stuck, plus every function below byte + readable of a unit whose base
//!          work is done. Units by the total distance (differing instructions) of their items, smallest first;
//!          inside a unit the closest function first; @stuck functions after everything else. An escalated function
//!          that is byte already and only fails readability (a Q-only item) waits behind its unit's byte work and
//!          is the names queue's.
//!   names  the Q-only deep functions (level deep or stuck, code byte, not readable), the deep queue's unit order.
//! Shards: a unit belongs to the shard k of N with the largest sha1("<unit start>:<k>") (rendezvous hashing).
//!
//! The baseline ledger/grades.tsv: target, address, name, unit, code, readability, level, accepted (a header
//! line; sorted by target in config order, then address).

use crate::error::{Error, Result};
use crate::store;
use crate::with_db;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::rc::Rc;
use sha1::{Digest, Sha1};

const CODE: [&str; 3] = ["draft", "shape", "byte"];
pub const HEADER: &str = "target\taddress\tname\tunit\tcode\treadability\tlevel\taccepted";

fn rank(code: &str) -> Option<usize> {
    CODE.iter().position(|c| *c == code)
}

type Row = Map<String, Value>;

fn s<'a>(r: &'a Row, k: &str) -> &'a str {
    r.get(k).and_then(|v| v.as_str()).unwrap_or("")
}

/// The function grade rows (the value with addr and by), by address.
pub fn function_grades(db: &str) -> Result<Rc<Vec<Row>>> {
    store::derived(db, "grades.function", || function_rows(db))
}

/// One grade row of an object: its experiment (`code`: the outcome, `level`: its @deep / @stuck tag, `failing`)
/// joined with its readability (`readability`, its failing rules appended to `failing`), the experiment's claim at
/// (lo, hi) by producer.
fn grade_rows(db: &str, of: &str) -> Result<Vec<(i64, i64, String, Row)>> {
    let (exps, reads) = with_db(db, |c| Ok((store::claims_of(c, db, "experiment", None, |f| f.s("of") == Some(of))?,
                                            store::claims_of(c, db, "readability", None, |f| f.s("of") == Some(of))?)))?;
    let read: HashMap<(i64, i64), &Rc<store::Claim>> = reads.iter().map(|f| ((f.lo, f.hi), f)).collect();
    Ok(exps.iter().map(|f| {
        let mut m = f.value.as_object().cloned().unwrap_or_default();
        if let Some(o) = m.remove("outcome") {
            m.insert("code".into(), o);
        }
        if let Some(t) = m.remove("tag") {
            m.insert("level".into(), t);
        }
        let r = read.get(&(f.lo, f.hi));
        m.insert("readability".into(), r.and_then(|r| r.value.get("grade").cloned()).unwrap_or(Value::from("draft")));
        if let Some(Value::Array(qf)) = r.and_then(|r| r.value.get("failing")) {
            if let Some(Value::Array(fl)) = m.get_mut("failing") {
                fl.extend(qf.iter().cloned());
            }
        }
        (f.lo, f.hi, f.by.clone(), m)
    }).collect())
}

fn function_rows(db: &str) -> Result<Vec<Row>> {
    let mut out: Vec<Row> = grade_rows(db, "function")?.into_iter().map(|(lo, _, by, mut m)| {
        m.insert("addr".into(), Value::from(lo));
        m.insert("by".into(), Value::String(by));
        m
    }).collect();
    out.sort_by_key(|r| r["addr"].as_i64());
    Ok(out)
}

pub fn unit_grades(db: &str) -> Result<Rc<Vec<Row>>> {
    store::derived(db, "grades.unit", || unit_rows(db))
}

fn unit_rows(db: &str) -> Result<Vec<Row>> {
    let mut out: Vec<Row> = grade_rows(db, "unit")?.into_iter().map(|(lo, hi, _, mut m)| {
        m.insert("lo".into(), Value::from(lo));
        m.insert("hi".into(), Value::from(hi));
        m
    }).collect();
    out.sort_by_key(|r| r["lo"].as_i64());
    Ok(out)
}

/// The game units of L.unit.extent: (tu, lo, status), by address.
fn game_units(db: &str) -> Result<Vec<(String, i64, String)>> {
    let facts = with_db(db, |c| store::claims_of(c, db, "unit", None, |f| f.value.get("status").is_some()))?;
    let mut out: Vec<(String, i64, String)> = facts.iter().map(|f| (f.s("tu").unwrap_or("").into(), f.lo, f.s("status").unwrap_or("").into())).collect();
    out.sort_by_key(|u| u.1);
    Ok(out)
}

fn below_shape(r: &Row) -> bool {
    s(r, "code") == "draft" || s(r, "readability") != "readable"
}

fn below_byte(r: &Row) -> bool {
    s(r, "code") != "byte" || s(r, "readability") != "readable"
}

fn q_only(r: &Row) -> bool {
    matches!(s(r, "level"), "deep" | "stuck") && s(r, "code") == "byte" && s(r, "readability") != "readable"
}

/// A @deep or @stuck tag: the function left the base queue (a @hard one did not).
fn has_level(r: &Row) -> bool {
    r.get("level").is_some_and(|v| !matches!(v, Value::Null) && v.as_str() != Some("") && v.as_str() != Some("hard") && v.as_bool() != Some(false))
}

fn dist(r: &Row) -> i64 {
    r.get("dist").and_then(|d| d.get("ins")).and_then(|v| v.as_i64()).unwrap_or(0)
}

/// The bounds of the easy tier (`[queue]` of the configuration, module docstring).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tiers {
    pub max_bytes: i64,
    pub max_dist: i64,
    pub read_max_bytes: i64,
}

impl Default for Tiers {
    /// First guesses, to be tuned against the wraps' tier lines: a short function whose draft is already close, or
    /// the naming and typing of a function of up to 1 KiB.
    fn default() -> Tiers {
        Tiers { max_bytes: 256, max_dist: 24, read_max_bytes: 1024 }
    }
}

/// The tier of a queue item: "easy" or "hard" (module docstring).
pub fn tier(r: &Row, t: &Tiers) -> &'static str {
    let orig = r.get("dist").and_then(|d| d.get("orig")).and_then(|v| v.as_i64());
    let easy = s(r, "level") != "hard" && match (s(r, "section"), orig) {
        ("read", Some(o)) => o <= t.read_max_bytes,
        ("draft", Some(o)) => o <= t.max_bytes && r.get("dist").and_then(|d| d.get("ins")).and_then(|v| v.as_i64()).is_none_or(|d| d <= t.max_dist),
        _ => false,
    };
    if easy { "easy" } else { "hard" }
}

/// The shard of a unit among n: rendezvous hashing of its start address.
pub fn shard_owner(start: i64, n: i64) -> i64 {
    let mut best: Option<(Vec<u8>, i64)> = None;
    for k in 0..n {
        let d = Sha1::digest(format!("{start:#010x}:{k}").as_bytes()).to_vec();
        if best.as_ref().is_none_or(|(b, _)| d > *b) {
            best = Some((d, k));
        }
    }
    best.map(|b| b.1).unwrap_or(0)
}

fn tagged(r: &Row, unit: &str, section: &str) -> Row {
    let mut m = r.clone();
    m.insert("queue_unit".into(), Value::String(unit.into()));
    m.insert("section".into(), Value::String(section.into()));
    m
}

/// The items of the base / deep / names queue in order (module docstring).
pub fn queue(db: &str, which: &str, shard: Option<(i64, i64)>, unit: Option<&str>) -> Result<Rc<Vec<Row>>> {
    store::derived(db, &format!("queue {which} {shard:?} {unit:?}"), || queue_rows(db, which, shard, unit))
}

fn queue_rows(db: &str, which: &str, shard: Option<(i64, i64)>, unit: Option<&str>) -> Result<Vec<Row>> {
    let rows = function_grades(db)?;
    let mut by_unit: Vec<(String, Vec<&Row>)> = vec![];
    // a function not run (its unit has no object) is no work item: M.compile is
    for r in rows.iter().filter(|r| s(r, "code") != crate::grade::NOT_RUN) {
        let u = s(r, "unit");
        match by_unit.iter_mut().find(|x| x.0 == u) {
            Some(x) => x.1.push(r),
            None => by_unit.push((u.to_string(), vec![r])),
        }
    }
    let of = |tu: &str| by_unit.iter().find(|x| x.0 == tu).map(|x| x.1.clone());
    let mut units: Vec<(String, i64, String)> = game_units(db)?.into_iter().filter(|u| u.2 == "separated" && of(&u.0).is_some()).collect();
    if let Some(name) = unit {
        units.retain(|u| u.0 == name);
    } else if let Some((k, n)) = shard {
        units.retain(|u| shard_owner(u.1, n) == k);
    }
    if which == "base" {
        let (mut drafts, mut reads): (Vec<(usize, i64, Vec<Row>)>, Vec<(usize, i64, Vec<Row>)>) = (vec![], vec![]);
        for (tu, lo, _) in &units {
            let base: Vec<&Row> = of(tu).unwrap().into_iter().filter(|r| below_shape(r) && !has_level(r)).collect();
            let d: Vec<Row> = base.iter().filter(|r| s(r, "code") == "draft").map(|r| tagged(r, tu, "draft")).collect();
            let rd: Vec<Row> = base.iter().filter(|r| s(r, "code") != "draft").map(|r| tagged(r, tu, "read")).collect();
            if !d.is_empty() {
                drafts.push((d.len(), *lo, d));
            }
            if !rd.is_empty() {
                reads.push((rd.len(), *lo, rd));
            }
        }
        drafts.sort_by_key(|x| (x.0, x.1));
        reads.sort_by_key(|x| (x.0, x.1));
        return Ok(drafts.into_iter().chain(reads).flat_map(|x| x.2).collect());
    }
    let mut per: Vec<(i64, i64, i64, Vec<Row>)> = vec![];
    for (tu, lo, _) in &units {
        let rs = of(tu).unwrap();
        let base_left = rs.iter().any(|r| below_shape(r) && !has_level(r));
        let all: Vec<&Row> = rs.iter().copied().filter(|r| matches!(s(r, "level"), "deep" | "stuck") || (!base_left && below_byte(r))).collect();
        let byte_items: Vec<&Row> = all.iter().copied().filter(|r| !q_only(r)).collect();
        let mut items: Vec<&Row> = if which == "names" {
            all.iter().copied().filter(|r| q_only(r)).collect()
        } else if !byte_items.is_empty() {
            byte_items.clone()
        } else {
            all.iter().copied().filter(|r| q_only(r)).collect()
        };
        items.sort_by_key(|r| (dist(r), r["addr"].as_i64()));
        if !items.is_empty() {
            let tagged_items = items.iter().map(|r| tagged(r, tu, if s(r, "level") == "stuck" { "stuck" } else { "deep" })).collect();
            per.push((if byte_items.is_empty() { 1 } else { 0 }, byte_items.iter().map(|r| dist(r)).sum(), *lo, tagged_items));
        }
    }
    per.sort_by_key(|x| (x.0, x.1, x.2));
    let flat: Vec<Row> = per.into_iter().flat_map(|x| x.3).collect();
    let (stuck, rest): (Vec<Row>, Vec<Row>) = flat.into_iter().partition(|r| s(r, "section") == "stuck");
    Ok(rest.into_iter().chain(stuck).collect())
}

/// 'k/N' -> (k, N); 'off' -> None.
pub fn parse_shard(text: &str) -> Result<Option<(i64, i64)>, String> {
    let t = text.trim();
    if t == "off" {
        return Ok(None);
    }
    let bad = || format!("a shard is k/N with 0 <= k < N (or off), not {}", crate::decl::py_repr(t));
    let (k, n) = t.split_once('/').ok_or_else(bad)?;
    let digits = |x: &str| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit());
    if !digits(k) || !digits(n) {
        return Err(bad());
    }
    let (k, n): (i64, i64) = (k.parse().map_err(|_| bad())?, n.parse().map_err(|_| bad())?);
    if !(0 <= k && k < n) {
        return Err(bad());
    }
    Ok(Some((k, n)))
}

/// True when every clause of the reason (split at `;` `,` `.` and the word `and`) speaks of missing or unwritten
/// statements, bodies, calls, branches, loops, cases, code or lines: reconstruction is base work.
pub fn only_missing_statements(reason: &str) -> bool {
    use std::sync::LazyLock;
    static SPLIT: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"[;,.]|\band\b").unwrap());
    static MISSING: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(?i)\b(missing|absent|lacks?|lacking|reconstruct\w*|unwritten|not\s+(?:yet\s+)?written|add(?:ed)?)\b").unwrap()
    });
    static STATEMENTS: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(?i)\b(statements?|bod(?:y|ies)|calls?|branch(?:es)?|loops?|cases?|code|lines?)\b").unwrap()
    });
    let clauses: Vec<&str> = SPLIT.split(reason).map(|c| c.trim()).filter(|c| !c.is_empty()).collect();
    !clauses.is_empty() && clauses.iter().all(|c| MISSING.is_match(c) && STATEMENTS.is_match(c))
}

/// The words of a reason that admit a part of the function not read against the original yet (not reconciled, not
/// checked, not compared, not verified, hard to judge): reading the whole function is base work. A word for what the
/// code does (`the parameter is not read`, `cm_SendUnchecked`) is no admission: only these phrasings count.
pub fn admits_unread(reason: &str) -> Option<String> {
    use std::sync::LazyLock;
    static UNREAD: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(?i)\b(un(?:reconciled|checked|verified|examined|compared)|not\s+(?:yet\s+|been\s+|fully\s+)*(?:reconciled|checked|verified|examined|compared)|not\s+yet\s+(?:read|looked\s+at)|(?:did|could|have|has)\s+not\s+(?:yet\s+)?(?:read|check|compare|reconcile)|left\s+unread|unread\s+(?:part|rest|tail|span|half|code|hunks?)|hard\s+to\s+judge)\b").unwrap()
    });
    UNREAD.find(reason).map(|m| m.as_str().split_whitespace().collect::<Vec<_>>().join(" "))
}

// ------------------------------------------------------------------------------------------------ the baseline

/// One baseline entry: name, unit, code, readability, level, accepted.
#[derive(Clone, Default)]
pub struct Entry {
    pub name: String,
    pub unit: String,
    pub code: String,
    pub readability: String,
    pub level: String,
    pub accepted: String,
}

/// (target, address) -> entry of a ledger/grades.tsv text, in file order (a later line of one key replaces the
/// earlier one in its place).
pub fn parse_baseline(text: &str) -> Vec<((String, i64), Entry)> {
    let mut out: Vec<((String, i64), Entry)> = vec![];
    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') || line.starts_with("target\t") {
            continue;
        }
        let mut f: Vec<&str> = line.split('\t').collect();
        while f.len() < 8 {
            f.push("");
        }
        let Some(a) = crate::layout::py_int16(f[1]) else { continue };
        let e = Entry { name: f[2].into(), unit: f[3].into(), code: f[4].into(), readability: f[5].into(), level: f[6].into(), accepted: f[7].into() };
        let key = (f[0].to_string(), a);
        match out.iter_mut().find(|x| x.0 == key) {
            Some(x) => x.1 = e,
            None => out.push((key, e)),
        }
    }
    out
}

/// What fell from a baseline entry to the current grade (None: the function has no grade any more).
pub fn falls(base: &Entry, now: Option<(&str, &str)>) -> Vec<String> {
    let Some((code, readability)) = now else {
        return vec![format!("graded {} + {} in the baseline, no grade now (its source is gone?)", base.code, base.readability)];
    };
    let mut out = vec![];
    if let (Some(b), Some(n)) = (rank(&base.code), rank(code)) {
        if n < b {
            out.push(format!("code {} -> {code}", base.code));
        }
    }
    if base.readability == "readable" && readability != "readable" {
        out.push("readability readable -> draft".into());
    }
    out
}

fn grade_of(code: &str, readability: &str) -> String {
    format!("{code}+{readability}")
}

/// A grade row at or above `code+readability` in both dimensions.
pub fn at_least(code: &str, readability: &str, grade: &str) -> bool {
    let (gc, gr) = grade.split_once('+').unwrap_or((grade, ""));
    rank(code).map(|x| x as i64).unwrap_or(-1) >= rank(gc).map(|x| x as i64).unwrap_or(-1) && (gr != "readable" || readability == "readable")
}

/// The accepted column, a debt item (docs/mental-model.md §8.6): `byte+readable -> shape+readable at 897b411: why`,
/// with ` [waits for: what]` when it names what it waits for (whitespace runs as one space). The commit is the last
/// witness: the source that reproduced the higher grade.
pub fn accept_note(before: &str, after: &str, commit: &str, why: &str) -> String {
    format!("{before} -> {after} at {commit}: {}", why.split_whitespace().collect::<Vec<_>>().join(" "))
}

/// A debt item's note with what it waits for.
pub fn debt_note(before: &str, after: &str, commit: &str, why: &str, waits_for: &str) -> String {
    let w = waits_for.split_whitespace().collect::<Vec<_>>().join(" ");
    let note = accept_note(before, after, commit, why);
    if w.is_empty() { note } else { format!("{note} [waits for: {w}]") }
}

static ACCEPTED: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"^(\w+\+\w+) -> (\w+\+\w+) at (\S+): (.*?)(?: \[waits for: (.*)\])?$").unwrap());

/// The grade an accepted fall came from (None for an empty or unreadable column).
pub fn note_from(note: &str) -> Option<String> {
    ACCEPTED.captures(note).map(|c| c[1].to_string())
}

/// One debt item of the baseline: a declared regression with its last witness.
#[derive(Clone, Debug, PartialEq)]
pub struct Debt {
    pub target: String,
    pub addr: i64,
    pub name: String,
    pub was: String,
    pub now: String,
    /// the commit whose source reproduced `was`
    pub witness: String,
    pub why: String,
    pub waits_for: String,
}

/// The debt items of a baseline text, in file order (an accepted column that does not parse is listed with its text
/// as the reason).
pub fn debts(text: &str) -> Vec<Debt> {
    parse_baseline(text).into_iter().filter(|x| !x.1.accepted.is_empty()).map(|((t, a), e)| match ACCEPTED.captures(&e.accepted) {
        Some(c) => Debt { target: t, addr: a, name: e.name.clone(), was: c[1].into(), now: c[2].into(), witness: c[3].into(), why: c[4].into(),
                          waits_for: c.get(5).map(|m| m.as_str().to_string()).unwrap_or_default() },
        None => Debt { target: t, addr: a, name: e.name.clone(), was: String::new(), now: grade_of(&e.code, &e.readability), witness: String::new(),
                       why: e.accepted.clone(), waits_for: String::new() },
    }).collect()
}

fn render(rows: &[(String, i64, Entry)]) -> String {
    let mut out = String::from(HEADER);
    out.push('\n');
    for (t, a, r) in rows {
        out.push_str(&[t.as_str(), &format!("{a:#010x}"), &r.name, &r.unit, &r.code, &r.readability, &r.level, &r.accepted].join("\t"));
        out.push('\n');
    }
    out
}

fn entry_of(r: &Row) -> Entry {
    let level = match r.get("level") {
        Some(Value::String(x)) => x.clone(),
        _ => String::new(),
    };
    Entry { name: s(r, "name").into(), unit: s(r, "unit").into(), code: s(r, "code").into(), readability: s(r, "readability").into(), level,
            accepted: String::new() }
}

/// ledger/grades.tsv from the current grades of every target ((name, store) in config order). An accepted column
/// of the old text is kept while the function stays below the grade it fell from; with accept_falls every fall
/// against the old text is written with a note `.. at COMMIT: promote --accept-falls`.
pub fn baseline_text(targets: &[(String, String)], old: &str, accept_falls: bool, commit: &str) -> Result<String> {
    let base = parse_baseline(old);
    let mut rows = vec![];
    for (t, db) in targets {
        for r in function_grades(db)?.iter() {
            let a = r["addr"].as_i64().unwrap_or(0);
            let mut e = entry_of(&r);
            if let Some((_, o)) = base.iter().find(|x| x.0 .0 == *t && x.0 .1 == a) {
                let src = note_from(&o.accepted);
                if let Some(g) = &src {
                    if !at_least(&e.code, &e.readability, g) {
                        e.accepted = o.accepted.clone();
                    }
                }
                if accept_falls && !falls(o, Some((&e.code, &e.readability))).is_empty() {
                    e.accepted = accept_note(&src.unwrap_or_else(|| grade_of(&o.code, &o.readability)), &grade_of(&e.code, &e.readability), commit,
                                             "promote --accept-falls");
                }
            }
            rows.push((t.clone(), a, e));
        }
    }
    Ok(render(&rows))
}

/// The functions of a target's grades whose experiment did not run (their unit has no object): (unit, count).
pub fn not_run(db: &str) -> Result<Vec<(String, usize)>> {
    let mut out: Vec<(String, usize)> = vec![];
    for r in function_grades(db)?.iter().filter(|r| s(r, "code") == crate::grade::NOT_RUN) {
        match out.iter_mut().find(|x| x.0 == s(r, "unit")) {
            Some(x) => x.1 += 1,
            None => out.push((s(r, "unit").to_string(), 1)),
        }
    }
    Ok(out)
}

/// The falls of a target's function grades against a baseline text.
pub fn regressions(target: &str, db: &str, text: &str) -> Result<Vec<String>> {
    let mut base: Vec<(i64, Entry)> = parse_baseline(text).into_iter().filter(|x| x.0 .0 == target).map(|x| (x.0 .1, x.1)).collect();
    base.sort_by_key(|x| x.0);
    let now: std::collections::HashMap<i64, Row> = function_grades(db)?.iter().cloned().map(|r| (r["addr"].as_i64().unwrap_or(0), r)).collect();
    let mut out = vec![];
    for (a, r) in base {
        let n = now.get(&a).map(|x| (s(x, "code"), s(x, "readability")));
        for what in falls(&r, n) {
            out.push(format!("{a:#010x} {}: {what}", r.name));
        }
    }
    Ok(out)
}

/// git's answer in a checkout, '' when git fails.
fn git(root: &str, args: &[&str]) -> String {
    match std::process::Command::new("git").args(args).current_dir(root).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        _ => String::new(),
    }
}

// ------------------------------------------------------------------------------------------------ the baseline ledger

/// The baseline text with one function's entry lowered to code + readability and its accepted column set.
pub fn grades_accept(text: &str, target: &str, addr: i64, code: &str, readability: &str, note: &str) -> String {
    let rows: Vec<(String, i64, Entry)> = parse_baseline(text).into_iter().map(|((t, a), mut e)| {
        if t == target && a == addr {
            e.code = code.into();
            e.readability = readability.into();
            e.accepted = note.into();
        }
        (t, a, e)
    }).collect();
    render(&rows)
}

pub fn grades_regressions(target: &str, db: &str, text: &str) -> Result<Vec<String>> {
    regressions(target, db, text)
}

/// The short hash of HEAD ('-' outside a git checkout).
pub fn grades_commit_of(root: &str) -> String {
    let h = git(root, &["rev-parse", "--short", "HEAD"]).trim().to_string();
    if h.is_empty() { "-".into() } else { h }
}

/// ledger/grades.tsv at a git revision ('' when it has none).
pub fn grades_baseline_at(root: &str, rev: &str) -> String {
    git(root, &["show", &format!("{rev}:ledger/grades.tsv")])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_order() {
        use crate::rules::testkit::Kit;
        use serde_json::json;
        let k = Kit::new(&crate::pe::testpe::build(None));
        let units = [("a", 0x1000, 0x2000, "separated"), ("b", 0x2000, 0x3000, "separated"), ("c", 0x3000, 0x4000, "separated"), ("open", 0x4000, 0x5000, "open")];
        let uf: Vec<(i64, i64, &str, Value, crate::store::Support)> = units.iter().map(|&(tu, lo, hi, status)| {
            (lo, hi, "unit", json!({"tu": tu, "status": status, "start_support": "declared", "end_support": "declared", "start_by": "x", "end_by": "y"}), crate::store::DECLARED)
        }).collect();
        let funcs = [(0x1000, "a1", "a", "draft", "draft", "", 9), (0x1100, "a2", "a", "draft", "readable", "", 3), (0x1200, "a3", "a", "shape", "draft", "", 2),
                     (0x1300, "a4", "a", "draft", "draft", "hard", 5),
                     (0x2000, "b1", "b", "draft", "draft", "", 50), (0x2100, "b2", "b", "byte", "readable", "", 0),
                     (0x3000, "c1", "c", "shape", "readable", "", 7), (0x3100, "c2", "c", "byte", "draft", "deep", 0),
                     (0x3200, "c3", "c", "draft", "draft", "stuck", 4), (0x4000, "o1", "open", "draft", "draft", "", 1)];
        let gf: Vec<(i64, i64, &str, Value, crate::store::Support)> = funcs.iter().flat_map(|&(a, n, u, code, q, lvl, d)| [
            (a, a + 1, "experiment", json!({"of": "function", "name": n, "unit": u, "file": format!("src/{u}.c"), "outcome": code, "tag": lvl,
                                            "failing": [], "dist": {"ins": d, "bytes": d, "size": 1, "orig": 1}}), crate::store::DECLARED),
            (a, a + 1, "readability", json!({"of": "function", "name": n, "unit": u, "file": format!("src/{u}.c"), "grade": q, "failing": []}),
             crate::store::DECLARED),
        ]).collect();
        k.put("L.unit.extent", &uf);
        k.put("G.grade", &gf);
        let names = |which: &str, shard: Option<(i64, i64)>| -> Vec<(String, String)> {
            queue(&k.db, which, shard, None).unwrap().iter().map(|r| (s(r, "name").to_string(), s(r, "section").to_string())).collect()
        };
        let pairs = |v: &[(&str, &str)]| -> Vec<(String, String)> { v.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect() };
        // every code draft first (unit b has 1 draft, a has 3: a @hard one stays base work), then the readability
        // work; the open unit is left out
        assert_eq!(names("base", None), pairs(&[("b1", "draft"), ("a1", "draft"), ("a2", "draft"), ("a4", "draft"), ("a3", "read")]));
        // c has no base item left: its byte work (c1) first, the Q-only c2 waits, the stuck c3 last
        assert_eq!(names("deep", None), pairs(&[("c1", "deep"), ("c3", "stuck")]));
        assert_eq!(names("names", None).iter().map(|x| x.0.as_str()).collect::<Vec<_>>(), ["c2"]);
        let mut got: Vec<String> = (0..2).flat_map(|i| names("base", Some((i, 2)))).map(|x| x.0).collect();
        got.sort();
        let mut all: Vec<String> = names("base", None).into_iter().map(|x| x.0).collect();
        all.sort();
        assert_eq!(got, all);
    }

    #[test]
    fn tiers() {
        let t = Tiers { max_bytes: 100, max_dist: 10, read_max_bytes: 400 };
        let row = |section: &str, level: &str, orig: Option<i64>, ins: Option<i64>| -> Row {
            serde_json::json!({"section": section, "level": level, "dist": {"orig": orig, "ins": ins}}).as_object().unwrap().clone()
        };
        // a short draft already close is easy; too long, too far or of unknown size is hard
        assert_eq!(tier(&row("draft", "", Some(100), Some(10)), &t), "easy");
        assert_eq!(tier(&row("draft", "", Some(101), Some(0)), &t), "hard");
        assert_eq!(tier(&row("draft", "", Some(60), Some(11)), &t), "hard");
        assert_eq!(tier(&row("draft", "", None, None), &t), "hard");
        // a draft without an object (no distance) is judged by its size alone
        assert_eq!(tier(&row("draft", "", Some(60), None), &t), "easy");
        // readability-only work up to its own bound
        assert_eq!(tier(&row("read", "", Some(400), Some(90)), &t), "easy");
        assert_eq!(tier(&row("read", "", Some(401), Some(0)), &t), "hard");
        // a function handed up with @hard is hard whatever its size
        assert_eq!(tier(&row("draft", "hard", Some(10), Some(0)), &t), "hard");
    }

    #[test]
    fn debt_items() {
        // a debt item names the grade before, the witness, why and (when given) what it waits for
        let a = debt_note("byte+readable", "shape+readable", "abc1234", "a tie\tbreak", " the net\nheader ");
        assert_eq!(a, "byte+readable -> shape+readable at abc1234: a tie break [waits for: the net header]");
        assert_eq!(note_from(&a).as_deref(), Some("byte+readable"));
        let b = debt_note("shape+draft", "draft+draft", "def5678", "older", "");
        let text = format!("{HEADER}\nt\t0x10001000\tf\tu\tshape\treadable\t\t{a}\nt\t0x10001010\tg\tu\tdraft\tdraft\t\t{b}\nt\t0x10001020\th\tu\tbyte\treadable\t\t\n");
        let d = debts(&text);
        assert_eq!(d.len(), 2);
        assert_eq!((d[0].name.as_str(), d[0].was.as_str(), d[0].now.as_str(), d[0].witness.as_str(), d[0].why.as_str(), d[0].waits_for.as_str()),
                   ("f", "byte+readable", "shape+readable", "abc1234", "a tie break", "the net header"));
        assert_eq!((d[1].why.as_str(), d[1].waits_for.as_str()), ("older", ""));
    }

    #[test]
    fn m1_lists_debt_and_bounds_it() {
        use crate::rules::testkit::Kit;
        use serde_json::json;
        let k = Kit::new(&crate::pe::testpe::build(None));
        let a = debt_note("byte+readable", "draft+readable", "abc1234", "tie-break", "the header");
        std::fs::create_dir_all(k.dir.join("ledger")).unwrap();
        std::fs::write(k.dir.join("ledger").join("grades.tsv"), format!("{HEADER}\nt\t0x10001000\tf\tu\tdraft\treadable\t\t{a}\n")).unwrap();
        k.put("G.grade", &[(0x10001000, 0x10001001, "experiment", json!({"of": "function", "name": "f", "outcome": "draft"}), crate::store::DECLARED),
                           (0x10001000, 0x10001001, "readability", json!({"of": "function", "name": "f", "grade": "readable"}), crate::store::DECLARED)]);
        let run = |max: i64| k.run("M1.baseline", &["G.grade"], &format!(r#"{{"target": "t", "max_debt": {max}, "code_rank": {{"draft": 0, "shape": 1, "byte": 2}}}}"#)).1;
        let f = run(20);
        assert_eq!(f.iter().map(|x| (x.severity.as_str(), x.check.as_str())).collect::<Vec<_>>(), [("warn", "M1.debt")]);
        assert!(f[0].message.contains("debt byte+readable -> draft+readable, witness abc1234: tie-break; waits for the header"), "{}", f[0].message);
        assert!(run(0).iter().any(|x| x.severity == "error" && x.check == "M1.debt"));
    }

    #[test]
    fn m1_counts_functions_not_run_per_unit() {
        // a unit without an object: its baseline functions are not run (open), one M1 line for the unit, no falls
        use crate::rules::testkit::Kit;
        use serde_json::json;
        let k = Kit::new(&crate::pe::testpe::build(None));
        std::fs::create_dir_all(k.dir.join("ledger")).unwrap();
        std::fs::write(k.dir.join("ledger").join("grades.tsv"),
                       format!("{HEADER}
t	0x10001000	f	u	byte	readable		
t	0x10001010	g	u	shape	readable		
")).unwrap();
        let open = |a: i64, n: &str| (a, a + 1, "experiment", json!({"of": "function", "name": n, "unit": "u", "outcome": "open"}), crate::store::DECLARED);
        k.put("G.grade", &[open(0x10001000, "f"), open(0x10001010, "g"),
                           (0x10001000, 0x10001001, "readability", json!({"of": "function", "name": "f", "grade": "draft"}), crate::store::DECLARED)]);
        let f = k.run("M1.baseline", &["G.grade"], r#"{"target": "t", "max_debt": -1, "code_rank": {"draft": 0, "shape": 1, "byte": 2}}"#).1;
        assert_eq!(f.len(), 1, "{:?}", f.iter().map(|x| &x.message).collect::<Vec<_>>());
        assert!(f[0].check == "M1" && f[0].lo == 0x10001000 && f[0].message.starts_with("unit u has no object (M.compile): 2 baseline function(s)"),
                "{}", f[0].message);
    }

    #[test]
    fn accepted_column() {
        // an old 7-column file parses (empty accepted column); accept lowers one entry and notes it, every other line stays
        let old = "target\taddress\tname\tunit\tcode\treadability\tlevel\nt\t0x10001000\tf\tu\tbyte\treadable\t\nt\t0x10001010\tg\tu\tshape\tdraft\tdeep\n";
        assert_eq!(parse_baseline(old)[0].1.accepted, "");
        let note = accept_note("byte+readable", "shape+readable", "abc1234", "a VC6\tdeclaration-set\ntie-break");
        assert_eq!(note, "byte+readable -> shape+readable at abc1234: a VC6 declaration-set tie-break");
        let new = grades_accept(old, "t", 0x10001000, "shape", "readable", &note);
        assert_eq!(new, format!("{HEADER}\nt\t0x10001000\tf\tu\tshape\treadable\t\t{note}\nt\t0x10001010\tg\tu\tshape\tdraft\tdeep\t\n"));
        let b = &parse_baseline(&new)[0].1;
        assert_eq!((b.code.as_str(), b.accepted.as_str()), ("shape", note.as_str()));
        assert!(falls(b, Some(("shape", "readable"))).is_empty()); // M1 holds it at shape
        assert_eq!(falls(b, Some(("draft", "readable"))), ["code shape -> draft"]);
        assert!(falls(&parse_baseline(old)[1].1, Some(("byte", "draft"))).is_empty());
        assert!(at_least("byte", "readable", "byte+readable") && !at_least("shape", "readable", "byte+readable") && !at_least("byte", "draft", "shape+readable"));
    }

    #[test]
    fn shards_baseline_and_reasons() {
        assert_eq!(parse_shard("1/3").unwrap(), Some((1, 3)));
        assert_eq!(parse_shard("off").unwrap(), None);
        assert!(parse_shard("3/3").is_err() && parse_shard("x").is_err());
        let owners: Vec<i64> = (0..20).map(|i| shard_owner(0x401000 + i * 0x100, 4)).collect();
        assert!(owners.iter().all(|&k| (0..4).contains(&k)) && owners.iter().any(|&k| k != owners[0]));
        let text = format!("{HEADER}\nexe\t0x00401000\tf\tbio\tbyte\treadable\t\t\nexe\t0x00401040\tg\tbio\tshape\tdraft\tdeep\n");
        let b = parse_baseline(&text);
        assert_eq!(b.len(), 2);
        assert_eq!(b[1].1.level, "deep");
        assert_eq!(falls(&b[0].1, Some(("shape", "readable"))), ["code byte -> shape"]);
        assert!(falls(&b[0].1, None)[0].contains("no grade now"));
        assert!(at_least("byte", "readable", "shape+readable") && !at_least("shape", "draft", "shape+readable"));
        let n = accept_note("byte+readable", "shape+readable", "897b411", "a\tb\n c");
        assert_eq!(n, "byte+readable -> shape+readable at 897b411: a b c");
        assert_eq!(note_from(&n).as_deref(), Some("byte+readable"));
        assert!(only_missing_statements("missing calls; the loop body is not yet written"));
        assert!(!only_missing_statements("register allocation differs"));
    }
}

// ------------------------------------------------------------------------------------------------ the level ladder

/// Write `@<level> reason` into the address comment of a function (the comment that starts on `line` of `rel`),
/// replacing a @deep, @stuck or @hard tag already there; no level removes it. What was done.
pub fn set_level(root: &str, rel: &str, level: Option<&str>, reason: Option<&str>, line: i64) -> Result<String, String> {
    use std::sync::LazyLock;
    // the tag and its reason run to the end of the comment (written last, below): a reason may hold `*`, `/`, `(...)`
    // and line breaks
    static TAG: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(?:\A|\s)\s*@(deep|stuck|hard)\b").unwrap());
    let path = crate::project::py_path(&format!("{root}/{rel}"));
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?.replace("\r\n", "\n");
    let src = crate::readability::Source::new(&text);
    let tx = &src.text;
    let own = |cs: usize| tx[..cs].iter().rposition(|&c| c == '\n').map(|i| i + 1).unwrap_or(0);
    let c = src.comments.iter().find(|(cs, _, _)| src.line_of(*cs) as i64 == line && tx[own(*cs)..*cs].iter().all(|c| crate::srcscan::py_space(*c)));
    let Some((cs, ce, body)) = c.filter(|c| !crate::srcscan::lead_addrs(&c.2).0.is_empty() || crate::srcscan::UNLINKED.is_match(&c.2)) else {
        return Err(format!("{rel}:{line}: no function's address comment there"));
    };
    let raw: String = tx[*cs..*ce].iter().collect();
    let tag = TAG.captures(body);
    let old = tag.as_ref().map(|c| format!("@{}", &c[1]));
    let cut = tag.as_ref().and_then(|c| c.get(0)).map(|m| m.start()).unwrap_or(body.len());
    let stripped = body[..cut].trim_end_matches(crate::srcscan::py_space).to_string();
    let (new_body, action) = match level {
        None => match old {
            None => return Ok("no @deep, @stuck or @hard tag".into()),
            Some(o) => (stripped, format!("{o} removed")),
        },
        Some(l) => {
            let reason = crate::srcscan::py_strip(&reason.unwrap_or("").replace("*/", "* /")).to_string();
            let action = match old {
                None => format!("@{l} added"),
                Some(o) if o == format!("@{l}") => format!("@{l} reason replaced"),
                Some(o) => format!("{o} -> @{l}"),
            };
            let tag = format!("@{l} {reason}");
            let body = if raw.starts_with("/*") { wrap_tag(&stripped, *cs - own(*cs), &tag) } else { format!("{stripped} {tag}") };
            (body, action)
        }
    };
    let new_raw = if raw.starts_with("/*") { format!("/*{new_body} */") } else { format!("//{new_body}") };
    let out: String = tx[..*cs].iter().collect::<String>() + &new_raw + &tx[*ce..].iter().collect::<String>();
    crate::edit::write(&path, &out)?;
    Ok(action)
}

/// The column a level tag's comment is wrapped at.
const TAG_WIDTH: usize = 110;

/// A `/* ... */` comment body (`body`, the comment starting at column `col`) with the level tag appended: on its
/// last line when it fits within TAG_WIDTH (with the closing ` */`), else on lines of its own below, indented 3
/// past the comment's start and wrapped at TAG_WIDTH (a match-base report: each escalation grew one line of the
/// comment, in txt.c to a single line of 600 characters). The reason's own line breaks are not kept.
fn wrap_tag(body: &str, col: usize, tag: &str) -> String {
    let words: Vec<&str> = tag.split_whitespace().collect();
    let flat = words.join(" ");
    let last = match body.rfind('\n') {
        Some(i) => body[i + 1..].chars().count(),
        None => col + 2 + body.chars().count(),
    };
    if last + 1 + flat.chars().count() + 3 <= TAG_WIDTH {
        return format!("{body} {flat}");
    }
    let indent = " ".repeat(col + 3);
    let room = TAG_WIDTH.saturating_sub(indent.len() + 3).max(40);
    let mut lines: Vec<String> = vec![];
    let mut cur = String::new();
    for w in words {
        if !cur.is_empty() && cur.chars().count() + 1 + w.chars().count() > room {
            lines.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(w);
    }
    lines.push(cur);
    format!("{body}\n{indent}{}", lines.join(&format!("\n{indent}")))
}

/// The line of a graded function's address comment.
fn comment_line(r: &Row) -> i64 {
    r.get("comment").and_then(|v| v.as_i64()).filter(|&c| c != 0).unwrap_or(1)
}

/// Remove the level tag of every function that reached byte + readable, and the @hard tag of every function that
/// reached shape + readable; one line per change.
pub fn grades_auto_clear(p: &crate::project::Project) -> Result<Vec<String>> {
    let root = p.root.to_string_lossy().into_owned();
    let mut out = vec![];
    for r in function_grades(&p.store_path())?.iter() {
        let s = |k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let level = r.get("level").is_some_and(|v| !v.is_null() && v.as_str() != Some(""));
        let done = if s("level") == "hard" { s("code") != "draft" } else { s("code") == "byte" };
        if level && done && s("readability") == "readable" {
            let action = set_level(&root, &s("file"), None, None, comment_line(&r)).map_err(Error::value)?;
            out.push(format!("auto-clear {}: {} is {} + readable, {action}", s("file"), s("name"), s("code")));
        }
    }
    Ok(out)
}

/// The instruction-count difference allocation explains: max(SIZE_INS, the original's count / SIZE_PER). Measured on
/// gildegold (2026-10-31): the 173 shape functions (allocation, slots, frame, order only) differ by at most 7
/// instructions (d3_MatInverse 429 vs 436, gm_Mix 33 vs 27), and 166 of them by none; extra saved registers
/// (push / pop pairs), a spill or a register-held constant add a few instructions, an encoding change none.
pub const SIZE_INS: i64 = 12;
pub const SIZE_PER: i64 = 100;

/// The refusal of a deep escalation whose instruction count differs from the original's beyond what allocation
/// explains (ours, the original's, the allowance), or None.
pub fn size_unexplained(ours: i64, orig: i64) -> Option<(i64, i64, i64)> {
    let allow = SIZE_INS.max(orig / SIZE_PER);
    ((ours - orig).abs() > allow).then_some((ours, orig, allow))
}

/// `dcp escalate|stuck NAME --why` (`--clear`): (the lines, the error for stderr, the exit status). A deep
/// escalation of a function below byte is refused while its instruction count differs from the original's beyond
/// size_unexplained's allowance (missing or wrong statements: base work), unless `size_explained` says why
/// allocation explains it (recorded in the reason), or the prover shows its behaviour the same as the
/// original's. It is refused on a concrete difference (equiv::witness: a call or a global store one side has and
/// the other never refers to), unless `divergence_explained` says why it is none (recorded in the reason).
#[allow(clippy::too_many_arguments)]
pub fn level_command(p: &crate::project::Project, level: &str, name: &str, clear: bool, why: Option<String>,
                     size_explained: Option<String>, divergence_explained: Option<String>) -> Result<(Vec<String>, Option<String>, i32)> {
    let Some(r) = crate::asmcmd::find_function(&p.store_path(), name)? else {
        return Ok((vec![], Some(format!("no graded function {name} (dcp build first)")), 1));
    };
    let s = |k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let root = p.root.to_string_lossy().into_owned();
    let line = r.as_object().map(comment_line).unwrap_or(1);
    let action = if clear {
        set_level(&root, &s("file"), None, None, line)
    } else {
        let why = why.unwrap_or_default();
        if why.trim().is_empty() {
            return Ok((vec![], Some("a reason is required".into()), 1));
        }
        if level == "hard" && s("code") != "draft" && s("readability") == "readable" {
            return Ok((vec![], Some(format!("refused: {name} is {} + readable, no base work is left to hand up (dcp escalate {name} \"why\" for the deep queue)",
                                            s("code"))), 1));
        }
        if level == "deep" && only_missing_statements(&why) {
            return Ok((vec![], Some("refused: the reason names only missing statements; reconstruction is base work (say which leads were tried and what \
                                     is left)".into()), 1));
        }
        if let Some(w) = admits_unread(&why).filter(|_| level == "deep") {
            return Ok((vec![], Some(format!("refused: the reason admits a part not read against the original (`{w}`); reading and reconciling the \
                                             whole function is base work: finish it, then escalate what is left")), 1));
        }
        let mut why = why;
        if level == "deep" && s("code") != "byte" {
            // a function without an object (no reading) has no size to judge
            if let Ok(rd) = crate::asmcmd::reading(p, r.clone(), None)? {
                // a block one side shares by a jump and the other has inline (a tail hunk) is the same code: the
                // instructions it adds to one side are explained
                let tails: i64 = rd.hunks.iter().filter(|h| h.4 == "tail").map(|h| (h.1 - h.0) as i64 - (h.3 - h.2) as i64).sum();
                let (ours, orig) = (rd.la.len() as i64 - tails, rd.lb.len() as i64);
                if tails != 0 {
                    why = format!("{why} (size: {} of the instruction difference are shared / inline tails)", tails.abs());
                }
                if let Some(w) = &rd.witness {
                    match divergence_explained.as_deref().map(str::trim).filter(|x| !x.is_empty()) {
                        None => return Ok((vec![], Some(format!(
                            "refused: a concrete difference: {w}; a call or a global store one side lacks is a meaning difference, and \
                             reconstruction is base work (dcp diffclass {name}; a difference that is none: --divergence-explained \"why\")")), 1)),
                        Some(x) => why = format!("{why} (difference: {w}, explained: {x})"),
                    }
                }
                let proved = matches!(rd.proof.0, crate::equiv::Outcome::Equal { .. });
                // the reference check (refcheck.rs): a reference of ours the original's field does not make, unless
                // the references only cross and the proof shows the effects the same (the grade is shape then)
                if !rd.ref_lines.is_empty() && crate::grade::code_grade(false, rd.verdict.shape, proved, &rd.refs) != "shape" {
                    let more = if rd.ref_lines.len() > 1 { format!(" (and {} more)", rd.ref_lines.len() - 1) } else { String::new() };
                    match divergence_explained.as_deref().map(str::trim).filter(|x| !x.is_empty()) {
                        None => return Ok((vec![], Some(format!(
                            "refused: a reference differs: {}{more}; another object or other literal bytes than the original's is a meaning \
                             difference, and fixing it is base work (dcp diffclass {name}; a difference that is none: --divergence-explained \"why\")",
                            rd.ref_lines[0])), 1)),
                        Some(x) => why = format!("{why} (references: {}{more}, explained: {x})", rd.ref_lines[0]),
                    }
                }
                if let (true, Some((o, t, _))) = (proved, size_unexplained(ours, orig)) {
                    why = format!("{why} (size: {o} vs {t} instructions, the behaviour proved the same)");
                } else if let Some((o, t, allow)) = size_unexplained(ours, orig) {
                    match size_explained.as_deref().map(str::trim).filter(|x| !x.is_empty()) {
                        None => return Ok((vec![], Some(format!(
                            "refused: ours has {o} instructions, the original {t} ({:+}; allocation explains at most {allow}: max({SIZE_INS}, 1/{SIZE_PER} \
                             of the original's)); a size difference beyond that is missing or wrong statements, and reconstruction is base work \
                             (a difference allocation does cause: --size-explained \"why\")", o - t)), 1)),
                        Some(x) => why = format!("{why} (size: {o} vs {t} instructions, explained: {x})"),
                    }
                }
            }
        }
        set_level(&root, &s("file"), Some(level), Some(&why), line)
    }.map_err(Error::value)?;
    let addr = r.get("addr").and_then(|v| v.as_i64()).unwrap_or(0);
    let rec = crate::cliread::record(&[("fn", crate::cliread::Tok::I(addr)), ("name", crate::cliread::Tok::S(s("name"))),
                                       ("file", crate::cliread::Tok::S(s("file"))), ("action", crate::cliread::Tok::S(action))]);
    Ok((vec![rec], None, 0))
}

#[cfg(test)]
mod level_tests {
    use super::*;

    #[test]
    fn level_ladder() {
        assert!(only_missing_statements("missing statements"));
        assert!(only_missing_statements("the loop body is unwritten; two calls are missing"));
        assert!(!only_missing_statements("register choice ebx/esi after the spell pass; missing statements"));
        // a match-base report: the part after +0x5c7 was admitted as not reconciled and escalate took it
        assert_eq!(admits_unread("frame 0x3bc vs 0x3b8. The part after +0x5c7 (summary page) is not yet reconciled and is hard to judge").as_deref(),
                   Some("not yet reconciled"));
        assert_eq!(admits_unread("the store order and the 0x5a paths unverified").as_deref(), Some("unverified"));
        assert_eq!(size_unexplained(436, 429), None); // the largest difference of a shape function on gildegold
        assert_eq!(size_unexplained(1205, 1226), Some((1205, 1226, 12))); // main_Unk5384e0, 4277 vs 4402 bytes
        assert_eq!((size_unexplained(3030, 3000), size_unexplained(3031, 3000)), (None, Some((3031, 3000, 30))));
        assert_eq!(admits_unread("bpp is not read; cm_SendMoveGoodsUnchecked's slots; read to the end, only ebx/esi left"), None);
        let dir = crate::testkit::scratch("level");
        let root = dir.to_string_lossy().into_owned();
        crate::edit::write(&format!("{root}/src/u.c"), "int x;  /* 0x10002000 */\n\n/* 0x10001000, does it */\nvoid f(void)\n{\n}\n").unwrap();
        assert!(set_level(&root, "src/u.c", Some("deep"), Some("the data comment"), 1).is_err());
        assert_eq!(set_level(&root, "src/u.c", Some("deep"), Some("slot order after vargen"), 3).unwrap(), "@deep added");
        assert!(crate::edit::read(&format!("{root}/src/u.c")).contains("\n/* 0x10001000, does it @deep slot order after vargen */\n"));
        assert_eq!(set_level(&root, "src/u.c", Some("stuck"), Some("every lead tried"), 3).unwrap(), "@deep -> @stuck");
        let text = crate::edit::read(&format!("{root}/src/u.c"));
        if let Some(part) = crate::srcscan::tests::scan_alone("src/u.c", &text) {
            let f = &part.functions[0];
            assert_eq!((f.1 .1.as_deref(), f.1 .0.as_deref(), f.0 .6.as_str(), f.1 .3), (Some("every lead tried"), None, "does it", 3));
        }
        // @hard: handed to a stronger worker, read back as the function's hard reason
        assert_eq!(set_level(&root, "src/u.c", Some("hard"), Some("the switch is still a chain of ifs"), 3).unwrap(), "@stuck -> @hard");
        let text = crate::edit::read(&format!("{root}/src/u.c"));
        if let Some(part) = crate::srcscan::tests::scan_alone("src/u.c", &text) {
            let f = &part.functions[0];
            assert_eq!((f.1 .7.as_deref(), f.1 .1.as_deref(), f.0 .6.as_str()), (Some("the switch is still a chain of ifs"), None, "does it"));
        }
        assert_eq!(set_level(&root, "src/u.c", None, None, 3).unwrap(), "@hard removed");
        assert_eq!(crate::edit::read(&format!("{root}/src/u.c")), "int x;  /* 0x10002000 */\n\n/* 0x10001000, does it */\nvoid f(void)\n{\n}\n");
        // a reason with `*`, `/`, `(...)` and a line break, on a comment of several lines: escalate, replace, clear
        // gives the comment back exactly (a match-base report: clear stopped at the first `*` and left the rest)
        let orig = "/* 0x10001000, steps the shot:\n   fall = step * g. Returns 1 while it flies. */\nvoid f(void)\n{\n}\n";
        crate::edit::write(&format!("{root}/src/u.c"), orig).unwrap();
        let why = "body reconstructed (354 ins): fall = step * g and perMass = step / mass;\n   the [esp+0x18] / ebx choice is left";
        assert_eq!(set_level(&root, "src/u.c", Some("deep"), Some(why), 1).unwrap(), "@deep added");
        // too long for the comment's last line: lines of its own below it, indented, within TAG_WIDTH (a match-base
        // report: escalations grew one line to 600 characters); the scan reads the reason over the lines
        let tagged = crate::edit::read(&format!("{root}/src/u.c"));
        assert!(tagged.contains("while it flies.\n   @deep body reconstructed (354 ins): fall = step * g and perMass = step / mass; the [esp+0x18] / ebx\n   \
                                 choice is left */\nvoid f"), "{tagged}");
        assert!(tagged.lines().all(|l| l.chars().count() <= TAG_WIDTH), "{tagged}");
        if let Some(part) = crate::srcscan::tests::scan_alone("src/u.c", &tagged) {
            assert_eq!(part.functions[0].1 .0.as_deref(), Some(why.split_whitespace().collect::<Vec<_>>().join(" ").as_str()));
        }
        assert_eq!(set_level(&root, "src/u.c", Some("deep"), Some("x * y (z)"), 1).unwrap(), "@deep reason replaced");
        assert!(crate::edit::read(&format!("{root}/src/u.c")).contains("while it flies. @deep x * y (z) */\nvoid f"));
        assert_eq!(set_level(&root, "src/u.c", Some("deep"), Some(why), 1).unwrap(), "@deep reason replaced");
        assert_eq!(set_level(&root, "src/u.c", Some("deep"), Some(why), 1).unwrap(), "@deep reason replaced");
        assert_eq!(crate::edit::read(&format!("{root}/src/u.c")), tagged); // replaced, not appended
        assert_eq!(set_level(&root, "src/u.c", None, None, 1).unwrap(), "@deep removed");
        assert_eq!(crate::edit::read(&format!("{root}/src/u.c")), orig);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
