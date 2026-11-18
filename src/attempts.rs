//! Unfinished match-deep attempts: how often a match-deep session took a function as its item and ended (wrapped,
//! or died: its context ran out, its process was stopped) without bringing it to byte + readable or to a committed
//! meaning fix. The deep queue hands out the functions with the fewest unfinished attempts first, so one that
//! defeated a session comes up again behind every function nobody has failed on yet, when more is known; what the
//! session found stays in the function's `@deep` note (`dcp note`).
//!
//! Where the fact comes from (no worker writes it): `dcp next --deep` in a match-deep session (`dcp session start
//! --kind match-deep`) records the item it hands out in the session record (.dcp/session.json) and hands out the
//! same item again until it is done; `dcp session wrap` and the next `dcp session start` (the previous session's
//! record is still there when that session died) count one unfinished attempt for a recorded item that is not
//! done, into ledger/attempts.tsv (committed with the session). Done: byte + readable as the grades read it (a proven
//! byte counts), or a commit since the session's base whose subject names `<name> fix`.
//!
//! `dcp session wrap` closes the session (`"wrapped": true` in the record): a `dcp next --deep` after it records no
//! item (it only shows the queue's head), and the next `dcp session start` counts nothing from a wrapped session.
//! `dcp next --peek` never records. `dcp next --deep --nearest` orders the queue (attempts, distance ins, distance
//! bytes, the queue's order) and hands out and records its first item as plain `--deep` does.
//!
//! The ledger: target, address, name, attempts (a header line; sorted by target, address).

use crate::error::{Error, Result};
use crate::project::{native_path, Project};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};

pub const LEDGER: &str = "ledger/attempts.tsv";
pub const HEADER: &str = "target\taddress\tname\tattempts";

fn err(e: impl std::fmt::Display) -> Error {
    Error::runtime(e.to_string())
}

/// The ledger's rows: (target, address) -> (name, attempts).
pub fn parse(text: &str) -> BTreeMap<(String, i64), (String, i64)> {
    text.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#') && !l.starts_with("target\t")).filter_map(|l| {
        let f: Vec<&str> = l.split('\t').collect();
        (f.len() >= 4).then(|| Some(((f[0].to_string(), crate::layout::int16(f[1])?), (f[2].to_string(), f[3].trim().parse().ok()?))))?
    }).collect()
}

pub fn render(rows: &BTreeMap<(String, i64), (String, i64)>) -> String {
    let mut out = format!("{HEADER}\n");
    for ((t, a), (n, k)) in rows {
        out.push_str(&format!("{t}\t{a:#010x}\t{n}\t{k}\n"));
    }
    out
}

fn path(root: &str) -> String {
    native_path(&format!("{root}/{LEDGER}"))
}

pub fn read(root: &str) -> BTreeMap<(String, i64), (String, i64)> {
    parse(&std::fs::read_to_string(path(root)).unwrap_or_default())
}

/// The unfinished attempts of a target's functions, by address.
pub fn counts(root: &str, target: &str) -> HashMap<i64, i64> {
    read(root).into_iter().filter(|((t, _), _)| t == target).map(|((_, a), (_, k))| (a, k)).collect()
}

/// Add `by` attempts to a function, or raise it to at least `at_least`: its count now.
fn bump(rows: &mut BTreeMap<(String, i64), (String, i64)>, target: &str, addr: i64, name: &str, by: i64, at_least: i64) -> i64 {
    let e = rows.entry((target.to_string(), addr)).or_insert((name.to_string(), 0));
    e.0 = name.to_string();
    e.1 = (e.1 + by).max(at_least);
    e.1
}

fn write(root: &str, rows: &BTreeMap<(String, i64), (String, i64)>) -> Result<()> {
    let p = path(root);
    if let Some(d) = std::path::Path::new(&p).parent() {
        let _ = std::fs::create_dir_all(d);
    }
    crate::edit::write(&p, &render(rows)).map_err(err)
}

// ------------------------------------------------------------------------------------------------ the session's item

/// The item a match-deep session's record holds: (target, address, name).
fn item_of(rec: &Value) -> Option<(String, i64, String)> {
    let i = rec.get("item")?;
    Some((i.get("target")?.as_str()?.to_string(), i.get("addr")?.as_i64()?, i.get("name")?.as_str()?.to_string()))
}

fn match_deep(rec: &Value) -> bool {
    rec.get("kind").and_then(|k| k.as_str()) == Some("match-deep")
}

/// Whether `dcp session wrap` closed the session of the record.
fn wrapped(rec: &Value) -> bool {
    rec.get("wrapped").and_then(|w| w.as_bool()) == Some(true)
}

/// Whether `dcp next --deep` records its item in the session record: a match-deep session that is not wrapped.
fn open_match_deep(rec: &Value) -> bool {
    match_deep(rec) && !wrapped(rec)
}

/// Take the item out of a session record: the item to judge (a match-deep session's, not wrapped before), the item
/// cleared; `wrap` closes the session.
fn take_item(rec: &mut Value, wrap: bool) -> Option<(String, i64, String)> {
    let item = item_of(rec).filter(|_| open_match_deep(rec));
    if let Some(o) = rec.as_object_mut() {
        o.remove("item");
        if wrap {
            o.insert("wrapped".into(), Value::Bool(true));
        }
    }
    item
}

fn git(root: &str, args: &[&str]) -> String {
    match std::process::Command::new("git").args(args).current_dir(root).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        _ => String::new(),
    }
}

/// Whether a commit subject records a meaning fix of `name` (`<unit>: <name> fix: ...`).
pub fn fix_subject(subject: &str, name: &str) -> bool {
    subject.split(&[' ', ':', ','][..]).collect::<Vec<_>>().windows(2).any(|w| w[0] == name && w[1] == "fix")
}

/// Whether a session's item is done: byte + readable in the grade rows (`proven` byte counts), or a commit since the
/// session's base names its meaning fix.
fn done(root: &str, rows: &[Map<String, Value>], base: &str, addr: i64, name: &str) -> bool {
    let s = |r: &Map<String, Value>, k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let graded = rows.iter().find(|r| r.get("addr").and_then(|v| v.as_i64()) == Some(addr)).is_some_and(|r| {
        let code = r.get("proven").and_then(|v| v.as_str()).map(str::to_string).unwrap_or_else(|| s(r, "code"));
        code == "byte" && s(r, "readability") == "readable"
    });
    graded || (!base.is_empty() && git(root, &["log", "--format=%s", &format!("{base}..HEAD")]).lines().any(|l| fix_subject(l, name)))
}

/// Close the item of the session record (at `dcp session wrap`, and at `dcp session start` for the record a dead
/// session left): one unfinished attempt counted when it is not done, the item cleared; `wrap` closes the session
/// (a wrapped session's record counts nothing again). The lines say what was counted.
pub fn close_item(p: &Project, wrap: bool) -> Result<Vec<String>> {
    let root = p.root.to_string_lossy().into_owned();
    let mut rec = crate::session::session_load(&root);
    if !rec.is_object() {
        return Ok(vec![]);
    }
    let changes = rec.get("item").is_some() || (wrap && !wrapped(&rec));
    let item = take_item(&mut rec, wrap);
    let mut out = vec![];
    if let Some((target, addr, name)) = item {
        let base = rec.get("base").and_then(|b| b.as_str()).unwrap_or("").to_string();
        let rows = crate::queues::function_grades(&p.store_path())?;
        if target == p.target_name && !done(&root, &rows, &base, addr, &name) {
            let mut ledger = read(&root);
            let n = bump(&mut ledger, &target, addr, &name, 1, 0);
            write(&root, &ledger)?;
            out.push(format!("attempts: {name} was this match-deep session's item and is not byte + readable: unfinished attempt {n} counted in \
                              {LEDGER} (commit it; dcp next --deep hands it out again behind the items with fewer attempts)"));
        }
    }
    if changes {
        crate::session::session_write(&root, &rec)?;
    }
    Ok(out)
}

/// `dcp next --deep`'s item in a match-deep session: the recorded item while it is not done (it stays the item:
/// no session skips it), else the first of `items` recorded as the new item. The address to put first, if any.
/// `peek` (`dcp next --peek`) records nothing; a wrapped session (`dcp session wrap`) neither.
pub fn hand_out(p: &Project, items: &[i64], names: &HashMap<i64, String>, peek: bool) -> Result<Option<i64>> {
    let root = p.root.to_string_lossy().into_owned();
    let mut rec = crate::session::session_load(&root);
    if !open_match_deep(&rec) {
        return Ok(None);
    }
    let base = rec.get("base").and_then(|b| b.as_str()).unwrap_or("").to_string();
    if let Some((t, a, n)) = item_of(&rec) {
        let rows = crate::queues::function_grades(&p.store_path())?;
        if t == p.target_name && !done(&root, &rows, &base, a, &n) {
            return Ok(Some(a));
        }
    }
    let Some(&first) = items.first() else { return Ok(None) };
    if peek {
        return Ok(None);
    }
    if let Some(o) = rec.as_object_mut() {
        o.insert("item".into(), json!({"target": p.target_name, "addr": first, "name": names.get(&first).cloned().unwrap_or_default()}));
        crate::session::session_write(&root, &rec)?;
    }
    Ok(Some(first))
}

/// The deep queue in `dcp next --deep`'s order: the fewest unfinished attempts first, the queue's order kept among
/// equal counts; the session's item (hand_out) before everything. (`order_by` without distances: next_command calls that.)
#[cfg(test)]
pub fn order<T>(items: &mut Vec<(i64, T)>, counts: &HashMap<i64, i64>, first: Option<i64>) {
    order_by(items, counts, None, first);
}

/// `order`, and with `near` (`dcp next --deep --nearest`: each address's distance, differing instructions and
/// bytes as `dcp grade` prints them) the nearest first among equal counts: (attempts, ins, bytes), the queue's order
/// kept among equals. A function without a distance comes after every measured one.
pub fn order_by<T>(items: &mut Vec<(i64, T)>, counts: &HashMap<i64, i64>, near: Option<&HashMap<i64, (i64, i64)>>, first: Option<i64>) {
    let far = (i64::MAX, i64::MAX);
    items.sort_by_key(|(a, _)| {
        let d = near.map(|m| m.get(a).copied().unwrap_or(far)).unwrap_or((0, 0));
        (Some(*a) != first, counts.get(a).copied().unwrap_or(0), d.0, d.1)
    });
}

// ------------------------------------------------------------------------------------------------ the journal

/// The `@deep` reason of the address comment of `addr` in a C text (its words joined by one space), None without one.
pub fn deep_reason(text: &str, addr: i64) -> Option<String> {
    use std::sync::LazyLock;
    static COMMENT: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(?s)/\*(.*?)\*/").unwrap());
    static TAG: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(?s)(?:\A|\s)@deep\b").unwrap());
    let text = text.replace("\r\n", "\n");
    // every comment that leads with the address: a prototype's or a reference's bare `/* 0x500190 */` above the
    // definition holds no tag (dcp note kept no prior: on gm_CreateObject and he_RunDecay: it read that one)
    COMMENT.captures_iter(&text)
        .filter(|c| crate::srcscan::lead_addrs(&c[1]).0.iter().any(|x| x.1 as i64 == addr))
        .find_map(|c| {
            // the reason, not the notes after it (srcscan::reason_end)
            let body = c.get(1).unwrap().as_str();
            TAG.find(body).map(|t| body[t.end()..crate::srcscan::reason_end(body, t.end())].split_whitespace().collect::<Vec<_>>().join(" "))
        })
}

/// `dcp note NAME "text"`: the match-deep journal. The function's `@deep` note becomes the text, the note as the
/// session found it (at its base commit; the note now outside a session) kept as `prior:`, so that a session's
/// updates replace each other instead of piling up. Only a deep item takes a note (a @deep function, or one the deep
/// queue holds). (the lines, the error, the exit status)
pub fn note_command(p: &Project, name: &str, text: &str) -> Result<(Vec<String>, Option<String>, i32)> {
    let db = p.store_path();
    let Some(r) = crate::asmcmd::find_function(&db, name)? else {
        return Ok((vec![], Some(format!("no graded function {name} (dcp build first)")), 1));
    };
    if text.trim().is_empty() {
        return Ok((vec![], Some("a note is required".into()), 1));
    }
    let s = |k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let addr = r.get("addr").and_then(|v| v.as_i64()).unwrap_or(0);
    let deep = s("level") == "deep" || crate::queues::queue(&db, "deep", None, None)?.iter().any(|q| q.get("addr").and_then(|v| v.as_i64()) == Some(addr));
    if !deep {
        return Ok((vec![], Some(format!("refused: {name} is no deep item (dcp escalate hands base work to the deep queue)")), 1));
    }
    let root = p.root.to_string_lossy().into_owned();
    let file = s("file");
    let base = crate::session::session_record(&root).0;
    let line = r.get("comment").and_then(|v| v.as_i64()).filter(|&c| c != 0).unwrap_or(1);
    let action = note_at(&root, &file, addr, line, text, base.as_deref()).map_err(Error::value)?;
    let rec = crate::cliread::record(&[("fn", crate::cliread::Tok::I(addr)), ("name", crate::cliread::Tok::S(name.into())),
                                       ("file", crate::cliread::Tok::S(file)), ("action", crate::cliread::Tok::S(action))]);
    Ok((vec![rec], None, 0))
}

/// The note of the function at `addr` (its address comment at `line` of `file`) becomes `text`, the note as the
/// session found it (its reason at the session's `base` commit; without a session the note as it is now) kept as
/// `prior:`. The action.
/// The action says which text is the prior: a worker read "the earlier reason kept as prior:" on its second note as
/// its own first text kept (a report of match-deep s27).
fn note_at(root: &str, file: &str, addr: i64, line: i64, text: &str, base: Option<&str>) -> std::result::Result<String, String> {
    let base = base.filter(|b| !b.is_empty());
    // the note as the session found it: what earlier sessions wrote stays, this session's own text is replaced
    let kept = base.map(|b| deep_reason(&git(root, &["show", &format!("{b}:{file}")]), addr).unwrap_or_default());
    let now = crate::edit::read_src(&crate::project::native_path(&format!("{root}/{file}"))).ok().and_then(|t| deep_reason(&t, addr));
    let action = crate::queues::set_level_kept(root, file, Some("deep"), Some(text), line, kept.as_deref())?;
    let Some(b) = base else { return Ok(action) };
    let short: String = b.chars().take(8).collect();
    let mut action = action.replace("the earlier reason kept as prior:", &format!("the note as the session found it (at its base {short}) kept as prior:"));
    let norm = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
    if now.as_deref().is_some_and(|n| !n.is_empty() && Some(norm(n)) != kept.as_deref().map(norm)) {
        action.push_str("; this session's earlier text replaced, not kept");
    }
    Ok(action)
}

// ------------------------------------------------------------------------------------------------ the migration

/// `@stuck why` -> `@deep why` in the address comments of a C text (a comment that also holds a @deep keeps that
/// reason as `prior:`): (the new text, the addresses migrated). The same text again changes nothing.
pub fn migrate_text(text: &str) -> (String, Vec<i64>) {
    use std::sync::LazyLock;
    static COMMENT: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(?s)/\*.*?\*/").unwrap());
    static STUCK: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"@stuck\b").unwrap());
    static TAGS: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"@(deep|stuck)\b").unwrap());
    let mut moved = vec![];
    let out = COMMENT.replace_all(text, |c: &regex::Captures| {
        let raw = &c[0];
        if !STUCK.is_match(raw) {
            return raw.to_string();
        }
        let body = &raw[2..raw.len() - 2];
        let addrs = crate::srcscan::lead_addrs(body).0;
        if addrs.is_empty() {
            return raw.to_string();
        }
        moved.extend(addrs.iter().map(|x| x.1 as i64));
        let tags: Vec<(usize, usize, bool)> = TAGS.captures_iter(raw).map(|t| {
            let m = t.get(0).unwrap();
            (m.start(), m.end(), &t[1] == "stuck")
        }).collect();
        if !tags.iter().any(|t| !t.2) {
            // the @stuck alone: the word changes, its reason and every line stay
            return STUCK.replace(raw, "@deep").into_owned();
        }
        // a @deep beside the @stuck: one @deep with the stuck reason first, the deep one kept as prior:
        let end = raw.len() - 2;
        let reason = |k: usize| -> String {
            let to = tags.get(k + 1).map(|t| t.0).unwrap_or(end);
            raw[tags[k].1..to].split_whitespace().collect::<Vec<_>>().join(" ")
        };
        let stuck: Vec<String> = (0..tags.len()).filter(|&k| tags[k].2).map(reason).filter(|r| !r.is_empty()).collect();
        let deep: Vec<String> = (0..tags.len()).filter(|&k| !tags[k].2).map(reason).filter(|r| !r.is_empty()).collect();
        let joined = stuck.into_iter().chain(deep).collect::<Vec<_>>().join(" prior: ");
        format!("{} @deep {joined} */", raw[..tags[0].0].trim_end())
    }).into_owned();
    (out, moved)
}

/// `dcp migrate stuck`: every `@stuck` tag of the sources becomes `@deep` (its reason, and its `prior:` reasons,
/// kept), and each such function counts one unfinished attempt (at least 1 in ledger/attempts.tsv: a session gave
/// it up once). Safe to run again: nothing is left to migrate, no count rises twice.
pub fn migrate_stuck(p: &Project) -> Result<Vec<String>> {
    let root = p.root.to_string_lossy().into_owned();
    let rows = crate::queues::function_grades(&p.store_path())?;
    let names: HashMap<i64, String> = rows.iter().filter_map(|r| Some((r.get("addr")?.as_i64()?, r.get("name")?.as_str()?.to_string()))).collect();
    let mut files: Vec<String> = rows.iter().filter_map(|r| r.get("file").and_then(|v| v.as_str()).map(str::to_string)).collect();
    files.sort();
    files.dedup();
    let mut ledger = read(&root);
    let (mut out, mut n) = (vec![], 0);
    for f in &files {
        let path = native_path(&format!("{root}/{f}"));
        let Ok(text) = crate::edit::read_src(&path) else { continue };
        let (new, moved) = migrate_text(&text);
        if moved.is_empty() {
            continue;
        }
        crate::edit::write(&path, &new).map_err(err)?;
        for a in &moved {
            let name = names.get(a).cloned().unwrap_or_default();
            bump(&mut ledger, &p.target_name, *a, &name, 0, 1);
        }
        n += moved.len();
        out.push(format!("{f}: {} @stuck -> @deep", moved.len()));
    }
    if n > 0 {
        write(&root, &ledger)?;
    }
    out.push(format!("migrated {n} @stuck tag(s) to @deep; each counts 1 unfinished attempt in {LEDGER}"));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ledger_round_trip_and_bump() {
        let mut rows = parse(&format!("{HEADER}\nexe\t0x00401000\tf\t2\n"));
        assert_eq!(rows.get(&("exe".into(), 0x401000)), Some(&("f".into(), 2)));
        assert_eq!(bump(&mut rows, "exe", 0x401000, "f", 1, 0), 3);
        // at least 1: the migration's seed never lowers nor raises twice
        assert_eq!(bump(&mut rows, "exe", 0x402000, "g", 0, 1), 1);
        assert_eq!(bump(&mut rows, "exe", 0x402000, "g", 0, 1), 1);
        assert_eq!(parse(&render(&rows)), rows);
    }

    #[test]
    fn the_fewest_attempts_first_the_session_item_before_all() {
        // the queue's order a, b, c, d; b failed twice, c once
        let counts: HashMap<i64, i64> = [(2, 2), (3, 1)].into_iter().collect();
        let mut items: Vec<(i64, &str)> = vec![(1, "a"), (2, "b"), (3, "c"), (4, "d")];
        order(&mut items, &counts, None);
        assert_eq!(items.iter().map(|x| x.1).collect::<Vec<_>>(), ["a", "d", "c", "b"]);
        // the session's own item stays first whatever its count
        order(&mut items, &counts, Some(2));
        assert_eq!(items.iter().map(|x| x.1).collect::<Vec<_>>(), ["b", "a", "d", "c"]);
    }

    #[test]
    fn nearest_first_among_equal_attempts() {
        // the queue's order a..f; c failed once; distances (ins, bytes): e has none
        let counts: HashMap<i64, i64> = [(3, 1)].into_iter().collect();
        let near: HashMap<i64, (i64, i64)> = [(1, (300, 900)), (2, (2, 9)), (3, (0, 1)), (4, (2, 4)), (6, (2, 4))].into_iter().collect();
        let mut items: Vec<(i64, &str)> = vec![(1, "a"), (2, "b"), (3, "c"), (4, "d"), (5, "e"), (6, "f")];
        order_by(&mut items, &counts, Some(&near), None);
        // the fewest attempts first (c, though nearest, after the 0-attempt ones), then ins, then bytes, then the
        // queue's order (d before f); e without a distance last among its count
        assert_eq!(items.iter().map(|x| x.1).collect::<Vec<_>>(), ["d", "f", "b", "a", "e", "c"]);
        // the session's item stays first
        order_by(&mut items, &counts, Some(&near), Some(1));
        assert_eq!(items.iter().map(|x| x.1).collect::<Vec<_>>(), ["a", "d", "f", "b", "e", "c"]);
        // without --nearest the default order is unchanged
        let mut plain: Vec<(i64, &str)> = vec![(1, "a"), (2, "b"), (3, "c"), (4, "d"), (5, "e"), (6, "f")];
        order(&mut plain, &counts, None);
        assert_eq!(plain.iter().map(|x| x.1).collect::<Vec<_>>(), ["a", "b", "d", "e", "f", "c"]);
    }

    #[test]
    fn a_wrapped_session_records_and_counts_nothing() {
        let item = json!({"target": "exe", "addr": 0x401000, "name": "f"});
        // a match-deep session that died with its item: the next start judges it
        let mut died = json!({"base": "b", "kind": "match-deep", "item": item});
        assert!(open_match_deep(&died));
        assert_eq!(take_item(&mut died, false), Some(("exe".into(), 0x401000, "f".into())));
        assert!(died.get("item").is_none() && !wrapped(&died));
        // the wrap judges its item and closes the session: nothing is recorded after it
        let mut rec = json!({"base": "b", "kind": "match-deep", "item": item});
        assert_eq!(take_item(&mut rec, true), Some(("exe".into(), 0x401000, "f".into())));
        assert!(wrapped(&rec) && !open_match_deep(&rec));
        // an item a wrapped record holds anyway (an older dcp recorded it after the wrap) counts nothing at the start
        rec.as_object_mut().unwrap().insert("item".into(), item.clone());
        assert_eq!(take_item(&mut rec, false), None);
        assert!(rec.get("item").is_none());
        // a wrap twice: still closed, still nothing
        assert_eq!(take_item(&mut rec, true), None);
        assert!(wrapped(&rec));
        // not match-deep: no item to judge
        let mut base = json!({"base": "b", "kind": "match-base", "item": item});
        assert!(!open_match_deep(&base));
        assert_eq!(take_item(&mut base, true), None);
    }

    #[test]
    fn fixes_and_notes() {
        assert!(fix_subject("sv_t: ai_Tutorial fix: the index was wrong", "ai_Tutorial"));
        assert!(!fix_subject("sv_t: ai_Tutorial byte (match-deep)", "ai_Tutorial"));
        assert!(!fix_subject("sv_t: ai_TutorialX fix: x", "ai_Tutorial"));
        let t = "/* 0x401000, does it @deep round 2: shape, 9 ins\n   prior: round 1 */\nint f(void) {}\n/* 0x402000 */\nint g(void) {}\n";
        assert_eq!(deep_reason(t, 0x401000).as_deref(), Some("round 2: shape, 9 ins prior: round 1"));
        assert_eq!(deep_reason(t, 0x402000), None);
        // the prototype's bare address comment above the definition's (he_RunDecay in he_b.c, gm_CreateObject in f3gmt.c)
        let t = "void he_RunDecay(int ev);          /* 0x5702e0 */\n/* 0x5702e0 */\n\n/* 0x5702e0, the decay\n   @deep read the whole function */\nvoid he_RunDecay(int ev) {}\n";
        assert_eq!(deep_reason(t, 0x5702e0).as_deref(), Some("read the whole function"));
    }

    /// Two notes in one session: the second replaces the first, and only the note as the session found it (at its
    /// base commit) stays as `prior:`; without a session the note as it is now is the prior.
    #[test]
    fn a_second_note_replaces_the_sessions_own() {
        let dir = crate::testkit::scratch("note-twice");
        let root = dir.to_string_lossy().into_owned();
        let run = |args: &[&str]| assert!(std::process::Command::new("git").args(args).current_dir(&dir).output().unwrap().status.success(), "{args:?}");
        run(&["init", "-q"]);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/u.c"), "/* 0x401000, does it
   @deep s1: old round */
int f(void) { return 1; }
").unwrap();
        run(&["add", "-A"]);
        run(&["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "base"]);
        let base = git(&root, &["rev-parse", "HEAD"]).trim().to_string();
        let note = |text: &str, base: Option<&str>| {
            let action = note_at(&root, "src/u.c", 0x401000, 1, text, base).unwrap();
            (deep_reason(&std::fs::read_to_string(dir.join("src/u.c")).unwrap(), 0x401000).unwrap(), action)
        };
        let short = &base[..8];
        let (r, action) = note("s2: round one", Some(&base));
        assert_eq!(r, "s2: round one prior: s1: old round");
        assert_eq!(action, format!("@deep reason replaced (the note as the session found it (at its base {short}) kept as prior:)"));
        // committed or not, the session's own first text is no prior, and the action says so
        run(&["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-am", "note"]);
        let (r, action) = note("s2: round two", Some(&base));
        assert_eq!(r, "s2: round two prior: s1: old round");
        assert!(action.ends_with("kept as prior:); this session's earlier text replaced, not kept"), "{action}");
        // without a session: the note as it is now
        let (r, action) = note("s3: alone", None);
        assert_eq!(r, "s3: alone prior: s2: round two prior: s1: old round");
        assert_eq!(action, "@deep reason replaced (the earlier reason kept as prior:)");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stuck_migrates_once() {
        let t = "/* 0x401000, does it @stuck every lead tried prior: slot order */\nint f(void) {}\n/* 0x402000 @deep x */\nint g(void) {}\n";
        let (m, moved) = migrate_text(t);
        assert_eq!(moved, [0x401000]);
        assert_eq!(m, "/* 0x401000, does it @deep every lead tried prior: slot order */\nint f(void) {}\n/* 0x402000 @deep x */\nint g(void) {}\n");
        // twice: nothing left
        assert_eq!(migrate_text(&m), (m.clone(), vec![]));
        // the line count stays (a unit that numbers by line)
        let t2 = "/* 0x401000\n   @stuck a\n   b */\nint f(void) {}\n";
        assert_eq!(migrate_text(t2).0.lines().count(), t2.lines().count());
    }
}
