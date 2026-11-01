//! The session protocol of a solo session, layout or match-base (`dcp session start` / `dcp session wrap`): a gate
//! at the start, the computed report at the end. Nothing here is written by hand: the report comes from git (the
//! session's base commit against the working tree), the store and names.log; the only record is .dcp/session.json
//! (git-ignored: the base commit, the start time and the states the gate saw).
//!
//! start   gate: the working tree is clean (git status, build/ and .dcp/ ignored), every unit compiles (dcp build),
//!         no bug or error conflict on any target, every target's link is ok; then the overview: per target the unit
//!         table summary, the first open function (`dcp layout next`), the toolchain declaration and how much of it is
//!         probed.
//! wrap    build, link, check every target; promote the grade baseline (main checkout only); the report: units
//!         declared, joined and renamed (decl/*.dcl and names.log since the base), the functions drafted (with their
//!         grades), renames, the boundary levels and status of every unit the session touched, the check before ->
//!         after, the next item.

use crate::error::{Error, Result};
use crate::cliread::{fmt_addr, record, Tok};
use crate::project::{py_path, Project};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;

/// The length of a session, in minutes.
pub const MINUTES: i64 = 30;

fn err(e: impl std::fmt::Display) -> Error {
    Error::runtime(e.to_string())
}

fn s(x: impl Into<String>) -> Tok {
    Tok::S(x.into())
}

fn os(x: Option<String>) -> Tok {
    x.map(Tok::S).unwrap_or(Tok::No)
}

/// git's stdout, '' when it fails.
fn git(root: &str, args: &[&str]) -> String {
    match std::process::Command::new("git").args(args).current_dir(root).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        _ => String::new(),
    }
}

fn read_lines(path: &str) -> Vec<String> {
    std::fs::read(path).map(|b| String::from_utf8_lossy(&b).replace("\r\n", "\n")).unwrap_or_default().lines().map(|l| l.to_string()).collect()
}

fn now() -> chrono::NaiveDateTime {
    chrono::Local::now().naive_local()
}

fn iso(t: chrono::NaiveDateTime) -> String {
    t.format("%Y-%m-%dT%H:%M:%S").to_string()
}

/// The changed or untracked paths of the working tree outside build/ and .dcp/.
pub fn session_dirty(root: &str) -> Vec<String> {
    git(root, &["status", "--porcelain", "--untracked-files=all"]).lines().filter(|l| {
        let path = l.get(3..).unwrap_or("").trim().trim_matches('"');
        !(path.starts_with("build/") || path.starts_with(".dcp/"))
    }).map(|l| l.trim_end().to_string()).collect()
}

/// The commit of HEAD ('' without one).
pub fn session_head(root: &str) -> String {
    git(root, &["rev-parse", "HEAD"]).trim().to_string()
}

fn record_path(root: &str) -> String {
    py_path(&format!("{root}/.dcp/session.json"))
}

fn load(root: &str) -> Option<Value> {
    serde_json::from_str(&std::fs::read_to_string(record_path(root)).ok()?).ok()
}

/// The counts a session report compares: functions, units, grades, errors.
fn state(p: &Project) -> Result<Value> {
    let db = p.store_path();
    crate::pystore::st_open(&db, &p.main_uri())?;
    let rows = crate::queues::function_grades(&db)?;
    let str_of = |r: &Map<String, Value>, k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let units = crate::with_db(&db, |c| crate::store::facts_of(c, &db, "unit", None, |f| f.value.get("status").is_some()))?;
    let mut grades: BTreeMap<String, i64> = BTreeMap::new();
    for r in rows.iter() {
        *grades.entry(format!("{}+{}", str_of(r, "code"), str_of(r, "readability"))).or_default() += 1;
    }
    let errors = crate::pystore::st_conflicts(&db, None, None)?.iter().filter(|c| c.0 == "bug" || c.0 == "error").count();
    Ok(json!({"functions": rows.len(), "byte": rows.iter().filter(|r| str_of(r, "code") == "byte").count(),
              "readable": rows.iter().filter(|r| str_of(r, "readability") == "readable").count(), "units": units.len(),
              "separated": units.iter().filter(|f| f.s("status") == Some("separated")).count(), "errors": errors, "grades": grades}))
}

/// The state of a target (a dict: functions, byte, readable, units, separated, errors, grades).
pub fn session_state(p: &crate::project::Project) -> Result<Value> {
    state(p)
}

/// Record .dcp/session.json: the base commit, the start time, the states of the targets.
pub fn session_save(root: &str, base: &str, states: &Value) -> Result<()> {
    let rec = json!({"base": base, "started": iso(now()), "states": states});
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, serde_json::ser::PrettyFormatter::with_indent(b" "));
    serde::Serialize::serialize(&rec, &mut ser).map_err(err)?;
    crate::edit::write(&record_path(root), &(String::from_utf8_lossy(&buf).into_owned() + "\n")).map_err(err)
}

/// The session's clock from .dcp/session.json: (the record line: base commit, start time, minutes elapsed and left
/// of `minutes`; over once they are used up), None without a started session. The only clock of a session: `dcp
/// session status`, and the first line of `dcp layout next` while a session runs.
pub fn session_clock(root: &str, minutes: i64) -> Option<(String, bool)> {
    let r = load(root)?;
    let started = r.get("started")?.as_str().filter(|s| !s.is_empty())?.to_string();
    let base: String = r.get("base").and_then(|b| b.as_str()).unwrap_or("").chars().take(8).collect();
    let t0 = chrono::NaiveDateTime::parse_from_str(&started, "%Y-%m-%dT%H:%M:%S").ok()?;
    let elapsed = (now() - t0).num_milliseconds() as f64 / 60000.0;
    let over = elapsed >= minutes as f64;
    let line = record(&[("session", s("running")), ("base", if base.is_empty() { Tok::No } else { s(base) }), ("started", s(started)),
                        ("elapsed", s(format!("{elapsed:.0}m"))), ("left", s(format!("{:.0}m", (minutes as f64 - elapsed).max(0.0)))),
                        ("over", Tok::B(over))]);
    Some((line, over))
}

/// The record of a started session: (its base commit, its start time).
pub fn session_record(root: &str) -> (Option<String>, Option<String>) {
    let r = load(root).unwrap_or(json!({}));
    let get = |k: &str| r.get(k).and_then(|v| v.as_str()).filter(|v| !v.is_empty()).map(|v| v.to_string());
    (get("base"), get("started"))
}

/// One row of the unit table.
pub(crate) struct UnitRow {
    pub(crate) unit: String,
    pub(crate) lo: i64,
    pub(crate) hi: i64,
    pub(crate) status: String,
    pub(crate) start: String,
    pub(crate) end: String,
    pub(crate) named_by: Option<String>,
    pub(crate) functions: i64,
    pub(crate) undrafted: i64,
    pub(crate) open_bytes: i64,
}

pub(crate) fn unit_rows(v: &crate::layoutview::View) -> Vec<UnitRow> {
    let mut ufs: Vec<_> = v.unit_facts.iter().collect();
    ufs.sort_by_key(|f| f.lo);
    ufs.iter().map(|f| {
        let st = |k: &str| f.s(k).unwrap_or("").to_string();
        let n = |k: &str| f.value.get(k).and_then(|x| x.as_i64()).unwrap_or(0);
        UnitRow { unit: st("tu"), lo: f.lo, hi: f.hi, status: st("status"), start: st("start_level"), end: st("end_level"),
                  named_by: f.s("named_by").filter(|x| !x.is_empty()).map(|x| x.to_string()), functions: n("functions"),
                  undrafted: n("functions") - n("sourced"), open_bytes: n("open_bytes") }
    }).collect()
}

/// The layout view of a target's store, made once per state of its current runs (and of the drafts it reads).
pub(crate) fn view_of(p: &Project) -> Result<std::rc::Rc<crate::layoutview::View>> {
    let db = p.store_path();
    let main = p.main_uri();
    crate::pystore::st_open(&db, &main)?;
    let image = p.target(None).map_err(err)?.path.clone();
    let drafts = (crate::pystore::st_meta(&db, "drafts")?, crate::pystore::st_main_meta(&db, &main, "drafts")?);
    crate::store::derived(&db, &format!("view {main} {image} {drafts:?}"), || crate::layoutview::View::load(&db, &main, &image))
}

/// The unit table summary, the first open function, the toolchain level and the analyzer of one target.
pub fn session_overview(p: &crate::project::Project, analyzer: &str) -> Result<Vec<String>> {
    let v = view_of(p)?;
    let rows = unit_rows(&v);
    let (glo, ghi, _) = v.game;
    let covered: i64 = rows.iter().map(|r| r.hi - r.lo).sum();
    let funcs: Vec<i64> = v.funcs.iter().map(|f| f.lo).filter(|&a| glo <= a && a < ghi).collect();
    let drafted = funcs.iter().filter(|a| v.sources.contains_key(a)).count();
    let count = |st: &str| rows.iter().filter(|r| r.status == st).count() as i64;
    let mut out = vec![record(&[("target", s(p.target_name.clone())), ("units", Tok::I(rows.len() as i64)), ("separated", Tok::I(count("separated"))),
                                ("open", Tok::I(count("open"))), ("game", Tok::R(glo, ghi)), ("unassigned", s(format!("{:#x}", (ghi - glo) - covered))),
                                ("functions", Tok::I(funcs.len() as i64)), ("drafted", Tok::I(drafted as i64))])];
    for r in &rows[rows.len().saturating_sub(3)..] {
        out.push(format!("  {}", record(&[("unit", s(r.unit.clone())), ("range", Tok::R(r.lo, r.hi)), ("status", s(r.status.clone())),
                                          ("named_by", os(r.named_by.clone())), ("undrafted", Tok::I(r.undrafted)), ("open_bytes", Tok::I(r.open_bytes))])));
    }
    match v.first_open_item() {
        Some((a, kind, size)) => {
            let unit = v.unit_index(a).map(|i| v.units[i].tu.clone());
            out.push(format!("  {}", record(&[("next", Tok::I(a)), ("kind", s(kind)), ("size", Tok::I(size)), ("unit", os(unit)),
                                              ("analyzed", Tok::B(v.drafted.contains(&a)))])));
        }
        None => out.push("  next: nothing open in the game code (layout complete when every unit is separated and named)".into()),
    }
    let decl = p.toolchain_decl(None).map_err(err)?;
    let db = p.store_path();
    let probed = crate::with_db(&db, |c| crate::store::facts_of(c, &db, "toolchain", None, |f| &*f.rule == "M.flags.proven"))?;
    let mut proven: Vec<String> = probed.iter().filter(|f| f.level == crate::store::PROVEN).filter_map(|f| f.s("flag").map(|x| x.to_string())).collect();
    proven.sort();
    let compiler = decl["compiler"].as_str().filter(|c| !c.is_empty()).map(|c| c.to_string());
    let cflags = decl["cflags"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" ")).filter(|c| !c.is_empty());
    let level = if proven.is_empty() { "declared".to_string() } else { format!("proven:{}", proven.join(",")) };
    out.push(format!("  {}", record(&[("toolchain", os(compiler)), ("cflags", os(cflags)), ("level", s(level))])));
    let n = crate::with_db(&db, |c| crate::names::draft_values(c, &p.main_uri()))?.len();
    out.push(format!("  {}", if analyzer == "none" && n == 0 {
        record(&[("analyzer", s(analyzer))])
    } else {
        record(&[("analyzer", s(analyzer)), ("drafts", Tok::I(n as i64))])
    }));
    Ok(out)
}

// ------------------------------------------------------------------------------------------------ the changes

type Addr = (Option<String>, u64);

/// The first (target or None, address) of every own-line address comment among the lines.
fn comment_addrs<'a>(lines: impl Iterator<Item = &'a str>) -> HashSet<Addr> {
    lines.filter_map(|l| l.strip_prefix("/*")).filter_map(|b| crate::srcscan::lead_addrs(b).0.into_iter().next()).collect()
}

struct Changes {
    base: String,
    head: String,
    commits: usize,
    drafted: Vec<(String, i64, String)>, // (unit, addr, file)
    units_new: Vec<String>,
    units_gone: Vec<String>,
    decl_added: Vec<String>,
    decl_removed: Vec<String>,
    names: Vec<String>, // names.log lines since the base
}

/// What the session changed: the base commit against the working tree (committed or not).
fn changes(root: &str, base: &str) -> Result<Changes, String> {
    let own_addr = r"^/\*[[:space:]]*([A-Za-z][A-Za-z0-9_-]*:)?0x[0-9a-fA-F]";
    let then = comment_addrs(git(root, &["grep", "-h", "-E", own_addr, base, "--", "src"]).lines().map(|l| l.trim_end_matches('\r')));
    let mut drafted = vec![];
    for ((file, _, unit, _, addrs, _, _), _) in crate::frontend::scan(root, None)?.functions() {
        if let Some(first) = addrs.first().filter(|a| !then.contains(*a)) {
            drafted.push((unit.clone(), first.1 as i64, file.clone()));
        }
    }
    let src = py_path(&format!("{root}/src"));
    let stems = |names: Vec<String>| -> BTreeSet<String> { names.into_iter().filter_map(|n| n.strip_suffix(".c").map(|x| x.to_string())).collect() };
    let before = stems(git(root, &["ls-tree", "--name-only", &format!("{base}:src")]).split_whitespace().map(|x| x.to_string()).collect());
    let now: BTreeSet<String> = if Path::new(&src).exists() {
        stems(std::fs::read_dir(&src).into_iter().flatten().flatten().filter(|e| e.path().is_file()).map(|e| e.file_name().to_string_lossy().into_owned()).collect())
    } else {
        BTreeSet::new()
    };
    let old_decl: Vec<String> = git(root, &["show", &format!("{base}:decl/text.dcl")]).lines().map(|l| l.trim_end_matches('\r').to_string()).collect();
    let new_decl = read_lines(&py_path(&format!("{root}/decl/text.dcl")));
    let real = |l: &&String| !l.trim().is_empty() && !l.starts_with('#');
    let old_names: Vec<String> = git(root, &["show", &format!("{base}:names.log")]).lines().map(|l| l.trim_end_matches('\r').to_string()).collect();
    let new_names = read_lines(&py_path(&format!("{root}/names.log")));
    let names = if new_names.len() >= old_names.len() && new_names[..old_names.len()] == old_names[..] {
        new_names[old_names.len()..].to_vec()
    } else {
        new_names.iter().filter(|l| !old_names.contains(l)).cloned().collect()
    };
    Ok(Changes {
        base: base.chars().take(8).collect(),
        head: git(root, &["rev-parse", "--short", "HEAD"]).trim().to_string(),
        commits: git(root, &["rev-list", &format!("{base}..HEAD")]).split_whitespace().count(),
        drafted,
        units_new: now.difference(&before).cloned().collect(),
        units_gone: before.difference(&now).cloned().collect(),
        decl_added: new_decl.iter().filter(real).filter(|l| !old_decl.contains(l)).cloned().collect(),
        decl_removed: old_decl.iter().filter(real).filter(|l| !new_decl.contains(l)).cloned().collect(),
        names,
    })
}

/// The functions of one target whose grade differs from the baseline ledger/grades.tsv at the base commit: (addr,
/// unit, name, before `code+readability[ level]` or None for a new function, after or None for one gone).
#[allow(clippy::type_complexity)]
fn grade_changes(root: &str, base: &str, target: &str, rows: &[Map<String, Value>]) -> Vec<(i64, String, String, Option<String>, Option<String>)> {
    let fmt = |code: &str, rd: &str, level: &str| format!("{code}+{rd}") + &if level.is_empty() { String::new() } else { format!(" {level}") };
    let mut before: HashMap<i64, (String, String, String)> = HashMap::new();
    for line in git(root, &["show", &format!("{base}:ledger/grades.tsv")]).lines().skip(1) {
        let cols: Vec<&str> = line.trim_end_matches('\r').split('\t').collect();
        if cols.len() >= 7 && cols[0] == target {
            if let Ok(a) = i64::from_str_radix(cols[1].trim_start_matches("0x").trim_start_matches("0X"), 16) {
                before.insert(a, (cols[3].to_string(), cols[2].to_string(), fmt(cols[4], cols[5], cols[6])));
            }
        }
    }
    let st = |r: &Map<String, Value>, k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let mut out = vec![];
    let mut now: HashSet<i64> = HashSet::new();
    for r in rows {
        let addr = r.get("addr").and_then(|v| v.as_i64()).unwrap_or(0);
        now.insert(addr);
        let a = fmt(&st(r, "code"), &st(r, "readability"), &st(r, "level"));
        let b = before.get(&addr);
        if b.is_none_or(|b| b.2 != a) {
            out.push((addr, st(r, "unit"), st(r, "name"), b.map(|b| b.2.clone()), Some(a)));
        }
    }
    for (addr, (unit, name, b)) in &before {
        if !now.contains(addr) {
            out.push((*addr, unit.clone(), name.clone(), Some(b.clone()), None));
        }
    }
    out.sort();
    out
}

/// `dcp session wrap`'s report (written to build/session/report.md too): `targets` are (name, project, link ok or
/// None when skipped, the undrafted externals), `states` the gate's states now, `promoted` what promote printed.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn session_report(root: &str, base: &str, targets: Vec<(String, &crate::project::Project, Option<bool>, Option<usize>)>,
                      states: &Value, promoted: Option<String>, refused: bool, ok: bool) -> Result<String> {
    let rec = load(root).unwrap_or(json!({}));
    let c = changes(root, base).map_err(err)?;
    let mut out = vec![format!("# session {} (base {}, head {}, {} commits)", &iso(now())[..10], c.base, c.head, c.commits), String::new()];
    for (name, _, link, undrafted) in &targets {
        let (b, a) = (&rec["states"][name], &states[name]);
        let bv = |k: &str| b.get(k).map(|v| v.to_string()).unwrap_or_else(|| "?".into());
        let av = |k: &str| a.get(k).map(|v| v.to_string()).unwrap_or_default();
        let lk = if link.is_none_or(|l| l) { "ok" } else { "FAILED" };
        let und = if link.is_some() { format!(" ({} undrafted externals)", undrafted.unwrap_or(0)) } else { String::new() };
        out.push(format!("target {name}: errors {} -> {}, functions {} -> {}, byte {} -> {}, readable {} -> {}, units {} -> {} (separated {} -> {}), link {lk}{und}",
                         bv("errors"), av("errors"), bv("functions"), av("functions"), bv("byte"), av("byte"), bv("readable"), av("readable"),
                         bv("units"), av("units"), bv("separated"), av("separated")));
    }
    out.push(String::new());
    let unit_events: Vec<&String> = c.names.iter().filter(|l| l.contains(" unit ")).collect();
    let joined: Vec<&String> = unit_events.iter().copied().filter(|l| l.contains("why:join:")).collect();
    let renamed: Vec<&String> = unit_events.iter().copied().filter(|l| !joined.contains(l)).collect();
    let list = |xs: &[String]| if xs.is_empty() { "-".to_string() } else { xs.join(", ") };
    out.push(format!("units: declared {} ({}), joined {}, renamed {}, gone {} ({})", c.units_new.len(), list(&c.units_new), joined.len(), renamed.len(),
                     c.units_gone.len(), list(&c.units_gone)));
    out.extend(joined.iter().chain(&renamed).map(|l| format!("  {l}")));
    out.extend(c.decl_added.iter().map(|l| format!("  decl + {l}")));
    out.extend(c.decl_removed.iter().map(|l| format!("  decl - {l}")));
    out.push(String::new());
    let p = targets[0].1;
    let rows0 = crate::queues::function_grades(&p.store_path())?;
    let st = |r: &Map<String, Value>, k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let by_addr: HashMap<i64, &Map<String, Value>> = rows0.iter().map(|r| (r.get("addr").and_then(|v| v.as_i64()).unwrap_or(0), r)).collect();
    out.push(format!("functions drafted: {}", c.drafted.len()));
    let mut drafted = c.drafted.clone();
    drafted.sort_by_key(|d| d.1);
    for (unit, a, _) in &drafted {
        let g = match by_addr.get(a) {
            Some(r) => format!("{} + {}  {}", st(r, "code"), st(r, "readability"), st(r, "name")),
            None => "no grade (not compiled)".into(),
        };
        out.push(format!("  {}  {unit:<16} {g}", fmt_addr(*a)));
    }
    let drafted_at: HashSet<i64> = c.drafted.iter().map(|d| d.1).collect();
    let mut graded_units: HashSet<String> = HashSet::new();
    for (name, tp, _, _) in &targets {
        let rows = crate::queues::function_grades(&tp.store_path())?;
        let ch: Vec<_> = grade_changes(root, base, name, &rows).into_iter().filter(|x| !drafted_at.contains(&x.0) || x.3.is_some()).collect();
        graded_units.extend(ch.iter().map(|x| x.1.clone()));
        out.push(format!("grades changed ({name}): {}", ch.len()));
        for (a, unit, fname, b, aft) in ch {
            out.push(format!("  {}  {unit:<16} {fname}: {} -> {}", fmt_addr(a), b.unwrap_or_else(|| "new".into()), aft.unwrap_or_else(|| "gone".into())));
        }
    }
    let other: Vec<&String> = c.names.iter().filter(|l| !l.contains(" unit ")).collect();
    out.push(format!("renames: {}", other.len()));
    out.extend(other.iter().map(|l| format!("  {l}")));
    out.push(String::new());
    let v = view_of(p)?;
    let mut touched: HashSet<String> = c.units_new.iter().cloned().collect();
    touched.extend(c.drafted.iter().map(|d| d.0.clone()));
    touched.extend(unit_events.iter().filter_map(|l| l.split(" -> ").nth(1).and_then(|x| x.split_whitespace().next()).map(|x| x.to_string())));
    touched.extend(graded_units);
    out.push("units touched:".into());
    for r in unit_rows(&v).iter().filter(|r| touched.contains(&r.unit)) {
        out.push(format!("  {:<16} {}..{}  {:<9} start {} end {}  named_by {}  functions {} undrafted {} open_bytes {}", r.unit, fmt_addr(r.lo), fmt_addr(r.hi),
                         r.status, r.start, r.end, r.named_by.clone().unwrap_or_else(|| "-".into()), r.functions, r.undrafted, r.open_bytes));
    }
    out.push(String::new());
    match v.first_open_item() {
        Some((a, kind, size)) => {
            let unit = v.unit_index(a).map(|i| v.units[i].tu.clone()).unwrap_or_else(|| "-".into());
            out.push(format!("next: {} {kind} {size} bytes, unit {unit}", fmt_addr(a)));
        }
        None => {
            // layout complete: the next item of the base queue (dcp next)
            let q = crate::queues::queue(&p.store_path(), "base", None, None)?;
            out.push("next: nothing open in the game code; ".to_string() + &match q.first() {
                Some(r) => format!("base queue {} {} ({}, {} + {}), {} items", fmt_addr(r.get("addr").and_then(|v| v.as_i64()).unwrap_or(0)), st(r, "name"),
                                   st(r, "unit"), st(r, "code"), st(r, "readability"), q.len()),
                None => "the base queue is empty".into(),
            });
        }
    }
    if let Some(pr) = promoted.filter(|p| !p.is_empty()) {
        let mut lines = pr.lines();
        let first = lines.next().unwrap_or("");
        out.push(format!("baseline: {first}{}", if refused { " (nothing written: dcp accept each fall wanted on purpose, then dcp promote)" }
                         else { " (commit ledger/grades.tsv with the session)" }));
        if refused {
            out.extend(lines.map(|l| l.to_string()));
        }
    }
    out.push(format!("gate: {}", if ok { "ok" } else { "FAIL" }));
    let text = out.join("\n") + "\n";
    crate::edit::write(&py_path(&format!("{root}/build/session/report.md")), &text).map_err(err)?;
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(root: &str, args: &[&str]) {
        assert!(std::process::Command::new("git").args(args).current_dir(root).output().unwrap().status.success(), "git {args:?}");
    }

    /// The session report's grade changes: the function grades against the baseline ledger/grades.tsv at the
    /// session's base commit.
    #[test]
    fn grades_against_the_base() {
        let dir = std::env::temp_dir().join(format!("dcp-session-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("ledger")).unwrap();
        let root = dir.to_string_lossy().into_owned();
        run(&root, &["init", "-q"]);
        run(&root, &["config", "user.email", "t@example.com"]);
        run(&root, &["config", "user.name", "t"]);
        std::fs::write(dir.join("ledger/grades.tsv"), "target\taddress\tname\tunit\tcode\treadability\tlevel\n\
                                                       exe\t0x00401000\tf\tu\tdraft\tdraft\t\n\
                                                       exe\t0x00401040\tg\tu\tshape\treadable\t\n\
                                                       exe\t0x00401080\th\tu\tdraft\tdraft\t\n\
                                                       dll\t0x10001000\tx\tv\tdraft\tdraft\t\n").unwrap();
        run(&root, &["add", "-A"]);
        run(&root, &["commit", "-q", "-m", "base"]);
        let base = session_head(&root);
        let row = |a: i64, n: &str, c: &str, r: &str, l: &str| -> Map<String, Value> {
            json!({"addr": a, "unit": "u", "name": n, "code": c, "readability": r, "level": l}).as_object().unwrap().clone()
        };
        let rows = [row(0x401000, "f", "shape", "readable", ""), row(0x401040, "g", "shape", "readable", ""), row(0x4010c0, "k", "draft", "draft", "deep")];
        let some = |x: &str| Some(x.to_string());
        assert_eq!(grade_changes(&root, &base, "exe", &rows), [
            (0x401000, "u".to_string(), "f".to_string(), some("draft+draft"), some("shape+readable")),
            (0x401080, "u".to_string(), "h".to_string(), some("draft+draft"), None), // gone since the base
            (0x4010c0, "u".to_string(), "k".to_string(), None, some("draft+draft deep"))]); // new, escalated
        let _ = std::fs::remove_dir_all(&dir);
    }
}
