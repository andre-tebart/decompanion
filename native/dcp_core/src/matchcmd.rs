//! The match-phase commands' output (the Python face builds and refreshes first, then prints these lines): grade,
//! next, asmdiff, diffclass, promote, accept, link, toolchain probe, lint. One record per line, key=value tokens,
//! addresses 0x%08x, counts before lists.

use crate::cliread::{fmt_addr, record, Tok};
use crate::project::{py_path, PyProject};
use crate::queues::{self, Entry};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use serde_json::{Map, Value};
use std::path::Path;

/// (lines, error for stderr as `dcp CMD: error`, exit code).
type Out = (Vec<String>, Option<String>, i32);

type Row = Map<String, Value>;

fn err(e: impl std::fmt::Display) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

fn s(x: impl Into<String>) -> Tok {
    Tok::S(x.into())
}

fn os(x: Option<impl Into<String>>) -> Tok {
    x.map(|v| Tok::S(v.into())).unwrap_or(Tok::No)
}

/// A JSON value as a token (None for null, a count or an address for a number).
fn vt(v: Option<&Value>) -> Tok {
    match v {
        None | Some(Value::Null) => Tok::No,
        Some(Value::Bool(b)) => Tok::B(*b),
        Some(Value::Number(n)) => n.as_i64().map(Tok::I).unwrap_or_else(|| s(n.to_string())),
        Some(Value::String(x)) => s(x.clone()),
        Some(v) => s(v.to_string()),
    }
}

fn st<'a>(r: &'a Row, k: &str) -> &'a str {
    r.get(k).and_then(|v| v.as_str()).unwrap_or("")
}

fn int(r: &Row, k: &str) -> i64 {
    r.get(k).and_then(|v| v.as_i64()).unwrap_or(0)
}

fn opened(p: &crate::project::Project) -> PyResult<String> {
    let db = p.store_path();
    crate::pystore::st_open(&db, &p.main_uri())?;
    Ok(db)
}

fn dist_text(d: Option<&Value>) -> String {
    match d {
        Some(d) if d.get("ins").is_some_and(|x| !x.is_null()) => {
            let g = |k: &str| d.get(k).map(|v| v.to_string()).unwrap_or_default();
            format!("{} ins / {} bytes, size {} vs {}", g("ins"), g("bytes"), g("size"), g("orig"))
        }
        _ => "-".into(),
    }
}

fn failing(r: &Row) -> Vec<String> {
    r.get("failing").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(|x| x.to_string())).collect()).unwrap_or_default()
}

/// The gates (B* / Q*) among the failing rules, once each.
fn gates(r: &Row) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    for x in failing(r) {
        let k = x.split(' ').next().unwrap_or("").to_string();
        if !out.contains(&k) && (k.starts_with('B') || k.starts_with('Q')) {
            out.push(k);
        }
    }
    out
}

fn function_lines(out: &mut Vec<String>, r: &Row, verbose: bool) {
    let level = match r.get("level") {
        Some(Value::String(l)) if !l.is_empty() => l.clone(),
        _ => "-".into(),
    };
    out.push(record(&[("fn", Tok::I(int(r, "addr"))), ("name", vt(r.get("name"))), ("unit", vt(r.get("unit"))), ("code", vt(r.get("code"))),
                      ("readability", vt(r.get("readability"))), ("level", s(level)), ("dist", s(dist_text(r.get("dist")))), ("file", vt(r.get("file")))]));
    if verbose {
        out.extend(failing(r).iter().map(|x| format!("  {x}")));
    }
}

/// `dcp grade [WHAT]`: without an argument the matrix and the unit table; a unit: its functions with the failing
/// rules; a function (name or address): its grades, the failing rules with evidence, the distance. `q7`: where Q7
/// comes from.
#[pyfunction]
#[pyo3(signature = (project, what, q7))]
pub fn grade_command(project: PyRef<'_, PyProject>, what: Option<String>, q7: &str) -> PyResult<Out> {
    let p = &project.p;
    let db = opened(p)?;
    let rows = queues::function_grades(&db)?;
    let units = queues::unit_grades(&db)?;
    let mut out = vec![];
    let Some(what) = what.filter(|w| !w.is_empty()) else {
        out.push(format!("{}  ({q7})", record(&[("target", s(p.target_name.clone())), ("functions", Tok::I(rows.len() as i64)),
                                                 ("units", Tok::I(units.len() as i64))])));
        out.push(format!("  {:<8} {:>7} {:>9} {:>7}", "code", "draft", "readable", "total"));
        for code in ["byte", "shape", "draft"] {
            let n = |rd: &str| rows.iter().filter(|r| st(r, "code") == code && st(r, "readability") == rd).count();
            let (d, rd) = (n("draft"), n("readable"));
            out.push(format!("  {code:<8} {d:>7} {rd:>9} {:>7}", d + rd));
        }
        for u in units.iter() {
            out.push(format!("  {}", record(&[("unit", vt(u.get("unit"))), ("range", Tok::R(int(u, "lo"), int(u, "hi"))), ("code", vt(u.get("code"))),
                                              ("readability", vt(u.get("readability"))), ("functions", vt(u.get("functions"))),
                                              ("named_by", vt(u.get("named_by")))])));
        }
        return Ok((out, None, 0));
    };
    if let Some(u) = units.iter().find(|u| st(u, "unit") == what) {
        let fs: Vec<&Row> = rows.iter().filter(|r| st(r, "unit") == st(u, "unit")).collect();
        for r in &fs {
            function_lines(&mut out, r, true);
        }
        let all_readable = fs.iter().all(|r| st(r, "readability") == "readable");
        let why = if st(u, "readability") != "readable" && matches!(st(u, "named_by"), "guess" | "-") && all_readable { "  (unit name origin guess)" } else { "" };
        let c = |code: &str| Tok::I(fs.iter().filter(|r| st(r, "code") == code).count() as i64);
        out.push(record(&[("unit", vt(u.get("unit"))), ("functions", Tok::I(fs.len() as i64)), ("code", vt(u.get("code"))),
                          ("readability", vt(u.get("readability"))), ("named_by", vt(u.get("named_by"))), ("byte", c("byte")), ("shape", c("shape")),
                          ("draft", c("draft")), ("readable", Tok::I(fs.iter().filter(|r| st(r, "readability") == "readable").count() as i64))]) + why);
        return Ok((out, None, 0));
    }
    let Some(Value::Object(r)) = crate::asmcmd::find_function(&db, &what)? else {
        return Ok((out, Some(format!("{what} is neither a unit nor a graded function of target {}", p.target_name)), 1));
    };
    function_lines(&mut out, &r, true);
    if let Some(Value::Object(h)) = r.get("hunks").filter(|h| h.as_object().is_some_and(|m| !m.is_empty())) {
        let mut hs: Vec<(&String, i64)> = h.iter().map(|(k, v)| (k, v.as_i64().unwrap_or(0))).collect();
        hs.sort_by_key(|x| -x.1);
        out.push(format!("  hunks: {}", hs.iter().map(|(k, v)| format!("{k} {v}")).collect::<Vec<_>>().join(", ")));
    }
    out.push(format!("  ({q7})"));
    Ok((out, None, 0))
}

/// `dcp next`: the next functions of a queue (base, deep, names), of a shard (`--shard k/N`, else .dcp/shard).
#[pyfunction]
#[pyo3(signature = (project, which, shard, unit, n))]
pub fn next_command(project: PyRef<'_, PyProject>, which: &str, shard: Option<String>, unit: Option<String>, n: usize) -> PyResult<Out> {
    let p = &project.p;
    let db = opened(p)?;
    let text = match shard.filter(|x| !x.is_empty()) {
        Some(x) => Some(x),
        None => std::fs::read_to_string(p.root.join(".dcp").join("shard")).ok(),
    };
    let shard = match text.map(|t| queues::parse_shard(&t)).transpose() {
        Ok(x) => x.flatten(),
        Err(e) => return Ok((vec![], Some(e), 2)),
    };
    let items = queues::queue(&db, which, shard, unit.as_deref())?;
    let sh = shard.map(|(k, n)| format!("{k}/{n}"));
    let mut out = vec![record(&[("target", s(p.target_name.clone())), ("queue", s(which)), ("items", Tok::I(items.len() as i64)), ("shard", os(sh.clone())),
                                ("unit", os(unit))])];
    for r in items.iter().take(n) {
        let g = gates(r).join(",");
        out.push(record(&[("next", Tok::I(int(r, "addr"))), ("name", vt(r.get("name"))), ("unit", vt(r.get("queue_unit"))), ("section", vt(r.get("section"))),
                          ("code", vt(r.get("code"))), ("readability", vt(r.get("readability"))), ("gates", os(Some(g).filter(|g| !g.is_empty()))),
                          ("dist", s(dist_text(r.get("dist")))), ("file", vt(r.get("file")))]));
    }
    if items.is_empty() {
        out.push(format!("nothing in the {which} queue{}", sh.map(|x| format!(" of shard {x}")).unwrap_or_default()));
    }
    Ok((out, None, 0))
}

// ------------------------------------------------------------------------------------------------ asmdiff / diffclass

/// One graded function's reading, or the lines to stop with: no such function (exit 1), no reading (a
/// configuration error, as the Python raised it).
fn reading(project: &PyProject, capstone: &str, key: &str, cmd: &str) -> PyResult<Result<crate::asmcmd::Reading, Out>> {
    let p = &project.p;
    let db = opened(p)?;
    let Some(row) = crate::asmcmd::find_function(&db, key)? else {
        return Ok(Err((vec![], Some(format!("no graded function {key}")), 1)));
    };
    let name = row["name"].as_str().unwrap_or("").to_string();
    match crate::asmcmd::reading(p, capstone, row)? {
        Ok(r) => Ok(Ok(r)),
        Err(why) => {
            let _ = cmd;
            Err(crate::project::cfg_err(format!("{name}: {why}")))
        }
    }
}

fn tables_tokens(t: &crate::diffclass::Tables) -> String {
    record(&[("tables", s(if t.diffs.is_empty() { "equal" } else { "differ" })), ("entries", Tok::I(t.entries)), ("index_bytes", Tok::I(t.bytes))])
}

/// `dcp asmdiff`: the instruction diff of one function, ours ('-') against the original ('+'), both listed at the
/// original address (numbers that are image addresses and our relocated fields read X); `regs` renames registers
/// of ours (`eax=ecx,ecx=eax`).
#[pyfunction]
#[pyo3(signature = (project, capstone, name, regs, all))]
pub fn asmdiff_command(project: PyRef<'_, PyProject>, capstone: &str, name: &str, regs: Option<String>, all: bool) -> PyResult<Out> {
    let r = match reading(&project, capstone, name, "asmdiff")? {
        Ok(r) => r,
        Err(o) => return Ok(o),
    };
    let mut a: Vec<String> = r.la.iter().map(|x| x.text.clone()).collect();
    if let Some(m) = regs.filter(|x| !x.is_empty()) {
        let pairs: Vec<(String, String)> = m.split(',').map(|x| {
            let (k, v) = x.split_once('=').unwrap_or((x, ""));
            (k.to_string(), v.to_string())
        }).collect();
        a = crate::x86::rename_registers(&a, &pairs);
    }
    let b: Vec<String> = r.lb.iter().map(|x| x.text.clone()).collect();
    let ops = crate::difflib::opcodes(&a, &b);
    use crate::difflib::Tag;
    let n: usize = ops.iter().filter(|o| o.0 != Tag::Equal).map(|o| o.2 - o.1 + o.4 - o.3).sum();
    let row = r.row.as_object().cloned().unwrap_or_default();
    let mut head = record(&[("fn", Tok::I(int(&row, "addr"))), ("name", vt(row.get("name"))), ("code", vt(row.get("code"))), ("ours", Tok::I(a.len() as i64)),
                            ("original", Tok::I(b.len() as i64)), ("differing", Tok::I(n as i64))]);
    if let Some(t) = &r.tables {
        head += &format!("  {}", tables_tokens(t));
    }
    let mut out = vec![head];
    if n > 0 {
        out.push("  legend: '-' ours (our object), '+' the original (the image)".into());
    }
    for (tag, i1, i2, j1, j2) in ops {
        if tag == Tag::Equal {
            if i2 - i1 > 6 && !all {
                out.push(format!("     ... {} equal instructions ...", i2 - i1));
                continue;
            }
            out.extend((i1..i2).map(|i| format!("   {:#010x}  {}", r.la[i].addr, a[i])));
            continue;
        }
        out.extend((i1..i2).map(|i| format!("-  {:#010x}  {}", r.la[i].addr, a[i])));
        out.extend((j1..j2).map(|j| format!("+  {:#010x}  {}", r.lb[j].addr, b[j])));
    }
    Ok((out, None, 0))
}

/// `dcp diffclass`: the hunks of one function's instruction diff with their classes (diffclass.rs).
#[pyfunction]
pub fn diffclass_command(project: PyRef<'_, PyProject>, capstone: &str, name: &str) -> PyResult<Out> {
    let r = match reading(&project, capstone, name, "diffclass")? {
        Ok(r) => r,
        Err(o) => return Ok(o),
    };
    let (la, lb) = (&r.la, &r.lb);
    let row = r.row.as_object().cloned().unwrap_or_default();
    let v = &r.verdict;
    let mut out = vec![record(&[("fn", Tok::I(int(&row, "addr"))), ("name", vt(row.get("name"))), ("ours", Tok::I(la.len() as i64)),
                                ("original", Tok::I(lb.len() as i64)), ("hunks", Tok::I(r.hunks.len() as i64)), ("differing", Tok::I(v.distance as i64)),
                                ("verdict", s(if v.shape { "shape" } else { "draft" }))])];
    if let Some((ours, orig)) = v.frame {
        out.push(format!("  frame: ours {ours:#x}, the original's {orig:#x}: the hunks of the frame-aligned diff (stack offsets masked for the alignment)"));
    }
    if let Some(t) = &r.tables {
        out.push(format!("  {}", tables_tokens(t)));
        out.extend(t.diffs.iter().map(|d| format!("      {d}")));
    }
    if !v.branches.is_empty() {
        out.push(format!("  branch targets differ ({}): jumps the alignment pairs go to other code", v.branches.len()));
        out.extend(v.branches.iter().map(|d| format!("      {d}")));
    }
    for (i1, i2, j1, j2, cls, info) in &r.hunks {
        let at = if *i1 < la.len() { la[*i1].addr } else { lb[*j1].addr };
        out.push(format!("  {at:#010x}  {cls:<6} {:>4}  {info}", i2 - i1 + j2 - j1));
        if cls == "code" && i2 - i1 + j2 - j1 <= 12 {
            out.extend(la[*i1..*i2].iter().map(|x| format!("      - {}", x.text)));
            out.extend(lb[*j1..*j2].iter().map(|x| format!("      + {}", x.text)));
        }
    }
    out.push(format!("  summary: {}", v.summary()));
    Ok((out, None, 0))
}

// ------------------------------------------------------------------------------------------------ promote / accept

fn baseline_path(root: &str) -> String {
    py_path(&format!("{root}/ledger/grades.tsv"))
}

fn read_baseline(root: &str) -> String {
    crate::fsmemo::read_text(&baseline_path(root)).unwrap_or_default()
}

fn write_baseline(root: &str, text: &str) -> PyResult<()> {
    let path = baseline_path(root);
    if let Some(d) = Path::new(&path).parent() {
        std::fs::create_dir_all(d).map_err(err)?;
    }
    std::fs::write(&path, text).map_err(err)?;
    crate::fsmemo::new_epoch();
    Ok(())
}

/// `dcp promote` (every target built): ledger/grades.tsv from the current grades of every target; refused when a
/// grade fell against it unless `accept_falls`.
#[pyfunction]
pub fn promote_command(root: &str, projects: Vec<PyRef<'_, PyProject>>, accept_falls: bool) -> PyResult<Out> {
    let old = read_baseline(root);
    let mut targets = vec![];
    let mut falls = vec![];
    for p in &projects {
        let db = opened(&p.p)?;
        falls.extend(queues::regressions(&p.p.target_name, &db, &old)?);
        targets.push((p.p.target_name.clone(), db));
    }
    if !falls.is_empty() && !accept_falls {
        let mut out = vec![record(&[("promote", s("refused")), ("falls", Tok::I(falls.len() as i64))])
            + "  (promote raises entries only: dcp accept FN --to GRADE --why TEXT for a fall wanted on purpose, --accept-falls takes them all)"];
        out.extend(falls.iter().map(|f| format!("  fell: {f}")));
        return Ok((out, None, 1));
    }
    let text = queues::baseline_text(&targets, &old, accept_falls, &queues::grades_commit_of(root))?;
    let accepted = queues::parse_baseline(&text).iter().filter(|x| !x.1.accepted.is_empty()).count();
    write_baseline(root, &text)?;
    let n = text.matches('\n').count() as i64 - 1;
    let mut out = vec![record(&[("promoted", s("ledger/grades.tsv")), ("functions", Tok::I(n)), ("targets", Tok::I(projects.len() as i64)),
                                ("falls_against_old", Tok::I(falls.len() as i64)), ("accepted", Tok::I(accepted as i64))])];
    out.extend(falls.iter().map(|f| format!("  fell (accepted): {f}")));
    Ok((out, None, 0))
}

const CODE: [&str; 3] = ["draft", "shape", "byte"];

/// `dcp accept FN --to GRADE --why TEXT`: lower one function's baseline entry to the grade it fell to, with the
/// reason (M1 then holds it there).
#[pyfunction]
#[pyo3(signature = (project, name, to, readability, why))]
pub fn accept_command(project: Option<PyRef<'_, PyProject>>, name: &str, to: Option<String>, readability: Option<String>, why: Option<String>) -> PyResult<Out> {
    let refuse = |m: String| Ok((vec![], Some(m), 1));
    let why = why.unwrap_or_default().split_whitespace().collect::<Vec<_>>().join(" ");
    if why.is_empty() {
        return refuse("a reason is required (--why TEXT)".into());
    }
    if to.as_deref().unwrap_or("").is_empty() && readability.as_deref().unwrap_or("").is_empty() {
        return refuse("--to shape|draft or --readability draft says what the entry falls to".into());
    }
    let Some(project) = project else { return Err(err("accept_command: no project")) };
    let p = &project.p;
    let root = p.root.to_string_lossy().into_owned();
    let old = read_baseline(&root);
    let db = opened(p)?;
    let Some(Value::Object(r)) = crate::asmcmd::find_function(&db, name)? else {
        return refuse(format!("no graded function {name} (dcp build first)"));
    };
    let addr = int(&r, "addr");
    let Some((_, o)) = queues::parse_baseline(&old).into_iter().find(|x| x.0 .0 == p.target_name && x.0 .1 == addr) else {
        return refuse(format!("{} is not in the baseline ledger/grades.tsv: it cannot fall", st(&r, "name")));
    };
    let o: Entry = o;
    let mut to_code = to.filter(|x| !x.is_empty()).unwrap_or_else(|| o.code.clone());
    let to_rd = readability.filter(|x| !x.is_empty()).unwrap_or_else(|| o.readability.clone());
    let grade_o = format!("{}+{}", o.code, o.readability);
    if queues::at_least(&to_code, &to_rd, &grade_o) {
        return refuse(format!("{to_code}+{to_rd} is no fall from the baseline's {grade_o}"));
    }
    let grade_to = format!("{to_code}+{to_rd}");
    let grade_r = format!("{}+{}", st(&r, "code"), st(&r, "readability"));
    if !queues::at_least(st(&r, "code"), st(&r, "readability"), &grade_to) {
        return refuse(format!("{} is {grade_r} now, below {grade_to}: accept the grade it has (or fix it)", st(&r, "name")));
    }
    let rank = |c: &str| CODE.iter().position(|x| *x == c);
    if rank(&to_code) > rank(&o.code) {
        // --readability alone never raises the code
        to_code = o.code.clone();
    }
    let grade_to = format!("{to_code}+{to_rd}");
    let commit = queues::grades_commit_of(&root);
    let note = queues::accept_note(&queues::note_from(&o.accepted).unwrap_or(grade_o.clone()), &grade_to, &commit, &why);
    write_baseline(&root, &queues::grades_accept(&old, &p.target_name, addr, &to_code, &to_rd, &note))?;
    Ok((vec![record(&[("accepted", s(fmt_addr(addr))), ("name", vt(r.get("name"))), ("target", s(p.target_name.clone())), ("was", s(grade_o)),
                      ("now", s(grade_to)), ("commit", s(commit))])
             + "  (commit ledger/grades.tsv with the change; dcp check holds it at the accepted grade)"], None, 0))
}

// ------------------------------------------------------------------------------------------------ link

/// The full link of the current target (link.rs): (the report lines, ok, the `link:` reason of a failed link for
/// `dcp check`, the undrafted externals, the gate's detail lines of a failed link).
#[pyfunction]
pub fn link_command(project: PyRef<'_, PyProject>) -> PyResult<(Vec<String>, bool, Option<String>, usize, Vec<String>)> {
    link_lines(&project.p)
}

#[allow(clippy::type_complexity)]
pub(crate) fn link_lines(p: &crate::project::Project) -> PyResult<(Vec<String>, bool, Option<String>, usize, Vec<String>)> {
    let r = crate::link::full_link(p).map_err(err)?;
    let n: usize = r.unresolved.iter().map(|(_, v)| v.len()).sum();
    let mut head = record(&[("link", s(r.target.clone())), ("ok", Tok::B(r.ok)), ("objects", Tok::I(r.objects as i64)), ("includes", Tok::I(r.includes as i64)),
                            ("unresolved", Tok::I(n as i64)), ("errors", Tok::I(r.errors.len() as i64)), ("out", os(Some(r.out.clone()).filter(|o| !o.is_empty()))),
                            ("cached", Tok::B(r.cached)), ("ms", Tok::I(r.ms))]);
    if !r.skipped.is_empty() {
        head += &format!("  skipped: {}", r.skipped);
    }
    let mut out = vec![head];
    let class = |k: &str| r.unresolved.iter().find(|(c, _)| c == k).map(|(_, v)| v.as_slice()).unwrap_or(&[]);
    for k in ["data", "renames", "aliases", "undrafted", "library", "other"] {
        let lines = class(k);
        if !lines.is_empty() {
            out.push(format!("  unresolved {k}={}", lines.len()));
            out.extend(lines.iter().take(20).map(|l| format!("    {l}")));
        }
    }
    out.extend(r.notes.iter().map(|x| format!("  note {x}")));
    out.extend(r.errors.iter().take(20).map(|x| format!("  error {x}")));
    let reason = (!r.ok).then(|| {
        let classes: Vec<String> = r.unresolved.iter().filter(|(k, v)| !v.is_empty() && k != "undrafted").map(|(k, v)| format!("{k}={}", v.len())).collect();
        format!("link:{}{}", classes.join(","), if r.errors.is_empty() { String::new() } else { format!(",errors={}", r.errors.len()) })
    });
    let mut gate = vec![];
    if !r.ok {
        for (k, lines) in r.unresolved.iter().filter(|(k, _)| k != "undrafted") {
            gate.extend(lines.iter().take(10).map(|l| format!("    unresolved {k}: {l}")));
        }
        gate.extend(r.errors.iter().take(5).map(|x| format!("    link error: {x}")));
    }
    Ok((out, r.ok, reason, class("undrafted").len(), gate))
}

// ------------------------------------------------------------------------------------------------ probe

/// `dcp toolchain probe`'s report of a probe result (probe.rs; the analysis mrules.rs).
#[pyfunction]
pub fn probe_report(project: PyRef<'_, PyProject>, result: &Bound<'_, PyAny>) -> PyResult<Vec<String>> {
    let res = crate::pystore::py_value(result)?;
    let an = crate::mrules::analyse(&res);
    let arr = |v: &Value| v.as_array().cloned().unwrap_or_default();
    let anchors = arr(&res["anchors"]);
    let users: Vec<&Value> = anchors.iter().filter(|a| a["kind"] == "user").collect();
    let crts: Vec<&Value> = anchors.iter().filter(|a| a["kind"] == "crt").collect();
    let combos = arr(&res["combos"]);
    let refused = combos.iter().filter(|c| c["refused"].as_bool().unwrap_or(false)).count();
    let crt_units: std::collections::BTreeSet<String> = crts.iter().filter_map(|a| a["unit"].as_str().map(|x| x.to_string())).collect();
    let crt_ids: std::collections::BTreeSet<String> = crts.iter().map(|a| a["id"].to_string()).collect();
    let crt_failed: std::collections::BTreeSet<String> = combos.iter().flat_map(|c| arr(&c["failed"]))
        .filter_map(|u| u.as_str().map(|x| x.to_string())).filter(|u| crt_units.contains(u)).collect();
    let crt_matched: std::collections::BTreeSet<String> = combos.iter().flat_map(|c| arr(&c["matched"])).map(|a| a.to_string())
        .filter(|a| crt_ids.contains(a)).collect();
    let mut out = vec![record(&[("target", s(project.p.target_name.clone())), ("anchors", Tok::I(users.len() as i64)), ("crt_anchors", Tok::I(crts.len() as i64)),
                                ("combinations", Tok::I(combos.len() as i64)), ("refused", Tok::I(refused as i64)), ("compiles", vt(res.get("compiles"))),
                                ("cached", Tok::I(res.get("cached").and_then(|v| v.as_i64()).unwrap_or(0))), ("ms", vt(res.get("ms")))])];
    if !crts.is_empty() {
        out.push(format!("  {}  (CRT anchors are reported apart: another compiler build, the library's own flags)",
                         record(&[("crt_sources", Tok::I(crt_units.len() as i64)), ("crt_sources_failing", Tok::I(crt_failed.len() as i64)),
                                  ("crt_anchors_matched_somewhere", Tok::I(crt_matched.len() as i64))])));
    }
    for a in &users {
        out.push(format!("  {}", record(&[("anchor", vt(a.get("id"))), ("name", vt(a.get("name"))), ("unit", vt(a.get("unit")))])));
    }
    let words = |v: &Value| arr(v).iter().filter_map(|x| x.as_str().map(|x| x.to_string())).collect::<Vec<_>>().join(" ");
    if an["best"].is_null() {
        out.push("  no combination the compiler accepts".into());
        return Ok(out);
    }
    out.push(format!("  {}", record(&[("best", s(words(&an["best"]["flags"]))), ("matched", s(format!("{}/{}", an["matched"], users.len()))),
                                      ("declared", s(words(&res["declared"])))])));
    for x in arr(&an["ranked"]) {
        out.push(format!("    {}", record(&[("matched", vt(x.get(0))), ("flags", s(words(&x[1])))])));
    }
    for g in arr(&an["groups"]) {
        let n = |k: &str| arr(&g[k]).len();
        let verdict = if g["alternatives"].as_i64().unwrap_or(0) == 0 {
            "fixed in the grid (no alternative)".to_string()
        } else if n("anchors") > 0 {
            format!("distinguished by {} anchors from {} units", n("anchors"), n("units"))
        } else if n("ruled_out") > 0 {
            format!("indistinguishable from {} ({} anchors rule out the other alternatives)", words(&g["same_as"]), n("ruled_out"))
        } else {
            "indistinguishable".to_string()
        };
        let crt = if n("crt_anchors") > 0 { format!("  (crt anchors: {})", n("crt_anchors")) } else { String::new() };
        out.push(format!("  {}  {verdict}{crt}", record(&[("flag", vt(g.get("flag"))), ("group", vt(g.get("group")))])));
    }
    Ok(out)
}

// ------------------------------------------------------------------------------------------------ lint

/// What `dcp grade` / `dcp next` do about Q7 before they read the grades: ("lint", note) when a unit changed
/// since the last lint and libclang is there (the caller lints and refreshes, then prints the note), else ("", note).
#[pyfunction]
pub fn lint_plan(project: PyRef<'_, PyProject>) -> PyResult<(String, String)> {
    let p = &project.p;
    let Some(stale) = crate::lintrun::stale(p).map_err(err)? else {
        return Ok((String::new(), "Q7 not evaluated (no lint run: dcp lint)".into()));
    };
    if stale.is_empty() {
        return Ok((String::new(), "Q7 current".into()));
    }
    if crate::frontend::library(Some(&p.cfg)).is_some() {
        return Ok(("lint".into(), format!("Q7 linted now ({} changed units)", stale.len())));
    }
    Ok((String::new(), format!("Q7 stale: {} units changed, libclang not found", stale.len())))
}

/// What `dcp lint` says without libclang.
#[pyfunction]
pub fn lint_not_found() -> &'static str {
    "libclang not found ([lint] libclang = ... in decompanion.toml, or an LLVM installation: clang on PATH or C:/Program Files/LLVM)"
}

/// `dcp lint` of the current target: lint every unit (lintrun.rs) and report M6 / M5 / M7; (lines, failed).
#[pyfunction]
pub fn lint_command(project: PyRef<'_, PyProject>) -> PyResult<(Vec<String>, bool)> {
    let p = &project.p;
    let (v, parsed, cached) = crate::lintrun::lint(p).map_err(err)?;
    p.forget_input("lint");
    let strs = |k: &str| v[k].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(|x| x.to_string())).collect::<Vec<_>>()).unwrap_or_default();
    let (errors, cross) = (strs("errors"), strs("cross"));
    let calls = v["calls"].as_object().cloned().unwrap_or_default();
    let ncalls: usize = calls.values().map(|c| c.as_array().map_or(0, |a| a.len())).sum();
    let units = v["units"].as_object().map_or(0, |u| u.len());
    let mut out = vec![record(&[("lint", s(p.target_name.clone())), ("units", Tok::I(units as i64)), ("parsed", Tok::I(parsed as i64)), ("cached", Tok::I(cached as i64)),
                                ("m6", Tok::I(errors.len() as i64)), ("m5", Tok::I(cross.len() as i64)), ("m7", Tok::I(ncalls as i64))])];
    out.extend(errors.iter().map(|x| format!("  M6 {x}")));
    out.extend(cross.iter().map(|x| format!("  M5 {x}")));
    for (f, cs) in &calls {
        for c in cs.as_array().into_iter().flatten() {
            out.push(format!("  M7 {f}: {}", c.get(1).and_then(|x| x.as_str()).unwrap_or("")));
        }
    }
    Ok((out, !errors.is_empty() || !cross.is_empty()))
}
