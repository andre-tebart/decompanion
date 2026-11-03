//! The match-phase commands' output (the CLI builds and refreshes first, then prints these lines): grade,
//! next, asmdiff, diffclass, promote, accept, link, toolchain probe, lint. One record per line, key=value tokens,
//! addresses 0x%08x, counts before lists.

use crate::error::{Error, Result};
use crate::cliread::{fmt_addr, record, Tok};
use crate::project::{py_path, Project};
use crate::queues::{self, Entry};
use crate::shape::Shape;
use serde_json::{Map, Value};
use std::path::Path;

/// (lines, error for stderr as `dcp CMD: error`, exit code).
type Out = (Vec<String>, Option<String>, i32);

type Row = Map<String, Value>;

fn err(e: impl std::fmt::Display) -> Error {
    Error::runtime(e.to_string())
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

fn opened(p: &crate::project::Project) -> Result<String> {
    let db = p.store_path();
    crate::storedb::st_open(&db, &p.main_uri())?;
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
    out.push(record(&[("fn", Tok::I(int(r, "addr"))), ("name", vt(r.get("name"))), ("unit", vt(r.get("unit"))), ("experiment", vt(r.get("code"))),
                      ("readability", vt(r.get("readability"))), ("tag", s(level)), ("dist", s(dist_text(r.get("dist")))), ("file", vt(r.get("file")))]));
    if verbose {
        out.extend(failing(r).iter().map(|x| format!("  {x}")));
        // the references φ cannot decide: not checked (the reference check, refcheck.rs)
        if let Some(Value::Array(o)) = r.get("open") {
            out.extend(o.iter().filter_map(|x| x.as_str()).map(|x| format!("  open: {x}")));
        }
        // the consistency convention (§8.8): calls without a declaration, the experiment's side
        if let Some(Value::Array(c)) = r.get("consistency") {
            let calls: Vec<&str> = c.iter().filter_map(|x| x.as_str()).collect();
            out.push(format!("  M7 consistency: {}", calls[..calls.len().min(6)].join(", ")));
        }
    }
}

/// `dcp grade [WHAT]`: the experiments (byte / shape / draft) and readability apart; without an argument the matrix
/// and the unit table; a unit: its functions with the failing
/// rules; a function (name or address): its grades, the failing rules with evidence, the distance. `lint`: where the
/// consistency calls (M7) come from.
pub fn grade_command(p: &crate::project::Project, what: Option<String>, lint: &str) -> Result<Out> {
    let db = opened(p)?;
    let rows = queues::function_grades(&db)?;
    let units = queues::unit_grades(&db)?;
    let mut out = vec![];
    let Some(what) = what.filter(|w| !w.is_empty()) else {
        out.push(format!("{}  ({lint})", record(&[("target", s(p.target_name.clone())), ("functions", Tok::I(rows.len() as i64)),
                                                 ("units", Tok::I(units.len() as i64))])));
        out.push(format!("  {:<10} {:>7} {:>9} {:>7}", "experiment", "draft", "readable", "total"));
        for code in ["byte", "shape", "draft", crate::grade::NOT_RUN] {
            let n = |rd: &str| rows.iter().filter(|r| st(r, "code") == code && st(r, "readability") == rd).count();
            let (d, rd) = (n("draft"), n("readable"));
            // open: not run (its unit has no object), listed only when there is one
            if code != crate::grade::NOT_RUN || d + rd > 0 {
                out.push(format!("  {code:<10} {d:>7} {rd:>9} {:>7}", d + rd));
            }
        }
        for u in units.iter() {
            out.push(format!("  {}", record(&[("unit", vt(u.get("unit"))), ("range", Tok::R(int(u, "lo"), int(u, "hi"))), ("experiment", vt(u.get("code"))),
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
        out.push(record(&[("unit", vt(u.get("unit"))), ("functions", Tok::I(fs.len() as i64)), ("experiment", vt(u.get("code"))),
                          ("readability", vt(u.get("readability"))), ("named_by", vt(u.get("named_by"))), ("byte", c("byte")), ("shape", c("shape")),
                          ("draft", c("draft")), ("readable", Tok::I(fs.iter().filter(|r| st(r, "readability") == "readable").count() as i64))]) + why);
        return Ok((out, None, 0));
    }
    let Some(Value::Object(r)) = crate::asmcmd::find_function(&db, &what)? else {
        return Ok((out, Some(crate::clicmd::not_found(p, format!("{what} is neither a unit nor a graded function of target {}", p.target_name))?), 1));
    };
    function_lines(&mut out, &r, true);
    if let Some(Value::Object(h)) = r.get("hunks").filter(|h| h.as_object().is_some_and(|m| !m.is_empty())) {
        let mut hs: Vec<(&String, i64)> = h.iter().map(|(k, v)| (k, v.as_i64().unwrap_or(0))).collect();
        hs.sort_by_key(|x| -x.1);
        out.push(format!("  hunks: {}", hs.iter().map(|(k, v)| format!("{k} {v}")).collect::<Vec<_>>().join(", ")));
    }
    out.push(format!("  ({lint})"));
    Ok((out, None, 0))
}

/// `dcp next`: the next functions of a queue (base, deep, names), of a shard (`--shard k/N`, else .dcp/shard).
pub fn next_command(p: &crate::project::Project, which: &str, shard: Option<String>, unit: Option<String>, n: usize) -> Result<Out> {
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
                          ("experiment", vt(r.get("code"))), ("readability", vt(r.get("readability"))), ("gates", os(Some(g).filter(|g| !g.is_empty()))),
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
fn reading(p: &Project, key: &str, cmd: &str, symbols: bool) -> Result<Result<crate::asmcmd::Reading, Out>> {
    let db = opened(p)?;
    let Some(row) = crate::asmcmd::find_function(&db, key)? else {
        return Ok(Err((vec![], Some(format!("no graded function {key}")), 1)));
    };
    let name = row["name"].as_str().unwrap_or("").to_string();
    let names = if symbols { Some(crate::names::Names::build(&db, &p.main_uri(), &p.target(None).map_err(Error::runtime)?.path)?) } else { None };
    match crate::asmcmd::reading(p, row, names.as_ref())? {
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

/// The reference check's differences as asmdiff and diffclass print them: `literal:` for a string or a floating
/// constant (M9 / M10), `ref:` for a named object (M8); `shape`: the verdict stands (the named references cross,
/// a proof shows the effects the same).
fn ref_lines(r: &crate::asmcmd::Reading, shape: bool) -> Vec<String> {
    r.ref_lines.iter().map(|l| {
        let what = if l.starts_with("M8") { "ref" } else { "literal" };
        let why = if shape { "the references cross: the proof shows the effects the same" } else { "a meaning difference: draft" };
        format!("  {what}: {l} ({why})")
    }).collect()
}

/// Our references outside their object (M.contain, ill-formed whatever the bytes compare), one line each.
fn contain_lines(r: &crate::asmcmd::Reading) -> Vec<String> {
    r.outside.iter().map(|(_, l)| format!("  contain: {l}")).collect()
}

/// asmdiff's diff: (the differing lines, the frames when aligned, the printed lines). a / b the texts compared, pa /
/// pb the texts printed (named with --symbols); same(i, j): the named lines i and j refer to the same addresses or
/// literals under other names (Reading::same_values).
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
fn diff_lines(la: &[crate::x86::Line], lb: &[crate::x86::Line], a: &[String], b: &[String], sa: &[Shape], sb: &[Shape], pa: &[String], pb: &[String],
              plain: bool, all: bool, same: &dyn Fn(usize, usize) -> bool, addresses: &dyn Fn(usize, usize) -> Option<String>,
              refs: &dyn Fn(usize) -> Option<String>) -> (usize, Option<(i64, i64)>, Vec<String>) {
    // the frames differ: align with the stack offsets masked; an aligned pair that differs only by the shift is equal
    let frame = if plain { None } else { crate::shape::frame_delta(sa, sb) };
    let ops = match frame {
        Some(f) => crate::difflib::opcodes(&crate::shape::stack_mask(sa, f), &crate::shape::stack_mask(sb, f)),
        None => crate::difflib::opcodes(&a, &b),
    };
    use crate::difflib::Tag;
    // an aligned pair: 0 the same text, 1 the same text naming other symbols (--symbols), 4 the same text naming
    // the same addresses or literals by other names, 2 shifted by the frame, 3 differing, 5 the same text whose
    // reference the reference check finds another (refcheck.rs: whatever the names print)
    let kind = |i: usize, j: usize| -> u8 {
        if a[i] == b[j] {
            if refs(i).is_some() {
                5
            } else if pa[i] == pb[j] {
                0
            } else if same(i, j) {
                4
            } else {
                1
            }
        } else if frame.is_some_and(|f| crate::shape::frame_explain(&sa[i..=i], &sb[j..=j], f).is_some()) {
            2
        } else {
            3
        }
    };
    let n = match frame {
        Some(f) => crate::diffclass::frame_distance(sa, sb, f),
        None => crate::diffclass::distance(a, b),
    };
    let mut out = vec![];
    let mut crossed = 0;
    for (tag, i1, i2, j1, j2) in ops {
        if tag == Tag::Equal {
            // runs of lines that print alike (equal or shifted by the frame: folded when long); a line whose names
            // differ (--symbols) is always printed, `!`, ours | the original's; a line the frame does not explain
            // is a difference
            let mut i = i1;
            while i < i2 {
                let group = |i: usize| match kind(i, j1 + i - i1) { 2 => 0, k => k };
                let mut e = i + 1;
                while e < i2 && group(e) == group(i) {
                    e += 1;
                }
                match group(i) {
                    1 => out.extend((i..e).map(|k| {
                        let at = addresses(k, j1 + k - i1).map(|x| format!("   ({x})")).unwrap_or_default();
                        format!("!  {:#010x}  {}   | {}{at}", la[k].addr, pa[k], pb[j1 + k - i1])
                    })),
                    4 => out.extend((i..e).map(|k| format!("=  {:#010x}  {}   | {}", la[k].addr, pa[k], pb[j1 + k - i1]))),
                    5 => {
                        crossed += e - i;
                        out.extend((i..e).map(|k| format!("!  {:#010x}  {}   | {}   ({})", la[k].addr, pa[k], pb[j1 + k - i1], refs(k).unwrap_or_default())));
                    }
                    3 => {
                        out.extend((i..e).map(|k| format!("-  {:#010x}  {}", la[k].addr, pa[k])));
                        out.extend((i..e).map(|k| format!("+  {:#010x}  {}", lb[j1 + k - i1].addr, pb[j1 + k - i1])));
                    }
                    _ if e - i > 6 && !all => {
                        let shifted = (i..e).filter(|&k| kind(k, j1 + k - i1) == 2).count();
                        let tail = if shifted > 0 { format!(", {shifted} shifted by the frame") } else { String::new() };
                        out.push(format!("     ... {} equal instructions{tail} ...", e - i));
                    }
                    _ => out.extend((i..e).map(|k| format!("{}  {:#010x}  {}", if kind(k, j1 + k - i1) == 2 { "~" } else { " " }, la[k].addr, pa[k]))),
                }
                i = e;
            }
            continue;
        }
        out.extend((i1..i2).map(|i| format!("-  {:#010x}  {}", la[i].addr, pa[i])));
        out.extend((j1..j2).map(|j| format!("+  {:#010x}  {}", lb[j].addr, pb[j])));
    }
    (n + crossed, frame, out)
}

/// `dcp asmdiff`: the instruction diff of one function, ours ('-') against the original ('+'), both listed at the
/// original address (numbers that are image addresses and our relocated fields read X); `regs` renames registers
/// of ours (`eax=ecx,ecx=eax`). `symbols`: the lines print the names for X (our relocations' symbols, the ledger's
/// labels of the original's addresses, else the number); the alignment still compares the X texts. When the frames
/// differ in size (diffclass's frame alignment), the lines are aligned with their stack offsets masked and a line
/// that differs from the original's only by the frame's shift counts as equal (`~` when printed); `plain`: the
/// diff of the texts as they are.
/// Which lines of asmdiff's listing print (`--changed`, `--at`, `--context`, `--side`).
pub struct View {
    pub changed: bool,
    pub at: Option<String>,
    pub context: Option<usize>,
    pub side: Option<String>,
}

/// The lines of an aligned listing (every line: `all`) that `--changed` / `--at` keep: the differing lines (or the
/// line at the address) with `context` lines around each, a gap as `... N lines ...`.
fn window(body: Vec<String>, view: &View) -> std::result::Result<Vec<String>, String> {
    let addr_of = |l: &str| l.get(3..13).and_then(|h| i64::from_str_radix(h.trim_start_matches("0x"), 16).ok());
    let differs = |l: &str| matches!(l.as_bytes().first(), Some(b'-' | b'+' | b'!' | b'='));
    let mut keep = vec![false; body.len()];
    let mut mark = |k: usize, n: usize| {
        for x in keep.iter_mut().take((k + n + 1).min(body.len())).skip(k.saturating_sub(n)) {
            *x = true;
        }
    };
    if let Some(at) = &view.at {
        let a = crate::cliread::parse_addr(at)?;
        let n = view.context.unwrap_or(20);
        let k = body.iter().position(|l| addr_of(l).is_some_and(|x| x >= a)).ok_or_else(|| format!("--at {at}: past the function's last line"))?;
        mark(k, n);
    }
    if view.changed {
        let n = view.context.unwrap_or(3);
        for k in (0..body.len()).filter(|&k| differs(&body[k])) {
            mark(k, n);
        }
    }
    let mut out = vec![];
    let mut gap = 0;
    for (l, k) in body.into_iter().zip(keep) {
        if k {
            if gap > 0 {
                out.push(format!("     ... {gap} line{} ...", if gap == 1 { "" } else { "s" }));
                gap = 0;
            }
            out.push(l);
        } else {
            gap += 1;
        }
    }
    if gap > 0 {
        out.push(format!("     ... {gap} line{} ...", if gap == 1 { "" } else { "s" }));
    }
    Ok(out)
}

pub fn asmdiff_command(p: &crate::project::Project, name: &str, regs: Option<String>, all: bool, symbols: bool,
                       plain: bool, view: View) -> Result<Out> {
    let r = match reading(p, name, "asmdiff", symbols)? {
        Ok(r) => r,
        Err(o) => return Ok(o),
    };
    let mut a: Vec<String> = r.la.iter().map(|x| x.text.clone()).collect();
    let mut ka: Vec<Shape> = r.la.iter().map(|x| x.shape.clone()).collect();
    let kb: Vec<Shape> = r.lb.iter().map(|x| x.shape.clone()).collect();
    let (mut sa, sb) = r.named.clone().unwrap_or_default();
    // --regs auto: the renaming most of the function agrees on (shape::voted_renaming), printed in the header
    let mut voted = None;
    if let Some(m) = regs.filter(|x| !x.is_empty()) {
        let pairs: Vec<(String, String)> = if m == "auto" {
            let v = crate::shape::voted_renaming(&ka, &kb);
            voted = Some(v.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(","));
            v
        } else {
            m.split(',').map(|x| {
                let (k, v) = x.split_once('=').unwrap_or((x, ""));
                (k.to_string(), v.to_string())
            }).collect()
        };
        a = crate::x86::rename_registers(&a, &pairs);
        sa = crate::x86::rename_registers(&sa, &pairs);
        if let Some(map) = crate::shape::reg_map(&pairs.iter().map(|(k, v)| (crate::x86::full_reg(k), crate::x86::full_reg(v))).collect::<Vec<_>>()) {
            ka = ka.iter().map(|s| crate::shape::rename(s, &map)).collect();
        }
    }
    let b: Vec<String> = r.lb.iter().map(|x| x.text.clone()).collect();
    // what a line prints: its X text, or with --symbols its named text
    let (pa, pb) = if r.named.is_some() { (&sa, &sb) } else { (&a, &b) };
    let img = if r.values.is_some() { Some(crate::image(&p.target(None).map_err(Error::runtime)?.path)?) } else { None };
    let same = |i: usize, j: usize| img.as_ref().is_some_and(|img| r.same_values(img, i, j));
    // a window (--changed, --at) cuts the whole listing; one side (--side) prints its own lines in its own order
    let windowed = view.changed || view.at.is_some();
    // our lines whose reference the check finds another: what each refers to on both sides
    let mut crossed: std::collections::HashMap<u32, Vec<String>> = Default::default();
    for x in r.refs.differs() {
        crossed.entry(x.ins).or_default().push(format!("{}: {}", x.rule, x.pair()));
    }
    for (field, _) in &r.outside {
        if let Some(l) = r.la.iter().find(|l| l.addr <= *field && *field < l.addr + l.size) {
            crossed.entry(l.addr).or_default().push("M.contain: outside its object".into());
        }
    }
    let refs = |i: usize| crossed.get(&r.la[i].addr).map(|v| v.join("; "));
    let (n, frame, mut body) = diff_lines(&r.la, &r.lb, &a, &b, &ka, &kb, pa, pb, plain, all || windowed, &same, &|i, j| r.addresses(i, j), &refs);
    if let Some(side) = &view.side {
        body = if side == "ours" {
            r.la.iter().zip(pa).map(|(l, t)| format!("   {:#010x}  {t}", l.addr)).collect()
        } else {
            r.lb.iter().zip(pb).map(|(l, t)| format!("   {:#010x}  {t}", l.addr)).collect()
        };
    }
    if windowed {
        body = match window(body, &view) {
            Ok(b) => b,
            Err(e) => return Ok((vec![], Some(e), 2)),
        };
    }
    let row = r.row.as_object().cloned().unwrap_or_default();
    let mut head = record(&[("fn", Tok::I(int(&row, "addr"))), ("name", vt(row.get("name"))), ("code", vt(row.get("code"))), ("ours", Tok::I(a.len() as i64)),
                            ("original", Tok::I(b.len() as i64)), ("differing", Tok::I(n as i64))]);
    if let Some((fa, fb)) = frame {
        head += &format!("  {}", record(&[("frame", s(format!("{fa:#x}/{fb:#x}")))]));
    }
    if let Some(v) = &voted {
        head += &format!("  {}", record(&[("regs", s(if v.is_empty() { "none".to_string() } else { v.clone() }))]));
    }
    // the returns of each side, when they differ: tails merged or duplicated (diffclass's tail class)
    let rets = |l: &[crate::x86::Line]| l.iter().filter(|x| x.shape.mn == "ret").count();
    if rets(&r.la) != rets(&r.lb) {
        head += &format!("  {}", record(&[("returns", s(format!("{}/{}", rets(&r.la), rets(&r.lb))))]));
    }
    if let Some(t) = &r.tables {
        head += &format!("  {}", tables_tokens(t));
    }
    // the reference check: concrete differences (counted in `differing` too) and the references φ cannot decide
    let nref = r.refs.differs().count();
    let nopen = r.refs.open().count();
    if nref > 0 || nopen > 0 {
        head += &format!("  {}", record(&[("refs_differ", Tok::I(nref as i64)), ("refs_open", Tok::I(nopen as i64))]));
    }
    let open_lines: Vec<String> = r.open_lines.iter().map(|l| format!("  open: {l}")).collect();
    let mut out = vec![head];
    if let Some((fa, fb)) = frame {
        out.push(format!("  frame: ours {fa:#x}, the original's {fb:#x}: stack offsets aligned, a line that differs only by the shift counts \
                          as equal ('~' ours); --plain diffs the texts as they are"));
    }
    if n > 0 {
        out.push("  legend: '-' ours (our object), '+' the original (the image)".into());
    }
    out.extend(r.calls_line().map(|l| format!("  {l}")));
    let proved = matches!(r.proof.0, crate::equiv::Outcome::Equal { .. });
    out.extend(ref_lines(&r, crate::grade::code_grade(false, r.verdict.shape, proved, &r.refs) == "shape"));
    out.extend(contain_lines(&r));
    out.extend(open_lines);
    if !crossed.is_empty() {
        out.push("  refs: '!' on an equal line: the original's field refers to another object or other bytes than ours (ours | the \
                  original's); the listing reads both as X".into());
    }
    if r.named.is_some() {
        out.push("  symbols: ours by our relocations, the original's by the ledger; '!' the same instruction naming another symbol \
                  (ours | the original's); '=' naming the same address or literal by another name (an alias: no error)".into());
    }
    out.extend(body);
    Ok((out, None, 0))
}

/// The lines of a `code` hunk diffclass prints per side (asmdiff prints them all); `all`: every line.
const HUNK_LINES: usize = 8;

/// `dcp diffclass`: the hunks of one function's instruction diff with their classes (diffclass.rs); a `code` hunk
/// with its lines, the first HUNK_LINES of each side and how many more (`all`: every line).
pub fn diffclass_command(p: &crate::project::Project, name: &str, all: bool) -> Result<Out> {
    let r = match reading(p, name, "diffclass", false)? {
        Ok(r) => r,
        Err(o) => return Ok(o),
    };
    let (la, lb) = (&r.la, &r.lb);
    let row = r.row.as_object().cloned().unwrap_or_default();
    let v = &r.verdict;
    // the code grade G.grade gives (grade::code_grade): the shape classes or a proof, and every reference of ours
    // the original's (the reference check, refcheck.rs)
    let proved = matches!(r.proof.0, crate::equiv::Outcome::Equal { .. });
    let verdict = match crate::grade::code_grade(false, v.shape, proved, &r.refs) {
        "shape" if !v.shape || r.refs.named_differs() => "shape (proved)",
        g => g,
    };
    let mut out = vec![record(&[("fn", Tok::I(int(&row, "addr"))), ("name", vt(row.get("name"))), ("ours", Tok::I(la.len() as i64)),
                                ("original", Tok::I(lb.len() as i64)), ("hunks", Tok::I(r.hunks.len() as i64)), ("differing", Tok::I(v.distance as i64)),
                                ("verdict", s(verdict))])];
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
    if !v.into_code.is_empty() {
        out.push(format!("  jumps into code hunks: targets the alignment pairs differ inside or at a code hunk (its difference): {}",
                         v.into_code.join("; ")));
    }
    for (i1, i2, j1, j2, cls, info) in &r.hunks {
        let at = if *i1 < la.len() { la[*i1].addr } else { lb[*j1].addr };
        out.push(format!("  {at:#010x}  {cls:<6} {:>4}  {info}", i2 - i1 + j2 - j1));
        if cls == "code" {
            // a small hunk whole (as before: up to 12 lines), else the first lines of each side
            let keep = if all || i2 - i1 + j2 - j1 <= 12 { usize::MAX } else { HUNK_LINES };
            for (sign, lines, whose) in [("-", &la[*i1..*i2], "ours"), ("+", &lb[*j1..*j2], "the original's")] {
                out.extend(lines.iter().take(keep).map(|x| format!("      {sign} {}", x.text)));
                if lines.len() > keep {
                    out.push(format!("      {sign} ... (+{} more of {whose}: --all, or dcp asmdiff)", lines.len() - keep));
                }
            }
        }
    }
    out.push(format!("  summary: {}", v.summary_without_branches()));
    out.extend(r.calls_line().map(|l| format!("  {l}")));
    out.extend(ref_lines(&r, verdict != "draft"));
    out.extend(contain_lines(&r));
    out.extend(r.open_lines.iter().map(|l| format!("  open: {l}")));
    let (proof, unbound) = &r.proof;
    let base = int(&row, "addr") as u32;
    out.push(format!("  proof: {}{}", proof.summary(base),
                     if *unbound > 0 { format!("; {unbound} of our relocations without a site that lines up") } else { String::new() }));
    if let Some(w) = &r.witness {
        out.push(format!("  differs: {w} (a meaning difference: dcp escalate refuses it)"));
    }
    Ok((out, None, 0))
}

// ------------------------------------------------------------------------------------------------ promote / accept

fn baseline_path(root: &str) -> String {
    py_path(&format!("{root}/ledger/grades.tsv"))
}

fn read_baseline(root: &str) -> String {
    crate::fsmemo::read_text(&baseline_path(root)).unwrap_or_default()
}

fn write_baseline(root: &str, text: &str) -> Result<()> {
    let path = baseline_path(root);
    if let Some(d) = Path::new(&path).parent() {
        std::fs::create_dir_all(d).map_err(err)?;
    }
    std::fs::write(&path, text).map_err(err)?;
    crate::fsmemo::new_epoch();
    Ok(())
}

/// `dcp promote` (every target built): ledger/grades.tsv from the current grades of every target; refused when the
/// source (src/, include/, decl/) has uncommitted changes, and when a grade fell against it unless `accept_falls`.
pub fn promote_command(root: &str, projects: &[Project], accept_falls: bool) -> Result<Out> {
    // a witness is a commit (docs/mental-model.md §8.6): grades of uncommitted source are in no history
    let dirty = crate::session::source_dirty(root);
    if !dirty.is_empty() {
        let mut out = vec![record(&[("promote", s("refused")), ("dirty", Tok::I(dirty.len() as i64))])
            + "  (the source is not committed: commit or revert src/, include/ and decl/ first, then promote)"];
        out.extend(dirty.iter().take(10).map(|l| format!("  dirty {l}")));
        if dirty.len() > 10 {
            out.push(format!("  ... {} more (git status)", dirty.len() - 10));
        }
        return Ok((out, None, 1));
    }
    let old = read_baseline(root);
    let mut targets = vec![];
    let mut falls = vec![];
    // a function not run has no grade to write: the baseline would lose its entry (not even --accept-falls)
    let mut unbuilt = vec![];
    for p in projects {
        let db = opened(p)?;
        unbuilt.extend(queues::not_run(&db)?.into_iter().map(|(u, n)| format!("  unbuilt: {} unit {u}: {n} function(s) not run", p.target_name)));
    }
    if !unbuilt.is_empty() {
        let mut out = vec![record(&[("promote", s("refused")), ("unbuilt", Tok::I(unbuilt.len() as i64))])
            + "  (a unit has no object: its functions have no experiment; fix the compile (dcp check: M.compile), then promote)"];
        out.extend(unbuilt);
        return Ok((out, None, 1));
    }
    for p in projects {
        let db = opened(p)?;
        falls.extend(queues::regressions(&p.target_name, &db, &old)?);
        targets.push((p.target_name.clone(), db));
    }
    if !falls.is_empty() && !accept_falls {
        let mut out = vec![record(&[("promote", s("refused")), ("falls", Tok::I(falls.len() as i64))])
            + "  (promote raises entries only: dcp debt add FN --to GRADE --why TEXT [--waits-for WHAT] for a fall wanted on purpose, --accept-falls takes them all)"];
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

/// `dcp debt add FN --to GRADE --why TEXT [--waits-for WHAT]`: declare a regression (docs/mental-model.md §8.6): lower one
/// function's baseline entry to the grade it fell to, its accepted column the grade before, the last witness commit,
/// the reason and what it waits for (M1 then holds it there and lists it as debt).
pub fn debt_add_command(project: Option<&Project>, name: &str, to: Option<String>, readability: Option<String>, why: Option<String>,
                        waits_for: Option<String>) -> Result<Out> {
    let refuse = |m: String| Ok((vec![], Some(m), 1));
    let why = why.unwrap_or_default().split_whitespace().collect::<Vec<_>>().join(" ");
    if why.is_empty() {
        return refuse("a reason is required (--why TEXT)".into());
    }
    if to.as_deref().unwrap_or("").is_empty() && readability.as_deref().unwrap_or("").is_empty() {
        return refuse("--to shape|draft or --readability draft says what the entry falls to".into());
    }
    let Some(p) = project else { return Err(err("debt_add_command: no project")) };
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
    let note = queues::debt_note(&queues::note_from(&o.accepted).unwrap_or(grade_o.clone()), &grade_to, &commit, &why, waits_for.as_deref().unwrap_or(""));
    write_baseline(&root, &queues::grades_accept(&old, &p.target_name, addr, &to_code, &to_rd, &note))?;
    Ok((vec![record(&[("debt", s(fmt_addr(addr))), ("name", vt(r.get("name"))), ("target", s(p.target_name.clone())), ("was", s(grade_o)),
                      ("now", s(grade_to)), ("witness", s(commit)), ("waits_for", os(waits_for.filter(|w| !w.trim().is_empty())))])
             + "  (commit ledger/grades.tsv with the change; dcp check holds it at the declared grade and lists it as debt)"], None, 0))
}

/// `dcp debt list`: every debt item of the baseline, per target, with the gate's bound.
pub fn debt_list_command(p: &Project) -> Vec<String> {
    let root = p.root.to_string_lossy().into_owned();
    let items = queues::debts(&read_baseline(&root));
    let mut out = vec![record(&[("debt", Tok::I(items.len() as i64)), ("max_debt", if p.max_debt() < 0 { s("none") } else { Tok::I(p.max_debt()) })])];
    for d in &items {
        out.push(format!("  {}", record(&[("target", s(d.target.clone())), ("fn", s(fmt_addr(d.addr))), ("name", s(d.name.clone())), ("was", s(d.was.clone())),
                                          ("now", s(d.now.clone())), ("witness", s(d.witness.clone())), ("why", s(d.why.clone())),
                                          ("waits_for", os(Some(d.waits_for.clone()).filter(|w| !w.is_empty())))])));
    }
    out
}

// ------------------------------------------------------------------------------------------------ link

/// The full link of the current target (link.rs): (the report lines, ok, the `link:` reason of a failed link for
/// `dcp check`, the undrafted externals, the gate's detail lines of a failed link).
pub fn link_command(p: &crate::project::Project) -> Result<(Vec<String>, bool, Option<String>, usize, Vec<String>)> {
    link_lines(p)
}

/// A link report's lines (the record, the unresolved externals by class, notes, errors) and whether it linked.
pub(crate) fn link_report_lines(r: &crate::link::LinkReport) -> (Vec<String>, bool) {
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
    (out, r.ok)
}

#[allow(clippy::type_complexity)]
pub(crate) fn link_lines(p: &crate::project::Project) -> Result<(Vec<String>, bool, Option<String>, usize, Vec<String>)> {
    let r = crate::link::full_link(p).map_err(err)?;
    let (out, _) = link_report_lines(&r);
    let class = |k: &str| r.unresolved.iter().find(|(c, _)| c == k).map(|(_, v)| v.as_slice()).unwrap_or(&[]);
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
pub fn probe_report(p: &crate::project::Project, result: &Value) -> Result<Vec<String>> {
    let res = result.clone();
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
    let mut out = vec![record(&[("target", s(p.target_name.clone())), ("anchors", Tok::I(users.len() as i64)), ("crt_anchors", Tok::I(crts.len() as i64)),
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

/// What `dcp grade` / `dcp next` do about the consistency calls (M7) before they read the grades: ("lint", note) when a unit changed
/// since the last lint and libclang is there (the caller lints and refreshes, then prints the note), else ("", note).
pub fn lint_plan(p: &crate::project::Project) -> Result<(String, String)> {
    let Some(stale) = crate::lintrun::stale(p).map_err(err)? else {
        return Ok((String::new(), "consistency (M7) not evaluated (no lint run: dcp lint)".into()));
    };
    if stale.is_empty() {
        return Ok((String::new(), "consistency (M7) current".into()));
    }
    if crate::frontend::library(Some(&p.cfg)).is_some() {
        return Ok(("lint".into(), format!("consistency (M7) linted now ({} changed units)", stale.len())));
    }
    Ok((String::new(), format!("consistency (M7) stale: {} units changed, libclang not found", stale.len())))
}

/// What `dcp lint` says without libclang.
pub fn lint_not_found() -> &'static str {
    "libclang not found ([lint] libclang = ... in decompanion.toml, or an LLVM installation: clang on PATH or C:/Program Files/LLVM)"
}

/// `dcp lint` of the current target: lint every unit (lintrun.rs) and report M6 / M5 / M7; (lines, failed).
pub fn lint_command(p: &crate::project::Project) -> Result<(Vec<String>, bool)> {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// promote refuses grades of uncommitted source (src/, include/, decl/); the ledger's own changes do not count.
    #[test]
    fn promote_refuses_dirty_source() {
        let d = std::env::temp_dir().join(format!("dcp-promote-dirty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let root = d.to_string_lossy().replace('\\', "/");
        let git = |args: &[&str]| assert!(std::process::Command::new("git").args(args).current_dir(&d).output().unwrap().status.success());
        crate::testkit::write(&d, "ledger/grades.tsv", "target\taddress\n");
        git(&["init", "-q"]);
        crate::testkit::write(&d, "notes.md", "x");
        assert!(crate::session::source_dirty(&root).is_empty()); // the ledger, a note: not H's source
        crate::testkit::write(&d, "include/net.h", "int f(void);\n");
        let (out, _, code) = promote_command(&root, &[], false).unwrap();
        assert!(code == 1 && out[0].starts_with("promote=refused  dirty=1") && out[1] == "  dirty ?? include/net.h", "{out:?}");
        assert_eq!(read_baseline(&root), "target\taddress\n");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn asmdiff_windows() {
        let body: Vec<String> = (0..20u32).map(|k| {
            let m = if k == 10 { "-" } else if k == 11 { "+" } else { " " };
            format!("{m}  {:#010x}  nop", 0x1000 + k)
        }).collect();
        let v = |changed, at: Option<&str>, context| View { changed, at: at.map(|x| x.to_string()), context, side: None };
        let w = window(body.clone(), &v(true, None, Some(1))).unwrap();
        assert_eq!(w, ["     ... 9 lines ...", "   0x00001009  nop", "-  0x0000100a  nop", "+  0x0000100b  nop", "   0x0000100c  nop",
                       "     ... 7 lines ..."]);
        let w = window(body.clone(), &v(false, Some("0x1002"), Some(2))).unwrap();
        assert_eq!(w.first().map(|s| s.as_str()), Some("   0x00001000  nop"));
        assert_eq!(w.len(), 6); // 0x1000..0x1004 and the gap
        assert!(window(body, &v(false, Some("0x2000"), None)).is_err());
    }

    /// A frame 4 bytes larger shifts every stack offset: aligned, only the store that differs otherwise is a
    /// difference (a match-base report: hundreds of lines differed by the shift alone).
    #[test]
    fn asmdiff_aligns_frames() {
        let body = ["sub esp, {f}", "mov eax, dword ptr [esp + {arg}]", "mov dword ptr [esp + 0x10], eax", "mov ecx, 3", "mov edx, 4",
                    "lea ecx, [esp + {loc}]", "push ecx", "call X", "{st}", "add esp, {f}", "ret"];
        let f = |fr: &str, arg: &str, loc: &str, st: &str| -> (Vec<crate::x86::Line>, Vec<String>) {
            let ts: Vec<String> = body.iter().map(|t| t.replace("{f}", fr).replace("{arg}", arg).replace("{loc}", loc).replace("{st}", st)).collect();
            (ts.iter().enumerate().map(|(k, t)| crate::x86::Line::of(0x1000 + k as u32, t, false, None)).collect(), ts)
        };
        let (la, a) = f("0xcc", "0xd0", "0x7c", "mov dword ptr [esp + 0x14], ecx");
        let (lb, b) = f("0xc8", "0xcc", "0x78", "mov dword ptr [esp + 0x14], 0");
        let sh = |l: &[crate::x86::Line]| l.iter().map(|x| x.shape.clone()).collect::<Vec<_>>();
        let (sa, sb) = (sh(&la), sh(&lb));
        let (n, frame, out) = diff_lines(&la, &lb, &a, &b, &sa, &sb, &a, &b, false, true, &|_, _| false, &|_, _| None, &|_| None);
        assert_eq!((n, frame), (2, Some((0xcc, 0xc8))));
        assert_eq!(out.iter().filter(|l| l.starts_with('-') || l.starts_with('+')).collect::<Vec<_>>(),
                   ["-  0x00001008  mov dword ptr [esp + 0x14], ecx", "+  0x00001008  mov dword ptr [esp + 0x14], 0"]);
        assert!(out.contains(&"~  0x00001001  mov eax, dword ptr [esp + 0xd0]".to_string()) && out.contains(&"   0x00001003  mov ecx, 3".to_string()));
        let (n, frame, _) = diff_lines(&la, &lb, &a, &b, &sa, &sb, &a, &b, true, true, &|_, _| false, &|_, _| None, &|_| None);
        assert_eq!((n, frame), (10, None)); // --plain: the shifted lines differ
        // the reference check finds the call's target another: `!` on the equal line, counted (a match-base report:
        // a wrong callee or literal behind X folded into the equal run)
        let refs = |i: usize| (i == 7).then(|| "M8: f 0x401000 | 0x402000".to_string());
        let (n, _, out) = diff_lines(&la, &lb, &a, &b, &sa, &sb, &a, &b, false, false, &|_, _| false, &|_, _| None, &refs);
        assert_eq!(n, 3);
        assert!(out.contains(&"!  0x00001007  call X   | call X   (M8: f 0x401000 | 0x402000)".to_string()), "{out:?}");
    }
}
