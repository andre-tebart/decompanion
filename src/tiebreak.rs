//! Declaration-set tie-breaks: VC6 /O2 breaks ties in its register allocation
//! by the declaration set a unit sees, so a change in a widely included header (a union member, a field, an unused
//! typedef) moves functions that never use the changed type between byte, shape and draft. That is the headers'
//! business, not the function's: the object experiment would be reporting on something else.
//!
//! The probe is the experiment that measures it once instead of per change: the unit compiled as the build compiles
//! it (the control) and with a no-meaning perturbation before its text (PROBES: unused typedefs, one, two, three and
//! one of another name), each function graded as G.grade grades it. A function whose bytes change under any probe
//! is tie-break sensitive: a change is proof, an observation, not a guess. Its best grade over the control and the
//! probes is its source-proven grade: a declaration set exists under which its text gives it.
//!
//! The records are kept in ledger/tiebreak.tsv (written by `dcp headers probe` and by `dcp build` when a function
//! of the baseline fell and has no record; never by hand): target, address, name, unit, the hash of the function's
//! text (comments and whitespace runs aside), sensitive, best, the witness (each compile's grade, `*` where its
//! bytes differ from the control's). M.tiebreak turns each record whose function's text is still the same into a
//! derived `tiebreak` claim; a changed text leaves the record stale, and the next fall probes again.
//!
//! Who reads them: G.grade (the experiment's `tiebreak` and `proven`; no M2.stale for a sensitive function; the
//! unit's G.tiebreak gap: its declaration set is not yet the original's while a sensitive function reaches a
//! better grade under a probe than as built), M1 and the session wrap (a sensitive function that moved after a
//! declaration change that left its own text the same is no fall: one `tie-break` line per changed header set),
//! promote (no refusal for those), the queues (the proven grade is the code grade of the work: a proven byte
//! leaves the base and the deep queue) and the build's auto-clear (no tag is cleared on a sensitive function: a
//! byte reached through the declaration set proves nothing about its source).

use crate::coff::{FunctionCode, Obj};
use crate::error::{Error, Result};
use crate::project::{py_path, Project};
use crate::rules::Ctx;
use crate::store::{self, Out, DERIVED};
use rusqlite::Connection;
use serde_json::{json, Value};
use sha1::{Digest, Sha1};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

pub const LEDGER: &str = "ledger/tiebreak.tsv";
pub const HEADER: &str = "target\taddress\tname\tunit\ttext\tsensitive\tbest\twitness";

/// The probes: the lines put before the unit's text (a `#line 1` after them keeps every line number and
/// `__FILE__` as the build has them). The count of declarations drives some tie-breaks, a name's hash others
/// (seen: one typedef raised one function's grade and left another's), so the family varies both.
pub const PROBES: [&str; 4] = [
    "typedef int __dcp_probe_1;",
    "typedef int __dcp_probe_1; typedef int __dcp_probe_2;",
    "typedef int __dcp_probe_1; typedef int __dcp_probe_2; typedef int __dcp_probe_3;",
    "typedef int __dcp_probe_q;",
];

/// The units a build probes at most, when functions of the baseline fell without a record.
const BUILD_MAX_UNITS: usize = 4;

fn err(e: impl std::fmt::Display) -> Error {
    Error::runtime(e.to_string())
}

fn rank(c: &str) -> Option<usize> {
    crate::grade::CODE.iter().position(|x| *x == c)
}

// ------------------------------------------------------------------------------------------------ the records

/// One function's probe record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub target: String,
    pub addr: i64,
    pub name: String,
    pub unit: String,
    pub text: String,
    pub sensitive: bool,
    pub best: String,
    pub witness: String,
}

pub fn parse(text: &str) -> Vec<Record> {
    text.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#') && !l.starts_with("target\t")).filter_map(|l| {
        let f: Vec<&str> = l.split('\t').collect();
        if f.len() < 8 {
            return None;
        }
        Some(Record { target: f[0].into(), addr: crate::layout::py_int16(f[1])?, name: f[2].into(), unit: f[3].into(), text: f[4].into(),
                      sensitive: f[5] == "yes", best: f[6].into(), witness: f[7].into() })
    }).collect()
}

pub fn render(recs: &[Record]) -> String {
    let mut out = format!("{HEADER}\n");
    for r in recs {
        out.push_str(&[r.target.as_str(), &format!("{:#010x}", r.addr), &r.name, &r.unit, &r.text, if r.sensitive { "yes" } else { "no" }, &r.best,
                       &r.witness].join("\t"));
        out.push('\n');
    }
    out
}

fn ledger_path(root: &str) -> String {
    py_path(&format!("{root}/{LEDGER}"))
}

pub fn read(root: &str) -> Vec<Record> {
    parse(&crate::fsmemo::read_text(&ledger_path(root)).unwrap_or_default())
}

/// The ledger with the records of the probed units of `target` replaced by `fresh` (sorted by target, address).
fn merged(old: Vec<Record>, target: &str, units: &HashSet<String>, fresh: Vec<Record>) -> Vec<Record> {
    let mut by: BTreeMap<(String, i64), Record> = old.into_iter().filter(|r| !(r.target == target && units.contains(&r.unit)))
        .map(|r| ((r.target.clone(), r.addr), r)).collect();
    by.extend(fresh.into_iter().map(|r| ((r.target.clone(), r.addr), r)));
    by.into_values().collect()
}

// ------------------------------------------------------------------------------------------------ the text

/// A C text without its comments, each run of whitespace one space: what the compiler reads of it (string and
/// character literals kept as they are).
pub fn normalize(text: &str) -> String {
    let c: Vec<char> = text.chars().collect();
    let (mut out, mut i, mut space) = (String::new(), 0, false);
    let put = |out: &mut String, ch: char, space: &mut bool| {
        if ch.is_whitespace() {
            *space = true;
            return;
        }
        if *space && !out.is_empty() {
            out.push(' ');
        }
        *space = false;
        out.push(ch);
    };
    while i < c.len() {
        match c[i] {
            '/' if c.get(i + 1) == Some(&'*') => {
                i = (i + 2..c.len().saturating_sub(1)).find(|&k| c[k] == '*' && c[k + 1] == '/').map(|k| k + 2).unwrap_or(c.len());
                space = true;
            }
            '/' if c.get(i + 1) == Some(&'/') => {
                i = (i..c.len()).find(|&k| c[k] == '\n').unwrap_or(c.len());
                space = true;
            }
            q @ ('"' | '\'') => {
                put(&mut out, q, &mut space);
                i += 1;
                while i < c.len() && c[i] != q && c[i] != '\n' {
                    if c[i] == '\\' && i + 1 < c.len() {
                        out.push(c[i]);
                        i += 1;
                    }
                    out.push(c[i]);
                    i += 1;
                }
                if i < c.len() && c[i] == q {
                    out.push(q);
                    i += 1;
                }
            }
            ch => {
                put(&mut out, ch, &mut space);
                i += 1;
            }
        }
    }
    out
}

/// The text of a function: its file's lines from its address comment to its definition's end, normalized.
pub fn fn_text(root: &str, file: &str, comment: i64, end: i64) -> Option<String> {
    let text = crate::fsmemo::read_text(&py_path(&format!("{root}/{file}"))).ok()?;
    let lines: Vec<&str> = text.lines().collect();
    let (lo, hi) = ((comment.max(1) - 1) as usize, (end.max(comment) as usize).min(lines.len()));
    (lo < hi).then(|| normalize(&lines[lo..hi].join("\n")))
}

pub fn text_hash(normalized: &str) -> String {
    let d = Sha1::digest(normalized.as_bytes());
    d.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

// ------------------------------------------------------------------------------------------------ M.tiebreak

/// M.tiebreak: each record of ledger/tiebreak.tsv of the current target whose function (L.src) still has the text
/// it was probed with, as a derived `tiebreak` claim at the function's address {name, unit, file, comment, end,
/// sensitive, best, witness}. A record whose text changed is stale and gives nothing.
pub fn m_tiebreak(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let recs: HashMap<i64, Record> = read(&ctx.root).into_iter().filter(|r| r.target == ctx.inputs.target).map(|r| (r.addr, r)).collect();
    if recs.is_empty() {
        return Ok(());
    }
    let srcs = store::claims(db, &ctx.db, "source", &ctx.needed, |f| &*f.rule == "L.src" && f.s("what") == Some("func")).map_err(err)?;
    for s in srcs {
        let Some(r) = recs.get(&s.lo) else { continue };
        let (file, comment, end) = (s.s("file").unwrap_or(""), s.value["comment"].as_i64().unwrap_or(0), s.value["end"].as_i64().unwrap_or(0));
        if fn_text(&ctx.root, file, comment, end).is_none_or(|t| text_hash(&t) != r.text) {
            continue;
        }
        out.claim(s.lo, s.lo + 1, "tiebreak", json!({"name": s.value["symbol"], "unit": s.value["unit"], "file": file, "comment": comment, "end": end,
                                                     "sensitive": r.sensitive, "best": r.best, "witness": r.witness}), DERIVED);
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ attribution

/// The changed declarations a tie-break sensitive function moved by (M1, the wrap, promote): its `tiebreak` value
/// sensitive, its own text the same as at the changes' base, and its unit's compile inputs changed (a header of
/// its include closure, or its unit's file outside the function). The label names them: the changed headers
/// (`, uncommitted` on each the working tree changed), else the unit's file.
pub fn declaration_move(root: &str, ch: &crate::cause::Changes, tb: &Value, unit_file: &str) -> Option<String> {
    if tb.get("sensitive").and_then(|v| v.as_bool()) != Some(true) {
        return None;
    }
    let (file, comment, end) = (tb["file"].as_str()?, tb["comment"].as_i64()?, tb["end"].as_i64()?);
    let now = fn_text(root, file, comment, end)?;
    if !normalize(&ch.text_at(root, file)?).contains(&now) {
        return None;
    }
    let c = ch.of_unit(root, unit_file);
    let fresh = |u: bool| if u { ", uncommitted" } else { "" };
    if !c.headers.is_empty() {
        return Some(c.headers.iter().map(|(h, _, u)| format!("{h}{}", fresh(*u))).collect::<Vec<_>>().join("; "));
    }
    c.unit.map(|(f, u)| format!("{f} outside the function{}", fresh(u)))
}

/// The tie-break line of M1 and the wrap: `tie-break: N functions moved (LABEL): names`.
pub fn moved_line(label: &str, names: &[String]) -> String {
    let more = if names.len() > 8 { format!(" (+{})", names.len() - 8) } else { String::new() };
    format!("tie-break: {} function{} moved ({label}): {}{more}", names.len(), if names.len() == 1 { "" } else { "s" },
            names.iter().take(8).cloned().collect::<Vec<_>>().join(", "))
}

// ------------------------------------------------------------------------------------------------ the bench

/// What a trial grades one compiled function against, as G.grade reads it: the image, φ, the fill forms, the
/// starts, the relocation sites, the walk's extents.
pub(crate) struct Bench {
    img: std::rc::Rc<crate::pe::Image>,
    phi: crate::phi::Phi,
    fills: HashSet<Vec<u8>>,
    forms: Vec<Vec<u8>>,
    align: i64,
    starts: Vec<i64>,
    relocs: Option<Vec<u32>>,
    walk: HashMap<i64, i64>,
}

impl Bench {
    pub(crate) fn of(p: &Project) -> Result<Bench> {
        let db = p.store_path();
        let img = crate::image(&p.target(None).map_err(err)?.path)?;
        let tc = crate::toolchain::of(&p.toolchain_key()).ok_or_else(|| err("no toolchain"))?;
        let fill_forms: Vec<Vec<u8>> = tc.fill_forms().iter().map(|f| f.to_vec()).collect();
        let relocs: Option<Vec<u32>> = if img.relocations().is_empty() {
            None
        } else {
            let mut v: Vec<u32> = crate::with_db(&db, |c| store::claims_of(c, &db, "ref", None, |f| f.s("rkind") == Some("reloc")))?.iter().map(|f| f.lo as u32).collect();
            v.sort_unstable();
            (!v.is_empty()).then_some(v)
        };
        // the walk's or the source extent's end of each function (G.grade's extent)
        let walk: HashMap<i64, i64> = crate::with_db(&db, |c| store::claims_of(c, &db, "symbol", None, |f| {
            f.s("skind") == Some("func") && matches!(&*f.rule, "S.codewalk" | "L.src.extent")
        }))?.iter().map(|f| (f.lo, f.hi)).collect();
        // the next start as M.match reads it (rules::compiled_functions): the starts of the rules M.match needs, not
        // an analyzer's (seen: Ghidra's start inside a function cut its compare short, byte read as shape)
        let needed: Vec<String> = crate::engine::resolve_needs(crate::engine::rule("M.match")?)?.iter().map(|s| s.to_string()).collect();
        let mut starts: Vec<i64> = crate::with_db(&db, |c| {
            let mut v = store::los(c, &db, "start", &needed, |_| true)?;
            v.extend(store::los(c, &db, "symbol", &needed, |f| matches!(f.s("skind"), Some("func" | "thunk")) && f.support > store::OPEN)?);
            Ok(v)
        })?;
        starts.extend(img.sections.iter().filter(|x| x.holds_code()).map(|x| x.end() as i64));
        starts.sort_unstable();
        starts.dedup();
        Ok(Bench { phi: crate::names::ledger_phi(&db)?, fills: fill_forms.iter().cloned().collect(), forms: crate::compare::fill_order(&fill_forms),
                   align: tc.function_alignment() as i64, starts, relocs, walk, img })
    }

    /// One function's code grade as G.grade gives it.
    pub(crate) fn grade(&self, o: &Obj, code: &FunctionCode, a: i64) -> &'static str {
        let img = &*self.img;
        let env = crate::diffclass::Env { img, range: (img.base as i64, img.end() as i64), fills: &self.fills, forms: &self.forms };
        let g = crate::grade::Grader { env, phi: &self.phi, align: self.align };
        let next = self.starts.get(self.starts.partition_point(|&x| x <= a)).copied().unwrap_or(img.end() as i64) as u32;
        let matched = crate::compare::compare(img, code, a as u32, self.relocs.as_deref(), next, &self.forms).matched();
        g.grade(o, code, a, next, self.walk.get(&a).copied(), matched)
    }

    /// One function's distance from the original as `dcp grade` reads it: (differing instructions on both sides,
    /// differing bytes with the size difference, the hunk classes).
    pub(crate) fn distance(&self, o: &Obj, code: &FunctionCode, a: i64) -> (usize, usize, String) {
        let img = &*self.img;
        let env = crate::diffclass::Env { img, range: (img.base as i64, img.end() as i64), fills: &self.fills, forms: &self.forms };
        let next = self.starts.get(self.starts.partition_point(|&x| x <= a)).copied().unwrap_or(img.end() as i64) as u32;
        let c = crate::compare::compare(img, code, a as u32, self.relocs.as_deref(), next, &self.forms);
        let (cd, cm) = code.code();
        let size = crate::diffclass::code_size(&env, cd, cm, a as u32);
        let extent = self.walk.get(&a).map(|h| h - a).unwrap_or(size);
        let orig = crate::diffclass::original(&env, a as u32, extent, extent.max(next as i64 - a), self.align);
        let n = size.min(orig.code);
        let bytes = c.diffs.iter().filter(|&&k| (k as i64) < n).count() + (size - orig.code).unsigned_abs() as usize;
        let fc = crate::diffclass::FunctionCompare::new(&env, o, code, a as u32, &orig);
        (fc.verdict.distance, bytes, fc.verdict.summary_without_branches())
    }
}

/// One compile of a trial: the unit, a tag naming the file, the lines before the text, the text.
pub(crate) struct Job<'a> {
    pub unit: &'a crate::plan::Tu,
    pub tag: String,
    pub prefix: String,
    pub text: String,
}

/// The jobs compiled as the build compiles their units (the unit's flags, its directory before include/ for the
/// quoted includes, `#line 1 "<its file>"` so that line numbers and `__FILE__` are the build's), each in
/// build/trial/ and build/obj/trial/ (the files removed after), in parallel: each object, or the compiler's first
/// error.
pub(crate) fn compile(p: &Project, jobs: &[Job]) -> Result<Vec<std::result::Result<Obj, String>>> {
    let root = p.root.to_string_lossy().into_owned();
    let tools = crate::vc6::Tools::of(p);
    if !tools.available() {
        return Ok(jobs.iter().map(|_| Err("the toolchain is not available".to_string())).collect());
    }
    let full = |r: &str| py_path(&format!("{root}/{r}"));
    for d in ["build/trial", "build/obj/trial"] {
        let _ = std::fs::create_dir_all(full(d));
    }
    let mut flags: HashMap<&str, Vec<String>> = HashMap::new();
    for j in jobs {
        if !flags.contains_key(j.unit.unit.as_str()) {
            flags.insert(&j.unit.unit, crate::plan::compile_flags(p, &j.unit.target, &j.unit.unit).map_err(err)?);
        }
    }
    let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let res = crate::compile::run_threads(n, jobs, |j| -> std::result::Result<Obj, String> {
        let (src, obj) = (format!("build/trial/{}-{}.c", j.unit.unit, j.tag), format!("build/obj/trial/{}-{}.obj", j.unit.unit, j.tag));
        let file = j.unit.file.replace('/', "\\");
        let mut dirs = vec![];
        if let Some((d, _)) = j.unit.file.rsplit_once('/') {
            dirs.push(d.replace('/', "\\"));
        }
        dirs.push("include".to_string());
        let pre = if j.prefix.is_empty() { String::new() } else { format!("{}\n", j.prefix) };
        let text = format!("{pre}#line 1 \"{}\"\n{}", file.replace('\\', "\\\\"), j.text);
        let _ = std::fs::remove_file(full(&obj));
        std::fs::write(full(&src), text).map_err(|e| e.to_string())?;
        let r = tools.compile(&src, &obj, &flags[j.unit.unit.as_str()], &dirs, &root);
        let data = std::fs::read(full(&obj));
        for f in [&src, &obj] {
            let _ = std::fs::remove_file(full(f));
        }
        let r = r?;
        if !r.ok {
            return Err(r.diags.iter().find(|d| d.severity == "error").map(|d| format!("{}({}): {} {}", d.file, d.line, d.code, d.message))
                .unwrap_or_else(|| "does not compile".into()));
        }
        Obj::parse(&data.map_err(|e| e.to_string())?)
    });
    Ok(res)
}

// ------------------------------------------------------------------------------------------------ the probe

/// The same code: the bytes outside the relocated fields, and the symbols of the relocations (a name the compiler
/// numbers, `$SG1234` / `$L567`, by its kind only: the probe's declarations shift the numbering, not the code).
fn same_code(o1: &Obj, c1: &FunctionCode, o2: &Obj, c2: &FunctionCode) -> bool {
    let syms = |o: &Obj, c: &FunctionCode| -> Vec<(u32, String)> {
        c.relocs.iter().map(|(off, r)| {
            let n = o.symbol_at(r.symbol_index).map(|s| s.name.clone()).unwrap_or_default();
            (*off, if n.starts_with('$') { n.trim_end_matches(|ch: char| ch.is_ascii_digit()).to_string() } else { n })
        }).collect()
    };
    let masked = |c: &FunctionCode| -> Vec<u8> { c.data.iter().zip(&c.mask).map(|(b, m)| if *m != 0 { 0 } else { *b }).collect() };
    masked(c1) == masked(c2) && syms(o1, c1) == syms(o2, c2)
}

/// One probed unit: its records, each with the function's built grade.
pub struct Probed {
    pub unit: String,
    pub recs: Vec<(Record, String)>, // with the built grade
}

/// Probe the units (their names): each the control and PROBES compiled, each function graded. Per unit its
/// records, or why there are none (the toolchain, a compile error, a control that is not the build).
pub fn probe_units(p: &Project, units: &[String]) -> Result<Vec<(String, std::result::Result<Probed, String>)>> {
    let root = p.root.to_string_lossy().into_owned();
    let db = p.store_path();
    let plan = crate::plan::plan(p).map_err(err)?;
    let mut out = vec![];
    let mut tus = vec![];
    for u in units {
        match plan.iter().find(|t| &t.unit == u) {
            Some(t) => tus.push(t),
            None => out.push((u.clone(), Err(format!("no unit {u} in target {}", p.target_name)))),
        }
    }
    let mut jobs = vec![];
    for t in &tus {
        let text = crate::fsmemo::read_text(&py_path(&format!("{root}/{}", t.file))).map_err(err)?;
        for (k, pre) in std::iter::once("").chain(PROBES).enumerate() {
            jobs.push(Job { unit: t, tag: if k == 0 { "control".into() } else { format!("probe{k}") }, prefix: pre.into(), text: text.clone() });
        }
    }
    let objs = compile(p, &jobs)?;
    let bench = if tus.is_empty() { None } else { Some(Bench::of(p)?) };
    let rows = crate::queues::function_grades(&db)?;
    let srcs: HashMap<i64, (String, i64, i64)> = crate::with_db(&db, |c| store::claims_of(c, &db, "source", None, |f| &*f.rule == "L.src" && f.s("what") == Some("func")))?
        .iter().map(|f| (f.lo, (f.s("file").unwrap_or("").to_string(), f.value["comment"].as_i64().unwrap_or(0), f.value["end"].as_i64().unwrap_or(0)))).collect();
    let per = PROBES.len() + 1;
    for (i, t) in tus.iter().enumerate() {
        let objs = &objs[i * per..(i + 1) * per];
        if let Some(e) = objs.iter().find_map(|o| o.as_ref().err()) {
            out.push((t.unit.clone(), Err(format!("does not compile: {e}"))));
            continue;
        }
        let objs: Vec<&Obj> = objs.iter().filter_map(|o| o.as_ref().ok()).collect();
        let index: Vec<HashMap<String, usize>> = objs.iter().map(|o| o.function_index()).collect();
        let bench = bench.as_ref().unwrap();
        let (mut recs, mut differ) = (vec![], vec![]);
        for r in rows.iter().filter(|r| r["unit"].as_str() == Some(t.unit.as_str())) {
            let (a, name, now) = (r["addr"].as_i64().unwrap_or(0), r["name"].as_str().unwrap_or(""), r["code"].as_str().unwrap_or(""));
            if now == crate::grade::NOT_RUN {
                continue;
            }
            let Some(&k0) = index[0].get(name) else { continue };
            let Some((file, comment, end)) = srcs.get(&a) else { continue };
            let Some(text) = fn_text(&root, file, *comment, *end) else { continue };
            let c0 = objs[0].function_code(k0);
            let control = bench.grade(objs[0], &c0, a);
            if control != now {
                differ.push(format!("{name} built {now}, control {control}"));
                continue;
            }
            let (mut witness, mut best, mut sensitive) = (vec![format!("control={control}")], control, false);
            for k in 1..per {
                let g = match index[k].get(name) {
                    None => {
                        sensitive = true;
                        witness.push(format!("p{k}=none*"));
                        continue;
                    }
                    Some(&j) => {
                        let c = objs[k].function_code(j);
                        let moved = !same_code(objs[0], &c0, objs[k], &c);
                        sensitive |= moved;
                        let g = if moved { bench.grade(objs[k], &c, a) } else { control };
                        witness.push(format!("p{k}={g}{}", if moved { "*" } else { "" }));
                        g
                    }
                };
                if rank(g) > rank(best) {
                    best = g;
                }
            }
            recs.push((Record { target: p.target_name.clone(), addr: a, name: name.into(), unit: t.unit.clone(), text: text_hash(&text), sensitive,
                                best: best.into(), witness: witness.join(" ") }, now.to_string()));
        }
        if !differ.is_empty() {
            out.push((t.unit.clone(), Err(format!("the control compile does not reproduce the build at {} function(s) ({}{}): dcp build, then probe again",
                                                  differ.len(), differ[0], if differ.len() > 1 { ", .." } else { "" }))));
            continue;
        }
        out.push((t.unit.clone(), Ok(Probed { unit: t.unit.clone(), recs })));
    }
    Ok(out)
}

/// Write the records of the probed units into the ledger (the other records kept).
fn write(p: &Project, probed: &[&Probed]) -> Result<()> {
    let root = p.root.to_string_lossy().into_owned();
    let units: HashSet<String> = probed.iter().map(|x| x.unit.clone()).collect();
    let fresh: Vec<Record> = probed.iter().flat_map(|x| x.recs.iter().map(|r| r.0.clone())).collect();
    let text = render(&merged(read(&root), &p.target_name, &units, fresh));
    let path = ledger_path(&root);
    if let Some(d) = Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(d);
    }
    crate::edit::write(&path, &text).map_err(Error::value)?;
    p.forget_input("tiebreak");
    Ok(())
}

/// The report lines of the probed units: per unit its counts, per sensitive function its grades.
fn report(res: &[(String, std::result::Result<Probed, String>)]) -> Vec<String> {
    use crate::cliread::{fmt_addr, record, Tok};
    let s = |x: &str| Tok::S(x.to_string());
    let mut out = vec![];
    for (unit, r) in res {
        match r {
            Err(e) => out.push(record(&[("unit", s(unit)), ("error", s(e))])),
            Ok(pr) => {
                let sens: Vec<&(Record, String)> = pr.recs.iter().filter(|r| r.0.sensitive).collect();
                let raised = sens.iter().filter(|r| rank(&r.0.best) > rank(&r.1)).count();
                out.push(record(&[("unit", s(unit)), ("functions", Tok::I(pr.recs.len() as i64)), ("sensitive", Tok::I(sens.len() as i64)),
                                  ("raised", Tok::I(raised as i64))]));
                for (r, now) in sens {
                    out.push(format!("  {}", record(&[("fn", s(&fmt_addr(r.addr))), ("name", s(&r.name)), ("built", s(now)), ("best", s(&r.best)),
                                                       ("witness", s(&r.witness))])));
                }
            }
        }
    }
    out
}

/// `dcp headers probe [UNIT..] [--dry-run]`: probe the units (every unit of the target when none is named) and
/// record them: (the lines, the exit status: 1 when a unit could not be probed).
pub fn probe_command(p: &Project, units: Vec<String>, dry: bool) -> Result<(Vec<String>, i32)> {
    let units = if units.is_empty() { crate::plan::plan(p).map_err(err)?.iter().map(|t| t.unit.clone()).collect() } else { units };
    let res = probe_units(p, &units)?;
    let ok: Vec<&Probed> = res.iter().filter_map(|r| r.1.as_ref().ok()).collect();
    let mut out = report(&res);
    let (n, sens) = (ok.iter().map(|x| x.recs.len()).sum::<usize>(), ok.iter().map(|x| x.recs.iter().filter(|r| r.0.sensitive).count()).sum::<usize>());
    let tail = if dry { " (--dry-run: nothing written)".to_string() } else { format!("; written to {LEDGER}") };
    out.push(format!("probed {} unit(s), {n} function(s), {sens} tie-break sensitive{tail}", ok.len()));
    if !dry && !ok.is_empty() {
        write(p, &ok)?;
    }
    Ok((out, if ok.len() < res.len() { 1 } else { 0 }))
}

/// The build's probe: the units of the functions that fell below the baseline (ledger/grades.tsv) and have no
/// fresh record (the `tiebreak` of their grade row), at most BUILD_MAX_UNITS, probed and recorded. The lines say
/// what was probed; nothing when nothing fell, or the toolchain is missing.
pub fn probe_falls(p: &Project) -> Result<Vec<String>> {
    let root = p.root.to_string_lossy().into_owned();
    let base = crate::fsmemo::read_text(&py_path(&format!("{root}/ledger/grades.tsv"))).unwrap_or_default();
    if base.is_empty() || !crate::vc6::Tools::of(p).available() {
        return Ok(vec![]);
    }
    let base: HashMap<i64, String> = crate::queues::parse_baseline(&base).into_iter().filter(|x| x.0 .0 == p.target_name).map(|x| (x.0 .1, x.1.code)).collect();
    let mut units: Vec<String> = vec![];
    for r in crate::queues::function_grades(&p.store_path())?.iter() {
        let (a, code, unit) = (r["addr"].as_i64().unwrap_or(0), r["code"].as_str().unwrap_or(""), r["unit"].as_str().unwrap_or(""));
        let fell = matches!((base.get(&a).and_then(|b| rank(b)), rank(code)), (Some(b), Some(n)) if n < b);
        if fell && r.get("tiebreak").is_none_or(|v| v.is_null()) && !units.iter().any(|u| u == unit) {
            units.push(unit.to_string());
        }
    }
    if units.is_empty() {
        return Ok(vec![]);
    }
    let left = units.len().saturating_sub(BUILD_MAX_UNITS);
    units.truncate(BUILD_MAX_UNITS);
    let res = probe_units(p, &units)?;
    let ok: Vec<&Probed> = res.iter().filter_map(|r| r.1.as_ref().ok()).collect();
    if !ok.is_empty() {
        write(p, &ok)?;
    }
    let mut out = vec![format!("tie-break probe of {} unit(s) with falls{}:", units.len(),
                               if left > 0 { format!(" ({left} more: dcp headers probe)") } else { String::new() })];
    out.extend(report(&res).into_iter().map(|l| format!("  {l}")));
    Ok(out)
}

// ------------------------------------------------------------------------------------------------ the sampler

/// A small deterministic generator (xorshift64): the same seed gives the same samples.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0.max(1);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// A place of a preprocessed text where a declaration may go: the line index, and the file and line the `#line`
/// directives in force give that line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Place {
    pub at: usize,
    pub file: String,
    pub line: i64,
}

/// The places of a preprocessed text (CL /E's output) at file scope: the start of a line at brace and parenthesis
/// depth 0 whose previous significant line ended a declaration (`;`, `}`) or was a directive. A place inside a K&R
/// parameter list passes this test; a sample that does not compile is dropped, so the test only has to be cheap.
pub fn places(lines: &[&str]) -> Vec<Place> {
    let (mut out, mut depth, mut file, mut line, mut ended) = (vec![], 0i64, String::new(), 0i64, true);
    for (k, l) in lines.iter().enumerate() {
        let t = l.trim();
        if let Some(rest) = t.strip_prefix("#line") {
            let mut parts = rest.trim().splitn(2, ' ');
            line = parts.next().and_then(|n| n.parse().ok()).unwrap_or(line);
            if let Some(f) = parts.next() {
                file = f.trim().trim_matches('"').replace("\\\\", "\\");
            }
            ended = true;
            continue;
        }
        if depth == 0 && ended && !t.is_empty() && !t.starts_with('{') {
            out.push(Place { at: k, file: file.clone(), line });
        }
        if t.starts_with('#') {
            ended = true;
        } else if !t.is_empty() {
            // braces and parentheses outside string and character literals
            let (mut q, mut esc) = (None::<char>, false);
            for ch in t.chars() {
                match (q, ch) {
                    (Some(_), _) if esc => esc = false,
                    (Some(_), '\\') => esc = true,
                    (Some(c), x) if x == c => q = None,
                    (Some(_), _) => {}
                    (None, '"' | '\'') => q = Some(ch),
                    (None, '{' | '(') => depth += 1,
                    (None, '}' | ')') => depth -= 1,
                    _ => {}
                }
            }
            ended = depth == 0 && (t.ends_with(';') || t.ends_with('}'));
        }
        line += 1;
    }
    out
}

/// The no-meaning declarations a sample inserts: unused, of every kind the compiler numbers (a type, a struct tag, a
/// function, a variable), each under a name of its own.
fn decl(kind: usize, name: &str) -> String {
    match kind % 4 {
        0 => format!("typedef int {name};"),
        1 => format!("struct {name} {{ int {name}_m; }};"),
        2 => format!("int {name}(void);"),
        _ => format!("extern int {name};"),
    }
}

const KINDS: [&str; 4] = ["typedef", "struct", "prototype", "extern"];

/// A member of a type definition a sample may change without changing the layout: a padding array (`char pad..[N]`,
/// N >= 2: split in two) or a union (a one-byte member added). Its line index and the parts of its line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Member {
    Pad { at: usize, head: String, name: String, n: usize, rest: String },
    Union { at: usize },
}

impl Member {
    fn at(&self) -> usize {
        match self {
            Member::Pad { at, .. } | Member::Union { at } => *at,
        }
    }
}

/// The members a sample may change: padding arrays (a name starting with `pad`: never used by name) and unions,
/// both inside a type definition (brace depth above 0).
pub fn members(lines: &[&str]) -> Vec<Member> {
    static PAD: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"^(\s*(?:unsigned\s+)?char\s+)(pad\w*)\[(0x[0-9a-fA-F]+|\d+)\];(.*)$").unwrap()
    });
    let (mut out, mut depth) = (vec![], 0i64);
    for (k, l) in lines.iter().enumerate() {
        let t = l.trim();
        if t.starts_with('#') {
            continue;
        }
        if depth > 0 {
            if let Some(c) = PAD.captures(l) {
                let n = match c[3].strip_prefix("0x") {
                    Some(h) => usize::from_str_radix(h, 16).unwrap_or(0),
                    None => c[3].parse().unwrap_or(0),
                };
                if n >= 2 {
                    out.push(Member::Pad { at: k, head: c[1].to_string(), name: c[2].to_string(), n, rest: c[4].to_string() });
                }
            }
            if t == "union {" || (t.starts_with("union ") && t.ends_with('{')) {
                out.push(Member::Union { at: k });
            }
        }
        depth += t.matches('{').count() as i64 - t.matches('}').count() as i64;
    }
    out
}

/// One change of a sample: `what` below KINDS.len() a declaration of that kind before place `idx`; KINDS.len() the
/// member `idx` changed (a padding array split after 1 + k % (N-1) bytes, a union given a one-byte member).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pick {
    pub what: usize,
    pub idx: usize,
    pub k: usize,
}

/// The text of one sample. Every line keeps its number: a declaration goes in with a `#line` after it, a member
/// change stays on its line.
fn sample_text(lines: &[&str], places: &[Place], mems: &[Member], picks: &[Pick], tag: &str) -> String {
    let mut before: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    let mut replace: HashMap<usize, String> = HashMap::new();
    for (j, pk) in picks.iter().enumerate() {
        let nm = format!("__dcp_{tag}_{j}");
        if pk.what < KINDS.len() {
            let pl = &places[pk.idx];
            let d = format!("{}\n#line {} \"{}\"", decl(pk.what, &nm), pl.line, pl.file.replace('\\', "\\\\"));
            before.entry(pl.at).or_default().push(d);
            continue;
        }
        match &mems[pk.idx] {
            Member::Pad { at, head, name, n, rest } => {
                // one in three: the array wrapped in a struct of its own (a member's type changed, the layout not:
                // a function moved when a member went from char[0x10] to a record); else split
                if pk.k % 3 == 0 {
                    replace.insert(*at, format!("{}struct {{ char {nm}[{n}]; }} {name};{rest}", head.trim_end().trim_end_matches("char").trim_end_matches("unsigned").to_string() + " "));
                } else {
                    let k = 1 + pk.k % (n - 1);
                    replace.insert(*at, format!("{head}{name}[{k}]; char {nm}[{}];{rest}", n - k));
                }
            }
            Member::Union { at } => {
                let l = replace.get(at).cloned().unwrap_or_else(|| lines[*at].to_string());
                replace.insert(*at, format!("{l} char {nm};"));
            }
        }
    }
    let mut out = String::with_capacity(lines.iter().map(|l| l.len() + 1).sum::<usize>() + 256);
    for (k, l) in lines.iter().enumerate() {
        if let Some(ds) = before.get(&k) {
            for d in ds {
                out.push_str(d);
                out.push('\n');
            }
        }
        out.push_str(replace.get(&k).map(|x| x.as_str()).unwrap_or(l));
        out.push('\n');
    }
    out
}

/// The code of a compiled function with what a declaration set may move (the relocated fields masked, the
/// compiler's numbered names by kind): two samples with the same key have the same code.
pub(crate) fn code_key(o: &Obj, c: &FunctionCode) -> (Vec<u8>, Vec<(u32, String)>) {
    let syms = c.relocs.iter().map(|(off, r)| {
        let n = o.symbol_at(r.symbol_index).map(|s| s.name.clone()).unwrap_or_default();
        (*off, if n.starts_with('$') { n.trim_end_matches(|ch: char| ch.is_ascii_digit()).to_string() } else { n })
    }).collect();
    (c.data.iter().zip(&c.mask).map(|(b, m)| if *m != 0 { 0 } else { *b }).collect(), syms)
}

/// What `dcp headers sample` found for one function.
pub struct Sampled {
    pub rec: Record,
    pub built: String,
    pub compiled: usize,
    pub failed: usize,
    /// the codegens seen: (grade, how many samples, the first sample's description), the control's first
    pub codegens: Vec<(String, usize, String)>,
}

/// `dcp headers sample NAME`: the function's unit preprocessed once, compiled as it is (the control: it must give
/// the build's grade) and `n` times with 1..3 no-meaning declarations at random file-scope places before the
/// function (unused typedefs, struct tags, prototypes, externs; every line keeping its number). The function is
/// tie-break sensitive when its code moves in any sample; its best grade over the samples is its source-proven one
/// (a declaration set exists under which its text gives it). The record goes to ledger/tiebreak.tsv.
pub fn sample_function(p: &Project, name: &str, n: usize, seed: u64) -> Result<std::result::Result<Sampled, String>> {
    let root = p.root.to_string_lossy().into_owned();
    let db = p.store_path();
    let rows = crate::queues::function_grades(&db)?;
    let Some(row) = rows.iter().find(|r| r["name"].as_str() == Some(name)) else { return Ok(Err(format!("no graded function {name} (dcp build first)"))) };
    let (a, unit, built) = (row["addr"].as_i64().unwrap_or(0), row["unit"].as_str().unwrap_or("").to_string(), row["code"].as_str().unwrap_or("").to_string());
    let plan = crate::plan::plan(p).map_err(err)?;
    let Some(t) = plan.iter().find(|t| t.unit == unit) else { return Ok(Err(format!("no unit {unit} in target {}", p.target_name))) };
    let srcs: HashMap<i64, (String, i64, i64)> = crate::with_db(&db, |c| store::claims_of(c, &db, "source", None, |f| &*f.rule == "L.src" && f.s("what") == Some("func")))?
        .iter().map(|f| (f.lo, (f.s("file").unwrap_or("").to_string(), f.value["comment"].as_i64().unwrap_or(0), f.value["end"].as_i64().unwrap_or(0)))).collect();
    let Some((file, comment, end)) = srcs.get(&a).cloned() else { return Ok(Err(format!("{name} has no source span"))) };
    let Some(text) = fn_text(&root, &file, comment, end) else { return Ok(Err(format!("{name}: its text is not readable"))) };
    // the unit preprocessed as the trial compiles it (its directory, then include/)
    let tools = crate::vc6::Tools::of(p);
    let flags = crate::plan::compile_flags(p, &t.target, &t.unit).map_err(err)?;
    let mut dirs = vec![];
    if let Some((d, _)) = t.file.rsplit_once('/') {
        dirs.push(d.replace('/', "\\"));
    }
    dirs.push("include".to_string());
    let expanded = match tools.preprocess(&t.file.replace('/', "\\"), &flags, &dirs, &root).map_err(err)? {
        Ok(x) => x.replace("\r\n", "\n"),
        Err(e) => return Ok(Err(format!("the unit does not preprocess: {}", e.lines().next().unwrap_or("")))),
    };
    let lines: Vec<&str> = expanded.lines().collect();
    // the places before the function's definition (its comment line in its own file)
    let unit_file = t.file.replace('/', "\\").to_lowercase();
    let all = places(&lines);
    let def = all.iter().position(|pl| pl.file.to_lowercase().ends_with(&unit_file) && pl.line >= comment).unwrap_or(all.len());
    let cands: Vec<Place> = all[..def].to_vec();
    if cands.is_empty() {
        return Ok(Err(format!("no file-scope place before {name} in the preprocessed unit")));
    }
    // the members of the type definitions before the function
    let mems: Vec<Member> = members(&lines).into_iter().filter(|m| cands.last().is_some_and(|c| m.at() < c.at)).collect();
    let mut rng = Rng(seed ^ (a as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15));
    // each sample 1..3 changes: a declaration at a place, or (one in three, when there are members) a member
    let samples: Vec<Vec<Pick>> = (0..n).map(|_| (0..1 + rng.below(3)).map(|_| {
        if !mems.is_empty() && rng.below(3) == 0 {
            Pick { what: KINDS.len(), idx: rng.below(mems.len()), k: rng.below(1 << 16) }
        } else {
            Pick { what: rng.below(KINDS.len()), idx: rng.below(cands.len()), k: 0 }
        }
    }).collect()).collect();
    let mut jobs = vec![Job { unit: t, tag: "sctl".into(), prefix: String::new(), text: expanded.clone() }];
    for (k, s) in samples.iter().enumerate() {
        jobs.push(Job { unit: t, tag: format!("s{k}"), prefix: String::new(), text: sample_text(&lines, &cands, &mems, s, &format!("s{k}")) });
    }
    let objs = compile(p, &jobs)?;
    let bench = Bench::of(p)?;
    let control = match &objs[0] {
        Err(e) => return Ok(Err(format!("the preprocessed unit does not compile: {e}"))),
        Ok(o) => o,
    };
    let Some(&k0) = control.function_index().get(name) else { return Ok(Err(format!("{name} is not in the compiled unit"))) };
    let c0 = control.function_code(k0);
    let g0 = bench.grade(control, &c0, a);
    // the preprocessed text alone (the same declarations, another form: #line directives, expanded macros) may move
    // a function: that is a codegen of its own and proof of sensitivity (seen: built draft, preprocessed shape); a
    // stale build shows the same way, so the line says both
    let form_moved = g0 != built;
    let where_at = |at: usize| -> String {
        // the file and line the #line directives give a line index
        cands.iter().rev().find(|c| c.at <= at).map(|c| format!("{}:{}", c.file.replace('\\', "/"), c.line + (at - c.at) as i64)).unwrap_or_default()
    };
    let describe = |s: &[Pick]| -> String {
        s.iter().map(|pk| {
            if pk.what < KINDS.len() {
                let pl = &cands[pk.idx];
                format!("{} before {}:{}", KINDS[pk.what], pl.file.replace('\\', "/"), pl.line)
            } else {
                match &mems[pk.idx] {
                    Member::Pad { at, name, n, .. } if pk.k % 3 == 0 => format!("{name}[{n:#x}] wrapped in a struct near {}", where_at(*at)),
                    Member::Pad { at, name, n, .. } => format!("{name}[{n:#x}] split after {:#x} near {}", 1 + pk.k % (n - 1), where_at(*at)),
                    Member::Union { at } => format!("a union member near {}", where_at(*at)),
                }
            }
        }).collect::<Vec<_>>().join(", ")
    };
    let key0 = code_key(control, &c0);
    let mut seen: Vec<((Vec<u8>, Vec<(u32, String)>), String, usize, String)> = vec![(key0, g0.to_string(), 0, "the build's declarations".into())];
    if form_moved {
        seen.insert(0, ((vec![], vec![]), built.clone(), 0, format!("the build itself (the preprocessed control gives {g0}; or the build is stale: dcp build)")));
    }
    let (mut compiled, mut failed) = (0usize, 0usize);
    for (k, o) in objs[1..].iter().enumerate() {
        let Ok(o) = o else {
            failed += 1;
            continue;
        };
        let Some(&j) = o.function_index().get(name) else {
            failed += 1;
            continue;
        };
        compiled += 1;
        let c = o.function_code(j);
        let key = code_key(o, &c);
        match seen.iter_mut().find(|x| x.0 == key) {
            Some(x) => x.2 += 1,
            None => {
                let g = bench.grade(o, &c, a);
                seen.push((key, g.to_string(), 1, format!("s{k}: {}", describe(&samples[k]))));
            }
        }
    }
    let sensitive = seen.len() > 1;
    let best = seen.iter().map(|x| x.1.as_str()).max_by_key(|g| rank(g)).unwrap_or(g0).to_string();
    let codegens: Vec<(String, usize, String)> = seen.into_iter().map(|x| (x.1, x.2, x.3)).collect();
    let witness = format!("sample n={n} seed={seed} compiled={compiled} codegens={} best={best}", codegens.len());
    let rec = Record { target: p.target_name.clone(), addr: a, name: name.into(), unit, text: text_hash(&text), sensitive, best, witness };
    Ok(Ok(Sampled { rec, built, compiled, failed, codegens }))
}

/// `dcp headers sample NAME [--n N] [--seed S] [--dry-run]`: the lines and the exit status. The record replaces the
/// function's record in ledger/tiebreak.tsv; an earlier probe's better grade is kept (proof is proof).
pub fn sample_command(p: &Project, name: &str, n: usize, seed: u64, dry: bool) -> Result<(Vec<String>, i32)> {
    use crate::cliread::{fmt_addr, record, Tok};
    let s = |x: &str| Tok::S(x.to_string());
    let r = match sample_function(p, name, n, seed)? {
        Err(e) => return Ok((vec![record(&[("name", s(name)), ("error", s(&e))])], 1)),
        Ok(r) => r,
    };
    let root = p.root.to_string_lossy().into_owned();
    let mut rec = r.rec.clone();
    let old = read(&root).into_iter().find(|x| x.target == rec.target && x.addr == rec.addr && x.text == rec.text);
    if let Some(o) = &old {
        rec.sensitive |= o.sensitive;
        if rank(&o.best) > rank(&rec.best) {
            rec.best = o.best.clone();
        }
    }
    let verdict = if !r.rec.sensitive {
        format!("insensitive: {} samples, one codegen: the declaration set does not move this function; what is left is in its text", r.compiled)
    } else if rank(&rec.best) > rank(&r.built) {
        format!("tie-break sensitive, and a declaration set gives {}: its source-proven grade (the deep queue counts it so)", rec.best)
    } else {
        format!("tie-break sensitive ({} codegens in {} samples), none better than built: the declaration set decides its allocation; park it for \
                 the unit's declaration pass rather than respell it", r.codegens.len(), r.compiled)
    };
    let mut out = vec![record(&[("fn", s(&fmt_addr(r.rec.addr))), ("name", s(name)), ("unit", s(&r.rec.unit)), ("built", s(&r.built)),
                                ("samples", Tok::I(n as i64)), ("compiled", Tok::I(r.compiled as i64)), ("failed", Tok::I(r.failed as i64)),
                                ("sensitive", s(if r.rec.sensitive { "yes" } else { "no" })), ("codegens", Tok::I(r.codegens.len() as i64)),
                                ("best", s(&rec.best))])];
    for (g, k, what) in &r.codegens {
        out.push(format!("  codegen {g}: {k} sample(s); first: {what}"));
    }
    out.push(verdict);
    if dry {
        out.push("(--dry-run: nothing written)".into());
    } else {
        let mut recs: Vec<Record> = read(&root).into_iter().filter(|x| !(x.target == rec.target && x.addr == rec.addr)).collect();
        recs.push(rec);
        recs.sort_by(|x, y| (&x.target, x.addr).cmp(&(&y.target, y.addr)));
        let path = ledger_path(&root);
        if let Some(d) = Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(d);
        }
        crate::edit::write(&path, &render(&recs)).map_err(Error::value)?;
        p.forget_input("tiebreak");
        out.push(format!("written to {LEDGER}"));
    }
    Ok((out, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sampler_places_and_texts() {
        let text = "#line 1 \"src\\\\u.c\"\n#line 1 \"include\\\\a.h\"\ntypedef int A;\nstruct S {\n  int x;\n};\n#line 3 \"src\\\\u.c\"\nint f(a)\nint a;\n{\n  return a;\n}\n";
        let lines: Vec<&str> = text.lines().collect();
        let ps = places(&lines);
        // file scope: `typedef`, `struct`, `int f(a)`; not a K&R parameter after an unended line, not a body's `{`,
        // nothing inside braces
        assert_eq!(ps.iter().map(|p| (p.at, p.file.as_str(), p.line)).collect::<Vec<_>>(),
                   [(2, "include\\a.h", 1), (3, "include\\a.h", 2), (7, "src\\u.c", 3)]);
        let picks = [Pick { what: 0, idx: 1, k: 0 }, Pick { what: 2, idx: 2, k: 0 }];
        let s = sample_text(&lines, &ps, &[], &picks, "t");
        // a padding array split and a union member, each on its own line
        let ty = ["struct T {", "  int a;", "  char pad4[0x8];", "  union {", "    int u;", "  };", "};"];
        let ms = members(&ty);
        assert_eq!(ms.len(), 2, "{ms:?}");
        let t3 = sample_text(&ty, &[], &ms, &[Pick { what: KINDS.len(), idx: 0, k: 3 }], "w");
        assert!(t3.contains("  struct { char __dcp_w_0[8]; } pad4;
"), "{t3}");
        let t2 = sample_text(&ty, &[], &ms, &[Pick { what: KINDS.len(), idx: 0, k: 2 }, Pick { what: KINDS.len(), idx: 1, k: 0 }], "m");
        assert!(t2.contains("  char pad4[3]; char __dcp_m_0[5];\n") && t2.contains("  union { char __dcp_m_1;\n"), "{t2}");
        assert!(s.contains("typedef int A;\ntypedef int __dcp_t_0;\n#line 2 \"include\\\\a.h\"\nstruct S {"), "{s}");
        assert!(s.contains("int __dcp_t_1(void);\n#line 3 \"src\\\\u.c\"\nint f(a)"), "{s}");
        let mut r = Rng(7);
        let v: Vec<usize> = (0..5).map(|_| r.below(10)).collect();
        let mut r2 = Rng(7);
        assert_eq!(v, (0..5).map(|_| r2.below(10)).collect::<Vec<_>>());
    }

    #[test]
    fn normalized_text() {
        assert_eq!(normalize("/* 0x401000, @deep why */\nint f(void)\n{\n    return 1; // one\n}\n"), "int f(void) { return 1; }");
        assert_eq!(normalize("char *s = \"/* no */ //\";  /* c */ int x;"), "char *s = \"/* no */ //\"; int x;");
        assert_eq!(normalize("a = '\\'';\tb;"), "a = '\\''; b;");
        // a tag in the address comment is no change of the text
        assert_eq!(text_hash(&normalize("/* 0x1 */\nint f(void) { }")), text_hash(&normalize("/* 0x1 @deep tried */\nint f(void) { }")));
    }

    #[test]
    fn records_round_trip_and_merge() {
        let r = |t: &str, a: i64, u: &str, s: bool| Record { target: t.into(), addr: a, name: format!("f{a:x}"), unit: u.into(), text: "ab".into(),
                                                            sensitive: s, best: "byte".into(), witness: "control=shape p1=byte*".into() };
        let recs = vec![r("exe", 0x401000, "a", true), r("exe", 0x402000, "b", false)];
        assert_eq!(parse(&render(&recs)), recs);
        // a probed unit's records replace its old ones; the others stay
        let m = merged(recs.clone(), "exe", &HashSet::from(["a".to_string()]), vec![r("exe", 0x401100, "a", false)]);
        assert_eq!(m.iter().map(|x| x.addr).collect::<Vec<_>>(), [0x401100, 0x402000]);
    }

    #[test]
    fn moved_lines() {
        assert_eq!(moved_line("include/ai_types.h, uncommitted", &["f".into(), "g".into()]), "tie-break: 2 functions moved (include/ai_types.h, uncommitted): f, g");
    }
}
