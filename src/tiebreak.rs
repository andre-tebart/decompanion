//! Declaration-set tie-breaks: VC6 /O2 breaks ties in its register allocation
//! by the declaration set a unit sees, so a change in a widely included header (a union member, a field, an unused
//! typedef) moves functions that never use the changed type between byte, shape and draft. That is the headers'
//! business, not the function's: the object experiment would be reporting on something else.
//!
//! The mechanism (measured on a VC6 project): the allocator frees unreferenced constant candidates in a 64-bucket
//! walk keyed by the front end's running symbol ordinal (`& 0x3f`) for every string literal and global a function
//! uses, so every declaration before a function can move it, with period 64 in the count. The sweep is the
//! experiment that settles it for one text: the unit compiled as the build compiles it (the control), then with
//! k = 1..63 unused typedefs at the unit's start (every ordinal shifted) and before the function (its own symbols
//! shifted against everything declared before it), each function graded as G.grade grades it. Measured: the code
//! under k and k + 64 typedefs is the same at both places (the names do not matter, the count does). A compile that
//! gives the original's bytes is proof that the text is right: a declaration set exists under which it gives them.
//! A sweep that finds none says the difference is in the text. Not covered: two shifts at once (the unit's start
//! and before the function in combination, 64 x 64 states) and shifts between two other declarations; a function
//! the original reached only so stays below byte, and nothing is counted done that no compile showed.
//!
//! Where it runs, so that no worker has to: `dcp try` on its closest variant when that is close (shape, or at most
//! CLOSE_INS instructions) and below byte, `dcp grade NAME` and `dcp build` on a close function below byte that the
//! tree changed, and `dcp build` on every function that fell below the baseline (to the grade it had); each stops
//! at the first compile that reaches its goal. `dcp headers sweep NAME` runs it whole, `dcp headers probe UNIT` at
//! the unit's start for every function of the unit at once.
//!
//! The records are kept in ledger/tiebreak.tsv (never written by hand): target, address, name, unit, the hash of
//! the function's text (comments and whitespace runs aside), sensitive (more than one codegen), best, the witness
//! (the sweep's control, best, the declaration set that gave it, the codegens), the unit's compile inputs it was
//! measured under. Sweeps of other texts (try's variants) are cached under build/. M.tiebreak turns each record
//! whose function's text is still the same into a derived `tiebreak` claim; a changed text leaves the record stale.
//!
//! Who reads them: G.grade (the experiment's `tiebreak` and `proven`: a best grade above the built one is the
//! source-proven grade; no M2.stale for a sensitive function; the unit's G.tiebreak gap: its declaration set is not
//! yet the original's while a function reaches a better grade under a swept set than as built), M1, the session
//! wrap and promote (a function whose own text is the same since the baseline and whose record under the unit's
//! current inputs still reaches the grade it had is no fall: declaration_move), the queues (the proven grade is the
//! code grade of the work: a proven byte leaves the base and the deep queue) and the build's auto-clear (no tag is
//! cleared on a sensitive function).

use crate::coff::{FunctionCode, Obj};
use crate::error::{Error, Result};
use crate::project::{native_path, Project};
use crate::rules::Ctx;
use crate::store::{self, Out, DERIVED};
use rusqlite::Connection;
use serde_json::{json, Value};
use sha1::{Digest, Sha1};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

pub const LEDGER: &str = "ledger/tiebreak.tsv";
pub const HEADER: &str = "target\taddress\tname\tunit\ttext\tsensitive\tbest\twitness\tinputs";

fn err(e: impl std::fmt::Display) -> Error {
    Error::runtime(e.to_string())
}

fn rank(c: &str) -> Option<usize> {
    crate::grade::CODE.iter().position(|x| *x == c)
}

// ------------------------------------------------------------------------------------------------ the records

/// One function's probe record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Record {
    pub target: String,
    pub addr: i64,
    pub name: String,
    pub unit: String,
    pub text: String,
    pub sensitive: bool,
    pub best: String,
    pub witness: String,
    /// the unit's compile inputs (`inputs_of`) the record was measured under; empty in a record of an older dcp
    pub inputs: String,
}

pub fn parse(text: &str) -> Vec<Record> {
    text.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#') && !l.starts_with("target\t")).filter_map(|l| {
        let f: Vec<&str> = l.split('\t').collect();
        if f.len() < 8 {
            return None;
        }
        Some(Record { target: f[0].into(), addr: crate::layout::int16(f[1])?, name: f[2].into(), unit: f[3].into(), text: f[4].into(),
                      sensitive: f[5] == "yes", best: f[6].into(), witness: f[7].into(), inputs: f.get(8).map(|x| x.to_string()).unwrap_or_default() })
    }).collect()
}

pub fn render(recs: &[Record]) -> String {
    let mut out = format!("{HEADER}\n");
    for r in recs {
        out.push_str(&[r.target.as_str(), &format!("{:#010x}", r.addr), &r.name, &r.unit, &r.text, if r.sensitive { "yes" } else { "no" }, &r.best,
                       &r.witness, &r.inputs].join("\t"));
        out.push('\n');
    }
    out
}

fn ledger_path(root: &str) -> String {
    native_path(&format!("{root}/{LEDGER}"))
}

pub fn read(root: &str) -> Vec<Record> {
    parse(&crate::fsmemo::read_text(&ledger_path(root)).unwrap_or_default())
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
    let text = crate::fsmemo::read_text(&native_path(&format!("{root}/{file}"))).ok()?;
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
/// sensitive, best, witness}, merged with the function's NOW record of the same text (tiebreak_of). A record whose
/// text changed is stale and gives nothing; a NOW record of the current text then stands alone (the text changed in
/// an earlier commit: its ledger row changes only with the next edit of the function).
pub fn m_tiebreak(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let recs: HashMap<i64, Record> = read(&ctx.root).into_iter().filter(|r| r.target == ctx.inputs.target).map(|r| (r.addr, r)).collect();
    let now: HashMap<i64, Record> = now_read(&ctx.root).into_iter().filter(|r| r.target == ctx.inputs.target).map(|r| (r.addr, r)).collect();
    if recs.is_empty() && now.is_empty() {
        return Ok(());
    }
    let srcs = store::claims(db, &ctx.db, "source", &ctx.needed, |f| &*f.rule == "L.src" && f.s("what") == Some("func")).map_err(err)?;
    for s in srcs {
        let (r, n) = (recs.get(&s.lo), now.get(&s.lo));
        if r.is_none() && n.is_none() {
            continue;
        }
        let (file, comment, end) = (s.s("file").unwrap_or(""), s.value["comment"].as_i64().unwrap_or(0), s.value["end"].as_i64().unwrap_or(0));
        let Some(th) = fn_text(&ctx.root, file, comment, end).map(|t| text_hash(&t)) else { continue };
        let Some(mut v) = tiebreak_of(r, n, &th) else { continue };
        for (k, x) in [("name", s.value["symbol"].clone()), ("unit", s.value["unit"].clone()), ("file", json!(file)), ("comment", json!(comment)), ("end", json!(end))] {
            v[k] = x;
        }
        out.claim(s.lo, s.lo + 1, "tiebreak", v, DERIVED);
    }
    Ok(())
}

/// The `tiebreak` claim's record part for a function whose text hashes to `th`: its ledger record `led` and its NOW
/// record `now` (the latest measurement under other inputs), each only when of that text. Both: NOW's inputs and its
/// own best (inputs_best) for declaration_move, the better best proves the text's grade (proof is proof). One alone
/// stands for itself.
fn tiebreak_of(led: Option<&Record>, now: Option<&Record>, th: &str) -> Option<Value> {
    let (led, now) = (led.filter(|r| r.text == th), now.filter(|r| r.text == th));
    Some(match (led, now) {
        (Some(r), Some(n)) => {
            let b = if rank(&n.best) > rank(&r.best) { n } else { r };
            json!({"sensitive": r.sensitive || n.sensitive, "best": b.best, "witness": b.witness, "inputs": n.inputs, "inputs_best": n.best})
        }
        (Some(r), None) | (None, Some(r)) => json!({"sensitive": r.sensitive, "best": r.best, "witness": r.witness, "inputs": r.inputs}),
        (None, None) => return None,
    })
}

// ------------------------------------------------------------------------------------------------ attribution

/// The changed declarations a function fell by without falling (M1, the wrap, promote): its `tiebreak` record
/// measured under its unit's current compile inputs (`inputs_now`) gives at least the grade it had (`was`): its
/// text, with the declarations as they are, still reaches that grade under some declaration set; its own text is the
/// same as at the changes' base; and its unit's compile inputs changed (a header of its include closure, or its
/// unit's file outside the function). The label names them: the changed headers (`, uncommitted` on each the
/// working tree changed), else the unit's file. A record of other inputs proves nothing: a header that changed a
/// meaning could have moved the function (the build sweeps a fallen function again: build_sweeps).
pub fn declaration_move(root: &str, ch: &crate::cause::Changes, tb: &Value, unit_file: &str, was: &str, inputs_now: &str) -> Option<String> {
    let inputs = tb.get("inputs").and_then(|v| v.as_str()).unwrap_or("");
    // the best under these inputs (a claim that merges a ledger record of other inputs carries it apart)
    let best = tb.get("inputs_best").or_else(|| tb.get("best")).and_then(|v| v.as_str()).unwrap_or("");
    if inputs.is_empty() || inputs != inputs_now || rank(best) < rank(was) || rank(was).is_none() {
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
        let img = crate::image(&p.target.path)?;
        let tc = crate::toolchain::Vc6;
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
        self.grade_refs(o, code, a).0
    }

    /// `grade`, and the references that differ from the original's by rule (`M8 x2`; '' when none does).
    pub(crate) fn grade_refs(&self, o: &Obj, code: &FunctionCode, a: i64) -> (&'static str, String) {
        let img = &*self.img;
        let env = crate::diffclass::Env { img, range: (img.base as i64, img.end() as i64), fills: &self.fills, forms: &self.forms };
        let g = crate::grade::Grader { env, phi: &self.phi, align: self.align };
        let next = self.starts.get(self.starts.partition_point(|&x| x <= a)).copied().unwrap_or(img.end() as i64) as u32;
        let matched = crate::compare::compare(img, code, a as u32, self.relocs.as_deref(), next, &self.forms).matched();
        let (grade, rules) = g.grade_refs(o, code, a, next, self.walk.get(&a).copied(), matched);
        let mut by: BTreeMap<&str, usize> = BTreeMap::new();
        for r in rules {
            *by.entry(r).or_default() += 1;
        }
        (grade, by.iter().map(|(r, n)| if *n == 1 { r.to_string() } else { format!("{r} x{n}") }).collect::<Vec<_>>().join(", "))
    }

    /// One function's distance from the original: (differing instructions on both sides, the bytes of the differing
    /// instructions, the hunk classes, our code size less the original's). The bytes are counted on the aligned
    /// listings (per differing run the longer side, the frames aligned as the instructions are): a positional count
    /// took every byte after one instruction of another length as differing (one 3-byte for a 2-byte encoding read 91
    /// bytes, and a worse variant ranked before it); a byte match has none, whatever the count.
    pub(crate) fn distance(&self, o: &Obj, code: &FunctionCode, a: i64) -> (usize, usize, String, i64) {
        let img = &*self.img;
        let env = crate::diffclass::Env { img, range: (img.base as i64, img.end() as i64), fills: &self.fills, forms: &self.forms };
        let next = self.starts.get(self.starts.partition_point(|&x| x <= a)).copied().unwrap_or(img.end() as i64) as u32;
        let (cd, cm) = code.code();
        let size = crate::diffclass::code_size(&env, cd, cm, a as u32);
        let extent = self.walk.get(&a).map(|h| h - a).unwrap_or(size);
        let orig = crate::diffclass::original(&env, a as u32, extent, extent.max(next as i64 - a), self.align);
        let fc = crate::diffclass::FunctionCompare::new(&env, o, code, a as u32, &orig);
        let shapes = |l: &[crate::x86::Line]| -> Vec<crate::shape::Shape> { l.iter().map(|x| x.shape.clone()).collect() };
        let texts = |l: &[crate::x86::Line]| -> Vec<String> { l.iter().map(|x| x.text.clone()).collect() };
        let ops = match fc.verdict.frame {
            Some(f) => crate::difflib::opcodes(&crate::shape::stack_mask(&shapes(&fc.la), f), &crate::shape::stack_mask(&shapes(&fc.lb), f)),
            None => crate::difflib::opcodes(&texts(&fc.la), &texts(&fc.lb)),
        };
        let run = |l: &[crate::x86::Line], lo: usize, hi: usize| l[lo..hi].iter().map(|x| x.size as usize).sum::<usize>();
        let bytes = ops.iter().filter(|o| o.0 != crate::difflib::Tag::Equal).map(|o| run(&fc.la, o.1, o.2).max(run(&fc.lb, o.3, o.4))).sum();
        (fc.verdict.distance, bytes, fc.verdict.summary_without_branches(), size - orig.code)
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
    let full = |r: &str| native_path(&format!("{root}/{r}"));
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
        // the unit's bytes as the file has them (edit::read_src kept a Latin-1 byte as its private-use character)
        std::fs::write(full(&src), crate::edit::encode(&text)).map_err(|e| e.to_string())?;
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

// ------------------------------------------------------------------------------------------------ the measurements

/// The functions a build sweeps at most (each costs up to 2 x 63 compiles of its unit); the rest the next build.
const BUILD_MAX: usize = 8;

/// A function close enough to its original that the declaration set may be all that is left: shape, or at most
/// CLOSE_INS differing instructions.
pub const CLOSE_INS: i64 = 24;

pub fn close(code: &str, ins: Option<i64>) -> bool {
    code == "shape" || ins.is_some_and(|d| d <= CLOSE_INS)
}

/// The sweeps of texts that are not (or not yet) the tree's: `dcp try`'s variants, the texts a build swept before
/// the function changed again. Not committed: the ledger holds the records of the tree's texts.
const CACHE: &str = "build/tiebreak-cache.tsv";
const CACHE_MAX: usize = 4000;

/// The records a build or `dcp grade` measured for a function whose ledger record holds the same text under other
/// compile inputs (another function of its unit changed, a header): one per function, not committed. The ledger
/// row stays as it is (it changes only with the function's text); M.tiebreak reads both.
pub const NOW: &str = "build/tiebreak-now.tsv";

pub fn now_read(root: &str) -> Vec<Record> {
    parse(&std::fs::read_to_string(native_path(&format!("{root}/{NOW}"))).unwrap_or_default())
}

/// Put records into NOW (each replaces its function's), drop those of `gone` (target, address: a ledger row written).
fn now_put(root: &str, fresh: &[Record], gone: &[(String, i64)]) {
    let old = now_read(root);
    if fresh.is_empty() && !old.iter().any(|r| gone.contains(&(r.target.clone(), r.addr))) {
        return;
    }
    let mut by: BTreeMap<(String, i64), Record> = old.into_iter().map(|r| ((r.target.clone(), r.addr), r)).collect();
    for g in gone {
        by.remove(g);
    }
    for r in fresh {
        by.insert((r.target.clone(), r.addr), r.clone());
    }
    let path = native_path(&format!("{root}/{NOW}"));
    if let Some(d) = Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::write(&path, render(&by.into_values().collect::<Vec<_>>()));
}

/// Where a measured record goes: the ledger when the function has no record there, one of another text while the
/// working tree changed the function's text (`edited`: against HEAD) or one of the same inputs (a refinement), else
/// NOW: the same text under other inputs (the ledger row does not churn with every edit of its unit), or a row left
/// stale by a text an earlier commit changed (it changes with the function's next edit, not in the commit of a
/// sibling's: he_RunSecretRoom's row rewritten by a build after a note on he_RunDecay).
fn to_ledger(ledger: &[Record], rec: &Record, edited: bool) -> bool {
    ledger.iter().find(|r| r.target == rec.target && r.addr == rec.addr).is_none_or(|r| (r.text != rec.text && edited) || (r.text == rec.text && r.inputs == rec.inputs))
}

/// Whether the working tree changed a function's text (normalized, `now`) of `file` against HEAD; true outside git
/// or when HEAD has no such file. `heads` keeps each file's normalized HEAD text.
fn edited_since_head(root: &str, ch: &Option<crate::cause::Changes>, heads: &mut HashMap<String, Option<String>>, file: &str, now: &str) -> bool {
    let Some(ch) = ch else { return true };
    let then = heads.entry(file.to_string()).or_insert_with(|| ch.text_at(root, file).map(|t| normalize(&t)));
    then.as_ref().is_none_or(|t| !t.contains(now))
}

fn cache_read(root: &str) -> Vec<Record> {
    parse(&std::fs::read_to_string(native_path(&format!("{root}/{CACHE}"))).unwrap_or_default())
}

fn cache_put(root: &str, fresh: &[Record]) {
    if fresh.is_empty() {
        return;
    }
    let key = |r: &Record| (r.target.clone(), r.addr, r.text.clone(), r.inputs.clone());
    let new: HashSet<_> = fresh.iter().map(key).collect();
    let mut recs: Vec<Record> = cache_read(root).into_iter().filter(|r| !new.contains(&key(r))).collect();
    recs.extend(fresh.iter().cloned());
    if recs.len() > CACHE_MAX {
        recs.drain(..recs.len() - CACHE_MAX);
    }
    let path = native_path(&format!("{root}/{CACHE}"));
    if let Some(d) = Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::write(&path, render(&recs));
}

/// Whether a sweep record covered every declaration set (a sweep stopped at its goal, or one of the unit's start
/// only, did not).
pub fn complete(r: &Record) -> bool {
    r.witness.starts_with("sweep ") && !r.witness.contains("(stopped at the goal)") && !r.witness.contains("(the unit's start only)")
}

/// The record of a function's text under its unit's inputs that answers for `goal`: one that reached the goal, or
/// a complete sweep. The ledger first, then the cache.
fn known(root: &str, ledger: &[Record], target: &str, addr: i64, text: &str, inputs: &str, goal: &str) -> Option<(Record, bool)> {
    let ok = |r: &Record| r.target == target && r.addr == addr && r.text == text && !inputs.is_empty() && r.inputs == inputs
        && (rank(&r.best) >= rank(goal) || complete(r));
    if let Some(r) = ledger.iter().find(|r| ok(r)) {
        return Some((r.clone(), true));
    }
    cache_read(root).into_iter().rev().find(|r| ok(r)).map(|r| (r, false))
}

/// One function to measure and the grade at which its sweep may stop.
pub(crate) struct Want {
    pub name: String,
    pub goal: &'static str,
}

/// One measured function: its record and whether it was swept now (else known from the ledger or the cache).
pub(crate) struct Measured {
    pub rec: Record,
    pub built: String,
    pub swept: bool,
    /// its record was not in the ledger (written now)
    pub new: bool,
}

/// Measure functions of the tree as it is: each function's record for its current text under its unit's current
/// compile inputs, known (the ledger, the cache) or swept now (one sweep per unit for its wanted functions,
/// stopping when each reached its goal). Every record goes into the ledger (a cached one too: it is the tree's now)
/// and the swept ones into the cache. A function that cannot be measured (no span, defined in an included file,
/// its unit not built) is left out.
pub(crate) fn measure(p: &Project, wants: &[Want], max_swept: usize) -> Result<(Vec<Measured>, usize)> {
    let root = p.root.to_string_lossy().into_owned();
    let db = p.store_path();
    let plan = crate::plan::plan(p).map_err(err)?;
    let ledger = read(&root);
    let keys = crate::compile::tu_keys(&db)?;
    let mut out: Vec<Measured> = vec![];
    // unit -> (its text, its inputs, the targets with their text hashes and built grades)
    let mut todo: BTreeMap<String, (String, String, Vec<(Target, String, String)>)> = BTreeMap::new();
    let (mut queued, mut left) = (0, 0);
    let loc = Locator::of(p)?;
    // the functions whose ledger row is of another text: whether the working tree changed it (to_ledger)
    let mut edited: HashMap<i64, bool> = HashMap::new();
    let (mut head, mut heads): (Option<Option<crate::cause::Changes>>, HashMap<String, Option<String>>) = (None, HashMap::new());
    for w in wants {
        let Some(l) = loc.get(&w.name).ok() else { continue };
        let Some(t) = plan.iter().find(|t| t.unit == l.unit) else { continue };
        let Some(k) = keys.get(&l.unit) else { continue };
        if l.file != t.file || l.built == crate::grade::NOT_RUN {
            continue;
        }
        let Some(ftext) = fn_text(&root, &l.file, l.comment, l.end) else { continue };
        let path = native_path(&format!("{root}/{}", t.file));
        let inputs = inputs_of(&crate::fsmemo::sha256(&path).map_err(err)?, &k.flags_hash, &k.include_hash);
        let th = text_hash(&ftext);
        if ledger.iter().any(|r| r.target == p.target_name && r.addr == l.addr && r.text != th) {
            let ch = head.get_or_insert_with(|| crate::cause::Changes::since(&root, "HEAD"));
            edited.insert(l.addr, edited_since_head(&root, ch, &mut heads, &l.file, &ftext));
        }
        if let Some((rec, _)) = known(&root, &ledger, &p.target_name, l.addr, &th, &inputs, w.goal) {
            out.push(Measured { rec, built: l.built.clone(), swept: false, new: false });
            continue;
        }
        if queued >= max_swept {
            left += 1;
            continue;
        }
        queued += 1;
        let e = match todo.entry(l.unit.clone()) {
            std::collections::btree_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::btree_map::Entry::Vacant(v) => {
                let text = crate::edit::read_src(&path).map_err(err)?;
                v.insert((text, inputs.clone(), vec![]))
            }
        };
        e.2.push((Target { name: w.name.clone(), addr: l.addr, comment: l.comment, goal: w.goal }, th, l.built.clone()));
    }
    if !todo.is_empty() {
        let bench = Bench::of(p)?;
        for (unit, (text, inputs, ts)) in &todo {
            let t = plan.iter().find(|t| &t.unit == unit).unwrap();
            let targets: Vec<Target> = ts.iter().map(|x| x.0.clone()).collect();
            let (res, _) = sweep(p, t, text, &targets, false, PERIOD, true, &bench)?;
            for (s, (_, th, built)) in res.iter().zip(ts) {
                if s.compiled == 0 {
                    continue;
                }
                out.push(Measured { rec: sweep_record(p, unit, th, inputs, s), built: built.clone(), swept: true, new: false });
            }
        }
    }
    let swept: Vec<Record> = out.iter().filter(|m| m.swept).map(|m| m.rec.clone()).collect();
    cache_put(&root, &swept);
    let mut fresh: Vec<Record> = vec![];
    let mut now: Vec<Record> = vec![];
    let have_now = now_read(&root);
    for m in out.iter_mut() {
        if ledger.iter().any(|r| r == &m.rec) || have_now.iter().any(|r| r == &m.rec) {
            continue;
        }
        m.new = true;
        if to_ledger(&ledger, &m.rec, edited.get(&m.rec.addr).copied().unwrap_or(true)) {
            fresh.push(m.rec.clone());
        } else {
            now.push(m.rec.clone());
        }
    }
    let gone: Vec<(String, i64)> = fresh.iter().map(|r| (r.target.clone(), r.addr)).collect();
    now_put(&root, &now, &gone);
    if !now.is_empty() {
        p.forget_input("tiebreak");
    }
    put_records(p, fresh)?;
    Ok((out, left))
}

/// One measured function in a line: `name: <verdict>`.
pub(crate) fn measured_line(m: &Measured) -> String {
    let set = m.rec.witness.split(" by ").nth(1).and_then(|x| x.split(';').next()).unwrap_or("").to_string();
    format!("{}: {}", m.rec.name, verdict(&m.rec.best, &m.built, &set, complete(&m.rec)))
}

/// The build's measurements (after its grades): every function that fell below the baseline (ledger/grades.tsv),
/// to the grade it had (so that M1 tells a declaration-set move from a fall), then every function the working tree
/// changed against HEAD in a unit this build compiled that is close to its original and below byte, to byte (so
/// that a text the declaration set alone keeps from byte counts as done). At most BUILD_MAX functions swept; the
/// lines say what was measured.
pub fn build_sweeps(p: &Project, compiled: &[String]) -> Result<Vec<String>> {
    let root = p.root.to_string_lossy().into_owned();
    if !crate::vc6::Tools::of(p).available() {
        return Ok(vec![]);
    }
    let db = p.store_path();
    let rows = crate::queues::function_grades(&db)?;
    let base = crate::fsmemo::read_text(&native_path(&format!("{root}/ledger/grades.tsv"))).unwrap_or_default();
    let base: HashMap<i64, String> = crate::queues::parse_baseline(&base).into_iter().filter(|x| x.0 .0 == p.target_name).map(|x| (x.0 .1, x.1.code)).collect();
    let mut wants: Vec<Want> = vec![];
    let mut out = restore_reverted(p, compiled)?;
    for r in rows.iter() {
        let (a, code) = (r["addr"].as_i64().unwrap_or(0), r["code"].as_str().unwrap_or(""));
        // only the units this build compiled: a unit it did not compile has the objects (and records) it had
        if !compiled.iter().any(|u| Some(u.as_str()) == r["unit"].as_str()) {
            continue;
        }
        if let Some(b) = base.get(&a) {
            if let (Some(bi), Some(n)) = (rank(b), rank(code)) {
                if n < bi {
                    wants.push(Want { name: r["name"].as_str().unwrap_or("").into(), goal: crate::grade::CODE[bi] });
                }
            }
        }
    }
    // the close functions below byte of the units this build compiled; git is read only when there is one
    let cands: Vec<&str> = rows.iter().filter(|r| {
        let (unit, code, name) = (r["unit"].as_str().unwrap_or(""), r["code"].as_str().unwrap_or(""), r["name"].as_str().unwrap_or(""));
        let ins = r.get("dist").and_then(|d| d.get("ins")).and_then(|v| v.as_i64());
        compiled.iter().any(|u| u == unit) && code != "byte" && code != crate::grade::NOT_RUN && close(code, ins) && !wants.iter().any(|w| w.name == name)
    }).map(|r| r["name"].as_str().unwrap_or("")).collect();
    if !cands.is_empty() {
        let ch = crate::cause::Changes::since(&root, "HEAD");
        if ch.is_some() {
            let mut heads: HashMap<String, Option<String>> = HashMap::new();
            let loc = Locator::of(p)?;
            for name in cands {
                let Some(l) = loc.get(name).ok() else { continue };
                let Some(now) = fn_text(&root, &l.file, l.comment, l.end) else { continue };
                if edited_since_head(&root, &ch, &mut heads, &l.file, &now) {
                    wants.push(Want { name: name.into(), goal: "byte" });
                }
            }
        }
    }
    if wants.is_empty() {
        return Ok(out);
    }
    let t0 = std::time::Instant::now();
    let (ms, left) = measure(p, &wants, BUILD_MAX)?;
    let swept = ms.iter().filter(|m| m.swept).count();
    if !ms.iter().any(|m| m.new) {
        return Ok(out);
    }
    out.push(format!("declaration-set sweep of {swept} function(s), {} ms{}:", t0.elapsed().as_millis(),
                               if left > 0 { format!(" ({left} more: the next build)") } else { String::new() }));
    out.extend(ms.iter().filter(|m| m.new).map(|m| format!("  {}", measured_line(m))));
    Ok(out)
}

/// The ledger rows of the functions of the units this build compiled whose text is no longer the function's while the
/// committed ledger (HEAD) has the row of the function's current text: an experiment's text (a `dcp try --apply`
/// reverted) wrote them; the committed rows come back. The lines say which.
fn restore_reverted(p: &Project, compiled: &[String]) -> Result<Vec<String>> {
    let root = p.root.to_string_lossy().into_owned();
    let ledger = read(&root);
    let loc = Locator::of(p)?;
    let mut stale: Vec<(&Record, String)> = vec![];
    for r in ledger.iter().filter(|r| r.target == p.target_name && compiled.contains(&r.unit)) {
        let Some(l) = loc.get(&r.name).ok().filter(|l| l.addr == r.addr) else { continue };
        let Some(now) = fn_text(&root, &l.file, l.comment, l.end) else { continue };
        let th = text_hash(&now);
        if th != r.text {
            stale.push((r, th));
        }
    }
    if stale.is_empty() {
        return Ok(vec![]);
    }
    let Some(head) = crate::cause::Changes::since(&root, "HEAD").and_then(|ch| ch.text_at(&root, LEDGER)) else { return Ok(vec![]) };
    let head = parse(&head);
    let back: Vec<Record> = stale.iter()
        .filter_map(|(r, th)| head.iter().find(|h| h.target == r.target && h.addr == r.addr && &h.text == th).cloned())
        .collect();
    if back.is_empty() {
        return Ok(vec![]);
    }
    let names: Vec<String> = back.iter().map(|r| r.name.clone()).collect();
    let mut by: BTreeMap<(String, i64), Record> = ledger.into_iter().map(|r| ((r.target.clone(), r.addr), r)).collect();
    for r in back {
        by.insert((r.target.clone(), r.addr), r);
    }
    crate::edit::write(&ledger_path(&root), &render(&by.into_values().collect::<Vec<_>>())).map_err(Error::value)?;
    p.forget_input("tiebreak");
    Ok(vec![format!("tie-break: the committed record back for {} function(s) whose text is the committed one again: {}", names.len(), names.join(", "))])
}

/// `dcp grade NAME`'s measurement: a function close to its original and below byte whose text has no record under
/// its unit's inputs is swept (to byte). The line, when one was swept.
pub fn grade_sweep(p: &Project, name: &str) -> Result<Option<String>> {
    if !crate::vc6::Tools::of(p).available() {
        return Ok(None);
    }
    let rows = crate::queues::function_grades(&p.store_path())?;
    let Some(r) = rows.iter().find(|r| r["name"].as_str() == Some(name)) else { return Ok(None) };
    let code = r["code"].as_str().unwrap_or("");
    let ins = r.get("dist").and_then(|d| d.get("ins")).and_then(|v| v.as_i64());
    if code == "byte" || code == crate::grade::NOT_RUN || !close(code, ins) {
        return Ok(None);
    }
    let (ms, _) = measure(p, &[Want { name: name.into(), goal: "byte" }], 1)?;
    Ok(ms.iter().find(|m| m.new).map(measured_line))
}

/// `dcp headers probe [UNIT..] [--dry-run]`: every function of the units (every unit when none is named) swept at
/// the unit's start (0..63 unused typedefs: one sweep measures the whole unit), recorded: (the lines, the exit
/// status: 1 when a unit could not be swept).
pub fn probe_command(p: &Project, units: Vec<String>, dry: bool) -> Result<(Vec<String>, i32)> {
    use crate::cliread::{fmt_addr, record, Tok};
    let s = |x: &str| Tok::S(x.to_string());
    let root = p.root.to_string_lossy().into_owned();
    let db = p.store_path();
    let plan = crate::plan::plan(p).map_err(err)?;
    let units = if units.is_empty() { plan.iter().map(|t| t.unit.clone()).collect() } else { units };
    let rows = crate::queues::function_grades(&db)?;
    let keys = crate::compile::tu_keys(&db)?;
    let bench = Bench::of(p)?;
    let loc = Locator::of(p)?;
    let (mut out, mut recs, mut bad, mut n) = (vec![], vec![], 0, 0);
    for u in &units {
        let Some(t) = plan.iter().find(|t| &t.unit == u) else {
            out.push(record(&[("unit", s(u)), ("error", s(&format!("no unit {u} in target {}", p.target_name)))]));
            bad += 1;
            continue;
        };
        let Some(k) = keys.get(u) else {
            out.push(record(&[("unit", s(u)), ("error", s("not built (dcp build)"))]));
            bad += 1;
            continue;
        };
        let path = native_path(&format!("{root}/{}", t.file));
        let inputs = inputs_of(&crate::fsmemo::sha256(&path).map_err(err)?, &k.flags_hash, &k.include_hash);
        let text = crate::edit::read_src(&path).map_err(err)?;
        let mut targets = vec![];
        let mut th = vec![];
        for r in rows.iter().filter(|r| r["unit"].as_str() == Some(u.as_str()) && r["code"].as_str() != Some(crate::grade::NOT_RUN)) {
            let name = r["name"].as_str().unwrap_or("");
            let Some(l) = loc.get(name).ok().filter(|l| l.file == t.file) else { continue };
            let Some(ft) = fn_text(&root, &l.file, l.comment, l.end) else { continue };
            targets.push(Target { name: name.into(), addr: l.addr, comment: l.comment, goal: "byte" });
            th.push((text_hash(&ft), l.built));
        }
        let (res, _) = sweep(p, t, &text, &targets, true, PERIOD, false, &bench)?;
        if res.iter().all(|r| r.compiled == 0) {
            out.push(record(&[("unit", s(u)), ("error", s("does not compile"))]));
            bad += 1;
            continue;
        }
        let raised: Vec<(&Swept, &String)> = res.iter().zip(&th).filter(|(r, (_, b))| rank(&r.best) > rank(b)).map(|(r, (_, b))| (r, b)).collect();
        out.push(record(&[("unit", s(u)), ("functions", Tok::I(res.len() as i64)), ("moved", Tok::I(res.iter().filter(|r| r.codegens > 1).count() as i64)),
                          ("raised", Tok::I(raised.len() as i64))]));
        for (r, b) in raised {
            out.push(format!("  {}", record(&[("fn", s(&fmt_addr(r.addr))), ("name", s(&r.name)), ("built", s(b)), ("best", s(&r.best)),
                                              ("by", s(&r.set.words()))])));
        }
        for (r, (h, _)) in res.iter().zip(&th) {
            if r.compiled > 0 {
                let mut rec = sweep_record(p, u, h, &inputs, r);
                rec.witness = format!("{} (the unit's start only)", rec.witness);
                recs.push(rec);
            }
        }
        n += 1;
    }
    let tail = if dry { " (--dry-run: nothing written)".to_string() } else { format!("; written to {LEDGER}") };
    out.push(format!("swept {n} unit(s), {} function(s){tail}", recs.len()));
    if !dry {
        put_records(p, recs)?;
    }
    Ok((out, if bad > 0 { 1 } else { 0 }))
}

/// `dcp try`'s measurement of its closest variant (or the control) that is close and below byte: its text swept
/// (to byte) unless the cache knows it under the unit's inputs with the variant applied. `unit_text`: the unit's text
/// with the variant (\n lines), `file_bytes`: the file as --apply would write it (its hash is the unit's inputs).
pub(crate) fn try_sweep(p: &Project, t: &crate::plan::Tu, unit_text: &str, file_bytes: &str, name: &str, addr: i64, comment: i64, ftext: &str)
                        -> Result<Option<Record>> {
    let root = p.root.to_string_lossy().into_owned();
    let Some(k) = crate::compile::tu_keys(&p.store_path())?.remove(&t.unit) else { return Ok(None) };
    // the file's bytes: a Latin-1 byte edit::read_src kept as its private-use character is that byte again
    let src_hash = crate::fsmemo::hex(&<sha2::Sha256 as sha2::Digest>::digest(crate::edit::encode(file_bytes)));
    let inputs = inputs_of(&src_hash, &k.flags_hash, &k.include_hash);
    let th = text_hash(&normalize(ftext));
    if let Some((r, _)) = known(&root, &read(&root), &p.target_name, addr, &th, &inputs, "byte") {
        return Ok(Some(r));
    }
    let bench = Bench::of(p)?;
    let (res, _) = sweep(p, t, unit_text, &[Target { name: name.into(), addr, comment, goal: "byte" }], false, PERIOD, true, &bench)?;
    let Some(s) = res.first().filter(|s| s.compiled > 0) else { return Ok(None) };
    let rec = sweep_record(p, &t.unit, &th, &inputs, s);
    cache_put(&root, std::slice::from_ref(&rec));
    Ok(Some(rec))
}

// ------------------------------------------------------------------------------------------------ the sweep

/// The period of the tie-breaks in the symbol ordinal: VC6's front end numbers every symbol it enters, and the
/// register allocator frees its unreferenced constant candidates in a 64-bucket walk keyed by `ordinal & 0x3f` for
/// every string literal and global a function uses. N unused typedefs shift every later ordinal by N, so the shifts
/// 0..63 at a place are every state that place's count can give.
pub const PERIOD: usize = 64;

/// One declaration set of a sweep: `k` unused typedefs at the unit's start (every ordinal of the unit shifted) or
/// before one function's address comment (that function's own symbols and every later one shifted against the
/// declarations before it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Shift {
    Start(usize),
    Before(usize, String),
}

impl Shift {
    /// The set in words: `17 unused typedefs at the unit's start`, `5 unused typedefs before f`.
    pub fn words(&self) -> String {
        let n = |k: usize| format!("{k} unused typedef{}", if k == 1 { "" } else { "s" });
        match self {
            Shift::Start(0) => "the build's declarations".into(),
            Shift::Start(k) => format!("{} at the unit's start", n(*k)),
            Shift::Before(k, f) => format!("{} before {f}", n(*k)),
        }
    }
}

/// `k` unused typedefs on one line, each under a name of its own.
fn typedefs(k: usize, tag: &str) -> String {
    (0..k).map(|j| format!("typedef int __dcp_{tag}_{j};")).collect::<Vec<_>>().join(" ")
}

/// One function a sweep measures: its name, address, address comment line (1-based, in the swept text) and the
/// grade at which the sweep may stop for it.
#[derive(Clone, Debug)]
pub(crate) struct Target {
    pub name: String,
    pub addr: i64,
    pub comment: i64,
    pub goal: &'static str,
}

/// What a sweep found for one function.
#[derive(Clone, Debug)]
pub(crate) struct Swept {
    pub name: String,
    pub addr: i64,
    /// the text's grade as the build's declarations give it (None: the control did not compile it)
    pub control: Option<String>,
    pub best: String,
    /// the declaration set that gives `best` (Start(0): the control)
    pub set: Shift,
    pub codegens: usize,
    pub compiled: usize,
    /// every shift at both places was compiled (a stop at the goal leaves the rest untried)
    pub complete: bool,
}

/// The unit text (lines joined by \n) of one shift.
fn shifted_text(lines: &[&str], file: &str, comment: i64, k: usize, tag: &str) -> String {
    let lo = (comment.max(1) - 1) as usize;
    let mut out = String::with_capacity(lines.iter().map(|l| l.len() + 1).sum::<usize>() + 64 * k);
    for l in &lines[..lo.min(lines.len())] {
        out.push_str(l);
        out.push('\n');
    }
    out.push_str(&typedefs(k, tag));
    out.push('\n');
    out.push_str(&format!("#line {comment} \"{}\"\n", file.replace('/', "\\").replace('\\', "\\\\")));
    for l in &lines[lo.min(lines.len())..] {
        out.push_str(l);
        out.push('\n');
    }
    out
}

/// Sweep the declaration set of the targets of unit `t` over `text` (the unit's text, or a variant of it): the
/// text compiled as the build compiles it (the control), then with k = 1..63 unused typedefs at the unit's start and
/// before each target, each target graded in every compile. The compiles run in waves of the machine's parallelism;
/// unless `full`, the sweep stops after the wave in which every target reached its goal. `max` (PERIOD unless
/// measuring the period) bounds k.
pub(crate) fn sweep(p: &Project, t: &crate::plan::Tu, text: &str, targets: &[Target], full: bool, max: usize, before: bool, bench: &Bench)
                    -> Result<(Vec<Swept>, Vec<(Shift, Vec<Option<(String, String)>>)>)> {
    let lines: Vec<&str> = text.split('\n').collect();
    let mut shifts: Vec<Shift> = vec![Shift::Start(0)];
    for k in 1..max {
        shifts.push(Shift::Start(k));
        if before {
            shifts.extend(targets.iter().map(|g| Shift::Before(k, g.name.clone())));
        }
    }
    let job_text = |s: &Shift, tag: &str| -> (String, String) {
        match s {
            Shift::Start(k) => (typedefs(*k, tag), text.to_string()),
            Shift::Before(k, f) => {
                let c = targets.iter().find(|g| &g.name == f).map(|g| g.comment).unwrap_or(1);
                (String::new(), shifted_text(&lines, &t.file, c, *k, tag))
            }
        }
    };
    let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).max(1);
    let mut res: Vec<Swept> = targets.iter().map(|g| Swept { name: g.name.clone(), addr: g.addr, control: None, best: String::new(), set: Shift::Start(0),
                                                             codegens: 0, compiled: 0, complete: false }).collect();
    let mut keys: Vec<HashSet<(Vec<u8>, Vec<(u32, String)>)>> = targets.iter().map(|_| HashSet::new()).collect();
    let mut table: Vec<(Shift, Vec<Option<(String, String)>>)> = vec![];
    let mut done = 0;
    while done < shifts.len() {
        let wave = &shifts[done..(done + n).min(shifts.len())];
        let jobs: Vec<Job> = wave.iter().enumerate().map(|(j, s)| {
            let tag = format!("w{}", done + j);
            let (prefix, text) = job_text(s, &tag);
            Job { unit: t, tag, prefix, text }
        }).collect();
        let objs = compile(p, &jobs)?;
        for (s, o) in wave.iter().zip(&objs) {
            let mut row = vec![];
            for (i, g) in targets.iter().enumerate() {
                let Ok(o) = o else {
                    row.push(None);
                    continue;
                };
                let Some(&k) = o.function_index().get(&g.name) else {
                    row.push(None);
                    continue;
                };
                let c = o.function_code(k);
                let key = code_key(o, &c);
                let grade = bench.grade(o, &c, g.addr).to_string();
                row.push(Some((grade.clone(), crate::variants::short_hash(&key))));
                keys[i].insert(key);
                let r = &mut res[i];
                r.compiled += 1;
                if *s == Shift::Start(0) {
                    r.control = Some(grade.clone());
                }
                if r.best.is_empty() || rank(&grade) > rank(&r.best) {
                    r.best = grade;
                    r.set = s.clone();
                }
            }
            table.push((s.clone(), row));
        }
        done += wave.len();
        if !full && res.iter().zip(targets).all(|(r, g)| rank(&r.best) >= rank(g.goal)) {
            break;
        }
    }
    for (r, k) in res.iter_mut().zip(&keys) {
        r.codegens = k.len();
        r.complete = done == shifts.len();
    }
    Ok((res, table))
}

/// The compile inputs of a unit as the build keys them (its text, its flags, its include set): a record measured
/// under other inputs proves nothing about the build's.
pub fn inputs_of(src_hash: &str, flags_hash: &str, include_hash: &str) -> String {
    crate::project::sha256_parts(&[src_hash.to_string(), flags_hash.to_string(), include_hash.to_string()]).chars().take(16).collect()
}


/// The compile inputs of unit `unit` with its text's hash `src_hash` (the file as it is now, or a variant of it) and
/// the last build's flags and include set; empty when the unit was not built.
pub(crate) fn inputs_with(db: &str, unit: &str, src_hash: &str) -> Result<String> {
    Ok(crate::compile::tu_keys(db)?.get(unit).map(|k| inputs_of(src_hash, &k.flags_hash, &k.include_hash)).unwrap_or_default())
}

/// A function as a sweep needs it: its grade row's address, unit and built grade, its unit, its source span.
pub(crate) struct Loc {
    pub addr: i64,
    pub unit: String,
    pub built: String,
    pub file: String,
    pub comment: i64,
    pub end: i64,
}

pub(crate) fn locate(p: &Project, name: &str) -> Result<std::result::Result<Loc, String>> {
    Ok(Locator::of(p)?.get(name))
}

/// The grade rows and source spans of a target, read once for many functions.
pub(crate) struct Locator {
    rows: std::rc::Rc<Vec<serde_json::Map<String, Value>>>,
    by_name: HashMap<String, usize>,
    spans: HashMap<i64, (String, i64, i64)>,
}

impl Locator {
    pub(crate) fn of(p: &Project) -> Result<Locator> {
        let db = p.store_path();
        let rows = crate::queues::function_grades(&db)?;
        let by_name = rows.iter().enumerate().map(|(k, r)| (r["name"].as_str().unwrap_or("").to_string(), k)).collect();
        let spans = crate::with_db(&db, |c| store::claims_of(c, &db, "source", None, |f| &*f.rule == "L.src" && f.s("what") == Some("func")))?
            .iter().map(|f| (f.lo, (f.s("file").unwrap_or("").to_string(), f.value["comment"].as_i64().unwrap_or(0), f.value["end"].as_i64().unwrap_or(0))))
            .collect();
        Ok(Locator { rows, by_name, spans })
    }

    pub(crate) fn get(&self, name: &str) -> std::result::Result<Loc, String> {
        let Some(row) = self.by_name.get(name).map(|&k| &self.rows[k]) else { return Err(format!("no graded function {name} (dcp build first)")) };
        let (addr, unit, built) = (row["addr"].as_i64().unwrap_or(0), row["unit"].as_str().unwrap_or("").to_string(), row["code"].as_str().unwrap_or("").to_string());
        let Some((file, comment, end)) = self.spans.get(&addr).cloned() else { return Err(format!("{name} has no source span")) };
        Ok(Loc { addr, unit, built, file, comment, end })
    }
}

/// The record of one function's sweep (`text`: its function text's hash, `inputs`: the unit's compile inputs).
pub(crate) fn sweep_record(p: &Project, unit: &str, text: &str, inputs: &str, s: &Swept) -> Record {
    let witness = format!("sweep control={} best={} by {}; codegens={} compiled={}{}", s.control.as_deref().unwrap_or("none"), s.best, s.set.words(), s.codegens,
                          s.compiled, if s.complete { "" } else { " (stopped at the goal)" });
    Record { target: p.target_name.clone(), addr: s.addr, name: s.name.clone(), unit: unit.into(), text: text.into(), sensitive: s.codegens > 1,
             best: s.best.clone(), witness, inputs: inputs.into() }
}

/// Put records into the ledger (each replaces its function's record; an older record of the same text and inputs
/// with a better grade keeps its grade: proof is proof).
pub(crate) fn put_records(p: &Project, fresh: Vec<Record>) -> Result<()> {
    if fresh.is_empty() {
        return Ok(());
    }
    let root = p.root.to_string_lossy().into_owned();
    let old = read(&root);
    let mut by: BTreeMap<(String, i64), Record> = old.into_iter().map(|r| ((r.target.clone(), r.addr), r)).collect();
    for mut r in fresh {
        if let Some(o) = by.get(&(r.target.clone(), r.addr)) {
            if o.text == r.text && o.inputs == r.inputs && rank(&o.best) > rank(&r.best) {
                r.best = o.best.clone();
                r.witness = o.witness.clone();
                r.sensitive |= o.sensitive;
            }
        }
        by.insert((r.target.clone(), r.addr), r);
    }
    let path = ledger_path(&root);
    if let Some(d) = Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(d);
    }
    crate::edit::write(&path, &render(&by.into_values().collect::<Vec<_>>())).map_err(Error::value)?;
    p.forget_input("tiebreak");
    Ok(())
}

/// The verdict of a sweep in plain words: proven at a grade under a named declaration set, or no declaration set
/// makes the text byte.
pub fn verdict(best: &str, built: &str, set: &str, complete: bool) -> String {
    if best == "byte" {
        if built == "byte" {
            "byte as built".into()
        } else {
            format!("this text is byte under a declaration set ({set}): done (proven byte; the unit's declaration set is the open part, G.tiebreak)")
        }
    } else if complete {
        format!("no declaration set makes this text byte (every symbol-count shift 0..{} at the unit's start and before the function: best {best}): \
                 the difference is in the text, go on", PERIOD - 1)
    } else {
        format!("not byte under the declaration sets tried (best {best}): the difference is in the text, go on")
    }
}

/// `dcp headers sweep NAME [--table] [--max K] [--dry-run]`: the function's declaration-set sweep, its verdict and
/// record (ledger/tiebreak.tsv).
pub fn sweep_command(p: &Project, name: &str, max: usize, table: bool, dry: bool) -> Result<(Vec<String>, i32)> {
    use crate::cliread::{fmt_addr, record, Tok};
    let s = |x: &str| Tok::S(x.to_string());
    let fail = |e: String| -> Result<(Vec<String>, i32)> { Ok((vec![record(&[("name", s(name)), ("error", s(&e))])], 1)) };
    let l = match locate(p, name)? {
        Ok(l) => l,
        Err(e) => return fail(e),
    };
    let root = p.root.to_string_lossy().into_owned();
    let plan = crate::plan::plan(p).map_err(err)?;
    let Some(t) = plan.iter().find(|t| t.unit == l.unit) else { return fail(format!("no unit {} in target {}", l.unit, p.target_name)) };
    if l.file != t.file {
        return fail(format!("{name} is defined in {}, not in its unit's file {} (an included file: not supported)", l.file, t.file));
    }
    let Some(ftext) = fn_text(&root, &l.file, l.comment, l.end) else { return fail(format!("{name}: its text is not readable")) };
    let text = crate::edit::read_src(&native_path(&format!("{root}/{}", t.file))).map_err(err)?;
    let bench = Bench::of(p)?;
    let t0 = std::time::Instant::now();
    let (res, tab) = sweep(p, t, &text, &[Target { name: name.into(), addr: l.addr, comment: l.comment, goal: "byte" }], true, max.max(1), true, &bench)?;
    let r = &res[0];
    let mut out = vec![record(&[("fn", s(&fmt_addr(l.addr))), ("name", s(name)), ("unit", s(&l.unit)), ("built", s(&l.built)),
                                ("control", s(r.control.as_deref().unwrap_or("none"))), ("compiled", Tok::I(r.compiled as i64)),
                                ("codegens", Tok::I(r.codegens as i64)), ("best", s(&r.best)), ("ms", Tok::I(t0.elapsed().as_millis() as i64))])];
    if table {
        for (sh, row) in &tab {
            let cell = row[0].as_ref().map(|(g, h)| format!("{g} {h}")).unwrap_or_else(|| "-".into());
            out.push(format!("  {:<48} {cell}", sh.words()));
        }
    }
    if r.control.as_deref().is_some_and(|c| c != l.built) {
        out.push(format!("note: the trial compile gives {}, the build says {} (a stale build: dcp build)", r.control.as_deref().unwrap_or(""), l.built));
    }
    out.push(verdict(&r.best, &l.built, &r.set.words(), r.complete));
    if dry || max != PERIOD {
        out.push("(nothing written)".into());
    } else {
        let src_hash = crate::fsmemo::sha256(&native_path(&format!("{root}/{}", t.file))).map_err(err)?;
        let inputs = inputs_with(&p.store_path(), &l.unit, &src_hash)?;
        put_records(p, vec![sweep_record(p, &l.unit, &text_hash(&ftext), &inputs, r)])?;
        out.push(format!("written to {LEDGER}"));
    }
    Ok((out, 0))
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
/// compiler's numbered names by kind): two samples with the same key have the same code. A relocated field's addend
/// is code (`ai_Slots+0x10`: the field of a global struct array, `mov ecx,[eax+ai_Slots+0x10]`; a variant that
/// only swaps two field loads differs there and nowhere else); only a section symbol's addend (`.data+0x1c8`: where
/// the unit's other data lies) is masked, except into the function's own section (its jump tables: relative to the
/// function's start).
pub(crate) fn code_key(o: &Obj, c: &FunctionCode) -> (Vec<u8>, Vec<(u32, String)>) {
    let syms = c.relocs.iter().map(|(off, r)| {
        let s = o.symbol_at(r.symbol_index);
        let n = s.map(|s| s.name.clone()).unwrap_or_default();
        let addend = o.addend(c.secnum, r);
        if n.starts_with('.') {
            let own = s.is_some_and(|s| s.secnum as usize == c.secnum);
            return (*off, if own { format!("{n}+fn{:+#x}", addend as i64 - c.start as i64) } else { n });
        }
        // a label of the function's own code (a jump table's entry: `$L1234`): where it is, not its number (two
        // switches whose tables send a case elsewhere are two codes: evt_Eval, a split `case 1: case 7:`)
        if let Some(s) = s.filter(|s| n.starts_with('$') && s.secnum as usize == c.secnum) {
            return (*off, format!("$L@fn{:+#x}", s.value as i64 + addend as i64 - c.start as i64));
        }
        let n = if n.starts_with('$') { n.trim_end_matches(|ch: char| ch.is_ascii_digit()).to_string() } else { n };
        (*off, if addend == 0 { n } else { format!("{n}+{addend:#x}") })
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
    let rec = Record { target: p.target_name.clone(), addr: a, name: name.into(), unit, text: text_hash(&text), sensitive, best, witness,
                       inputs: inputs_with(&db, &t.unit, &crate::fsmemo::sha256(&native_path(&format!("{root}/{}", t.file))).map_err(err)?)? };
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
    let first = r.codegens.iter().find(|c| c.0 == rec.best).map(|c| c.2.clone()).unwrap_or_default();
    let verdict = verdict(&rec.best, &r.built, &first, false);
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

    /// `mov ecx, [eax + _ai_Slots + DISP]` (a field of a global struct array, the field in the relocated field's
    /// addend), and a load of `.data + DATA` (a section symbol: where the unit's data lies).
    fn field_load(disp: u32, data: u32) -> Obj {
        use crate::coff::{Reloc, Section, Symbol};
        let code: Vec<u8> = [&[0x8bu8, 0x88][..], &disp.to_le_bytes(), &[0xa1], &data.to_le_bytes(), &[0xc3]].concat();
        let relocs = vec![Reloc { offset: 2, symbol_index: 1, typ: 0x06 }, Reloc { offset: 7, symbol_index: 2, typ: 0x06 }];
        let text = Section { name: ".text".into(), chars: 0x6000_0020, size: code.len() as u32, data: Some(code), relocs, syms: vec![0] };
        let none = Section { name: String::new(), chars: 0, data: None, size: 0, relocs: vec![], syms: vec![] };
        let data_sec = Section { name: ".data".into(), chars: 0xc000_0040, size: 0x100, data: Some(vec![0; 0x100]), relocs: vec![], syms: vec![2] };
        let symbols = vec![Symbol { index: 0, name: "_f".into(), value: 0, secnum: 1, typ: 0x20, cls: 2 },
                           Symbol { index: 1, name: "_ai_Slots".into(), value: 0, secnum: 0, typ: 0, cls: 2 },
                           Symbol { index: 2, name: ".data".into(), value: 0, secnum: 2, typ: 0, cls: 3 }];
        Obj { name: String::new(), sections: vec![none, text, data_sec], by_index: (0..3).map(|k| (k, k)).collect(), symbols }
    }

    /// The code key holds a relocated field's addend (a field displacement: `make -= amount + pending` against
    /// `pending + amount` swaps two field loads of a global array and nothing else; `dcp try` printed it `= control`,
    /// the build graded it byte instead of draft), not where a section symbol's data lies.
    #[test]
    fn the_code_key_holds_field_displacements() {
        let key = |o: &Obj| code_key(o, &o.function_code(0));
        let (a, b) = (field_load(0x10, 0x20), field_load(0x14, 0x20));
        assert_ne!(key(&a), key(&b));
        assert_ne!(crate::variants::short_hash(&key(&a)), crate::variants::short_hash(&key(&b)));
        assert_eq!(key(&a).1[0], (2, "_ai_Slots+0x10".to_string()));
        // the same field: the same key, wherever the unit's data lies
        assert_eq!(key(&a), key(&field_load(0x10, 0x48)));
    }

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
                                                            sensitive: s, best: "byte".into(), witness: "control=shape p1=byte*".into(), inputs: "i".into() };
        let recs = vec![r("exe", 0x401000, "a", true), r("exe", 0x402000, "b", false)];
        assert_eq!(parse(&render(&recs)), recs);
        // a record of an older dcp (8 columns) has no inputs: it answers for no build's inputs
        let old = parse("target\taddress\tname\tunit\ttext\tsensitive\tbest\twitness\nexe\t0x00401000\tf\ta\tab\tyes\tbyte\tcontrol=shape p1=byte*\n");
        assert_eq!(old[0].inputs, "");
        let tb = json!({"best": "byte", "inputs": "", "file": "x.c", "comment": 1, "end": 2});
        let ch = crate::cause::Changes::of("abc", &[]);
        assert_eq!(declaration_move(".", &ch, &tb, "x.c", "byte", "abc"), None);
        // a record under other inputs, or below the grade the function had, excuses no fall
        let tb = json!({"best": "byte", "inputs": "i1", "file": "x.c", "comment": 1, "end": 2});
        assert_eq!(declaration_move(".", &ch, &tb, "x.c", "byte", "i2"), None);
        let tb = json!({"best": "shape", "inputs": "i1", "file": "x.c", "comment": 1, "end": 2});
        assert_eq!(declaration_move(".", &ch, &tb, "x.c", "byte", "i1"), None);
    }

    #[test]
    fn sweep_texts_and_verdicts() {
        // a shift before the function: the typedefs on a line of their own, then the function's own line number back
        let lines = ["int a;", "/* 0x401000 */", "int f(void) { return a; }"];
        let t = shifted_text(&lines, "src/u.c", 2, 3, "w1");
        assert_eq!(t, "int a;\ntypedef int __dcp_w1_0; typedef int __dcp_w1_1; typedef int __dcp_w1_2;\n#line 2 \"src\\\\u.c\"\n/* 0x401000 */\nint f(void) { return a; }\n");
        assert_eq!(shifted_text(&lines, "src/u.c", 1, 0, "w").lines().next(), Some(""));
        assert_eq!(Shift::Before(5, "f".into()).words(), "5 unused typedefs before f");
        assert_eq!(Shift::Start(1).words(), "1 unused typedef at the unit's start");
        // the two answers a worker gets: done by proof, or the text
        let v = verdict("byte", "shape", "5 unused typedefs before f", true);
        assert!(v.contains("byte under a declaration set (5 unused typedefs before f): done"), "{v}");
        let v = verdict("shape", "shape", "", true);
        assert!(v.starts_with("no declaration set makes this text byte") && v.ends_with("the difference is in the text, go on"), "{v}");
        assert!(!verdict("shape", "draft", "", false).contains("sensitive"));
        // complete: a full sweep; one stopped at its goal or of the unit's start only is not
        let rec = |w: &str| Record { witness: w.into(), ..Record::default() };
        assert!(complete(&rec("sweep control=shape best=shape by the build's declarations; codegens=2 compiled=127")));
        assert!(!complete(&rec("sweep control=shape best=byte by 3 unused typedefs before f; codegens=2 compiled=12 (stopped at the goal)")));
        assert!(!complete(&rec("control=shape p1=byte*")));
        assert!(close("shape", None) && close("draft", Some(24)) && !close("draft", Some(25)) && !close("draft", None));
    }

    /// A record of a function's same text under other inputs (another function of its unit changed) goes to NOW,
    /// not the ledger; a changed text, a new function or the same inputs (a refinement) to the ledger.
    #[test]
    fn ledger_rows_change_with_the_text() {
        let r = |text: &str, inputs: &str, best: &str| Record { target: "t".into(), addr: 0x401000, name: "f".into(), unit: "u".into(), text: text.into(),
                                                              sensitive: true, best: best.into(), witness: "w".into(), inputs: inputs.into() };
        let ledger = vec![r("ab", "i1", "byte")];
        assert!(!to_ledger(&ledger, &r("ab", "i2", "shape"), false));
        assert!(to_ledger(&ledger, &r("cd", "i2", "shape"), true));
        assert!(to_ledger(&ledger, &r("ab", "i1", "byte"), false));
        assert!(to_ledger(&[], &r("ab", "i2", "shape"), false));
        let mut other = r("ab", "i1", "byte");
        other.addr = 0x402000;
        assert!(to_ledger(&[other], &r("ab", "i2", "shape"), false));
    }

    /// he_RunSecretRoom (bug report tiebreak-row-rewritten-after-note): its text changed in an earlier commit (a
    /// name became a literal) and its row stayed of the old text; a build after a comment-only edit of a sibling
    /// (dcp note he_RunDecay) measured it. The record goes to NOW (the working tree did not change the function),
    /// the ledger row stays, and M.tiebreak's record part comes from NOW alone.
    #[test]
    fn sibling_comment_edit_leaves_a_stale_row() {
        let d = crate::testkit::scratch("tiebreak-sibling-note");
        let _ = std::fs::remove_dir_all(&d);
        let root = d.to_string_lossy().replace('\\', "/");
        let git = |args: &[&str]| assert!(std::process::Command::new("git").args(args).current_dir(&d).output().unwrap().status.success());
        let room = "/* 0x56e5b0, the room */\nvoid room(int ev)\n{\n    walk(ev, \"ASSASSIN\");\n}\n";
        let decay = |note: &str| format!("/* 0x5702e0, decay\n   @deep {note} */\nvoid decay(int ev)\n{{\n    walk(ev, 0);\n}}\n");
        crate::testkit::write(&d, "src/he_b.c", &format!("{room}{}", decay("first reading")));
        git(&["init", "-q"]);
        git(&["add", "."]);
        git(&["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "c"]);
        // the note: only decay's comment changes
        crate::testkit::write(&d, "src/he_b.c", &format!("{room}{}", decay("second reading")));
        let ch = crate::cause::Changes::since(&root, "HEAD");
        assert!(ch.is_some());
        let mut heads = HashMap::new();
        let room_now = fn_text(&root, "src/he_b.c", 1, 5).unwrap();
        assert!(!edited_since_head(&root, &ch, &mut heads, "src/he_b.c", &room_now));
        let r = |text: &str, inputs: &str, best: &str| Record { target: "exe".into(), addr: 0x56e5b0, name: "room".into(), unit: "he_b".into(), text: text.into(),
                                                              sensitive: false, best: best.into(), witness: "sweep".into(), inputs: inputs.into() };
        let th = text_hash(&room_now);
        let ledger = vec![r("bfa7a700d3f8d72e", "i0", "shape")];
        let measured = r(&th, "i1", "shape");
        assert!(!to_ledger(&ledger, &measured, false));
        assert_eq!(tiebreak_of(ledger.first(), Some(&measured), &th).unwrap()["inputs"], "i1");
        assert!(tiebreak_of(ledger.first(), None, &th).is_none());
        // the function's own edit: its row changes
        crate::testkit::write(&d, "src/he_b.c", &format!("{}{}", room.replace("ASSASSIN", "SPY"), decay("second reading")));
        crate::fsmemo::new_epoch(); // a new command: the file is read again
        let room_edit = fn_text(&root, "src/he_b.c", 1, 5).unwrap();
        assert!(edited_since_head(&root, &ch, &mut heads, "src/he_b.c", &room_edit));
        assert!(to_ledger(&ledger, &r(&text_hash(&room_edit), "i2", "shape"), true));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn moved_lines() {
        assert_eq!(moved_line("include/ai_types.h, uncommitted", &["f".into(), "g".into()]), "tie-break: 2 functions moved (include/ai_types.h, uncommitted): f, g");
    }
}
