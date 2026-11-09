//! G.grade: per sourced function the object experiment (docs/mental-model.md §4: its outcome byte / shape / draft
//! from the compare and the instruction diff, diffclass.rs; what failed, B1..B3; the calls the consistency
//! convention finds without a declaration, M7) as an `experiment` claim, and its readability (§9, readability.rs:
//! Q1..Q6, Q8) as a `readability` row, kept apart; the same per unit.

use crate::error::{Error, Result};
use crate::diffclass::{self, Env, Verdict};
use crate::readability::{self, Context, Source};
use crate::phi::Phi;
use crate::refcheck::{Refs, Site};
use crate::rules::{compiled_functions, Ctx};
use crate::store::{self, Out, Claim, DECLARED, REPRODUCED};
use crate::image;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::rc::Rc;

fn err(e: rusqlite::Error) -> Error {
    Error::runtime(e.to_string())
}

pub(crate) const CODE: [&str; 3] = ["draft", "shape", "byte"];

/// The outcome of an experiment that did not run (its unit has no object): open, no grade, so below none of CODE
/// and no fall (docs/mental-model.md §3, §4); M.compile / M.compile.stale say why, M1 counts it per unit.
pub(crate) const NOT_RUN: &str = "open";

/// The reference differences a function's failing lines name one by one (the rest by their count).
const REF_LINES: usize = 8;

fn rank(c: &str) -> usize {
    CODE.iter().position(|x| *x == c).unwrap_or(0)
}

/// One function's code grade row: (code, why, hunks, dist).
struct Row {
    src: Rc<Claim>,
    code: String,
    why: Vec<String>,
    hunks: Value,
    dist: Value,
    /// the references φ says nothing about (refcheck: open, not checked)
    open: Vec<String>,
}

fn read_text(path: &std::path::Path) -> Option<String> {
    let b = std::fs::read(path).ok()?;
    Some(String::from_utf8_lossy(&b).replace("\r\n", "\n").replace('\r', "\n"))
}

/// What one function's code grade is computed from besides its compare: its bytes and relocation mask, where its
/// code ends (code_len), the targets of the relocated fields after it (its switch tables: offset, width, target
/// inside the function), its address, the next start, the walk's or the source extent's end, and per relocation
/// its symbol's name, a literal's bytes and φ's addresses of the object (the prover binds through φ, the
/// reference check reads the bytes: a changed callee, string or address comment leaves the code bytes as they
/// were). The reference check itself runs on every run (refcheck.rs: φ against the held sites).
type Key = (Vec<u8>, Vec<u8>, Option<u32>, Vec<(u32, u32, Option<i64>)>, i64, u32, Option<i64>, Vec<(String, Option<Vec<u8>>, Vec<i64>)>);

fn key_of(f: &crate::rules::Compiled, w: Option<&Rc<Claim>>, refs: &Refs) -> Key {
    let code = &f.code;
    let obj = &f.obj.0;
    let tbl = match code.code_len {
        None => vec![],
        Some(cl) => code.relocs.iter().filter(|(off, _)| *off >= cl).map(|(off, r)| {
            let t = obj.symbol_at(r.symbol_index).filter(|s| s.secnum as usize == code.secnum)
                .map(|s| s.value as i64 + obj.addend(code.secnum, r) as i64 - code.start as i64);
            (*off, r.kind_width().1, t)
        }).collect(),
    };
    let syms = code.relocs.iter().zip(refs.targets.iter().zip(&refs.expect)).map(|((_, r), (t, at))| {
        let lit = match t {
            crate::refcheck::Target::Lit { bytes, .. } => Some(bytes.clone()),
            _ => None,
        };
        (obj.symbol_at(r.symbol_index).map(|s| s.name.clone()).unwrap_or_default(), lit, at.clone())
    }).collect();
    (code.data.clone(), code.mask.clone(), code.code_len, tbl, f.src.lo, f.next, w.map(|w| w.hi), syms)
}

/// A function's code size, its extent and slot, the original as the diff reads it, a byte match's reference
/// sites (each relocation at its offset), its verdict (when asked: a byte match whose references agree needs none).
struct Held {
    size: i64,
    extent: i64,
    slot: i64,
    o: diffclass::Original,
    matched_sites: Vec<Site>,
    verdict: std::cell::OnceCell<Judged>,
    /// the reference census's input (no byte match: refcheck::census_input over the prover's binding)
    census: std::cell::OnceCell<crate::refcheck::CensusInput>,
}

thread_local! {
    // the latest run's results by what they are computed from (Key), under the image, the
    // fill forms and the alignment they were computed with; each run keeps the ones it used
    static HELD: std::cell::RefCell<(String, HashMap<Key, Rc<Held>>)> = std::cell::RefCell::new((String::new(), HashMap::new()));
}

/// What one function's readability is computed from besides its file and the context.
type FnKey = (String, Option<(i64, i64, Option<(i64, i64)>)>, i64, i64, bool, i64, Option<Vec<String>>);

/// A source file's text, its lexing and the readability of its functions (FnKey).
struct FileHeld {
    text: Option<String>,
    src: Option<Source>,
    verdicts: std::cell::RefCell<HashMap<FnKey, (String, Vec<String>)>>,
}

type Stamp = (Vec<String>, Vec<i64>, (i64, i64)); // the raw macros, the described addresses, the image range

thread_local! {
    // the latest run's files, under the context their verdicts were computed in; each run keeps the files it read
    static FILES: std::cell::RefCell<(Stamp, HashMap<String, Rc<FileHeld>>)> = std::cell::RefCell::new(Default::default());
}

/// One function to compute: its code, its object, address, next start, the walk's end, whether it byte-matches.
struct Task<'a> {
    i: usize, // its index among the compiled functions
    code: &'a crate::coff::FunctionCode,
    obj: &'a crate::coff::Obj,
    lo: i64,
    next: u32,
    whi: Option<i64>,
    matched: bool,
    /// φ, the correspondence the references are checked against, and what the relocations refer to by it
    phi: &'a Phi,
    refs: &'a Refs,
}

type Computed = (i64, i64, i64, diffclass::Original, Vec<Site>, Option<Judged>);

/// A function's shape verdict, its reference sites (the alignment's: refcheck::sites_aligned) and the prover's
/// block pairs when it shows the behaviour the same.
type Judged = (Verdict, Vec<Site>, Option<usize>);

/// A function's code size, extent, slot, original, a byte match's sites and (no byte match, or a byte match
/// whose named references cross) its verdict.
fn compute(env: &Env, t: &Task, align: i64) -> Computed {
    let (cd, cm) = t.code.code();
    let size = diffclass::code_size(env, cd, cm, t.lo as u32);
    let extent = t.whi.map(|h| h - t.lo).unwrap_or(size);
    let slot = extent.max(t.next as i64 - t.lo);
    let o = diffclass::original(env, t.lo as u32, extent, slot, align);
    let sites = if t.matched { crate::refcheck::sites_matched(t.code, env.img, t.lo as u32) } else { vec![] };
    let crossed = t.matched && crate::refcheck::check(t.obj, t.code, env.img, &sites, t.refs, t.phi).named_differs();
    let v = if t.matched && !crossed { None } else { Some(verdict(env, t.obj, t.code, t.lo as u32, &o, t.refs, t.phi)) };
    (size, extent, slot, o, sites, v)
}

/// A function's shape verdict, its reference sites, and where the shape check leaves it draft or a named
/// reference of ours differs from the original's field, the prover's: the block pairs when it shows our code's
/// behaviour the same as the original's (equiv: the same effects in the same order, the same branches, the same
/// returns), our references bound through φ (equiv::bind). Two stores reordered pair their fields crosswise: the
/// proof shows the effects the same all the same.
fn verdict(env: &Env, obj: &crate::coff::Obj, code: &crate::coff::FunctionCode, lo: u32, o: &diffclass::Original, refs: &Refs,
           phi: &Phi) -> Judged {
    let fc = diffclass::FunctionCompare::new(env, obj, code, lo, o);
    let sites = crate::refcheck::sites_aligned(code, env.img, lo, &fc.la, &fc.lb);
    let crossed = crate::refcheck::check(obj, code, env.img, &sites, refs, phi).named_differs();
    let proof = if fc.verdict.shape && !crossed {
        None
    } else {
        let data = env.img.read(lo, o.code.max(0) as usize);
        let (ours, _) = crate::equiv::bind(obj, code, env.img, lo, &sites, refs, phi);
        match crate::equiv::prove(&ours, &data, lo) {
            crate::equiv::Outcome::Equal { pairs } => Some(pairs),
            _ => None,
        }
    };
    (fc.verdict, sites, proof)
}

/// The code grade from the structure and the reference check: byte when the bytes match and every reference
/// agrees; shape when the bytes, the shape classes or a proof explain the code and no literal differs (a named
/// reference that differs only with a proof: the fields cross, the effects are the same); else draft.
pub(crate) fn code_grade(matched: bool, structural: bool, proved: bool, chk: &crate::refcheck::Check) -> &'static str {
    if matched && chk.differs().next().is_none() {
        "byte"
    } else if (matched || structural || proved) && !chk.literal_differs() && (!chk.named_differs() || proved) {
        "shape"
    } else {
        "draft"
    }
}

/// The code grade of one function from its reference check and (when needed: not a byte match whose every reference
/// agrees) its verdict. The one decision G.grade, the header trial and data fix's trial share (docs/mental-model.md
/// §4: an experiment has one implementation).
fn decide<'a>(is_byte: bool, chk: &crate::refcheck::Check, judged: impl Fn() -> &'a Judged) -> &'static str {
    if is_byte {
        if chk.differs().next().is_none() {
            return "byte";
        }
        // the bytes match, a reference does not: shape only when named references cross and a proof shows the
        // effects the same
        let proof = if chk.literal_differs() { None } else { judged().2 };
        code_grade(true, false, proof.is_some(), chk)
    } else {
        let (v, _, proof) = judged();
        code_grade(false, v.shape, proof.is_some(), chk)
    }
}

/// What a trial grades one compiled function against (as G.grade reads them): the image, φ, the function alignment.
pub(crate) struct Grader<'a> {
    pub env: Env<'a>,
    pub phi: &'a Phi,
    pub align: i64,
}

impl Grader<'_> {
    /// One function's code grade as G.grade gives it: `matched` the compare's byte match (M.match's), `next` the next
    /// start, `whi` the walk's or the source extent's end.
    pub(crate) fn grade(&self, obj: &crate::coff::Obj, code: &crate::coff::FunctionCode, lo: i64, next: u32, whi: Option<i64>,
                        matched: bool) -> &'static str {
        let refs = Refs::new(obj, code, self.phi);
        let t = Task { i: 0, code, obj, lo, next, whi, matched, phi: self.phi, refs: &refs };
        let (_, _, _, o, sites, v) = compute(&self.env, &t, self.align);
        let cell = std::cell::OnceCell::new();
        if let Some(v) = v {
            let _ = cell.set(v);
        }
        let judged = || cell.get_or_init(|| verdict(&self.env, obj, code, lo as u32, &o, &refs, self.phi));
        let chk = if matched {
            crate::refcheck::check(obj, code, self.env.img, &sites, &refs, self.phi)
        } else {
            crate::refcheck::check(obj, code, self.env.img, &judged().1, &refs, self.phi)
        };
        decide(matched, &chk, judged)
    }
}

/// compute over the tasks on every core: (index, result).
fn compute_all(env: &Env, todo: &[Task], align: i64) -> Vec<(usize, Computed)> {
    let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).min(todo.len().max(1));
    if n <= 1 || todo.len() < 32 {
        return todo.iter().map(|t| (t.i, compute(env, t, align))).collect();
    }
    // each thread takes the next task: the functions differ widely in size
    let next = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|s| {
        let parts: Vec<_> = (0..n).map(|_| s.spawn(|| {
            let mut out = vec![];
            loop {
                let k = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some(t) = todo.get(k) else { break };
                out.push((t.i, compute(env, t, align)));
            }
            out
        })).collect();
        parts.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect()
    })
}

pub fn g_grade(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    let x = &ctx.inputs;
    let scan_defs = crate::srcscan::defs(&x.scan)?;
    let (funcs, missing) = compiled_functions(ctx, db)?;
    let symbols = store::claims(db, &ctx.db, "symbol", &ctx.needed, |_| true).map_err(err)?;
    let matched: HashSet<i64> = symbols.iter().filter(|f| &*f.rule == "M.match").map(|f| f.lo).collect();
    let mut walk: HashMap<i64, Rc<Claim>> = HashMap::new();
    for f in symbols.iter().filter(|f| f.s("skind") == Some("func") && matches!(&*f.rule, "S.codewalk" | "L.src.extent")) {
        walk.insert(f.lo, f.clone());
    }
    // the declaration-set probes (M.tiebreak): each fresh record, by address
    let tiebreak: HashMap<i64, Rc<Claim>> = store::claims(db, &ctx.db, "tiebreak", &ctx.needed, |_| true).map_err(err)?.into_iter().map(|f| (f.lo, f)).collect();
    let range = (img.base as i64, img.end() as i64);
    let fills: HashSet<Vec<u8>> = ctx.fill_forms.iter().cloned().collect();
    let forms = crate::compare::fill_order(&ctx.fill_forms);
    let env = Env { img: &img, range, fills: &fills, forms: &forms };
    let mut rows: Vec<Row> = vec![];
    let world = format!("{}|{:?}|{}", ctx.image, ctx.fill_forms, x.function_alignment);
    let mut held = HELD.with(|h| std::mem::take(&mut *h.borrow_mut()));
    if held.0 != world {
        held = (world, HashMap::new());
    }
    let mut used: HashMap<Key, Rc<Held>> = HashMap::new();
    let phi = crate::timing::phase("g.phi", || -> Result<Phi> { Ok(Phi::new(&store::claims(db, &ctx.db, "name", &ctx.needed, |_| true).map_err(err)?, &[])) })?;
    // what each relocation refers to, by φ: the key's, the check's and the binding's
    let refs: Vec<Refs> = crate::timing::phase("g.refs", || funcs.iter().map(|f| Refs::new(&f.obj.0, &f.code, &phi)).collect());
    let keys: Vec<Key> = crate::timing::phase("g.keys", || funcs.iter().zip(&refs).map(|(f, r)| key_of(f, walk.get(&f.src.lo), r)).collect());
    // the functions not held (all of them after a start): computed on every core, each independent of the others
    let todo: Vec<Task> = funcs.iter().zip(&keys).enumerate().filter(|(_, (_, k))| !held.1.contains_key(*k)).map(|(i, (f, _))| Task {
        i, code: &f.code, obj: &f.obj.0, lo: f.src.lo, next: f.next, whi: walk.get(&f.src.lo).map(|w| w.hi), matched: matched.contains(&f.src.lo),
        phi: &phi, refs: &refs[i],
    }).collect();
    let mut fresh: HashMap<usize, Rc<Held>> = HashMap::new();
    for (i, r) in crate::timing::phase("g.compute", || compute_all(&env, &todo, x.function_alignment)) {
        let (size, extent, slot, o, matched_sites, v) = r;
        let verdict = std::cell::OnceCell::new();
        if let Some(v) = v {
            let _ = verdict.set(v);
        }
        fresh.insert(i, Rc::new(Held { size, extent, slot, o, matched_sites, verdict, census: Default::default() }));
    }
    for (i, (f, key)) in funcs.iter().zip(keys).enumerate() {
        let lo = f.src.lo;
        let h = match held.1.get(&key) {
            Some(h) => h.clone(),
            None => fresh[&i].clone(),
        };
        used.insert(key, h.clone());
        let (size, extent, slot) = (h.size, h.extent, h.slot);
        let orig_size = h.o.code;
        let n = size.min(orig_size);
        let nbytes = f.c.diffs.iter().filter(|&&k| (k as i64) < n).count() as i64 + (size - orig_size).abs();
        let (g, mut why, hunks, dist_ins);
        let is_byte = matched.contains(&lo);
        let unit = f.src.s("unit");
        // the reference check (refcheck.rs): a byte match's sites at their offsets, else the alignment's
        let judged = || -> &Judged {
            h.verdict.get_or_init(|| verdict(&env, &f.obj.0, &f.code, lo as u32, &h.o, &refs[i], &phi))
        };
        let chk = crate::timing::phase("g.check", || if is_byte {
            crate::refcheck::check(&f.obj.0, &f.code, &img, &h.matched_sites, &refs[i], &phi)
        } else {
            crate::refcheck::check(&f.obj.0, &f.code, &img, &judged().1, &refs[i], &phi)
        });
        // the reference census (tasks/reference-census.md): the objects one side refers to and the other never
        // does, whatever the alignment; no byte match only (equal bytes refer alike)
        let census: Vec<crate::refcheck::CensusDiff> = if is_byte {
            vec![]
        } else {
            let inp = h.census.get_or_init(|| crate::timing::phase("g.census", || {
                let sites = &judged().1;
                let (bound, unbound) = crate::equiv::bind(&f.obj.0, &f.code, &img, lo as u32, sites, &refs[i], &phi);
                let data = img.read(lo as u32, h.o.code.max(0) as usize);
                crate::refcheck::census_input(&f.obj.0, &f.code, &refs[i], &bound, unbound, &data, lo as u32)
            }));
            crate::refcheck::census(inp, &phi)
        };
        let mut lines = chk.lines(&phi, lo as u32, unit);
        if !is_byte && census.is_empty() {
            // the alignment paired reordered code crosswise: both sides refer to every object either one names
            for (l, r) in lines.iter_mut().zip(chk.firsts()) {
                if r.rule == "M8" {
                    l.push_str(" (crossed: both sides refer to both)");
                }
            }
        }
        let rules: BTreeSet<&str> = chk.differs().map(|r| r.rule).collect();
        let rules = rules.into_iter().collect::<Vec<_>>().join(", ");
        // the failing lines name the first differences, the count names them all
        let shown = |tag: &str| -> Vec<String> {
            let mut v: Vec<String> = lines.iter().take(REF_LINES).map(|l| format!("{tag}{l}")).collect();
            if lines.len() > REF_LINES {
                v.push(format!("{tag}{} more reference(s) differ (dcp diffclass {})", lines.len() - REF_LINES, f.src.s("symbol").unwrap_or("")));
            }
            v
        };
        if is_byte && lines.is_empty() {
            (g, why, hunks, dist_ins) = ("byte".to_string(), vec![], json!({}), 0usize);
        } else if is_byte {
            // the bytes match, a reference does not (M8: another object, M9 / M10: other bytes): a meaning
            // difference, unless named references only cross and a proof shows the effects the same
            let proof = if chk.literal_differs() { None } else { judged().2 };
            g = decide(true, &chk, judged).to_string();
            (hunks, dist_ins) = (json!({}), 0usize);
            why = shown("B1 byte: the bytes match; ");
            why.push(match proof {
                Some(pairs) => format!("B2 shape: the same behaviour, proved ({pairs} block pairs) with every reference at φ's address: the \
                                        references cross ({rules})"),
                None => format!("B3 draft: {} reference(s) differ from the original's ({rules}): a meaning difference", lines.len()),
            });
        } else {
            let (v, _, proof) = judged();
            g = decide(false, &chk, judged).to_string();
            hunks = v.hunks_json();
            dist_ins = v.distance;
            let mut w = vec![];
            let c_why = f.c.why();
            if !c_why.is_empty() {
                w.push(format!("B1 byte: {c_why}"));
            }
            // the reference differences first: a meaning difference, whatever else the code has
            w.extend(shown(if v.shape || proof.is_some() { "B2 shape: " } else { "B3 draft: " }));
            if g == "shape" && !lines.is_empty() {
                w.push(format!("B2 shape: the same behaviour, proved ({} block pairs) with every reference at φ's address: the references \
                                cross ({rules}); the hunks: {}", proof.unwrap_or(0), v.summary()));
            } else if g == "draft" && (v.shape || proof.is_some()) {
                // the code is shape, a reference it makes is not the original's
                w.push(format!("B3 draft: {} reference(s) differ from the original's ({rules}): a meaning difference; the hunks: {}",
                               lines.len(), v.summary()));
            } else if g == "draft" {
                w.push(format!("{}{}", if v.code.is_empty() { "B3 draft: " } else { "B3 draft: unexplained code hunks: " }, v.summary()));
            } else if let (false, Some(pairs)) = (v.shape, proof) {
                w.push(format!("B2 shape: the same behaviour, proved ({pairs} block pairs); the hunks: {}", v.summary()));
            } else {
                w.push(format!("B2 shape: {}", v.summary()));
            }
            why = w;
        }
        // the census and our addresses used as numbers: listed and warned (not yet a concrete difference: measured
        // on gildegold first)
        let name = f.src.s("symbol").unwrap_or("");
        for c in &census {
            why.push(format!("census: {}", c.line()));
            let site = lo + c.off as i64;
            out.finding("warn", "M.census", site, site + 4, format!("{name} at {lo:#x}: {}", c.line()), &f.src.by);
        }
        for (k, n) in refs[i].numeric.iter().enumerate() {
            let expect = f.code.relocs.iter().position(|(off, _)| *off == n.off).map(|j| refs[i].expect[j].as_slice()).unwrap_or(&[]);
            let l = n.line(expect);
            if k < REF_LINES {
                why.push(format!("addrnum: {l}"));
            }
            let site = lo + n.off as i64;
            out.finding("warn", "M.addrnum", site, site + 4, format!("{name} at {lo:#x}: {l}"), &f.src.by);
        }
        // the findings view (M8 / M9 / M10): a byte match whose reference φ contradicts, at the site (the bytes are
        // equal at this layout only, docs/mental-model.md §8.3); the positional pairing is exact there. Elsewhere
        // the difference is the experiment's failing line (the alignment pairs reordered code crosswise).
        if is_byte && g == "draft" {
            let name = f.src.s("symbol").unwrap_or("");
            for (r, l) in chk.firsts().into_iter().zip(&lines) {
                let site = lo + r.off as i64;
                out.finding("error", r.rule, site, site + 4, format!("{name} at {lo:#x}: {l}"), &f.src.by);
            }
        }
        // containment (§8.7): a reference of ours outside its object's declared size is no address of it, whatever
        // the bytes compare (ill-formed: it moves with the object in a relinked image)
        for o in &refs[i].outside {
            let site = lo + o.off as i64;
            out.finding("error", "M.contain", site, site + 4, format!("{} at {lo:#x}: {}", f.src.s("symbol").unwrap_or(""), o.line()), &f.src.by);
        }
        let open = chk.open_lines(&phi, lo as u32);
        rows.push(Row { src: f.src.clone(), code: g, why, hunks, open,
                        dist: json!({"ins": dist_ins, "bytes": nbytes, "size": size, "orig": orig_size, "extent": extent, "slot": slot}) });
    }
    HELD.with(|h| *h.borrow_mut() = (held.0, used));
    for m in &missing {
        let orig = walk.get(&m.src.lo).map(|w| json!(w.hi - m.src.lo)).unwrap_or(Value::Null);
        let (code, why) = if m.ran { ("draft", format!("B3 draft: {}", m.why)) } else { (NOT_RUN, format!("not run: {}", m.why)) };
        rows.push(Row { src: m.src.clone(), code: code.into(), why: vec![why], hunks: json!({}), open: vec![],
                        dist: json!({"ins": null, "bytes": null, "size": null, "orig": orig}) });
    }
    rows.sort_by_key(|r| r.src.lo); // stable
    // readability
    let raw: HashSet<String> = x.raw.iter().cloned().collect();
    let described: HashSet<i64> = x.described.iter().copied().collect();
    let cx = Context { raw: &raw, described: &described, range };
    let linted: HashSet<&str> = x.linted.iter().map(|s| s.as_str()).collect();
    let root = std::path::Path::new(&ctx.root);
    // the files' lexing and their functions' verdicts, held while the text and the context are the same
    let stamp = (x.raw.clone(), x.described.clone(), range);
    let mut files = FILES.with(|h| std::mem::take(&mut *h.borrow_mut()));
    if files.0 != stamp {
        files = (stamp, HashMap::new());
    }
    let mut used_files: HashMap<String, Rc<FileHeld>> = HashMap::new();
    let mut per_unit: HashMap<String, Vec<(String, String)>> = HashMap::new(); // unit -> (code, readability)
    // unit -> the tie-break functions a probe raises: (address, name, built, best)
    let mut raised: HashMap<String, Vec<(i64, String, String, String)>> = HashMap::new();
    for r in &rows {
        let s = &r.src;
        let v = &s.value;
        let file = s.s("file").unwrap_or("").to_string();
        let name = s.s("symbol").unwrap_or("");
        let unit = s.s("unit").unwrap_or("").to_string();
        if !used_files.contains_key(&file) {
            let text = read_text(&root.join(&file));
            let held = match files.1.get(&file) {
                Some(h) if h.text == text => h.clone(),
                _ => Rc::new(FileHeld { src: text.as_deref().map(Source::new), text, verdicts: Default::default() }),
            };
            used_files.insert(file.clone(), held);
        }
        let fh = used_files[&file].clone();
        let def = scan_defs.get(&file).and_then(|d| d.get(name)).map(|&(l, c, el, ec)| (l, c, el.zip(ec)));
        let comment = v.get("comment").and_then(|c| c.as_i64()).unwrap_or(1);
        let fnv = readability::Fn { name, comment, end: v.get("end").and_then(|c| c.as_i64()).unwrap_or(0),
                                    rough: v.get("rough").is_some_and(|r| !r.is_null() && r != &json!(false) && r != &json!("") && r != &json!(0)),
                                    def };
        // own_calls: the last lint's calls inside the function's span (its address comment to its end)
        let lint: Option<Vec<String>> = if linted.contains(unit.as_str()) {
            x.lint_calls.as_ref().map(|c| {
                c.get(&file).map(|v| v.iter().filter(|(line, _)| fnv.comment <= *line && (fnv.end == 0 || *line <= fnv.end))
                    .map(|c| c.1.clone()).collect()).unwrap_or_default()
            })
        } else {
            None
        };
        let key: FnKey = (name.to_string(), fnv.def, comment, fnv.end, fnv.rough, s.lo, None);
        let known = fh.verdicts.borrow().get(&key).cloned();
        let (mut q, mut qf) = match known {
            Some(r) => r,
            None => {
                let r = readability::readability(fh.src.as_ref(), &fnv, s.lo, &cx);
                fh.verdicts.borrow_mut().insert(key, r.clone());
                r
            }
        };
        if let (Some(size), Some(orig)) = (r.dist["size"].as_i64(), r.dist["orig"].as_i64()) {
            if size != 0 && orig != 0 && size * 2 < orig {
                q = "draft".into();
                qf.push(format!("Q8 complete: our code is {size} bytes, the original's {orig}: the body is a stub or unfinished \
                                 (at least half the original's size)"));
            }
        }
        let has = |k: &str| v.get(k).is_some_and(|x| !x.is_null());
        let tag = if has("stuck") { "stuck" } else if has("deep") { "deep" } else if has("hard") { "hard" } else { "" };
        // the experiment: its outcome, what failed (B1..B3), the distance; the calls the consistency convention
        // (docs/mental-model.md §8.8, M7) finds without a declaration belong to it, not to readability
        let mut e = json!({"of": "function", "name": v["symbol"], "unit": v["unit"], "file": v["file"], "comment": comment,
                           "outcome": r.code, "tag": tag, "failing": r.why, "dist": r.dist});
        if r.hunks.as_object().is_some_and(|h| !h.is_empty()) {
            e["hunks"] = r.hunks.clone();
        }
        if !r.open.is_empty() {
            e["open"] = json!(r.open);
        }
        if let Some(calls) = lint.as_ref().filter(|c| !c.is_empty()) {
            e["consistency"] = json!(calls);
        }
        // the declaration-set probe: a sensitive function's best grade under the probes is its source-proven one
        let tb = tiebreak.get(&s.lo).filter(|t| t.s("name") == Some(name));
        let sensitive = tb.is_some_and(|t| t.value["sensitive"].as_bool() == Some(true));
        if let Some(t) = tb {
            e["tiebreak"] = t.value.clone();
            let best = t.s("best").unwrap_or("");
            if sensitive && r.code != NOT_RUN && CODE.contains(&best) && rank(best) > rank(&r.code) {
                e["proven"] = json!(best);
                raised.entry(unit.clone()).or_default().push((s.lo, name.to_string(), r.code.clone(), best.to_string()));
            }
        }
        let levels: Vec<&str> = ["deep", "stuck", "hard"].into_iter().filter(|k| has(k)).collect();
        if levels.len() > 1 {
            out.finding("error", "M2", s.lo, s.lo + 1, format!("{name}: carries more than one level tag (@{})", levels.join(", @")), &s.by);
        } else if sensitive {
            // a byte reached through the declaration set proves nothing about the source: the tag stays
        } else if !tag.is_empty() && r.code == "byte" && q == "readable" {
            out.finding("warn", "M2.stale", s.lo, s.lo + 1, format!("{name}: byte + readable, its @{tag} tag is stale (dcp build clears it)"), &s.by);
        } else if tag == "hard" && r.code != "draft" && q == "readable" {
            // @hard is base work for a stronger worker: shape + readable ends it
            out.finding("warn", "M2.stale", s.lo, s.lo + 1, format!("{name}: {} + readable, its @hard tag is stale (dcp build clears it)", r.code), &s.by);
        }
        // a passing byte experiment reproduces; anything less rests on the address comment
        out.claim(s.lo, s.lo + 1, "experiment", e, if r.code == "byte" { REPRODUCED } else { DECLARED });
        // readability: H against its own standard (§9), no claim about I
        out.claim(s.lo, s.lo + 1, "readability", json!({"of": "function", "name": v["symbol"], "unit": v["unit"], "file": v["file"],
                                                        "grade": q, "failing": qf}), DECLARED);
        per_unit.entry(unit).or_default().push((r.code.clone(), q));
    }
    FILES.with(|h| *h.borrow_mut() = (files.0, used_files));
    for u in store::claims(db, &ctx.db, "unit", &ctx.needed, |f| f.value.get("status").is_some()).map_err(err)? {
        let tu = u.s("tu").unwrap_or("");
        let Some(fs) = per_unit.get(tu) else { continue };
        // a unit with a function not run has no outcome: open
        let code = if fs.iter().any(|f| f.0 == NOT_RUN) { NOT_RUN } else { fs.iter().map(|f| f.0.as_str()).min_by_key(|c| rank(c)).unwrap_or("draft") };
        let named = u.value.get("named_by").filter(|n| !n.is_null());
        let readable = fs.iter().all(|f| f.1 == "readable") && named.is_some_and(|n| n.as_str() != Some("guess"));
        let named_v = match named {
            Some(n) if n.as_str() != Some("") => n.clone(),
            _ => json!("-"),
        };
        out.claim(u.lo, u.hi, "experiment", json!({"of": "unit", "unit": tu, "outcome": code, "functions": fs.len(), "named_by": named_v}),
                  u.support.min(DECLARED));
        if let Some(fs) = raised.get(tu) {
            // the remaining gap is the unit's: its declaration set gives these functions less than their text can
            let names: Vec<String> = fs.iter().take(6).map(|f| format!("{} {} -> {}", f.1, f.2, f.3)).collect();
            let more = if fs.len() > 6 { format!(" (+{})", fs.len() - 6) } else { String::new() };
            out.finding("warn", "G.tiebreak", u.lo, u.hi, format!("unit {tu}: declaration set not yet the original's: {} tie-break function(s) reach a \
                better grade under a no-meaning probe than as built: {}{more} (the headers' declarations, their order or count; the re-match pass \
                runs them last; dcp headers probe {tu})", fs.len(), names.join(", ")), &u.by);
        }
        out.claim(u.lo, u.hi, "readability", json!({"of": "unit", "unit": tu, "grade": if readable { "readable" } else { "draft" }}),
                  u.support.min(DECLARED));
    }
    Ok(())
}
