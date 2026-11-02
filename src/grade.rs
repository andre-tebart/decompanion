//! G.grade: per sourced function the object experiment (docs/mental-model.md §4: its outcome byte / shape / draft
//! from the compare and the instruction diff, diffclass.rs; what failed, B1..B3; the calls the consistency
//! convention finds without a declaration, M7) as an `experiment` claim, and its readability (§9, readability.rs:
//! Q1..Q6, Q8) as a `readability` row, kept apart; the same per unit.

use crate::error::{Error, Result};
use crate::diffclass::{self, Env, Verdict};
use crate::readability::{self, Context, Source};
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
}

fn read_text(path: &std::path::Path) -> Option<String> {
    let b = std::fs::read(path).ok()?;
    Some(String::from_utf8_lossy(&b).replace("\r\n", "\n").replace('\r', "\n"))
}

/// What one function's code grade is computed from besides its compare: its bytes and relocation mask, where its
/// code ends (code_len), the targets of the relocated fields after it (its switch tables: offset, width, target
/// inside the function), its address, the next start, the walk's or the source extent's end.
type Key = (Vec<u8>, Vec<u8>, Option<u32>, Vec<(u32, u32, Option<i64>)>, i64, u32, Option<i64>);

fn key_of(f: &crate::rules::Compiled, w: Option<&Rc<Claim>>) -> Key {
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
    (code.data.clone(), code.mask.clone(), code.code_len, tbl, f.src.lo, f.next, w.map(|w| w.hi))
}

/// A function's code size, its extent and slot, the original as the diff reads it, its verdict (when asked: a
/// byte match needs none).
struct Held {
    size: i64,
    extent: i64,
    slot: i64,
    o: diffclass::Original,
    verdict: std::cell::OnceCell<Verdict>,
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
}

type Computed = (i64, i64, i64, diffclass::Original, Option<Verdict>);

/// A function's code size, extent, slot, original and (no byte match) its verdict.
fn compute(env: &Env, t: &Task, align: i64) -> Computed {
    let (cd, cm) = t.code.code();
    let size = diffclass::code_size(env, cd, cm, t.lo as u32);
    let extent = t.whi.map(|h| h - t.lo).unwrap_or(size);
    let slot = extent.max(t.next as i64 - t.lo);
    let o = diffclass::original(env, t.lo as u32, extent, slot, align);
    let v = if t.matched { None } else { Some(diffclass::FunctionCompare::new(env, t.obj, t.code, t.lo as u32, &o).verdict) };
    (size, extent, slot, o, v)
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
    let keys: Vec<Key> = funcs.iter().map(|f| key_of(f, walk.get(&f.src.lo))).collect();
    // the functions not held (all of them after a start): computed on every core, each independent of the others
    let todo: Vec<Task> = funcs.iter().zip(&keys).enumerate().filter(|(_, (_, k))| !held.1.contains_key(*k)).map(|(i, (f, _))| Task {
        i, code: &f.code, obj: &f.obj.0, lo: f.src.lo, next: f.next, whi: walk.get(&f.src.lo).map(|w| w.hi), matched: matched.contains(&f.src.lo),
    }).collect();
    let mut fresh: HashMap<usize, Rc<Held>> = HashMap::new();
    for (i, r) in compute_all(&env, &todo, x.function_alignment) {
        let (size, extent, slot, o, v) = r;
        let verdict = std::cell::OnceCell::new();
        if let Some(v) = v {
            let _ = verdict.set(v);
        }
        fresh.insert(i, Rc::new(Held { size, extent, slot, o, verdict }));
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
        let (g, why, hunks, dist_ins);
        let consts = if matched.contains(&lo) {
            let sites: HashSet<u32> = f.code.relocs.iter().map(|(off, _)| *off).collect();
            crate::rules::constant_mismatches(&img, f, &sites)
        } else {
            vec![]
        };
        if matched.contains(&lo) && consts.is_empty() {
            (g, why, hunks, dist_ins) = ("byte".to_string(), vec![], json!({}), 0usize);
        } else if matched.contains(&lo) {
            // the bytes match, a literal or a floating constant they reference does not (M9 / M10): a meaning
            // difference, draft (it must not pass at shape)
            (g, hunks, dist_ins) = ("draft".to_string(), json!({}), 0usize);
            let mut w: Vec<String> = consts.iter().map(|(_, _, rule, msg)| format!("B1 byte: {rule} {msg}")).collect();
            let rules: BTreeSet<&str> = consts.iter().map(|c| c.2).collect();
            w.push(format!("B3 draft: {} referenced literal(s) / constant(s) differ from the original's ({}): a meaning difference",
                           consts.len(), rules.into_iter().collect::<Vec<_>>().join(", ")));
            why = w;
        } else {
            if h.verdict.get().is_none() {
                let v = diffclass::FunctionCompare::new(&env, &f.obj.0, &f.code, lo as u32, &h.o).verdict;
                let _ = h.verdict.set(v);
            }
            let v: &Verdict = h.verdict.get().unwrap();
            g = if v.shape { "shape" } else { "draft" }.to_string();
            hunks = v.hunks_json();
            dist_ins = v.distance;
            let mut w = vec![];
            let c_why = f.c.why();
            if !c_why.is_empty() {
                w.push(format!("B1 byte: {c_why}"));
            }
            if g == "draft" {
                w.push(format!("{}{}", if v.code.is_empty() { "B3 draft: " } else { "B3 draft: unexplained code hunks: " }, v.summary()));
            } else {
                w.push(format!("B2 shape: {}", v.summary()));
            }
            why = w;
        }
        rows.push(Row { src: f.src.clone(), code: g, why, hunks,
                        dist: json!({"ins": dist_ins, "bytes": nbytes, "size": size, "orig": orig_size, "extent": extent, "slot": slot}) });
    }
    HELD.with(|h| *h.borrow_mut() = (held.0, used));
    for (s, reason) in &missing {
        let orig = walk.get(&s.lo).map(|w| json!(w.hi - s.lo)).unwrap_or(Value::Null);
        rows.push(Row { src: s.clone(), code: "draft".into(), why: vec![format!("B3 draft: {reason}")], hunks: json!({}),
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
        let tag = if has("stuck") { "stuck" } else if has("deep") { "deep" } else { "" };
        // the experiment: its outcome, what failed (B1..B3), the distance; the calls the consistency convention
        // (docs/mental-model.md §8.8, M7) finds without a declaration belong to it, not to readability
        let mut e = json!({"of": "function", "name": v["symbol"], "unit": v["unit"], "file": v["file"], "comment": comment,
                           "outcome": r.code, "tag": tag, "failing": r.why, "dist": r.dist});
        if r.hunks.as_object().is_some_and(|h| !h.is_empty()) {
            e["hunks"] = r.hunks.clone();
        }
        if let Some(calls) = lint.as_ref().filter(|c| !c.is_empty()) {
            e["consistency"] = json!(calls);
        }
        if has("deep") && has("stuck") {
            out.finding("error", "M2", s.lo, s.lo + 1, format!("{name}: carries both @deep and @stuck"), &s.by);
        } else if !tag.is_empty() && r.code == "byte" && q == "readable" {
            out.finding("warn", "M2", s.lo, s.lo + 1, format!("{name}: byte + readable, its @{tag} tag is stale (dcp build clears it)"), &s.by);
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
        let code = fs.iter().map(|f| f.0.as_str()).min_by_key(|c| rank(c)).unwrap_or("draft");
        let named = u.value.get("named_by").filter(|n| !n.is_null());
        let readable = fs.iter().all(|f| f.1 == "readable") && named.is_some_and(|n| n.as_str() != Some("guess"));
        let named_v = match named {
            Some(n) if n.as_str() != Some("") => n.clone(),
            _ => json!("-"),
        };
        out.claim(u.lo, u.hi, "experiment", json!({"of": "unit", "unit": tu, "outcome": code, "functions": fs.len(), "named_by": named_v}),
                  u.support.min(DECLARED));
        out.claim(u.lo, u.hi, "readability", json!({"of": "unit", "unit": tu, "grade": if readable { "readable" } else { "draft" }}),
                  u.support.min(DECLARED));
    }
    Ok(())
}
