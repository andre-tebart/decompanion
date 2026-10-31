//! G.grade (rules/grade.py keeps the criteria: its module docstring and the rule's): the code grade of every
//! sourced function from its compare and instruction diff (diffclass.rs), its readability (readability.rs), the
//! unit grades.

use crate::diffclass::{self, Env, Verdict};
use crate::readability::{self, Context, Source};
use crate::rules::{compiled_functions, Ctx};
use crate::store::{self, Out, SFact, DECLARED, PROVEN};
use crate::image;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

fn err(e: rusqlite::Error) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

const CODE: [&str; 3] = ["draft", "shape", "byte"];

fn rank(c: &str) -> usize {
    CODE.iter().position(|x| *x == c).unwrap_or(0)
}

/// What G.grade reads that only Python computes (grade_inputs in rules/grade.py).
#[derive(Default, serde::Deserialize)]
#[serde(default)]
struct Inputs {
    raw: Vec<String>,
    described: Vec<i64>,
    scan: ScanDefs,
    lint_calls: Option<HashMap<String, Vec<(i64, String)>>>,
    linted: Vec<String>,
    function_alignment: i64,
}

#[derive(Default, serde::Deserialize)]
#[serde(default)]
struct ScanDefs {
    defs: HashMap<String, HashMap<String, (i64, i64, Option<i64>, Option<i64>)>>, // file -> name -> start, end
}

/// One function's code grade row: (code, why, hunks, dist).
struct Row {
    src: Rc<SFact>,
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

fn key_of(f: &crate::rules::Compiled, w: Option<&Rc<SFact>>) -> Key {
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
    // the latest run's results by what they are computed from (Key), under the image, the capstone library, the
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

pub fn g_grade(ctx: &Ctx, db: &Connection, out: &mut Out) -> PyResult<()> {
    let img = image(&ctx.image)?;
    let x: Inputs = serde_json::from_str(&ctx.extra).map_err(|e| PyRuntimeError::new_err(format!("G.grade: native inputs: {e}")))?;
    let (funcs, missing) = compiled_functions(ctx, db)?;
    let symbols = store::facts(db, &ctx.db, "symbol", &ctx.needed, |_| true).map_err(err)?;
    let matched: HashSet<i64> = symbols.iter().filter(|f| &*f.rule == "M.match").map(|f| f.lo).collect();
    let mut walk: HashMap<i64, Rc<SFact>> = HashMap::new();
    for f in symbols.iter().filter(|f| f.s("skind") == Some("func") && matches!(&*f.rule, "S.codewalk" | "L.src.extent")) {
        walk.insert(f.lo, f.clone());
    }
    let range = (img.base as i64, img.end() as i64);
    let fills: HashSet<Vec<u8>> = ctx.fill_forms.iter().cloned().collect();
    let forms = crate::compare::fill_order(&ctx.fill_forms);
    let env = Env { dll: &ctx.capstone, img: &img, range, fills: &fills, forms: &forms };
    let e = |s: String| PyRuntimeError::new_err(s);
    let mut rows: Vec<Row> = vec![];
    let world = format!("{}|{}|{:?}|{}", ctx.image, ctx.capstone, ctx.fill_forms, x.function_alignment);
    let mut held = HELD.with(|h| std::mem::take(&mut *h.borrow_mut()));
    if held.0 != world {
        held = (world, HashMap::new());
    }
    let mut used: HashMap<Key, Rc<Held>> = HashMap::new();
    for f in &funcs {
        let lo = f.src.lo;
        let w = walk.get(&lo);
        let key = key_of(f, w);
        let h = match held.1.get(&key) {
            Some(h) => h.clone(),
            None => {
                let (cd, cm) = f.code.code();
                let size = diffclass::code_size(&env, cd, cm, lo as u32).map_err(e)?;
                let extent = w.map(|w| w.hi - lo).unwrap_or(size);
                let slot = extent.max(f.next as i64 - lo);
                let o = diffclass::original(&env, lo as u32, extent, slot, x.function_alignment).map_err(e)?;
                Rc::new(Held { size, extent, slot, o, verdict: std::cell::OnceCell::new() })
            }
        };
        used.insert(key, h.clone());
        let (size, extent, slot) = (h.size, h.extent, h.slot);
        let orig_size = h.o.code;
        let n = size.min(orig_size);
        let nbytes = f.c.diffs.iter().filter(|&&k| (k as i64) < n).count() as i64 + (size - orig_size).abs();
        let (g, why, hunks, dist_ins);
        if matched.contains(&lo) {
            (g, why, hunks, dist_ins) = ("byte".to_string(), vec![], json!({}), 0usize);
        } else {
            if h.verdict.get().is_none() {
                let v = diffclass::function_verdict(&env, &f.obj.0, &f.code, lo as u32, &h.o).map_err(e)?;
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
        let def = x.scan.defs.get(&file).and_then(|d| d.get(name)).map(|&(l, c, el, ec)| (l, c, el.zip(ec)));
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
        let key: FnKey = (name.to_string(), fnv.def, comment, fnv.end, fnv.rough, s.lo, lint.clone());
        let known = fh.verdicts.borrow().get(&key).cloned();
        let (mut q, mut qf) = match known {
            Some(r) => r,
            None => {
                let r = readability::readability(fh.src.as_ref(), &fnv, s.lo, &cx, lint.as_deref());
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
        let level = if has("stuck") { "stuck" } else if has("deep") { "deep" } else { "" };
        let mut failing = r.why.clone();
        failing.extend(qf);
        let mut g = json!({"of": "function", "name": v["symbol"], "unit": v["unit"], "file": v["file"], "comment": comment,
                           "code": r.code, "readability": q, "level": level, "failing": failing, "dist": r.dist});
        if r.hunks.as_object().is_some_and(|h| !h.is_empty()) {
            g["hunks"] = r.hunks.clone();
        }
        if has("deep") && has("stuck") {
            out.conflict("error", "M2", s.lo, s.lo + 1, format!("{name}: carries both @deep and @stuck"), &s.by);
        } else if !level.is_empty() && r.code == "byte" && q == "readable" {
            out.conflict("warn", "M2", s.lo, s.lo + 1, format!("{name}: byte + readable, its @{level} tag is stale (dcp build clears it)"), &s.by);
        }
        out.fact(s.lo, s.lo + 1, "grade", g, if r.code == "byte" { PROVEN } else { DECLARED });
        per_unit.entry(unit).or_default().push((r.code.clone(), q));
    }
    FILES.with(|h| *h.borrow_mut() = (files.0, used_files));
    for u in store::facts(db, &ctx.db, "unit", &ctx.needed, |f| f.value.get("status").is_some()).map_err(err)? {
        let tu = u.s("tu").unwrap_or("");
        let Some(fs) = per_unit.get(tu) else { continue };
        let code = fs.iter().map(|f| f.0.as_str()).min_by_key(|c| rank(c)).unwrap_or("draft");
        let named = u.value.get("named_by").filter(|n| !n.is_null());
        let readable = fs.iter().all(|f| f.1 == "readable") && named.is_some_and(|n| n.as_str() != Some("guess"));
        let named_v = match named {
            Some(n) if n.as_str() != Some("") => n.clone(),
            _ => json!("-"),
        };
        out.fact(u.lo, u.hi, "grade", json!({"of": "unit", "unit": tu, "code": code, "readability": if readable { "readable" } else { "draft" },
                                            "functions": fs.len(), "named_by": named_v}), u.level.min(DECLARED));
    }
    Ok(())
}
