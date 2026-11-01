//! `dcp toolchain probe`: which compiler flags the matched functions prove.
//! The result feeds M.flags.proven (mrules.rs analyse reads it).
//!
//! Anchors: every byte-matched function of the target (code grade byte), compiled as its unit; and, when the
//! toolchain root holds CRT sources (VC6: VC98/CRT/SRC), every source whose object is a library member placed in the
//! image (S.crt.code), its functions compared at their placed addresses (reported apart: another compiler build).
//!
//! The grid (VC6: /O1 /O2 /Ox x /G3 /G4 /G5 /G6 /GB x /Oy /Oy- x /Gy x /GF /Gf x /Ob0 /Ob1 /Ob2): every combination
//! replaces the grid's flags among the unit's flags; a combination the compiler refuses is pruned. Each anchor unit
//! is compiled once per combination (one process each, on threads; objects kept by the unit's text and flags), each
//! anchor compared with the masked compare of M.match. The result is the store meta `probe`.

use crate::error::{Error, Result};
use crate::fsmemo;
use crate::project::{py_path, sha256_parts, Project};
use crate::store::{self, canon};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

pub const GRID: [(&str, &[&str]); 6] = [("optimise", &["/O1", "/O2", "/Ox"]), ("cpu", &["/G3", "/G4", "/G5", "/G6", "/GB"]), ("frame", &["/Oy", "/Oy-"]),
                                        ("comdat", &["/Gy"]), ("strings", &["/GF", "/Gf"]), ("inline", &["/Ob0", "/Ob1", "/Ob2"])];
/// What CL does in each group when the command line names nothing of it under /O1 /O2 /Ox.
pub const DEFAULTS: [&str; 4] = ["/GB", "/Oy", "/GF", "/Ob1"];

fn canonical(v: &Value) -> String {
    let mut s = String::new();
    canon(&mut s, v);
    s
}

fn combos() -> Vec<Vec<String>> {
    let mut out: Vec<Vec<String>> = vec![vec![]];
    for (_, alts) in GRID {
        out = out.into_iter().flat_map(|c| alts.iter().map(move |a| {
            let mut x = c.clone();
            x.push(a.to_string());
            x
        })).collect();
    }
    out
}

fn strip_grid(flags: &[String]) -> Vec<String> {
    let every: BTreeSet<String> = GRID.iter().flat_map(|(_, a)| a.iter().map(|f| f.to_lowercase())).collect();
    flags.iter().filter(|f| !every.contains(&f.to_lowercase())).cloned().collect()
}

/// One anchor unit: (id, kind, unit, source as the compiler reads it, base flags, include dirs, anchors (id, name,
/// address), its text).
struct Job {
    kind: &'static str,
    unit: String,
    src: String,
    base: Vec<String>,
    dirs: Vec<String>,
    anchors: Vec<(String, String, i64)>,
    text: String,
}

pub fn probe(p: &Project) -> Result<(Value, String), String> {
    let t0 = std::time::Instant::now();
    let root = p.root.to_string_lossy().into_owned();
    let db = p.store_path();
    crate::pystore::st_open(&db, &p.main_uri()).map_err(|e| e.to_string())?;
    let tools = crate::vc6::Tools::of(p);
    let target = p.target(None)?;
    let img = crate::image(&target.path).map_err(|e| e.to_string())?;
    let all_combos = combos();
    let rows: Vec<serde_json::Map<String, Value>> = crate::queues::function_grades(&db).map_err(|e| e.to_string())?
        .iter().cloned().filter(|r| r["code"] == "byte").collect();
    let plan = crate::plan::plan(p)?;
    let units: HashMap<&str, &crate::plan::Tu> = plan.iter().map(|a| (a.unit.as_str(), a)).collect();
    let mut jobs: Vec<Job> = vec![];
    let row_units: BTreeSet<&str> = rows.iter().filter_map(|r| r["unit"].as_str()).collect();
    for unit in row_units {
        let Some(a) = units.get(unit) else { continue };
        let flags = crate::plan::compile_flags(p, &a.target, unit)?;
        let anchors = rows.iter().filter(|r| r["unit"] == unit)
            .map(|r| { let x = r["addr"].as_i64().unwrap_or(0); (format!("{x:#010x}"), r["name"].as_str().unwrap_or("").to_string(), x) }).collect();
        let text = fsmemo::read_text(&py_path(&format!("{root}/{}", a.file))).map_err(|e| e.to_string())?;
        jobs.push(Job { kind: "user", unit: unit.into(), src: a.file.replace('/', "\\"), base: strip_grid(&flags), dirs: vec!["include".into()], anchors, text });
    }
    let all = |k: &str| crate::with_db(&db, |c| store::facts_of(c, &db, k, None, |_| true)).map_err(|e| e.to_string());
    let mut lib_names: BTreeMap<(String, String), i64> = BTreeMap::new();
    for f in all("name")? {
        if f.s("origin") == Some("lib") {
            if let Some(u) = f.s("unit").filter(|u| !u.is_empty()) {
                for n in f.s("name").unwrap_or("").split('|') {
                    lib_names.insert((u.to_string(), n.to_string()), f.lo);
                }
            }
        }
    }
    // the CRT sources whose objects are placed members
    if let Some(r) = tools.root.clone() {
        let src = Path::new(&r).join("VC98").join("CRT").join("SRC");
        if src.exists() {
            let mut placed: HashMap<String, String> = HashMap::new();
            for f in all("unit")? {
                let tu = f.s("tu").unwrap_or("");
                if tu.starts_with("lib:") && tu.contains('/') {
                    placed.entry(tu.rsplit_once('/').unwrap().1.to_lowercase()).or_insert_with(|| tu.to_string());
                }
            }
            let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&src).into_iter().flatten().flatten().map(|e| e.path()).collect();
            files.sort_by_key(|x| x.to_string_lossy().to_lowercase());
            for path in files {
                if !path.extension().is_some_and(|x| x.eq_ignore_ascii_case("c")) {
                    continue;
                }
                let stem = path.file_stem().map(|s| s.to_string_lossy().to_lowercase()).unwrap_or_default();
                let Some(unit) = placed.get(&format!("{stem}.obj")) else { continue };
                let anchors: Vec<(String, String, i64)> = lib_names.iter().filter(|((u, _), _)| u == unit)
                    .map(|((_, n), a)| (format!("{a:#010x}"), n.clone(), *a)).collect();
                if anchors.is_empty() {
                    continue;
                }
                let ps = py_path(&path.to_string_lossy());
                let text = crate::vc6::cp1252(&std::fs::read(&path).map_err(|e| e.to_string())?);
                jobs.push(Job { kind: "crt", unit: unit.clone(), src: ps, base: vec![], dirs: vec![py_path(&src.to_string_lossy())], anchors, text });
            }
        }
    }
    let relocs: Vec<u32> = {
        let mut r = img.relocations();
        r.sort();
        r
    };
    let relocs_opt = if relocs.is_empty() { None } else { Some(relocs.as_slice()) };
    let mut starts: BTreeSet<i64> = all("start")?.iter().map(|f| f.lo).collect();
    starts.extend(img.sections.iter().filter(|s| s.holds_code()).map(|s| s.end() as i64));
    let starts: Vec<i64> = starts.into_iter().collect();
    let key_of = |j: &Job, combo: &[String]| -> String {
        let flags: Vec<String> = j.base.iter().chain(combo).cloned().collect();
        sha256_parts(&["probe".to_string(), j.text.clone(), canonical(&json!(flags)), canonical(&json!(j.dirs))])
    };
    let blob = |k: &str| -> Result<Option<Value>, String> {
        Ok(crate::with_db(&db, |c| {
            use rusqlite::OptionalExtension;
            c.query_row("SELECT data FROM blob WHERE hash=?", [k], |r| r.get::<_, Vec<u8>>(0)).optional()
        }).map_err(|e| e.to_string())?.and_then(|d| serde_json::from_slice(&d).ok()))
    };
    let obj_exists = |h: &str| Path::new(&crate::compile::obj_path(&root, h)).exists();
    let run = |j: &Job, combo: &[String], key: &str| -> Value {
        let flags: Vec<String> = j.base.iter().chain(combo).cloned().collect();
        let tmp = format!("build\\obj\\probe\\{}\\p.obj", &key[..16]);
        let tmp_abs = py_path(&format!("{root}/{tmp}"));
        let _ = std::fs::create_dir_all(Path::new(&tmp_abs).parent().unwrap());
        let res = match tools.compile(&j.src, &tmp, &flags, &j.dirs, &root) {
            Ok(r) => r,
            Err(e) => return json!({"failed": [e]}),
        };
        let out = if !res.refused.is_empty() {
            json!({"refused": res.refused})
        } else if !res.ok {
            json!({"failed": res.diags.iter().filter(|d| d.severity == "error").take(3).map(|d| d.text()).collect::<Vec<_>>()})
        } else {
            match std::fs::read(&tmp_abs) {
                Ok(data) => {
                    let h = fsmemo::hex(&<sha2::Sha256 as sha2::Digest>::digest(&data));
                    let dest = crate::compile::obj_path(&root, &h);
                    if Path::new(&dest).exists() {
                        let _ = std::fs::remove_file(&tmp_abs);
                    } else {
                        let _ = std::fs::create_dir_all(Path::new(&dest).parent().unwrap());
                        let _ = std::fs::rename(&tmp_abs, &dest);
                    }
                    json!({"obj": h})
                }
                Err(e) => json!({"failed": [e.to_string()]}),
            }
        };
        let _ = std::fs::remove_dir(Path::new(&tmp_abs).parent().unwrap());
        out
    };
    let mut results: HashMap<String, Value> = HashMap::new();
    let mut compiles = 0usize;
    let mut compile_missing = |items: Vec<(usize, Vec<String>, String)>, results: &mut HashMap<String, Value>| -> Result<(), String> {
        let mut todo = vec![];
        for (k, c, key) in items {
            match blob(&key)? {
                Some(hit) if hit.get("obj").and_then(|o| o.as_str()).is_none_or(obj_exists) => {
                    results.insert(key, hit);
                }
                _ => todo.push((k, c, key)),
            }
        }
        let done = crate::compile_threads(&todo, |(k, c, key)| run(&jobs[*k], c, key));
        for ((_, _, key), res) in todo.iter().zip(done) {
            crate::with_db(&db, |c| c.execute("INSERT OR IGNORE INTO blob (hash, kind, data) VALUES (?, 'probe', ?)",
                                              rusqlite::params![key, canonical(&res).as_bytes()]).map(|_| ())).map_err(|e| e.to_string())?;
            results.insert(key.clone(), res);
        }
        compiles += todo.len();
        Ok(())
    };
    let first = &all_combos[0];
    compile_missing(jobs.iter().enumerate().map(|(k, j)| (k, first.clone(), key_of(j, first))).collect(), &mut results)?;
    let dead: BTreeSet<usize> = jobs.iter().enumerate().filter(|(_, j)| results[&key_of(j, first)].get("failed").is_some()).map(|(k, _)| k).collect();
    let work: Vec<(usize, Vec<String>, String)> = jobs.iter().enumerate()
        .flat_map(|(k, j)| all_combos.iter().map(move |c| (k, c.clone(), key_of(j, c)))).collect();
    compile_missing(work.iter().filter(|w| !dead.contains(&w.0)).cloned().collect(), &mut results)?;
    let res_of = |k: usize, c: &[String]| -> Value {
        let key = if dead.contains(&k) { key_of(&jobs[k], first) } else { key_of(&jobs[k], c) };
        results.get(&key).cloned().unwrap_or(Value::Null)
    };
    let anchors_out: Vec<Value> = jobs.iter().flat_map(|j| j.anchors.iter().map(move |(aid, name, _)| json!({"id": aid, "name": name, "unit": j.unit, "kind": j.kind}))).collect();
    let tc_forms: Vec<Vec<u8>> = crate::toolchain::of(&p.toolchain_key()).map(|t| t.fill_forms().iter().map(|f| f.to_vec()).collect()).unwrap_or_default();
    let forms = crate::compare::fill_order(&tc_forms);
    let mut objs: HashMap<String, Option<crate::coff::Obj>> = HashMap::new();
    let mut out_combos = vec![];
    for combo in &all_combos {
        let (mut matched, mut refused, mut failed): (BTreeSet<String>, Value, BTreeSet<String>) = (BTreeSet::new(), Value::Null, BTreeSet::new());
        for (k, j) in jobs.iter().enumerate() {
            let res = res_of(k, combo);
            if let Some(r) = res.get("refused") {
                refused = r.clone();
                continue;
            }
            if res.get("failed").is_some() {
                failed.insert(j.unit.clone());
                continue;
            }
            let Some(h) = res.get("obj").and_then(|o| o.as_str()) else { continue };
            let obj = objs.entry(h.to_string()).or_insert_with(|| {
                std::fs::read(crate::compile::obj_path(&root, h)).ok().and_then(|d| crate::coff::Obj::parse(&d).ok())
            });
            let Some(obj) = obj else { continue };
            let mut idx: HashMap<String, usize> = HashMap::new();
            for s in obj.functions() {
                let n = &obj.symbols[s].name;
                idx.entry(n.clone()).or_insert(s);
                idx.entry(crate::coff::undecorate(n)).or_insert(s);
            }
            for (aid, name, addr) in &j.anchors {
                let Some(&s) = idx.get(name) else { continue };
                let code = obj.function_code(s);
                let nxt = starts.get(starts.partition_point(|&x| x <= *addr)).copied().unwrap_or(img.end() as i64);
                if crate::compare::compare(&img, &code, *addr as u32, relocs_opt, nxt as u32, &forms).matched() {
                    matched.insert(aid.clone());
                }
            }
        }
        out_combos.push(json!({"flags": combo, "matched": matched, "refused": refused, "failed": failed}));
    }
    let decl = p.toolchain_decl(None)?;
    let result = json!({"grid": GRID.iter().map(|(g, a)| json!([g, a])).collect::<Vec<_>>(), "anchors": anchors_out, "combos": out_combos,
                        "declared": decl["cflags"], "defaults": DEFAULTS});
    crate::pystore::st_set_meta(&db, "probe", &canonical(&result)).map_err(|e| e.to_string())?;
    let ms = t0.elapsed().as_millis() as i64;
    let mut result = result;
    result["ms"] = json!(ms);
    result["compiles"] = json!(compiles);
    result["cached"] = json!(work.len() - compiles);
    let log = format!("probe: {} anchor units, {} combinations, {compiles} compiles, {ms} ms", jobs.len(), all_combos.len());
    Ok((result, log))
}

/// probe.probe: (the result with ms, compiles, cached; the log line).
pub fn probe_run(p: &crate::project::Project) -> Result<(Value, String)> {
    probe(p).map_err(Error::runtime)
}
