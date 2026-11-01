//! `dcp libs candidates`: the evidence of the obligation libs.archives. Every run-time archive of the declared
//! toolchain root (VC6: LIBC, LIBCMT, their debug variants, MSVCRT, the C++ libraries) is placed into the image on
//! its own with S.crt.code's search (crt.rs place_members), and reported as members (objects in the archive),
//! placed (members with a placed section), bytes (placed bytes). Two archives conflict where they place sections of
//! different names on overlapping bytes.
//!
//! Each archive's result is kept as a blob keyed by (the placement's code, the image's sha256, the archive's
//! contents' sha256), like a rule run; the summary of the last call is the store's meta `libs.candidates`. Nothing
//! here declares anything: `dcp libs declare` does, with a reason.

use crate::error::{Error, Result};
use crate::crt::{place_members, Placed};
use crate::fsmemo;
use crate::project::{py_path, sha256_parts, Project};
use crate::store::canon;
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashSet};
use std::path::Path;

/// The run-time archives VC6 links (the order `dcp libs candidates` tries them in).
const CRT_ARCHIVES: [&str; 13] = ["LIBC.LIB", "LIBCD.LIB", "LIBCMT.LIB", "LIBCMTD.LIB", "MSVCRT.LIB", "MSVCRTD.LIB", "LIBCP.LIB", "LIBCPD.LIB",
                                  "LIBCPMT.LIB", "LIBCPMTD.LIB", "MSVCPRT.LIB", "MSVCPRTD.LIB", "OLDNAMES.LIB"];

/// The run-time archives present under VC98/Lib of the root.
pub fn library_candidates(root: Option<&str>) -> Vec<String> {
    let Some(root) = root else { return vec![] };
    let d = Path::new(root).join("VC98").join("Lib");
    let have: std::collections::HashMap<String, String> = std::fs::read_dir(&d).into_iter().flatten().flatten()
        .map(|e| (e.file_name().to_string_lossy().to_uppercase(), py_path(&e.path().to_string_lossy()))).collect();
    CRT_ARCHIVES.iter().filter_map(|a| have.get(*a).cloned()).collect()
}

fn canonical(v: &Value) -> String {
    let mut s = String::new();
    canon(&mut s, v);
    s
}

/// {archive, members, placed, bytes, places: [[lo, hi, name], ...]} of one archive.
fn place_one(img: &crate::pe::Image, archive: &str, sites: &BTreeSet<i64>) -> Result<Value, String> {
    let data = std::fs::read(archive).map_err(|e| format!("{archive}: {e}"))?;
    let objs = crate::coff::archive_objects(&data).map_err(|e| format!("{archive}: {e}"))?;
    let name = Path::new(archive).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let members = objs.iter().map(|o| o.name.clone()).collect::<HashSet<_>>().len();
    let places: Vec<crate::crt::Placement> = place_members(img, &[(name.clone(), objs)], sites).into_iter()
        .filter_map(|p| match p { Placed::At(x) => Some(x), _ => None }).collect();
    let units: HashSet<&str> = places.iter().map(|p| p.unit.as_str()).collect();
    Ok(json!({"archive": name, "members": members, "placed": units.len(), "bytes": places.iter().map(|p| p.hi - p.lo).sum::<i64>(),
              "places": places.iter().map(|p| json!([p.lo, p.hi, p.name])).collect::<Vec<_>>()}))
}

/// Archive pairs placing sections of different names on overlapping bytes: {a, b, overlaps, first}.
fn conflicts(results: &[Value]) -> Vec<Value> {
    let places = |r: &Value| -> Vec<(i64, i64, String)> {
        r["places"].as_array().into_iter().flatten().map(|p| (p[0].as_i64().unwrap_or(0), p[1].as_i64().unwrap_or(0), p[2].as_str().unwrap_or("").to_string())).collect()
    };
    let mut out = vec![];
    for (i, a) in results.iter().enumerate() {
        for b in &results[i + 1..] {
            let mut pb = places(b);
            pb.sort();
            let (mut n, mut first): (i64, Option<i64>) = (0, None);
            for (lo, hi, name) in places(a) {
                for (blo, bhi, bname) in &pb {
                    if *blo >= hi {
                        break;
                    }
                    if *bhi > lo && *bname != name {
                        n += 1;
                        first = Some(first.unwrap_or(lo.min(*blo)));
                    }
                }
            }
            if n > 0 {
                out.push(json!({"a": a["archive"], "b": b["archive"], "overlaps": n, "first": first}));
            }
        }
    }
    out
}

/// Place every candidate archive (kept per image and archive contents); store and return the summary {root,
/// image, archives: [...] by placed bytes, conflicts: [...], ms, cached} and the log lines.
pub fn candidates(p: &Project, core_hash: &str, force: bool) -> Result<(Value, Vec<String>), String> {
    let t0 = std::time::Instant::now();
    let db = p.store_path();
    crate::pystore::st_open(&db, &p.main_uri()).map_err(|e| e.to_string())?;
    let target = p.target(None)?;
    let img = crate::image(&target.path).map_err(|e| e.to_string())?;
    let img_sha = fsmemo::sha256(&target.path).map_err(|e| e.to_string())?;
    let code = crate::engine::native_code_hash(crate::engine::rule("S.crt.code").map_err(|e| e.to_string())?, core_hash);
    let sites: BTreeSet<i64> = img.relocations().into_iter().map(|x| x as i64).collect();
    let (mut results, mut cached, mut log) = (vec![], 0, vec![]);
    for archive in library_candidates(p.toolchain_root().as_deref()) {
        let key = sha256_parts(&["libs.candidates", &code, &img_sha, &fsmemo::sha256(&archive).map_err(|e| e.to_string())?]);
        let hit: Option<Value> = if force {
            None
        } else {
            crate::with_db(&db, |c| {
                use rusqlite::OptionalExtension;
                c.query_row("SELECT data FROM blob WHERE hash=?", [&key], |r| r.get::<_, Vec<u8>>(0)).optional()
            }).map_err(|e| e.to_string())?.and_then(|d| serde_json::from_slice(&d).ok())
        };
        let r = match hit {
            Some(r) => {
                cached += 1;
                r
            }
            None => {
                let t1 = std::time::Instant::now();
                let r = place_one(&img, &archive, &sites)?;
                crate::with_db(&db, |c| c.execute("INSERT OR IGNORE INTO blob (hash, kind, data) VALUES (?, 'libs.candidates', ?)",
                                                  rusqlite::params![key, canonical(&r).as_bytes()]).map(|_| ())).map_err(|e| e.to_string())?;
                log.push(format!("placed {}: {} members, {} ms", r["archive"].as_str().unwrap_or(""), r["placed"], t1.elapsed().as_millis()));
                r
            }
        };
        results.push(r);
    }
    results.sort_by(|a, b| (-a["bytes"].as_i64().unwrap_or(0), a["archive"].as_str()).cmp(&(-b["bytes"].as_i64().unwrap_or(0), b["archive"].as_str())));
    let decl = p.toolchain_decl(None)?;
    let mut summary = json!({
        "root": decl["root"].as_str().unwrap_or(""), "image": img_sha,
        "archives": results.iter().map(|r| json!({"archive": r["archive"], "members": r["members"], "placed": r["placed"], "bytes": r["bytes"]})).collect::<Vec<_>>(),
        "conflicts": conflicts(&results),
    });
    crate::pystore::st_set_meta(&db, "libs.candidates", &canonical(&summary)).map_err(|e| e.to_string())?;
    summary["ms"] = json!(t0.elapsed().as_millis() as i64);
    summary["cached"] = json!(cached);
    Ok((summary, log))
}

/// `dcp libs candidates`: (the lines, the log lines): per archive members, placed members and bytes (sorted by
/// bytes), whether the target declares it, the archive pairs that conflict.
pub fn libs_candidates_lines(p: &crate::project::Project, core_hash: &str, force: bool) -> Result<(Vec<String>, Vec<String>)> {
    use crate::cliread::{record, Tok};
    let _ = core_hash; // the build's own (crate::CORE_HASH, through the project)
    let (v, log) = candidates(p, &p.core_hash, force).map_err(Error::runtime)?;
    let declared: Vec<String> = p.archives_decl(None).map_err(Error::runtime)?.0.unwrap_or_default().iter()
        .map(|a| a.rsplit(['/', '\\']).next().unwrap_or(a).to_uppercase()).collect();
    let i = |x: &Value| Tok::I(x.as_i64().unwrap_or(0));
    let st = |x: &Value| Tok::S(x.as_str().unwrap_or("").to_string());
    let mut out = vec![record(&[("target", Tok::S(p.target_name.clone())), ("root", st(&v["root"])), ("archives", Tok::I(v["archives"].as_array().map_or(0, |a| a.len()) as i64)),
                                ("cached", i(&v["cached"])), ("ms", i(&v["ms"]))])];
    for r in v["archives"].as_array().into_iter().flatten() {
        let name = r["archive"].as_str().unwrap_or("");
        out.push(format!("  {}", record(&[("archive", st(&r["archive"])), ("members", i(&r["members"])), ("placed", i(&r["placed"])), ("bytes", i(&r["bytes"])),
                                          ("declared", if declared.contains(&name.to_uppercase()) { Tok::S("yes".into()) } else { Tok::No })])));
    }
    let conflicts = v["conflicts"].as_array().cloned().unwrap_or_default();
    for c in &conflicts {
        out.push(format!("  {}", record(&[("conflict", Tok::S(format!("{},{}", c["a"].as_str().unwrap_or(""), c["b"].as_str().unwrap_or("")))),
                                          ("overlaps", i(&c["overlaps"])), ("first", c["first"].as_i64().map(Tok::I).unwrap_or(Tok::No))])));
    }
    if conflicts.is_empty() {
        out.push("  conflicts: none".into());
    }
    out.push("resolve: dcp libs declare ARCHIVE... --why \"...\" (the evidence above)".into());
    Ok((out, log))
}
