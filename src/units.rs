//! The file side of unit commands: `dcp unit new` (the skeleton files), `dcp unit join` and `dcp unit rename`.
//!
//! A unit's files: src/<unit>.c (the translation unit: its head region, then its functions in TU order) and
//! include/<unit>.h. Its boundaries are
//! `boundary start|end tu=<unit>` lines of decl/text.dcl (any target prefix). Placeholders of its functions are
//! spelled `<unit>_<addr>` (draft.rs), so a join or a rename of the unit renames them too.

use crate::error::{Error, Result};
use crate::cliread::{record, Tok};
use crate::decl::{Decl, KeyVal};
use crate::edit as E;
use crate::project::native_path;
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::LazyLock;

static UNIT: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"^[A-Za-z_][A-Za-z0-9_.\-]*$").unwrap());
static HEX_TAIL: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"^[0-9a-fA-F]{6,8}$").unwrap());

fn err(e: impl std::fmt::Display) -> Error {
    Error::runtime(e.to_string())
}

fn s(x: impl Into<String>) -> Tok {
    Tok::S(x.into())
}

fn p_of(root: &str, rel: &str) -> String {
    native_path(&format!("{root}/{rel}"))
}

fn exists(root: &str, rel: &str) -> bool {
    Path::new(&p_of(root, rel)).exists()
}

/// A file's text as Path.read_text() reads it (UTF-8, universal newlines).
fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_default().replace("\r\n", "\n").replace('\r', "\n")
}

fn head_text(unit: &str, lo: i64, hi: Option<i64>, by: Option<&str>, why: &str) -> String {
    let rng = match hi { Some(h) => format!("{lo:#010x}..{h:#010x}"), None => format!("{lo:#010x}..") };
    format!("/* {unit}: {why}\n   unit {rng}, named by {}; boundaries in decl/text.dcl */\n#include \"{unit}.h\"\n", by.unwrap_or("-"))
}

/// Write the skeleton files of a new unit (those that do not exist): `wrote <path>` lines.
pub fn unit_create(root: &str, unit: &str, range: &str, by: Option<String>, why: &str) -> Result<Vec<String>> {
    let pa = |x: &str| crate::cliread::parse_addr(x).map_err(Error::value);
    let (lo, hi) = match range.split_once("..") {
        Some((a, b)) => (pa(a)?, Some(pa(b)?)),
        None => (pa(range)?, None),
    };
    let mut out = vec![];
    for (rel, text) in [(format!("src/{unit}.c"), head_text(unit, lo, hi, by.as_deref(), why)), (format!("include/{unit}.h"), E::header_text(unit, why))] {
        if !exists(root, &rel) {
            E::write(&p_of(root, &rel), &text).map_err(err)?;
            out.push(format!("wrote {rel}"));
        }
    }
    Ok(out)
}

// ------------------------------------------------------------------------------------------------ decl lines

/// Rewrite the boundary lines of decl/*.dcl: fix(decl) -> a new Decl, None (drop it) or the same one. The changed
/// lines as `old => new` texts.
fn rewrite_boundaries(root: &str, fix: &mut dyn FnMut(&Decl) -> Option<Decl>) -> Result<Vec<String>, String> {
    let mut changes = vec![];
    for path in crate::decl::files(root) {
        let path = path.to_string_lossy().into_owned();
        let mut out: Vec<String> = vec![];
        for raw in E::splitlines(&read(&path)) {
            let st = raw.trim();
            let d = if st.is_empty() || st.starts_with('#') { None } else { crate::decl::parse_line(st, "", 0).ok().filter(|d| d.kind == "boundary") };
            let Some(d) = d else {
                out.push(raw.to_string());
                continue;
            };
            match fix(&d) {
                None => changes.push(format!("- {}", d.text())),
                Some(n) => {
                    if n.text() != d.text() {
                        changes.push(format!("{}  =>  {}", d.text(), n.text()));
                    }
                    out.push(n.text());
                }
            }
        }
        E::write(&path, &(out.join("\n") + "\n"))?;
    }
    Ok(changes)
}

fn replace_keys(d: &Decl, kv: &[(&str, &str)]) -> Decl {
    let mut n = d.clone();
    for (k, v) in kv {
        match n.keys.iter_mut().find(|x| x.0 == *k) {
            Some(x) => x.1 = KeyVal::Str(v.to_string()),
            None => n.keys.push((k.to_string(), KeyVal::Str(v.to_string()))),
        }
    }
    n
}

fn tu_of(d: &Decl) -> Option<&str> {
    d.key("tu").map(|k| k.s())
}

/// {`<unit>_<addr>` -> `<new>_<addr>`} for every placeholder of the sources spelled with the unit's prefix.
fn unit_placeholders(root: &str, unit: &str, new: &str) -> Result<BTreeMap<String, String>, String> {
    let pre = format!("{}_", E::c_name(unit));
    let mut out = BTreeMap::new();
    for part in &crate::frontend::scan(root, None)?.parts {
        for ph in &part.placeholders {
            if let Some(tail) = ph.2.strip_prefix(&pre).filter(|t| HEX_TAIL.is_match(t)) {
                out.insert(ph.2.clone(), format!("{}_{tail}", E::c_name(new)));
            }
        }
    }
    Ok(out)
}

// ------------------------------------------------------------------------------------------------ join

#[derive(Default)]
struct Join {
    moved: Vec<String>,
    renamed: BTreeMap<String, String>,
    decl: Vec<String>,
}

/// into + the lines of extra that into does not hold (and that are not in drop), in extra's order.
fn merge_lines(into: &str, extra: &str, drop: &HashSet<String>) -> String {
    let have: HashSet<&str> = E::splitlines(into).into_iter().map(|l| l.trim()).filter(|l| !l.is_empty()).collect();
    let add: Vec<&str> = E::splitlines(extra).into_iter().filter(|l| !l.trim().is_empty() && !have.contains(l.trim()) && !drop.contains(l.trim())).collect();
    if add.is_empty() {
        return into.to_string();
    }
    into.trim_end_matches('\n').to_string() + "\n" + &add.join("\n") + "\n"
}

/// Move unit b into unit a (the caller checked that b directly follows a): a's head region plus the lines of b's head
/// a lacks (b's include of its own header becomes a's, b's leading comment goes), then a's functions, then b's.
fn join(root: &str, a: &str, b: &str) -> Result<Join, String> {
    let mut j = Join::default();
    let (fa, fb) = (p_of(root, &format!("src/{a}.c")), p_of(root, &format!("src/{b}.c")));
    if Path::new(&fb).exists() {
        let ea = if Path::new(&fa).exists() { E::head_end(root, &format!("src/{a}.c"))? } else { 0 };
        let eb = E::head_end(root, &format!("src/{b}.c"))?;
        let la: Vec<String> = if Path::new(&fa).exists() { read(&fa).trim_end_matches('\n').split('\n').map(|l| l.to_string()).collect() } else { vec![format!("#include \"{a}.h\"")] };
        let lb: Vec<String> = read(&fb).trim_end_matches('\n').split('\n').map(|l| l.to_string()).collect();
        let head_b = lb[..eb.min(lb.len())].join("\n");
        let mut drop: HashSet<String> = [format!("#include \"{b}.h\""), format!("#include \"{a}.h\"")].into_iter().collect();
        drop.extend(lb.iter().take(2).filter(|l| l.trim_start().starts_with("/*") || l.trim_start().starts_with("unit")).map(|l| l.trim().to_string()));
        let head = merge_lines(&(la[..ea.min(la.len())].join("\n") + "\n"), &head_b, &drop);
        let body_a = la[ea.min(la.len())..].join("\n").trim_matches('\n').to_string();
        let body_b = lb[eb.min(lb.len())..].join("\n").trim_matches('\n').to_string();
        let bodies: Vec<&str> = [body_a.as_str(), body_b.as_str()].into_iter().filter(|x| !x.is_empty()).collect();
        E::write(&fa, &(head.trim_end_matches('\n').to_string() + "\n\n" + &bodies.join("\n\n") + "\n"))?;
        E::remove(root, &fb)?;
        j.moved.push(format!("src/{b}.c -> src/{a}.c"));
    }
    // the headers: b's declarations into a's, before a's #endif
    let (xa, xb) = (p_of(root, &format!("include/{a}.h")), p_of(root, &format!("include/{b}.h")));
    if Path::new(&xb).exists() {
        let gb = format!("#define {}", E::guard(b));
        let lead = format!("/* {b}.h");
        let body: Vec<String> = E::splitlines(&read(&xb)).into_iter()
            .filter(|l| !l.trim().is_empty() && !(l.starts_with("#ifndef") || l.starts_with(&gb) || l.starts_with("#endif") || l.starts_with(&lead)))
            .map(|l| l.to_string()).collect();
        let text = if Path::new(&xa).exists() { read(&xa) } else { E::header_text(a, "") };
        let mut lines: Vec<String> = E::splitlines(text.trim_end_matches('\n')).into_iter().map(|l| l.to_string()).collect();
        let have: HashSet<String> = lines.iter().map(|l| l.trim().to_string()).collect();
        let at = lines.iter().rposition(|l| l.trim().starts_with("#endif")).unwrap_or(lines.len());
        let add: Vec<String> = body.into_iter().filter(|l| !have.contains(l.trim())).collect();
        lines.splice(at..at, add);
        E::write(&xa, &(lines.join("\n") + "\n"))?;
        E::remove(root, &xb)?;
    }
    // includes of b's header now name a's
    let (inc_b, inc_a) = (format!("#include \"{b}.h\""), format!("#include \"{a}.h\""));
    for (_, p) in E::sources(root) {
        let t = String::from_utf8_lossy(&std::fs::read(&p).unwrap_or_default()).replace("\r\n", "\n");
        if t.contains(&inc_b) {
            let mut seen = false;
            let mut out: Vec<String> = vec![];
            for l in E::splitlines(&t) {
                if l.trim() == inc_b || l.trim() == inc_a {
                    if seen {
                        continue;
                    }
                    seen = true;
                    out.push(inc_a.clone());
                } else {
                    out.push(l.to_string());
                }
            }
            E::write(&p, &(out.join("\n") + "\n"))?;
        }
    }
    // decl: b's start goes, b's end becomes a's end, a's own end (at b's start) goes
    let mut b_start: Option<i64> = None;
    rewrite_boundaries(root, &mut |d: &Decl| {
        if tu_of(d) == Some(b) && d.words.first().map(|w| w.as_str()) == Some("start") {
            b_start = Some(d.lo);
        }
        Some(d.clone())
    })?;
    j.decl = rewrite_boundaries(root, &mut |d: &Decl| {
        let tu = tu_of(d);
        let w = d.words.first().map(|w| w.as_str());
        if tu == Some(b) && w == Some("start") {
            return None;
        }
        if tu == Some(a) && w == Some("end") && b_start == Some(d.lo) {
            return None;
        }
        if tu == Some(b) && w == Some("end") {
            return Some(replace_keys(d, &[("tu", a)]));
        }
        Some(d.clone())
    })?;
    // placeholders of b's functions are a's now
    j.renamed = unit_placeholders(root, b, a)?;
    E::rename_words(root, &j.renamed, false, None)?;
    Ok(j)
}

// ------------------------------------------------------------------------------------------------ rename

#[derive(Default)]
struct Rename {
    moved: Vec<String>,
    renamed: BTreeMap<String, String>,
    decl: Vec<String>,
    includes: i64,
}

/// Rename unit old to new: its file, the header (and its guard), the includes, the boundary lines' tu= (and
/// the start's by=), the placeholders `<old>_<addr>`.
fn rename(root: &str, old: &str, new: &str, by: Option<&str>) -> Result<Rename, String> {
    let mut r = Rename::default();
    if exists(root, &format!("src/{new}.c")) || exists(root, &format!("include/{new}.h")) {
        return Err(format!("unit {new} exists (src/{new}.c or include/{new}.h)"));
    }
    let (so, sn) = (format!("src/{old}.c"), format!("src/{new}.c"));
    if exists(root, &so) {
        E::move_file(root, &p_of(root, &so), &p_of(root, &sn))?;
        r.moved.push(format!("{so} -> {sn}"));
    }
    let (ho, hn) = (format!("include/{old}.h"), format!("include/{new}.h"));
    if exists(root, &ho) {
        E::move_file(root, &p_of(root, &ho), &p_of(root, &hn))?;
        r.moved.push(format!("{ho} -> {hn}"));
        let t = read(&p_of(root, &hn));
        let t = regex::Regex::new(&format!(r"\b{}\b", regex::escape(&E::guard(old)))).unwrap().replace_all(&t, regex::NoExpand(&E::guard(new))).into_owned();
        let t = t.replace(&format!("/* {old}.h:"), &format!("/* {new}.h:")).replace(&format!("of unit {old}"), &format!("of unit {new}"));
        E::write(&p_of(root, &hn), &t)?;
    }
    let (io, inew) = (format!("#include \"{old}.h\""), format!("#include \"{new}.h\""));
    for (_, p) in E::sources(root) {
        let t = String::from_utf8_lossy(&std::fs::read(&p).unwrap_or_default()).replace("\r\n", "\n");
        if t.contains(&io) {
            E::write(&p, &t.replace(&io, &inew))?;
            r.includes += 1;
        }
    }
    let sn = p_of(root, &format!("src/{new}.c"));
    if Path::new(&sn).exists() {
        let t = read(&sn);
        let lead = format!("/* {old}:");
        if let Some(rest) = t.strip_prefix(&lead) {
            E::write(&sn, &(format!("/* {new}:") + rest))?;
        }
    }
    r.decl = rewrite_boundaries(root, &mut |d: &Decl| {
        if tu_of(d) != Some(old) {
            return Some(d.clone());
        }
        match by {
            Some(b) if d.words.first().map(|w| w.as_str()) == Some("start") => Some(replace_keys(d, &[("tu", new), ("by", b)])),
            _ => Some(replace_keys(d, &[("tu", new)])),
        }
    })?;
    r.renamed = unit_placeholders(root, old, new)?;
    E::rename_words(root, &r.renamed, false, None)?;
    Ok(r)
}

// ------------------------------------------------------------------------------------------------ the commands

fn view_units(p: &crate::project::Project) -> Result<Vec<String>> {
    let db = p.store_path();
    crate::storedb::st_open(&db)?;
    let image = p.target.path.clone();
    Ok(crate::layoutview::View::load(&db, &image)?.units.iter().map(|u| u.tu.clone()).collect())
}

/// ({function address: code grade}, the number of bug / error conflicts).
fn byte_state(db: &str) -> Result<(BTreeMap<i64, Option<String>>, usize)> {
    let grades = crate::queues::function_grades(db)?.iter().cloned()
        .filter_map(|r| Some((r.get("addr")?.as_i64()?, r.get("code").and_then(|c| c.as_str()).map(|c| c.to_string())))).collect();
    let errors = crate::storedb::st_findings(db, None, None)?.iter().filter(|c| c.0 == "bug" || c.0 == "error").count();
    Ok((grades, errors))
}

fn placeholder_events(renamed: &BTreeMap<String, String>) -> Vec<(Option<i64>, &'static str, String, String)> {
    renamed.iter().map(|(o, n)| (o.rsplit('_').next().and_then(|h| i64::from_str_radix(h, 16).ok()), "func", o.clone(), n.clone())).collect()
}

/// `dcp unit join` (unit_join): `build()` builds and refreshes the target.
pub fn unit_join(p: &crate::project::Project, a: &str, b: &str, why: &str, build: &mut dyn FnMut() -> Result<()>) -> Result<(Vec<String>, Option<String>, i32)> {
    let root = p.root.to_string_lossy().into_owned();
    let names = view_units(p)?;
    if let Some(m) = [a, b].into_iter().find(|u| !names.iter().any(|n| n == u)) {
        let list = if names.is_empty() { "none".to_string() } else { names.join(", ") };
        return Ok((vec![], Some(format!("no unit {m} (units: {list})")), 1));
    }
    let (ia, ib) = (names.iter().position(|n| n == a).unwrap(), names.iter().position(|n| n == b).unwrap());
    if ib != ia + 1 {
        return Ok((vec![], Some(format!("{b} does not directly follow {a} (join neighbours, the earlier one first)")), 1));
    }
    build()?;
    let db = p.store_path();
    let (before, err_before) = byte_state(&db)?;
    let j = match join(&root, a, b) {
        Ok(j) => j,
        Err(e) => return Ok((vec![], Some(e), 1)),
    };
    let mut events = vec![(None, "unit", b.to_string(), a.to_string())];
    events.extend(placeholder_events(&j.renamed));
    E::log_names(&root, &events, &format!("join: {why}")).map_err(err)?;
    let mut out: Vec<String> = j.moved.iter().map(|m| format!("moved {m}")).collect();
    out.extend(j.decl.iter().map(|c| format!("decl  {c}")));
    out.extend(j.renamed.iter().map(|(o, n)| format!("renamed {o} -> {n}")));
    build()?;
    let (after, err_after) = byte_state(&db)?;
    let keys: std::collections::BTreeSet<i64> = before.keys().chain(after.keys()).copied().collect();
    let get = |m: &BTreeMap<i64, Option<String>>, k: &i64| m.get(k).cloned().flatten();
    let changed: Vec<i64> = keys.into_iter().filter(|k| get(&before, k) != get(&after, k)).collect();
    let byte = |m: &BTreeMap<i64, Option<String>>| m.values().filter(|c| c.as_deref() == Some("byte")).count() as i64;
    out.push(record(&[("joined", s(b)), ("into", s(a)), ("byte_before", Tok::I(byte(&before))), ("byte_after", Tok::I(byte(&after))),
                      ("grades_changed", Tok::I(changed.len() as i64)), ("errors_before", Tok::I(err_before as i64)), ("errors_after", Tok::I(err_after as i64))]));
    let ot = |x: Option<String>| x.map(Tok::S).unwrap_or(Tok::No);
    for k in &changed {
        out.push(format!("  {}", record(&[("fn", Tok::I(*k)), ("before", ot(get(&before, k))), ("after", ot(get(&after, k)))])));
    }
    if !changed.is_empty() || err_after > err_before {
        out.push("the join changed grades or added errors: evidence to keep the units apart (revert: git checkout -- . && git clean -fd src include)".into());
        return Ok((out, None, 1));
    }
    Ok((out, None, 0))
}

/// `dcp unit rename` (unit_rename): `rebuild()` compiles and refreshes.
pub fn unit_rename(p: &crate::project::Project, old: &str, new: &str, by: Option<String>, why: &str, rebuild: &mut dyn FnMut() -> Result<()>)
    -> Result<(Vec<String>, Option<String>, i32)> {
    let root = p.root.to_string_lossy().into_owned();
    let names = view_units(p)?;
    if !UNIT.is_match(new) || !E::IDENT.is_match(&E::c_name(new)) {
        return Ok((vec![], Some(format!("{} is not a unit name", crate::decl::quote_str(new))), 1));
    }
    if !names.iter().any(|n| n == old) && !exists(&root, &format!("src/{old}")) {
        return Ok((vec![], Some(format!("no unit {old}")), 1));
    }
    let r = match rename(&root, old, new, by.as_deref()) {
        Ok(r) => r,
        Err(e) => return Ok((vec![], Some(e), 1)),
    };
    let mut events = vec![(None, "unit", old.to_string(), new.to_string())];
    events.extend(placeholder_events(&r.renamed));
    E::log_names(&root, &events, &format!("by={}: {why}", by.as_deref().unwrap_or("-"))).map_err(err)?;
    let mut out: Vec<String> = r.moved.iter().map(|m| format!("moved {m}")).collect();
    out.extend(r.decl.iter().map(|c| format!("decl  {c}")));
    out.extend(r.renamed.iter().map(|(o, n)| format!("renamed {o} -> {n}")));
    rebuild()?;
    let (_, bad) = byte_state(&p.store_path())?;
    out.push(record(&[("unit", s(old)), ("renamed", s(new)), ("by", by.map(Tok::S).unwrap_or(Tok::No)), ("includes", Tok::I(r.includes)),
                      ("placeholders", Tok::I(r.renamed.len() as i64)), ("errors", Tok::I(bad as i64))]));
    Ok((out, None, if bad > 0 { 1 } else { 0 }))
}
