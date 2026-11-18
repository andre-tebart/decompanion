//! The file side of unit commands: `dcp unit new` (the skeleton files), `dcp unit join`, `dcp unit split` (one unit
//! into two at an address) and `dcp unit rename`.
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
use std::collections::{BTreeMap, HashMap, HashSet};
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

// ------------------------------------------------------------------------------------------------ split

/// One function of the unit's file: its lines [lo, hi) (0-based: its address comment to its closing line).
struct Chunk {
    addr: Option<i64>,
    name: String,
    lo: usize,
    hi: usize,
    def_line: i64,
    stat: bool,
}

/// A data definition outside every function: its statement's lines [lo, hi) (with the comment lines above it that
/// lead into it and the lines of a comment its last line opens), its start (line, column; 1-based).
struct DataDef {
    name: String,
    /// every declarator's name (`int a, b;`: a and b)
    names: Vec<String>,
    stat: bool,
    /// an initializer: no tentative definition (a non-static one without is a common, LINK places it)
    init: bool,
    lo: usize,
    hi: usize,
    start: (i64, i64),
}

/// Where a data definition goes in a split (`Split::data_moved`): its name, its lines in the old file, why.
type MovedData = (String, usize, usize, String);

/// What a split writes and what the dry run prints.
#[derive(Default)]
struct Split {
    moved: Vec<(i64, String, usize, usize)>, // addr, name, lines [lo, hi) of the old file (0-based)
    kept: usize,
    data: Vec<(String, usize, usize)>, // the data definitions among the moved functions that stay: the new file declares them extern
    data_moved: Vec<MovedData>,        // the data definitions that move with the functions (their uses, the original's data layout)
    copied: usize,                     // declaration lines among the moved functions the old file keeps a copy of
    carried: usize,                    // declaration lines of the old file before the moved functions the new file copies
    protos_old: Vec<String>,           // prototypes of moved functions the rest of the old file uses
    decls_new: Vec<String>,            // declarations of the old file's definitions the moved functions use
    head_externs: Vec<String>,         // head data definitions the new file's copy of the head declares extern
    notes: Vec<String>,
    warnings: Vec<String>,
    old_text: String,
    new_text: String,
    new_head: Vec<String>,  // the new file's head lines (the old head, its data definitions extern), without the lead
    new_parts: Vec<String>, // the new file's parts after its head: declarations, data that moves, the moved functions
    renamed: BTreeMap<String, String>,
}

static CODE_TOKEN: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"(?s)"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|//[^\n]*|/\*.*?\*/"#).unwrap());
static WORD: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"[A-Za-z_]\w*").unwrap());

/// The identifiers of a C text outside its comments and literals.
fn code_words(text: &str) -> HashSet<String> {
    let code = CODE_TOKEN.replace_all(text, " ");
    WORD.find_iter(&code).map(|m| m.as_str().to_string()).collect()
}

/// The text between two clang positions (1-based line and column, columns in characters; `to` exclusive, a column
/// past the line's end is its end).
fn slice(lines: &[&str], from: (i64, i64), to: (i64, i64)) -> String {
    let at = |(l, c): (i64, i64)| -> (usize, usize) {
        let l = ((l - 1).max(0) as usize).min(lines.len().saturating_sub(1));
        let line = lines.get(l).copied().unwrap_or("");
        let c = line.char_indices().nth((c - 1).max(0) as usize).map(|(i, _)| i).unwrap_or(line.len());
        (l, c)
    };
    let ((l1, c1), (l2, c2)) = (at(from), at(to));
    if l1 >= l2 {
        let l = lines.get(l1).copied().unwrap_or("");
        return l[c1.min(l.len())..c2.max(c1).min(l.len())].to_string();
    }
    let mut s = lines[l1][c1..].to_string();
    for l in &lines[l1 + 1..l2] {
        s.push('\n');
        s.push_str(l);
    }
    s.push('\n');
    s.push_str(&lines[l2][..c2]);
    s
}

/// One line of declaration text: whitespace runs as one space (kept as written when a `//` comment is in it).
fn one_line(s: &str) -> String {
    if s.contains("//") {
        return s.trim().to_string();
    }
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The extern declaration of a data definition statement (the text from its start): the initializers dropped (each
/// declarator's `= ...` at depth 0), the statement cut at its `;`.
fn extern_of(stmt: &str) -> String {
    let cs: Vec<char> = stmt.chars().collect();
    let mut out = String::new();
    let (mut depth, mut skip, mut i) = (0i32, false, 0usize);
    while i < cs.len() {
        let c = cs[i];
        if c == '/' && cs.get(i + 1) == Some(&'*') {
            let mut j = i + 2;
            while j + 1 < cs.len() && !(cs[j] == '*' && cs[j + 1] == '/') {
                j += 1;
            }
            if !skip {
                out.extend(&cs[i..(j + 2).min(cs.len())]);
            }
            i = j + 2;
            continue;
        }
        if c == '"' || c == '\'' {
            let mut j = i + 1;
            while j < cs.len() && cs[j] != c {
                j += if cs[j] == '\\' { 2 } else { 1 };
            }
            if !skip {
                out.extend(&cs[i..(j + 1).min(cs.len())]);
            }
            i = j + 1;
            continue;
        }
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ';' if depth == 0 => break,
            '=' if depth == 0 => {
                out.truncate(out.trim_end().len());
                skip = true;
                i += 1;
                continue;
            }
            ',' if depth == 0 => skip = false,
            _ => {}
        }
        if !skip {
            out.push(c);
        }
        i += 1;
    }
    format!("extern {};", one_line(&out))
}

/// The prototype of a function definition from its text up to the body: a K&R definition's as `T f();`.
fn prototype_of(sig: &str, name: &str) -> String {
    let s = sig.trim();
    if let Some(k) = s.rfind(')') {
        if !s[k + 1..].trim().is_empty() {
            let re = regex::Regex::new(&format!(r"\b{}\s*\(", regex::escape(name))).unwrap();
            if let Some(m) = re.find(s) {
                return format!("{});", one_line(&s[..m.end()]));
            }
        }
    }
    format!("{};", one_line(s))
}

/// Blank lines off both ends.
fn trim_blank(v: &mut Vec<String>) {
    while v.last().is_some_and(|l| l.trim().is_empty()) {
        v.pop();
    }
    let k = v.iter().position(|l| !l.trim().is_empty()).unwrap_or(v.len());
    v.drain(..k);
}

/// The texts of a split of unit `unit` at `at` into `new` (nothing written). `lead`: the new file's leading comment.
/// `section(addr)`: the original's section kind of a data address (data / rdata / bss), None outside the image.
///
/// The old file loses the moved functions' lines (each function's address comment to its closing line, and what lies
/// between them); the new file is `lead`, the old head region (its leading comment left out, its data definitions
/// extern, `#include "<new>.h"` after the old unit's include), the declarations between the head and the moved
/// functions (every one but the macros they do not use), the declarations of the old file's definitions the moved
/// functions use, the data definitions that move, then the moved lines as they were.
///
/// A data definition moves with the functions (`data_moved`) when the new object's data block holds it: per section
/// kind of the original, the unit's addressed definitions in address order, the new unit's block the run from the
/// lowest one only the moved functions use above every one only the rest of the old file uses (the new unit links
/// after the old one, its data after the old unit's); a definition without an address, or a tentative one (a
/// common: LINK places it apart from its unit), moves when only the moved functions use it. A moved definition the
/// rest of the old file uses leaves an extern declaration in its place; a static one stays. The other data
/// definitions between the moved functions stay in the old file, the new file declares them extern in their place;
/// the declarations between them (macros, types, externs) move and the old file keeps a copy (before the prototypes
/// of the moved functions the rest of the old file uses). A data definition takes along the comment lines that lead
/// into it and the lines of a comment its statement's last line opens; a declaration line, the lines of a comment it
/// opens.
///
/// `front`: the functions below `at` move instead (the front of the unit, into the unit before it: dcp unit move); the
/// new object's data block is then the run up to the highest datum only the moved functions use, below every one only
/// the rest uses.
fn plan_split(root: &str, unit: &str, at: i64, new: &str, target: &str, lead: &str, section: &dyn Fn(i64) -> Option<String>, front: bool)
              -> Result<Split, String> {
    let rel = format!("src/{unit}.c");
    let path = p_of(root, &rel);
    if !Path::new(&path).exists() {
        return Err(format!("unit {unit} has no file {rel}"));
    }
    let text = read(&path);
    let lines: Vec<&str> = text.trim_end_matches('\n').split('\n').collect();
    let sc = crate::frontend::scan(root, None)?;
    let model = sc.models.get(&rel).ok_or_else(|| format!("{rel} has no parse (dcp build says why)"))?;
    let mut fns: Vec<Chunk> = vec![];
    for f in sc.functions().filter(|f| f.0 .0 == rel) {
        let addr = f.0 .4.iter().find(|(t, _)| t.as_deref().is_none_or(|t| t == target)).map(|x| x.1 as i64);
        let (c, e) = (f.1 .3, f.1 .5);
        if e <= 0 || c <= 0 {
            return Err(format!("{rel}:{}: function {} has no end in the file", f.0 .1, f.0 .3));
        }
        fns.push(Chunk { addr, name: f.0 .3.clone(), lo: (c - 1) as usize, hi: (e as usize).min(lines.len()), def_line: f.0 .1, stat: f.1 .4 });
    }
    fns.sort_by_key(|c| c.lo);
    let (moved, kept): (Vec<&Chunk>, Vec<&Chunk>) = fns.iter().partition(|c| c.addr.is_some_and(|a| (a >= at) != front));
    let side = if front { "below" } else { "at or above" };
    if moved.is_empty() {
        return Err(format!("no function of {rel} lies {side} {at:#x}"));
    }
    if !kept.iter().any(|c| c.addr.is_some()) {
        return Err(format!("every function of {rel} lies {side} {at:#x}: nothing would stay (dcp unit rename renames a unit)"));
    }
    let (r0, r1) = (moved[0].lo, moved.iter().map(|c| c.hi).max().unwrap());
    if let Some(k) = kept.iter().find(|k| k.lo < r1 && k.hi > r0) {
        let what = k.addr.map(|a| format!("{a:#x}")).unwrap_or_else(|| "unlinked".into());
        return Err(format!("{rel}:{}: {} ({what}) lies among the functions to move (lines {}..{}): put the file in address order first",
                           k.lo + 1, k.name, r0 + 1, r1));
    }
    let mut s = Split { kept: kept.iter().filter(|c| c.addr.is_some()).count(), ..Default::default() };
    s.moved = moved.iter().map(|c| (c.addr.unwrap(), c.name.clone(), c.lo, c.hi)).collect();
    if moved.windows(2).any(|w| w[0].addr > w[1].addr) {
        s.notes.push(format!("the moved functions are not in address order in {rel}: they keep the file's order"));
    }
    let in_fn = |i: usize| fns.iter().any(|c| c.lo <= i && i < c.hi);
    let in_moved = |i: usize| moved.iter().any(|c| c.lo <= i && i < c.hi);
    // whole-line comments (a comment alone on its lines), and the continuation lines of a comment a line of code
    // opens (glue: line -> the line that opens it)
    let mut comment_only: HashSet<usize> = HashSet::new();
    let mut glue: HashMap<usize, usize> = HashMap::new();
    let mut spans: Vec<(usize, usize)> = vec![];
    for &(l1, c1, l2, c2) in &model.comments {
        let (a, b) = ((l1 - 1).max(0) as usize, (l2 - 1).max(0) as usize);
        let (Some(first), Some(last)) = (lines.get(a), lines.get(b)) else { continue };
        let before: String = first.chars().take((c1 - 1).max(0) as usize).collect();
        let after: String = last.chars().skip((c2 - 1).max(0) as usize).collect();
        spans.push((a, b));
        if before.trim().is_empty() && after.trim().is_empty() {
            comment_only.extend(a..=b);
        } else {
            for k in a + 1..=b {
                glue.entry(k).or_insert(a);
            }
        }
    }
    // the data definitions outside the functions (one statement each; several declarators share a start)
    let mut datas: Vec<DataDef> = vec![];
    for d in &model.decls {
        if let crate::clang::Decl::V(name, stat, ws, np, e, kind, _, _) = d {
            let lo = (ws.0 - 1).max(0) as usize;
            if kind != "def" || lo >= lines.len() || in_fn(lo) {
                continue;
            }
            // an initialiser: a `=` between the declarator's name and its end (clang's init flag also counts an
            // array's bound: `int a[4];` is a tentative definition, a common)
            let init = &CODE_TOKEN.replace_all(&slice(&lines, *np, *e), " ").contains('=');
            if let Some(x) = datas.iter_mut().find(|x| x.start == *ws) {
                x.names.push(name.clone());
                x.init |= *init;
                continue;
            }
            // the statement runs to its `;` (the extent ends with the declarator)
            let mut hi = ((e.0 - 1).max(0) as usize).max(lo);
            while hi + 1 < lines.len() && !CODE_TOKEN.replace_all(&slice(&lines, *ws, (hi as i64 + 1, i64::MAX / 4)), " ").contains(';') {
                hi += 1;
            }
            datas.push(DataDef { name: name.clone(), names: vec![name.clone()], stat: *stat, init: *init, lo, hi: hi + 1, start: *ws });
        }
    }
    for d in datas.iter_mut() {
        // a comment the statement's lines open runs on: its lines are the definition's
        loop {
            let end = spans.iter().filter(|&&(a, b)| d.lo <= a && a < d.hi && b >= d.hi).map(|x| x.1 + 1).max();
            match end {
                Some(e) if e > d.hi => d.hi = e.min(lines.len()),
                _ => break,
            }
        }
        // the comment lines right above it (no blank line between; never the file's leading comment) lead into it
        while d.lo > 0 && comment_only.contains(&(d.lo - 1)) && !in_fn(d.lo - 1) {
            let top = spans.iter().filter(|&&(a, b)| a <= d.lo - 1 && d.lo - 1 <= b).map(|x| x.0).min().unwrap_or(d.lo - 1);
            if top == 0 {
                break;
            }
            d.lo = top;
        }
    }
    let stmt_of = |d: &DataDef| slice(&lines, d.start, (d.hi as i64, i64::MAX / 4));
    // which data moves: by its uses (the moved functions' text against the rest of the file) and the original's
    // data layout
    let moved_text: String = moved.iter().map(|c| lines[c.lo..c.hi].join("\n")).collect::<Vec<_>>().join("\n");
    let moved_fn_words = code_words(&moved_text);
    // a file-scope extern declaration is no use (a unit that declares its .bss and commons at its head and defines
    // them after its functions)
    let ext_lines: HashSet<usize> = model.decls.iter().filter_map(|d| match d {
        crate::clang::Decl::V(_, _, ws, _, e, kind, _, _) if kind == "extern" && !in_fn((ws.0 - 1).max(0) as usize) => {
            Some((ws.0 - 1).max(0) as usize..=(e.0 - 1).max(0) as usize)
        }
        _ => None,
    }).flatten().collect();
    let rest_text: String = lines.iter().enumerate().map(|(i, l)| if in_moved(i) || ext_lines.contains(&i) { "" } else { *l }).collect::<Vec<_>>().join("\n");
    let rest_counts = word_counts(&rest_text);
    let use_of = |d: &DataDef| -> (bool, bool) {
        let own = word_counts(&lines[d.lo..d.hi].join("\n"));
        let m = d.names.iter().any(|n| moved_fn_words.contains(n));
        let k = d.names.iter().any(|n| rest_counts.get(n).copied().unwrap_or(0) > own.get(n).copied().unwrap_or(0));
        (m, k)
    };
    let addr_of: HashMap<String, i64> = sc.parts.iter().filter(|p| p.rel == rel)
        .flat_map(|p| p.data.iter())
        .filter_map(|r| r.5.iter().find(|(t, _)| t.as_deref().is_none_or(|t| t == target)).map(|x| (r.3.clone(), x.1 as i64)))
        .collect();
    let uses: Vec<(bool, bool)> = datas.iter().map(use_of).collect();
    let addrs: Vec<Option<i64>> = datas.iter().map(|d| d.names.iter().filter_map(|n| addr_of.get(n).copied()).min()).collect();
    let mut moves: Vec<Option<String>> = vec![None; datas.len()];
    let mut by_sec: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (j, d) in datas.iter().enumerate() {
        let tentative = !d.stat && !d.init;
        match addrs[j].and_then(|a| section(a)) {
            Some(k) if !tentative => by_sec.entry(k).or_default().push(j),
            _ => {
                if uses[j] == (true, false) {
                    moves[j] = Some(format!("only the moved functions use it{}", if tentative { " (a common)" } else { "" }));
                }
            }
        }
    }
    for (kind, mut js) in by_sec {
        // the moved block lies at the far end from the kept one: the top (a tail) or the bottom (a front, read from
        // the top down)
        js.sort_by_key(|&j| addrs[j]);
        if front {
            js.reverse();
        }
        let (from, first_word, below) = if front { ("up to", "last", "above") } else { ("from", "first", "below") };
        let last_kept = js.iter().rposition(|&j| uses[j] == (false, true));
        let first = js.iter().enumerate().position(|(x, &j)| uses[j] == (true, false) && last_kept.is_none_or(|k| x > k));
        if let Some(f) = first {
            for &j in &js[f..] {
                moves[j] = Some(format!("in the new object's {kind} block ({from} {:#x}, the {first_word} {kind} only the moved functions use)", addrs[js[f]].unwrap()));
            }
        }
        for &j in &js[..first.unwrap_or(js.len())] {
            if uses[j] == (true, false) {
                s.notes.push(format!("{rel}:{}: {} ({:#x}) only the moved functions use, but it lies {below} {kind} the rest of {unit} uses: it \
                                      stays, {new} declares it extern", datas[j].lo + 1, datas[j].name, addrs[j].unwrap()));
            }
        }
    }
    for (j, d) in datas.iter().enumerate() {
        if moves[j].is_some() && d.stat && uses[j].1 {
            s.warnings.push(format!("{rel}:{}: static data {} lies in the new object's data but the rest of {unit} uses it: it stays", d.lo + 1, d.name));
            moves[j] = None;
        }
    }
    let moving = |d: &DataDef| datas.iter().position(|x| x.start == d.start).is_some_and(|j| moves[j].is_some());
    // the old file's text of a moving definition: its extern declaration where the rest of the file uses it
    let mut old_repl: HashMap<usize, (usize, Option<String>)> = HashMap::new();
    for (j, d) in datas.iter().enumerate() {
        if let Some(why) = &moves[j] {
            s.data_moved.push((d.name.clone(), d.lo, d.hi, why.clone()));
            old_repl.insert(d.lo, (d.hi, uses[j].1.then(|| extern_of(&stmt_of(d)))));
        }
    }
    // the region: the moved functions and what lies between them
    let mut new_body: Vec<String> = vec![];
    let mut stay: Vec<String> = vec![];
    let mut copies: Vec<usize> = vec![];
    let mut i = r0;
    while i < r1 {
        if let Some(d) = datas.iter().find(|d| d.lo == i && !in_moved(i)) {
            if moving(d) {
                new_body.extend(lines[d.lo..d.hi].iter().map(|l| l.to_string()));
                if let Some((_, Some(x))) = old_repl.get(&d.lo) {
                    stay.push(x.clone());
                }
                i = d.hi;
                continue;
            }
            if d.stat {
                s.warnings.push(format!("{rel}:{}: static data {} lies among the moved functions: it stays in {unit}; the moved functions that use it \
                                         do not compile until it is shared", i + 1, d.name));
            } else {
                new_body.push(extern_of(&stmt_of(d)));
            }
            stay.extend(lines[d.lo..d.hi].iter().map(|l| l.to_string()));
            s.data.push((d.name.clone(), d.lo, d.hi));
            i = d.hi;
            continue;
        }
        let l = lines[i];
        new_body.push(l.to_string());
        if !in_moved(i) && !l.trim().is_empty() && !comment_only.contains(&i) {
            copies.push(i);
        }
        i += 1;
    }
    // the head region: the new file's copy without the old file's leading comment, its data definitions extern
    let he = fns.iter().map(|c| c.lo).min().unwrap_or(lines.len()).min(E::head_end(root, &rel)?);
    let mut hs = 0;
    if lines.first().is_some_and(|l| l.trim_start().starts_with("/*")) {
        if let Some(&(_, _, l2, c2)) = model.comments.iter().find(|c| c.0 == 1) {
            let rest: String = lines.get((l2 - 1).max(0) as usize).copied().unwrap_or("").chars().skip((c2 - 1).max(0) as usize).collect();
            if rest.trim().is_empty() && (l2 as usize) <= he {
                hs = l2 as usize;
            }
        }
    }
    let mut head: Vec<String> = vec![];
    let mut k = hs;
    while k < he {
        if let Some(d) = datas.iter().find(|d| d.lo == k && d.hi <= he) {
            if moving(d) {
                // its definition moves: the new file defines it below
            } else if d.stat {
                s.warnings.push(format!("{rel}:{}: static data {} of the head is copied: each unit has its own", k + 1, d.name));
                head.extend(lines[d.lo..d.hi].iter().map(|l| l.to_string()));
            } else {
                let x = extern_of(&stmt_of(d));
                s.head_externs.push(x.clone());
                head.push(x);
            }
            k = d.hi;
            continue;
        }
        head.push(lines[k].to_string());
        k += 1;
    }
    trim_blank(&mut head);
    let at_inc = head.iter().position(|l| l.trim() == format!("#include \"{unit}.h\""))
        .or_else(|| head.iter().rposition(|l| l.trim_start().starts_with("#include"))).map(|x| x + 1).unwrap_or(0);
    head.insert(at_inc, format!("#include \"{new}.h\""));
    // what both halves declare already: the old head and the unit's header
    let header = read(&p_of(root, &format!("include/{unit}.h")));
    let known = lines[..he].join("\n") + "\n" + &header;
    let decl_of = |c: &Chunk| -> Option<String> {
        model.decls.iter().find_map(|d| match d {
            crate::clang::Decl::F(n, _, ws, _, _, Some(b), _) if *n == c.name && ws.0 == c.def_line => Some(prototype_of(&slice(&lines, *ws, *b), n)),
            _ => None,
        })
    };
    // the declarations between the moved functions the rest of the old file needs (it keeps a copy)
    let mut rest_words = code_words(&(lines[r1..].join("\n") + "\n" + &stay.join("\n")));
    let copies = needed_lines(&lines, &copies, &rest_words, &glue);
    rest_words.extend(code_words(&copies.join("\n")));
    s.copied = copies.len();
    // the moved functions the rest of the old file uses
    for c in &moved {
        if !rest_words.contains(&c.name) || E::declared_in(&known, &c.name) {
            continue;
        }
        if c.stat {
            s.warnings.push(format!("static function {} moves to {new}, the rest of {unit} uses it: {unit} does not compile until it is shared", c.name));
        } else if let Some(p) = decl_of(c) {
            s.protos_old.push(p);
        }
    }
    // the old file's definitions before the region the moved functions use
    let mut moved_words = code_words(&new_body.join("\n"));
    // the declarations between the head and the moved functions (macros, types, externs, prototypes) they need
    let is_data = |i: usize| datas.iter().any(|d| d.lo <= i && i < d.hi);
    let pre: Vec<usize> = (he..r0).filter(|&i| !in_fn(i) && !is_data(i) && !lines[i].trim().is_empty() && !comment_only.contains(&i)).collect();
    let carried = needed_lines(&lines, &pre, &moved_words, &glue);
    moved_words.extend(code_words(&carried.join("\n")));
    // the data definitions outside the region that move (file order)
    let moved_defs: Vec<String> = datas.iter().filter(|d| moving(d) && !(r0 <= d.lo && d.lo < r1))
        .flat_map(|d| lines[d.lo..d.hi].iter().map(|l| l.to_string())).collect();
    moved_words.extend(code_words(&moved_defs.join("\n")));
    for c in kept.iter().filter(|c| c.hi <= r0 || c.lo >= r1) {
        if !moved_words.contains(&c.name) || E::declared_in(&known, &c.name) {
            continue;
        }
        if c.stat {
            s.warnings.push(format!("static function {} stays in {unit}, the moved functions use it: {new} does not link until it is shared", c.name));
        } else if let Some(p) = decl_of(c) {
            s.decls_new.push(p);
        }
    }
    for d in datas.iter().filter(|d| he <= d.lo && (d.hi <= r0 || d.lo >= r1) && !moving(d)) {
        if !d.names.iter().any(|n| moved_words.contains(n)) || d.names.iter().all(|n| E::declared_in(&known, n)) {
            continue;
        }
        if d.stat {
            s.warnings.push(format!("static data {} stays in {unit}, the moved functions use it: {new} does not compile until it is shared", d.name));
        } else {
            s.decls_new.push(extern_of(&stmt_of(d)));
        }
    }
    // the old file: the region out, the copies, the prototypes and the kept lines in its place; a moving
    // definition out (its extern where the rest uses it)
    let old_lines = |from: usize, to: usize| -> Vec<String> {
        let mut v = vec![];
        let mut i = from;
        while i < to {
            if let Some((hi, x)) = old_repl.get(&i) {
                v.extend(x.iter().cloned());
                i = *hi;
                continue;
            }
            v.push(lines[i].to_string());
            i += 1;
        }
        v
    };
    let mut before = old_lines(0, r0);
    while before.last().is_some_and(|l| l.trim().is_empty()) {
        before.pop();
    }
    let mut after = old_lines(r1, lines.len());
    trim_blank(&mut after);
    let mut mid: Vec<String> = vec![];
    if !copies.is_empty() {
        mid.push(format!("/* dcp unit split: the declarations that moved to {new} (copies: drop what {unit} does not use) */"));
        mid.extend(copies);
    }
    if !s.protos_old.is_empty() {
        mid.push(format!("/* dcp unit split: the functions of {new} the rest of {unit} uses */"));
        mid.extend(s.protos_old.iter().cloned());
    }
    mid.extend(stay);
    let parts: Vec<Vec<String>> = [before, mid, after].into_iter().filter(|p| !p.is_empty()).collect();
    s.old_text = parts.iter().map(|p| p.join("\n")).collect::<Vec<_>>().join("\n\n") + "\n";
    // the new file
    trim_blank(&mut new_body);
    s.new_head = head.clone();
    let mut parts: Vec<String> = vec![lead.trim_end_matches('\n').to_string() + "\n" + &head.join("\n")];
    s.carried = carried.len();
    if !carried.is_empty() {
        parts.push(format!("/* dcp unit split: the declarations of {unit} before the moved functions */\n{}", carried.join("\n")));
    }
    if !s.decls_new.is_empty() {
        parts.push(format!("/* dcp unit split: the definitions of {unit} the functions of {new} use */\n{}", s.decls_new.join("\n")));
    }
    if !moved_defs.is_empty() {
        parts.push(moved_defs.join("\n"));
    }
    parts.push(new_body.join("\n"));
    s.new_parts = parts[1..].to_vec();
    s.new_text = parts.join("\n\n") + "\n";
    // placeholders of the moved functions: <unit>_<addr> -> <new>_<addr>
    let pre = format!("{}_", E::c_name(unit));
    for c in &moved {
        if let Some(tail) = c.name.strip_prefix(&pre).filter(|t| HEX_TAIL.is_match(t)) {
            s.renamed.insert(c.name.clone(), format!("{}_{tail}", E::c_name(new)));
        }
    }
    Ok(s)
}

/// The identifiers of a C text outside its comments and literals, with their counts.
fn word_counts(text: &str) -> HashMap<String, usize> {
    let code = CODE_TOKEN.replace_all(text, " ");
    let mut m: HashMap<String, usize> = HashMap::new();
    for w in WORD.find_iter(&code) {
        *m.entry(w.as_str().to_string()).or_default() += 1;
    }
    m
}

static DEFINE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"^\s*#\s*define\s+([A-Za-z_]\w*)").unwrap());

/// The declaration lines (indices into `lines`, in order) a text with the identifiers `words` needs: every
/// declaration but a macro definition, which it needs when it or a needed macro uses the macro's name. A line
/// `glue` ties to an earlier one (the continuation of a comment that line opens) goes with it.
fn needed_lines(lines: &[&str], idx: &[usize], words: &HashSet<String>, glue: &HashMap<usize, usize>) -> Vec<String> {
    // the items: a preprocessor line with its continuation lines, else one line
    let mut items: Vec<(Option<String>, Vec<usize>)> = vec![];
    let mut k = 0;
    while k < idx.len() {
        let mut it = vec![idx[k]];
        if lines[idx[k]].trim_start().starts_with('#') {
            while lines[*it.last().unwrap()].trim_end().ends_with('\\') && k + 1 < idx.len() && idx[k + 1] == it.last().unwrap() + 1 {
                k += 1;
                it.push(idx[k]);
            }
        }
        while k + 1 < idx.len() && glue.get(&idx[k + 1]).is_some_and(|o| it.contains(o) || it.iter().any(|&x| glue.get(&x) == Some(o))) {
            k += 1;
            it.push(idx[k]);
        }
        items.push((DEFINE.captures(lines[it[0]]).map(|c| c[1].to_string()), it));
        k += 1;
    }
    let mut words = words.clone();
    let mut keep: Vec<bool> = items.iter().map(|x| x.0.is_none()).collect();
    loop {
        let mut more = false;
        for (j, (name, it)) in items.iter().enumerate() {
            if !keep[j] && name.as_ref().is_some_and(|n| words.contains(n)) {
                keep[j] = true;
                more = true;
                words.extend(code_words(&it.iter().map(|&i| lines[i]).collect::<Vec<_>>().join("\n")));
            }
        }
        if !more {
            break;
        }
    }
    items.iter().zip(keep).filter(|x| x.1).flat_map(|x| x.0 .1.iter().map(|&i| lines[i].to_string())).collect()
}

/// The grade order (draft < shape < byte; none lowest).
fn grade_rank(c: Option<&str>) -> usize {
    match c {
        Some("byte") => 3,
        Some("shape") => 2,
        Some("draft") => 1,
        _ => 0,
    }
}

/// `dcp unit split UNIT AT NEW` (unit_split): the functions of UNIT at or above AT into the new unit NEW (src/NEW.c,
/// include/NEW.h, its boundaries: NEW starts at AT, UNIT's declared end becomes NEW's), built before and after with
/// the grades compared as `dcp unit join` does; a dry run prints what would move. `build()` builds and refreshes.
#[allow(clippy::too_many_arguments)]
pub fn unit_split(p: &crate::project::Project, unit: &str, at: &str, new: &str, by: Option<String>, why: Option<String>, dry_run: bool,
                  build: &mut dyn FnMut() -> Result<()>) -> Result<(Vec<String>, Option<String>, i32)> {
    let root = p.root.to_string_lossy().into_owned();
    let fail = |m: String| -> Result<(Vec<String>, Option<String>, i32)> { Ok((vec![], Some(m), 1)) };
    let at = match crate::cliread::parse_addr(at) {
        Ok(a) => a,
        Err(e) => return fail(e.to_string()),
    };
    if !UNIT.is_match(new) || !E::IDENT.is_match(&E::c_name(new)) {
        return fail(format!("{} is not a unit name", crate::decl::quote_str(new)));
    }
    let db = p.store_path();
    crate::storedb::st_open(&db)?;
    let view = crate::layoutview::View::load(&db, &p.target.path)?;
    let Some(u) = view.units.iter().find(|u| u.tu == unit) else {
        let names: Vec<&str> = view.units.iter().map(|u| u.tu.as_str()).collect();
        return fail(format!("no unit {unit} (units: {})", if names.is_empty() { "none".to_string() } else { names.join(", ") }));
    };
    let (lo, hi) = (u.lo, u.hi);
    if view.units.iter().any(|u| u.tu == new) || exists(&root, &format!("src/{new}.c")) || exists(&root, &format!("include/{new}.h")) {
        return fail(format!("unit {new} exists (a unit, src/{new}.c or include/{new}.h)"));
    }
    if !(lo < at && at < hi) {
        return fail(format!("{at:#x} does not lie inside unit {unit} {lo:#010x}..{hi:#010x} above its start"));
    }
    let by = by.unwrap_or_else(|| "guess".into());
    let why = why.unwrap_or_else(|| format!("split from {unit} at {at:#x}")).split_whitespace().collect::<Vec<_>>().join(" ");
    // the --why text is the boundary's reason (decl/text.dcl) and the names log's: the source comments say what the
    // unit is, not why it was cut (a reason's `*/` would end the comment, too)
    let lead = format!("/* {new}: the functions {at:#010x}..{hi:#010x} of the original, split from {unit}\n   unit {at:#010x}..{hi:#010x}, \
                        named by {by}; boundaries in decl/text.dcl */");
    let img = crate::image(&p.target.path)?;
    let section = |a: i64| -> Option<String> {
        let sec = img.section_of(u32::try_from(a).ok()?)?;
        Some(if img.off(a as u32).is_none() { "bss".into() } else if sec.name.starts_with(".rdata") { "rdata".into() } else { "data".into() })
    };
    let sp = match plan_split(&root, unit, at, new, &p.target_name, &lead, &section, false) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    let n_lines = |t: &str| t.matches('\n').count() as i64;
    let mut out = vec![record(&[("split", s(unit)), ("at", Tok::I(at)), ("new", s(new)), ("moved", Tok::I(sp.moved.len() as i64)),
                                ("kept", Tok::I(sp.kept as i64)), ("data_moved", Tok::I(sp.data_moved.len() as i64)), ("data_kept", Tok::I(sp.data.len() as i64)),
                                ("old_lines", Tok::I(n_lines(&sp.old_text))), ("new_lines", Tok::I(n_lines(&sp.new_text)))])];
    for (a, n, l, h) in &sp.moved {
        out.push(format!("  {}", record(&[("fn", Tok::I(*a)), ("name", s(n.clone())), ("lines", s(format!("{}..{}", l + 1, h)))])));
    }
    for (n, l, h, why) in &sp.data_moved {
        out.push(format!("  {}  (moves to {new}: {why})", record(&[("data", s(n.clone())), ("lines", s(format!("{}..{}", l + 1, h)))])));
    }
    for (n, l, h) in &sp.data {
        out.push(format!("  {}  (stays in {unit}: neither its uses nor the data layout give it to {new}; {new} declares it extern)",
                         record(&[("data", s(n.clone())), ("lines", s(format!("{}..{}", l + 1, h)))])));
    }
    if sp.carried > 0 {
        out.push(format!("  {new} copies {} declaration line(s) of {unit} before the moved functions (macros it uses, types, externs, prototypes)", sp.carried));
    }
    if sp.copied > 0 {
        out.push(format!("  {unit} keeps a copy of {} declaration line(s) between the moved functions", sp.copied));
    }
    for x in &sp.protos_old {
        out.push(format!("  {unit} declares  {x}"));
    }
    for x in sp.decls_new.iter().chain(&sp.head_externs) {
        out.push(format!("  {new} declares  {x}"));
    }
    for (o, n) in &sp.renamed {
        out.push(format!("  rename {o} -> {n}"));
    }
    out.extend(sp.notes.iter().map(|n| format!("  note: {n}")));
    out.extend(sp.warnings.iter().map(|w| format!("  warning: {w}")));
    // the boundary lines: UNIT's declared end becomes NEW's; UNIT ends (when it had an end) and NEW starts at AT
    let unit_end = view.bounds.iter().find(|b| b.2 == unit && b.1 == "end").map(|b| b.0);
    let mk = |tu: &str, side: &str, with_by: bool| {
        let mut keys = vec![("tu".to_string(), KeyVal::Str(tu.into()))];
        if with_by {
            keys.insert(0, ("by".into(), KeyVal::Str(by.clone())));
        }
        // the reason once, on NEW's start; UNIT's end points there
        let reason = if with_by { why.clone() } else { format!("{new} starts here (dcp unit split)") };
        Decl { lo: at, hi: at + 1, kind: "boundary".into(), words: vec![side.to_string()], keys, reason, file: String::new(), line: 0 }
    };
    let mut adds = vec![mk(new, "start", true)];
    if let Some(e) = unit_end {
        adds.insert(0, mk(unit, "end", false));
        out.push(format!("  decl  {e:#010x} boundary end tu={unit}  =>  tu={new}"));
    }
    out.extend(adds.iter().map(|d| format!("  decl  + {}", d.text())));
    if dry_run {
        out.push("dry run: nothing written".into());
        return Ok((out, None, 0));
    }
    build()?;
    let (before, err_before) = byte_state(&db)?;
    let write_all = || -> Result<(), String> {
        // the placeholders renamed in the texts first: a second write of a file in the same clock tick with the same
        // size (a_<addr> -> b_<addr>) would keep the read memo's stamp, so the next scan would see the first text
        E::write(&p_of(&root, &format!("src/{unit}.c")), &E::replace_words(&sp.old_text, &sp.renamed, None).0)?;
        E::write(&p_of(&root, &format!("src/{new}.c")), &E::replace_words(&sp.new_text, &sp.renamed, None).0)?;
        E::write(&p_of(&root, &format!("include/{new}.h")), &E::header_text(new, &format!("split from {unit}")))?;
        rewrite_boundaries(&root, &mut |d: &Decl| {
            if tu_of(d) == Some(unit) && d.words.first().map(|w| w.as_str()) == Some("end") && Some(d.lo) == unit_end {
                Some(replace_keys(d, &[("tu", new)]))
            } else {
                Some(d.clone())
            }
        })?;
        let path = p.root.join("decl").join("text.dcl");
        for d in &adds {
            crate::decl::insert(&path, d).map_err(|e| e.to_string())?;
        }
        if !sp.renamed.is_empty() {
            E::rename_words(&root, &sp.renamed, false, None)?;
            E::log_names(&root, &placeholder_events(&sp.renamed), &format!("split: {why}"))?;
        }
        crate::fsmemo::new_epoch();
        Ok(())
    };
    if let Err(e) = write_all() {
        return Ok((out, Some(e), 1));
    }
    out.push(format!("wrote src/{unit}.c, src/{new}.c, include/{new}.h, decl/text.dcl"));
    build()?;
    let (after, err_after) = byte_state(&db)?;
    let keys: std::collections::BTreeSet<i64> = before.keys().chain(after.keys()).copied().collect();
    let get = |m: &BTreeMap<i64, Option<String>>, k: &i64| m.get(k).cloned().flatten();
    let changed: Vec<i64> = keys.into_iter().filter(|k| get(&before, k) != get(&after, k)).collect();
    let fell = changed.iter().filter(|k| grade_rank(get(&after, k).as_deref()) < grade_rank(get(&before, k).as_deref())).count();
    let byte = |m: &BTreeMap<i64, Option<String>>| m.values().filter(|c| c.as_deref() == Some("byte")).count() as i64;
    out.push(record(&[("split", s(unit)), ("new", s(new)), ("byte_before", Tok::I(byte(&before))), ("byte_after", Tok::I(byte(&after))),
                      ("grades_changed", Tok::I(changed.len() as i64)), ("grades_fell", Tok::I(fell as i64)),
                      ("errors_before", Tok::I(err_before as i64)), ("errors_after", Tok::I(err_after as i64))]));
    let ot = |x: Option<String>| x.map(Tok::S).unwrap_or(Tok::No);
    for k in &changed {
        out.push(format!("  {}", record(&[("fn", Tok::I(*k)), ("before", ot(get(&before, k))), ("after", ot(get(&after, k)))])));
    }
    // dcp unit join is no exact inverse (NEW's head lines go into UNIT's head, its functions after UNIT's tail): git is
    let undo = format!("undo: git checkout -- . && git clean -fd src include  (dcp unit join {unit} {new} merges for good, not back to this text)");
    if (fell > 0 || err_after > err_before) && !sp.warnings.is_empty() {
        // what the split could not share (the warnings) breaks the build: no evidence about the boundary
        out.push(format!("the split lowered grades or added errors, but it left unshared what the warnings above name: share or move that \
                          by hand and rebuild before reading the grades as evidence about a boundary at {at:#x}; {undo}"));
        return Ok((out, None, 1));
    }
    if fell > 0 || err_after > err_before {
        out.push(format!("the split lowered grades or added errors: evidence against a boundary at {at:#x}; {undo}"));
        return Ok((out, None, 1));
    }
    out.push(undo);
    Ok((out, None, 0))
}

// ------------------------------------------------------------------------------------------------ move

/// The declared boundary lines of decl/*.dcl that `pick` takes.
fn moved_bounds(root: &str, pick: &dyn Fn(&Decl) -> bool) -> Vec<Decl> {
    let mut out = vec![];
    for path in crate::decl::files(root) {
        for raw in E::splitlines(&read(&path.to_string_lossy())) {
            let st = raw.trim();
            if st.is_empty() || st.starts_with('#') {
                continue;
            }
            if let Ok(d) = crate::decl::parse_line(st, "", 0) {
                if d.kind == "boundary" && pick(&d) {
                    out.push(d);
                }
            }
        }
    }
    out
}

/// `dcp unit move FROM AT TO`: move the boundary between two neighbouring units. TO directly after FROM: FROM's
/// functions at or above AT go to the front of TO; TO directly before FROM: FROM's functions below AT go to the end
/// of TO. The texts as dcp unit split plans them (plan_split: the data the moved functions own, declarations,
/// prototypes); the moved part goes after TO's head (TO after FROM) or after TO's last function (TO before FROM), the
/// lines of FROM's head TO's head lacks are added to it; the boundary lines between the two move to AT,
/// placeholders `FROM_<addr>` of the moved functions become `TO_<addr>`. `build()` builds and refreshes the target.
pub fn unit_move(p: &crate::project::Project, from: &str, at: &str, to: &str, why: &str, dry_run: bool,
                 build: &mut dyn FnMut() -> Result<()>) -> Result<(Vec<String>, Option<String>, i32)> {
    let root = p.root.to_string_lossy().into_owned();
    let fail = |m: String| -> Result<(Vec<String>, Option<String>, i32)> { Ok((vec![], Some(m), 1)) };
    let at = match crate::cliread::parse_addr(at) {
        Ok(a) => a,
        Err(e) => return fail(e.to_string()),
    };
    let db = p.store_path();
    crate::storedb::st_open(&db)?;
    let view = crate::layoutview::View::load(&db, &p.target.path)?;
    let names: Vec<&str> = view.units.iter().map(|u| u.tu.as_str()).collect();
    let (Some(i_from), Some(i_to)) = (names.iter().position(|n| *n == from), names.iter().position(|n| *n == to)) else {
        let m = if names.contains(&from) { to } else { from };
        return fail(format!("no unit {m} (units: {})", if names.is_empty() { "none".to_string() } else { names.join(", ") }));
    };
    let front = if i_to + 1 == i_from {
        true
    } else if i_from + 1 == i_to {
        false
    } else {
        return fail(format!("{to} is no neighbour of {from} (a move shifts the boundary between two neighbouring units)"));
    };
    let u = &view.units[i_from];
    if !(u.lo < at && at < u.hi) {
        return fail(format!("{at:#x} does not lie inside unit {from} {:#010x}..{:#010x} above its start", u.lo, u.hi));
    }
    if !exists(&root, &format!("src/{to}.c")) {
        return fail(format!("unit {to} has no file src/{to}.c"));
    }
    let img = crate::image(&p.target.path)?;
    let section = |a: i64| -> Option<String> {
        let sec = img.section_of(u32::try_from(a).ok()?)?;
        Some(if img.off(a as u32).is_none() { "bss".into() } else if sec.name.starts_with(".rdata") { "rdata".into() } else { "data".into() })
    };
    let sp = match plan_split(&root, from, at, to, &p.target_name, "", &section, front) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    // TO's file: its head plus the lines of FROM's head it lacks, then the moved part before (TO after FROM) or
    // after (TO before FROM) its functions
    let rel_to = format!("src/{to}.c");
    let text_to = read(&p_of(&root, &rel_to));
    let lines_to: Vec<&str> = text_to.trim_end_matches('\n').split('\n').collect();
    let et = E::head_end(&root, &rel_to)?.min(lines_to.len());
    let head_to = lines_to[..et].join("\n") + "\n";
    let head_new = merge_lines(&head_to, &sp.new_head.join("\n"), &HashSet::new());
    let added = E::splitlines(&head_new).len().saturating_sub(E::splitlines(&head_to).len());
    let body_to = lines_to[et..].join("\n").trim_matches('\n').to_string();
    let moved_part = sp.new_parts.join("\n\n").trim_matches('\n').to_string();
    let bodies: Vec<&str> = if front { [body_to.as_str(), moved_part.as_str()] } else { [moved_part.as_str(), body_to.as_str()] }
        .into_iter().filter(|x| !x.is_empty()).collect();
    let new_to = head_new.trim_end_matches('\n').to_string() + "\n\n" + &bodies.join("\n\n") + "\n";
    // the boundary lines between the two units: TO's start and FROM's end (TO after FROM), FROM's start and TO's
    // end (TO before FROM)
    let (first, second) = if front { (to, from) } else { (from, to) };
    let old_at = if front { u.lo } else { u.hi };
    let pick = |d: &Decl| {
        let w = d.words.first().map(|w| w.as_str());
        d.lo == old_at && ((tu_of(d) == Some(second) && w == Some("start")) || (tu_of(d) == Some(first) && w == Some("end")))
    };
    let shifted = moved_bounds(&root, &pick);
    if !shifted.iter().any(|d| tu_of(d) == Some(second)) {
        return fail(format!("no boundary start line of {second} at {old_at:#x} in decl/*.dcl (the boundary to move)"));
    }
    let shift = |d: &Decl| -> Decl {
        let mut n = d.clone();
        n.lo = at;
        n.hi = at + 1;
        // the move's reason first, the line's evidence kept after it
        n.reason = if d.reason.is_empty() { why.to_string() } else { format!("{why}; moved from {old_at:#x} by dcp unit move, before: {}", d.reason) };
        n
    };
    let n_lines = |t: &str| t.matches('\n').count() as i64;
    let mut out = vec![record(&[("move", s(from)), ("at", Tok::I(at)), ("to", s(to)), ("side", s(if front { "front" } else { "tail" })),
                                ("moved", Tok::I(sp.moved.len() as i64)), ("kept", Tok::I(sp.kept as i64)),
                                ("data_moved", Tok::I(sp.data_moved.len() as i64)), ("data_kept", Tok::I(sp.data.len() as i64)),
                                ("from_lines", Tok::I(n_lines(&sp.old_text))), ("to_lines", Tok::I(n_lines(&new_to)))])];
    for (a, n, l, h) in &sp.moved {
        out.push(format!("  {}", record(&[("fn", Tok::I(*a)), ("name", s(n.clone())), ("lines", s(format!("{}..{}", l + 1, h)))])));
    }
    for (n, l, h, why) in &sp.data_moved {
        out.push(format!("  {}  (moves to {to}: {why})", record(&[("data", s(n.clone())), ("lines", s(format!("{}..{}", l + 1, h)))])));
    }
    for (n, l, h) in &sp.data {
        out.push(format!("  {}  (stays in {from}: neither its uses nor the data layout give it to {to}; {to} declares it extern)",
                         record(&[("data", s(n.clone())), ("lines", s(format!("{}..{}", l + 1, h)))])));
    }
    if added > 0 {
        out.push(format!("  {to}'s head takes {added} line(s) of {from}'s head it lacks (includes, macros, types, externs: trim what it does not use)"));
    }
    if sp.carried > 0 {
        out.push(format!("  {to} copies {} declaration line(s) of {from} before the moved functions", sp.carried));
    }
    if sp.copied > 0 {
        out.push(format!("  {from} keeps a copy of {} declaration line(s) between the moved functions", sp.copied));
    }
    for x in &sp.protos_old {
        out.push(format!("  {from} declares  {x}"));
    }
    for x in &sp.decls_new {
        out.push(format!("  {to} declares  {x}"));
    }
    for (o, n) in &sp.renamed {
        out.push(format!("  rename {o} -> {n}"));
    }
    out.extend(sp.notes.iter().map(|n| format!("  note: {n}")));
    out.extend(sp.warnings.iter().map(|w| format!("  warning: {w}")));
    out.push(format!("  note: the moved functions' prototypes stay in include/{from}.h (move them to include/{to}.h by hand)"));
    for d in &shifted {
        out.push(format!("  decl  {}  =>  {}", d.text(), shift(d).text()));
    }
    if dry_run {
        out.push("dry run: nothing written".into());
        return Ok((out, None, 0));
    }
    build()?;
    let (before, err_before) = byte_state(&db)?;
    let write_all = || -> Result<(), String> {
        // the placeholders renamed in the texts first (as dcp unit split: one write per file)
        E::write(&p_of(&root, &format!("src/{from}.c")), &E::replace_words(&sp.old_text, &sp.renamed, None).0)?;
        E::write(&p_of(&root, &rel_to), &E::replace_words(&new_to, &sp.renamed, None).0)?;
        rewrite_boundaries(&root, &mut |d: &Decl| Some(if pick(d) { shift(d) } else { d.clone() }))?;
        if !sp.renamed.is_empty() {
            E::rename_words(&root, &sp.renamed, false, None)?;
            E::log_names(&root, &placeholder_events(&sp.renamed), &format!("move: {why}"))?;
        }
        crate::fsmemo::new_epoch();
        Ok(())
    };
    if let Err(e) = write_all() {
        return Ok((out, Some(e), 1));
    }
    out.push(format!("wrote src/{from}.c, src/{to}.c, decl/text.dcl"));
    build()?;
    let (after, err_after) = byte_state(&db)?;
    let keys: std::collections::BTreeSet<i64> = before.keys().chain(after.keys()).copied().collect();
    let get = |m: &BTreeMap<i64, Option<String>>, k: &i64| m.get(k).cloned().flatten();
    let changed: Vec<i64> = keys.into_iter().filter(|k| get(&before, k) != get(&after, k)).collect();
    let fell = changed.iter().filter(|k| grade_rank(get(&after, k).as_deref()) < grade_rank(get(&before, k).as_deref())).count();
    let byte = |m: &BTreeMap<i64, Option<String>>| m.values().filter(|c| c.as_deref() == Some("byte")).count() as i64;
    out.push(record(&[("move", s(from)), ("to", s(to)), ("byte_before", Tok::I(byte(&before))), ("byte_after", Tok::I(byte(&after))),
                      ("grades_changed", Tok::I(changed.len() as i64)), ("grades_fell", Tok::I(fell as i64)),
                      ("errors_before", Tok::I(err_before as i64)), ("errors_after", Tok::I(err_after as i64))]));
    let ot = |x: Option<String>| x.map(Tok::S).unwrap_or(Tok::No);
    for k in &changed {
        out.push(format!("  {}", record(&[("fn", Tok::I(*k)), ("before", ot(get(&before, k))), ("after", ot(get(&after, k)))])));
    }
    let undo = "undo: git checkout -- . && git clean -fd src include";
    if fell > 0 || err_after > err_before {
        let left = if sp.warnings.is_empty() { String::new() } else { " (or what the warnings above name is left unshared: share it and rebuild first)".into() };
        out.push(format!("the move lowered grades or added errors: evidence against a boundary at {at:#x}{left}; {undo}"));
        return Ok((out, None, 1));
    }
    out.push(undo.into());
    Ok((out, None, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_declarations() {
        assert_eq!(extern_of("int a = 1, b[2] = { 1, 2 }; /* x */"), "extern int a, b[2];");
        assert_eq!(extern_of("char *s = \"a;=b\";"), "extern char *s;");
        assert_eq!(extern_of("int (*f[2])(int, int) = { g, h };"), "extern int (*f[2])(int, int);");
        assert_eq!(extern_of("unsigned short\n   tbl[3];"), "extern unsigned short tbl[3];");
        assert_eq!(prototype_of("static int\nf(int a,\n  char *b)\n", "f"), "static int f(int a, char *b);");
        assert_eq!(prototype_of("int f(a, b)\nint a;\nchar *b;\n", "f"), "int f();");
        let lines = ["#define A(x) B(x)", "#define B(x) \\", "  (x)", "#define C 1", "typedef int T;"];
        let words: HashSet<String> = ["A".to_string()].into_iter().collect();
        assert_eq!(needed_lines(&lines, &[0, 1, 2, 3, 4], &words, &HashMap::new()), vec!["#define A(x) B(x)", "#define B(x) \\", "  (x)", "typedef int T;"]);
    }
}
