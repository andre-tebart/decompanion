//! `dcp rename OLD NEW [OLD NEW..] [--from FILE] --why WHY`: rename identifiers: every whole-word occurrence in src/
//! and include/ (code and comments; string literals and #include lines are left alone), the `name` declarations of
//! decl/*.dcl. Several pairs are renamed in one call: one refresh, one rebuild, one check for all of them, and nothing
//! is written unless every pair passes (a refusal record per failing pair). OLD is a C identifier or an address
//! (`0xADDR`): the ledger's name of the address. Refused (an error record, exit 1, nothing written) when OLD names nothing renamable: no such address
//! name, OLD occurs nowhere, or only inside string literals / #include lines; when NEW is no C identifier or equals
//! OLD; when NEW occurs already and is not OLD's own (the ledger names another address NEW, or OLD has no address):
//! NEW written by hand in part for OLD's address is completed; when the pairs of a call chain or repeat. A success
//! prints per pair the rename record (files, replacements, decl lines) and one line per changed file, with its first
//! changed lines (`LINE: text` as it reads now, 4 per file, `(+N more line(s))`), and every line where OLD stood inside
//! a comment (`comments:`, for review: prose may argue from the old name). names.log
//! records each event, with the address the ledger knows for OLD, all of a call's events in one append. The write is
//! all or nothing: a failed write of a source, a decl file or names.log puts every file back as it read before
//! (an error, exit 1). The rename done by hand already (OLD nowhere,
//! NEW the ledger's name of OLD's address) is only recorded. The views of OLD (OLD with an upper-case view suffix)
//! keep their names: a note lists them.
//!
//! A symbol with an address is renamed where clang finds it, not where a local, a parameter or a field of the same
//! name stands (local_refs); a name without one (a type, a field) by its words.
//!
//! A rename the check after its rebuild finds new errors with (NEW declared already with another type, a placeholder
//! of no start) is refused like any other: every file, names.log and the tu rows are put back and the tree rebuilt.
//!
//! The rebuild after the write compiles only what the rename changed: a unit that reads a renamed file and whose
//! preprocessed text (CL /E, before and after the write) differs only by the names keeps its object with the symbols
//! renamed (compile.rs rename_after); a unit where a name is stringified, pasted or tested by #ifdef compiles.

use crate::error::{Error, Result};
use crate::cliread::{record, Tok};
use crate::edit::{self as E, Skip};
use crate::names::Names;
use crate::project::{py_path, Project};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;

fn err(e: impl std::fmt::Display) -> Error {
    Error::runtime(e.to_string())
}

fn s(x: impl Into<String>) -> Tok {
    Tok::S(x.into())
}

fn oi(x: Option<i64>) -> Tok {
    x.map(Tok::I).unwrap_or(Tok::No)
}

/// The `name OLD` of a declaration line: preceded by ` name `, followed by a space or the line's end.
fn decl_name(old: &str) -> fancy_regex::Regex {
    fancy_regex::Regex::new(&format!(r"(?m)(?<= name ){}(?= |$)", regex::escape(old))).unwrap()
}

fn decl_files(root: &str) -> Vec<std::path::PathBuf> {
    crate::decl::files(root)
}

/// rel -> {(line, column)} of the occurrences of `names` the front end finds referring to a declaration not at file
/// scope (a local, a parameter, a field, a label), in every project file that holds one of the names (as the default
/// target's compile sees it): what a rename of a file-scope symbol leaves alone. One parse per such file, not per
/// unit that reads it: each unit file that holds a name, and for a header that holds one, the first unit that
/// includes it; a unit's parse covers the headers it reads.
pub fn local_refs(root: &str, names: &[String]) -> Result<Skip, String> {
    let front = crate::frontend::Front::of(root)?;
    let defines = front.targets[0].1.clone();
    crate::frontend::scan(root, None)?; // every unit's dependencies (its last parse's)
    let src = py_path(&format!("{root}/src"));
    let files: Vec<(String, String)> = if Path::new(&src).exists() { crate::fsmemo::walk(&src, &["*.c".into()]) } else { vec![] };
    let pat = regex::Regex::new(&format!(r"\b(?:{})\b", names.iter().map(|n| regex::escape(n)).collect::<Vec<_>>().join("|"))).unwrap();
    let mut holds: HashMap<String, bool> = HashMap::new();
    let mut held = |p: &str| -> bool {
        *holds.entry(p.to_string()).or_insert_with(|| {
            crate::fsmemo::read_text(p).map(|t| names.iter().any(|n| t.contains(n.as_str())) && pat.is_match(&t)).unwrap_or(false)
        })
    };
    let norm = |d: &str| -> String {
        let p = if Path::new(d).is_absolute() { d.to_string() } else { std::env::current_dir().map(|c| c.join(d).to_string_lossy().into_owned()).unwrap_or(d.into()) };
        py_path(&p).to_lowercase()
    };
    let under = {
        let r = std::fs::canonicalize(root).map(|c| c.to_string_lossy().trim_start_matches(r"\\?\").to_string()).unwrap_or(root.into());
        norm(&r) + "\\"
    };
    let mut sorted = files;
    sorted.sort_by_key(|t| t.0.to_lowercase());
    // (unit file, it holds a name, the headers below root it reads that do)
    let mut units: Vec<(String, bool, BTreeSet<String>)> = vec![];
    for (rel, p) in &sorted {
        if rel.contains('/') || rel.contains('\\') {
            continue;
        }
        let deps: BTreeSet<String> = crate::frontend::front_last_deps(p).iter().map(|d| norm(d)).collect();
        let own = held(p);
        let mine: BTreeSet<String> = deps.into_iter().filter(|d| d.starts_with(&under) && held(d)).collect();
        units.push((p.clone(), own, mine));
    }
    let (mut covered, mut pick): (BTreeSet<String>, HashSet<String>) = (BTreeSet::new(), HashSet::new());
    for (p, own, deps) in &units {
        if *own {
            pick.insert(p.clone());
            covered.extend(deps.iter().cloned());
        }
    }
    for (p, own, deps) in &units {
        if !*own && deps.iter().any(|d| !covered.contains(d)) {
            pick.insert(p.clone());
            covered.extend(deps.iter().cloned());
        }
    }
    let jobs: Vec<&String> = units.iter().map(|u| &u.0).filter(|p| pick.contains(*p)).collect();
    let args = front.args(&defines);
    // one file to parse (a rename inside one unit): its parse is the live unit the scan's parse of the edit keeps
    // (frontend.rs with_parse), so neither parses it from scratch
    let keep = jobs.len() == 1;
    let found = crate::compile_threads(&jobs, |p| -> Result<Vec<(String, Vec<(usize, usize)>)>, String> {
        let text = crate::fsmemo::read_text(p).map_err(|e| format!("{p}: {e}"))?;
        crate::frontend::with_parse(p, &args, &text, keep, |u| u.refs(root, &text, names.to_vec()).map_err(|e| e.to_string()))
    });
    let mut out: Skip = HashMap::new();
    for r in found {
        for (rel, xs) in r? {
            out.entry(rel).or_default().extend(xs.into_iter().map(|(l, c)| (l as i64, c as i64)));
        }
    }
    Ok(out)
}

/// The (OLD, NEW, why) of a rename call: the OLD NEW pairs of the command line with --why, then the lines of
/// --from FILE (`OLD NEW [why]`, a line without a why takes --why; blank lines and `#` lines skipped); a message
/// instead when the call is malformed. With them: the first OLD that is an address.
#[allow(clippy::type_complexity)]
pub fn rename_pairs(words: Vec<String>, from_file: Option<String>, why: Option<String>)
    -> (Option<String>, Vec<(String, String, String)>, Option<String>) {
    match pairs_of(words, from_file, why) {
        Ok((pairs, first)) => (None, pairs, first),
        Err(e) => (Some(e), vec![], None),
    }
}

#[allow(clippy::type_complexity)]
fn pairs_of(words: Vec<String>, from_file: Option<String>, why: Option<String>) -> Result<(Vec<(String, String, String)>, Option<String>), String> {
    if words.len() % 2 == 1 {
        return Err(format!("OLD NEW pairs expected, got {} word(s): {}", words.len(), words.join(" ")));
    }
    let mut pairs: Vec<(String, String, Option<String>)> = words.chunks(2).map(|w| (w[0].clone(), w[1].clone(), why.clone())).collect();
    if let Some(f) = from_file {
        let text = std::fs::read_to_string(&f).map_err(|e| format!("--from {f}: {e}"))?;
        for (n, line) in E::splitlines(&text.replace("\r\n", "\n")).iter().enumerate() {
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            let fs: Vec<String> = {
                // str.split(None, 2): runs of white space separate, the third part keeps its inner spaces
                let mut parts = vec![];
                let mut rest = line.trim_start();
                for _ in 0..2 {
                    match rest.find(char::is_whitespace) {
                        Some(i) => {
                            parts.push(rest[..i].to_string());
                            rest = rest[i..].trim_start();
                        }
                        None => {
                            if !rest.is_empty() {
                                parts.push(rest.to_string());
                            }
                            rest = "";
                            break;
                        }
                    }
                }
                if !rest.trim_end().is_empty() {
                    parts.push(rest.trim_end().to_string());
                }
                parts
            };
            if fs.len() < 2 {
                return Err(format!("--from {f}:{}: `OLD NEW [why]` expected", n + 1));
            }
            let w = if fs.len() > 2 { Some(fs[2].trim().to_string()) } else { why.clone() };
            if w.as_deref().is_none_or(|w| w.is_empty()) {
                return Err(format!("--from {f}:{}: no why (give one on the line or --why)", n + 1));
            }
            pairs.push((fs[0].clone(), fs[1].clone(), w));
        }
    }
    if pairs.is_empty() {
        return Err("nothing to rename: give OLD NEW (or --from FILE)".into());
    }
    if pairs.iter().any(|p| p.2.is_none()) {
        return Err("--why is required (or a why on each --from line)".into());
    }
    let is_addr = |o: &str| o.trim().to_lowercase().starts_with("0x");
    let first = pairs.iter().find(|p| is_addr(&p.0)).map(|p| p.0.trim().to_string());
    Ok((pairs.into_iter().map(|(o, n, w)| (o, n, w.unwrap())).collect(), first))
}

/// One pair of a rename call, checked and not yet written.
struct Plan {
    old: String,
    new: String,
    why: String,
    a: Option<i64>,
    kind: &'static str,
    decls: Vec<String>,
    recorded: bool,
    used: Vec<(String, i64)>,
    skip: Option<Skip>,
    files: BTreeMap<String, usize>,
    decl_lines: usize,
    lines: BTreeMap<String, Vec<(usize, String)>>, // file -> (line, its text after the write) of each changed line
    comments: Vec<(String, usize, String)>,        // (file, line, its text after the write) of each replacement in a comment
}

impl Plan {
    fn exact(&self) -> bool {
        self.a.is_some()
    }
}

type Refusal = (String, String, String);

/// The changed lines printed per file of a pair.
const LINES: usize = 4;

/// The lines of comment replacements printed per pair.
const COMMENT_LINES: usize = 12;

struct Ctx<'a> {
    p: &'a Project,
    root: String,
    names: Names,
    out: Vec<String>,
}

/// One pair checked against the tree as it stands (nothing written): a plan, or (old, new, message) when refused.
fn plan_rename(x: &mut Ctx, old_arg: &str, new: &str, why: &str) -> Result<Result<Plan, Refusal>> {
    let refuse = |o: &str, m: String| Ok(Err((o.to_string(), new.to_string(), m)));
    let addr = old_arg;
    let mut given = None;
    if !E::IDENT.is_match(new) {
        return refuse(old_arg, format!("NEW {} is no C identifier", crate::decl::py_repr(new)));
    }
    let old = if addr.to_lowercase().starts_with("0x") {
        let Ok(a) = crate::cliread::parse_addr(addr) else { return refuse(old_arg, format!("{old_arg} is no address")) };
        let Some(old) = x.names.name_of(a).map(|s| s.to_string()) else {
            return refuse(old_arg, format!("the ledger knows no name of {a:#010x} on target {}", x.p.target_name));
        };
        x.out.push(format!("note: {old_arg} is {old} (the ledger's name on target {})", x.p.target_name));
        given = Some(a);
        old
    } else if !E::IDENT.is_match(old_arg) {
        return refuse(old_arg, format!("OLD {} is neither a C identifier nor an address (0xADDR)", crate::decl::py_repr(old_arg)));
    } else {
        old_arg.to_string()
    };
    if old == new {
        return refuse(&old, format!("OLD and NEW are the same name {old}"));
    }
    let hits = x.names.addrs_of(&old).first().copied();
    let a = given.or(hits).or_else(|| crate::srcscan::placeholder_whole(&old).map(|v| v as i64));
    let mut kind = "ident";
    if let Some(a) = a {
        let sym = x.names.symbol_at(a).cloned();
        let sk = sym.as_ref().and_then(|f| f.s("skind").map(|s| s.to_string()));
        let db = x.p.store_path();
        let starts = crate::with_db(&db, |c| crate::store::claims_of(c, &db, "start", None, |f| f.lo <= a && a < f.hi.max(f.lo + 1)))?;
        let at_start = starts.iter().any(|f| f.lo == a);
        kind = if matches!(sk.as_deref(), Some("func" | "thunk")) && (sym.as_ref().is_some_and(|f| f.lo == a) || at_start) { "func" } else { "data" };
    }
    let pat = decl_name(&old);
    let decls: Vec<String> = decl_files(&x.root).into_iter().map(|p| p.to_string_lossy().into_owned())
        .filter(|p| pat.is_match(&std::fs::read_to_string(p).unwrap_or_default()).unwrap_or(false)).collect();
    let used = E::uses(&x.root, &old);
    let mut plan = Plan { old: old.clone(), new: new.to_string(), why: why.to_string(), a, kind, decls, recorded: false, used, skip: None,
                          files: BTreeMap::new(), decl_lines: 0, lines: BTreeMap::new(), comments: vec![] };
    if plan.used.is_empty() && plan.decls.is_empty() {
        let mine = a.is_some_and(|a| x.names.addrs_of(new).contains(&a));
        if mine {
            plan.recorded = true;
            return Ok(Ok(plan));
        }
        let tail = a.map(|a| format!(" and {new} is not the ledger's name of {a:#x}")).unwrap_or_default();
        return refuse(&old, format!("{old} occurs nowhere in src/, include/ or decl/{tail}"));
    }
    Ok(Ok(plan))
}

/// The checks of the pairs that need the front end, for all pairs at once (one parse per file that holds any of the
/// names): an OLD found only inside string literals or #include lines, a NEW that collides. Sets each plan's skip
/// and files (the dry run's replacements per file). The refusals.
fn check_renames(x: &mut Ctx, plans: &mut [&mut Plan]) -> Result<Vec<Refusal>, String> {
    let exact_used: BTreeSet<String> = plans.iter().filter(|p| p.exact() && !p.used.is_empty()).map(|p| p.old.clone()).collect();
    let new_hit: BTreeSet<String> = plans.iter().filter(|p| p.exact() && !E::code_uses(&x.root, &p.new, None).is_empty()).map(|p| p.new.clone()).collect();
    let names: Vec<String> = exact_used.into_iter().chain(new_hit).collect();
    let skip = if names.is_empty() { Skip::new() } else { local_refs(&x.root, &names)? };
    let mut out = vec![];
    for p in plans.iter_mut() {
        p.skip = (p.exact() && !p.used.is_empty()).then(|| skip.clone());
        p.files = if p.used.is_empty() {
            BTreeMap::new()
        } else {
            E::rename_words(&x.root, &[(p.old.clone(), p.new.clone())].into_iter().collect(), true, p.skip.as_ref())?
        };
        if !p.used.is_empty() && p.files.is_empty() && p.decls.is_empty() {
            let at: Vec<String> = p.used.iter().take(4).map(|(f, l)| format!("{f}:{l}")).collect();
            out.push((p.old.clone(), p.new.clone(), format!("{} occurs only inside string literals or #include lines ({}): nothing to rename (a header \
                                                             file's name is no identifier; edit a string by hand)", p.old, at.join(", "))));
            continue;
        }
        let clash = E::code_uses(&x.root, &p.new, if p.exact() { Some(&skip) } else { None });
        let mut elsewhere: Vec<i64> = x.names.addrs_of(&p.new).to_vec();
        elsewhere.retain(|v| Some(*v) != p.a);
        elsewhere.sort();
        elsewhere.dedup();
        if let Some(c) = clash.first() {
            if p.a.is_none() || !elsewhere.is_empty() {
                let tail = if elsewhere.is_empty() {
                    String::new()
                } else {
                    format!(", the ledger's name at {}", elsewhere.iter().map(|v| format!("{v:#x}")).collect::<Vec<_>>().join(", "))
                };
                out.push((p.old.clone(), p.new.clone(), format!("{} exists already ({}:{}){tail}: refused (a collision)", p.new, c.0, c.1)));
            } else {
                // NEW is OLD's own address's name, written by hand in part
                x.out.push(format!("note: {} occurs already ({}:{}) and names no other address: the rename completes it", p.new, c.0, c.1));
            }
        }
    }
    Ok(out)
}

/// Each line of new that differs from old's, given to the plans whose OLD word old's line holds: (line, text).
fn changed_lines(rel: &str, old: &str, new: &str, plans: &mut [&mut Plan]) {
    let words: Vec<regex::Regex> = plans.iter().map(|p| regex::Regex::new(&format!(r"\b{}\b", regex::escape(&p.old))).unwrap()).collect();
    for (i, (a, b)) in old.lines().zip(new.lines()).enumerate() {
        if a != b {
            for (p, w) in plans.iter_mut().zip(&words) {
                if w.is_match(a) {
                    p.lines.entry(rel.to_string()).or_default().push((i + 1, b.trim().to_string()));
                }
            }
        }
    }
}

/// Write the checked pairs: one pass over src/ and include/ for all of them (the skip positions were taken on the
/// text before any write), then each pair's decl/*.dcl lines. Each plan's changed lines are kept.
fn write_renames(root: &str, plans: &mut [&mut Plan]) -> Result<(), String> {
    let mut skip: Skip = HashMap::new();
    for p in plans.iter() {
        for (f, pos) in p.skip.iter().flatten() {
            skip.entry(f.clone()).or_default().extend(pos.iter().copied());
        }
    }
    let mapping: BTreeMap<String, String> = plans.iter().map(|p| (p.old.clone(), p.new.clone())).collect();
    let files: BTreeSet<String> = plans.iter().flat_map(|p| p.files.keys().cloned()).collect();
    let old: Vec<(String, String)> = files.into_iter().map(|rel| { let t = E::read(&py_path(&format!("{root}/{rel}"))); (rel, t) }).collect();
    E::rename_words(root, &mapping, false, Some(&skip))?;
    for (rel, text) in &old {
        let now = E::read(&py_path(&format!("{root}/{rel}")));
        changed_lines(rel, text, &now, plans);
        // the replacements inside comments, for review: prose may argue from the old name (a match-base report: a
        // note about one object with two names read "txt_Random ... txt_Random" after the rename)
        let now_lines: Vec<&str> = now.lines().collect();
        for p in plans.iter_mut() {
            for l in E::comment_lines(text, &p.old) {
                p.comments.push((rel.clone(), l, now_lines.get(l - 1).map(|x| x.trim().to_string()).unwrap_or_default()));
            }
        }
    }
    for p in plans.iter_mut() {
        p.decl_lines = 0;
        let pat = decl_name(&p.old);
        for path in p.decls.clone() {
            let t = std::fs::read_to_string(&path).map_err(|e| e.to_string())?.replace("\r\n", "\n");
            let k = pat.find_iter(&t).count();
            if k > 0 {
                let new = pat.replace_all(&t, fancy_regex::NoExpand(&p.new)).into_owned();
                E::write(&path, &new)?;
                p.decl_lines += k;
                let rel = Path::new(&path).strip_prefix(root).map(|r| r.to_string_lossy().replace('\\', "/")).unwrap_or(path.clone());
                changed_lines(&rel, &t, &new, std::slice::from_mut(p));
                p.files.insert(rel, k);
            }
        }
    }
    Ok(())
}

fn errors_of(db: &str) -> Result<Vec<(String, String, i64, String)>> {
    Ok(crate::storedb::st_findings(db, None, None)?.into_iter().filter(|c| c.0 == "bug" || c.0 == "error").map(|c| (c.0, c.1, c.2, c.4)).collect())
}

/// `dcp rename` (rename_command): `rebuild()` compiles and refreshes after the write.
pub fn rename_command(p: &crate::project::Project, pairs: Vec<(String, String, String)>, rebuild: &mut dyn FnMut() -> Result<()>)
    -> Result<(Vec<String>, Vec<String>, i32)> {
    let db = p.store_path();
    let main = p.main_uri();
    crate::storedb::st_open(&db, &main)?;
    let image = p.target.path.clone();
    let mut x = Ctx { p, root: p.root.to_string_lossy().into_owned(), names: Names::build(&db, &main, &image)?, out: vec![] };
    let before: HashSet<(String, i64, String)> = errors_of(&db)?.into_iter().map(|e| (e.1, e.2, e.3)).collect();
    let mut plans: Vec<Plan> = vec![];
    let mut refusals: Vec<Refusal> = vec![];
    let words: Vec<String> = pairs.iter().map(|p| p.0.trim().to_string()).collect();
    for (old_arg, new, why) in &pairs {
        if words.contains(new) && *new != old_arg.trim() {
            refusals.push((old_arg.trim().to_string(), new.clone(), format!("{new} is another pair's OLD: a chain (rename in two calls)")));
            continue;
        }
        match plan_rename(&mut x, old_arg.trim(), new, why)? {
            Ok(pl) => plans.push(pl),
            Err(r) => refusals.push(r),
        }
    }
    let olds: Vec<String> = plans.iter().map(|p| p.old.clone()).collect();
    let news: Vec<String> = plans.iter().map(|p| p.new.clone()).collect();
    for pl in &plans {
        if olds.iter().filter(|o| **o == pl.old).count() > 1 {
            refusals.push((pl.old.clone(), pl.new.clone(), format!("{} is renamed by several pairs of the call", pl.old)));
        } else if news.iter().filter(|n| **n == pl.new).count() > 1 {
            refusals.push((pl.old.clone(), pl.new.clone(), format!("{} is the new name of several pairs of the call", pl.new)));
        } else if olds.contains(&pl.new) {
            refusals.push((pl.old.clone(), pl.new.clone(), format!("{} is another pair's OLD: a chain (rename in two calls)", pl.new)));
        }
    }
    if refusals.is_empty() {
        let mut todo: Vec<&mut Plan> = plans.iter_mut().filter(|p| !p.recorded).collect();
        refusals = check_renames(&mut x, &mut todo).map_err(err)?;
    }
    let mut errs = vec![];
    if !refusals.is_empty() {
        for (old, new, msg) in &refusals {
            x.out.push(record(&[("rename", s(old.clone())), ("to", s(new.clone())), ("error", s(msg.clone()))]));
            errs.push(format!("dcp rename: {msg}"));
        }
        if pairs.len() > 1 {
            x.out.push(format!("rename: {} of {} pair(s) refused: nothing written", refusals.len(), pairs.len()));
        }
        return Ok((x.out, errs, 1));
    }
    let root = x.root.clone();
    let recorded: Vec<(Option<i64>, &'static str, String, String, String)> =
        plans.iter().filter(|p| p.recorded).map(|p| (p.a, p.kind, p.old.clone(), p.new.clone(), p.why.clone())).collect();
    // printed once the write went through
    let said: Vec<String> = recorded.iter().map(|(a, kind, old, new, _)| {
        record(&[("recorded", s(old.clone())), ("to", s(new.clone())), ("kind", s(*kind)), ("at", oi(*a)), ("files", Tok::I(0))])
            + "  (renamed by hand already: names.log only)"
    }).collect();
    if plans.iter().all(|p| p.recorded) {
        let ev: Vec<(Option<i64>, &str, String, String, &str)> = recorded.iter().map(|(a, k, o, n, w)| (*a, *k, o.clone(), n.clone(), w.as_str())).collect();
        if let Err(e) = E::log_names_each(&root, &ev) {
            errs.push(format!("dcp rename: names.log not written ({e}): nothing recorded"));
            return Ok((x.out, errs, 1));
        }
        x.out.extend(said);
        return Ok((x.out, errs, 0));
    }
    let mut edits: Vec<&mut Plan> = plans.iter_mut().filter(|p| !p.recorded).collect();
    // the units that read a file the rename writes, preprocessed before the write: one whose text changes only by
    // the names keeps its object with the symbols renamed instead of compiling again (compile.rs rename_after)
    let touched: Vec<String> = edits.iter().flat_map(|p| p.files.keys().cloned()).filter(|f| !f.starts_with("decl/")).collect();
    let pre = crate::compile::rename_before(p, &touched).map_err(err)?;
    // the tu rows as they are: a rename refused after the write puts them back with the files (no compile)
    let tu_rows = crate::compile::tu_snapshot(p).map_err(err)?;
    // all or nothing: every file the rename writes is kept as it reads now; a failed write of a source, a decl file
    // or names.log puts every one back
    let mut kept: Vec<(String, Vec<u8>)> = vec![];
    {
        let mut seen = BTreeSet::new();
        let paths = edits.iter().flat_map(|p| p.files.keys().filter(|f| !f.starts_with("decl/")).map(|f| py_path(&format!("{root}/{f}")))
                                           .chain(p.decls.iter().cloned()).collect::<Vec<_>>());
        for path in paths {
            if seen.insert(path.clone()) {
                let b = std::fs::read(&path).map_err(|e| err(format!("{path}: {e}")))?;
                kept.push((path, b));
            }
        }
    }
    let log = py_path(&format!("{root}/names.log"));
    if let Ok(b) = std::fs::read(&log) {
        kept.push((log, b));
    }
    let events: Vec<(Option<i64>, &'static str, String, String, String)> = recorded.iter().cloned()
        .chain(edits.iter().map(|p| (p.a, p.kind, p.old.clone(), p.new.clone(), p.why.clone()))).collect();
    let written = write_renames(&root, &mut edits).and_then(|_| {
        let ev: Vec<(Option<i64>, &str, String, String, &str)> = events.iter().map(|(a, k, o, n, w)| (*a, *k, o.clone(), n.clone(), w.as_str())).collect();
        E::log_names_each(&root, &ev)
    });
    if let Err(e) = written {
        let stuck: Vec<String> = kept.iter().filter(|(path, b)| std::fs::read(path).ok().as_ref() != Some(b))
            .filter_map(|(path, b)| E::write_bytes(path, b).err()).collect();
        if stuck.is_empty() {
            errs.push(format!("dcp rename: a write failed ({e}): every file put back as it was, nothing renamed"));
        } else {
            errs.push(format!("dcp rename: a write failed ({e}), and putting back failed for {} file(s): {} (git checkout them)", stuck.len(),
                              stuck.join("; ")));
        }
        return Ok((x.out, errs, 1));
    }
    x.out.extend(said);
    // φ before the rename: the other names of ours at OLD's address (C.name.alias: one object has one name)
    let names = crate::with_db(&db, |c| crate::store::claims_of(c, &db, "name", None, |_| true))?;
    let phi = crate::phi::Phi::new(&names, &[]);
    for pl in &edits {
        x.out.push(record(&[("renamed", s(pl.old.clone())), ("to", s(pl.new.clone())), ("kind", s(pl.kind)), ("at", oi(pl.a)),
                            ("files", Tok::I(pl.files.len() as i64)), ("replacements", Tok::I(pl.files.values().sum::<usize>() as i64)),
                            ("decl", Tok::I(pl.decl_lines as i64))]));
        for (f, k) in &pl.files {
            x.out.push(format!("  {}", record(&[("file", s(f.clone())), ("replacements", Tok::I(*k as i64))])));
            // the changed lines as they read now: which declarations, prototypes and uses the rename reached
            let lines = pl.lines.get(f).map(|v| v.as_slice()).unwrap_or(&[]);
            for (n, t) in lines.iter().take(LINES) {
                let t: String = if t.chars().count() > 110 { t.chars().take(107).collect::<String>() + "..." } else { t.clone() };
                x.out.push(format!("    {n}: {t}"));
            }
            if lines.len() > LINES {
                x.out.push(format!("    (+{} more line(s))", lines.len() - LINES));
            }
        }
        if !pl.comments.is_empty() {
            x.out.push(format!("  comments: {} line(s) where {} stood inside a comment now read {} (review them: a comment may \
                                argue from the old name)", pl.comments.len(), pl.old, pl.new));
            for (f, n, t) in pl.comments.iter().take(COMMENT_LINES) {
                let t: String = if t.chars().count() > 110 { t.chars().take(107).collect::<String>() + "..." } else { t.clone() };
                x.out.push(format!("    {f}:{n}: {t}"));
            }
            if pl.comments.len() > COMMENT_LINES {
                x.out.push(format!("    (+{} more line(s))", pl.comments.len() - COMMENT_LINES));
            }
        }
        if crate::srcscan::placeholder_whole(&pl.old).is_some() {
            let mut views: Vec<String> = E::words_with_prefix(&root, &pl.old).into_iter().filter(|w| {
                *w != pl.old && w[pl.old.len()..].chars().next().is_some_and(|c| c.is_uppercase())
                    && crate::srcscan::placeholder_whole(w).map(|v| v as i64) == pl.a
            }).collect();
            views.sort();
            if !views.is_empty() {
                x.out.push(format!("note: the views of {} keep their names: {} (rename each: dcp rename VIEW NEW)", pl.old,
                                   views.iter().take(8).cloned().collect::<Vec<_>>().join(", ")));
            }
        }
        if let Some(a) = pl.a {
            let mut others: BTreeMap<&str, &str> = BTreeMap::new();
            for e in phi.at(a).filter(|e| matches!(e.origin, crate::phi::Origin::Source | crate::phi::Origin::Decl) && e.view.is_none()) {
                if e.name != pl.old && e.name != pl.new {
                    others.entry(e.name.as_str()).or_insert(e.by.strip_prefix("src:").or_else(|| e.by.strip_prefix("decl:")).unwrap_or(&e.by));
                }
            }
            if !others.is_empty() {
                x.out.push(format!("note: other names of ours at {a:#x}: {} (one object has one name: dcp rename each to {})",
                                   others.iter().map(|(n, w)| format!("{n} ({w})")).collect::<Vec<_>>().join(", "), pl.new));
            }
        }
    }
    let mapping: BTreeMap<String, String> = edits.iter().map(|p| (p.old.clone(), p.new.clone())).collect();
    let (read, reused) = (pre.len(), crate::compile::rename_after(p, pre, &mapping).map_err(err)?);
    if read > 0 {
        x.out.push(format!("build: {} of {read} unit(s) that read the renamed files keep their objects, the symbols renamed (their preprocessed \
                            text differs only by the names)", reused.len()));
    }
    rebuild()?;
    // an error from before keeps its rule and address; its message names the new names now (or still the old ones:
    // M1 names a function by the baseline's name)
    let words: Vec<(regex::Regex, &str)> = edits.iter().map(|p| (regex::Regex::new(&format!(r"\b{}\b", regex::escape(&p.old))).unwrap(), p.new.as_str())).collect();
    let before: HashSet<(String, i64, String)> = before.into_iter().flat_map(|(r, a, m)| {
        let renamed = words.iter().fold(m.clone(), |m, (w, n)| w.replace_all(&m, regex::NoExpand(n)).into_owned());
        [(r.clone(), a, m), (r, a, renamed)]
    }).collect();
    let bad = errors_of(&db)?;
    let new: Vec<&(String, String, i64, String)> = bad.iter().filter(|e| !before.contains(&(e.1.clone(), e.2, e.3.clone()))).collect();
    if !bad.is_empty() {
        x.out.push(format!("check: {} new error(s) after the rename, {} from before (dcp check lists them)", new.len(), bad.len() - new.len()));
    }
    for e in new.iter().take(10) {
        x.out.push(format!("  {} {} {:#010x}: {}", e.0, e.1, e.2, e.3));
    }
    if new.is_empty() {
        return Ok((x.out, errs, 0));
    }
    // a rename that brings an error is refused, and a refusal writes nothing: every file is put back as it read
    // before (sources, decl files, names.log) and the tree rebuilt (a match-base report: NEW was declared already
    // with another array size; the rename wrote both declarations into one unit, then failed the check)
    let stuck: Vec<String> = kept.iter().filter(|(path, b)| std::fs::read(path).ok().as_ref() != Some(b))
        .filter_map(|(path, b)| E::write_bytes(path, b).err()).collect();
    let pairs_txt: Vec<String> = edits.iter().map(|p| format!("{} -> {}", p.old, p.new)).collect();
    let msg = format!("the rename brings {} new error(s) (listed above; fix them first, e.g. a declaration of the new name with another type)",
                      new.len());
    for pl in &edits {
        x.out.push(record(&[("rename", s(pl.old.clone())), ("to", s(pl.new.clone())), ("error", s(msg.clone()))]));
    }
    if stuck.is_empty() {
        crate::compile::tu_restore(p, &tu_rows).map_err(err)?;
        rebuild()?;
        x.out.push(format!("rename: refused, every file put back as it was, nothing renamed ({})", pairs_txt.join(", ")));
        errs.push(format!("dcp rename: {msg}: nothing written"));
    } else {
        errs.push(format!("dcp rename: {msg}, and putting back failed for {} file(s): {} (git checkout them)", stuck.len(), stuck.join("; ")));
    }
    Ok((x.out, errs, 1))
}
