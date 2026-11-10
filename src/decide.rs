//! The guided decisions: every human decision of a decompilation is an **obligation** the tool names when it
//! becomes due, with the evidence it has, the command that resolves it and the check that verifies it afterwards.
//! `dcp init` declares nothing; the obligations are computed here from the configuration and the store on every
//! call (never stored, never written by hand), and `dcp status` prints them in order. A declaration (`dcp toolchain
//! declare`, `dcp libs declare`, `dcp analyzer declare`) always carries a reason and is always level declared; the
//! rules raise it (C.toolchain checks the builds against the Rich header, S.crt.code places the archives' members,
//! M.flags.probe proves flags).
//!
//! The obligations, in order (the ids are stable; Project.waiting names the ones a rule input waits on):
//!   toolchain.compiler   the compiler build of the user's objects       dcp toolchain declare compiler=...
//!   toolchain.linker     the linker build                               dcp toolchain declare linker=...
//!   toolchain.root       the installation of that toolchain            dcp toolchain declare root=...
//!   toolchain.cflags     the compiler flags (until the probe proves)    dcp toolchain declare cflags=...
//!   libs.archives        the static libraries linked in                 dcp libs declare ARCHIVE...   (due once the root is
//!                        declared; open again while the last link has unresolved names an undeclared archive defines:
//!                        link class `library`)
//!   analyzer             the third-party analyzer for the drafts        dcp analyzer declare ghidra|none
//!   layout               functions without a source, open units       dcp session start, dcp layout next
//!   match                the grade queue                                dcp next
//! An obligation is open while its value is missing or declared without a reason. The toolchain and libs obligations
//! are the gate of `dcp session start` and `dcp check`; the analyzer is due before the first draft is wanted; layout
//! and match are the work itself.
//!
//! The commands here return their output lines; the CLI prints them and reruns the rules between a
//! declaration and its verdict (the engine's refresh).

use crate::error::{Error, Result};
use crate::cliread::{record, Tok};
use crate::project::{py_path, Project};
use crate::store;
use crate::tomledit::{self, TV};
use crate::toolchain::Install;
use crate::with_db;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::LazyLock;

const GATE: [&str; 2] = ["toolchain.", "libs."];
const CANDIDATES_META: &str = "libs.candidates"; // the last `dcp libs candidates` summary (libcand.rs)
const DETAIL: &str = "    "; // a step's detail lines start here
const WRAP: usize = 100; // the width of a status line
pub const TOOLCHAIN_DECL_KEYS: [&str; 4] = ["compiler", "linker", "root", "cflags"];
const TARGET_COVERED: [&str; 4] = ["compiler", "linker", "cflags", "archives"];

fn err(e: impl std::fmt::Display) -> Error {
    Error::runtime(e.to_string())
}

fn s(x: impl Into<String>) -> Tok {
    Tok::S(x.into())
}

fn os(x: Option<impl Into<String>>) -> Tok {
    x.map(|v| Tok::S(v.into())).unwrap_or(Tok::No)
}

fn name_of(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

// ------------------------------------------------------------------------------------------------ the obligations

pub struct Obligation {
    pub id: String,
    pub target: Option<String>, // None: the project's (one declaration for every target)
    pub missing: String,        // what a human has to decide
    pub evidence: String,       // what the tool knows so far (short; `dcp toolchain`, `dcp libs candidates` have the rest)
    pub resolve: String,        // the command that resolves it
    pub waits: String,          // not due yet: the obligation it follows
}

impl Obligation {
    fn new(id: &str, target: Option<&str>, missing: String, evidence: String, resolve: &str, waits: &str) -> Obligation {
        Obligation { id: id.into(), target: target.map(|t| t.to_string()), missing, evidence, resolve: resolve.into(), waits: waits.into() }
    }

    /// Open, it fails `dcp session start` and `dcp check`.
    pub fn gate(&self) -> bool {
        GATE.iter().any(|g| self.id.starts_with(g))
    }

    /// The fields of the output contract, in order.
    fn fields(&self) -> Vec<(&'static str, Option<String>)> {
        let mut out = vec![("obligation", Some(self.id.clone())), ("target", self.target.clone())];
        if !self.waits.is_empty() {
            out.push(("waits", Some(self.waits.clone())));
        }
        out.push(("missing", Some(self.missing.clone())));
        if !self.evidence.is_empty() && self.waits.is_empty() {
            out.push(("evidence", Some(self.evidence.clone())));
        }
        out.push(("resolve", Some(self.resolve.clone())));
        out
    }

    pub fn record(&self) -> String {
        let kv: Vec<(&str, Tok)> = self.fields().into_iter().map(|(k, v)| (k, os(v))).collect();
        record(&kv)
    }

    fn json(&self) -> String {
        json_line(&self.fields().into_iter().map(|(k, v)| (k, v.map(J::S).unwrap_or(J::Null))).collect::<Vec<_>>())
    }
}

enum J {
    S(String),
    I(i64),
    Null,
}

/// One object as json.dumps writes it (", " and ": ", ensure_ascii).
fn json_line(kv: &[(&str, J)]) -> String {
    let mut out = String::from("{");
    for (i, (k, v)) in kv.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        crate::put_str(&mut out, k);
        out.push_str(": ");
        match v {
            J::S(x) => crate::put_str(&mut out, x),
            J::I(n) => out.push_str(&n.to_string()),
            J::Null => out.push_str("null"),
        }
    }
    out.push('}');
    out
}

/// What a project needs for its obligations: the store, the image, the toolchain.
struct Ctx<'a> {
    p: &'a Project,
    db: String,
    img: std::rc::Rc<crate::pe::Image>,
    tc: crate::toolchain::Vc6,
    decl: Value,
}

impl<'a> Ctx<'a> {
    fn new(p: &'a Project) -> Result<Ctx<'a>> {
        let db = p.store_path();
        crate::storedb::st_open(&db, &p.main_uri())?;
        let img = crate::image(&p.target(None).map_err(err)?.path)?;
        let tc = crate::toolchain::Vc6;
        let decl = p.toolchain_decl(None).map_err(err)?;
        Ok(Ctx { p, db, img, tc, decl })
    }

    fn facts(&self, kind: &str, rule: &str) -> Result<store::Claims> {
        let rules = [rule.to_string()];
        with_db(&self.db, |c| store::claims_of(c, &self.db, kind, Some(&rules), |_| true))
    }

    fn rich(&self) -> Result<Option<std::rc::Rc<store::Claim>>> {
        Ok(self.facts("toolchain", "S.rich")?.into_iter().next())
    }

    fn decl_str(&self, k: &str) -> String {
        match &self.decl[k] {
            Value::String(x) => x.clone(),
            Value::Array(a) => a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" "),
            _ => String::new(),
        }
    }

    fn reason(&self, k: &str) -> String {
        self.decl["reasons"][k].as_str().unwrap_or("").to_string()
    }

    fn crt_strings(&self) -> Vec<(u32, &'static str)> {
        self.tc.crt_strings(&self.img)
    }

    fn c_toolchain_errors(&self) -> Result<Vec<String>> {
        Ok(crate::storedb::st_findings(&self.db, None, None)?.into_iter().filter(|c| c.1 == "C.toolchain").map(|c| c.4).collect())
    }
}

/// The date (UTC) of a time stamp.
fn utc_date(ts: i64) -> String {
    // the civil date of a day count (Howard Hinnant's days_from_civil, inverted)
    let z = ts.div_euclid(86400) + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

fn built_at(img: &crate::pe::Image) -> String {
    utc_date(img.timestamp as i64)
}

fn entry_s<'v>(e: &'v Value, k: &str) -> &'v str {
    e.get(k).and_then(|v| v.as_str()).unwrap_or("")
}

fn entry_i(e: &Value, k: &str) -> i64 {
    e.get(k).and_then(|v| v.as_i64()).unwrap_or(0)
}

fn declare_of(tc: &crate::toolchain::Vc6, e: &Value) -> String {
    tc.declare(entry_s(e, "tool"), entry_s(e, "family"), entry_i(e, "build") as u32)
}

fn candidate_text(tc: &crate::toolchain::Vc6, e: &Value) -> String {
    let lib = match entry_i(e, "archive_objects") {
        0 => String::new(),
        n => format!(" lib={n}"),
    };
    let lang = match entry_s(e, "language") {
        "" | "C" => String::new(),
        l => format!(" {l}"),
    };
    format!("{} x{}{lang}{lib}", declare_of(tc, e), entry_i(e, "count"))
}

/// One Rich candidate as `dcp toolchain` prints it.
fn candidate_entry(tc: &crate::toolchain::Vc6, e: &Value) -> String {
    let extra = match entry_i(e, "archive_objects") {
        0 => String::new(),
        n => format!(", {n} archive objects"),
    };
    let lang = match entry_s(e, "language") {
        "" => "-",
        l => l,
    };
    format!("{} ({} {lang} x{}{extra})", declare_of(tc, e), entry_s(e, "tool"), entry_i(e, "count"))
}

/// The build a declaration names ('cl 12.00.9044' -> 9044), None when it names none.
fn declared_build(text: &str) -> Option<u32> {
    text.split_whitespace().last()?.rsplit('.').next()?.parse().ok()
}

/// One installation as evidence: its tool versions and which declared (or, before the declaration, which Rich)
/// builds it makes.
fn install_text(inst: &Install, c: &Ctx, rich: Option<&store::Claim>) -> String {
    let vers: Vec<String> = ["cl", "c2", "link"].iter()
        .filter_map(|k| inst.versions.iter().find(|(x, _)| x == k).map(|(_, v)| format!("{k} {v}"))).collect();
    let mut makes = vec![];
    for (key, build) in [("compiler", inst.compiler_build), ("linker", inst.linker_build)] {
        if let Some(want) = declared_build(&c.decl_str(key)) {
            if build == Some(want) {
                makes.push(format!("the declared {key}"));
            }
        } else if let (Some(r), Some(b)) = (rich, build) {
            let rich_builds = r.value.get(format!("{key}s")).and_then(|v| v.as_array()).cloned().unwrap_or_default();
            if rich_builds.iter().any(|e| entry_i(e, "build") == b as i64) {
                makes.push(format!("a Rich {key} ({b})"));
            }
        }
    }
    let m = if makes.is_empty() { String::new() } else { format!("; makes {}", makes.join(" and ")) };
    format!("{} ({}{m})", inst.root, vers.join(" "))
}

/// The last `dcp libs candidates` of this root (meta, cheap), else the command.
fn libs_evidence(c: &Ctx) -> Result<String> {
    if let Some(m) = crate::storedb::st_meta(&c.db, CANDIDATES_META)? {
        let d: Value = serde_json::from_str(&m).unwrap_or(Value::Null);
        if d["root"].as_str().unwrap_or("") == c.decl_str("root") {
            let mut rows: Vec<&Value> = d["archives"].as_array().map(|a| a.iter().collect()).unwrap_or_default();
            rows.sort_by(|a, b| entry_i(b, "bytes").cmp(&entry_i(a, "bytes")).then_with(|| entry_s(a, "archive").cmp(entry_s(b, "archive"))));
            let top: Vec<String> = rows.iter().take(4).filter(|r| entry_i(r, "placed") != 0)
                .map(|r| format!("{} placed={}", entry_s(r, "archive"), entry_i(r, "placed"))).collect();
            let top = if top.is_empty() { "no archive places a member".to_string() } else { top.join(", ") };
            return Ok(format!("dcp libs candidates: {top}"));
        }
    }
    Ok("not placed yet: dcp libs candidates places every run-time archive of the root".into())
}

/// The `library` lines of the target's last full link (build/link/<target>/link.json, which the link rewrites with
/// every classification): unresolved names that an archive the target does not declare defines. [] without a link.
fn link_library_names(p: &Project) -> Vec<String> {
    let f = p.root.join("build").join("link").join(&p.target_name).join("link.json");
    let Ok(text) = std::fs::read_to_string(f) else { return vec![] };
    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    v["unresolved"]["library"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect()).unwrap_or_default()
}

/// The toolchain, libs and analyzer obligations of the current target (open ones only).
fn setup_obligations(c: &Ctx) -> Result<Vec<Obligation>> {
    let p = c.p;
    let t = Some(p.target_name.as_str());
    let mut out = vec![];
    let rich = c.rich()?;
    let state = |key: &str| -> Option<&'static str> {
        if c.decl_str(key).is_empty() {
            Some("missing")
        } else if c.reason(key).is_empty() {
            Some("declared without a reason")
        } else {
            None
        }
    };
    for (key, what) in [("compiler", "the compiler build that made the user's objects"), ("linker", "the linker build")] {
        let Some(st) = state(key) else { continue };
        let mut ev = vec![match &rich {
            Some(r) => {
                let cands: Vec<String> = r.value.get(format!("{key}s")).and_then(|v| v.as_array()).into_iter().flatten()
                    .map(|e| candidate_text(&c.tc, e)).collect();
                format!("Rich {key}s {}", if cands.is_empty() { "none".to_string() } else { cands.join(", ") })
            }
            None => "no Rich header".to_string(),
        }];
        if key == "compiler" {
            ev.push(format!("built {}", built_at(&c.img)));
            let crt = c.crt_strings();
            if let Some(first) = crt.first() {
                ev.push(format!("CRT strings {} ({})", crt.len(), first.1.trim()));
            }
        } else {
            ev.push(format!("PE linker version {}.{:02}", c.img.linker_version.0, c.img.linker_version.1));
        }
        out.push(Obligation::new(&format!("toolchain.{key}"), t, format!("{what} ({st})"), ev.join("; "),
                                 &format!("dcp toolchain declare {key}=\"<one of the Rich {key}s>\" --why \"...\""), ""));
    }
    // a declared root the plugin finds no compiler under is no open obligation: the match rules warn (M.compile)
    // and `dcp toolchain` says available=no
    if let Some(st) = state("root") {
        let installs = c.tc.installs();
        let ev = if installs.is_empty() {
            "none".to_string()
        } else {
            installs.iter().map(|i| install_text(i, c, rich.as_deref())).collect::<Vec<_>>().join("; ")
        };
        out.push(Obligation::new("toolchain.root", None, format!("the installation of that toolchain ({st})"), format!("installs found: {ev}"),
                                 "dcp toolchain declare root=DIR --why \"...\"", ""));
    }
    if let Some(st) = state("cflags") {
        let wiz = c.tc.wizard_cflags().join(" ");
        let pre = if wiz.is_empty() { String::new() } else { format!("the VC6 project wizard's release flags {wiz}; ") };
        out.push(Obligation::new("toolchain.cflags", t, format!("the compiler flags ({st})"),
                                 format!("{pre}dcp toolchain probe proves flags once functions byte-match"),
                                 "dcp toolchain declare cflags=\"/F1 /F2 ...\" --why \"...\"", ""));
    }
    let (archives, _, reason) = p.archives_decl(None).map_err(err)?;
    let st = match &archives {
        None => Some("missing"),
        Some(_) if reason.is_empty() => Some("declared without a reason"),
        Some(_) => None,
    };
    if let Some(st) = st {
        let waits = if c.decl_str("root").is_empty() { "toolchain.root" } else { "" };
        let ev = if waits.is_empty() { libs_evidence(c)? } else { String::new() };
        out.push(Obligation::new("libs.archives", t, format!("the static libraries linked into the image ({st})"), ev,
                                 "dcp libs candidates; dcp libs declare ARCHIVE... --why \"...\"", waits));
    } else {
        let lib = link_library_names(p);
        if !lib.is_empty() {
            let mut per: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for line in &lib {
                // `symbol  ->  first archive, ...  (undeclared: ...)`
                let (sym, rest) = line.split_once("  ->  ").unwrap_or((line, ""));
                let first = rest.split("  (").next().unwrap_or("").split(", ").next().unwrap_or("").to_string();
                per.entry(first).or_default().push(sym.to_string());
            }
            let ev: Vec<String> = per.iter().map(|(a, s)| {
                format!("{a} defines {}: {}{}", s.len(), s.iter().take(3).cloned().collect::<Vec<_>>().join(", "), if s.len() > 3 { " ..." } else { "" })
            }).collect();
            let specs = archives.unwrap_or_default().join(" ");
            out.push(Obligation::new("libs.archives", t, format!("{} unresolved name(s) of the last link that an undeclared archive defines", lib.len()),
                                     ev.join("; "), &format!("dcp libs declare {specs} ARCHIVE --why \"...\" (dcp link lists the names)"), ""));
        }
    }
    if let Some(a) = analyzer_obligation(c)? {
        out.push(a);
    }
    Ok(out)
}

fn analyzer_obligation(c: &Ctx) -> Result<Option<Obligation>> {
    let p = c.p;
    if !crate::project::reason_of(p.table("analyzer"), "root").is_empty() {
        return Ok(None);
    }
    let az = crate::analyzers::Analyzer::of(p).map_err(crate::project::cfg_err)?;
    let inst = az.available();
    let found = match &inst.reason {
        None => format!("found at {}", inst.at),
        Some(r) => format!("not available: {r}"),
    };
    let n = with_db(&c.db, |db| crate::names::draft_values(db, &p.main_uri()))?.len();
    let written = p.table("analyzer").and_then(|t| t.get("root")).is_some_and(|v| v.as_str() != Some(""));
    let origin = if written { "as dcp init found it" } else { "no [analyzer] root written" };
    Ok(Some(Obligation::new("analyzer", None, "the Ghidra installation whose pseudocode the drafts start from (computed, not confirmed)".into(),
                            format!("[analyzer] {origin} ({found}); drafts={n}"), "dcp analyzer declare [root=DIR] [java_home=DIR] --why \"...\"", "")))
}

/// The layout and match obligations of the current target: the first open function and the counts; the first item
/// of the grade queue.
fn work_obligations(c: &Ctx) -> Result<Vec<Obligation>> {
    let p = c.p;
    let t = Some(p.target_name.as_str());
    let mut out = vec![];
    let v = crate::session::view_of(p)?;
    let (glo, ghi, _) = v.game;
    let funcs: Vec<i64> = v.funcs.iter().map(|f| f.lo).filter(|&a| glo <= a && a < ghi).collect();
    let without = funcs.iter().filter(|a| !v.sources.contains_key(a)).count();
    let rows = crate::session::unit_rows(&v);
    let count = |st: &str| rows.iter().filter(|r| r.status == st).count();
    let nxt = v.first_open_item();
    if nxt.is_some() || count("open") > 0 {
        let ev = match nxt {
            Some((a, kind, size)) => {
                let unit = v.unit_index(a).map(|i| v.units[i].tu.clone()).unwrap_or_else(|| "-".into());
                format!("next={a:#010x} kind={kind} size={size} unit={unit} start={} analyzed={} (dcp layout next: the evidence)",
                        v.start_hows(a), if v.drafted.contains(&a) { "yes" } else { "no" })
            }
            None => String::new(),
        };
        out.push(Obligation::new("layout", t, format!("{without} of {} functions of the game code without a source; units open={} separated={}",
                                                      funcs.len(), count("open"), count("separated")),
                                 ev, "dcp session start; dcp layout next; dcp draft --next", ""));
    }
    let grades = crate::queues::function_grades(&c.db)?;
    if !grades.is_empty() {
        let g = |r: &serde_json::Map<String, Value>, k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let below = grades.iter().filter(|r| g(r, "code") != "byte" || g(r, "readability") != "readable").count();
        if below > 0 {
            let q = crate::queues::queue(&c.db, "base", None, None)?;
            let ev = match q.first() {
                Some(r) => format!("next={:#010x} {} {}+{}", r.get("addr").and_then(|v| v.as_i64()).unwrap_or(0), g(r, "name"), g(r, "code"), g(r, "readability")),
                None => "base queue empty: dcp next --deep".into(),
            };
            out.push(Obligation::new("match", t, format!("{below} of {} functions below byte + readable", grades.len()), ev, "dcp next", ""));
        }
    }
    Ok(out)
}

/// Every open obligation of the current target, in order (the project-wide ones included).
fn compute(c: &Ctx, work: bool) -> Result<Vec<Obligation>> {
    let mut out = setup_obligations(c)?;
    if work {
        out.extend(work_obligations(c)?);
    }
    Ok(out)
}

fn phase(obls: &[Obligation]) -> &'static str {
    if obls.iter().any(|o| o.gate()) {
        "setup"
    } else if obls.iter().any(|o| o.id == "layout") {
        "layout"
    } else if obls.iter().any(|o| o.id == "match") {
        "match"
    } else {
        "done"
    }
}

// ------------------------------------------------------------------------------------------------ status

static WORDSEP: LazyLock<fancy_regex::Regex> = LazyLock::new(|| {
    // textwrap.TextWrapper.wordsep_re (break_on_hyphens): whitespace, an em-dash between words, a word possibly
    // hyphenated
    let (wp, lt) = (r#"[\w!"'&.,?]"#, r"[^\d\W]");
    fancy_regex::Regex::new(&format!(
        r"( +|(?<={wp})-{{2,}}(?=\w)|[^ ]+?(?:-(?:(?<={lt}{lt}-)|(?<={lt}-{lt}-))(?={lt}-?{lt})|(?= |$)|(?<={wp})(?=-{{2,}}\w)))"
    )).unwrap()
});

/// textwrap.fill(text, width, initial_indent=first, subsequent_indent=spaces as wide): the lines.
pub fn fill(text: &str, width: usize, first: &str) -> Vec<String> {
    let text: String = text.chars().map(|c| if matches!(c, '\t' | '\n' | '\x0b' | '\x0c' | '\r') { ' ' } else { c }).collect();
    let mut chunks: Vec<String> = vec![];
    let mut at = 0;
    for m in WORDSEP.find_iter(&text).flatten() {
        if m.start() > at {
            chunks.push(text[at..m.start()].to_string());
        }
        if !m.as_str().is_empty() {
            chunks.push(m.as_str().to_string());
        }
        at = m.end();
    }
    if at < text.len() {
        chunks.push(text[at..].to_string());
    }
    let len = |s: &str| s.chars().count();
    let rest = " ".repeat(len(first));
    chunks.reverse();
    let mut lines: Vec<String> = vec![];
    while !chunks.is_empty() {
        let mut cur: Vec<String> = vec![];
        let mut cur_len = 0;
        let indent = if lines.is_empty() { first } else { rest.as_str() };
        let w = width.saturating_sub(len(indent));
        if chunks.last().is_some_and(|c| c.trim().is_empty()) && !lines.is_empty() {
            chunks.pop();
        }
        while let Some(c) = chunks.last() {
            let l = len(c);
            if cur_len + l > w {
                break;
            }
            cur_len += l;
            cur.push(chunks.pop().unwrap());
        }
        if chunks.last().is_some_and(|c| len(c) > w) {
            // _handle_long_word: break it, after the last hyphen that fits when there is one
            let space_left = if w < 1 { 1 } else { w - cur_len };
            let chunk: Vec<char> = chunks.last().unwrap().chars().collect();
            let mut end = space_left;
            if chunk.len() > space_left {
                if let Some(h) = chunk[..space_left.min(chunk.len())].iter().rposition(|&c| c == '-') {
                    if h > 0 && chunk[..h].iter().any(|&c| c != '-') {
                        end = h + 1;
                    }
                }
            }
            let end = end.min(chunk.len());
            cur.push(chunk[..end].iter().collect());
            *chunks.last_mut().unwrap() = chunk[end..].iter().collect();
            if chunks.last().is_some_and(|c| c.is_empty()) {
                chunks.pop();
            }
        }
        if cur.last().is_some_and(|c| c.trim().is_empty()) {
            cur.pop();
        }
        if !cur.is_empty() {
            lines.push(format!("{indent}{}", cur.concat()));
        }
    }
    lines
}

/// One labelled detail line of a step, wrapped under its own column (`need`, `seen`, `run`, ...).
fn detail(out: &mut Vec<String>, label: &str, text: &str) {
    out.extend(fill(text, WRAP, &format!("{DETAIL}{label:<6}")));
}

/// The status of one target. Human output: the phase, whether the gate is blocked, then one numbered step per open
/// obligation (target, what is missing, the evidence, the command that resolves it), and a `next:` line for the
/// first one to do. `shown`: ids of project-wide obligations already printed (multi-target output prints them
/// once), extended. `as_json`: the records of the output contract instead.
fn status(c: &Ctx, shown: &mut Vec<String>, work: bool, as_json: bool) -> Result<Vec<String>> {
    let p = c.p;
    let obls = compute(c, work)?;
    let was_shown = shown.clone();
    let rows: Vec<&Obligation> = obls.iter().filter(|o| !(o.target.is_none() && was_shown.contains(&o.id))).collect();
    let mut out = vec![];
    if as_json {
        out.push(json_line(&[("status", J::S(p.target_name.clone())), ("phase", J::S(phase(&obls).into())), ("open", J::I(obls.len() as i64))]));
        for o in &rows {
            out.push(o.json());
            if o.target.is_none() {
                shown.push(o.id.clone());
            }
        }
        return Ok(out);
    }
    let waiting = obls.iter().filter(|o| !o.waits.is_empty()).count();
    let gates = obls.iter().filter(|o| o.gate()).count();
    out.push(format!("dcp status: {}", p.target_name));
    out.push(format!("  phase  {}", phase(&obls)));
    out.push(format!("  open   {}{}", obls.len(),
                     if waiting > 0 { format!(" ({} to do now, {waiting} waiting)", obls.len() - waiting) } else { String::new() }));
    out.push(format!("  gate   {}", if gates > 0 {
        format!("blocked by {gates} open obligation{} (dcp session start and dcp check fail)", if gates != 1 { "s" } else { "" })
    } else {
        "clear".to_string()
    }));
    let hidden: Vec<&str> = obls.iter().filter(|o| o.target.is_none() && was_shown.contains(&o.id)).map(|o| o.id.as_str()).collect();
    if !hidden.is_empty() {
        out.push(format!("  also   {} (project-wide, printed above)", hidden.join(", ")));
    }
    if obls.is_empty() {
        out.push(String::new());
        out.push("nothing open: every decision is declared and every function is byte + readable".into());
        return Ok(out);
    }
    out.push(String::new());
    for (i, o) in rows.iter().enumerate() {
        let tgt = match &o.target {
            None => "every target".to_string(),
            Some(t) => format!("target {t}"),
        };
        out.push(format!("{:>2}. {:<18} {tgt}", i + 1, o.id));
        detail(&mut out, "need", &o.missing);
        if !o.waits.is_empty() {
            detail(&mut out, "wait", &format!("on {}: declare that first", o.waits));
        } else {
            if !o.evidence.is_empty() {
                detail(&mut out, "seen", &o.evidence);
            }
            let cmds: Vec<&str> = o.resolve.split("; ").collect();
            detail(&mut out, "run", cmds[0]);
            for cmd in &cmds[1..] {
                detail(&mut out, "then", cmd);
            }
        }
        out.push(String::new());
        if o.target.is_none() {
            shown.push(o.id.clone());
        }
    }
    if let Some(n) = rows.iter().find(|o| o.waits.is_empty()) {
        out.push(format!("next: {}", n.resolve.split("; ").next().unwrap_or("")));
    } else if !rows.is_empty() {
        let w: std::collections::BTreeSet<&str> = rows.iter().map(|o| o.waits.as_str()).collect();
        out.push(format!("next: waiting for {}", w.into_iter().collect::<Vec<_>>().join(", ")));
    } else {
        out.push("next: see the project-wide obligations above".into());
    }
    Ok(out)
}

/// The status lines of one target (`dcp status`; other commands print them as their tail after an empty line) and
/// the project-wide obligation ids shown so far (`shown` extended).
pub fn decide_status(p: &crate::project::Project, shown: Vec<String>, work: bool, as_json: bool) -> Result<(Vec<String>, Vec<String>)> {
    let c = Ctx::new(p)?;
    let mut shown = shown;
    let lines = status(&c, &mut shown, work, as_json)?;
    Ok((lines, shown))
}

/// The open toolchain and libs obligations of the current target (the session and check gate), as records.
pub fn decide_gate(p: &crate::project::Project) -> Result<Vec<String>> {
    gate_records(p)
}

pub(crate) fn gate_records(p: &Project) -> Result<Vec<String>> {
    let c = Ctx::new(p)?;
    Ok(setup_obligations(&c)?.iter().filter(|o| o.gate()).map(|o| o.record()).collect())
}

// ------------------------------------------------------------------------------------------------ the evidence view

/// `dcp toolchain` of one target: what is declared (per key with its reason and level), the installs found on this
/// machine with the versions they report, the Rich candidates with the plugin's build names, the PE linker version
/// and time stamp, the CRT strings, the C.toolchain verdict, the archives and the members placed, the probe.
pub fn decide_toolchain_view(p: &crate::project::Project) -> Result<Vec<String>> {
    let c = Ctx::new(p)?;
    let tc = &c.tc;
    let img = &c.img;
    let mut out = vec![];
    let probed = c.facts("toolchain", "M.flags.probe")?;
    let mut proven: Vec<String> = probed.iter().filter(|f| f.support == store::REPRODUCED).filter_map(|f| f.s("flag").map(|x| x.to_string())).collect();
    proven.sort();
    out.push(record(&[("target", s(p.target_name.clone())), ("available", Tok::B(p.toolchain_available()))]));
    for k in ["compiler", "linker", "root", "cflags"] {
        let v = c.decl_str(k);
        let mut level = if v.is_empty() {
            "open".to_string()
        } else if !c.reason(k).is_empty() {
            "declared".to_string()
        } else {
            "declared-no-reason".to_string()
        };
        if k == "cflags" && !proven.is_empty() {
            level += &format!(";reproduced:{}", proven.join(","));
        }
        let from = c.decl["from"][k].as_str().map(|x| x.to_string());
        let why = Some(c.reason(k)).filter(|r| !r.is_empty());
        out.push(format!("  {}", record(&[("key", s(k)), ("value", os(Some(v).filter(|v| !v.is_empty()))), ("level", s(level)), ("source", os(from)),
                                          ("why", os(why))])));
    }
    let installs = tc.installs();
    out.push(format!("  installs found={}  (VC6's usual places)", installs.len()));
    let rich = c.rich()?;
    for inst in &installs {
        out.push(format!("    {}", install_text(inst, &c, rich.as_deref())));
    }
    out.push(format!("  {}", record(&[("pe_linker", s(format!("{}.{:02}", img.linker_version.0, img.linker_version.1))), ("built", s(built_at(img))),
                                      ("timestamp", s(format!("{:#010x}", img.timestamp)))])));
    let crt = c.crt_strings();
    out.push(format!("  crt strings={}", crt.len()));
    for (a, t) in &crt {
        out.push(format!("    {a:#010x} {}", crate::decl::py_repr(t)));
    }
    match &rich {
        None => out.push("  rich: no Rich header".into()),
        Some(r) => {
            let level = r.support.name();
            for key in ["compilers", "linkers"] {
                let cands = r.value.get(key).and_then(|v| v.as_array()).cloned().unwrap_or_default();
                out.push(format!("  {} candidates={}  ({level}, {})", &key[..key.len() - 1], cands.len(), r.by));
                for e in &cands {
                    let bn = tc.build_name(entry_s(e, "family"), entry_i(e, "build") as u32);
                    out.push(format!("    {}{}", candidate_entry(tc, e), if bn.is_empty() { String::new() } else { format!("  [{bn}]") }));
                }
            }
            let entries = r.value.get("entries").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            out.push(format!("  rich entries={}", entries.len()));
            for e in &entries {
                out.push(format!("    prodid={:#04x} {:<16} family={:<9} build={:<5} count={:<4} archive_objects={}", entry_i(e, "prodid"), entry_s(e, "tool"),
                                 entry_s(e, "family"), entry_i(e, "build"), entry_i(e, "count"), entry_i(e, "archive_objects")));
            }
        }
    }
    let waits = p.waiting("toolchain").map_err(err)?;
    let bad = c.c_toolchain_errors()?;
    out.push(format!("  C.toolchain: {}", if !waits.is_empty() {
        format!("waiting: {}", waits.join(", "))
    } else if bad.is_empty() {
        "ok".into()
    } else {
        format!("{} error(s)", bad.len())
    }));
    out.extend(bad.iter().map(|m| format!("    {m}")));
    let (archives, from, reason) = p.archives_decl(None).map_err(err)?;
    match archives {
        None => out.push("  archives: open (dcp libs candidates, dcp libs declare)".into()),
        Some(a) => {
            let names = a.iter().map(|x| name_of(x)).collect::<Vec<_>>().join(",");
            let waiting = p.waiting("libs").map_err(err)?.join(",");
            out.push(format!("  {}", record(&[("archives", s(if names.is_empty() { "none".into() } else { names })), ("source", s(from)),
                                              ("why", os(Some(reason).filter(|r| !r.is_empty()))),
                                              ("waiting", os(Some(waiting).filter(|w| !w.is_empty())))])));
        }
    }
    let mut members: Vec<(String, usize)> = vec![];
    for f in c.facts("unit", "S.crt.code")? {
        let lib = f.s("lib").unwrap_or("").to_string();
        match members.iter_mut().find(|(l, _)| *l == lib) {
            Some(m) => m.1 += 1,
            None => members.push((lib, 1)),
        }
    }
    let placed: Vec<String> = members.iter().map(|(k, v)| format!("{k}={v}")).collect();
    out.push(format!("  libraries placed: {}", if placed.is_empty() { "none".into() } else { placed.join("  ") }));
    if probed.is_empty() {
        out.push("  probe: not run (dcp toolchain probe): flags are declared only".into());
    }
    for f in &probed {
        let level = f.support.name();
        let g = |k: &str| json_tok(f.value.get(k).unwrap_or(&Value::Null));
        out.push(format!("  probe  {}", record(&[("flag", g("flag")), ("group", g("group")), ("anchors", g("anchors")), ("units", g("units")), ("level", s(level))])));
    }
    Ok(out)
}

/// A JSON value as a key=value token (lists joined with commas).
fn json_tok(v: &Value) -> Tok {
    match v {
        Value::Null => Tok::No,
        Value::Bool(b) => Tok::B(*b),
        Value::Number(n) => n.as_i64().map(Tok::I).unwrap_or_else(|| s(n.to_string())),
        Value::String(x) => s(x.clone()),
        Value::Array(a) => {
            let j: Vec<String> = a.iter().map(|x| crate::cliread::tok(&json_tok(x))).collect();
            Tok::S(if j.is_empty() { "-".into() } else { j.join(",") })
        }
        v => s(v.to_string()),
    }
}

// ------------------------------------------------------------------------------------------------ declarations

/// (lines, error, exit code) of a command: the error goes to stderr as `dcp CMD: error`.
type Out = (Vec<String>, Option<String>, i32);

fn refused(msg: impl Into<String>) -> Result<Out> {
    Ok((vec![], Some(msg.into()), 2))
}

fn no_why(why: &Option<String>) -> bool {
    why.as_deref().is_none_or(|w| w.trim().is_empty())
}

const NO_WHY: &str = "a declaration needs its reason: --why \"...\" (the evidence it rests on); nothing written";

/// KEY=VALUE pairs of known keys, in order (a repeated key keeps its first place).
fn parse_pairs(pairs: &[String], known: &[&str]) -> Result<Vec<(String, String)>, String> {
    let mut out: Vec<(String, String)> = vec![];
    for x in pairs {
        let Some((k, v)) = x.split_once('=') else {
            return Err(format!("{} is not KEY=VALUE (keys: {})", crate::decl::py_repr(x), known.join(", ")));
        };
        let k = k.trim();
        if !known.contains(&k) {
            return Err(format!("unknown key {} (keys: {})", crate::decl::py_repr(k), known.join(", ")));
        }
        match out.iter_mut().find(|(o, _)| o == k) {
            Some(o) => o.1 = v.trim().to_string(),
            None => out.push((k.to_string(), v.trim().to_string())),
        }
    }
    Ok(out)
}

/// The [[target]] index of the current target for the line editor (None: the single-table form).
fn target_index(p: &Project) -> Result<Option<usize>> {
    let t = p.target(None).map_err(err)?;
    Ok(if t.legacy { None } else { p.targets.iter().position(|x| x.name == t.name) })
}

fn config_path(p: &Project) -> String {
    py_path(&p.root.join(crate::project::CONFIG_NAME).to_string_lossy())
}

/// A path as Path(s).expanduser().resolve() spells it (posix).
fn resolved(path: &str) -> String {
    let path = match (path.strip_prefix('~'), std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME"))) {
        (Some(rest), Ok(home)) if rest.is_empty() || rest.starts_with(['/', '\\']) => format!("{home}{rest}"),
        _ => path.to_string(),
    };
    let abs = std::fs::canonicalize(&path).map(|c| c.to_string_lossy().into_owned()).unwrap_or(path);
    abs.trim_start_matches(r"\\?\").replace('\\', "/")
}

/// `dcp toolchain declare`: compiler= linker= cflags= (the current target's table), root= ([toolchain]), each
/// with the reason; the declared lines. `root` is the declared root when one was (the verdict after the rerun names
/// its versions).
pub fn decide_toolchain_declare(p: &crate::project::Project, pairs: Vec<String>, why: Option<String>) -> Result<(Vec<String>, Option<String>, i32, Option<String>)> {
    let r = toolchain_declare(p, &pairs, &why)?;
    Ok(r)
}

fn toolchain_declare(p: &Project, pairs: &[String], why: &Option<String>) -> Result<(Vec<String>, Option<String>, i32, Option<String>)> {
    let no = |(l, e, c): Out| (l, e, c, None);
    if no_why(why) {
        return refused(NO_WHY).map(no);
    }
    let mut kv = match parse_pairs(pairs, &TOOLCHAIN_DECL_KEYS) {
        Ok(kv) => kv,
        Err(e) => return refused(e).map(no),
    };
    if kv.is_empty() {
        return refused(format!("nothing to declare (keys: {})", TOOLCHAIN_DECL_KEYS.join(", "))).map(no);
    }
    let why = why.as_deref().unwrap_or("").trim().to_string();
    for (k, v) in kv.iter_mut() {
        if k == "root" {
            let r = resolved(v);
            if !Path::new(&r).is_dir() {
                return refused(format!("root={v}: no such directory; nothing written")).map(no);
            }
            *v = r;
        }
    }
    let path = config_path(p);
    let value = |k: &str, v: &str| if k == "cflags" { TV::L(v.split_whitespace().map(|x| x.to_string()).collect()) } else { TV::S(v.to_string()) };
    let tgt: Vec<(String, TV)> = kv.iter().filter(|(k, _)| ["compiler", "linker", "cflags"].contains(&k.as_str())).map(|(k, v)| (k.clone(), value(k, v))).collect();
    let proj: Vec<(String, TV)> = kv.iter().filter(|(k, _)| k == "root").map(|(k, v)| (k.clone(), value(k, v))).collect();
    let with_reasons = |vals: &[(String, TV)]| -> Vec<(String, TV)> {
        vals.iter().cloned().chain(vals.iter().map(|(k, _)| (format!("reason.{k}"), TV::S(why.clone())))).collect()
    };
    if !tgt.is_empty() {
        tomledit::set_keys(&path, "target", &with_reasons(&tgt), target_index(p)?, &TARGET_COVERED).map_err(err)?;
    }
    if !proj.is_empty() {
        tomledit::set_keys(&path, "toolchain", &with_reasons(&proj), None, &["root", "compiler", "linker", "cflags"]).map_err(err)?;
    }
    let mut out = vec![];
    for (k, v) in tgt.iter().chain(&proj) {
        let place = if tgt.iter().any(|(t, _)| t == k) { format!("target {}", p.target_name) } else { "[toolchain]".into() };
        let text = match v {
            TV::L(l) => l.join(" "),
            TV::S(x) => x.clone(),
            _ => String::new(),
        };
        out.push(record(&[("declared", s(k.clone())), ("value", s(text)), ("level", s("declared")), ("where", s(place)), ("why", s(why.clone()))]));
        if let TV::L(l) = v {
            out.push(format!("  flags  {}", if l.is_empty() { "-".into() } else { l.iter().map(|f| crate::decl::py_repr(f)).collect::<Vec<_>>().join(" ") }));
        }
    }
    let root = proj.iter().find(|(k, _)| k == "root").and_then(|(_, v)| if let TV::S(x) = v { Some(x.clone()) } else { None });
    Ok((out, None, 0, root))
}

/// After `dcp toolchain declare` reran the rules: the declared root's versions, C.toolchain's verdict, the status
/// tail; exit 1 when C.toolchain has errors.
pub fn decide_toolchain_after(p: &crate::project::Project, root: Option<String>) -> Result<(Vec<String>, i32)> {
    let c = Ctx::new(p)?;
    let mut out = vec![];
    if let Some(r) = root {
        let inst = c.tc.install(&r);
        let mut kv = vec![("root", s(r.clone())), ("available", Tok::B(p.toolchain_available()))];
        kv.extend(inst.versions.iter().map(|(k, v)| (*k, s(v.clone()))));
        out.push(format!("  {}", record(&kv)));
    }
    let bad = c.c_toolchain_errors()?;
    if p.waiting("toolchain").map_err(err)?.is_empty() {
        out.push(format!("C.toolchain: {}", if bad.is_empty() { "ok".into() } else { format!("{} error(s)", bad.len()) }));
        out.extend(bad.iter().map(|m| format!("  {m}")));
    }
    out.push(String::new());
    out.extend(status(&c, &mut vec![], true, false)?);
    Ok((out, if bad.is_empty() { 0 } else { 1 }))
}

/// `dcp libs declare`: the current target's static library archives (bare names are the toolchain's archives
/// under the declared root) with the reason.
pub fn decide_libs_declare(p: &crate::project::Project, archives: Vec<String>, why: Option<String>) -> Result<Out> {
    if no_why(&why) {
        return refused(NO_WHY);
    }
    let tc = crate::toolchain::Vc6;
    let specs: Vec<String> = archives.iter().map(|a| tc.archive_spec(a)).collect();
    if specs.iter().any(|x| x.contains("{toolchain.root}")) && p.toolchain_root().is_none() {
        return refused("the archives are named under the toolchain root, which is not declared yet: dcp toolchain declare root=DIR --why \"...\" first; \
                        nothing written");
    }
    let missing: Vec<String> = specs.iter().map(|x| p.expand(x)).filter(|x| !Path::new(x).exists()).map(|x| x.replace('\\', "/")).collect();
    if !missing.is_empty() {
        return refused(format!("no such archive: {}; nothing written", missing.join(", ")));
    }
    let why = why.unwrap_or_default().trim().to_string();
    tomledit::set_keys(&config_path(p), "target", &[("archives".into(), TV::L(specs.clone())), ("reason.archives".into(), TV::S(why.clone()))],
                       target_index(p)?, &TARGET_COVERED).map_err(err)?;
    let names = specs.iter().map(|x| name_of(x)).collect::<Vec<_>>().join(",");
    Ok((vec![record(&[("declared", s("archives")), ("value", s(names)), ("level", s("declared")), ("where", s(format!("target {}", p.target_name))),
                      ("why", s(why))])], None, 0))
}

/// After `dcp libs declare` reran the rules: what S.crt.code placed per archive, the status tail.
pub fn decide_libs_after(p: &crate::project::Project) -> Result<Vec<String>> {
    let c = Ctx::new(p)?;
    let mut units: BTreeMap<String, String> = BTreeMap::new();
    for f in c.facts("unit", "S.crt.code")? {
        units.insert(f.s("tu").unwrap_or("").to_string(), f.s("lib").unwrap_or("").to_string());
    }
    let mut per: BTreeMap<&str, usize> = BTreeMap::new();
    for lib in units.values() {
        *per.entry(lib.as_str()).or_default() += 1;
    }
    let placed: Vec<String> = per.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let mut out = vec![format!("  placed: {}  (S.crt.code)", if placed.is_empty() { "nothing".into() } else { placed.join("  ") }), String::new()];
    out.extend(status(&c, &mut vec![], true, false)?);
    Ok(out)
}

/// `dcp analyzer declare`: confirm or change Ghidra's installation ([analyzer] root, java_home, timeout) with the reason.
pub fn decide_analyzer_declare(p: &crate::project::Project, pairs: Vec<String>, why: Option<String>) -> Result<Out> {
    if no_why(&why) {
        return refused(NO_WHY);
    }
    let kv = match parse_pairs(&pairs, &["root", "java_home", "timeout"]) {
        Ok(kv) => kv,
        Err(e) => return refused(e),
    };
    let mut vals: Vec<(String, TV)> = vec![];
    for (k, v) in kv {
        vals.push(match k.as_str() {
            "timeout" => match v.parse::<i64>() {
                Ok(n) => (k, TV::I(n)),
                Err(_) => return refused(format!("timeout={v}: not a number of seconds; nothing written")),
            },
            _ => (k, TV::S(v.replace('\\', "/"))),
        });
    }
    let why = why.unwrap_or_default().trim().to_string();
    vals.push(("reason".into(), TV::S(why.clone())));
    tomledit::set_keys(&config_path(p), "analyzer", &vals, None, &[]).map_err(err)?;
    let p = Project::open(&p.root, Some(&p.target_name), &p.core_hash).map_err(crate::project::cfg_err)?;
    let inst = crate::analyzers::Analyzer::of(&p).map_err(crate::project::cfg_err)?.available();
    let mut out = vec![record(&[("declared", s("analyzer")), ("value", s(crate::analyzers::NAME)), ("level", s("declared")), ("where", s("[analyzer]")), ("why", s(why)),
                                ("available", Tok::B(inst.ok())), ("at", if inst.ok() { s(inst.at.clone()) } else { Tok::No })])];
    if let Some(r) = &inst.reason {
        out.push(format!("  {}", record(&[("unavailable", s(r.clone()))])));
    }
    Ok((out, None, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_like_textwrap() {
        let first = "    seen  ";
        let text = "installs found: C:/VC/Studio-6.0 (cl 12.00.8804 c2 12.00.9782 link 6.00.8447; makes a Rich linker (8447)); \
                    C:/VC/Studio-6.0-SP5PP (cl 12.00.8804 c2 13.00.9044 link 6.00.8447; makes a Rich compiler (9044) and a Rich linker (8447))";
        assert_eq!(fill(text, 100, first), [
            "    seen  installs found: C:/VC/Studio-6.0 (cl 12.00.8804 c2 12.00.9782 link 6.00.8447; makes a Rich",
            "          linker (8447)); C:/VC/Studio-6.0-SP5PP (cl 12.00.8804 c2 13.00.9044 link 6.00.8447; makes",
            "          a Rich compiler (9044) and a Rich linker (8447))",
        ]);
        // hyphenated words break after a hyphen between letters; a word longer than the line breaks anywhere
        assert_eq!(fill("aaaa bbbb-cccc", 12, ""), ["aaaa bbbb-", "cccc"]);
        assert_eq!(fill("abcdefghij", 4, ""), ["abcd", "efgh", "ij"]);
        assert_eq!(fill("ab-cdefgh", 5, ""), ["ab-cd", "efgh"]);
        assert_eq!(fill("x  y -- z --w a--b see-saw-it", 6, ""), ["x  y", "-- z", "--w a", "--b", "see-", "saw-it"]);
        assert_eq!(fill("one two", 3, ""), ["one", "two"]);
        assert!(fill("", 10, "x").is_empty());
    }

    #[test]
    fn pieces() {
        assert_eq!(utc_date(0x3f7a8411), "2003-10-01");
        assert_eq!(utc_date(0), "1970-01-01");
        assert_eq!(utc_date(951782400), "2000-02-29");
        assert_eq!(declared_build("cl 12.00.9044"), Some(9044));
        assert_eq!(declared_build(""), None);
        assert_eq!(parse_pairs(&["a=1".into(), "b = 2".into(), "a=3".into()], &["a", "b"]).unwrap(), [("a".to_string(), "3".to_string()), ("b".into(), "2".into())]);
        assert_eq!(parse_pairs(&["x".into()], &["a"]).unwrap_err(), "'x' is not KEY=VALUE (keys: a)");
        assert_eq!(parse_pairs(&["c=1".into()], &["a", "b"]).unwrap_err(), "unknown key 'c' (keys: a, b)");
        assert_eq!(json_line(&[("a", J::S("é\"".into())), ("b", J::I(3)), ("c", J::Null)]), r#"{"a": "\u00e9\"", "b": 3, "c": null}"#);
    }
}
