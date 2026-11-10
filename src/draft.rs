//! `dcp draft ADDR`: the first source of a function, written from what the ledger knows, into its unit's file
//! src/<unit>.c (created with its head when the unit has none) in address order: before the address comment of the
//! unit's next function of the target, else at the end of the file.
//!
//! The function:
//!   comment  the address comment `/* 0x10001234, <name> */` directly above it (a target other than the default:
//!            `<target>:0x...` and the definition under `#if defined(DCP_TARGET_<target>)`)
//!   body     Ghidra's pseudocode of the function (`dcp setup` runs the export), its signature on one line, every name
//!            rewritten by the rules below; a function without a Ghidra draft is refused
//! The name: the one the ledger registers for the address from a declaration, an export or the user entry, else the
//! placeholder `<unit>_<addr>` (8 hex digits; L5 checks that it spells a start, Q1 that it gets replaced).
//!
//! Ghidra's pseudocode comes in (ghidra.rs), VC6's language goes out (Vc6 keywords / sized_conventions /
//! import_header, the declaring header of a C library function).
//!
//! Names inside an analyzer's body:
//!   the function itself        its name above
//!   a function it names        the ledger's name for the address, else the placeholder `<unit>_<addr>` of the unit
//!                              the address lies in, else `unk_<addr>`
//!   a data label of its own    the ledger's name for the address when the sources, a declaration or a library
//!                              member name it, else `DAT_<hex>`
//! Every other spelling of the drafted function's address in src/ and include/ (a placeholder another draft wrote
//! before) is renamed to its name at the same time, so one address has one name in the sources.
//!
//! Declarations (appended, never duplicated; edit.rs), for every name the body uses that has an address:
//!   include/<unit>.h        the drafted function's prototype; `#include "<types header>"` when the prototype is
//!                           the analyzer's (its type names)
//!   the unit's head region  `#include "<types header>"` (before the unit's header) for an analyzer's body, written
//!                           to include/ when missing; then per name:
//!     an import (a thunk or an import slot)   the system header that declares it (the toolchain's import header)
//!     a C library function                    the system header that declares it
//!     a name another unit's header declares   `#include "<that unit>.h"`
//!     any other function                      in the head's dcp block: a K&R declaration with the analyzer's return
//!                                             type, its whole prototype for a convention whose decorated name needs
//!                                             the parameters, `int name();` without a draft
//!     a datum                                 in the head's dcp block: `extern <type> <name>;`, the type from the
//!                                             spelling of the analyzer's label, else its unknown data type
//! When a function is drafted, the declarations of its name in the dcp blocks are removed.

use crate::error::{Error, Result};
use crate::cliread::{fmt_addr, record, Tok};
use crate::edit as E;
use crate::layoutview::View;
use crate::names::Names;
use crate::project::{py_path, Project};
use regex::Regex;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{LazyLock, Mutex};

const C_KEYWORDS: &[&str] = &["if", "while", "for", "switch", "return", "sizeof", "do", "else", "case", "default", "goto", "break", "continue",
                              "typedef", "struct", "union", "enum", "static", "extern", "const", "volatile", "register", "auto", "unsigned",
                              "signed", "int", "char", "short", "long", "float", "double", "void"];
const CANONICAL: &[&str] = &["decl", "export", "entry"];

static IDENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b[A-Za-z_]\w*\b").unwrap());
static COMMENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)/\*.*?\*/").unwrap());
static TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?s)"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|//[^\n]*|/\*.*?\*/"#).unwrap());

fn err(e: impl std::fmt::Display) -> Error {
    Error::runtime(e.to_string())
}

/// An analyzer's stored draft of one function.
struct Entry {
    start: i64,
    name: String,
    body: String,
    requested: i64,
    source: String,
    analyzer: String,
}

fn entry_of(v: &Value) -> Entry {
    let start = v["start"].as_i64().unwrap_or(0);
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    Entry { start, name: s("name"), body: s("body"), requested: v.get("requested").and_then(|x| x.as_i64()).unwrap_or(start), source: s("source"),
            analyzer: s("analyzer") }
}

fn placeholder(unit: &str, a: i64) -> String {
    format!("{}_{a:08x}", E::c_name(unit))
}

/// What a draft reads of the project.
struct Ctx<'a> {
    p: &'a Project,
    root: String,
    v: View,
    names: Names,
    tc: crate::toolchain::Vc6,
    entries: BTreeMap<i64, Entry>,
    labels: BTreeMap<String, i64>,
}

impl Ctx<'_> {
    fn name(&self, a: i64) -> Option<&str> {
        self.names.name_of(a)
    }

    fn origin(&self, a: i64) -> Option<&str> {
        self.names.origin_of(a).map(|o| o.name())
    }

    fn unit_at(&self, a: i64) -> Option<&crate::layout::Unit> {
        self.v.unit_index(a).map(|i| &self.v.units[i])
    }

    fn is_start(&self, a: i64) -> bool {
        self.v.starts.contains_key(&a) || self.v.funcs.iter().any(|f| f.lo == a) || self.v.symbol_kind(a).as_deref() == Some("thunk")
    }

    /// The name a new draft defines (module docs).
    fn function_name(&self, unit: &str, a: i64) -> String {
        match (self.name(a), self.origin(a)) {
            (Some(n), Some(o)) if CANONICAL.contains(&o) => n.to_string(),
            _ => placeholder(unit, a),
        }
    }

    /// How a draft spells a function at a.
    fn callee_name(&self, a: i64) -> String {
        if let Some(n) = self.name(a) {
            return n.to_string();
        }
        match self.unit_at(a) {
            Some(u) => placeholder(&u.tu, a),
            None => format!("unk_{a:08x}"),
        }
    }

    fn data_name(&self, a: i64) -> String {
        match (self.name(a), self.origin(a)) {
            (Some(n), Some("source" | "decl" | "lib")) => n.to_string(),
            _ => format!("DAT_{a:08x}"),
        }
    }

    /// (an analyzer's pseudocode with every name rewritten, {used name: (address, a function, data type)}).
    fn rewrite_body(&self, e: &Entry, own: &str) -> (String, BTreeMap<String, (i64, bool, String)>) {
        let types = crate::ghidra::data_labels(&e.body);
        let out = crate::ghidra::rewrite(&e.body, (&e.name, own), &|a| self.callee_name(a), &|a| self.data_name(a), &self.labels);
        let keywords: Vec<&str> = C_KEYWORDS.iter().chain(self.tc.keywords()).copied().collect();
        let mut uses: BTreeMap<String, (i64, bool, String)> = BTreeMap::new();
        let (_, body) = split(&out);
        let code = TOKEN.replace_all(&body, " ");
        for m in IDENT.find_iter(&code) {
            let n = m.as_str();
            if keywords.contains(&n) || n == own || uses.contains_key(n) {
                continue;
            }
            let hit = self.names.addrs_of(n).first().copied();
            let Some(a) = hit.or_else(|| crate::srcscan::placeholder_whole(n).map(|v| v as i64)) else { continue };
            uses.insert(n.to_string(), (a, self.is_start(a), types.get(&a).cloned().unwrap_or_else(|| "undefined4".to_string())));
        }
        (out, uses)
    }

    /// The return type of a signature (without the calling convention).
    fn return_type(&self, sig: &str, name: &str) -> String {
        let call = format!("{name}(");
        let mut before = match sig.split_once(&call) {
            Some((b, _)) => b.to_string(),
            None => {
                let b = sig.split('(').next().unwrap_or("");
                b.rsplit_once(' ').map(|x| x.0).unwrap_or(b).to_string()
            }
        };
        for conv in std::iter::once("__cdecl").chain(self.tc.sized_conventions().iter().copied()) {
            if !conv.is_empty() {
                before = Regex::new(&format!(r"\b{}\b", regex::escape(conv))).unwrap().replace_all(&before, "").into_owned();
            }
        }
        let t = before.split_whitespace().collect::<Vec<_>>().join(" ");
        if t.is_empty() { "int".into() } else { t }
    }
}

/// (the signature on one line without the analyzer's comments before it, the body from its opening brace on).
fn split(text: &str) -> (String, String) {
    let (head, body) = match text.find('{') {
        Some(i) => (&text[..i], &text[i..]),
        None => (text, ""),
    };
    (COMMENT.replace_all(head, " ").split_whitespace().collect::<Vec<_>>().join(" "), body.to_string())
}

/// The analyzer's comments before the signature, each for a line of its own.
fn lead_comments(text: &str) -> Vec<String> {
    let head = text.split('{').next().unwrap_or("");
    COMMENT.find_iter(head).map(|m| m.as_str().split_whitespace().collect::<Vec<_>>().join(" ")).collect()
}

/// name -> the declaring header (lower case) of every C library function of the toolchain's system headers, the
/// standard headers first, then alphabetical; parsed once per set of directories (an installation does not change).
fn declaring_header(p: &Project, tc: &crate::toolchain::Vc6, name: &str) -> Option<String> {
    static MEMO: LazyLock<Mutex<HashMap<Vec<String>, HashMap<String, String>>>> = LazyLock::new(Default::default);
    let dirs = crate::frontend::system_dirs(p);
    let mut memo = MEMO.lock().unwrap();
    if !memo.contains_key(&dirs) {
        let std_h = tc.standard_headers();
        let mut headers: Vec<String> = dirs.iter().flat_map(|d| std::fs::read_dir(d).into_iter().flatten().flatten())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.to_lowercase().ends_with(".h")).collect();
        headers.sort();
        headers.dedup();
        headers.sort_by_key(|n| (!std_h.contains(&n.to_lowercase().as_str()), n.to_lowercase()));
        let lib = crate::frontend::library(Some(&p.cfg)).or_else(|| crate::frontend::library(None));
        let idx = match lib {
            Some(l) if !headers.is_empty() && crate::clang::load(&l).is_ok() => {
                let mut args: Vec<String> = crate::frontend::ARGS.iter().map(|s| s.to_string()).collect();
                for d in &dirs {
                    args.push("-isystem".into());
                    args.push(d.clone());
                }
                crate::clang::clang_function_headers(args, headers).map(|v| v.into_iter().collect()).unwrap_or_default()
            }
            _ => HashMap::new(),
        };
        memo.insert(dirs.clone(), idx);
    }
    memo[&dirs].get(name).cloned()
}

struct Draft {
    unit: String,
    name: String,
    file: String,
    source: String,
    renamed: BTreeMap<String, String>,
    declared: Vec<String>,
    uses: usize,
}

/// Write the function at a into its unit's file (module docs); Err(message) when there is nothing to draft.
fn draft(x: &Ctx, a: i64, unit: Option<&str>) -> Result<Result<Draft, String>> {
    let root = &x.root;
    let u = x.unit_at(a);
    if let (Some(want), Some(u)) = (unit, u) {
        if u.tu != want {
            return Ok(Err(format!("{a:#x} lies in unit {} ({:#x}..{:#x}), not in {want}", u.tu, u.lo, u.hi)));
        }
    }
    let tu = match (u, unit) {
        (Some(u), _) => u.tu.clone(),
        (None, Some(w)) => w.to_string(),
        (None, None) => return Ok(Err(format!("{a:#x} lies in no unit: declare one first (dcp unit new NAME --range LO..HI --by ... --why ...)"))),
    };
    if let Some(s) = x.v.sources.get(&a) {
        return Ok(Err(format!("{a:#x} is drafted already: {}", s.s("file").unwrap_or(""))));
    }
    if !(x.v.starts.contains_key(&a) || x.v.funcs.iter().any(|f| f.lo == a)) {
        return Ok(Err(format!("no function starts at {a:#x} (dcp layout starts; declare one with `ADDR start -- why`)")));
    }
    let name = x.function_name(&tu, a);
    let rel = format!("src/{tu}.c");
    let head = py_path(&format!("{root}/{rel}"));
    let header = py_path(&format!("{root}/include/{tu}.h"));
    let Some(e) = x.entries.get(&a).filter(|e| !e.body.trim().is_empty()) else {
        return Ok(Err(format!("no Ghidra draft at {a:#x}: dcp setup runs Ghidra's export (dcp draft --show {a:#x})")));
    };
    let mut d = Draft { unit: tu.clone(), name: name.clone(), file: rel.clone(), source: e.analyzer.clone(), renamed: BTreeMap::new(), declared: vec![], uses: 0 };
    if !Path::new(&head).exists() {
        E::write(&head, &format!("/* {tu}: the unit's includes, local types and declarations, then its functions */\n#include \"{tu}.h\"\n")).map_err(err)?;
    }
    if !Path::new(&header).exists() {
        E::write(&header, &E::header_text(&tu, "")).map_err(err)?;
    }
    // one address, one name: earlier placeholders of this address follow
    let scan = crate::frontend::scan(root, None).map_err(err)?;
    let olds: std::collections::BTreeSet<String> = scan.parts.iter().flat_map(|p| p.placeholders.iter())
        .filter(|ph| ph.3 as i64 == a && ph.2 != name).map(|ph| ph.2.clone()).collect();
    if !olds.is_empty() {
        d.renamed = olds.into_iter().map(|o| (o, name.clone())).collect();
        E::rename_words(root, &d.renamed, false, None).map_err(err)?;
    }
    let mut cs: Vec<String> = std::fs::read_dir(py_path(&format!("{root}/src"))).into_iter().flatten().flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| n.ends_with(".c")).collect();
    cs.sort();
    for f in cs {
        if E::drop_declarations(&py_path(&format!("{root}/src/{f}")), &name).map_err(err)? {
            d.declared.push(format!("dropped the declaration of {name} from src/{f}'s dcp block"));
        }
    }
    let default = x.p.target_name.clone();
    let target = x.p.target_name.clone();
    let tag = if target == default { fmt_addr(a) } else { format!("{target}:{}", fmt_addr(a)) };
    let (text, uses) = x.rewrite_body(e, &name);
    let (sig, body) = split(&text);
    let lead: String = lead_comments(&text).iter().map(|c| format!("{c}\n")).collect();
    let block = format!("/* {tag}, {name} */\n{lead}{sig}\n{}\n", body.trim_matches('\n'));
    d.uses = uses.len();
    let next = scan.functions().filter(|f| f.0 .0 == rel)
        .filter_map(|f| f.0 .4.iter().find(|(t, _)| t.as_deref().unwrap_or(&default) == target).map(|(_, x)| (*x as i64, f.1 .3)))
        .filter(|(x, _)| *x > a).min().map(|m| m.1);
    E::insert_function(&head, &block, next).map_err(err)?;
    let end = E::head_end(root, &rel).map_err(err)?;
    E::ensure_include(&head, &format!("#include \"{tu}.h\""), Some(end)).map_err(err)?;
    if E::add_to_header(&header, &tu, &format!("{sig};"), &name).map_err(err)? {
        d.declared.push(format!("include/{tu}.h: {sig};"));
    }
    let include = ensure_types_header(root, &head, &rel, &tu, crate::ghidra::GHIDRA_HEADER, &mut d, end).map_err(err)?;
    if E::ensure_after_guard(&header, &tu, &include).map_err(err)? {
        d.declared.push(format!("include/{tu}.h: {include}"));
    }
    declare_uses(x, &head, &rel, &tu, &uses, &mut d, end)?;
    Ok(Ok(d))
}

/// include/<the analyzer's types header> (written again when it differs: the file is dcp's, not the project's) and
/// its #include in the unit's head (its first `end` lines) before the unit's own header; the #include line.
fn ensure_types_header(root: &str, head: &str, rel: &str, unit: &str, shipped: (&str, &str), d: &mut Draft, end: usize) -> Result<String, String> {
    let (name, want) = shipped;
    let line = format!("#include \"{name}\"");
    let dh = py_path(&format!("{root}/include/{name}"));
    let have = Path::new(&dh).exists();
    if !have || std::fs::read_to_string(&dh).map(|t| t.replace("\r\n", "\n")).unwrap_or_default() != want {
        d.declared.push(format!("{} include/{name} (the analyzer's type names)", if have { "updated" } else { "wrote" }));
        E::write(&dh, want)?;
    }
    let text = std::fs::read_to_string(head).map_err(|e| e.to_string())?.replace("\r\n", "\n");
    if !text.contains(&line) {
        let own = format!("#include \"{unit}.h\"");
        let mut lines: Vec<String> = E::splitlines(&text).into_iter().map(|l| l.to_string()).collect();
        match lines[..end.min(lines.len())].iter().position(|l| l.trim() == own) {
            None => {
                E::ensure_include(head, &line, Some(end))?;
            }
            Some(at) => {
                lines.insert(at, line.clone());
                E::write(head, &(lines.join("\n") + "\n"))?;
            }
        }
        d.declared.push(format!("{rel}: {line}"));
    }
    Ok(line)
}

/// The unit header of include/ that declares `name` (its own unit's first): a function or data declaration of the
/// front end's model of the header.
fn header_declaring(root: &str, name: &str, unit: &str) -> Result<Option<String>> {
    let skip = [crate::ghidra::GHIDRA_HEADER.0];
    let mut hs: Vec<String> = std::fs::read_dir(py_path(&format!("{root}/include"))).into_iter().flatten().flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| n.to_lowercase().ends_with(".h")).collect();
    hs.sort_by_key(|h| (h[..h.len() - 2] != *unit, h.clone()));
    let scan = crate::frontend::scan(root, None).map_err(err)?;
    for h in hs {
        if skip.contains(&h.as_str()) {
            continue;
        }
        if let Some(m) = scan.models.get(&format!("include/{h}")) {
            let declares = m.decls.iter().any(|d| match d {
                crate::clang::Decl::F(n, ..) | crate::clang::Decl::V(n, ..) => n == name,
            });
            if declares {
                return Ok(Some(h));
            }
        }
    }
    Ok(None)
}

/// The includes and declarations the names of a draft need (module docs), in the unit's head (its first `end` lines).
fn declare_uses(x: &Ctx, head: &str, rel: &str, unit: &str, uses: &BTreeMap<String, (i64, bool, String)>, d: &mut Draft, end: usize) -> Result<()> {
    let sized: Vec<Regex> = x.tc.sized_conventions().iter().map(|c| Regex::new(&format!(r"\b{}\b", regex::escape(c))).unwrap()).collect();
    let include = |line: String, d: &mut Draft| -> Result<()> {
        if E::ensure_include(head, &line, Some(end)).map_err(err)? {
            d.declared.push(format!("{rel}: {line}"));
        }
        Ok(())
    };
    for (n, (a, func, dtype)) in uses {
        let imported = x.origin(*a) == Some("import") || matches!(x.v.symbol_kind(*a).as_deref(), Some("thunk" | "iat"));
        if imported {
            if let Some(h) = x.tc.import_header("") {
                include(format!("#include <{h}>"), d)?;
            }
            continue;
        }
        if *func {
            if let Some(h) = declaring_header(x.p, &x.tc, n) {
                include(format!("#include <{h}>"), d)?;
                continue;
            }
        }
        if let Some(hdr) = header_declaring(&x.root, n, unit)? {
            if hdr != format!("{unit}.h") {
                include(format!("#include \"{hdr}\""), d)?;
            }
            continue;
        }
        let decl = if *func {
            match x.entries.get(a).filter(|e| !e.body.trim().is_empty()) {
                Some(e) => {
                    let (sig, _) = split(&x.rewrite_body(e, n).0);
                    if sized.iter().any(|r| r.is_match(&sig)) { format!("{sig};") } else { format!("{} {n}();", x.return_type(&sig, n)) }
                }
                None => format!("int {n}();"),
            }
        } else if dtype == "char []" {
            format!("extern char {n}[];")
        } else {
            format!("extern {dtype} {n};")
        };
        if E::add_declaration(head, &decl, n, Some(end)).map_err(err)? {
            d.declared.push(format!("{rel}: {decl}"));
        }
    }
    Ok(())
}

fn open<'a>(p: &'a Project) -> Result<Ctx<'a>> {
    let db = p.store_path();
    crate::storedb::st_open(&db)?;
    let image = p.target.path.clone();
    let v = View::load(&db, &image)?;
    let names = Names::build(&db, &image)?;
    let tc = crate::toolchain::Vc6;
    let all = crate::with_db(&db, |c| crate::names::draft_values(c))?;
    let entries: BTreeMap<i64, Entry> = all.iter().map(|v| (v["start"].as_i64().unwrap_or(0), entry_of(v))).collect();
    let labels: BTreeMap<String, i64> = entries.values().filter(|e| !e.name.is_empty()).map(|e| (e.name.clone(), e.start)).collect();
    Ok(Ctx { p, root: p.root.to_string_lossy().into_owned(), v, names, tc, entries, labels })
}

/// `dcp draft [ADDR|--next] [--unit U]` and `--show`: (the lines, the error for stderr, the exit status).
#[allow(clippy::too_many_arguments)]
pub fn draft_command(p: &crate::project::Project, addr: Option<String>, next: bool, show: bool, unit: Option<String>)
    -> Result<(Vec<String>, Option<String>, i32)> {
    let x = open(p)?;
    let resolve = |s: &str| crate::cliread::resolve_key(p, s);
    if show {
        let Some(addr) = addr else { return Ok((vec![], Some("--show needs ADDR".into()), 1)) };
        let Some(a) = resolve(&addr)? else { return Ok((vec![], Some(format!("{addr}: no such address or name")), 1)) };
        let mut e = x.entries.get(&a);
        if e.is_none() {
            let db = p.store_path();
            let f = crate::with_db(&db, |c| crate::store::claims_of(c, &db, "symbol", None, |f| f.lo <= a && a < f.hi.max(f.lo + 1) && f.s("skind") == Some("func")))?;
            if let Some(f) = f.iter().next() {
                e = x.entries.get(&f.lo);
            }
        }
        let Some(e) = e else {
            return Ok((vec![format!("no draft at {} (dcp setup runs Ghidra's export)", fmt_addr(a))], None, 1));
        };
        let mut out = vec![format!("/* {} draft of {} {} (requested {}, from {}) */", e.analyzer, fmt_addr(e.start), e.name, fmt_addr(e.requested), e.source)];
        out.extend(e.body.strip_suffix('\n').unwrap_or(&e.body).split('\n').map(|l| l.to_string()));
        return Ok((out, None, 0));
    }
    let a = if next {
        match x.v.first_open_item() {
            None => return Ok((vec!["nothing to draft: every function of the game code has a source".into()], None, 0)),
            Some((a, "unknown", size)) => {
                return Ok((vec![], Some(format!("the next open item {a:#x} is unknown code ({size} bytes) no start explains: declare a start \
                                                 (`dcp decl add \"{a:#x} start -- why\"`) or dead bytes (`..END bytes dead -- why`)")), 1));
            }
            Some((a, _, _)) => a,
        }
    } else {
        let Some(addr) = addr else { return Ok((vec![], Some("ADDR or --next".into()), 1)) };
        match resolve(&addr)? {
            Some(a) => a,
            None => return Ok((vec![], Some(format!("{addr}: no such address or name")), 1)),
        }
    };
    let d = match draft(&x, a, unit.as_deref())? {
        Ok(d) => d,
        Err(e) => return Ok((vec![], Some(e), 1)),
    };
    if !d.renamed.is_empty() {
        let events: Vec<(Option<i64>, &str, String, String)> = d.renamed.iter().map(|(o, n)| (Some(a), "func", o.clone(), n.clone())).collect();
        E::log_names(&x.root, &events, &format!("drafted at {}", fmt_addr(a))).map_err(err)?;
    }
    let size = x.v.funcs.iter().find(|f| f.lo == a).map(|f| f.hi - f.lo);
    let mut out = vec![record(&[("drafted", Tok::I(a)), ("name", Tok::S(d.name.clone())), ("unit", Tok::S(d.unit.clone())), ("file", Tok::S(d.file.clone())),
                                ("body", Tok::S(d.source.clone())), ("size", size.map(Tok::I).unwrap_or(Tok::No)), ("uses", Tok::I(d.uses as i64))])];
    for (o, n) in &d.renamed {
        out.push(format!("  renamed {o} -> {n}"));
    }
    for s in &d.declared {
        out.push(format!("  {s}"));
    }
    out.push(format!("next: dcp build, dcp grade {}", d.unit));
    Ok((out, None, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An analyzer's comments before the signature go on lines of their own: a comment on the signature's line hides
    /// the definition from the scan.
    #[test]
    fn signature_and_lead_comments() {
        let text = "/* WARNING: Removing unreachable block */\n/* WARNING:   two\n   lines */\nint __cdecl f(int a)\n{\n  return a;\n}\n";
        let (sig, body) = split(text);
        assert_eq!(sig, "int __cdecl f(int a)");
        assert!(body.starts_with("{\n  return a;"));
        assert_eq!(lead_comments(text), ["/* WARNING: Removing unreachable block */", "/* WARNING: two lines */"]);
    }

    #[test]
    fn crlf_drafts() {
        let text = "\r\n/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */\r\n\r\nvoid f(int a)\r\n\r\n{\r\n  return;\r\n}\r\n";
        assert_eq!(split(text).0, "void f(int a)");
        assert_eq!(lead_comments(text), ["/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */"]);
    }
}
