//! The full link of a target (build/link.py is its face; its module docstring states what goes in and how the
//! unresolved externals are classified): every object of the target through the toolchain's linker.

use crate::fsmemo;
use crate::project::{py_path, sha256_parts, Project};
use crate::store::{self, canon, SFact};
use crate::vc6::{LinkJob, Tools};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;

pub const CLASSES: [&str; 6] = ["data", "renames", "aliases", "undrafted", "library", "other"];

#[derive(Default)]
pub struct LinkReport {
    pub target: String,
    pub ok: bool,
    pub skipped: String,
    pub objects: usize,
    pub includes: usize,
    pub unresolved: Vec<(String, Vec<String>)>, // class -> lines, in CLASSES order
    pub errors: Vec<String>,
    pub notes: Vec<String>,
    pub out: String,
    pub cached: bool,
    pub ms: i64,
}

fn name_of(p: &str) -> String {
    Path::new(p).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

fn file_digest(p: &str) -> String {
    match std::fs::read(p) {
        Ok(d) => fsmemo::hex(&<sha2::Sha256 as sha2::Digest>::digest(&d)),
        Err(_) => "missing".into(),
    }
}

/// json.dumps of a list of strings (Python's default spelling: `", "` between items, non-ASCII escaped).
fn py_json_list(xs: &[String]) -> String {
    let item = |s: &str| {
        let mut o = String::from("\"");
        for c in s.chars() {
            match c {
                '"' => o.push_str("\\\""),
                '\\' => o.push_str("\\\\"),
                '\n' => o.push_str("\\n"),
                '\r' => o.push_str("\\r"),
                '\t' => o.push_str("\\t"),
                c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                    let mut b = [0u16; 2];
                    for u in c.encode_utf16(&mut b) {
                        o.push_str(&format!("\\u{:04x}", u));
                    }
                }
                c => o.push(c),
            }
        }
        o.push('"');
        o
    };
    format!("[{}]", xs.iter().map(|s| item(s)).collect::<Vec<_>>().join(", "))
}

struct Ctx<'a> {
    p: &'a Project,
    root: String,
    db: String,
    img: Rc<crate::pe::Image>,
    tools: Tools,
}

impl Ctx<'_> {
    fn facts(&self, kind: &str) -> Result<Vec<Rc<SFact>>, String> {
        crate::with_db(&self.db, |c| store::facts_of(c, &self.db, kind, None, |_| true)).map_err(|e| e.to_string())
    }

    /// Where an archive of the link may come from: the project's libs/, then the toolchain's library directories.
    fn library_dirs(&self) -> Vec<String> {
        let mut v = vec![py_path(&format!("{}/libs", self.root))];
        v.extend(self.tools.lib_path());
        v
    }

    fn find_library(&self, name: &str) -> Option<String> {
        for d in self.library_dirs() {
            for c in [format!("{d}\\{name}"), format!("{d}\\{}", name.to_uppercase())] {
                if Path::new(&c).exists() {
                    return Some(c);
                }
            }
            if let Ok(rd) = std::fs::read_dir(&d) {
                for e in rd.flatten() {
                    if e.file_name().to_string_lossy().to_lowercase() == name.to_lowercase() {
                        return Some(py_path(&e.path().to_string_lossy()));
                    }
                }
            }
        }
        None
    }

    /// The public symbols of an archive (its first linker member), kept by its content hash in the store.
    fn archive_symbols(&self, path: &str) -> Result<HashSet<String>, String> {
        let h = fsmemo::sha256(path).map_err(|e| e.to_string())?;
        let key = sha256_parts(&["archive.symbols", "1", &h]);
        let hit: Option<Vec<String>> = crate::with_db(&self.db, |c| {
            use rusqlite::OptionalExtension;
            c.query_row("SELECT data FROM blob WHERE hash=?", [&key], |r| r.get::<_, Vec<u8>>(0)).optional()
        }).map_err(|e| e.to_string())?.and_then(|d| serde_json::from_slice(&d).ok());
        let names = match hit {
            Some(n) => n,
            None => {
                let data = fsmemo::read_bytes(path).map_err(|e| e.to_string())?;
                let n: BTreeSet<String> = crate::coff::archive_symbol_table(&data).unwrap_or_default().into_iter().collect();
                let n: Vec<String> = n.into_iter().collect();
                let mut s = String::new();
                canon(&mut s, &json!(n));
                crate::with_db(&self.db, |c| c.execute("INSERT OR IGNORE INTO blob (hash, kind, data) VALUES (?, 'archive.symbols', ?)",
                                                       rusqlite::params![key, s.as_bytes()]).map(|_| ())).map_err(|e| e.to_string())?;
                n
            }
        };
        Ok(names.into_iter().collect())
    }

    /// symbol -> the archives (*.lib directly in library_dirs, in search order) whose symbol table defines it, of the
    /// archives the target does not declare.
    fn undeclared_definers(&self, names: &[String]) -> Result<HashMap<String, Vec<String>>, String> {
        let mut out: HashMap<String, Vec<String>> = HashMap::new();
        if names.is_empty() {
            return Ok(out);
        }
        let canon_path = |p: &str| crate::vc6::resolved("", p).to_lowercase();
        let declared: HashSet<String> = self.p.lib_archives(None).unwrap_or_default().iter().map(|a| canon_path(a)).collect();
        let want: HashSet<&String> = names.iter().collect();
        let mut seen = HashSet::new();
        for d in self.library_dirs() {
            if !Path::new(&d).is_dir() {
                continue;
            }
            let mut files: Vec<PathBuf> = std::fs::read_dir(&d).into_iter().flatten().flatten().map(|e| e.path()).collect();
            files.sort_by_key(|x| name_of(&x.to_string_lossy()).to_lowercase());
            for p in files {
                if !p.extension().is_some_and(|x| x.eq_ignore_ascii_case("lib")) || !p.is_file() {
                    continue;
                }
                let ps = py_path(&p.to_string_lossy());
                let rp = canon_path(&ps);
                if declared.contains(&rp) || !seen.insert(rp) {
                    continue;
                }
                let syms = self.archive_symbols(&ps)?;
                for n in want.iter().filter(|n| syms.contains(n.as_str())) {
                    out.entry((*n).clone()).or_default().push(ps.clone());
                }
            }
        }
        Ok(out)
    }

    /// The six classes of the unresolved externals, one line per symbol.
    fn classify(&self, unresolved: &[String]) -> Result<Vec<(String, Vec<String>)>, String> {
        let starts: HashSet<i64> = self.facts("start")?.iter().map(|f| f.lo).collect();
        let names = self.facts("name")?;
        let mut registered: HashMap<String, BTreeSet<i64>> = HashMap::new();
        for f in &names {
            if matches!(f.s("origin"), Some("decl" | "export" | "entry")) {
                registered.entry(f.s("name").unwrap_or("").to_string()).or_default().insert(f.lo);
            }
        }
        let (mut data_names, mut func_at): (HashSet<String>, HashMap<i64, String>) = (HashSet::new(), HashMap::new());
        for f in self.facts("source")?.iter().filter(|f| &*f.rule == "L.src") {
            match f.s("what") {
                Some("func") => {
                    func_at.insert(f.lo, f.s("symbol").unwrap_or("").to_string());
                }
                Some("data") => {
                    data_names.insert(f.s("symbol").unwrap_or("").to_string());
                }
                _ => {}
            }
        }
        let (mut name_at, mut data_at): (HashMap<String, BTreeSet<i64>>, HashMap<i64, String>) = (HashMap::new(), HashMap::new());
        for f in names.iter().filter(|f| &*f.rule == "L.src") {
            let n = f.s("name").unwrap_or("").to_string();
            name_at.entry(n.clone()).or_default().insert(f.lo);
            if !func_at.contains_key(&f.lo) {
                data_at.entry(f.lo).or_insert(n);
            }
        }
        let src = self.p.input_hash("src")?.unwrap_or_default();
        let scan = crate::frontend::scan(&self.root, Some(&src))?;
        for part in &scan.parts {
            data_names.extend(part.data.iter().map(|d| d.3.clone()));
        }
        let mut out: BTreeMap<&str, Vec<String>> = CLASSES.iter().map(|c| (*c, vec![])).collect();
        let mut rest: Vec<(String, Vec<i64>)> = vec![];
        for u in unresolved {
            let cn = crate::coff::undecorate(u);
            let mut addrs: BTreeSet<i64> = name_at.get(&cn).cloned().unwrap_or_default();
            if let Some(v) = crate::srcscan::placeholder_whole(&cn) {
                addrs.insert(v as i64);
            }
            if let Some(&a) = addrs.iter().find(|a| func_at.get(a).is_some_and(|n| *n != cn)) {
                out.get_mut("renames").unwrap().push(format!("{u}  ->  {}  ({a:#010x})", func_at[&a]));
                continue;
            }
            if let Some(&a) = addrs.iter().find(|a| data_at.get(a).is_some_and(|n| *n != cn)) {
                out.get_mut("aliases").unwrap().push(format!("{u}  ->  {}  ({a:#010x})", data_at[&a]));
                continue;
            }
            if addrs.is_empty() {
                if let Some(r) = registered.get(&cn) {
                    addrs = r.clone();
                }
            }
            let open_at: Vec<i64> = addrs.iter().copied().filter(|a| {
                !func_at.contains_key(a) && !data_at.contains_key(a)
                    && self.img.section_of(*a as u32).is_some_and(|s| starts.contains(a) || !s.holds_code())
            }).collect();
            if let Some(&a) = open_at.first() {
                let what = if starts.contains(&a) { "no source" } else { "no definition" };
                out.get_mut("undrafted").unwrap().push(format!("{u}  ({what} at {a:#010x} yet)"));
                continue;
            }
            if data_names.contains(&cn) {
                out.get_mut("data").unwrap().push(u.clone());
                continue;
            }
            rest.push((u.clone(), addrs.iter().copied().filter(|a| !func_at.contains_key(a)).collect()));
        }
        let definers = self.undeclared_definers(&rest.iter().map(|r| r.0.clone()).collect::<Vec<_>>())?;
        for (u, where_) in rest {
            if let Some(libs) = definers.get(&u) {
                let posix: Vec<String> = libs.iter().map(|l| l.replace('\\', "/")).collect();
                let more = if posix.len() > 3 { format!(" (+{})", posix.len() - 3) } else { String::new() };
                out.get_mut("library").unwrap().push(format!("{u}  ->  {}{more}  (undeclared: dcp libs declare <the declared archives> {} --why \"...\")",
                                                             posix.iter().take(3).cloned().collect::<Vec<_>>().join(", "), posix[0]));
                continue;
            }
            out.get_mut("other").unwrap().push(match where_.first() {
                Some(a) => format!("{u}  (no source at {a:#010x})"),
                None => u,
            });
        }
        Ok(CLASSES.iter().map(|c| (c.to_string(), out.remove(c).unwrap())).collect())
    }

    /// The libraries in the order the image shows (LINK places library contributions in the order it searches the
    /// libraries); (libraries, the chains used).
    fn library_order(&self, libs: Vec<String>, lib_units: &[(i64, String)]) -> Result<(Vec<String>, Vec<String>), String> {
        let mut first: BTreeMap<String, Vec<(String, i64)>> = BTreeMap::new();
        let seen = |k: String, at: i64, first: &mut BTreeMap<String, Vec<(String, i64)>>| {
            if let Some(sec) = self.img.section_of(at as u32) {
                let d = first.entry(sec.name.clone()).or_default();
                match d.iter_mut().find(|x| x.0 == k) {
                    Some(x) => x.1 = x.1.min(at),
                    None => d.push((k, at)),
                }
            }
        };
        for f in self.facts("unit")? {
            if let Some(l) = f.s("lib") {
                seen(l.to_lowercase(), f.lo, &mut first);
            }
        }
        let tc = crate::toolchain::of(&self.p.toolchain_key()).ok_or("no toolchain")?;
        for f in self.facts("name")? {
            let n = f.s("name").unwrap_or("");
            if f.s("origin") == Some("import") && n.starts_with("thunk:") {
                seen(tc.import_library_name(n[6..].split('!').next().unwrap_or("")), f.lo, &mut first);
            }
        }
        for (lo, lib) in lib_units {
            seen(lib.to_lowercase(), *lo, &mut first);
        }
        Ok(order_libraries(libs, &first))
    }
}

/// The libraries ordered by the image's sections' first contributions (section -> [(library key, first address)]
/// in the order they were seen): every pair that follows one another in a section is a precedence; a topological
/// sort keeps the given order wherever the image says nothing; a contradiction keeps the given order and says so.
pub fn order_libraries(libs: Vec<String>, first: &BTreeMap<String, Vec<(String, i64)>>) -> (Vec<String>, Vec<String>) {
    let key = |x: &str| name_of(x).to_lowercase();
    let mut keys: Vec<String> = vec![];
    for x in &libs {
        if !keys.contains(&key(x)) {
            keys.push(key(x));
        }
    }
    let pos: HashMap<&str, usize> = keys.iter().enumerate().map(|(i, k)| (k.as_str(), i)).collect();
    let mut succ: HashMap<&str, BTreeSet<&str>> = keys.iter().map(|k| (k.as_str(), BTreeSet::new())).collect();
    let mut chains = vec![];
    for (sec, d) in first {
        let mut d = d.clone();
        d.sort_by_key(|x| x.1);
        let chain: Vec<&str> = d.iter().filter_map(|(k, _)| pos.get_key_value(k.as_str()).map(|x| *x.0)).collect();
        if chain.len() > 1 {
            chains.push(format!("{sec}: {}", chain.join(" < ")));
        }
        for w in chain.windows(2) {
            succ.get_mut(w[0]).unwrap().insert(w[1]);
        }
    }
    let mut indeg: HashMap<&str, usize> = keys.iter().map(|k| (k.as_str(), 0)).collect();
    for a in &keys {
        for b in &succ[a.as_str()] {
            *indeg.get_mut(b).unwrap() += 1;
        }
    }
    let mut ready: Vec<&str> = keys.iter().map(|k| k.as_str()).filter(|k| indeg[k] == 0).collect();
    ready.sort_by_key(|k| pos[k]);
    let mut out: Vec<&str> = vec![];
    while !ready.is_empty() {
        let k = ready.remove(0);
        out.push(k);
        for b in &succ[k] {
            let d = indeg.get_mut(b).unwrap();
            *d -= 1;
            if *d == 0 {
                ready.push(b);
            }
        }
        ready.sort_by_key(|k| pos[k]);
    }
    if out.len() != keys.len() {
        chains.push("the image's orders contradict each other: the given order is kept".into());
        return (libs, chains);
    }
    let rank: HashMap<&str, usize> = out.iter().enumerate().map(|(i, k)| (*k, i)).collect();
    let mut libs = libs;
    libs.sort_by_key(|x| rank[key(x).as_str()]);
    (libs, chains)
}

/// The full link of the current target (build/link.py module docstring).
pub fn full_link(p: &Project) -> Result<LinkReport, String> {
    let t0 = std::time::Instant::now();
    let root = p.root.to_string_lossy().into_owned();
    let db = p.store_path();
    crate::pystore::st_open(&db, &p.main_uri()).map_err(|e| e.to_string())?;
    let target = p.target(None)?.clone();
    let img = Python::attach(|_| crate::image(&target.path)).map_err(|e| e.to_string())?;
    let x = Ctx { p, root: root.clone(), db: db.clone(), img: img.clone(), tools: Tools::of(p) };
    let mut rep = LinkReport { target: p.target_name.clone(), unresolved: CLASSES.iter().map(|c| (c.to_string(), vec![])).collect(), ..Default::default() };
    let out_dir = py_path(&format!("{root}/build/link/{}", p.target_name));
    std::fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
    let tus = crate::compile::tu_rows(&db).map_err(|e| e.to_string())?;
    let mut builds = x.facts("build")?;
    builds.sort_by(|a, b| (a.lo, a.s("tu")).cmp(&(b.lo, b.s("tu"))));
    let ok = |f: &SFact| f.value.get("ok").and_then(|v| v.as_bool()) == Some(true);
    let failed: Vec<&str> = builds.iter().filter(|f| !ok(f)).filter_map(|f| f.s("tu")).collect();
    if !failed.is_empty() {
        rep.errors.push(format!("units that do not compile: {}", failed.join(", ")));
    }
    let mut objs: Vec<(String, String)> = vec![];
    for f in builds.iter().filter(|f| ok(f)) {
        let u = f.s("tu").unwrap_or("");
        if let Some(t) = tus.get(u) {
            let path = crate::compile::obj_path(&root, &t.obj_hash);
            if Path::new(&path).exists() {
                objs.push((u.to_string(), path));
            }
        }
    }
    rep.objects = objs.len();
    if objs.is_empty() {
        rep.skipped = "no compiled unit".into();
        return Ok(rep);
    }
    let parsed: Vec<(String, crate::coff::Obj)> = objs.iter()
        .filter_map(|(u, path)| std::fs::read(path).ok().and_then(|d| crate::coff::Obj::parse(&d).ok()).map(|o| (u.clone(), o))).collect();
    // library units (decl `libunit`): their objects go into their archive, not the object list
    let targets: Vec<String> = p.targets.iter().map(|t| t.name.clone()).collect();
    let (decls, _) = crate::decl::load(&crate::decl::files(&root), &root, &targets);
    let lu = crate::decl::lib_units(&decls, &p.target_name, &targets[0]);
    let lib_of = |u: &str| lu.get(u).and_then(|d| d.key("lib")).map(|k| k.s().to_string());
    let mut members: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for (u, path) in &objs {
        if let Some(l) = lib_of(u) {
            members.entry(l.to_lowercase()).or_default().push((u.clone(), path.clone()));
        }
    }
    let lib_units: Vec<(i64, String)> = lu.values().filter_map(|d| d.key("lib").map(|k| (d.lo, k.s().to_string()))).collect();
    objs.retain(|(u, _)| lib_of(u).is_none());
    rep.objects = objs.len();
    let mut defined: HashSet<String> = HashSet::new();
    let mut includes: Vec<String> = vec![];
    for (u, o) in &parsed {
        for s in &o.symbols {
            if s.defined() && s.external() {
                defined.insert(s.name.clone());
            }
        }
        if lib_of(u).is_some() {
            continue;
        }
        for k in o.functions() {
            if o.symbols[k].external() {
                includes.push(o.symbols[k].name.clone());
            }
        }
    }
    rep.includes = includes.len();
    let kind = img.kind();
    let names = x.facts("name")?;
    let entry_at: BTreeSet<i64> = names.iter().filter(|f| f.s("origin") == Some("entry")).map(|f| f.lo).collect();
    let src_names: HashMap<i64, String> = x.facts("source")?.iter().filter(|f| f.s("what") == Some("func") && &*f.rule == "L.src")
        .map(|f| (f.lo, f.s("symbol").unwrap_or("").to_string())).collect();
    let user = entry_at.iter().find_map(|a| src_names.get(a)).cloned();
    let mut extra: Vec<String> = vec![];
    if let Some(e) = x.tools.entry_object(kind, &out_dir, user.as_deref())? {
        extra.push(e);
    }
    // aliases: several source names of one data address
    let mut by_addr: BTreeMap<i64, BTreeSet<String>> = BTreeMap::new();
    for f in names.iter().filter(|f| f.s("origin") == Some("source") && &*f.rule == "L.src" && !src_names.contains_key(&f.lo)) {
        by_addr.entry(f.lo).or_default().insert(f.s("name").unwrap_or("").to_string());
    }
    let mut aliases: Vec<(String, String)> = vec![];
    for ns in by_addr.values() {
        let syms: Vec<String> = ns.iter().map(|n| format!("_{n}")).collect();
        let Some(canon) = syms.iter().find(|s| defined.contains(*s)).cloned() else { continue };
        aliases.extend(syms.iter().filter(|s| **s != canon && !defined.contains(*s)).map(|s| (s.clone(), canon.clone())));
    }
    if !aliases.is_empty() {
        let path = py_path(&format!("{out_dir}/aliases.obj"));
        std::fs::write(&path, crate::coff::alias_object(&aliases)).map_err(|e| e.to_string())?;
        extra.push(path);
    }
    let mut libs: Vec<String> = p.lib_archives(None).unwrap_or_default();
    let mut missing_libs = vec![];
    let imports = img.imports();
    let mut dlls: Vec<String> = imports.iter().map(|i| i.dll.clone()).collect::<BTreeSet<_>>().into_iter().collect();
    dlls.sort_by_key(|d| d.to_lowercase());
    dlls.dedup();
    let tc = crate::toolchain::of(&p.toolchain_key()).ok_or("no toolchain")?;
    for dll in dlls {
        let name = tc.import_library_name(&dll);
        let path = match x.find_library(&name) {
            Some(path) => path,
            None => {
                let path = py_path(&format!("{out_dir}/{name}"));
                let mine: Vec<crate::pe::Import> = imports.iter().filter(|i| i.dll == dll).cloned().collect();
                if let Some(why) = x.tools.make_import_library(&dll, &mine, &path)? {
                    missing_libs.push(format!("no import library {name} for {dll}: {why}"));
                    continue;
                }
                rep.notes.push(format!("import library {name} for {dll} built from the image's import directory"));
                path
            }
        };
        libs.push(path);
    }
    for (key, units) in &members {
        let Some(k) = libs.iter().position(|l| name_of(l).to_lowercase() == *key) else {
            rep.errors.push(format!("library unit(s) {}: the archive {key} is not linked", units.iter().map(|u| u.0.as_str()).collect::<Vec<_>>().join(", ")));
            continue;
        };
        let dest = py_path(&format!("{out_dir}/{}", name_of(&libs[k])));
        if crate::vc6::resolved("", &libs[k]).to_lowercase() != crate::vc6::resolved("", &dest).to_lowercase() {
            std::fs::copy(&libs[k], &dest).map_err(|e| e.to_string())?;
            libs[k] = dest.clone();
        }
        let us = units.iter().map(|u| u.0.as_str()).collect::<Vec<_>>().join(", ");
        match x.tools.add_library_members(&dest, &units.iter().map(|u| u.1.clone()).collect::<Vec<_>>())? {
            Some(why) => rep.errors.push(format!("library unit(s) {us}: {why}")),
            None => rep.notes.push(format!("{} holds the library unit(s) {us}", name_of(&dest))),
        }
    }
    let (libs, chains) = x.library_order(libs, &lib_units)?;
    if !chains.is_empty() {
        rep.notes.push(format!("library order from the image: {}", chains.join("; ")));
    }
    rep.errors.extend(missing_libs);
    let stem = Path::new(&target.path).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let mut def_file = None;
    let mut open_exports = vec![];
    if img.is_dll {
        let path = py_path(&format!("{out_dir}/{}.def", p.target_name));
        let exports = img.exports();
        let exports: Vec<&crate::pe::Export> = exports.iter().filter(|e| e.forwarder.is_none()).collect();
        open_exports = exports.iter().filter(|e| !src_names.contains_key(&(e.va as i64)))
            .map(|e| format!("{}  (export, no source at {:#010x} yet)", e.name.clone().unwrap_or_else(|| format!("#{}", e.ordinal)), e.va)).collect();
        let mine: Vec<&crate::pe::Export> = exports.iter().copied().filter(|e| src_names.contains_key(&(e.va as i64))).collect();
        let text = crate::vc6::module_definition(&stem, &mine);
        if std::fs::read_to_string(&path).ok().as_deref() != Some(text.as_str()) {
            std::fs::write(&path, &text).map_err(|e| e.to_string())?;
        }
        def_file = Some(path);
    }
    let out = py_path(&format!("{out_dir}/{}", name_of(&target.path)));
    let objects: Vec<String> = extra.iter().cloned().chain(objs.iter().map(|o| o.1.clone())).collect();
    let job = LinkJob {
        cwd: root.clone(), out: out.clone(), objects: objects.clone(), libraries: libs.clone(), dll: img.is_dll, base: img.base,
        map_file: py_path(&format!("{out_dir}/{}.map", p.target_name)), def_file: def_file.clone(), includes: includes.clone(),
        subsystem: if kind == "gui" || kind == "console" { kind.to_string() } else { String::new() },
        rsp: py_path(&format!("{out_dir}/link.rsp")),
    };
    rep.out = crate::vc6::rel_to(&root, &out);
    let mut parts = vec![py_json_list(&objects.iter().chain(&libs).chain(&includes).cloned().collect::<Vec<_>>())];
    parts.extend(objects.iter().chain(&libs).map(|f| file_digest(f)));
    parts.push(def_file.as_deref().map(file_digest).unwrap_or_default());
    parts.push(img.base.to_string());
    let key = sha256_parts(&parts);
    let cache = py_path(&format!("{out_dir}/link.json"));
    let hit: Option<Value> = std::fs::read_to_string(&cache).ok().and_then(|t| serde_json::from_str(&t).ok());
    let lines = |v: &Value| -> Vec<String> { v.as_array().into_iter().flatten().filter_map(|x| x.as_str().map(|s| s.to_string())).collect() };
    let settle = |rep: &mut LinkReport, link_ok: bool, raw_nonempty: bool| {
        let others = rep.unresolved.iter().any(|(k, v)| k != "undrafted" && !v.is_empty());
        rep.ok = rep.errors.is_empty() && (link_ok || (raw_nonempty && !others));
    };
    let unresolved_json = |u: &[(String, Vec<String>)]| -> Value { Value::Object(u.iter().map(|(k, v)| (k.clone(), json!(v))).collect()) };
    if let Some(mut h) = hit.filter(|h| h["key"] == key.as_str() && h.get("raw").is_some()
        && (Path::new(&out).exists() || h["link_ok"].as_bool() != Some(true))) {
        let raw = lines(&h["raw"]);
        rep.unresolved = x.classify(&raw)?;
        rep.cached = true;
        rep.unresolved.iter_mut().find(|x| x.0 == "undrafted").unwrap().1.extend(open_exports);
        let now = unresolved_json(&rep.unresolved);
        if h.get("unresolved") != Some(&now) {
            h["unresolved"] = now;
            std::fs::write(&cache, serde_json::to_string(&h).unwrap_or_default()).map_err(|e| e.to_string())?;
        }
        rep.errors.extend(lines(&h["errors"]));
        settle(&mut rep, h["link_ok"].as_bool() == Some(true), !raw.is_empty());
        rep.ms = t0.elapsed().as_millis() as i64;
        return Ok(rep);
    }
    let _ = std::fs::remove_file(&out);
    let res = x.tools.link(&job)?;
    std::fs::write(py_path(&format!("{out_dir}/link.log")), &res.log).map_err(|e| e.to_string())?;
    rep.unresolved = x.classify(&res.unresolved)?;
    rep.unresolved.iter_mut().find(|x| x.0 == "undrafted").unwrap().1.extend(open_exports);
    rep.errors.extend(res.errors.iter().cloned());
    settle(&mut rep, res.ok, !res.unresolved.is_empty());
    for (k, ls) in &rep.unresolved {
        std::fs::write(py_path(&format!("{out_dir}/unresolved-{k}.txt")), ls.iter().map(|l| format!("{l}\n")).collect::<String>()).map_err(|e| e.to_string())?;
    }
    let j = json!({"key": key, "ok": rep.ok, "link_ok": res.ok, "raw": res.unresolved, "unresolved": unresolved_json(&rep.unresolved), "errors": res.errors});
    std::fs::write(&cache, serde_json::to_string(&j).unwrap_or_default()).map_err(|e| e.to_string())?;
    rep.ms = t0.elapsed().as_millis() as i64;
    Ok(rep)
}

/// link.full_link: {target, ok, skipped, objects, includes, unresolved {class: lines}, errors, notes, out, cached, ms}.
#[pyfunction]
pub fn link_full<'py>(py: Python<'py>, project: PyRef<'py, crate::project::PyProject>) -> PyResult<Bound<'py, PyDict>> {
    let r = full_link(&project.p).map_err(PyRuntimeError::new_err)?;
    let d = PyDict::new(py);
    d.set_item("target", r.target)?;
    d.set_item("ok", r.ok)?;
    d.set_item("skipped", r.skipped)?;
    d.set_item("objects", r.objects)?;
    d.set_item("includes", r.includes)?;
    let u = PyDict::new(py);
    for (k, v) in r.unresolved {
        u.set_item(k, v)?;
    }
    d.set_item("unresolved", u)?;
    d.set_item("errors", r.errors)?;
    d.set_item("notes", r.notes)?;
    d.set_item("out", r.out)?;
    d.set_item("cached", r.cached)?;
    d.set_item("ms", r.ms)?;
    Ok(d)
}

/// link.classify for Python: the classes of these unresolved externals.
#[pyfunction]
pub fn link_classify<'py>(py: Python<'py>, project: PyRef<'py, crate::project::PyProject>, names: Vec<String>) -> PyResult<Bound<'py, PyDict>> {
    let p = &project.p;
    let db = p.store_path();
    crate::pystore::st_open(&db, &p.main_uri())?;
    let target = p.target(None).map_err(PyRuntimeError::new_err)?;
    let img = crate::image(&target.path)?;
    let x = Ctx { p, root: p.root.to_string_lossy().into_owned(), db, img, tools: Tools::of(p) };
    let d = PyDict::new(py);
    for (k, v) in x.classify(&names).map_err(PyRuntimeError::new_err)? {
        d.set_item(k, v)?;
    }
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn library_order_from_the_image() {
        // per section, the first contributions follow one another (placed members, import thunks, library units);
        // unconstrained libraries keep their given place
        let mut first: BTreeMap<String, Vec<(String, i64)>> = BTreeMap::new();
        first.insert(".text".into(), vec![("libc.lib".into(), 0x5de4a0), ("dinput.lib".into(), 0x5dd3e0), ("ddraw.lib".into(), 0x5de486),
                                          ("mss32.lib".into(), 0x5de460)]);
        first.insert(".rdata".into(), vec![("libc.lib".into(), 0x5eef50), ("strmiids.lib".into(), 0x5eeee0)]);
        let libs: Vec<String> = ["C:/x/LIBC.LIB", "C:/x/DINPUT.LIB", "C:/x/STRMIIDS.LIB", "b/ddraw.lib", "b/gdi32.lib", "b/mss32.lib"].iter().map(|s| s.to_string()).collect();
        let (out, chains) = order_libraries(libs, &first);
        assert_eq!(out.iter().map(|p| name_of(p).to_lowercase()).collect::<Vec<_>>(), ["dinput.lib", "strmiids.lib", "gdi32.lib", "mss32.lib", "ddraw.lib", "libc.lib"]);
        assert!(chains.contains(&".text: dinput.lib < mss32.lib < ddraw.lib < libc.lib".to_string()), "{chains:?}");
    }
}
