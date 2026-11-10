//! The translation units of a target (the compile's plan): one source file per unit,
//! `src/<unit>.c`, compiled as it stands.
//!
//! A unit is a translation unit of a target when it holds a function with an address of that target or an unlinked
//! function, or when it has code but no function addressed for any target or unlinked (ill-formed, the scan's L.src;
//! it is still compiled, so the build shows it). A head alone (`dcp unit new`) is no unit yet.
//!
//! The flags of a unit: the target's declared cflags, then the cflags of the first [[toolchain.unit]] whose glob
//! matches the unit name (and whose `targets`, when given, list the target), then the target's define
//! (`/DDCP_TARGET_<name>`).
//!
//! `__FILE__` and `__LINE__`: the file carries the original's `#line 1 "<path>"` and its `#line N` pins itself; the
//! compiler reports a diagnostic at the name and line the directives give; `locate` maps it back to the file's
//! physical line.

use crate::error::Result;
use crate::frontend;
use crate::fsmemo;
use crate::project::{native_path, Project};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;

/// A translation unit of a target.
#[derive(Clone)]
pub struct Tu {
    pub target: String,
    pub unit: String,
    pub file: String,                             // src/<unit>.c, project-relative posix
    pub functions: Vec<(Option<i64>, String)>,    // (address, None for an unlinked one; name) in text order
    pub file_name: Option<String>,                // the declared original file name
    pub src_hash: String,
}

impl Tu {
    /// The least address of the target's functions in the unit.
    pub fn first_addr(&self) -> Option<i64> {
        self.functions.iter().filter_map(|f| f.0).min()
    }
}

/// unit -> its declared original file name (`file` declarations; the first per unit).
pub fn unit_files(decls: &[crate::decl::Decl]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for d in decls {
        if d.kind == "file" {
            if let (Some(tu), Some(path)) = (d.key("tu"), d.key("path")) {
                out.entry(tu.s().to_string()).or_insert_with(|| path.s().to_string());
            }
        }
    }
    out
}

fn address_for(addrs: &[(Option<String>, u64)], target: &str, default: &str) -> Option<i64> {
    addrs.iter().find(|(t, _)| t.as_deref().unwrap_or(default) == target).map(|x| x.1 as i64)
}

/// The translation units of one target, in unit name order, planned from the file list: every `src/<unit>.c` with a
/// function addressed for the target or unlinked, and every one with code but no function addressed for any target
/// or unlinked (ill-formed, L.src), so its compile shows what is wrong instead of its row going.
pub fn units(root: &str, scan: &frontend::Scan, target: &str, default: &str, names: &HashMap<String, String>) -> Result<Vec<Tu>, String> {
    let by_file: BTreeMap<&str, &crate::srcscan::FilePart> = scan.parts.iter().map(|p| (p.rel.as_str(), &**p)).collect();
    let mut out = vec![];
    for (rel, part) in by_file {
        let Some(unit) = rel.strip_prefix("src/").and_then(|r| r.strip_suffix(".c")).filter(|u| !u.contains('/')) else { continue };
        let mut fs: Vec<&crate::srcscan::FnRow> = part.functions.iter().collect();
        fs.sort_by_key(|f| f.0 .1);
        let fns: Vec<(Option<i64>, String)> = fs.iter().filter_map(|f| {
            let a = address_for(&f.0 .4, target, default);
            (a.is_some() || f.0 .5).then(|| (a, f.0 .3.clone()))
        }).collect();
        if !fns.is_empty() || part.no_unit.is_some() {
            let path = native_path(&format!("{root}/{rel}"));
            let src_hash = fsmemo::sha256(&path).map_err(|e| format!("{path}: {e}"))?;
            out.push(Tu { target: target.into(), unit: unit.into(), file: rel.into(), functions: fns, file_name: names.get(unit).cloned(), src_hash });
        }
    }
    Ok(out)
}

thread_local! {
    static PLANS: RefCell<Vec<(Vec<String>, Rc<Vec<Tu>>)>> = const { RefCell::new(Vec::new()) };
}

/// The translation units of the project's current target, memoised by the root, the target and the hashes of what
/// they depend on (the sources, the declarations, the target list).
pub fn plan(p: &Project) -> Result<Rc<Vec<Tu>>, String> {
    let h = |n: &str| p.input_hash(n).map(|x| x.unwrap_or_default());
    let root = p.root.to_string_lossy().into_owned();
    let key = vec![root.clone(), p.target_name.clone(), h("src")?, h("decl")?, h("target")?];
    if let Some(hit) = PLANS.with(|c| c.borrow().iter().find(|x| x.0 == key).map(|x| x.1.clone())) {
        return Ok(hit);
    }
    let scan = frontend::scan(&root, Some(&key[2]))?;
    let (decls, _) = crate::decl::load(&crate::decl::files(&root), &root);
    let names = unit_files(&decls);
    let out = Rc::new(units(&root, &scan, &p.target_name, &p.target_name, &names)?);
    PLANS.with(|c| {
        let mut c = c.borrow_mut();
        if c.len() > 2 {
            c.clear();
        }
        c.push((key, out.clone()));
    });
    Ok(out)
}

/// The [[toolchain.unit]] tables: glob (on the unit name), cflags, reason, optional targets.
pub fn unit_overrides(p: &Project) -> Vec<toml::Table> {
    p.cfg.get("toolchain").and_then(|t| t.get("unit")).and_then(|u| u.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_table().cloned()).collect()).unwrap_or_default()
}

fn strings(v: Option<&toml::Value>) -> Vec<String> {
    v.and_then(|x| x.as_array()).map(|a| a.iter().map(|s| s.as_str().map(|s| s.to_string()).unwrap_or_else(|| crate::project::toml_json(s).to_string())).collect()).unwrap_or_default()
}

/// (flags, the override table that applied): the target's declared cflags, then the cflags of the first
/// [[toolchain.unit]] whose glob matches the unit name.
pub fn flags_for(p: &Project, unit: &str) -> Result<(Vec<String>, Option<toml::Table>), String> {
    let decl = p.toolchain_decl()?;
    let mut flags: Vec<String> = decl["cflags"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect()).unwrap_or_default();
    for o in unit_overrides(p) {
        let glob = o.get("glob").map(|g| g.as_str().map(|s| s.to_string()).unwrap_or_else(|| crate::project::toml_json(g).to_string())).unwrap_or_default();
        if fsmemo::fnmatch(unit.as_bytes(), glob.as_bytes()) {
            flags.extend(strings(o.get("cflags")));
            return Ok((flags, Some(o)));
        }
    }
    Ok((flags, None))
}

/// The flags a unit compiles with: the declared cflags and the unit's override.
pub fn compile_flags(p: &Project, unit: &str) -> Result<Vec<String>, String> {
    Ok(flags_for(p, unit)?.0)
}

/// (name, first reported line, n lines, first physical line) of every stretch of the text one `#line` directive
/// numbers (the file's own name and line 1 before the first).
pub fn segments(text: &str, rel: &str) -> Vec<(String, i64, i64, i64)> {
    use std::sync::LazyLock;
    static LINE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r#"^[ \t]*#[ \t]*line[ \t]+(\d+)(?:[ \t]+"((?:\\.|[^"\\])*)")?"#).unwrap());
    let (mut out, mut name, mut first, mut phys) = (vec![], rel.to_string(), 1i64, 1i64);
    let lines: Vec<&str> = text.split('\n').collect();
    for (k, s) in lines.iter().enumerate() {
        let k = k as i64 + 1;
        if let Some(m) = LINE.captures(s) {
            out.push((name.clone(), first, k - phys, phys));
            if let Some(n) = m.get(2) {
                name = n.as_str().replace("\\\\", "\\");
            }
            first = m[1].parse().unwrap_or(1);
            phys = k + 1;
        }
    }
    out.push((name, first, lines.len() as i64 + 1 - phys, phys));
    out.retain(|s| s.2 > 0);
    out
}

fn same_file(a: &str, b: &str) -> bool {
    let (na, nb) = (a.replace('\\', "/").to_lowercase(), b.replace('\\', "/").to_lowercase());
    na == nb || na.ends_with(&format!("/{nb}")) || nb.ends_with(&format!("/{na}"))
}

/// The physical lines of a file a compiler position (the name and line its `#line` directives give) stands for.
pub fn locate(text: &str, rel: &str, name: &str, line: i64) -> Vec<i64> {
    segments(text, rel).into_iter().filter(|(n, first, k, _)| same_file(n, name) && *first <= line && line < first + k)
        .map(|(_, first, _, phys)| phys + line - first).collect()
}

// ------------------------------------------------------------------------------------------------ entry points

#[cfg(test)]
type TuRow = (String, String, String, Vec<(Option<i64>, String)>, Option<String>, String);

#[cfg(test)]
fn rows(units: &[Tu]) -> Vec<TuRow> {
    units.iter().map(|a| (a.target.clone(), a.unit.clone(), a.file.clone(), a.functions.clone(), a.file_name.clone(), a.src_hash.clone())).collect()
}

/// The translation units of one target of a scan (tu.units).
#[cfg(test)]
pub fn plan_scan_units(root: &str, scan: &frontend::Scan, target: &str, default: &str, names: Option<HashMap<String, String>>) -> Result<Vec<TuRow>> {
    Ok(rows(&units(&native_path(root), scan, target, default, &names.unwrap_or_default()).map_err(crate::error::Error::runtime)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_directives() {
        let text = "#line 1 \"c:\\\\src\\\\net.c\"\nint a;\nint b;\n#line 40\nint c;\n";
        assert_eq!(locate(text, "src/net.c", "c:\\src\\net.c", 2), vec![3]);
        assert_eq!(locate(text, "src/net.c", "net.c", 40), vec![5]);
        assert!(locate(text, "src/net.c", "other.c", 2).is_empty());
        // a unit with its original file name and a `__LINE__` pin
        let text = "int x;\n#line 1 \"D:\\\\dev\\\\u.c\"\nint a(void)\n{\n#line 200\n    return 1;\n}\n";
        assert_eq!(locate(text, "src/u.c", "src/u.c", 1), vec![1]);
        assert_eq!(locate(text, "src/u.c", "src\\u.c", 1), vec![1]);
        assert_eq!(locate(text, "src/u.c", "D:\\dev\\u.c", 1), vec![3]); // `int a(void)`
        assert_eq!(locate(text, "src/u.c", "d:/dev/U.C", 200), vec![6]); // after the pin
        assert!(locate(text, "src/u.c", "D:\\dev\\u.c", 5).is_empty());
    }
}
