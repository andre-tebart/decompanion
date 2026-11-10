//! `dcp export`: the build of the current target as data, for a build without dcp (a configure script and ninja, say).
//!
//! The export is a projection of H's build: the units with their sources and flags, the link in its order (objects,
//! archives, the `/INCLUDE` symbols, the linker options), and the inputs dcp generates (the entry stub, the alias
//! object, an import library built from the image's import directory, a dll's module definition). It is written to
//! `<dir>/<target>.json` and `<dir>/<target>/` (`[export] dir`, default `export`) and meant to be committed.
//!
//! Paths: a path inside the project is relative to its root; a path outside is `{name}/rest`, where `name` is a name
//! of `[paths]` (project.rs: name = directory, a machine's own in decompanion.local.toml) or `toolchain` (the
//! toolchain root, when no name holds it). A path outside the project that no name covers is refused: the export names
//! it, the one who builds supplies the directories.
//!
//! `--check` writes nothing: it lists the files the export would change (stale, missing, extra) and fails when there
//! is one. An import library is current when its module definition is (LIB.EXE stamps the time into the archive).

use crate::link::{LinkPlan, PlanObject};
use crate::project::{py_path, Project};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const FORMAT: i64 = 1;

/// One file of the export: its bytes, or an import library (built by LIB.EXE from its module definition).
enum Content {
    Bytes(Vec<u8>),
    ImportLibrary { dll: String, def: String },
}

/// Path variables: (name, directory) with the directory resolved, longest first.
pub struct Vars(Vec<(String, String)>);

fn norm(p: &str) -> String {
    p.replace('\\', "/").trim_end_matches('/').to_string()
}

impl Vars {
    pub fn new(mut v: Vec<(String, String)>) -> Vars {
        for x in v.iter_mut() {
            x.1 = norm(&x.1);
        }
        v.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(&b.0)));
        Vars(v)
    }

    /// The path as the export spells it: relative to the project root inside it, `{name}/rest` outside; the name
    /// used is added to `used`.
    pub fn portable(&self, root: &str, path: &str, used: &mut BTreeSet<String>) -> Result<String, String> {
        let p = norm(path);
        let under = |dir: &str| -> Option<String> {
            let d = norm(dir);
            let (pl, dl) = (p.to_lowercase(), d.to_lowercase());
            if pl == dl {
                Some(String::new())
            } else if pl.starts_with(&dl) && pl.as_bytes().get(dl.len()) == Some(&b'/') {
                Some(p[d.len() + 1..].to_string())
            } else {
                None
            }
        };
        if !Path::new(&p).is_absolute() && !p.contains(':') {
            return Ok(p);
        }
        if let Some(rest) = under(root) {
            return Ok(rest);
        }
        for (name, dir) in &self.0 {
            if let Some(rest) = under(dir) {
                used.insert(name.clone());
                return Ok(if rest.is_empty() { format!("{{{name}}}") } else { format!("{{{name}}}/{rest}") });
            }
        }
        Err(format!("{p} lies outside the project and outside every named directory: name its directory in [paths] (name = \"DIR\")"))
    }
}

/// The real spelling of a path (its case on disk), else the path.
fn real(p: &str) -> String {
    norm(&crate::vc6::resolved("", p))
}

fn vars_of(p: &Project) -> Vars {
    let mut v: Vec<(String, String)> = p.paths.iter().map(|(k, d)| (k.clone(), real(&p.expand(d)))).collect();
    if let Some(r) = p.toolchain_root().map(|r| real(&r)) {
        if !v.iter().any(|x| x.1.eq_ignore_ascii_case(&r)) && !p.paths.contains_key("toolchain") {
            v.push(("toolchain".to_string(), r));
        }
    }
    Vars::new(v)
}

fn export_dir(p: &Project) -> String {
    p.cfg.get("export").and_then(|e| e.get("dir")).and_then(|d| d.as_str()).unwrap_or("export").trim_end_matches('/').to_string()
}

/// The export of the current target: (project-relative path, content) of every file, in path order.
fn files(p: &Project, plan: &LinkPlan) -> Result<Vec<(String, Content)>, String> {
    let root = real(&p.root.to_string_lossy());
    let vars = vars_of(p);
    let mut used = BTreeSet::new();
    let mut port = |s: &str| vars.portable(&root, &if Path::new(s).is_absolute() { real(s) } else { s.to_string() }, &mut used);
    let dir = export_dir(p);
    let t = p.target_name.clone();
    let gdir = format!("{dir}/{t}");
    let mut out: Vec<(String, Content)> = vec![];
    let units: BTreeMap<String, crate::plan::Tu> = crate::plan::plan(p)?.iter().map(|u| (u.unit.clone(), u.clone())).collect();
    let flags = |unit: &str, port: &mut dyn FnMut(&str) -> Result<String, String>| -> Result<Vec<String>, String> {
        crate::plan::compile_flags(p, &t, unit)?.into_iter().map(|f| match f.strip_prefix("/I") {
            Some(d) if Path::new(d).is_absolute() => Ok(format!("/I{}", port(d)?)),
            _ => Ok(f),
        }).collect()
    };
    let mut cunits: Vec<Value> = vec![];
    let mut objects: Vec<Value> = vec![];
    let add_unit = |u: &str, cunits: &mut Vec<Value>, port: &mut dyn FnMut(&str) -> Result<String, String>| -> Result<(), String> {
        let tu = units.get(u).ok_or_else(|| format!("unit {u}: linked but not planned"))?;
        cunits.push(json!({"unit": u, "source": tu.file, "flags": flags(u, port)?}));
        Ok(())
    };
    for o in &plan.objects {
        match o {
            PlanObject::Unit(u) => {
                add_unit(u, &mut cunits, &mut port)?;
                objects.push(json!({"unit": u}));
            }
            PlanObject::Entry(text) => {
                let src = format!("{gdir}/entry.c");
                out.push((src.clone(), Content::Bytes(text.clone().into_bytes())));
                cunits.push(json!({"unit": "_entry", "source": src, "flags": crate::vc6::ENTRY_FLAGS}));
                objects.push(json!({"unit": "_entry"}));
            }
            PlanObject::Aliases(pairs) => {
                let f = format!("{gdir}/aliases.obj");
                out.push((f.clone(), Content::Bytes(crate::coff::alias_object(pairs))));
                objects.push(json!({"file": f}));
            }
        }
    }
    let img = crate::image(&p.target(None)?.path).map_err(|e| e.to_string())?;
    let imports = img.imports();
    let mut libraries: Vec<Value> = vec![];
    for l in &plan.libraries {
        for m in &l.members {
            add_unit(m, &mut cunits, &mut port)?;
        }
        let file = match &l.imports_of {
            Some(dll) => {
                let name = Path::new(&l.path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                let mine: Vec<crate::pe::Import> = imports.iter().filter(|i| &i.dll == dll).cloned().collect();
                let lib = format!("{gdir}/{name}");
                let def = crate::vc6::import_definition(dll, &mine);
                out.push((Path::new(&lib).with_extension("def").to_string_lossy().replace('\\', "/"), Content::Bytes(def.clone().into_bytes())));
                out.push((lib.clone(), Content::ImportLibrary { dll: dll.clone(), def }));
                lib
            }
            None => port(&l.path)?,
        };
        libraries.push(if l.members.is_empty() { json!({"file": file}) } else { json!({"file": file, "members": l.members}) });
    }
    let tools = crate::vc6::Tools::of(p);
    let dirs = |v: Vec<String>, port: &mut dyn FnMut(&str) -> Result<String, String>| -> Result<Vec<String>, String> { v.iter().map(|d| port(d)).collect() };
    let tr = tools.root.clone().unwrap_or_default();
    let toolchain = json!({
        "kind": p.toolchain_key(),
        "compiler": p.toolchain_decl(None)?["compiler"],
        "linker": p.toolchain_decl(None)?["linker"],
        "cl": port(&format!("{tr}/VC98/Bin/CL.EXE"))?,
        "link": port(&format!("{tr}/VC98/Bin/LINK.EXE"))?,
        "lib": port(&format!("{tr}/VC98/Bin/LIB.EXE"))?,
        "path": dirs(vec![tools.bindir(), format!("{tr}/Common/MSDev98/Bin")], &mut port)?,
        "include": dirs(tools.system_include(), &mut port)?,
        "libpath": dirs(tools.lib_path(), &mut port)?,
    });
    let mut args: Vec<String> = vec!["/OPT:REF".into(), "/OPT:ICF".into(), "/MACHINE:IX86".into()];
    let mut def = Value::Null;
    if plan.dll {
        args.push("/DLL".into());
        args.push(format!("/BASE:{:#x}", plan.base));
        if let Some(text) = &plan.def_text {
            let f = format!("{gdir}/{t}.def");
            out.push((f.clone(), Content::Bytes(text.clone().into_bytes())));
            def = json!(f);
        }
    }
    if !plan.subsystem.is_empty() {
        args.push(format!("/SUBSYSTEM:{}", match plan.subsystem.as_str() { "gui" => "WINDOWS", "console" => "CONSOLE", s => s }));
    }
    let target = p.target(None)?;
    let doc = json!({
        "format": FORMAT,
        "generator": "dcp export",
        "target": t,
        "output": {"name": plan.out_name, "sha256": target.sha256},
        "paths": used.iter().collect::<Vec<_>>(),
        "toolchain": toolchain,
        "compile": {"include": ["include"], "units": cunits},
        "link": {"args": args, "def": def, "objects": objects, "libraries": libraries, "includes": plan.includes},
    });
    let text = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())? + "\n";
    out.push((format!("{dir}/{t}.json"), Content::Bytes(text.into_bytes())));
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// What differs between the export on disk and this one: (state, path) with state stale / missing / extra.
fn differences(root: &Path, gen_dir: &str, files: &[(String, Content)]) -> Vec<(&'static str, String)> {
    let mut out = vec![];
    for (f, c) in files {
        let path = root.join(f);
        let state = match c {
            Content::Bytes(b) => match std::fs::read(&path) {
                Ok(d) if d == *b => None,
                Ok(_) => Some("stale"),
                Err(_) => Some("missing"),
            },
            Content::ImportLibrary { def, .. } => {
                let def_now = std::fs::read(path.with_extension("def")).ok();
                if !path.exists() {
                    Some("missing")
                } else if def_now.as_deref() != Some(def.as_bytes()) {
                    Some("stale")
                } else {
                    None
                }
            }
        };
        if let Some(s) = state {
            out.push((s, f.clone()));
        }
    }
    let ours: BTreeSet<&str> = files.iter().map(|f| f.0.as_str()).collect();
    if let Ok(rd) = std::fs::read_dir(root.join(gen_dir)) {
        let mut extra: Vec<String> = rd.flatten().filter(|e| e.path().is_file())
            .map(|e| format!("{gen_dir}/{}", e.file_name().to_string_lossy())).filter(|f| !ours.contains(f.as_str())).collect();
        extra.sort();
        out.extend(extra.into_iter().map(|f| ("extra", f)));
    }
    out
}

/// `dcp export [--check]`: (lines, exit code).
pub fn export_command(p: &Project, check: bool) -> Result<(Vec<String>, i32), String> {
    let t0 = std::time::Instant::now();
    let r = crate::link::full_link(p)?;
    let rec = |kv: &[(&str, crate::cliread::Tok)]| crate::cliread::record(kv);
    use crate::cliread::Tok;
    let Some(plan) = r.plan.as_ref().filter(|_| r.ok) else {
        let why = if !r.skipped.is_empty() { r.skipped.clone() } else { "the link fails (dcp link)".into() };
        return Ok((vec![rec(&[("export", Tok::S(p.target_name.clone())), ("ok", Tok::B(false))]) + &format!("  {why}")], 1));
    };
    let fs = files(p, plan)?;
    let gdir = format!("{}/{}", export_dir(p), p.target_name);
    let diffs = differences(&p.root, &gdir, &fs);
    let mut written = 0;
    if !check {
        let tools = crate::vc6::Tools::of(p);
        let img = crate::image(&p.target(None)?.path).map_err(|e| e.to_string())?;
        for (state, f) in &diffs {
            let path = p.root.join(f);
            if *state == "extra" {
                std::fs::remove_file(&path).map_err(|e| format!("{f}: {e}"))?;
                continue;
            }
            if let Some(d) = path.parent() {
                std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
            }
            match &fs.iter().find(|x| &x.0 == f).unwrap().1 {
                Content::Bytes(b) => std::fs::write(&path, b).map_err(|e| format!("{f}: {e}"))?,
                Content::ImportLibrary { dll, .. } => {
                    let mine: Vec<crate::pe::Import> = img.imports().into_iter().filter(|i| &i.dll == dll).collect();
                    if let Some(why) = tools.make_import_library(dll, &mine, &py_path(&path.to_string_lossy()))? {
                        return Err(format!("{f}: {why}"));
                    }
                    let _ = std::fs::remove_file(path.with_extension("exp")); // LIB.EXE's export file: the link does not read it
                }
            }
            written += 1;
        }
    }
    let units = fs.iter().find(|f| f.0.ends_with(".json")).and_then(|f| match &f.1 {
        Content::Bytes(b) => serde_json::from_slice::<Value>(b).ok(),
        _ => None,
    });
    let count = |k: &str, j: &str| units.as_ref().and_then(|u| u[k][j].as_array().map(|a| a.len() as i64)).unwrap_or(0);
    let paths: Vec<String> = units.as_ref().and_then(|u| u["paths"].as_array().cloned()).unwrap_or_default().iter().filter_map(|v| v.as_str().map(String::from)).collect();
    let mut head = vec![("export", Tok::S(p.target_name.clone())), ("ok", Tok::B(!check || diffs.is_empty())), ("units", Tok::I(count("compile", "units"))),
                        ("objects", Tok::I(count("link", "objects"))), ("libraries", Tok::I(count("link", "libraries"))), ("includes", Tok::I(count("link", "includes"))),
                        ("paths", Tok::S(if paths.is_empty() { "-".into() } else { paths.join(",") }))];
    if check {
        head.push(("stale", Tok::I(diffs.len() as i64)));
    } else {
        head.push(("written", Tok::I(written)));
    }
    head.push(("ms", Tok::I(t0.elapsed().as_millis() as i64)));
    let mut lines = vec![rec(&head)];
    lines.extend(diffs.iter().map(|(s, f)| if check { format!("  {s} {f}") } else if *s == "extra" { format!("  removed {f}") } else { format!("  wrote {f}") }));
    if check && !diffs.is_empty() {
        lines.push("  the export is older than H: dcp export".into());
    }
    Ok((lines, (check && !diffs.is_empty()) as i32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portable_paths() {
        let v = Vars::new(vec![("toolchain".into(), "C:/Tools/MSVC600".into()), ("dx".into(), "C:\\Tools\\DX".into()), ("dx8".into(), "C:/Tools/DX/v8".into())]);
        let mut used = BTreeSet::new();
        let root = "C:/proj";
        assert_eq!(v.portable(root, "C:/proj/src/a.c", &mut used).unwrap(), "src/a.c");
        assert_eq!(v.portable(root, "src/a.c", &mut used).unwrap(), "src/a.c");
        assert_eq!(v.portable(root, "c:\\tools\\msvc600\\VC98\\Lib\\LIBC.LIB", &mut used).unwrap(), "{toolchain}/VC98/Lib/LIBC.LIB");
        assert_eq!(v.portable(root, "C:/Tools/DX/v8/lib/dxguid.lib", &mut used).unwrap(), "{dx8}/lib/dxguid.lib");
        assert_eq!(v.portable(root, "C:/Tools/DX", &mut used).unwrap(), "{dx}");
        assert!(v.portable(root, "C:/Tools/DXSDK/x.lib", &mut used).is_err());
        assert!(v.portable(root, "C:/projector/x.c", &mut used).is_err());
        assert_eq!(used.into_iter().collect::<Vec<_>>(), ["dx", "dx8", "toolchain"]);
    }

    #[test]
    fn differences_of_the_export() {
        let dir = crate::testkit::scratch("export-diff");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("export/exe")).unwrap();
        std::fs::write(dir.join("export/exe.json"), "{}\n").unwrap();
        std::fs::write(dir.join("export/exe/entry.c"), "old").unwrap();
        std::fs::write(dir.join("export/exe/gone.obj"), "x").unwrap();
        std::fs::write(dir.join("export/exe/m.def"), "DEF").unwrap();
        std::fs::write(dir.join("export/exe/m.lib"), "LIB, stamped").unwrap();
        let fs = vec![
            ("export/exe.json".to_string(), Content::Bytes(b"{}\n".to_vec())),
            ("export/exe/aliases.obj".to_string(), Content::Bytes(vec![1])),
            ("export/exe/entry.c".to_string(), Content::Bytes(b"new".to_vec())),
            ("export/exe/m.def".to_string(), Content::Bytes(b"DEF".to_vec())),
            ("export/exe/m.lib".to_string(), Content::ImportLibrary { dll: "m.dll".into(), def: "DEF".into() }),
        ];
        let d = differences(&dir, "export/exe", &fs);
        assert_eq!(d, [("missing", "export/exe/aliases.obj".to_string()), ("stale", "export/exe/entry.c".to_string()), ("extra", "export/exe/gone.obj".to_string())]);
    }
}
