//! The guided decisions (decide.rs): `dcp init` declares nothing, `dcp setup` and `dcp status` name the open
//! obligations in order, the declarations refuse a missing reason, the rules waiting on a declaration run once it is
//! made, and an open toolchain or libs obligation fails `dcp session start` (tests/test_obligations.py).

use super::*;
use serde_json::{json, Value};

/// The ids of the numbered steps of the guided status view.
fn obligations(out: &str) -> Vec<String> {
    let re = regex::Regex::new(r"^\s*\d+\.\s+(\S+)").unwrap();
    out.lines().filter_map(|l| re.captures(l).map(|c| c[1].to_string())).collect()
}

/// The output with every run of whitespace (wrapped lines included) collapsed to one space.
fn flat(out: &str) -> String {
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A project of the synthetic dll made by `dcp init` (nothing declared), without an analyzer.
fn fresh() -> PathBuf {
    let d = tmp("fresh");
    let pe = build_pe(&d.join("t.dll"), 0, Some(RICH_TINY));
    let root = d.join("proj");
    let (code, out, err) = dcp_bare(&["init", &root.to_string_lossy(), &pe.to_string_lossy()]);
    assert_eq!(code, 0, "{out}{err}");
    let t = read(&root, "decompanion.toml");
    let t = &t[..t.find("[analyzer]").unwrap()];
    write(&root, "decompanion.toml", &format!("{t}[analyzer]\nroot = \"C:/nowhere/ghidra\"\n")); // no Ghidra run in tests
    root
}

#[test]
fn init_writes_no_decision() {
    let f = fresh();
    let cfg: toml::Table = toml::from_str(&read(&f, "decompanion.toml")).unwrap();
    let keys: std::collections::BTreeSet<&str> = cfg.keys().map(|k| k.as_str()).collect();
    assert_eq!(keys, ["analyzer", "sources", "target"].into()); // no [toolchain], no [libs]
    let t = cfg["target"].as_array().unwrap()[0].as_table().unwrap();
    let tk: std::collections::BTreeSet<&str> = t.keys().map(|k| k.as_str()).collect();
    assert_eq!(tk, ["image", "isa", "name", "path", "sha256"].into()); // computed from the file
    assert!(!cfg["analyzer"].as_table().unwrap().contains_key("reason")); // the analyzer is computed, to be confirmed
}

#[test]
fn status_after_setup_lists_the_toolchain_obligations() {
    let f = fresh();
    let (code, out) = dcp(&f, &["setup", "--no-analyzer"]);
    assert_eq!(code, 0, "{out}");
    let tail = &out[out.find("dcp status: t").unwrap()..];
    assert!(tail.contains("phase  setup") && tail.contains("open   7 (6 to do now, 1 waiting)"), "{tail}");
    assert_eq!(obligations(tail), ["toolchain.compiler", "toolchain.linker", "toolchain.root", "toolchain.cflags", "libs.archives", "analyzer", "layout"]);
    assert!(flat(tail).contains("Rich compilers cl 12.00.8047 x5, cl 12.00.9044 x3; built"), "{tail}");
    assert!(tail.contains("5. libs.archives      target t") && tail.contains("wait  on toolchain.root: declare that first"), "{tail}");
    assert!(tail.contains("next: dcp toolchain declare compiler="), "{tail}");
    let (code, again) = dcp(&f, &["status"]);
    assert!(code == 0 && obligations(&again) == obligations(tail));
    let (_, rules) = dcp(&f, &["rules", "-v"]);
    for r in ["S.crt.code", "S.crt.refs", "S.crt.data", "S4.import.libs"] {
        assert!(rules.lines().any(|l| l.starts_with(&format!("{r} ")) && l.contains(" waiting ")), "{r}");
    }
    assert!(rules.contains("    waiting: libs.archives  (dcp status)") && rules.contains("    waiting: toolchain.compiler, toolchain.linker  (dcp status)"), "{rules}");
}

/// --json is the output contract (one record per line) for scripts; the guided view is the default.
#[test]
fn status_json_keeps_the_records() {
    let f = fresh();
    assert_eq!(dcp(&f, &["setup", "--no-analyzer"]).0, 0);
    let (code, out) = dcp(&f, &["status", "--json"]);
    assert_eq!(code, 0);
    let rows: Vec<Value> = out.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(rows[0], json!({"status": "t", "phase": "setup", "open": 7}));
    let ids: Vec<String> = rows[1..].iter().map(|r| r["obligation"].as_str().unwrap().to_string()).collect();
    assert_eq!(ids, obligations(&dcp(&f, &["status"]).1));
    assert_eq!(rows[1]["resolve"], "dcp toolchain declare compiler=\"<one of the Rich compilers>\" --why \"...\"");
    assert!(rows[5].get("waits").is_some() && rows[5]["obligation"] == "libs.archives");
}

#[test]
fn declare_refuses_a_missing_why() {
    let f = fresh();
    let before = read(&f, "decompanion.toml");
    assert_eq!(dcp(&f, &["toolchain", "declare", "compiler=cl 12.00.9044"]).0, 2);
    assert_eq!(dcp(&f, &["toolchain", "declare", "compiler=cl 12.00.9044", "--why", "  "]).0, 2);
    assert_eq!(dcp(&f, &["libs", "declare", "LIBCMT"]).0, 2);
    assert_eq!(dcp(&f, &["analyzer", "declare", "none"]).0, 2);
    assert_eq!(read(&f, "decompanion.toml"), before);
}

#[test]
fn declarations_end_the_waits() {
    let f = fresh();
    assert_eq!(dcp(&f, &["setup", "--no-analyzer"]).0, 0);
    let vc = f.parent().unwrap().join("vc");
    std::fs::create_dir_all(&vc).unwrap();
    let root = format!("root={}", posix(&vc));
    let (code, out) = dcp(&f, &["toolchain", "declare", "compiler=cl 12.00.9044", "linker=link 6.00.8447", &root, "cflags=/O2 /Gy", "--why",
                                "the Rich builds of the user's objects"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("C.toolchain: ok") && obligations(&out) == ["libs.archives", "analyzer", "layout"], "{out}");
    assert!(out.contains("flags  '/O2' '/Gy'"), "{out}"); // the flags as stored, one token each
    let d = project(&f, None).toolchain_decl(None).unwrap();
    let why = "the Rich builds of the user's objects";
    assert_eq!(d["reasons"], json!({"root": why, "compiler": why, "linker": why, "cflags": why}));
    assert_eq!(d["cflags"], json!(["/O2", "/Gy"]));
    let lib = build_lib(&f.parent().unwrap().join("crt.lib"), &[(0x0a, 8047), (0x0a, 8047)]);
    let (code, out) = dcp(&f, &["libs", "declare", &posix(&lib), "--why", "the CRT objects of the Rich header"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(obligations(&out), ["analyzer", "layout"]);
    assert!(read(&f, "decompanion.toml").contains(&format!("archives = [\"{}\"]\nreason.archives = \"the CRT objects of the Rich header\"", posix(&lib))));
    let (_, rules) = dcp(&f, &["rules"]);
    assert!(!rules.split_once('\n').unwrap().1.contains("waiting") || rules.contains("waiting=0"), "{rules}");
    assert!(rules.contains("waiting=0"), "{rules}");
    let tc = facts(&f, "toolchain", None)[0].value.clone();
    let rich = tc["compilers"].as_array().unwrap().iter().find(|c| c["build"] == 8047).unwrap().clone();
    assert_eq!(rich["archive_objects"], 2); // S.rich reads the declared archives now
    let (code, out) = dcp(&f, &["analyzer", "declare", "--why", "no drafts in a unit test"]);
    assert!(code == 0 && obligations(&out) == ["layout"], "{out}");
    assert_eq!(dcp(&f, &["check"]).0, 0);
}

/// A shell that mangled the value is visible at once: the flags line shows the tokens as they were stored.
#[test]
fn declare_prints_each_cflag_it_stored() {
    let f = fresh();
    assert_eq!(dcp(&f, &["setup", "--no-analyzer"]).0, 0);
    let (code, out) = dcp(&f, &["toolchain", "declare", "cflags=C:/Program Files/Git/O2 /Gy", "--why", "test: a mangled value"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("flags  'C:/Program' 'Files/Git/O2' '/Gy'"), "{out}");
}

#[test]
#[ignore = "e2e: starts git"]
fn session_start_fails_on_an_open_obligation() {
    let f = fresh();
    let git = |a: &[&str]| {
        let o = std::process::Command::new("git").args(["-c", "user.name=t", "-c", "user.email=t@t"]).args(a).current_dir(&f).output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    };
    git(&["init", "-q", "-b", "main"]);
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "init"]);
    let (code, out) = dcp(&f, &["session", "start"]);
    assert!(code == 1 && out.contains("gate: FAIL"), "{out}");
    assert!(out.contains("obligations=5  gate=FAIL") && out.contains("    obligation=toolchain.compiler  target=t"), "{out}");
    let (code, out) = dcp(&f, &["check"]);
    assert!(code == 1 && out.contains("obligation=toolchain.root"), "{out}");
}
