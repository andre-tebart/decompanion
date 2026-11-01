//! Every command and rule per target and across targets, on the synthetic dll as two targets (tiny, other): the
//! toolchain declaration and the Rich candidates, library archives, the loaders' target prefixes, decl add, layout,
//! the analyzer, setup --all-targets, seed (tests/test_multitarget.py).

use super::*;
use serde_json::{json, Value};

fn toolchain(t: &Path, target: Option<&str>) -> Value {
    facts(t, "toolchain", target)[0].value.clone()
}

#[test]
fn rich_candidates_per_target() {
    let t = tiny2();
    assert_eq!(dcp(&t, &["setup", "--all-targets"]).0, 0);
    let tv = toolchain(&t, None);
    let ov = toolchain(&t, Some("other"));
    let c: Vec<(String, i64, i64)> = tv["compilers"].as_array().unwrap().iter()
        .map(|c| (c["tool"].as_str().unwrap().to_string(), c["build"].as_i64().unwrap(), c["count"].as_i64().unwrap())).collect();
    assert_eq!(c, [("Utc12_C".to_string(), 8047, 5), ("Utc12_2_C".to_string(), 9044, 3)]);
    let builds = |v: &Value, k: &str| v[k].as_array().unwrap().iter().map(|c| c["build"].as_i64().unwrap()).collect::<std::collections::BTreeSet<_>>();
    assert_eq!(builds(&ov, "compilers"), [8047, 9044, 9178].into());
    assert_eq!(builds(&ov, "linkers"), [8447, 9049].into());
    assert!(tv.get("compiler_build").is_none()); // nothing is picked
    // both inherit the [toolchain] defaults cl 12.00.9044 / link 6.00.8447: candidates of both
    let (code, out) = dcp(&t, &["check"]);
    assert_eq!(code, 0, "{out}");
}

#[test]
fn toolchain_declaration_per_target() {
    let t = tiny2();
    target_table(&t, "other", "compiler = \"cl 13.00.9178\"\nreason = \"the VC7 object, on purpose\"");
    let d = project(&t, Some("other")).toolchain_decl(None).unwrap();
    assert!(d["compiler"] == "cl 13.00.9178" && d["linker"] == "link 6.00.8447" && d["from"]["compiler"] == "target", "{d}");
    assert!(d["from"]["linker"] == "toolchain" && d["cflags"] == json!(["/O2"]), "{d}");
    assert_eq!(project(&t, None).toolchain_decl(None).unwrap()["compiler"], "cl 12.00.9044");
    assert_eq!(dcp(&t, &["check"]).0, 0); // 9178 is a compiler candidate of other
    // the same declaration on tiny is wrong there only
    target_table(&t, "tiny", "compiler = \"cl 13.00.9178\"\nreason = \"wrong on purpose\"");
    let (code, _) = dcp(&t, &["check"]);
    assert_eq!(code, 1);
    let bad = conflicts_of(&t, Some("tiny"), "C.toolchain");
    assert!(bad.len() == 1 && bad[0].4.contains("names build 9178") && bad[0].4.contains("cl 12.00.9044 (Utc12_2_C x3)"), "{bad:?}");
    assert!(conflicts_of(&t, Some("other"), "C.toolchain").is_empty());
    let (_, out) = dcp(&t, &["toolchain"]);
    for w in ["target=tiny", "target=other", "C.toolchain: 1 error(s)", "C.toolchain: ok", "cl 13.00.9178 (Utc13_C C x1)",
              "key=linker  value='link 6.00.8447'  level=declared  source=toolchain",
              "key=compiler  value='cl 13.00.9178'  level=declared  source=target  why='the VC7 object, on purpose'"] {
        assert!(out.contains(w), "{w}: {out}");
    }
    let (_, out) = dcp(&t, &["--target", "other", "toolchain"]);
    assert!(!out.contains("target=tiny") && out.contains("target=other"), "{out}");
}

#[test]
fn toolchain_missing_reason_and_compiler() {
    let t = tiny2();
    set_config(&t, "reason = \"test project\"\n", "");
    set_config(&t, "compiler = \"cl 12.00.9044\"\n", "");
    target_table(&t, "other", "compiler = \"cl 12.00.9044\"\nreason = \"declared\"");
    let (code, out) = dcp(&t, &["check"]);
    assert_eq!(code, 1);
    // tiny: no compiler at all -> C.toolchain waits, the obligation fails the gate; the linker has no reason
    assert!(conflicts_of(&t, Some("tiny"), "C.toolchain").is_empty());
    assert!(out.contains("obligation=toolchain.compiler  target=tiny  missing=\"the compiler build that made the user's objects (missing)\""), "{out}");
    assert!(out.contains("obligation=toolchain.linker  target=tiny  missing='the linker build (declared without a reason)'"), "{out}");
    let (_, rules) = dcp(&t, &["rules"]);
    assert!(rules.contains("C.toolchain        v2   proven    waiting") && rules.contains("waiting: toolchain.compiler  (dcp status)"), "{rules}");
    // other: its own compiler with a reason; the inherited linker and cflags have none -> C.toolchain errors
    let msgs: Vec<String> = conflicts_of(&t, Some("other"), "C.toolchain").into_iter().map(|c| c.4).collect();
    assert_eq!(msgs, ["target other: the cflags declaration has no reason", "target other: the linker declaration has no reason"]);
}

#[test]
fn unknown_target_key() {
    let t = tiny2();
    target_table(&t, "other", "compilr = \"cl 12.00.9044\"");
    let Err(e) = crate::project::Project::find(Some(&t.to_string_lossy()), None) else { panic!("no error") };
    assert!(e.to_string().contains("unknown keys compilr"), "{e}");
}

#[test]
fn archives_per_target() {
    let t = tiny2();
    let lib = build_lib(&t.join("crt.lib"), &[(0x0a, 8047), (0x0a, 8047)]);
    target_table(&t, "other", &format!("archives = [\"{}\"]", posix(&lib)));
    assert!(project(&t, None).lib_archives(None).unwrap().is_empty());
    assert_eq!(project(&t, Some("other")).lib_archives(None).unwrap().iter().map(|a| a.replace('\\', "/")).collect::<Vec<_>>(), [posix(&lib)]);
    assert_eq!(dcp(&t, &["setup", "--all-targets"]).0, 0);
    let crt = |target: &str| toolchain(&t, Some(target))["compilers"].as_array().unwrap().iter().find(|c| c["build"] == 8047).unwrap()["archive_objects"].as_i64().unwrap();
    assert_eq!((crt("tiny"), crt("other")), (0, 2));
    // a changed archive reruns the rules of the target that names it, not the other's
    build_lib(&lib, &[(0x0a, 8047)]);
    crate::fsmemo::new_epoch();
    assert!(!engine_ran(&t, Some("tiny")));
    assert!(engine_ran(&t, Some("other")));
    assert_eq!(crt("other"), 1);
    let (_, out) = dcp(&t, &["--target", "other", "toolchain"]);
    assert!(out.contains("archives=crt.lib  source=target"), "{out}");
}

#[test]
fn setup_all_targets_and_memo() {
    let t = tiny2();
    let (code, out) = dcp(&t, &["setup", "--all-targets"]);
    assert!(code == 0 && out.contains("target=tiny") && out.contains("target=other") && out.contains("toolchain: compiler='cl 12.00.9044'"), "{out}");
    let (code, _, err) = dcp3(&t, &["setup", "--all-targets"]);
    assert!(code == 0 && !err.contains("rules:"), "{err}"); // a second setup runs no rule
    let (_, out) = dcp(&t, &["report", "--target", "other"]);
    assert!(out.contains("target=other") && !out.contains("target=tiny"), "{out}");
    assert_eq!(dcp(&t, &["setup", "--all-targets", "--target", "other"]), (2, String::new()));
}

#[test]
fn src_prefixes() {
    let t = tiny2();
    unit(&t, "net", &["int both;  /* tiny:0x10002000, other:0x10002004 */\nint mine;  /* 0x10002008 */\n",
                      "/* tiny:0x10001020, other:0x10001030, the helper in both */\nint get(void)\n{\n    return 1;\n}\n",
                      "#ifdef DCP_TARGET_tiny\n/* 0x10001050, the default target's only */\nint put(void)\n{\n    return 2;\n}\n#endif\n"]);
    assert_eq!(dcp(&t, &["check"]).0, 0);
    let src = |target: &str| facts(&t, "source", Some(target)).iter().map(|f| (f.lo, f.value["symbol"].as_str().unwrap().to_string())).collect::<std::collections::BTreeSet<_>>();
    let set = |v: &[(i64, &str)]| v.iter().map(|(a, s)| (*a, s.to_string())).collect::<std::collections::BTreeSet<_>>();
    assert_eq!(src("tiny"), set(&[(0x10001020, "get"), (0x10001050, "put"), (0x10002000, "both"), (0x10002008, "mine")]));
    assert_eq!(src("other"), set(&[(0x10001030, "get"), (0x10002004, "both")]));
    let starts: Vec<i64> = facts(&t, "start", Some("other")).iter().filter(|f| f.value["how"] == "source").map(|f| f.lo).collect();
    assert_eq!(starts, [0x10001030]);
}

#[test]
fn src_errors_reported_once() {
    let t = tiny2();
    unit(&t, "net", &["void g(void)\n{\n}\n", "/* nope:0x10001030, unknown target */\nvoid h(void)\n{\n}\n"]);
    let (code, _) = dcp(&t, &["check"]);
    assert_eq!(code, 1);
    assert!(conflicts_of(&t, Some("tiny"), "L.src").len() == 2 && conflicts_of(&t, Some("other"), "L.src").is_empty());
    assert!(conflicts_of(&t, Some("tiny"), "L16").is_empty()); // an unknown prefix is the one error
}

#[test]
fn placeholders_per_target() {
    let t = tiny2();
    unit(&t, "net", &["int x;\nint y(void);\n#define Z FUN_20001000\n",
                      "#ifdef DCP_TARGET_other\n/* other:0x10001020, other's only */\nint g(void)\n{\n    return FUN_10001044();\n}\n#endif\n"]);
    let (code, _) = dcp(&t, &["check"]);
    assert_eq!(code, 1);
    let l5 = |target: &str| conflicts_of(&t, Some(target), "L5").into_iter().map(|c| c.4).collect::<Vec<_>>();
    assert!(l5("other").iter().any(|m| m.contains("FUN_10001044"))); // a function of other: checked in other
    assert!(!l5("tiny").iter().any(|m| m.contains("FUN_10001044"))); // not a line of tiny
    assert!(l5("tiny").iter().any(|m| m.contains("FUN_20001000") && m.contains("tiny, other")));
    assert!(!l5("other").iter().any(|m| m.contains("FUN_20001000"))); // reported once, by the default target
}

#[test]
fn decl_prefixes_and_add() {
    let t = tiny2();
    let (code, out) = dcp(&t, &["--target", "other", "decl", "add", "0x10001050 name Handler -- reached through data only"]);
    assert_eq!(code, 0, "{out}");
    assert!(read(&t, "decl/text.dcl").contains("other:0x10001050 name Handler -- reached through data only"));
    let (code, out) = dcp(&t, &["decl", "add", "0x10001050 name Fourth -- the default target's"]);
    assert_eq!(code, 0, "{out}");
    let names = |target: &str| facts(&t, "name", Some(target)).iter().filter(|f| f.value.get("origin") == Some(&json!("decl")))
        .map(|f| f.value["name"].as_str().unwrap().to_string()).collect::<Vec<_>>();
    assert_eq!(names("tiny"), ["Fourth"]);
    assert_eq!(names("other"), ["Handler"]);
    let text = read(&t, "decl/text.dcl");
    let lines: Vec<&str> = text.lines().filter(|l| !l.starts_with('#')).collect();
    assert_eq!(lines, ["0x10001050 name Fourth -- the default target's", "other:0x10001050 name Handler -- reached through data only"]);
    // an error of an other: line is other's conflict only
    write(&t, "decl/text.dcl", "# code\nother:0x10001000 frob -- unknown kind\n");
    let (code, _) = dcp(&t, &["check"]);
    assert!(code == 1 && !conflicts_of(&t, Some("other"), "L.decl").is_empty() && conflicts_of(&t, Some("tiny"), "L.decl").is_empty());
}

#[test]
fn layout_per_target() {
    let t = tiny2();
    assert_eq!(dcp(&t, &["setup", "--all-targets"]).0, 0);
    let (code, out) = dcp(&t, &["--target", "other", "layout", "unit", "propose", "0x10001020..0x10001050", "--name", "net", "--why", "leaked path"]);
    assert_eq!(code, 0, "{out}");
    let text = read(&t, "decl/text.dcl");
    assert!(text.contains("other:0x10001020 boundary start tu=net -- leaked path") && text.contains("other:0x10001050 boundary end tu=net"), "{text}");
    let (_, out) = dcp(&t, &["--target", "other", "layout", "units"]);
    assert!(out.contains("target=other") && out.contains("unit=net") && out.contains("status=separated"), "{out}");
    let (_, out) = dcp(&t, &["layout", "units"]);
    assert!(out.contains("target=tiny") && out.contains("units=0"), "{out}");
    let (_, out) = dcp(&t, &["--target", "other", "layout", "next", "--start", "0x10001020"]);
    assert!(out.contains("target=other") && out.contains("unit=net"), "{out}");
}

/// The analyzer's export of the second target stores its drafts in that target's store only.
#[test]
fn analyzer_per_target() {
    let t = tiny2();
    let j = json!({"subject": {"digest": {"sha256": sha256_of(&t.join("tiny2.dll"))}},
        "normalized_result": {"items": [{"address": "0x10001050", "status": "ok", "pseudocode": "int f(void)\n{\n  return 0;\n}\n",
                                         "procedure": {"address": "0x10001050", "name": "FUN_10001050"}}]}});
    let f = t.parent().unwrap().join("other.json");
    std::fs::write(&f, j.to_string()).unwrap();
    use_fake_ghidra(&t, &f);
    let (code, out) = dcp(&t, &["--target", "other", "setup"]);
    assert!(code == 0 && out.contains("analyzer=ghidra  exported=1") && out.contains("target=other"), "{out}");
    assert_eq!(dcp(&t, &["--target", "other", "draft", "0x10001050", "--show"]).0, 0);
    assert_eq!(dcp(&t, &["draft", "0x10001050", "--show"]).0, 1);
    assert_eq!(facts(&t, "start", Some("other")).iter().filter(|s| s.value["how"] == "ghidra").map(|s| s.lo).collect::<Vec<_>>(), [0x10001050]);
    assert!(!facts(&t, "start", None).iter().any(|s| s.value["how"] == "ghidra"));
}

#[test]
fn queries_name_the_target() {
    let t = tiny2();
    assert_eq!(dcp(&t, &["setup", "--all-targets"]).0, 0);
    for cmd in [&["facts", "0x10001000..0x10001010"][..], &["conflicts"], &["map", "0x10001000..0x10001040"], &["rules"]] {
        let mut a = vec!["--target", "other"];
        a.extend(cmd);
        let (code, out) = dcp(&t, &a);
        assert!(code == 0 && out.starts_with("target=other"), "{cmd:?}: {out}");
    }
    let (_, out) = dcp(&t, &["--target", "other", "why", "0x10001020"]);
    assert!(out.contains("target=other") && out.contains("toolchain  compilers=3  linkers=2"), "{out}");
}

#[test]
fn seed_copies_every_store() {
    let t = tiny2();
    assert_eq!(dcp(&t, &["setup", "--all-targets"]).0, 0);
    let dest = t.parent().unwrap().join("copy");
    std::fs::create_dir_all(&dest).unwrap();
    for e in std::fs::read_dir(&t).unwrap().flatten() {
        if e.file_name() != "build" && e.path().is_file() {
            std::fs::copy(e.path(), dest.join(e.file_name())).unwrap();
        }
    }
    std::fs::create_dir_all(dest.join("decl")).unwrap();
    for f in ["text.dcl", "data.dcl"] {
        std::fs::copy(t.join("decl").join(f), dest.join("decl").join(f)).unwrap();
    }
    let (code, out) = dcp(&t, &["seed", &dest.to_string_lossy()]);
    assert!(code == 0 && out.contains("other.sqlite") && out.contains("tiny.sqlite"), "{out}");
    for name in ["tiny", "other"] {
        assert!(!engine_ran(&dest, Some(name)), "{name}");
    }
}
