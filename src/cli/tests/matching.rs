//! The match phase on the synthetic dll: the translation units of the scan, Q6's documentation, the unit targets; with
//! VC6 installed: compile and byte match, the literal check, asmdiff --symbols, rename against the tree's errors,
//! escalate, headers --trial, promote / accept, the include-set cache, lint (libclang), Q4, auto-clear and the data
//! order (tests/test_match.py).

use super::*;
use crate::store::REPRODUCED;

const VC6: &str = "C:/Tools/MSVC600-SP5PP";

fn has_vc6() -> bool {
    Path::new(VC6).join("VC98/Bin/CL.EXE").exists()
}

fn with_vc6(root: &Path) {
    set_config(root, "root = \"C:/nowhere/vc6\"\n", &format!("root = \"{VC6}\"\n"));
}

fn scan(root: &Path) -> std::rc::Rc<crate::frontend::Scan> {
    crate::frontend::scan(&root.to_string_lossy(), None).unwrap()
}

/// (file, line, check, message) of the scan's errors of one check.
fn errors(sc: &crate::frontend::Scan, check: &str) -> Vec<(String, i64, String, String)> {
    sc.parts.iter().flat_map(|p| p.errors.iter().cloned()).chain(sc.own_errors.iter().cloned()).filter(|e| e.2 == check).collect()
}

fn all_errors(sc: &crate::frontend::Scan) -> Vec<(String, i64, String, String)> {
    sc.parts.iter().flat_map(|p| p.errors.iter().cloned()).chain(sc.own_errors.iter().cloned()).collect()
}

/// {unit: [(address or None, name)]} of one target's translation units (plan.rs).
fn units(root: &Path, sc: &crate::frontend::Scan, target: &str) -> std::collections::BTreeMap<String, Vec<(Option<i64>, String)>> {
    crate::plan::plan_scan_units(&root.to_string_lossy(), sc, target, "tiny", None).unwrap().into_iter().map(|(_, u, _, fns, _, _)| (u, fns)).collect()
}

#[test]
fn unit_file_order_and_fn() {
    let t = tiny();
    unit(&t, "net", &["int counter = 1;  /* 0x10002000 */\n", "/* 0x10001030, logs */\nvoid log3(void)\n{\n}\n",
                      "/* 0x10001020, reads */\nint get(void)\n{\n    return counter;\n}\n", "/* unlinked, dropped by /OPT:REF */\nvoid spare(void)\n{\n}\n",
                      "int last = 2;\n"]);
    let sc = scan(&t);
    assert!(all_errors(&sc).is_empty(), "{:?}", all_errors(&sc));
    let u = units(&t, &sc, "tiny");
    assert_eq!(u["net"], [(Some(0x10001030), "log3".to_string()), (Some(0x10001020), "get".to_string()), (None, "spare".to_string())]); // the text's order
    let get = sc.functions().find(|f| f.0 .3 == "get").unwrap();
    assert_eq!((get.1 .3, get.0 .1, get.1 .5), (8, 9, 12));
    let (code, out) = dcp(&t, &["fn", "0x10001020"]);
    assert!(code == 0 && out.contains("at=src/net.c:8-12") && out.ends_with("/* 0x10001020, reads */\nint get(void)\n{\n    return counter;\n}\n"), "{out}");
    // a definition without its address comment directly above it
    unit(&t, "net", &["/* 0x10001020, reads */\nint x;\nint get(void)\n{\n    return 1;\n}\n"]);
    let errs = errors(&scan(&t), "L.src");
    assert!(errs.len() == 1 && errs[0].3.contains("get: no address comment") && errs[0].1 == 3, "{errs:?}");
    unit(&t, "net", &["/* 0x10001020, reads */\nint get(void)\n{\n    return 1;\n}\n"]);
    write(&t, "src/old/f_10001020.c", "int y;\n");
    let errs = errors(&scan(&t), "L.src");
    assert!(errs.len() == 1 && errs[0].3.contains("unexpected source file src/old/f_10001020.c"), "{errs:?}");
}

/// Q6's described addresses: a function's definition comment and its declaration in its owner header
/// include/<unit>.h; never a copy in another unit's header or source, nor a later address in another function's
/// comment, nor a text that only names a file.
#[test]
fn q6_reads_a_functions_own_documentation() {
    let t = tiny();
    write(&t, "include/net.h", "int get(void);  /* 0x10001020, reads the counter */\nvoid log3(void);  /* 0x10001030, logs three times */\n");
    write(&t, "include/log.h", "void log3(void);  /* 0x10001030, net.h */\n");
    unit(&t, "net", &["#include \"net.h\"\nvoid log4(void);  /* 0x10001040, logs four times */\n", "/* 0x10001020 */\nint get(void)\n{\n    return 1;\n}\n",
                      "/* 0x10001060, 0x10001030 on the record */\nvoid put(void)\n{\n}\n"]);
    unit(&t, "log", &["int get(void);  /* 0x10001020, as in net.h */\n", "/* 0x10001030 */\nvoid log3(void)\n{\n}\n",
                      "/* 0x10001040, defined in log.c */\nvoid log4(void)\n{\n}\n", "/* 0x10001050, logs five times */\nvoid log5(void)\n{\n}\n"]);
    assert_eq!(crate::frontend::context(&scan(&t)).1, [0x10001020, 0x10001050, 0x10001060]);
}

#[test]
fn unit_targets() {
    let t = tiny2();
    unit(&t, "net", &["/* 0x10001020, other:0x10001020, both */\nint get(void)\n{\n    return 1;\n}\n",
                      "#if defined(DCP_TARGET_other)\n/* other:0x10001030, only the second target */\nvoid only(void)\n{\n}\n#endif\n",
                      "#ifdef DCP_TARGET_tiny\n/* 0x10001050, only the default target */\nvoid first(void)\n{\n}\n#endif\n"]);
    unit(&t, "lone", &["#ifdef DCP_TARGET_other\n/* other:0x10001040, a unit of the second target only */\nvoid lone(void)\n{\n}\n#endif\n"]);
    let sc = scan(&t);
    assert!(all_errors(&sc).is_empty(), "{:?}", all_errors(&sc));
    let names = |u: std::collections::BTreeMap<String, Vec<(Option<i64>, String)>>| u.into_iter().map(|(k, v)| (k, v.into_iter().map(|x| x.1).collect::<Vec<_>>())).collect::<Vec<_>>();
    assert_eq!(names(units(&t, &sc, "tiny")), [("net".to_string(), vec!["get".to_string(), "first".to_string()])]);
    assert_eq!(names(units(&t, &sc, "other")), [("lone".to_string(), vec!["lone".to_string()]), ("net".to_string(), vec!["get".to_string(), "only".to_string()])]);
    // L16: a function the guard and the comment disagree on
    unit(&t, "lone", &["/* other:0x10001040, unguarded */\nvoid lone(void)\n{\n}\n"]);
    let errs = errors(&scan(&t), "L16");
    assert!(errs.len() == 1 && errs[0].3.contains("lone is compiled into tiny") && errs[0].3.contains("DCP_TARGET_other"), "{errs:?}");
    unit(&t, "lone", &["#ifdef DCP_TARGET_tiny\n/* other:0x10001040, the wrong guard */\nvoid lone(void)\n{\n}\n#endif\n"]);
    let mut msgs: Vec<String> = errors(&scan(&t), "L16").into_iter().map(|e| e.3).collect();
    msgs.sort();
    assert!(msgs.len() == 2 && msgs[1].contains("lists other, whose compile does not hold it"), "{msgs:?}");
}

/// The declarations of the VC6 tests: f2 is the unit net, f3 another.
fn net_decl(t: &Path) {
    write(t, "decl/text.dcl", "# code\n0x10001020 boundary start tu=net by=tag -- f2 reads the counter\n0x10001030 boundary end tu=net -- f3 is another unit\n");
}

/// f2 of the synthetic dll is `mov eax, [0x10002000]; ret`: `return counter;` compiles to it.
#[test]
#[ignore = "e2e: VC6"]
fn compile_and_byte_match() {
    if !has_vc6() {
        return;
    }
    let t = tiny();
    with_vc6(&t);
    net_decl(&t);
    let head = "int counter = 0x1234;  /* 0x10002000 */\n";
    unit(&t, "net", &[head, "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return counter;\n}\n"]);
    let (code, out) = dcp(&t, &["build"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("compiled=1") && out.contains("grades: byte+readable=1"), "{out}");
    let sym: Vec<(i64, i64, crate::store::Support, String)> = facts(&t, "symbol", None).iter().filter(|f| &*f.rule == "M.match")
        .map(|f| (f.lo, f.hi, f.support, f.value["relocs"].as_str().unwrap_or("").to_string())).collect();
    assert_eq!(sym, [(0x10001020, 0x10001026, REPRODUCED, "1/1".to_string())]);
    assert!(dcp(&t, &["build"]).1.contains("compiled=0")); // nothing changed: nothing compiles, no rule runs
    let (_, out) = dcp(&t, &["grade", "get"]);
    assert!(out.contains("experiment=byte") && out.contains("readability=readable"), "{out}");
    // a draft: another constant
    unit(&t, "net", &[head, "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return counter + 1;\n}\n"]);
    let (_, out) = dcp(&t, &["grade", "get"]);
    assert!(out.contains("experiment=draft") && out.contains("B3 draft"), "{out}");
    assert!(dcp(&t, &["diffclass", "get"]).1.contains("code"));
    // a big code hunk: its first lines and how many more (every line with --all)
    let calls: String = (1..10).map(|k| format!("    put({k});\n")).collect();
    unit(&t, "net", &[&format!("{head}void put(int x);\n"), &format!("/* 0x10001020, reads the counter */\nint get(void)\n{{\n{calls}    return counter;\n}}\n")]);
    let (_, out) = dcp(&t, &["diffclass", "get"]);
    assert!(out.contains("      - push 1") && out.contains("more of ours: --all, or dcp asmdiff)"), "{out}");
    let (_, out) = dcp(&t, &["diffclass", "get", "--all"]);
    assert!(!out.contains("more of ours") && out.matches("      - call X").count() == 9, "{out}");
    // a compile error names the unit's file and line and fails the gate
    unit(&t, "net", &[head, "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return nothing;\n}\n"]);
    let (code, out) = dcp(&t, &["build"]);
    assert!(code == 1 && out.contains("src/net.c(6)") && out.contains("C2065"), "{out}");
    assert!(out.trim_end().lines().last().unwrap().starts_with("  FAILED units=net  "), "{out}");
    let (code, out) = dcp(&t, &["check"]);
    assert!(code == 1 && out.contains("M.compile"), "{out}");
}

#[test]
#[ignore = "e2e: VC6"]
fn byte_match_with_a_differing_literal_is_no_byte() {
    if !has_vc6() {
        return;
    }
    let t = tiny();
    with_vc6(&t);
    net_decl(&t);
    let f = |lit: &str| format!("/* 0x10001020, reads the counter */\nint get(void)\n{{\n    return *(int *)\"{lit}\";\n}}\n");
    unit(&t, "net", &[&f("\\x34\\x12")]);
    assert_eq!(dcp(&t, &["build"]).0, 0);
    assert!(dcp(&t, &["grade", "get"]).1.contains("experiment=byte"));
    let (_, out) = dcp(&t, &["asmdiff", "get", "--symbols"]); // the literal is the original's: one name
    assert!(out.contains("   0x10001020  mov eax, dword ptr [0x10002000]") && !out.contains("\n!  "), "{out}");
    unit(&t, "net", &[&f("\\x34\\x13")]);
    dcp(&t, &["build"]);
    assert_eq!(facts(&t, "symbol", None).iter().filter(|f| &*f.rule == "M.match").map(|f| f.lo).collect::<Vec<_>>(), [0x10001020]);
    let (_, out) = dcp(&t, &["grade", "get"]);
    assert!(out.contains("experiment=draft") && out.contains("B1 byte: M9") && out.contains("differs from the original's bytes"), "{out}");
    assert!(out.contains("B3 draft: 1 referenced literal(s) / constant(s) differ from the original's (M9)"), "{out}");
    let (_, out) = dcp(&t, &["asmdiff", "get"]); // X on both sides: equal
    assert!(out.contains("differing=0") && !out.contains("... ") && out.contains("   0x10001020  mov eax, dword ptr [X]"), "{out}");
    let (_, out) = dcp(&t, &["asmdiff", "get", "--symbols"]);
    assert!(out.contains("differing=0") && out.contains("!  0x10001020  mov eax, dword ptr [\"4\\x13\"]   | mov eax, dword ptr [0x10002000]"), "{out}");
}

#[test]
#[ignore = "e2e: VC6"]
fn asmdiff_symbols_marks_an_alias_equal() {
    if !has_vc6() {
        return;
    }
    let t = tiny();
    with_vc6(&t);
    net_decl(&t);
    write(&t, "include/other.h", "extern int net_Counter;  /* 0x10002000 */\n");
    unit(&t, "net", &["#include \"other.h\"\nint counter = 0x1234;  /* 0x10002000 */\nvoid put(int x);\n",
                      "/* 0x10001020, reads the counter */\nint get(void)\n{\n    put(1);\n    return net_Counter;\n}\n"]);
    dcp(&t, &["build"]);
    let (_, out) = dcp(&t, &["asmdiff", "get", "--symbols"]);
    assert!(out.contains("=  ") && out.contains("dword ptr [net_Counter]   | mov eax, dword ptr [counter]") && !out.contains("\n!  "), "{out}");
    let (_, out) = dcp(&t, &["check", "--strict"]);
    assert!(out.contains("C.name.alias") && out.contains("counter (src/net.c:2), net_Counter (include/other.h:1)"), "{out}");
}

#[test]
#[ignore = "e2e: VC6"]
fn rename_counts_the_errors_of_the_tree_as_from_before() {
    if !has_vc6() {
        return;
    }
    let t = tiny();
    with_vc6(&t);
    net_decl(&t);
    let f = |name: &str, lit: &str| format!("/* 0x10001020, reads the counter */\nint {name}(void)\n{{\n    return *(int *)\"{lit}\";\n}}\n");
    unit(&t, "net", &[&f("get", "\\x34\\x12")]);
    assert_eq!(dcp(&t, &["build"]).0, 0);
    unit(&t, "net", &[&f("get", "\\x34\\x13")]); // the edit, not built
    let (code, out) = dcp(&t, &["rename", "get", "read_counter", "--why", "reads the counter"]);
    assert!(code == 0 && out.contains("renamed=get") && out.contains("check: 0 new error(s) after the rename, 1 from before"), "{out}");
    assert!(out.contains("build: 1 of 1 unit(s) that read the renamed files keep their objects"), "{out}");
    let db = project(&t, None).store_path();
    let h: String = rusqlite::Connection::open(&db).unwrap().query_row("SELECT obj_hash FROM tu WHERE unit='net'", [], |r| r.get(0)).unwrap();
    let obj = std::fs::read(t.join("build/obj").join(format!("{h}.obj"))).unwrap();
    assert!(obj.windows(13).any(|w| w == b"_read_counter"));
    let (code, out) = dcp(&t, &["rename", "read_counter", "counter_value", "--why", "the store names read_counter"]);
    assert!(code == 0 && out.contains("check: 0 new error(s) after the rename, 1 from before"), "{out}");
    unit(&t, "net", &[&f("counter_value", "\\x34\\x12")]);
    assert_eq!(dcp(&t, &["build"]).0, 0);
    let (code, out) = dcp(&t, &["rename", "counter_value", "FUN_10001021", "--why", "a placeholder of no start (L5)"]);
    assert!(code == 1 && out.contains("check: 1 new error(s) after the rename, 0 from before") && out.contains("L5"), "{out}");
    assert!(out.contains("nothing renamed") && read(&t, "src/net.c").contains("counter_value(void)"), "{out}");
    assert!(!read(&t, "names.log").contains("FUN_10001021"));
    let (code, out) = dcp(&t, &["build"]);
    assert!(code == 0 && out.contains("compiled=0"), "{out}");
}

#[test]
#[ignore = "e2e: VC6"]
fn escalate_refuses_an_unexplained_size() {
    if !has_vc6() {
        return;
    }
    let t = tiny();
    with_vc6(&t);
    net_decl(&t);
    let body: String = (3..9).map(|k| format!("    n = n * {k} + *(int *)\"\\x34\\x12\";\n")).collect();
    unit(&t, "net", &[&format!("/* 0x10001020, reads the counter */\nint get(int n)\n{{\n{body}    return n;\n}}\n")]);
    assert_eq!(dcp(&t, &["build"]).0, 0);
    let (code, out) = dcp(&t, &["escalate", "get", "register choice after the spell pass"]);
    assert!(code == 1 && !read(&t, "src/net.c").contains("@deep"), "{out}");
    let (code, out) = dcp(&t, &["escalate", "get", "register choice", "--size-explained", "the original keeps n in a register"]);
    assert!(code == 0 && read(&t, "src/net.c").contains("@deep register choice (size: "), "{out}");
    assert!(read(&t, "src/net.c").contains("explained: the original keeps n in a register)"));
}

#[test]
#[ignore = "e2e: VC6"]
fn headers_conflicts_trial_grades() {
    if !has_vc6() {
        return;
    }
    let t = tiny();
    with_vc6(&t);
    net_decl(&t);
    unit(&t, "net", &["/* 0x10001020, reads the counter */\nint get(void)\n{\n    return *(int *)\"\\x34\\x12\";\n}\n"]);
    assert_eq!(dcp(&t, &["build"]).0, 0);
    write(&t, "include/plain.h", "int spare(void);\n");
    write(&t, "include/slow.h", "#pragma optimize(\"\", off)\n");
    let before = read(&t, "src/net.c");
    let (code, out) = dcp(&t, &["headers", "conflicts", "net", "plain", "--trial"]);
    assert!(code == 0 && out.contains("trial=compiled  functions=1  falls=0  rises=0  same=1"), "{out}");
    let (code, out) = dcp(&t, &["headers", "conflicts", "net", "slow", "--trial"]);
    assert!(code == 1 && out.contains("falls=1") && out.contains("  fall=0x10001020  name=get  code=byte  trial=draft"), "{out}");
    assert_eq!(read(&t, "src/net.c"), before);
    assert!(std::fs::read_dir(t.join("build/obj/trial")).map(|d| d.count() == 0).unwrap_or(true));
    assert!(dcp(&t, &["grade", "get"]).1.contains("experiment=byte"));
}

#[test]
#[ignore = "e2e: VC6"]
fn promote_raises_only_and_accept() {
    if !has_vc6() {
        return;
    }
    let t = tiny();
    with_vc6(&t);
    net_decl(&t);
    let good = "int counter = 0x1234;  /* 0x10002000 */\n\n/* 0x10001020, reads the counter */\nint get(void)\n{\n    return counter;\n}\n";
    let bad = good.replace("counter;\n}", "counter + 1;\n}");
    unit(&t, "net", &[good]);
    let (code, out) = dcp(&t, &["promote"]);
    assert!(code == 0 && out.contains("functions=1") && out.contains("accepted=0"), "{out}");
    let tsv = || read(&t, "ledger/grades.tsv");
    assert_eq!(tsv(), "target\taddress\tname\tunit\tcode\treadability\tlevel\taccepted\ntiny\t0x10001020\tget\tnet\tbyte\treadable\t\t\n");
    unit(&t, "net", &[&bad]);
    let before = tsv();
    let (code, out) = dcp(&t, &["promote"]);
    assert!(code == 1 && out.contains("promote=refused  falls=1") && out.contains("fell: 0x10001020 get: code byte -> draft"), "{out}");
    assert_eq!(tsv(), before);
    assert_eq!(dcp(&t, &["accept", "get", "--to", "shape", "--why", "x"]).0, 1); // it is draft now, below shape
    assert_eq!(dcp(&t, &["accept", "get", "--readability", "draft", "--why", "x"]).0, 1); // still draft code
    let (code, out) = dcp(&t, &["accept", "0x10001020", "--to", "draft", "--why", "a declaration-set tie-break"]);
    assert!(code == 0 && out.contains("accepted=0x10001020  name=get") && out.contains("was=byte+readable  now=draft+readable"), "{out}");
    let line = tsv().lines().nth(1).unwrap().to_string();
    assert!(line.starts_with("tiny\t0x10001020\tget\tnet\tdraft\treadable\t\tbyte+readable -> draft+readable at ") && line.ends_with(": a declaration-set tie-break"), "{line}");
    assert!(!dcp(&t, &["findings"]).1.contains("M1"));
    let (code, out) = dcp(&t, &["promote"]); // no fall against the lowered entry; the note stays
    assert!(code == 0 && out.contains("accepted=1") && tsv().lines().nth(1).unwrap() == line, "{out}");
    unit(&t, "net", &[good]);
    let (code, out) = dcp(&t, &["promote"]); // back at byte: raised, the note cleared
    assert!(code == 0 && out.contains("accepted=0") && tsv() == before, "{out}");
    unit(&t, "net", &[&bad]);
    let (code, out) = dcp(&t, &["promote", "--accept-falls"]);
    assert!(code == 0 && out.contains("fell (accepted): 0x10001020 get") && out.contains("accepted=1"), "{out}");
    assert!(tsv().contains("\tdraft\treadable\t\tbyte+readable -> draft+readable at ") && tsv().trim_end().ends_with(": promote --accept-falls"));
}

#[test]
#[ignore = "e2e: VC6"]
fn header_edit_recompiles_only_includers() {
    if !has_vc6() {
        return;
    }
    let t = tiny();
    with_vc6(&t);
    write(&t, "include/net.h", "extern int counter;\n");
    let get = "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return counter;\n}\n";
    unit(&t, "net", &["#include \"net.h\"\nint counter = 0x1234;  /* 0x10002000 */\n", get]);
    unit(&t, "log", &["/* 0x10001030, logs */\nvoid log3(void)\n{\n}\n"]);
    assert!(dcp(&t, &["build"]).1.contains("compiled=2"));
    write(&t, "include/net.h", "extern int counter;  /* edited */\n");
    let (_, out) = dcp(&t, &["build"]);
    assert!(out.contains("compiled=1") && out.contains("ok   net") && !out.contains("ok   log"), "{out}");
    unit(&t, "net", &["#include \"net.h\"\n/* a comment */\nint counter = 0x1234;  /* 0x10002000 */\n", get]);
    let (_, out) = dcp(&t, &["build"]);
    assert!(out.contains("compiled=1") && out.contains("ok   net"), "{out}");
    assert!(dcp(&t, &["build"]).1.contains("compiled=0"));
}

fn has_clang() -> bool {
    crate::frontend::clang_library().is_some()
}

#[test]
#[ignore = "e2e: VC6 and libclang"]
fn lint_consistency_and_exemption() {
    if !(has_vc6() && has_clang()) {
        return;
    }
    let t = tiny();
    with_vc6(&t);
    let head = "int counter = 0x1234;  /* 0x10002000 */\nint helper();\n";
    unit(&t, "net", &[head, "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return counter + helper(1.5f);\n}\n"]);
    let (code, out) = dcp(&t, &["lint"]);
    assert!(code == 0 && out.contains("m7=1") && out.contains("helper() at line 7"), "{out}");
    let (_, out) = dcp(&t, &["grade", "get"]);
    assert!(out.contains("M7 consistency: helper() at line 7"), "{out}");
    unit(&t, "net", &[head, "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return counter + helper(1.5f);  /* @original the original passes a double */\n}\n"]);
    assert!(dcp(&t, &["lint"]).1.contains("m7=0"));
    // a conflict across units: two prototypes of one function
    unit(&t, "log", &["long helper(int x);\n", "/* 0x10001030, logs */\nvoid log3(void)\n{\n}\n"]);
    let (code, out) = dcp(&t, &["lint"]);
    assert!(code == 1 && out.contains("m5=1") && out.contains("M5"), "{out}");
}

#[test]
#[ignore = "e2e: VC6 and libclang"]
fn lint_m5_between_headers() {
    if !(has_vc6() && has_clang()) {
        return;
    }
    let t = tiny();
    with_vc6(&t);
    write(&t, "include/a.h", "typedef struct BITS { int x; } BITS;\nint f(char *p);  /* @original a.c's spelling */\n");
    write(&t, "include/b.h", "typedef struct BITS { short x; } BITS;\nint f(void *p);\n");
    let (code, out) = dcp(&t, &["lint"]);
    assert_eq!(code, 1, "{out}");
    let m5: Vec<&str> = out.lines().filter(|l| l.contains("M5") || l.contains("include/")).collect();
    assert!(m5.iter().any(|l| l.contains("redefinition of 'BITS'")), "{out}");
    assert!(m5.iter().any(|l| l.contains("conflicting types for 'f'") && l.contains("cannot be included together")), "{out}");
    write(&t, "include/b.h", "int g(void);\n");
    assert!(dcp(&t, &["lint"]).1.contains("m5=0"));
    write(&t, "include/a.h", "/* @private net */\ntypedef struct BITS { int x; } BITS;\n");
    write(&t, "include/b.h", "typedef struct BITS { short x; } BITS;\n");
    unit(&t, "net", &["#include \"a.h\"\nint counter = 0x1234;  /* 0x10002000 */\nint helper();\n"]);
    assert!(dcp(&t, &["lint"]).1.contains("m5=0"));
    unit(&t, "log", &["#include \"a.h\"\n"]);
    let (_, out) = dcp(&t, &["lint"]);
    assert!(out.contains("m5=1") && out.contains("src/log.c:1: includes a.h, private to net"), "{out}");
}

#[test]
#[ignore = "e2e: VC6 and libclang"]
fn lint_m5_per_symbol() {
    if !(has_vc6() && has_clang()) {
        return;
    }
    let t = tiny();
    with_vc6(&t);
    unit(&t, "net", &["int counter = 0x1234;  /* 0x10002000 */\n", "/* 0x10001020, reads */\nint get(void)\n{\n    return counter;\n}\n"]);
    let log3 = "/* 0x10001030, logs */\nint log3(a)\nint a;\n{\n    return a;\n}\n";
    unit(&t, "log", &["#define GAPDATA __declspec(align(1)) unsigned char\nextern GAPDATA counter[];\nint get();\nint log3(int a);\n", log3]);
    write(&t, "include/a.h", "long get(void);\n");
    write(&t, "include/b.h", "int get(void);\nextern int counter;\n");
    let (code, out) = dcp(&t, &["lint"]);
    assert_eq!(code, 1, "{out}");
    let m5: Vec<&str> = out.lines().filter(|l| l.starts_with("  M5 ")).collect();
    assert_eq!(m5.len(), 2, "{out}");
    let get = m5.iter().find(|l| l.contains(" get declared unlike its definition")).unwrap();
    assert!(get.starts_with("  M5 include/a.h:1: get declared unlike its definition src/net.c:4 (unit net) `int get(void)`"), "{get}");
    assert!(get.contains("disagree=1 `long get(void)` at include/a.h:1; agree=2 include/b.h:1, src/log.c:3"), "{get}");
    let cnt = m5.iter().find(|l| l.contains("counter")).unwrap();
    assert!(cnt.contains("disagree=1 `GAPDATA counter[]` at src/log.c:2; agree=1 include/b.h:2"), "{cnt}");
    write(&t, "include/a.h", "long get(void);  /* @original why */\n");
    let (_, out) = dcp(&t, &["lint"]);
    assert!(out.contains("the @original spelling is in a header (include/a.h:1): a header repeats the definition's spelling `int get(void);` (unit net); a unit's own view goes in its head region as a cast macro: `#define get_X ((long (*)(void))get) /* @original why */`"), "{out}");
    write(&t, "include/a.h", "int get(void);\n");
    unit(&t, "log", &["extern int counter;\nlong get(void);  /* @original why */\nint log3(int a);\n", log3]);
    assert!(dcp(&t, &["lint"]).1.contains("m5=0"));
    unit(&t, "log", &["extern int counter;\nint log3(char *a);\n", log3]);
    let (_, out) = dcp(&t, &["lint"]);
    assert!(out.contains("m5=1") && out.contains("log3 declared unlike its definition src/log.c:5") && out.contains("`int log3(a) int a;` (as a prototype `int log3(int a)`)"), "{out}");
    unit(&t, "log", &["extern int counter;\n", log3]);
    write(&t, "include/c.h", "NOSUCHTYPE *mk(void);\n");
    let (_, out) = dcp(&t, &["lint"]);
    assert!(out.contains("m5=1") && out.contains("include/c.h:1: include/c.h does not compile in the all-declarations unit (1 errors, first: unknown type name 'NOSUCHTYPE')"), "{out}");
    write(&t, "include/c.h", "#define get get_ag\nlong get(void);\n#undef get\n");
    assert!(dcp(&t, &["lint"]).1.contains("m5=0"));
}

/// Q4: `(*(T *)datum)` reads through the datum's value (raw), `(*(T *)&datum)` with its address comment is a view.
#[test]
#[ignore = "e2e: VC6"]
fn q4_view_forms() {
    if !has_vc6() {
        return;
    }
    let t = tiny();
    with_vc6(&t);
    let head = "char *counter = 0;  /* 0x10002000 */\n#define COUNT_RAW (*(int *)counter)\n#define COUNT (*(int *)&counter)  /* 0x10002000 */\n";
    unit(&t, "net", &[head, "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return COUNT_RAW;\n}\n"]);
    let (_, out) = dcp(&t, &["grade", "get"]);
    assert!(out.contains("Q4 raw access: macro COUNT_RAW (") && out.contains("`#define NAME (*(T *)&datum)  /* 0xADDR */`")
            && out.contains("`(*(T *)datum)` reads through the datum's value and stays raw"), "{out}");
    unit(&t, "net", &[head, "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return COUNT;\n}\n"]);
    assert!(!dcp(&t, &["grade", "get"]).1.contains("Q4"));
    let head = "char counter[8] = {0};  /* 0x10002000 */\n#define COUNT_HI (*(int *)(counter + 4))  /* 0x10002004 */\n";
    unit(&t, "net", &[head, "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return COUNT_HI;\n}\n"]);
    assert!(!dcp(&t, &["grade", "get"]).1.contains("Q4"));
    let out = dcp(&t, &["findings"]).1;
    assert!(!out.contains("L15") && !out.contains("D7"), "{out}");
    let head = "int counter = 0;  /* 0x10002000 */\n#define COUNT_HI (*(int *)((char *)&counter + 4))  /* 0x10002004 */\n";
    unit(&t, "net", &[head, "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return COUNT_HI;\n}\n"]);
    dcp(&t, &["build"]);
    let out = dcp(&t, &["findings"]).1;
    assert!(out.contains("D7") && out.contains("view COUNT_HI at 0x10002004 is counter +0x4, outside counter (4 bytes)"), "{out}");
}

#[test]
#[ignore = "e2e: VC6"]
fn auto_clear_and_data_order() {
    if !has_vc6() {
        return;
    }
    let t = tiny();
    with_vc6(&t);
    unit(&t, "net", &["int pad = 7;  /* 0x10002004 */\nint counter = 0x1234;  /* 0x10002000 */\n",
                      "/* 0x10001020, reads the counter @deep register choice after the spell pass */\nint get(void)\n{\n    return counter;\n}\n"]);
    let (_, out) = dcp(&t, &["build"]);
    assert!(out.contains("auto-clear src/net.c: get is byte + readable, @deep removed"), "{out}");
    assert!(read(&t, "src/net.c").contains("\n/* 0x10001020, reads the counter */\nint get(void)\n"));
    let (_, out) = dcp(&t, &["findings"]);
    assert!(out.contains("D4") && out.contains("counter (0x10002000) is defined after pad (0x10002004)"), "{out}");
    let syms: std::collections::HashMap<i64, String> = facts(&t, "symbol", None).iter().filter(|f| f.rule.starts_with("M.data"))
        .map(|f| (f.lo, f.value["extent"].as_str().unwrap_or("").to_string())).collect();
    assert!(syms[&0x10002000] == "site" && syms[&0x10002004] == "draft", "{syms:?}");
}
