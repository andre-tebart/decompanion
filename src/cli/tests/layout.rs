//! Layout rules on the synthetic dll: loaders, evidence, unit extents, the checks, propose, the analyzer's drafts
//! (tests/test_layout.py).

use super::*;
use crate::store::DECLARED;
use serde_json::json;

#[test]
fn evidence() {
    let t = tiny();
    assert_eq!(dcp(&t, &["setup"]).0, 0);
    let ev = facts(&t, "evidence", None);
    let leak: Vec<(i64, String, String)> = ev.iter().filter(|f| f.value["ekind"] == "leak")
        .map(|f| (f.lo, f.value["path"].as_str().unwrap().to_string(), f.value["stem"].as_str().unwrap().to_string())).collect();
    assert_eq!(leak, [(0x10001030, "c:\\src\\net\\net.c".to_string(), "net".to_string())]);
    let lit = |a: i64| ev.iter().find(|f| f.value["ekind"] == "lit" && f.lo == a).map(|f| f.value["first"].as_i64().unwrap());
    assert_eq!(lit(0x10002010), Some(0x10001030));
    assert_eq!(lit(0x10002038), Some(0x10001050));
    let fill = ev.iter().find(|f| f.value["ekind"] == "fill" && f.lo == 0x10001020).map(|f| f.value["pre"].as_str().unwrap().to_string());
    assert_eq!(fill.as_deref(), Some("nop"));
    assert!(findings(&t, None).iter().all(|c| c.0 == "warn"));
}

#[test]
fn units_from_decl_and_sources() {
    let t = tiny();
    write(&t, "decl/text.dcl", "# code\n0x10001020 boundary start tu=net by=leaked -- c:\\src\\net\\net.c in f3's log string\n");
    unit(&t, "net", &["int counter = 0x1234;  /* 0x10002000 */\n", "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return counter;\n}\n"]);
    let (code, out) = dcp(&t, &["check"]);
    assert_eq!(code, 0, "{out}");
    let (_, out) = dcp(&t, &["layout", "units"]);
    assert!(out.contains("units=1"), "{out}");
    let line = line_with(&out, "unit=net");
    // the last unit runs to the end of the game code; functions after it lack sources, so its end is open
    for w in ["range=0x10001020..0x10001060", "status=open", "end=open", "named_by=leaked", "functions=3", "sourced=1", "leaks=c:\\src\\net\\net.c"] {
        assert!(line.contains(w), "{w} in {line}");
    }
    let mut names: Vec<(String, i64)> = facts(&t, "name", None).iter().filter(|f| f.value.get("origin") == Some(&json!("source")))
        .map(|f| (f.value["name"].as_str().unwrap().to_string(), f.lo)).collect();
    names.sort();
    assert_eq!(names, [("counter".to_string(), 0x10002000), ("get".to_string(), 0x10001020)]);
    let src = facts(&t, "source", None);
    assert!(!src.is_empty() && src.iter().all(|f| f.support == DECLARED && f.by.starts_with("src:") && f.reason.as_deref().is_some_and(|r| !r.is_empty())));
    // an end boundary separates it
    let (code, out) = dcp(&t, &["decl", "add", "0x10001050 boundary end tu=net -- f4 is reached only through data"]);
    assert_eq!(code, 0, "{out}");
    let (_, out) = dcp(&t, &["layout", "units"]);
    let line = line_with(&out, "unit=net");
    assert!(line.contains("range=0x10001020..0x10001050") && line.contains("status=separated") && line.contains("undrafted=1"), "{line}");
    let (_, out) = dcp(&t, &["layout", "next"]);
    assert!(out.contains("next=0x10001000"), "{out}");
    let (_, out) = dcp(&t, &["layout", "next", "--start", "0x10001020", "-n", "3"]);
    assert!(out.contains("next=0x10001030") && out.contains("literal") && out.contains("leak") && out.contains("next=0x10001050"), "{out}");
}

#[test]
fn l4_l6_l1_l5_l7() {
    let t = tiny();
    write(&t, "decl/text.dcl", "# code\n\
        0x10001024 boundary start tu=bad -- inside f2 on purpose\n\
        0x10001028 boundary start tu=fill -- inside the fill after f2\n\
        0x10001030..0x10001034 bytes dead -- the walk reaches these\n\
        0x10001050 boundary start tu=x -- after its own function: L7\n");
    unit(&t, "x", &["/* 0x10001031, inside f3 */\nvoid f(void)\n{\n    FUN_10001044();\n}\n"]);
    let (code, out) = dcp(&t, &["check"]);
    assert_eq!(code, 1, "{out}");
    let all = findings(&t, None);
    for c in ["L4", "L6", "L1", "L5", "L7"] {
        assert!(all.iter().any(|x| x.1 == c), "{c}: {out}");
    }
    let l4: Vec<&str> = all.iter().filter(|c| c.1 == "L4").map(|c| c.4.as_str()).collect();
    assert!(l4.iter().any(|m| m.contains("inside the function 0x10001020")) && l4.iter().any(|m| m.contains("inside fill")), "{l4:?}");
}

#[test]
fn decl_errors_fail_check() {
    let t = tiny();
    write(&t, "decl/text.dcl", "0x10001020 start -- b\n0x10001000 start -- a\n0x10001000 frob -- x\n0x10002000 start -- data address in text.dcl\n");
    let (code, _) = dcp(&t, &["check"]);
    assert_eq!(code, 1);
    let msgs: Vec<String> = findings_of(&t, None, "L.decl").into_iter().map(|c| c.4).collect();
    assert!(msgs.iter().any(|m| m.contains("out of order")) && msgs.iter().any(|m| m.contains("unknown kind")) && msgs.iter().any(|m| m.contains("text.dcl holds code")), "{msgs:?}");
}

#[test]
fn propose() {
    let t = tiny();
    assert_eq!(dcp(&t, &["setup"]).0, 0);
    let (code, out) = dcp(&t, &["layout", "unit", "propose", "0x10001024..0x10001050", "--name", "bad", "--why", "x"]);
    assert!(code == 1 && out.contains("refused") && out.contains("L4"), "{out}");
    assert!(!read(&t, "decl/text.dcl").contains("bad"));
    let (code, out) = dcp(&t, &["layout", "unit", "propose", "0x10001020..0x10001050", "--name", "net", "--why", "leaked path", "--by", "leaked"]);
    assert_eq!(code, 0, "{out}");
    let text = read(&t, "decl/text.dcl");
    assert!(text.contains("0x10001020 boundary start by=leaked tu=net -- leaked path") && text.contains("0x10001050 boundary end tu=net"), "{text}");
    let (_, out) = dcp(&t, &["layout", "units"]);
    assert!(out.contains("unit=net") && out.contains("status=separated"), "{out}");
}

/// dcp setup runs the analyzer's export (a stand-in Ghidra writes the batch_decompile file), L.analyzer declares its
/// starts, a second setup is a no-op, a forced one exports again, an export about another binary fails.
#[test]
fn ghidra_analyzer() {
    let t = tiny();
    let sha = sha256_of(&t.join("tiny.dll"));
    let mut j = json!({"subject": {"digest": {"sha256": sha}},
        "normalized_result": {"items": [
            {"address": "0x10001055", "procedure": {"status": "resolved", "address": "0x10001050", "name": "FUN_10001050"},
             "status": "ok", "pseudocode": "\r\nint FUN_10001050(void)\r\n{\r\n  return 0;\r\n}\r\n"},
            {"address": "0x10001000", "status": "error", "error": "timeout"}]}});
    let f = t.parent().unwrap().join("batch.json");
    std::fs::write(&f, j.to_string()).unwrap();
    use_fake_ghidra(&t, &f);
    let (code, out) = dcp(&t, &["setup"]);
    assert!(code == 0 && out.contains("analyzer=ghidra  exported=1  failed=1"), "{out}");
    assert!(out.contains("analyzer=ghidra  drafts=1  export=up-to-date"), "{out}");
    let starts: Vec<(i64, crate::store::Support, Option<String>, String)> = facts(&t, "start", None).iter().filter(|s| s.value["how"] == "ghidra")
        .map(|s| (s.lo, s.support, s.reason.clone(), s.by.clone())).collect();
    assert_eq!(starts, [(0x10001050, DECLARED, Some("ghidra analysis".to_string()), "decl:analyzer:ghidra:export.json".to_string())]);
    let (code, out) = dcp(&t, &["setup"]);
    assert!(code == 0 && !out.contains("exported="), "{out}"); // the same image, script and starts: nothing runs
    let (code, out) = dcp(&t, &["draft", "0x10001052", "--show"]);
    assert!(code == 0 && out.contains("int FUN_10001050(void)") && out.starts_with("/* ghidra draft of 0x10001050"), "{out}");
    let (_, out) = dcp(&t, &["layout", "next", "--start", "0x10001050"]);
    assert!(out.contains("analyzed=yes"), "{out}");
    j["normalized_result"]["items"][0]["procedure"]["name"] = json!("Answer");
    std::fs::write(&f, j.to_string()).unwrap();
    let (_, out) = dcp(&t, &["setup", "--analyzer-force"]);
    assert!(out.contains("analyzer=ghidra  exported=1"), "{out}"); // forced: exported again
    let names = |t: &Path| facts(t, "start", None).iter().filter(|s| s.value["how"] == "ghidra").map(|s| s.value["name"].as_str().unwrap_or("").to_string()).collect::<Vec<_>>();
    assert_eq!(names(&t), ["Answer"]);
    let (_, out) = dcp(&t, &["refs", "Answer"]);
    assert!(out.contains("origin=analyzer"), "{out}");
    j["subject"]["digest"]["sha256"] = json!("0".repeat(64));
    std::fs::write(&f, j.to_string()).unwrap();
    let (code, out, err) = dcp3(&t, &["setup", "--analyzer-force"]);
    assert!(code == 1 && err.contains("analyzer=ghidra failed: ghidra analysed sha256 0000000000000000"), "{out}{err}");
    assert_eq!(names(&t), ["Answer"]); // kept
}
