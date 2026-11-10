//! The layout tooling on the synthetic dll: the reading commands (disasm, dump, refs, layout literals / starts),
//! drafting (unit new, draft, rename, unit rename, unit join, names.log), L9, L10, declared dead bytes owned by their
//! unit, the analyzer lines of the report, the session gate and report, the skills.

use super::*;
use crate::store::DECLARED;
use serde_json::json;
use std::collections::BTreeMap;


fn errors(root: &Path) -> Vec<FindingRow> {
    findings(root).into_iter().filter(|c| c.0 == "bug" || c.0 == "error").collect()
}

/// Drafts from a Ghidra export (a stand-in installation writes the batch_decompile file in dcp setup) with these
/// items: (address, name, pseudocode, body ranges).
fn analyze(root: &Path, items: &[(i64, &str, &str, &[(i64, i64)])]) {
    let sha = sha256_of(&root.join("tiny.dll"));
    let h = |a: i64| format!("{a:#010x}");
    let its: Vec<serde_json::Value> = items.iter().map(|(a, n, text, rs)| json!({
        "address": h(*a), "status": "ok", "procedure": {"address": h(*a), "name": n}, "pseudocode": text,
        "body": {"start": h(rs[0].0), "end": h(rs[rs.len() - 1].1), "size": rs.iter().map(|(x, b)| b - x).sum::<i64>(),
                 "ranges": rs.iter().map(|(x, b)| json!([h(*x), h(*b)])).collect::<Vec<_>>()}})).collect();
    let js = json!({"subject": {"digest": {"sha256": sha}}, "normalized_result": {"items": its}});
    let f = root.parent().unwrap().join("export.json");
    std::fs::write(&f, js.to_string()).unwrap();
    use_fake_ghidra(root, &f);
    let (code, out) = dcp(root, &["setup"]);
    assert!(code == 0 && out.contains(&format!("exported={}", items.len())), "{out}");
}

/// Ghidra drafts with an empty body for these starts (through the fake Ghidra): what `dcp draft` needs.
fn stub_drafts(root: &Path, starts: &[i64]) {
    let texts: Vec<(i64, String, String)> = starts.iter().map(|a| (*a, format!("FUN_{a:08x}"), format!("\nvoid FUN_{a:08x}(void)\n\n{{\n  return;\n}}\n"))).collect();
    let ranges: Vec<[(i64, i64); 1]> = starts.iter().map(|a| [(*a, *a + 1)]).collect();
    let items: Vec<(i64, &str, &str, &[(i64, i64)])> = texts.iter().zip(&ranges).map(|((a, n, t), r)| (*a, n.as_str(), t.as_str(), &r[..])).collect();
    analyze(root, &items);
}

const F1: &str = "\nvoid FUN_10001000(void)\n\n{\n  FUN_10001020();\n  FUN_10001030();\n  DAT_10002000 = 0;\n  return;\n}\n";
const F2: &str = "\nundefined4\nFUN_10001020(void)\n\n{\n  return DAT_10002000;\n}\n";

#[test]
fn disasm_dump_refs() {
    let t = tiny();
    assert_eq!(dcp(&t, &["decl", "add", "0x10001020 name GetCounter -- reads the counter (test)"]).0, 0);
    let (code, out) = dcp(&t, &["disasm", "0x10001000"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("function=0x10001000..0x1000100f") && out.contains("-- 0x10001000") && out.contains("call 0x10001020 <GetCounter>"), "{out}");
    let (_, out) = dcp(&t, &["disasm", "GetCounter"]);
    assert!(out.contains("instructions=2") && out.contains("mov eax, dword ptr [0x10002000]"), "{out}");
    let (code, out) = dcp(&t, &["why", "GetCounter"]); // why takes a name too
    assert!(code == 0 && out.starts_with("addr=0x10001020") && out.contains("owner=func"), "{out}");
    // grouped by question: the answer first, the claims stacked under it after; φ names the object of ours there
    let line = |q: &str| out.lines().find(|l| l.trim_start().starts_with(q)).unwrap_or("").to_string();
    assert!(line("owner").contains("answer") && line("start").contains("answer") && line("section").contains("answer"), "{out}");
    assert!(out.lines().any(|l| l.trim_start().starts_with("phi") && l.contains("GetCounter") && l.contains("origin=decl")), "{out}");
    let (code, out) = dcp(&t, &["phi", "GetCounter"]);
    assert!(code == 0 && out.contains("addresses=0x10001020") && out.contains("origin=decl") && out.contains("support=declared"), "{out}");
    let (code, out) = dcp(&t, &["phi", "0x10001020"]);
    assert!(code == 0 && out.contains("objects=1") && out.contains("shown=GetCounter"), "{out}");
    let (code, out) = dcp(&t, &["phi"]);
    assert!(code == 0 && out.contains("decl=1"), "{out}");
    assert_eq!(dcp(&t, &["phi", "NoSuchName"]).0, 1);
    let (code, out) = dcp(&t, &["why", "NoSuchName"]);
    assert!(code == 1 && out.contains("name=NoSuchName") && out.contains("unknown"), "{out}");
    let (code, out) = dcp(&t, &["why", "0x10002000"]); // a datum shows its value
    assert!(code == 0 && out.contains("  value='34 12 00 00") && out.contains("u32=0x00001234  f32="), "{out}");
    let (code, out) = dcp(&t, &["dump", "0x10002000", "0x48", "--str", "--dword"]);
    assert!(code == 0 && out.contains("section=.data"), "{out}");
    for w in ["text=hello", "text=world", "text=c:\\src\\net\\net.c", "at=0x10002040  u32=0x10001050", "string@0x10002030"] {
        assert!(out.contains(w), "{w}: {out}");
    }
    let (code, out) = dcp(&t, &["dump", "0x10002000", "8", "--float"]);
    assert!(code == 0 && out.contains("at=0x10002000  f32=") && out.contains("f64="), "{out}");
    let (code, out) = dcp(&t, &["refs", "GetCounter"]);
    assert_eq!(code, 0, "{out}");
    for w in ["address=0x10001020", "named=GetCounter  origin=decl", "ref_to=call  site=0x10001003", "fn=0x10001000", "decl/text.dcl:"] {
        assert!(out.contains(w), "{w}: {out}");
    }
}

#[test]
fn layout_starts_and_literals() {
    let t = tiny();
    let (code, out) = dcp(&t, &["layout", "starts"]);
    assert!(code == 0 && out.contains("starts=4"), "{out}");
    let line = line_with(&out, "start=0x10001050");
    assert!(line.contains("how=fptr") && line.contains("callers=1") && line.contains("drafted=no"), "{line}");
    assert!(line_with(&out, "start=0x10001020").contains("fill=nop"));
    let (code, out2) = dcp(&t, &["layout", "starts", "0x10001000", "0x10001060"]); // LO HI as two words
    let out3 = dcp(&t, &["layout", "starts", "0x10001000..0x10001060"]).1;
    assert!(code == 0 && out2.lines().skip(1).eq(out3.lines().skip(1)));
    // the table of pointers in .data: one function pointer, to f4
    let (code, out) = dcp(&t, &["layout", "fptrs"]);
    assert!(code == 0 && out.contains("fptrs=1"), "{out}");
    let row = line_with(&out, "  site=");
    assert!(row.contains("section=.data") && row.contains("to=0x10001050") && row.contains("delta=-"), "{row}");
    assert!(dcp(&t, &["layout", "fptrs", "0x10001000..0x10001040"]).1.contains("fptrs=0"));
    let (code, out) = dcp(&t, &["layout", "literals", "0x10001000..0x10001060"]);
    assert_eq!(code, 0, "{out}");
    let lit = line_with(&out, "  lit=0x10002030");
    assert!(lit.contains("kind=string") && lit.contains("first=0x10001030") && lit.contains("text=hello"), "{lit}");
    assert!(out.contains("fn=0x10001030") && out.contains("fn=0x10001050"), "{out}");
}

/// The file and its head region.
fn unit_text(t: &Path) -> (String, String) {
    let text = read(t, "src/net.c");
    let head = text[..text.find("\n/* 0x1000").unwrap()].to_string();
    (text, head)
}

#[test]
fn unit_new_draft_rename() {
    let t = tiny();
    assert_eq!(dcp(&t, &["setup"]).0, 0);
    analyze(&t, &[(0x10001000, "FUN_10001000", F1, &[(0x10001000, 0x1000100f)]), (0x10001020, "FUN_10001020", F2, &[(0x10001020, 0x10001026)])]);
    let (code, out) = dcp(&t, &["unit", "new", "net", "--range", "0x10001000..0x10001060", "--by", "guess", "--why", "the whole test code"]);
    assert_eq!(code, 0, "{out}");
    assert!(t.join("src/net.c").exists() && t.join("include/net.h").exists() && !t.join("notes").exists());
    assert!(read(&t, "src/net.c").contains("boundaries in decl/text.dcl */"));
    assert!(read(&t, "include/net.h").contains("NET_H"));
    let n_err = errors(&t).len();
    // f1 from the analyzer (Ghidra's dialect): the callees spelled as placeholders of their unit, the data label kept, declarations added
    let (code, out) = dcp(&t, &["draft", "--next"]);
    assert!(code == 0 && out.contains("drafted=0x10001000") && out.contains("body=ghidra") && out.contains("file=src/net.c"), "{out}");
    let (text, head) = unit_text(&t);
    let f1 = &text[text.find("/* 0x10001000").unwrap()..];
    assert!(f1.starts_with("/* 0x10001000, net_10001000 */\nvoid net_10001000(void)\n{"), "{f1}");
    assert!(f1.contains("net_10001020();") && f1.contains("net_10001030();") && f1.contains("DAT_10002000 = 0;"));
    assert!(head.find("#include \"dcp_ghidra.h\"").unwrap() < head.find("#include \"net.h\"").unwrap());
    assert!(head.contains("undefined4 net_10001020();") && head.contains("int net_10001030();") && head.contains("extern undefined4 DAT_10002000;"), "{head}");
    assert!(read(&t, "include/net.h").contains("void net_10001000(void);"));
    assert!(t.join("include/dcp_ghidra.h").exists());
    // f2: its K&R line leaves the head, its prototype (one line) goes into the header, its text after f1's
    let (_, out) = dcp(&t, &["draft", "--next"]);
    assert!(out.contains("drafted=0x10001020"), "{out}");
    let (text, head) = unit_text(&t);
    assert!(text.contains("\n/* 0x10001020, net_10001020 */\nundefined4 net_10001020(void)\n"));
    assert!(text.find("/* 0x10001000").unwrap() < text.find("/* 0x10001020").unwrap());
    assert!(!head.contains("net_10001020"));
    assert!(read(&t, "include/net.h").contains("undefined4 net_10001020(void);"));
    // f3 without a draft: refused, nothing written
    let (code, _, err) = dcp3(&t, &["draft", "--next"]);
    assert!(code == 1 && err.contains("no Ghidra draft at 0x10001030"), "{err}");
    assert!(!unit_text(&t).0.contains("/* 0x10001030"));
    assert_eq!(errors(&t).len(), n_err, "{:?}", errors(&t));
    assert!(!findings(&t).iter().any(|c| ["L5", "L.src", "L1", "L7"].contains(&c.1.as_str())));
    // rename: whole words, names.log, collision refused, the check count unchanged
    let (code, out) = dcp(&t, &["rename", "net_10001020", "GetCounter", "--why", "returns the counter"]);
    assert_eq!(code, 0, "{out}");
    assert!(read(&t, "src/net.c").contains("GetCounter();"));
    let log = read(&t, "names.log");
    assert!(log.lines().last().unwrap().split_once(' ').unwrap().1.starts_with("0x10001020 func net_10001020 -> GetCounter by:main why:returns the counter"), "{log}");
    assert_eq!(dcp(&t, &["rename", "net_10001030", "GetCounter", "--why", "x"]).0, 1);
    assert_eq!(errors(&t).len(), n_err);
    // unit rename: its file, header, guard, includes, boundary lines, placeholders
    let (code, out) = dcp(&t, &["unit", "rename", "net", "netcode", "--by", "tag", "--why", "the tag string 'net:'"]);
    assert_eq!(code, 0, "{out}");
    assert!(!t.join("src/net.c").exists() && t.join("src/netcode.c").exists());
    let hdr = read(&t, "include/netcode.h");
    assert!(hdr.contains("NETCODE_H") && !hdr.contains("NET_H") && !t.join("include/net.h").exists());
    let text = read(&t, "src/netcode.c");
    assert!(text.starts_with("/* netcode:") && text.contains("#include \"netcode.h\"") && text.contains("netcode_10001000"), "{text}");
    let text = read(&t, "decl/text.dcl");
    assert!(text.contains("boundary start by=tag tu=netcode") && !text.contains("tu=net "), "{text}");
    let log = read(&t, "names.log");
    assert!(log.contains("- unit net -> netcode") && log.contains("0x10001000 func net_10001000 -> netcode_10001000"), "{log}");
    assert_eq!(errors(&t).len(), n_err);
    let (_, out) = dcp(&t, &["layout", "units"]);
    assert!(out.contains("unit=netcode") && out.contains("named_by=tag"), "{out}");
}

#[test]
fn unit_join() {
    let t = tiny();
    stub_drafts(&t, &[0x10001000, 0x10001020, 0x10001030, 0x10001050]);
    assert_eq!(dcp(&t, &["unit", "new", "a", "--range", "0x10001000..0x10001030", "--by", "guess", "--why", "first half"]).0, 0);
    assert_eq!(dcp(&t, &["unit", "new", "b", "--range", "0x10001030..0x10001060", "--by", "guess", "--why", "second half"]).0, 0);
    for _ in 0..4 {
        assert_eq!(dcp(&t, &["draft", "--next"]).0, 0);
    }
    assert!(read(&t, "src/b.c").contains("/* 0x10001050, b_10001050"));
    let before = errors(&t).len();
    assert_eq!(dcp(&t, &["unit", "join", "b", "a", "--why", "x"]).0, 1); // the earlier unit first
    let (code, out) = dcp(&t, &["unit", "join", "a", "b", "--why", "one literal block"]);
    assert_eq!(code, 0, "{out}");
    assert!(!t.join("src/b.c").exists() && !t.join("include/b.h").exists());
    let text = read(&t, "src/a.c");
    let at: Vec<usize> = [0x10001000, 0x10001020, 0x10001030, 0x10001050].iter().map(|a: &i64| text.find(&format!("/* {a:#010x}")).unwrap()).collect();
    let mut sorted = at.clone();
    sorted.sort();
    assert!(at == sorted && text.matches("#include \"a.h\"").count() == 1 && !text.contains("/* b:"), "{text}");
    assert!(text.contains("a_10001030") && read(&t, "include/a.h").contains("a_10001050(void);"));
    let decl: Vec<String> = read(&t, "decl/text.dcl").lines().filter(|l| l.contains("boundary")).map(|l| l.to_string()).collect();
    // b ran to the end of the game code without an end line: a's end at b's start goes, a runs on
    assert!(decl.len() == 1 && decl[0].starts_with("0x10001000 boundary start by=guess tu=a"), "{decl:?}");
    assert!(read(&t, "names.log").contains("- unit b -> a by:main why:join: one literal block"));
    assert!(errors(&t).len() == before && out.contains("grades_changed=0"), "{out}");
    let (_, out) = dcp(&t, &["layout", "units"]);
    assert!(out.contains("units=1") && out.contains("unit=a  range=0x10001000..0x10001060"), "{out}");
}

#[test]
fn l9_and_analyzer_report() {
    let t = tiny();
    assert_eq!(dcp(&t, &["setup"]).0, 0);
    analyze(&t, &[(0x10001000, "FUN_10001000", F1, &[(0x10001000, 0x10001040)]), (0x10001058, "FUN_10001058", F2, &[(0x10001058, 0x1000105b)])]);
    let l9 = findings_of(&t, "L9");
    assert!(l9.len() == 1 && l9[0].0 == "warn" && l9[0].4.contains("0x10001020") && l9[0].4.contains("0x10001030"), "{l9:?}");
    let (code, out) = dcp(&t, &["report"]);
    assert!(code == 0 && out.contains("analyzer=ghidra  drafts=2  export=up-to-date"), "{out}");
    assert!(out.contains("l9=1") && out.contains("analyzer_only=1") && out.contains("ours_only=3") && out.contains("analyzer_only=0x10001058"), "{out}");
    let (code, out) = dcp(&t, &["check", "--strict"]);
    assert!(code == 1 && out.contains("L9"), "{out}");
}

/// The synthetic dll with `xor eax, eax; ret` at 0x10001058 in the fill after f4: 0x10001057..0x10001060 is unknown
/// code (no fill run any more).
fn patched() -> PathBuf {
    let root = make_project(&tmp("dead").join("dead"));
    let dll = root.join("tiny.dll");
    let mut data = std::fs::read(&dll).unwrap();
    data[0x400 + 0x58..0x400 + 0x5b].copy_from_slice(&[0x33, 0xc0, 0xc3]);
    std::fs::write(&dll, data).unwrap();
    root
}

#[test]
fn bytes_dead_owned_by_the_unit() {
    let root = patched();
    assert_eq!(dcp(&root, &["unit", "new", "tail", "--range", "0x10001050..0x10001060", "--by", "guess", "--why", "f4"]).0, 0);
    let (_, out) = dcp(&root, &["layout", "units", "-v"]);
    let line = line_with(&out, "unit=tail");
    assert!(line.contains("status=open") && line.contains("open_bytes=9"), "{line}"); // the patch breaks the fill run: 0x10001057..0x10001060
    assert_eq!(dcp(&root, &["decl", "add", "0x10001057..0x10001060 bytes dead -- unreachable return after f4"]).0, 0);
    let (_, out) = dcp(&root, &["layout", "units", "-v"]);
    let line = line_with(&out, "unit=tail");
    // explained now; the unit stays open only because f4, the last function of the game code, has no source
    assert!(line.contains("open_bytes=0") && out.contains("dead_bytes=9") && line.contains("end=open"), "{out}");
    let p = project(&root);
    let db = p.store_path();
    crate::storedb::st_open(&db).unwrap();
    crate::answers::ensure_at(&db).unwrap();
    let crate::answers::Answer { owner, unit, source: src, .. } = crate::answers::at(&db, 0x10001059).unwrap().unwrap();
    assert_eq!(owner, "dead");
    let u = crate::storedb::st_fact(&db, unit.unwrap()).unwrap().unwrap().1;
    assert_eq!(u.value["tu"], "tail");
    let s = crate::storedb::st_fact(&db, src.unwrap()).unwrap().unwrap().1;
    assert_eq!(s.value, json!({"what": "dead", "unit": "tail", "decl": "decl:decl/text.dcl:3"}));
    assert!(errors(&root).is_empty());
}

#[test]
fn declared_start_is_walked() {
    let root = patched();
    assert_eq!(dcp(&root, &["decl", "add", "0x10001058 start -- a function only a table reaches (test)"]).0, 0);
    assert_eq!(dcp(&root, &["unit", "new", "tail", "--range", "0x10001050..0x10001060", "--by", "guess", "--why", "f4"]).0, 0);
    stub_drafts(&root, &[0x10001058]);
    let (code, out) = dcp(&root, &["draft", "0x10001058"]);
    assert_eq!(code, 0, "{out}");
    let w = facts(&root, "symbol").into_iter().find(|f| &*f.rule == "S.codewalk" && f.lo == 0x10001058).unwrap();
    assert!(w.support == DECLARED && w.hi == 0x1000105b); // xor eax,eax; ret
    assert!(findings_of(&root, "L10").is_empty());
    // the only errors: the Ghidra types header's system includes, which the test machine's lint has no headers for
    let (_, out) = dcp(&root, &["check"]);
    assert!(!out.lines().any(|l| l.starts_with("error") && !l.contains("include/dcp_ghidra.h")), "{out}");
}

/// A fragment whose start only the source names owns its code up to the next stop by the contiguity convention
/// (L.src.extent), its trailing fill too; no L10.
#[test]
fn source_only_start_owns_its_code() {
    let root = patched();
    assert_eq!(dcp(&root, &["unit", "new", "tail", "--range", "0x10001050..0x10001060", "--by", "guess", "--why", "f4"]).0, 0);
    let f = read(&root, "src/tail.c");
    write(&root, "src/tail.c", &(f + "\n/* 0x10001058, only the source names this start */\nint f5(void)\n{\n    return 0;\n}\n"));
    dcp(&root, &["layout", "units", "-v"]);
    let own: Vec<_> = facts(&root, "symbol").into_iter().filter(|f| &*f.rule == "L.src.extent").collect();
    let funcs: Vec<(i64, i64)> = own.iter().filter(|f| f.value["skind"] == "func").map(|f| (f.lo, f.hi)).collect();
    assert_eq!(funcs, [(0x10001058, 0x1000105b)]); // xor eax,eax; ret
    assert!(own.iter().all(|f| f.support == DECLARED));
    assert!(findings_of(&root, "L10").is_empty());
    assert_eq!(dcp(&root, &["check"]).0, 0);
}

#[test]
#[ignore = "e2e: VC6"]
fn unlinked_helper_builds_without_a_grade() {
    let Some(vc6) = vc6_root() else {
        return;
    };
    let t = tiny();
    set_config(&t, "root = \"C:/nowhere/vc6\"\n", &format!("root = \"{vc6}\"\n"));
    write(&t, "decl/text.dcl", "# code\n0x10001020 boundary start by=guess tu=net -- test\n0x10001030 boundary end tu=net -- test\n");
    unit(&t, "net", &["int counter = 0x1234;  /* 0x10002000 */\nint twice(int x);\n", "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return counter;\n}\n",
                      "/* unlinked, inlined everywhere by /Ob1 */\nint twice(int x)\n{\n    return x + x;\n}\n"]);
    let (code, out) = dcp(&t, &["build"]);
    assert!(code == 0 && out.contains("failed=0") && !out.contains("ok=yes"), "{out}"); // only failed units get a row
    let (code, out) = dcp(&t, &["build", "--units"]);
    assert!(code == 0 && out.contains("tu=net") && out.contains("ok=yes"), "{out}");
    let rows = crate::queues::function_grades(&project(&t).store_path()).unwrap();
    let names: Vec<&str> = rows.iter().map(|r| r["name"].as_str().unwrap()).collect();
    assert!(names == ["get"] && rows[0]["code"] == "byte", "{names:?}");
    assert!(!findings(&t).iter().any(|c| c.1 == "M.gen" || c.1 == "M.compile"));
    let (_, out) = dcp(&t, &["layout", "units", "-v"]);
    assert!(out.contains("unlinked=twice  file=src/net.c"), "{out}");
    let (code, out) = dcp(&t, &["disasm", "--ours", "get"]);
    assert!(code == 0 && out.contains("ours=get") && out.contains("relocations=1") && out.contains("dword ptr [counter]"), "{out}");
}

fn git(root: &Path, args: &[&str]) {
    let o = std::process::Command::new("git").args(args).current_dir(root).output().unwrap();
    assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
}

#[test]
#[ignore = "e2e: starts git"]
fn session_start_and_wrap() {
    let t = tiny();
    stub_drafts(&t, &[0x10001000, 0x10001020]);
    git(&t, &["init", "-q", "-b", "main"]);
    write(&t, ".gitignore", "/build/\n.dcp/\n");
    git(&t, &["add", "-A"]);
    git(&t, &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "init"]);
    let (code, out) = dcp(&t, &["session", "start", "--kind", "layout"]);
    assert!(code == 0 && out.contains("gate: ok") && out.contains("next=0x10001000") && out.contains("over=yes"), "{out}");
    assert!(t.join(".dcp/session.json").exists());
    let (code, out) = dcp(&t, &["session", "status"]);
    assert!(code == 0 && out.contains("session=running") && out.contains("elapsed=0m") && out.contains("over=no"), "{out}");
    assert!(dcp(&t, &["layout", "next"]).1.lines().next().unwrap().starts_with("session=running"));
    assert_eq!(dcp(&t, &["unit", "new", "net", "--range", "0x10001000..0x10001060", "--by", "guess", "--why", "all"]).0, 0);
    let (code, out) = dcp(&t, &["session", "start"]);
    assert!(code == 1 && out.contains("dirty"), "{out}"); // the gate wants a clean tree
    for _ in 0..2 {
        assert_eq!(dcp(&t, &["draft", "--next"]).0, 0);
    }
    assert_eq!(dcp(&t, &["rename", "net_10001000", "Main", "--why", "the entry"]).0, 0);
    let (_, out) = dcp(&t, &["session", "wrap"]);
    for w in ["units: declared 1 (net)", "functions drafted: 2", "0x10001020", "renames: 1", "net_10001000 -> Main", "next: 0x10001030"] {
        assert!(out.contains(w), "{w}: {out}");
    }
    assert!(t.join("build/session/report.md").exists());
}

#[test]
fn skills_install() {
    let t = tiny();
    let (code, out) = dcp(&t, &["skills", "install"]);
    assert_eq!(code, 0, "{out}");
    let skill = read(&t, ".claude/skills/dcp-layout/SKILL.md");
    assert!(skill.starts_with("---\nname: dcp-layout\n") && skill.contains("dcp session status") && !skill.contains("sleep 1800"));
    let (_, out) = dcp(&t, &["skills", "install"]);
    assert!(out.contains("skills=0"), "{out}"); // nothing changed
}

/// The configured analyzer is missing: one warning line, setup still exits 0, nothing else breaks.
#[test]
fn setup_without_ghidra() {
    let t = tiny();
    let (code, out, err) = dcp3(&t, &["setup"]);
    assert!(code == 0 && out.contains("analyzer=ghidra  drafts=0  export=none"), "{out}");
    let lines: Vec<&str> = err.lines().filter(|l| l.starts_with("analyzer=")).collect();
    assert!(lines.len() == 1 && lines[0].starts_with("analyzer=ghidra unavailable: Ghidra not found ([analyzer] root = C:/nowhere/ghidra)"), "{err}");
    assert_eq!(dcp(&t, &["layout", "next"]).0, 0); // nothing else breaks
    let (code, _, err) = dcp3(&t, &["setup", "--no-analyzer"]);
    assert!(code == 0 && !err.contains("unavailable"));
}

/// A symbol with an address is renamed where it is used, not where a parameter, a local or a struct field of the
/// same name stands; a new name that is only a local elsewhere is no collision.
#[test]
fn rename_is_symbol_exact() {
    let t = tiny();
    unit(&t, "a", &["struct S { int a_10001000; };\nint count;\n",
                    "/* 0x10001000, a_10001000 */\nint a_10001000(int count)\n{\n    struct S s;\n    s.a_10001000 = count;\n    return s.a_10001000;\n}\n",
                    "/* 0x10001020, a_10001020 */\nint a_10001020(void)\n{\n    int a_10001000 = 1;\n    int checksum = 2;\n    return a_10001000 + checksum + a_10001000;\n}\n"]);
    let (code, out) = dcp(&t, &["rename", "a_10001000", "checksum", "--why", "what it computes"]);
    assert_eq!(code, 0, "{out}");
    let text = read(&t, "src/a.c");
    for w in ["/* 0x10001000, checksum */\nint checksum(int count)", "s.a_10001000 = count;", "return s.a_10001000;", "int a_10001000 = 1;",
              "return a_10001000 + checksum + a_10001000;", "struct S { int a_10001000; };"] {
        assert!(text.contains(w), "{w}: {text}");
    }
    assert!(out.contains("  comments: 1 line(s) where a_10001000 stood inside a comment now read checksum"), "{out}");
    assert!(out.contains("    src/a.c:4: /* 0x10001000, checksum */"), "{out}");
}

#[test]
fn rename_collides_only_with_code() {
    let t = tiny();
    unit(&t, "a", &["/* adler32: the checksum */\n#include \"adler32.h\"\n", "/* 0x10001000, a_10001000 */\nint a_10001000(void)\n{\n    return 0;\n}\n"]);
    let (code, out) = dcp(&t, &["rename", "a_10001000", "adler32", "--why", "zlib's name"]);
    assert_eq!(code, 0, "{out}");
    assert!(read(&t, "src/a.c").contains("int adler32(void)"));
    // renamed by hand already: recorded only
    let (code, out) = dcp(&t, &["rename", "a_10001000", "adler32", "--why", "written by hand"]);
    assert!(code == 0 && out.contains("recorded=a_10001000"), "{out}");
    let last = |t: &Path| read(t, "names.log").lines().last().unwrap().split_once(' ').unwrap().1.to_string();
    assert!(last(&t).starts_with("0x10001000 func a_10001000 -> adler32 by:main why:written by hand"));
    assert_eq!(dcp(&t, &["rename", "a_10001040", "crc32", "--why", "x"]).0, 1); // nowhere, and not the ledger's name
    let f = read(&t, "src/a.c");
    write(&t, "src/a.c", &(f + "\n/* 0x10001020, a_10001020 */\nint a_10001020(void)\n{\n    return 1;\n}\n"));
    assert_eq!(dcp(&t, &["rename", "a_10001020", "adler32", "--why", "x"]).0, 1);
    // the new name written by hand in part while the placeholder is still in the code: the rename completes it
    write(&t, "include/a.h", "int crc32(void);  /* 0x10001020 */\n");
    let (code, out) = dcp(&t, &["rename", "a_10001020", "crc32", "--why", "the crc table"]);
    assert!(code == 0 && out.contains("completes it"), "{out}");
    assert!(read(&t, "src/a.c").contains("int crc32(void)"));
    assert!(last(&t).starts_with("0x10001020 func a_10001020 -> crc32"));
}

/// Every file of the kinds a rename may touch, by path: its bytes.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(d: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for e in std::fs::read_dir(d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| ["c", "h", "dcl", "log"].contains(&&*x.to_string_lossy())) {
                out.insert(p.clone(), std::fs::read(&p).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, &mut out);
    out
}

/// Every refused rename prints an error record (stdout) and exits 1 without writing; every rename prints what it
/// changed: the record, then one line per file with its replacements and its changed lines as they read now.
#[test]
fn rename_reports_every_outcome() {
    let t = tiny();
    write(&t, "include/a.h", "int a_HdrOnly(void);  /* 0x10001050 */\nextern int a_Unk10002000;  /* 0x10002000 */\n\
                              #define a_Unk10002000B (*(short *)&a_Unk10002000)  /* 0x10002000 */\n");
    unit(&t, "a", &["#include \"a.h\"\n", "/* 0x10001000, a_10001000 */\nint a_10001000(void)\n{\n    return a_Unk10002000 + a_Unk10002000B;\n}\n",
                    "/* 0x10001020, a_10001020 */\nint a_10001020(void)\n{\n    return (int)\"a_InString\";\n}\n"]);
    unit(&t, "d", &["int a_Unk10002000 = 0x1234;  /* 0x10002000 */\n"]);
    let refused = |old: &str, new: &str, says: &str| {
        let before = snapshot(&t);
        let (code, out, err) = dcp3(&t, &["rename", old, new, "--why", "x"]);
        assert!(code == 1 && out.contains("error=") && out.contains(says) && err.contains(says), "{says}: {out}{err}");
        assert!(snapshot(&t) == before);
    };
    // a name only in a header: renamed there, the file listed
    let (code, out) = dcp(&t, &["rename", "a_HdrOnly", "a_Probe", "--why", "x"]);
    assert!(code == 0 && out.contains("files=1  replacements=1") && out.contains("  file=include/a.h  replacements=1"), "{out}");
    // a data name: every file listed; its view keeps its own name, a note says so
    let (code, out) = dcp(&t, &["rename", "a_Unk10002000", "a_Counter", "--why", "the counter"]);
    assert!(code == 0 && out.contains("kind=data  at=0x10002000  files=3  replacements=4"), "{out}");
    assert!(out.contains("file=src/d.c  replacements=1\n    1: int a_Counter = 0x1234;  /* 0x10002000 */\n"), "{out}");
    assert!(out.contains("file=include/a.h  replacements=2\n    2: extern int a_Counter;  /* 0x10002000 */\n"), "{out}");
    assert!(out.contains("the views of a_Unk10002000 keep their names: a_Unk10002000B"), "{out}");
    // the view by its own name
    let (code, out) = dcp(&t, &["rename", "a_Unk10002000B", "a_CounterLo", "--why", "the low half"]);
    assert!(code == 0 && out.contains("kind=data  at=0x10002000  files=2"), "{out}");
    assert!(read(&t, "include/a.h").contains("#define a_CounterLo (*(short *)&a_Counter)"));
    // an address: the ledger's name of it
    let (code, out) = dcp(&t, &["rename", "0x10001000", "a_Main", "--why", "the entry"]);
    assert!(code == 0 && out.contains("is a_10001000") && out.contains("renamed=a_10001000  to=a_Main  kind=func  at=0x10001000"), "{out}");
    let (code, out) = dcp(&t, &["rename", "0x10001000", "a_Entry", "--why", "the entry"]);
    assert!(code == 0 && out.contains("renamed=a_Main  to=a_Entry"), "{out}");
    assert!(read(&t, "names.log").lines().last().unwrap().split_once(' ').unwrap().1.starts_with("0x10001000 func a_Main -> a_Entry"));
    // refusals: an error record each, nothing written
    refused("a_InString", "a_Other", "only inside string literals");
    refused("a_10001020", "a_Counter", "a_Counter exists already");
    refused("a_Nowhere", "a_Other", "occurs nowhere");
    refused("nosuch:0x10001000", "a_Other", "neither a C identifier nor an address");
    refused("0x10001040", "a_Other", "knows no name of 0x10001040");
    refused("a_10001020", "9bad", "no C identifier");
    refused("a-b", "a_Other", "neither a C identifier nor an address");
    refused("a_Counter", "a_Counter", "the same name");
    // a name declared only in decl/*.dcl: the declaration line is renamed
    write(&t, "decl/data.dcl", "# data\n0x10002040 name a_Table -- the pointer table\n");
    let (code, out) = dcp(&t, &["rename", "a_Table", "a_Handlers", "--why", "x"]);
    assert!(code == 0 && out.contains("decl=1") && out.contains("file=decl/data.dcl  replacements=1\n    2: 0x10002040 name a_Handlers -- the pointer table"), "{out}");
    assert!(read(&t, "decl/data.dcl").contains("0x10002040 name a_Handlers -- the pointer table"));
}

/// Several OLD NEW pairs (and --from FILE) in one call: all are checked before anything is written, then written in
/// one pass, each with its record and its names.log event.
#[test]
fn rename_several_pairs() {
    let t = tiny();
    write(&t, "include/a.h", "int a_10001000(void);  /* 0x10001000 */\nextern int a_Unk10002000;  /* 0x10002000 */\n");
    unit(&t, "a", &["#include \"a.h\"\n", "/* 0x10001000, a_10001000 */\nint a_10001000(void)\n{\n    return a_Unk10002000;\n}\n",
                    "/* 0x10001020, a_10001020 */\nint a_10001020(void)\n{\n    return a_10001000() + a_Unk10002000;\n}\n"]);
    unit(&t, "d", &["int a_Unk10002000 = 0x1234;  /* 0x10002000 */\n"]);
    let before = snapshot(&t);
    let (code, out) = dcp(&t, &["rename", "a_10001000", "a_Main", "a_Nowhere", "a_Other", "--why", "x"]);
    assert!(code == 1 && out.contains("rename=a_Nowhere  to=a_Other  error=") && out.contains("nothing written"), "{out}");
    assert!(snapshot(&t) == before);
    let (code, out) = dcp(&t, &["rename", "a_10001000", "a_Main", "a_Main", "a_Entry", "--why", "x"]);
    assert!(code == 1 && out.contains("a chain") && snapshot(&t) == before, "{out}");
    let (code, out) = dcp(&t, &["rename", "a_10001000", "--why", "x"]);
    assert!(code == 1 && out.contains("pairs expected"), "{out}");
    // two pairs on the command line and one from a file (its own why); a why keeps its backslashes as written
    let why_file = r#"the sum of both ("Menu\SUM", \\server\x)"#;
    let why_arg = r#"the entry "Menu\CHOOSEPLAYER" \\server\ end\"#;
    write(&t, "pairs.txt", &format!("# the table\n0x10001020 a_Sum {why_file}\n"));
    let pairs = t.join("pairs.txt").to_string_lossy().into_owned();
    let (code, out) = dcp(&t, &["rename", "a_10001000", "a_Main", "a_Unk10002000", "a_Counter", "--from", &pairs, "--why", why_arg]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("renamed=a_10001000  to=a_Main  kind=func  at=0x10001000  files=2  replacements=4"), "{out}");
    assert!(out.contains("renamed=a_Unk10002000  to=a_Counter  kind=data  at=0x10002000  files=3"), "{out}");
    assert!(out.contains("renamed=a_10001020  to=a_Sum  kind=func  at=0x10001020  files=1"), "{out}");
    let a = read(&t, "src/a.c");
    assert!(a.contains("return a_Main() + a_Counter;") && a.contains("int a_Sum(void)") && !a.contains("a_10001000"));
    let log = read(&t, "names.log");
    let events: Vec<&str> = log.lines().rev().take(3).collect::<Vec<_>>().into_iter().rev().map(|l| l.split_once(' ').unwrap().1).collect();
    assert!(events[0].starts_with("0x10001000 func a_10001000 -> a_Main") && events[0].ends_with(&format!("why:{why_arg}")), "{events:?}");
    assert!(events[2].starts_with("0x10001020 func a_10001020 -> a_Sum") && events[2].ends_with(&format!("why:{why_file}")), "{events:?}");
}

/// A read-only mapping of a file held open (as `git diff` maps the files it reads): Windows refuses to truncate it.
#[cfg(windows)]
struct Mapped(*mut std::ffi::c_void, *mut std::ffi::c_void, std::fs::File);

#[cfg(windows)]
impl Mapped {
    fn new(p: &Path) -> Mapped {
        use std::os::windows::io::AsRawHandle;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn CreateFileMappingW(h: *mut std::ffi::c_void, sa: *mut std::ffi::c_void, prot: u32, hi: u32, lo: u32, name: *const u16) -> *mut std::ffi::c_void;
            fn MapViewOfFile(m: *mut std::ffi::c_void, access: u32, hi: u32, lo: u32, n: usize) -> *mut std::ffi::c_void;
        }
        let f = std::fs::File::open(p).unwrap();
        let m = unsafe { CreateFileMappingW(f.as_raw_handle(), std::ptr::null_mut(), 0x02, 0, 0, std::ptr::null()) };
        assert!(!m.is_null());
        let v = unsafe { MapViewOfFile(m, 0x0004, 0, 0, 0) };
        assert!(!v.is_null());
        Mapped(m, v, f)
    }
}

#[cfg(windows)]
impl Drop for Mapped {
    fn drop(&mut self) {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn UnmapViewOfFile(v: *mut std::ffi::c_void) -> i32;
            fn CloseHandle(h: *mut std::ffi::c_void) -> i32;
        }
        unsafe {
            UnmapViewOfFile(self.1);
            CloseHandle(self.0);
        }
    }
}

/// names.log is appended, never rewritten: a rename succeeds while another process maps the log. A write that fails
/// puts every file back: the sources, decl/ and names.log read as before, and the error says so.
#[test]
#[cfg(windows)]
fn rename_writes_all_or_nothing() {
    let t = tiny();
    write(&t, "include/a.h", "int a_10001000(void);  /* 0x10001000 */\nextern int a_Unk10002000;  /* 0x10002000 */\n");
    unit(&t, "a", &["#include \"a.h\"\n", "/* 0x10001000, a_10001000 */\nint a_10001000(void)\n{\n    return a_Unk10002000;\n}\n"]);
    unit(&t, "d", &["int a_Unk10002000 = 0x1234;  /* 0x10002000 */\n"]);
    let log = t.join("names.log");
    if std::fs::read(&log).map(|b| b.is_empty()).unwrap_or(true) {
        std::fs::write(&log, "2026-01-01T00:00:00 - unit x -> y by:main why:seed\n").unwrap();
    }
    // a source that cannot be written: nothing renamed, every file as before
    let before = snapshot(&t);
    let d = t.join("src/d.c");
    let mut perm = std::fs::metadata(&d).unwrap().permissions();
    perm.set_readonly(true);
    std::fs::set_permissions(&d, perm.clone()).unwrap();
    let (code, _, err) = dcp3(&t, &["rename", "a_10001000", "a_Main", "a_Unk10002000", "a_Counter", "--why", "x"]);
    #[allow(clippy::permissions_set_readonly_false)]
    perm.set_readonly(false);
    std::fs::set_permissions(&d, perm).unwrap();
    assert!(code == 1 && err.contains("d.c: ") && err.contains("every file put back as it was, nothing renamed"), "{err}");
    assert!(snapshot(&t) == before);
    // the log mapped by another reader: the rename goes through, one event per pair appended
    let lines = read(&t, "names.log").lines().count();
    let code = {
        let _m = Mapped::new(&log);
        dcp(&t, &["rename", "a_10001000", "a_Main", "a_Unk10002000", "a_Counter", "--why", "x"]).0
    };
    assert_eq!(code, 0);
    let events: Vec<String> = read(&t, "names.log").lines().map(|l| l.to_string()).collect();
    assert!(events.len() == lines + 2 && events[events.len() - 2].contains("a_10001000 -> a_Main") && events[events.len() - 1].contains("a_Unk10002000 -> a_Counter"), "{events:?}");
    assert!(read(&t, "src/a.c").contains("return a_Counter;"));
}

/// An address inside an instruction of a function lists from the next instruction boundary, with a note.
#[test]
fn disasm_inside_an_instruction() {
    let t = tiny();
    let (_, out) = dcp(&t, &["disasm", "0x10001000"]);
    let at: Vec<i64> = out.lines().filter(|l| l.starts_with("   0x")).map(|l| i64::from_str_radix(l.split_whitespace().next().unwrap().trim_start_matches("0x"), 16).unwrap()).collect();
    let (first, second) = at.windows(2).find(|w| w[1] - w[0] > 1).map(|w| (w[0], w[1])).unwrap();
    let (code, out) = dcp(&t, &["disasm", &format!("{:#x}", first + 1)]);
    assert!(code == 0 && out.contains("is inside an instruction") && out.contains(&format!("disasm=0x{second:08x}..")) && !out.contains("do not decode"), "{out}");
    assert_eq!(out.lines().find(|l| l.starts_with("   0x")).unwrap().split_whitespace().next().unwrap(), format!("0x{second:08x}"));
}

/// The line after `gate: ok` fits the session's kind.
#[test]
fn session_start_guidance_by_kind() {
    use crate::cli::commands::guidance;
    assert!(guidance(Some("layout")).contains("over=yes") && !guidance(Some("layout")).contains("functions"));
    assert!(guidance(Some("match-base")).contains("counted in functions") && !guidance(Some("match-base")).contains("over=yes"));
    assert!(guidance(None).contains("A layout session") && guidance(None).contains("A match-base session"));
}
