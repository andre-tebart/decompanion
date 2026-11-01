//! Checks that catch source decisions the link and the byte match let pass: A1 (an image address literal cast to a
//! pointer), L13 (a data declaration at a function's code), L15 (views), the link's `library` class with its
//! libs.archives obligation, and `dcp headers conflicts` (tests/test_source_checks.py).

use super::*;

const VC6: &str = "C:/Tools/MSVC600-SP5PP";
const DX6: &str = "C:/Tools/DXSDK61/lib";

fn errors(root: &Path, check: &str) -> Vec<FindingRow> {
    findings(root, None).into_iter().filter(|c| c.1 == check && c.0 == "error").collect()
}

fn has_clang() -> bool {
    crate::frontend::clang_library().is_some()
}

#[test]
fn a1_addr_cast() {
    let t = tiny();
    assert_eq!(dcp(&t, &["decl", "add", "0x10001050 name ShowWorld -- pushes world (test)"]).0, 0);
    unit(&t, "net", &["int counter = 0x1234;  /* 0x10002000 */\nextern int atexit(void (*)(void));\n",
                      "/* 0x10001030, logs hello */\nvoid log_hello(void)\n{\n\
                           char *p = (char *)(unsigned)&counter;\n\
                           int n = (int)0x10001050;\n\
                           char *s = (char *)0x10002030;\n\
                           char *z = (char *)0x20002030;\n\
                           atexit((void (*)(void))0x10001050);\n}\n"]);
    let (code, out) = dcp(&t, &["check"]);
    assert!(code == 1 && out.contains("gate=FAIL"), "{out}");
    let mut a1 = errors(&t, "A1");
    a1.sort_by_key(|c| std::cmp::Reverse(c.2));
    assert_eq!(a1.iter().map(|c| c.2).collect::<Vec<_>>(), [0x10002030, 0x10001050], "{out}");
    assert!(a1[0].4.contains("src/net.c:9: `(char *)0x10002030`") && a1[0].4.contains("the string 0x10002030"), "{}", a1[0].4);
    assert!(a1[1].4.contains("src/net.c:11: `(void (*)(void))0x10001050`") && a1[1].4.contains("the name ShowWorld there: reference ShowWorld by name"), "{}", a1[1].4);
}

#[test]
fn l13_data_at_code() {
    let t = tiny();
    let get = "/* 0x10001020, reads the counter */\nint get(void)\n{\n    return counter;\n}\n";
    unit(&t, "net", &["int counter = 0x1234;  /* 0x10002000 */\nextern char stub[];  /* 0x10001020, a function's start */\nextern char mid[];   /* 0x10001021, inside it */\n", get]);
    let (code, out) = dcp(&t, &["check"]);
    assert_eq!(code, 1, "{out}");
    let mut l13 = errors(&t, "L13");
    l13.sort_by_key(|c| c.2);
    assert_eq!(l13.iter().map(|c| c.2).collect::<Vec<_>>(), [0x10001020, 0x10001021], "{out}");
    assert!(l13[0].4.contains("data extern stub at 0x10001020 lies at the start of the function 0x10001020..0x10001026 (the name get)"), "{}", l13[0].4);
    assert!(l13[1].4.contains("+0x1 inside the function 0x10001020..0x10001026"), "{}", l13[1].4);
    unit(&t, "net", &["int counter = 0x1234;  /* 0x10002000 */\n", get]);
    let (code, out) = dcp(&t, &["check"]);
    assert!(code == 0 && errors(&t, "L13").is_empty(), "{out}");
}

const VIEWS_H: &str = "#define rec_Count (*(int *)((char *)&records + 0x4))  /* 0x10002004 */\n\
#define rec_Names (*(char (*)[2][8])((char *)table + 8))  /* 0x10002008 */\n\
#define rec_All (*(int (*)[4])&records)  /* 0x10002000 */\n\
#define rec_Alias records  /* 0x10002000 */\n\
#define rec_Bad (*(int *)((char *)&records + 0x8))  /* 0x1000200c */\n\
#define LOCAL (*(int *)&p)\n\
#define SIZE 0x10  /* 0x10, the record size */\n";

#[test]
fn l15_views() {
    let t = tiny();
    write(&t, "include/views.h", &format!("extern int records[4];  /* 0x10002000 */\n{VIEWS_H}"));
    unit(&t, "net", &["#include \"views.h\"\n", "/* 0x10001020, reads the count */\nint get(void)\n{\n    return rec_Count;\n}\n"]);
    let (code, out) = dcp(&t, &["check"]);
    assert_eq!(code, 1, "{out}");
    let mut l15 = errors(&t, "L15");
    l15.sort_by_key(|c| c.2);
    assert_eq!(l15.iter().map(|c| c.2).collect::<Vec<_>>(), [0x10002008, 0x1000200c], "{out}");
    assert!(l15[0].4.contains("view rec_Names: its container table has no data declaration with an address"), "{}", l15[0].4);
    assert!(l15[1].4.contains("view rec_Bad at 0x1000200c, but records (0x10002000) + 0x8 is 0x10002008"), "{}", l15[1].4);
    let names: std::collections::BTreeMap<String, i64> = facts(&t, "name", None).iter().filter(|f| f.value.get("view").is_some_and(|v| !v.is_null() && v != false))
        .map(|f| (f.value["name"].as_str().unwrap().to_string(), f.lo)).collect();
    assert_eq!(names, [("rec_Alias".to_string(), 0x10002000), ("rec_All".to_string(), 0x10002000), ("rec_Count".to_string(), 0x10002004)].into());
}

/// A COFF archive whose first linker member lists `symbols` (all at one dummy member).
fn build_symlib(path: &Path, symbols: &[&str]) -> PathBuf {
    let n = symbols.len() as u32;
    let mut body = n.to_be_bytes().to_vec();
    for _ in 0..n {
        body.extend(0u32.to_be_bytes());
    }
    for s in symbols {
        body.extend(s.as_bytes());
        body.push(0);
    }
    let pad = |s: &str, w: usize| format!("{s:<w$}");
    let hdr = format!("{}{}{}{}{}{}`\n", pad("/", 16), pad("0", 12), pad("0", 6), pad("0", 6), pad("0", 8), pad(&body.len().to_string(), 10));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut out = b"!<arch>\n".to_vec();
    out.extend(hdr.as_bytes());
    let odd = body.len() & 1 == 1;
    out.extend(body);
    if odd {
        out.push(b'\n');
    }
    std::fs::write(path, out).unwrap();
    path.to_path_buf()
}

#[test]
fn link_library_class() {
    let t = tiny();
    assert_eq!(dcp(&t, &["setup"]).0, 0);
    let lib = build_symlib(&t.join("libs").join("guids.lib"), &["_IID_Foo"]);
    let p = project(&t, None);
    let out: std::collections::HashMap<String, Vec<String>> = crate::link::link_classify(&p, vec!["_IID_Foo".into(), "_nowhere".into()]).unwrap().into_iter().collect();
    let l = posix(&lib);
    assert_eq!(out["library"], [format!("_IID_Foo  ->  {l}  (undeclared: dcp libs declare <the declared archives> {l} --why \"...\")")]);
    assert_eq!(out["other"], ["_nowhere"]);
    // the index is in the store, by content
    assert!(!crate::storedb::st_blobs(&p.store_path(), &p.main_uri(), "archive.symbols").unwrap().is_empty());
    // the obligation reads the last link's classes
    write(&t, "build/link/tiny/link.json", &serde_json::json!({"unresolved": out}).to_string());
    let obl: Vec<String> = crate::decide::decide_gate(&p).unwrap().into_iter().filter(|o| o.contains("obligation=libs.archives")).collect();
    assert!(obl.len() == 1 && obl[0].contains("1 unresolved name(s)") && obl[0].contains("guids.lib defines 1: _IID_Foo"), "{obl:?}");
}

/// _IID_IDirectDraw4 is in the DX 6.1 SDK's dxguid.lib only (VC98's DXGUID.LIB is DX5).
#[test]
#[ignore = "e2e: VC6 and the DX 6.1 SDK"]
fn link_library_class_dx6() {
    if !(Path::new(VC6).join("VC98/Lib").exists() && Path::new(DX6).join("dxguid.lib").exists()) {
        return;
    }
    let t = tiny();
    set_config(&t, "root = \"C:/nowhere/vc6\"\n", &format!("root = \"{VC6}\"\nlib_dirs = [\"{DX6}\"]\n"));
    assert_eq!(dcp(&t, &["setup"]).0, 0);
    let out: std::collections::HashMap<String, Vec<String>> =
        crate::link::link_classify(&project(&t, None), vec!["_IID_IDirectDraw4".into(), "_GUID_SysMouse".into()]).unwrap().into_iter().collect();
    let line = out["library"].iter().find(|l| l.starts_with("_IID_IDirectDraw4")).unwrap();
    assert!(line.starts_with(&format!("_IID_IDirectDraw4  ->  {DX6}/dxguid.lib  (")), "{line}");
    let mouse = out["library"].iter().find(|l| l.starts_with("_GUID_SysMouse")).unwrap();
    assert!(mouse.contains(&format!("{DX6}/dxguid.lib")) && mouse.contains("VC98/Lib/DXGUID.LIB"), "{mouse}");
}

#[test]
#[ignore = "e2e: libclang"]
fn headers_conflicts() {
    if !has_clang() {
        return;
    }
    let t = tiny();
    write(&t, "include/net.h", "extern int counter;\nextern short width;\nint add2(int a, int b);\n");
    unit(&t, "net", &["extern int counter;  /* the same as net.h */\nextern char width;\n", "/* 0x10001030, logs hello */\nvoid log_hello(void)\n{\n    add2(1);\n    other(2);\n}\n"]);
    let (code, out) = dcp(&t, &["headers", "conflicts", "net", "net"]);
    assert_eq!(code, 1, "{out}");
    for w in ["supersedes=1  call=1", "duplicate=1", "kind=supersedes  name=width  at=src/net.c:2  header=include/net.h:2", "kind=duplicate  name=counter  at=src/net.c:1",
              "kind=call  name=add2  at=src/net.c:7", "too few arguments", "fn=0x10001030"] {
        assert!(out.contains(w), "{w}: {out}");
    }
    let (code, out) = dcp(&t, &["headers", "conflicts", "net", "net", "--write"]);
    assert!(code == 1 && out.contains("write=refused"), "{out}");
    assert!(read(&t, "src/net.c").contains("extern char width;"));
    let f = "/* 0x10001030, logs hello */\nvoid log_hello(void)\n{\n    add2(1, 2);\n}\n";
    unit(&t, "net", &["extern int counter;  /* the same as net.h */\n", f]);
    let (code, out) = dcp(&t, &["headers", "conflicts", "net", "net.h", "--write"]);
    assert!(code == 0 && out.contains("dropped=1"), "{out}");
    assert_eq!(read(&t, "src/net.c"), format!("#include \"net.h\"\n\n{f}"));
}

#[test]
#[ignore = "e2e: libclang"]
fn headers_conflicts_exempt_and_shifted() {
    if !has_clang() {
        return;
    }
    let t = tiny();
    write(&t, "include/net.h", "int add2(int a, int b);\n");
    unit(&t, "net", &["extern int counter;\n", "/* 0x10001030, logs hello */\nvoid log_hello(void)\n{\n    add2(1);  /* @original the original pushes one argument */\n    counter = nope;\n}\n"]);
    let (code, out) = dcp(&t, &["headers", "conflicts", "net", "net"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("call=0  vc6=0  other=0") && out.contains("kind=call  name=add2  at=src/net.c:6  decl=include/net.h:1  exempt=@original") && !out.contains("nope"), "{out}");
    let (code, out) = dcp(&t, &["headers", "conflicts", "net", "net", "--write"]);
    assert!(code == 0 && out.contains("write=src/net.c"), "{out}");
    assert!(read(&t, "src/net.c").contains("#include \"net.h\""));
    write(&t, "include/net.h", "extern short width;\n");
    unit(&t, "net", &["extern char width;  /* @original the unit reads a byte */\n", "/* 0x10001030, logs hello */\nvoid log_hello(void)\n{\n    width = 1;\n}\n"]);
    let (code, out) = dcp(&t, &["headers", "conflicts", "net", "net"]);
    assert!(code == 1 && out.contains("supersedes=1") && out.contains("kind=supersedes  name=width  at=src/net.c:1  header=include/net.h:1  exempt=-"), "{out}");
    let (code, out) = dcp(&t, &["headers", "conflicts", "net", "net", "--write"]);
    assert!(code == 1 && out.contains("write=refused"), "{out}");
}

#[test]
#[ignore = "e2e: libclang"]
fn headers_conflicts_warnings() {
    if !has_clang() {
        return;
    }
    let t = tiny();
    write(&t, "include/net.h", "int add2(int a, int b);  /* 0x10001020 */\nvoid setf(float f);\nint spare(void);\n");
    let head = "int add2(int a, int b);  /* 0x10001020, adds two numbers */\n";
    let add2 = "/* 0x10001020 */\nint add2(int a, int b)\n{\n    return a + b;\n}\n";
    unit(&t, "net", &[head, add2, "/* 0x10001030, logs hello */\nvoid log_hello(int x)\n{\n    setf(1);\n    setf(x);\n    g(1, \"a\");\n}\n"]);
    let (_, out) = dcp(&t, &["headers", "conflicts", "net", "net"]);
    for w in ["vc6_trial=unavailable", "kind=prototyped  name=setf", "safe=0 (constant arguments", "regrade=2",
              "src/net.c:12 (an integer constant to a floating parameter: re-grade)", "src/net.c:13 (expressions: re-grade)",
              "warning=declaration-set  added=2  duplicates=1  functions=2  byte=0  shape=0"] {
        assert!(out.contains(w), "{w}: {out}");
    }
    write(&t, "include/net.h", "int add2(int a, int b);\nint add3(int a, char *s);\n");
    unit(&t, "net", &[head, add2, "/* 0x10001030, logs hello */\nvoid log_hello(int x)\n{\n    add3(-1, (char *)\"a\");\n}\n"]);
    let (_, out) = dcp(&t, &["headers", "conflicts", "net", "net"]);
    assert!(out.contains("kind=prototyped  name=add3") && out.contains("safe=1") && out.contains("regrade=0") && out.contains("src/net.c:12 (constants: safe)"), "{out}");
}

#[test]
#[ignore = "e2e: libclang"]
fn headers_conflicts_multi_name_and_position() {
    if !has_clang() {
        return;
    }
    let t = tiny();
    write(&t, "include/net.h", "extern int counter;\nextern int width;\nextern int height;\n");
    write(&t, "include/late.h", "typedef int LATE;\n");
    write(&t, "include/base.h", "typedef int BASE;\n");
    let get = "/* 0x10001020, reads */\nint get(void)\n{\n    return counter + depth;\n}\n";
    unit(&t, "net", &["#include \"base.h\"\nextern int counter, width, depth;  /* 0x10002000, the counter */\nextern int height;\nint *pw = &width;\n#include \"late.h\"\nLATE spare;\n", get]);
    let (code, out) = dcp(&t, &["headers", "conflicts", "net", "net"]);
    assert_eq!(code, 0, "{out}");
    for (n, ln) in [("counter", 2), ("width", 2), ("height", 3)] {
        assert!(out.contains(&format!("kind=duplicate  name={n}  at=src/net.c:{ln}")), "{out}");
    }
    assert!(out.contains("duplicate=3"), "{out}");
    let (code, out) = dcp(&t, &["headers", "conflicts", "net", "net", "--write"]);
    assert!(code == 0 && out.contains("at=4") && out.contains("dropped=3  lines=2"), "{out}");
    assert_eq!(read(&t, "src/net.c"), format!("#include \"base.h\"\nextern int depth;  /* 0x10002000, the counter */\n#include \"net.h\"\nint *pw = &width;\n#include \"late.h\"\nLATE spare;\n\n{get}"));
    write(&t, "include/net2.h", "extern int depth;\n");
    let (code, out) = dcp(&t, &["headers", "conflicts", "net", "net2", "--write", "--at", "1"]);
    assert!(code == 0 && out.contains("at=1"), "{out}");
    assert!(read(&t, "src/net.c").starts_with("#include \"net2.h\"\n#include \"base.h\"\n#include \"net.h\"\n"));
}

/// clang accepts a struct parameter by value whose type the unit never completes; VC6 rejects it (C2079): the VC6
/// trial reports it as a blocking `vc6` item and --write refuses.
#[test]
#[ignore = "e2e: VC6 and libclang"]
fn headers_conflicts_vc6() {
    if !(has_clang() && Path::new(VC6).join("VC98/Bin/CL.EXE").exists()) {
        return;
    }
    let t = tiny();
    set_config(&t, "root = \"C:/nowhere/vc6\"\n", &format!("root = \"{VC6}\"\n"));
    write(&t, "include/net.h", "void paint(struct COLOR c);\n");
    unit(&t, "net", &["int counter = 1;  /* 0x10002000 */\n", "/* 0x10001020, reads */\nint get(void)\n{\n    return counter;\n}\n"]);
    let (code, out) = dcp(&t, &["headers", "conflicts", "net", "net"]);
    assert!(code == 1 && out.contains("supersedes=0") && out.contains("vc6=1") && out.contains("kind=vc6") && out.contains("C2079") && out.contains("COLOR"), "{out}");
    let (code, out) = dcp(&t, &["headers", "conflicts", "net", "net", "--write"]);
    assert!(code == 1 && out.contains("write=refused"), "{out}");
}

/// The byte map after a rerun with the same output names current facts only (tests/test_speed.py).
#[test]
fn answers_name_current_claims_after_same_output_rerun() {
    let t = tiny();
    assert_eq!(dcp(&t, &["setup", "--no-analyzer"]).0, 0);
    assert_eq!(dcp(&t, &["setup", "--no-analyzer", "--force"]).0, 0); // every rule again, the same output
    let p = project(&t, None);
    let db = p.store_path();
    crate::storedb::st_open(&db, &p.main_uri()).unwrap();
    crate::answers::ensure_at(&db).unwrap();
    let ids: std::collections::BTreeSet<i64> = crate::answers::rows(&db, None, None).unwrap().iter().filter_map(|r| r.symbol).collect();
    assert!(!ids.is_empty() && ids.iter().all(|&i| crate::storedb::st_fact(&db, i).unwrap().is_some()));
}
