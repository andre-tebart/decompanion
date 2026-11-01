//! The real binaries of The Guild Gold (skipped when the GOG install or VC6 is absent): setup on server.dll (the PE
//! facts, a total map), layout on it, the match phase (byte matches, the data site, the link, promote and M1, the
//! probe), the reading tools and the Ghidra export, and server.dll with GildeGold.exe as two targets
//! (tests/test_setup_server.py, test_layout_server.py, test_match_server.py, test_layout_tools_server.py,
//! test_setup_exe.py). All e2e: `cargo test servers -- --ignored`.

use super::*;
use crate::store::{DECLARED, DERIVED};

const GAME: &str = "C:/Program Files/GOG Galaxy/Games/The Guild Gold";
const VC6: &str = "C:/Tools/MSVC600-SP5PP";

fn server() -> PathBuf {
    PathBuf::from(GAME).join("server/server.dll")
}

fn exe() -> PathBuf {
    PathBuf::from(GAME).join("GildeGold.exe")
}

fn have(cl: bool) -> bool {
    server().exists() && Path::new(VC6).exists() && (!cl || Path::new(VC6).join("VC98/Bin/CL.EXE").exists())
}

/// What a human declares for a project of The Guild Gold after `dcp init`: the VC6 SP5 + PP builds, the root, the
/// release flags, the static archives; each with a reason (conftest.declare_vc6).
fn declare_vc6(root: &Path, archives: &[&str], target: Option<&str>, with_root: bool) {
    let mut pre: Vec<&str> = vec![];
    if let Some(t) = target {
        pre.extend(["--target", t]);
    }
    let root_kv = format!("root={VC6}");
    let mut pairs = vec!["compiler=cl 12.00.9044", "linker=link 6.00.8447", "cflags=/O2 /Gy"];
    if with_root {
        pairs.push(&root_kv);
    }
    let mut tc: Vec<&str> = pre.clone();
    tc.extend(["toolchain", "declare"]);
    tc.extend(&pairs);
    tc.extend(["--why", "test: the Rich builds 9044 / 8447, VC6 SP5 + PP"]);
    let mut libs: Vec<&str> = pre.clone();
    libs.extend(["libs", "declare"]);
    libs.extend(archives);
    libs.extend(["--why", "test: the static CRT the image links"]);
    let steps = if with_root { vec![tc, libs] } else { vec![libs, tc] };
    for s in steps {
        let (code, out) = dcp(root, &s);
        assert_eq!(code, 0, "{s:?}: {out}");
    }
}

fn init(dir: &Path, binary: &Path, target_name: Option<&str>) {
    let (b, d) = (binary.to_string_lossy().into_owned(), dir.to_string_lossy().into_owned());
    let mut a = vec!["init", &d, &b];
    if let Some(n) = target_name {
        a.extend(["--target-name", n]);
    }
    let (code, out, err) = dcp_bare(&a);
    assert_eq!(code, 0, "{out}{err}");
}

// ------------------------------------------------------------------------------------------------ setup

#[test]
#[ignore = "e2e: server.dll and VC6"]
fn setup_server_pe_facts_and_total_map() {
    if !have(false) {
        return;
    }
    let d = tmp("guild-server").join("proj");
    init(&d, &server(), None);
    declare_vc6(&d, &["LIBC"], None, true);
    let p = project(&d, None);
    let img = p.image_checked().unwrap();
    assert!(img.is_dll && img.base == 0x10000000);
    let ex: std::collections::BTreeSet<String> = img.exports().into_iter().filter_map(|e| e.name).collect();
    assert_eq!(ex, ["Exit".to_string(), "Init".to_string()].into());
    assert_eq!(img.relocations().len(), 3099);
    assert!(img.rich().contains(&(48, 9044, 37)));
    assert_eq!(dcp(&d, &["setup", "--no-analyzer"]).0, 0);
    let db = p.store_path();
    crate::storedb::st_open(&db, &p.main_uri()).unwrap();
    crate::answers::ensure_at(&db).unwrap();
    let rows = crate::answers::rows(&db, None, None).unwrap();
    // total and non-overlapping over the mapped image
    assert!(rows[0].lo == img.base as i64 && rows[rows.len() - 1].hi == img.end() as i64);
    for w in rows.windows(2) {
        assert_eq!(w[0].hi, w[1].lo, "gap or overlap at {:#x}", w[0].hi);
    }
    let names: std::collections::HashMap<String, i64> = facts(&d, "name", None).iter().map(|f| (f.value["name"].as_str().unwrap().to_string(), f.lo)).collect();
    assert!(names["Init"] == 0x10008cc0 && names["Exit"] == 0x10008cf0 && names["_DllMain@12"] == 0x10008cb0 && names["DllMain"] == 0x10008cb0);
    assert!(names.contains_key("_malloc") && names["__DllMainCRTStartup@12"] == img.entry as i64);
    let bad: Vec<FindingRow> = findings(&d, None).into_iter().filter(|c| c.0 == "bug" || c.0 == "error").collect();
    assert!(bad.is_empty(), "{:?}", &bad[..bad.len().min(5)]);
    let tc = facts(&d, "toolchain", None)[0].value.clone();
    let comp = |tool: &str, build: i64| tc["compilers"].as_array().unwrap().iter().find(|c| c["tool"] == tool && c["build"] == build).unwrap().clone();
    assert!(comp("Utc12_2_C", 9044)["count"] == 37 && comp("Utc12_2_C", 9044)["archive_objects"] == 0);
    assert!(comp("Utc12_C", 8047)["archive_objects"].as_i64().unwrap() > 0);
    assert!(tc["linkers"].as_array().unwrap().iter().any(|k| k["build"] == 8447));
    let decl = p.toolchain_decl(None).unwrap();
    assert!(decl["compiler"] == "cl 12.00.9044" && decl["linker"] == "link 6.00.8447" && decl["reasons"]["compiler"].as_str().unwrap().starts_with("test:"));
    assert!(!engine_ran(&d, None)); // a second run runs nothing
}

// ------------------------------------------------------------------------------------------------ layout

fn set_decl(root: &Path, text: &str) {
    write(root, "decl/text.dcl", &format!("# code\n{text}"));
}

#[test]
#[ignore = "e2e: server.dll and VC6"]
fn layout_server() {
    if !have(false) {
        return;
    }
    let d = tmp("guild-server").join("proj");
    init(&d, &server(), None);
    declare_vc6(&d, &["LIBC"], None, true);
    assert_eq!(dcp(&d, &["setup", "--no-analyzer"]).0, 0);
    // Init's unit
    set_decl(&d, "");
    assert_eq!(dcp(&d, &["decl", "add", "0x10008cb0 boundary start tu=dllmain by=guess -- DllMain, Init and Exit: the entry points"]).0, 0);
    assert_eq!(dcp(&d, &["decl", "add", "0x10008d20 boundary end tu=dllmain -- the thread procedure Init starts begins the next unit"]).0, 0);
    let (_, out) = dcp(&d, &["layout", "units"]);
    let line = line_with(&out, "unit=dllmain");
    assert!(line.contains("range=0x10008cb0..0x10008d20") && line.contains("status=separated") && line.contains("functions=3"), "{line}");
    assert_eq!(dcp(&d, &["check"]).0, 0);
    let (_, out) = dcp(&d, &["layout", "next", "--start", "0x10008cb0"]);
    assert!(out.contains("next=0x10008cb0") && out.contains("unit=dllmain"), "{out}");
    // a wrong boundary
    set_decl(&d, "0x10008cc5 boundary start tu=bad -- inside Init on purpose\n");
    let (code, out) = dcp(&d, &["check"]);
    assert!(code == 1 && out.contains("L4") && out.contains("inside the function 0x10008cc0"), "{out}");
    // dead bytes over walked code
    set_decl(&d, "0x10008cd0..0x10008ce0 bytes dead -- the walk reaches these\n");
    let (code, out) = dcp(&d, &["check"]);
    assert!(code == 1 && out.contains("L6"), "{out}");
    // a walk crossing a source
    set_decl(&d, "");
    write(&d, "src/inside.c", "/* 0x10008cc5, a start inside Init */\nvoid f(void)\n{\n}\n");
    let (code, out) = dcp(&d, &["check"]);
    assert!(code == 1 && out.contains("L1") && out.contains("src/inside.c:1: f starts at 0x10008cc5"), "{out}");
    std::fs::remove_file(d.join("src/inside.c")).unwrap();
    assert_eq!(dcp(&d, &["check"]).0, 0);
}

// ------------------------------------------------------------------------------------------------ match

const HEAD: &str = "/* dllmain: the dll's entry points and the server thread's handle and stop flag */\n#include <windows.h>\n\n\
unsigned long __cdecl _beginthread(void (__cdecl *start)(void *), unsigned stack_size, void *arglist);\nvoid __cdecl ServerThread(void *arg);\n\n\
int g_stopServer = 0;                   /* 0x10031270 */\nunsigned long g_hServerThread = 0;      /* 0x11760c74 */\n";

const DECL: &str = "0x10008cb0 boundary start by=guess tu=dllmain -- DllMain, Init and Exit\n\
0x10008d20 boundary end tu=dllmain -- the thread procedure begins the next unit\n\
0x10008d20 boundary start by=guess tu=server -- the server thread\n\
0x10009840 boundary end tu=server -- the server thread ends at 0x1000983f\n";

#[test]
#[ignore = "e2e: server.dll and VC6"]
fn match_server() {
    if !have(true) {
        return;
    }
    let d = tmp("m3-server").join("proj");
    init(&d, &server(), Some("server"));
    declare_vc6(&d, &["LIBCMT"], None, true);
    set_decl(&d, DECL);
    write(&d, "src/dllmain.c", &format!("{HEAD}\n/* 0x10008cb0, the dll's entry point */\nBOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)\n{{\n    return TRUE;\n}}\n\
        \n/* 0x10008cc0, starts the server thread */\nint __cdecl Init(void *arg)\n{{\n    g_hServerThread = _beginthread(ServerThread, 0, arg);\n    return g_hServerThread != (unsigned long)-1;\n}}\n\
        \n/* 0x10008cf0, stops the server thread */\nvoid __cdecl Exit(void)\n{{\n    if (g_hServerThread) {{\n        g_stopServer = 1;\n        do {{\n            Sleep(10);\n        }} while (g_stopServer);\n    }}\n}}\n"));
    write(&d, "src/server.c", "extern int g_stopServer;\n\n/* 0x10008d20, the server thread @rough */\nvoid __cdecl ServerThread(void *arg)\n{\n    g_stopServer = 0;\n}\n");
    let (code, out) = dcp(&d, &["build"]);
    assert_eq!(code, 0, "{out}");
    // byte matches
    let (_, out) = dcp(&d, &["grade", "dllmain"]);
    for name in ["DllMain", "Init", "Exit"] {
        let line = out.lines().find(|l| l.contains(&format!("name={name} "))).unwrap();
        assert!(line.contains("experiment=byte") && line.contains("readability=readable"), "{out}");
    }
    let (_, out) = dcp(&d, &["claims", "0x10008cb0..0x10008d20", "--kind", "symbol"]);
    assert!(out.contains("relocs=2/2") && out.contains("relocs=4/4") && out.contains("relocs=0/0"), "{out}");
    let (_, out) = dcp(&d, &["next"]);
    assert!(out.contains("next=0x10008d20") && out.contains("name=ServerThread") && out.contains("section=draft"), "{out}");
    // the data site
    let (_, out) = dcp(&d, &["claims", "0x10031270..0x10031274", "--kind", "symbol"]);
    assert!(out.contains("extent=site") && out.contains("name=g_stopServer") && out.contains("proven"), "{out}");
    // the link and check
    let (code, out) = dcp(&d, &["link"]);
    assert!(code == 0 && out.contains("ok=yes") && out.contains("unresolved=0"), "{out}");
    assert!(d.join("build/link/server/server.dll").exists() && read(&d, "build/link/server/server.def").contains("Init @2"));
    assert_eq!(dcp(&d, &["check"]).0, 0);
    // promote and M1
    let (code, out) = dcp(&d, &["promote"]);
    assert!(code == 0 && out.contains("functions=4"), "{out}");
    let good = read(&d, "src/dllmain.c");
    write(&d, "src/dllmain.c", &good.replace("!= (unsigned long)-1", "== 0"));
    let (code, out) = dcp(&d, &["check"]);
    write(&d, "src/dllmain.c", &good);
    assert!(code == 1 && out.contains("M1") && out.contains("Init"), "{out}");
    assert_eq!(dcp(&d, &["check"]).0, 0);
    // the probe
    let (code, out) = dcp(&d, &["toolchain", "probe"]);
    assert!(code == 0 && out.contains("anchors=3") && out.contains("matched=3/3") && out.contains("indistinguishable"), "{out}");
    assert!(dcp(&d, &["toolchain"]).1.contains("probe  flag=/O2"));
}

// ------------------------------------------------------------------------------------------------ reading tools, Ghidra

fn srv() -> PathBuf {
    let root = tmp("srv").join("proj");
    init(&root, &server(), Some("server"));
    declare_vc6(&root, &["LIBCMT"], None, true);
    assert_eq!(dcp(&root, &["setup", "--no-analyzer"]).0, 0);
    root
}

#[test]
#[ignore = "e2e: server.dll and VC6"]
fn reading_tools_on_server() {
    if !have(false) {
        return;
    }
    let s = srv();
    let (code, out) = dcp(&s, &["layout", "starts", "0x10008c00..0x10009000"]);
    assert!(code == 0 && out.contains("starts=6") && out.contains("start=0x10008cc0  how=export") && out.contains("start=0x10008d20  how=immediate"), "{out}");
    let (_, out) = dcp(&s, &["layout", "literals", "0x10008c00..0x10009000"]);
    assert!(out.contains("fn=0x10008d20") && out.contains("first_used=10") && out.contains("text=GamePath"), "{out}");
    let (_, out) = dcp(&s, &["disasm", "Init"]);
    assert!(out.contains("push 0x10008d20") && out.contains("<_beginthread>"), "{out}");
    let (_, out) = dcp(&s, &["dump", "0x10027d08", "0x20", "--str"]);
    assert!(out.contains("text=General") && out.contains("text=GamePath"), "{out}");
    assert!(dcp(&s, &["refs", "Init"]).1.contains("named=Init  origin=export"));
}

#[test]
#[ignore = "e2e: Ghidra headless (about 30 s), server.dll and VC6"]
fn ghidra_export_and_draft() {
    if !(have(false) && crate::analyzers::Analyzer::default_unconfigured().available().ok()) {
        return;
    }
    let s = srv();
    assert!(read(&s, "decompanion.toml").contains("plugin = \"ghidra\"")); // dcp init found it
    let (code, out) = dcp(&s, &["setup"]);
    assert!(code == 0 && out.contains("analyzer=ghidra  exported=678  failed=0"), "{out}");
    let (_, out) = dcp(&s, &["setup"]);
    assert!(!out.contains("exported=") && out.contains("export=up-to-date"), "{out}"); // the same image, script and starts: nothing runs
    assert!(out.contains("game_functions=311") && out.contains("with_draft=311") && out.contains("ours_only=0") && out.contains("l9=0"), "{out}");
    let (code, out) = dcp(&s, &["draft", "0x10008cc0", "--show"]);
    assert!(code == 0 && out.contains("FUN_10019af5(FUN_10008d20"), "{out}"); // Ghidra's own names
    assert_eq!(dcp(&s, &["unit", "new", "dllmain", "--range", "0x10008cb0..0x10008d20", "--by", "guess", "--why", "DllMain, Init and Exit"]).0, 0);
    for a in ["0x10008cb0", "0x10008cc0", "0x10008cf0"] {
        let (code, out) = dcp(&s, &["draft", a]);
        assert!(code == 0 && out.contains("body=ghidra"), "{out}");
    }
    let text = read(&s, "src/dllmain.c");
    let init = &text[text.find("/* 0x10008cc0").unwrap()..text.find("/* 0x10008cf0").unwrap()];
    // the export's name, the library member's name, the placeholder of a function in no unit yet
    assert!(init.starts_with("/* 0x10008cc0, Init */") && init.contains("_beginthread(unk_10008d20,0,param_1)"), "{init}");
    assert!(text[..text.find("/* 0x10008cb0").unwrap()].contains("#include <process.h>")); // the CRT header that declares _beginthread
}

// ------------------------------------------------------------------------------------------------ two targets

fn guild() -> PathBuf {
    let d = tmp("guild").join("proj");
    init(&d, &server(), Some("server"));
    assert_eq!(dcp(&d, &["target", "add", "exe", &exe().to_string_lossy()]).0, 0);
    declare_vc6(&d, &["LIBC"], None, true);
    declare_vc6(&d, &["LIBC", "DINPUT"], Some("exe"), false);
    let (code, out) = dcp(&d, &["setup", "--all-targets", "--no-analyzer"]); // a Ghidra export of the exe takes minutes
    assert_eq!(code, 0, "{out}");
    d
}

#[test]
#[ignore = "e2e: server.dll, GildeGold.exe and VC6"]
fn setup_exe() {
    if !(have(false) && exe().exists()) {
        return;
    }
    let g = guild();
    // declarations and the gate
    for name in ["server", "exe"] {
        let d = project(&g, Some(name)).toolchain_decl(None).unwrap();
        assert!(d["compiler"] == "cl 12.00.9044" && d["linker"] == "link 6.00.8447", "{name}");
    }
    let (code, out) = dcp(&g, &["check"]);
    assert_eq!(code, 0, "{out}");
    let (_, out) = dcp(&g, &["toolchain"]);
    assert!(out.matches("C.toolchain: ok").count() == 2 && out.contains("link 5.12.9049 (Linker512 - x3)"), "{out}");
    // the exe's landmarks
    let syms: std::collections::HashMap<i64, std::rc::Rc<crate::store::Claim>> = facts(&g, "symbol", Some("exe")).into_iter().map(|f| (f.lo, f)).collect();
    assert!(syms[&0x422d90].hi == 0x422dbc && syms[&0x422d90].value["skind"] == "func");
    assert!(syms[&0x42c3a0].value["skind"] == "func" && syms[&0x42c3a0].hi == 0x42c3a6);
    assert_eq!(syms[&0x5de450].value["skind"], "thunk");
    assert_eq!(syms[&0x5dd3e0].value["unit"], "lib:DINPUT.LIB/dilib2.obj");
    assert!(syms[&0x465e00].hi == 0x465e6d && syms.contains_key(&0x465e70));
    assert!(syms[&0x4eabd0].hi == 0x4eabd5 && syms.contains_key(&0x4eabe0));
    assert_eq!(syms[&0x4276a0].hi, 0x4277b5);
    assert_eq!(syms[&0x5de4a0].value["name"], "_strrchr");
    assert!(dcp(&g, &["--target", "exe", "layout", "units"]).1.contains("game=0x00401000..0x005dd3e0"));
    // a declared start is a walk root; a declared file name must be the image's string at its address
    let walked = |g: &Path| facts(g, "symbol", Some("exe")).into_iter().filter(|f| &*f.rule == "S.codewalk").map(|f| (f.lo, f)).collect::<std::collections::HashMap<_, _>>();
    let w = walked(&g);
    assert!(!w.contains_key(&0x4eba80) && w[&0x4eb480].hi > 0x4eba80); // the walk swallows ahm_LoadDfn
    assert_eq!(dcp(&g, &["--target", "exe", "decl", "add", "0x4eba80 start -- called from 0x4eb4a3 (ahm_LoadPrototypes)"]).0, 0);
    assert_eq!(dcp(&g, &["--target", "exe", "decl", "add", "0x5fbd94 file tu=d3_interface path=D:\\develop\\Units\\d3\\d3_interface.c -- __FILE__"]).0, 0);
    assert_ne!(dcp(&g, &["--target", "exe", "decl", "add", "0x5fbd94 file tu=other path=D:\\wrong.c -- __FILE__"]).0, 0); // duplicate key
    let (code, out) = dcp(&g, &["--target", "exe", "setup", "--no-analyzer"]);
    assert_eq!(code, 0, "{out}");
    let w = walked(&g);
    assert!(w[&0x4eba80].support == DECLARED && w[&0x4eb480].hi <= 0x4eba80 && w[&0x4eb480].support == DERIVED);
    assert!(findings_of(&g, Some("exe"), "L.decl").is_empty());
}
