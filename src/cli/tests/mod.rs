//! The command-line tests: whole dcp commands in this process over a synthetic project (the tests/ of the Python
//! frontend, ported). The synthetic dll and its archives are conftest.py's, byte for byte, so the expected values are
//! the ones the Python tests asserted. Tests that need an installation (VC6, libclang, Ghidra, the GOG binaries) are
//! `#[ignore = "e2e: ..."]`: `cargo test -- --ignored` runs them.

mod layout;
mod launch;
mod layout_tools;
mod matching;
mod multitarget;
mod obligations;
mod seams;
mod servers;
mod source_checks;
mod targets;

use crate::pystore;
use crate::store::SFact;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};

pub const BASE: u32 = 0x1000_0000;
const TEXT: u32 = 0x1000;
const DATA: u32 = 0x2000;
const RELOC: u32 = 0x3000;

/// Rich headers of the two synthetic targets (prodid, build, count).
pub const RICH_TINY: &[(u32, u32, u32)] = &[(0x30, 9044, 3), (0x0a, 8047, 5), (0x04, 8447, 1)];
pub const RICH_OTHER: &[(u32, u32, u32)] = &[(0x30, 9044, 2), (0x0a, 8047, 5), (0x1c, 9178, 1), (0x04, 8447, 2), (0x13, 9049, 1)];

static N: AtomicUsize = AtomicUsize::new(0);

/// A fresh empty directory for one test.
pub fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("dcp-cli-{}-{}-{name}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

pub fn posix(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

pub fn write(root: &Path, rel: &str, text: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

pub fn read(root: &Path, rel: &str) -> String {
    std::fs::read_to_string(root.join(rel)).unwrap()
}

/// The config file with `old` replaced by `new` (once; `old` must be there).
pub fn set_config(root: &Path, old: &str, new: &str) {
    let t = read(root, "decompanion.toml");
    assert!(t.contains(old), "{old:?} not in the config");
    write(root, "decompanion.toml", &t.replacen(old, new, 1));
}

/// Key lines appended to the [[target]] table of `name`.
pub fn target_table(root: &Path, name: &str, extra: &str) {
    set_config(root, &format!("name = \"{name}\"\n"), &format!("name = \"{name}\"\n{extra}\n"));
}

fn rich_header(entries: &[(u32, u32, u32)], key: u32) -> Vec<u8> {
    let mut out = vec![];
    for v in [0x536e6144 ^ key, key, key, key] {
        out.extend(v.to_le_bytes());
    }
    for &(p, b, c) in entries {
        out.extend((((p << 16) | b) ^ key).to_le_bytes());
        out.extend((c ^ key).to_le_bytes());
    }
    out.extend(b"Rich");
    out.extend(key.to_le_bytes());
    out
}

/// A COFF archive of one object per (prodid, build): no sections, only the absolute `@comp.id` symbol.
pub fn build_lib(path: &Path, comp_ids: &[(u32, u32)]) -> PathBuf {
    let mut members = vec![];
    for (k, &(prodid, build)) in comp_ids.iter().enumerate() {
        let mut sym = b"@comp.id".to_vec();
        sym.extend(((prodid << 16) | build).to_le_bytes());
        sym.extend((-1i16).to_le_bytes());
        sym.extend(0u16.to_le_bytes());
        sym.extend([3u8, 0]);
        let mut obj = vec![];
        obj.extend(0x14cu16.to_le_bytes());
        obj.extend(0u16.to_le_bytes());
        obj.extend(0u32.to_le_bytes());
        obj.extend(20u32.to_le_bytes());
        obj.extend(1u32.to_le_bytes());
        obj.extend(0u16.to_le_bytes());
        obj.extend(0u16.to_le_bytes());
        obj.extend(sym);
        obj.extend(4u32.to_le_bytes());
        let pad = |s: &str, n: usize| format!("{s:<n$}");
        let hdr = format!("{}{}{}{}{}{}`\n", pad(&format!("o{k}.obj/"), 16), pad("0", 12), pad("0", 6), pad("0", 6), pad("644", 8), pad(&obj.len().to_string(), 10));
        members.extend(hdr.as_bytes());
        let odd = obj.len() & 1 == 1;
        members.extend(obj);
        if odd {
            members.push(b'\n');
        }
    }
    let mut out = b"!<arch>\n".to_vec();
    out.extend(members);
    std::fs::write(path, out).unwrap();
    path.to_path_buf()
}

fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

fn put16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}

/// The synthetic dll (conftest.build_pe): `variant` changes one data byte (another binary of the same codebase);
/// `rich` adds a Rich header with these entries.
pub fn build_pe(path: &Path, variant: u32, rich: Option<&[(u32, u32, u32)]>) -> PathBuf {
    let va = |rva: u32| BASE + rva;
    let (s_path, s_hello, s_world) = (va(DATA + 0x10), va(DATA + 0x30), va(DATA + 0x38));
    let mut code = vec![0x90u8; 0x60];
    let mut relocs = vec![];
    let f1: Vec<u8> = [&[0x55u8, 0x8b, 0xec, 0xe8][..], &(0x20i32 - (0x03 + 5)).to_le_bytes(), &[0xe8], &(0x30i32 - (0x08 + 5)).to_le_bytes(), &[0x5d, 0xc3]].concat();
    code[..f1.len()].copy_from_slice(&f1);
    let f2: Vec<u8> = [&[0xa1u8][..], &va(DATA).to_le_bytes(), &[0xc3]].concat();
    code[0x20..0x20 + f2.len()].copy_from_slice(&f2);
    relocs.push(TEXT + 0x21);
    let f3: Vec<u8> = [&[0x68u8][..], &s_path.to_le_bytes(), &[0x68], &s_hello.to_le_bytes(), &[0x83, 0xc4, 0x08, 0xc3]].concat();
    code[0x30..0x30 + f3.len()].copy_from_slice(&f3);
    relocs.extend([TEXT + 0x31, TEXT + 0x36]);
    let f4: Vec<u8> = [&[0x68u8][..], &s_world.to_le_bytes(), &[0x58, 0xc3]].concat();
    code[0x50..0x50 + f4.len()].copy_from_slice(&f4);
    relocs.push(TEXT + 0x51);
    let mut data = vec![0u8; 0x50];
    put32(&mut data, 0, 0x1234 + variant);
    data[0x10..0x10 + 17].copy_from_slice(b"c:\\src\\net\\net.c\0");
    data[0x30..0x36].copy_from_slice(b"hello\0");
    data[0x38..0x3e].copy_from_slice(b"world\0");
    put32(&mut data, 0x40, va(TEXT + 0x50));
    relocs.push(DATA + 0x40);
    let mut pages: Vec<u32> = relocs.iter().map(|r| r & !0xfff).collect();
    pages.sort();
    pages.dedup();
    let mut blocks = vec![];
    for page in pages {
        let mut ents: Vec<u16> = relocs.iter().filter(|r| *r & !0xfff == page).map(|r| (3 << 12) | (r & 0xfff) as u16).collect();
        if ents.len() % 2 == 1 {
            ents.push(0);
        }
        blocks.extend(page.to_le_bytes());
        blocks.extend((8 + 2 * ents.len() as u32).to_le_bytes());
        for e in ents {
            blocks.extend(e.to_le_bytes());
        }
    }
    let secs: Vec<(&[u8; 8], u32, Vec<u8>, u32)> = vec![(b".text\0\0\0", TEXT, code, 0x6000_0020), (b".data\0\0\0", DATA, data, 0xC000_0040),
                                                         (b".reloc\0\0", RELOC, blocks.clone(), 0x4200_0040)];
    let (falign, hdr) = (0x200usize, 0x400usize);
    let mut raw = vec![];
    let mut off = hdr;
    for (name, rva, body, ch) in &secs {
        let rs = body.len().div_ceil(falign) * falign;
        raw.push((*name, *rva, body.clone(), *ch, off, rs));
        off += rs;
    }
    let mut out = vec![0u8; off];
    out[0..2].copy_from_slice(b"MZ");
    let mut pe = 0x80usize;
    if let Some(r) = rich {
        let r = rich_header(r, 0x1234abcd);
        out[0x80..0x80 + r.len()].copy_from_slice(&r);
        pe = (0x80 + r.len() + 0xf) & !0xf;
    }
    put32(&mut out, 0x3c, pe as u32);
    out[pe..pe + 4].copy_from_slice(b"PE\0\0");
    // file header: machine, sections, time stamp, symbols, characteristics
    put16(&mut out, pe + 4, 0x14c);
    put16(&mut out, pe + 6, secs.len() as u16);
    put32(&mut out, pe + 8, 0x3f7a0000);
    put32(&mut out, pe + 12, 0);
    put32(&mut out, pe + 16, 0);
    put16(&mut out, pe + 20, 0xE0);
    put16(&mut out, pe + 22, 0x2102);
    let opt = pe + 24;
    let size_image = RELOC + 0x1000;
    // "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII"
    let mut o = opt;
    let mut h = |v: u16, o: &mut usize, out: &mut Vec<u8>| { put16(out, *o, v); *o += 2; };
    let b = |v: u8, o: &mut usize, out: &mut Vec<u8>| { out[*o] = v; *o += 1; };
    let i = |v: u32, o: &mut usize, out: &mut Vec<u8>| { put32(out, *o, v); *o += 4; };
    h(0x10b, &mut o, &mut out);
    b(6, &mut o, &mut out);
    b(0, &mut o, &mut out);
    for v in [0x200, 0x200, 0, TEXT, TEXT, DATA, BASE, 0x1000, falign as u32] {
        i(v, &mut o, &mut out);
    }
    for v in [4u16, 0, 0, 0, 4, 0] {
        h(v, &mut o, &mut out);
    }
    for v in [0u32, size_image, hdr as u32, 0] {
        i(v, &mut o, &mut out);
    }
    h(2, &mut o, &mut out);
    h(0, &mut o, &mut out);
    for v in [0x100000u32, 0x1000, 0x100000, 0x1000, 0, 16] {
        i(v, &mut o, &mut out);
    }
    let dd = opt + 96;
    put32(&mut out, dd + 8 * 5, RELOC);
    put32(&mut out, dd + 8 * 5 + 4, blocks.len() as u32);
    let st = opt + 0xE0;
    for (k, (name, rva, body, ch, roff, rs)) in raw.iter().enumerate() {
        let s = st + 40 * k;
        out[s..s + 8].copy_from_slice(&name[..]);
        put32(&mut out, s + 8, body.len() as u32);
        put32(&mut out, s + 12, *rva);
        put32(&mut out, s + 16, *rs as u32);
        put32(&mut out, s + 20, *roff as u32);
        put32(&mut out, s + 36, *ch);
        out[*roff..*roff + body.len()].copy_from_slice(body);
    }
    std::fs::write(path, out).unwrap();
    path.to_path_buf()
}

const CONFIG: &str = r#"[[target]]
name = "{n1}"
path = "{p1}"
image = "pe32"
{second}
[toolchain]
plugin = "vc6"
root = "C:/nowhere/vc6"
compiler = "cl 12.00.9044"
linker = "link 6.00.8447"
cflags = ["/O2"]
reason = "test project"

[libs]
archives = []
reason = "test project: no static library"

[analyzer]
plugin = "none"
"#;

/// The synthetic project (conftest.make_project): tiny.dll as target `tiny` (and tiny2.dll as `other`).
pub fn make_project(d: &Path, two: bool) -> PathBuf {
    std::fs::create_dir_all(d).unwrap();
    let p1 = build_pe(&d.join("tiny.dll"), 0, Some(RICH_TINY));
    let second = if two {
        let p2 = build_pe(&d.join("tiny2.dll"), 1, Some(RICH_OTHER));
        format!("\n[[target]]\nname = \"other\"\npath = \"{}\"\nimage = \"pe32\"\n", posix(&p2))
    } else {
        String::new()
    };
    write(d, "decompanion.toml", &CONFIG.replace("{n1}", "tiny").replace("{p1}", &posix(&p1)).replace("{second}", &second));
    write(d, "decl/text.dcl", "# code\n");
    write(d, "decl/data.dcl", "# data\n");
    d.to_path_buf()
}

pub fn tiny() -> PathBuf {
    make_project(&tmp("proj").join("proj"), false)
}

pub fn tiny2() -> PathBuf {
    make_project(&tmp("proj2").join("proj2"), true)
}

/// Write src/<name>.c from its parts, a blank line between two parts; an empty part is left out.
pub fn unit(root: &Path, name: &str, parts: &[&str]) -> PathBuf {
    let text = parts.iter().filter(|p| !p.is_empty()).map(|p| if p.ends_with('\n') { p.to_string() } else { format!("{p}\n") }).collect::<Vec<_>>().join("\n");
    write(root, &format!("src/{name}.c"), &text);
    root.join("src").join(format!("{name}.c"))
}

/// Run a command line in this process over the project at root: (exit code, stdout, stderr).
pub fn dcp3(root: &Path, args: &[&str]) -> (i32, String, String) {
    let mut argv: Vec<String> = vec!["dcp".into(), "--root".into(), root.to_string_lossy().into_owned()];
    argv.extend(args.iter().map(|a| a.to_string()));
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = crate::cli::run(&argv, &mut out, &mut err);
    (code, String::from_utf8_lossy(&out).into_owned(), String::from_utf8_lossy(&err).into_owned())
}

/// (exit code, stdout).
pub fn dcp(root: &Path, args: &[&str]) -> (i32, String) {
    let (c, o, _) = dcp3(root, args);
    (c, o)
}

/// A command line without --root (init).
pub fn dcp_bare(args: &[&str]) -> (i32, String, String) {
    let mut argv: Vec<String> = vec!["dcp".into()];
    argv.extend(args.iter().map(|a| a.to_string()));
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = crate::cli::run(&argv, &mut out, &mut err);
    (code, String::from_utf8_lossy(&out).into_owned(), String::from_utf8_lossy(&err).into_owned())
}

pub fn project(root: &Path, target: Option<&str>) -> crate::project::Project {
    crate::project::Project::find(Some(&root.to_string_lossy()), target).unwrap()
}

/// The facts of one kind of a target's current runs.
pub fn facts(root: &Path, kind: &str, target: Option<&str>) -> Vec<Rc<SFact>> {
    let p = project(root, target);
    let db = p.store_path();
    pystore::st_open(&db, &p.main_uri()).unwrap();
    pystore::st_facts(&db, Some(kind), None, None, None).unwrap().into_iter().map(|(_, f)| f).collect()
}

/// A conflict: (severity, check, lo, hi, message, a, b).
pub type Conflict = (String, String, i64, i64, String, String, String);

pub fn conflicts(root: &Path, target: Option<&str>) -> Vec<Conflict> {
    let p = project(root, target);
    let db = p.store_path();
    pystore::st_open(&db, &p.main_uri()).unwrap();
    pystore::st_conflicts(&db, None, None).unwrap()
}

pub fn conflicts_of(root: &Path, target: Option<&str>, check: &str) -> Vec<Conflict> {
    conflicts(root, target).into_iter().filter(|c| c.1 == check).collect()
}

/// The rules of a target refreshed as a command refreshes them: whether any ran.
pub fn engine_ran(root: &Path, target: Option<&str>) -> bool {
    let p = project(root, target);
    pystore::st_open(&p.store_path(), &p.main_uri()).unwrap();
    crate::engine::engine_run(&p, "", None, false).unwrap().iter().any(|r| r.ran)
}

/// Switch the project's analyzer to Ghidra: a stand-in installation beside the project whose analyzeHeadless copies
/// the batch_decompile file `export` to where the post-script would write it.
pub fn use_fake_ghidra(root: &Path, export: &Path) {
    let fake = root.parent().unwrap().join(format!("{}-ghidra", root.file_name().unwrap().to_string_lossy()));
    std::fs::create_dir_all(fake.join("support")).unwrap();
    std::fs::create_dir_all(fake.join("jdk").join("bin")).unwrap();
    let bat = format!("@echo off\r\n:loop\r\nif \"%~1\"==\"\" goto :eof\r\nif \"%~1\"==\"-postScript\" (\r\n  copy /y \"{}\" \"%~3\" >nul\r\n  goto :eof\r\n)\r\nshift\r\ngoto loop\r\n",
                      export.to_string_lossy());
    std::fs::write(fake.join("support").join("analyzeHeadless.bat"), bat).unwrap();
    set_config(root, "[analyzer]\nplugin = \"none\"\n",
               &format!("[analyzer]\nplugin = \"ghidra\"\nroot = \"{}\"\njava_home = \"{}\"\n", posix(&fake), posix(&fake.join("jdk"))));
}

/// The sha256 of a file.
pub fn sha256_of(p: &Path) -> String {
    crate::fsmemo::sha256(&p.to_string_lossy()).unwrap()
}

/// The first line of `out` that starts with `prefix`.
pub fn line_with<'a>(out: &'a str, prefix: &str) -> &'a str {
    out.lines().find(|l| l.starts_with(prefix)).unwrap_or_else(|| panic!("no line {prefix:?} in:\n{out}"))
}
