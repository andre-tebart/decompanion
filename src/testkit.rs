//! The synthetic project of the tests (a dll, archives and a project): the
//! command-line tests (src/cli/tests/) and the integration tests (tests/) build their projects with it.

use std::path::{Path, PathBuf};

/// The VC6 installation of the e2e tests (`DCP_VC6`: the directory holding VC98/), when it is installed there.
pub fn vc6_root() -> Option<String> {
    std::env::var("DCP_VC6").ok().map(|r| r.replace('\\', "/").trim_end_matches('/').to_string())
        .filter(|r| Path::new(r).join("VC98/Bin/CL.EXE").exists())
}

/// The DirectX 6.1 SDK's lib directory of the e2e tests (`DCP_DXSDK6`: the SDK's directory), when it holds dxguid.lib.
pub fn dxsdk6_lib() -> Option<String> {
    std::env::var("DCP_DXSDK6").ok().map(|r| format!("{}/lib", r.replace('\\', "/").trim_end_matches('/')))
        .filter(|l| Path::new(l).join("dxguid.lib").exists())
}

pub const BASE: u32 = 0x1000_0000;
const TEXT: u32 = 0x1000;
const DATA: u32 = 0x2000;
const RELOC: u32 = 0x3000;

/// Rich headers of the two synthetic targets (prodid, build, count).
pub const RICH_TINY: &[(u32, u32, u32)] = &[(0x30, 9044, 3), (0x0a, 8047, 5), (0x04, 8447, 1)];
pub const RICH_OTHER: &[(u32, u32, u32)] = &[(0x30, 9044, 2), (0x0a, 8047, 5), (0x1c, 9178, 1), (0x04, 8447, 2), (0x13, 9049, 1)];

/// A test's directory of its own, empty: `name` and a number below the test run's own directory (the system's
/// temporary directory, then dcp-tests-<pid>); no two calls share one, so tests running in parallel never touch each
/// other's. It goes when the thread that made it ends (libtest runs each test on a thread of its own, so
/// the tests remove theirs in parallel), what is left with the run's directory when the process exits; a run's
/// directory left behind (killed, crashed) goes with the first test directory of a later run, once an hour old.
pub fn scratch(name: &str) -> PathBuf {
    static ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    let root = ROOT.get_or_init(|| {
        let tmp = std::env::temp_dir();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        for e in std::fs::read_dir(&tmp).into_iter().flatten().flatten() {
            let stale = e.file_name().to_string_lossy().strip_prefix("dcp-tests-").is_some_and(|pid| pid.parse::<u32>().is_ok_and(|p| p != std::process::id()))
                && e.metadata().and_then(|m| m.modified()).is_ok_and(|t| t < old);
            if stale {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
        extern "C" fn remove_root() {
            if let Some(r) = ROOT.get() {
                let _ = std::fs::remove_dir_all(r);
            }
        }
        unsafe extern "C" {
            fn atexit(f: extern "C" fn()) -> std::ffi::c_int;
        }
        unsafe { atexit(remove_root) };
        tmp.join(format!("dcp-tests-{}", std::process::id()))
    });
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let d = root.join(format!("{name}-{}", N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    std::fs::create_dir_all(&d).unwrap();
    MADE.with(|m| m.borrow_mut().0.push(d.clone()));
    d
}

/// The test directories this thread made, removed when it ends (its store connections closed first: Windows does
/// not remove an open file).
struct Made(Vec<PathBuf>);

impl Drop for Made {
    fn drop(&mut self) {
        for d in &self.0 {
            crate::forget_conns_under(d);
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

thread_local!(static MADE: std::cell::RefCell<Made> = const { std::cell::RefCell::new(Made(Vec::new())) });

pub fn posix(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

pub fn write(root: &Path, rel: &str, text: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

pub fn rich_header(entries: &[(u32, u32, u32)], key: u32) -> Vec<u8> {
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

/// The synthetic dll: `variant` changes one data byte (another binary of the same codebase);
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
    let h = |v: u16, o: &mut usize, out: &mut Vec<u8>| { put16(out, *o, v); *o += 2; };
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

const CONFIG: &str = r#"[target]
name = "tiny"
path = "{p1}"
compiler = "cl 12.00.9044"
linker = "link 6.00.8447"
cflags = ["/O2"]
archives = []
reason = "test project"

[toolchain]
root = "C:/nowhere/vc6"
reason = "test project"

[analyzer]
root = "C:/nowhere/ghidra"
"#;

/// The synthetic project: tiny.dll as the target `tiny`.
pub fn make_project(d: &Path) -> PathBuf {
    std::fs::create_dir_all(d).unwrap();
    let p1 = build_pe(&d.join("tiny.dll"), 0, Some(RICH_TINY));
    write(d, "decompanion.toml", &CONFIG.replace("{p1}", &posix(&p1)));
    write(d, "decl/text.dcl", "# code\n");
    write(d, "decl/data.dcl", "# data\n");
    d.to_path_buf()
}
