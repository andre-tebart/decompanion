//! VC6 (cl 12.00, link 6.00): the conventions of its compiler and linker the rules rest on, as data, and the evidence
//! the guided decisions ask for (decide.rs; it hands over evidence, it never declares anything).

use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// A Rich header product: prodid, name (Microsoft's internal, as the community reconstructed them), family
/// (compiler / linker / assembler / ...), language.
#[derive(Clone, Debug, PartialEq)]
pub struct RichProduct {
    pub prodid: u32,
    pub name: String,
    pub family: &'static str,
    pub language: &'static str,
}

/// One installation of a toolchain: its root (posix), the versions of its tools in their order, the compiler and
/// linker builds it makes (what a Rich entry and a declaration name; None when unknown), whether it can run.
#[derive(Clone, Debug, PartialEq)]
pub struct Install {
    pub root: String,
    pub versions: Vec<(&'static str, String)>,
    pub compiler_build: Option<u32>,
    pub linker_build: Option<u32>,
    pub ok: bool,
}


// ------------------------------------------------------------------------------------------------ VC6

const PRODUCTS: &[(u32, &str, &str, &str)] = &[
    (0x00, "Unknown", "unknown", ""),
    (0x01, "Import0", "import", ""),
    (0x02, "Linker510", "linker", ""),
    (0x03, "Cvtomf510", "cvtomf", ""),
    (0x04, "Linker600", "linker", ""),
    (0x05, "Cvtomf600", "cvtomf", ""),
    (0x06, "Cvtres500", "cvtres", ""),
    (0x07, "Utc11_Basic", "compiler", "Basic"),
    (0x08, "Utc11_C", "compiler", "C"),
    (0x09, "Utc12_Basic", "compiler", "Basic"),
    (0x0a, "Utc12_C", "compiler", "C"),
    (0x0b, "Utc12_CPP", "compiler", "C++"),
    (0x0c, "AliasObj60", "alias", ""),
    (0x0d, "VisualBasic60", "compiler", "Basic"),
    (0x0e, "Masm613", "assembler", ""),
    (0x0f, "Masm710", "assembler", ""),
    (0x10, "Linker511", "linker", ""),
    (0x11, "Cvtomf511", "cvtomf", ""),
    (0x12, "Masm614", "assembler", ""),
    (0x13, "Linker512", "linker", ""),
    (0x14, "Cvtomf512", "cvtomf", ""),
    (0x15, "Utc12_C_Std", "compiler", "C"),
    (0x16, "Utc12_CPP_Std", "compiler", "C++"),
    (0x17, "Utc12_C_Book", "compiler", "C"),
    (0x18, "Utc12_CPP_Book", "compiler", "C++"),
    (0x19, "Implib700", "implib", ""),
    (0x1a, "Cvtomf700", "cvtomf", ""),
    (0x1b, "Utc13_Basic", "compiler", "Basic"),
    (0x1c, "Utc13_C", "compiler", "C"),
    (0x1d, "Utc13_CPP", "compiler", "C++"),
    (0x1e, "Linker610", "linker", ""),
    (0x1f, "Cvtomf610", "cvtomf", ""),
    (0x20, "Linker601", "linker", ""),
    (0x21, "Cvtomf601", "cvtomf", ""),
    (0x22, "Utc12_1_Basic", "compiler", "Basic"),
    (0x23, "Utc12_1_C", "compiler", "C"),
    (0x24, "Utc12_1_CPP", "compiler", "C++"),
    (0x25, "Linker620", "linker", ""),
    (0x26, "Cvtomf620", "cvtomf", ""),
    (0x27, "AliasObj70", "alias", ""),
    (0x28, "Linker621", "linker", ""),
    (0x29, "Cvtomf621", "cvtomf", ""),
    (0x2a, "Masm615", "assembler", ""),
    (0x2b, "Utc13_LTCG_C", "compiler", "C"),
    (0x2c, "Utc13_LTCG_CPP", "compiler", "C++"),
    (0x2d, "Masm620", "assembler", ""),
    (0x2e, "ILAsm100", "assembler", ""),
    (0x2f, "Utc12_2_Basic", "compiler", "Basic"),
    (0x30, "Utc12_2_C", "compiler", "C"),
    (0x31, "Utc12_2_CPP", "compiler", "C++"),
    (0x32, "Utc12_2_C_Std", "compiler", "C"),
    (0x33, "Utc12_2_CPP_Std", "compiler", "C++"),
    (0x34, "Utc12_2_C_Book", "compiler", "C"),
    (0x35, "Utc12_2_CPP_Book", "compiler", "C++"),
    (0x36, "Implib622", "implib", ""),
    (0x37, "Cvtomf622", "cvtomf", ""),
    (0x38, "Cvtres501", "cvtres", ""),
    (0x39, "Utc13_C_Std", "compiler", "C"),
    (0x3a, "Utc13_CPP_Std", "compiler", "C++"),
    (0x3b, "Cvtpgd1300", "cvtpgd", ""),
    (0x3c, "Linker622", "linker", ""),
    (0x3d, "Linker700", "linker", ""),
    (0x3e, "Export622", "export", ""),
    (0x3f, "Export700", "export", ""),
    (0x40, "Masm700", "assembler", ""),
    (0x41, "Utc13_POGO_I_C", "compiler", "C"),
    (0x42, "Utc13_POGO_I_CPP", "compiler", "C++"),
    (0x43, "Utc13_POGO_O_C", "compiler", "C"),
    (0x44, "Utc13_POGO_O_CPP", "compiler", "C++"),
    (0x45, "Cvtres700", "cvtres", ""),
    (0x46, "Cvtres710p", "cvtres", ""),
    (0x47, "Linker710p", "linker", ""),
    (0x48, "Cvtomf710p", "cvtomf", ""),
    (0x49, "Export710p", "export", ""),
    (0x4a, "Implib710p", "implib", ""),
    (0x4b, "Masm710p", "assembler", ""),
    (0x4c, "Utc1310p_C", "compiler", "C"),
    (0x4d, "Utc1310p_CPP", "compiler", "C++"),
    (0x4e, "Utc1310p_C_Std", "compiler", "C"),
    (0x4f, "Utc1310p_CPP_Std", "compiler", "C++"),
    (0x50, "Utc1310p_LTCG_C", "compiler", "C"),
    (0x51, "Utc1310p_LTCG_CPP", "compiler", "C++"),
    (0x52, "Utc1310p_POGO_I_C", "compiler", "C"),
    (0x53, "Utc1310p_POGO_I_CPP", "compiler", "C++"),
    (0x54, "Utc1310p_POGO_O_C", "compiler", "C"),
    (0x55, "Utc1310p_POGO_O_CPP", "compiler", "C++"),
    (0x56, "Linker624", "linker", ""),
    (0x57, "Cvtomf624", "cvtomf", ""),
    (0x58, "Export624", "export", ""),
    (0x59, "Implib624", "implib", ""),
    (0x5a, "Linker710", "linker", ""),
    (0x5b, "Cvtomf710", "cvtomf", ""),
    (0x5c, "Export710", "export", ""),
    (0x5d, "Implib710", "implib", ""),
    (0x5e, "Cvtres710", "cvtres", ""),
    (0x5f, "Utc1310_C", "compiler", "C"),
    (0x60, "Utc1310_CPP", "compiler", "C++"),
    (0x61, "Utc1310_C_Std", "compiler", "C"),
    (0x62, "Utc1310_CPP_Std", "compiler", "C++"),
    (0x63, "Utc1310_LTCG_C", "compiler", "C"),
    (0x64, "Utc1310_LTCG_CPP", "compiler", "C++"),
    (0x65, "Utc1310_POGO_I_C", "compiler", "C"),
    (0x66, "Utc1310_POGO_I_CPP", "compiler", "C++"),
    (0x67, "Utc1310_POGO_O_C", "compiler", "C"),
    (0x68, "Utc1310_POGO_O_CPP", "compiler", "C++"),
    (0x69, "AliasObj710", "alias", ""),
    (0x6a, "AliasObj710p", "alias", ""),
    (0x6b, "Cvtpgd1310", "cvtpgd", ""),
    (0x6c, "Cvtpgd1310p", "cvtpgd", ""),
];

/// Known builds of the VC6 back end (a Rich Utc12* entry's build) and linker, with their names.
const COMPILER_BUILDS: &[(u32, &str)] = &[
    (8047, "VC6 pre-release build used for the shipped CRT / SDK libraries"),
    (8168, "VC6 RTM (cl 12.00.8168)"),
    (8447, "VC6 RTM linker (link 6.00.8447)"),
    (8804, "VC6 SP3 (cl 12.00.8804)"),
    (8964, "VC6 SP4 (cl 12.00.8964)"),
    (9044, "VC6 SP5 and SP5 + Processor Pack (cl 12.00.9044, C2 13.00.9044)"),
    (9782, "VC6 SP6 (cl 12.00.9782)"),
];

/// nop, int3, mov edi,edi, lea ecx,[ecx+0]: the fill VC6 / LINK leave between functions.
const FILL_FORMS: &[&[u8]] = &[b"\x90", b"\xcc", b"\x8b\xff", b"\x8d\x49\x00"];
const INT3: u8 = 0xcc;
const STUB_OPCODE: &[u8] = b"\xff\x25"; // LINK's import stub: jmp dword ptr [slot]
const STUB_SIZE: u32 = 6;
/// The CRT start-up symbols, what they start, the decorated user entry each calls and its C name.
const ENTRIES: &[(&str, &str, &str, &str)] = &[
    ("__DllMainCRTStartup@12", "dll", "_DllMain@12", "DllMain"),
    ("_DllMainCRTStartup@12", "dll", "_DllMain@12", "DllMain"),
    ("_WinMainCRTStartup", "gui", "_WinMain@16", "WinMain"),
    ("_mainCRTStartup", "console", "_main", "main"),
    ("_wWinMainCRTStartup", "gui", "_wWinMain@16", "wWinMain"),
    ("_wmainCRTStartup", "console", "_wmain", "wmain"),
];
const LIB_DIR: [&str; 2] = ["VC98", "Lib"];
/// The release flags of a VC6 project wizard (/O2: maximise speed; /Gy: function-level linking): evidence for the
/// cflags obligation until `dcp toolchain probe` distinguishes them; never written by the tool.
const WIZARD_CFLAGS: &[&str] = &["/O2", "/Gy"];
/// The tools whose versions an installation reports (version resources, VS_FIXEDFILEINFO; the files are read, never
/// run): CL.EXE is only the driver; the build a Rich compiler entry records is the back end's (C2.DLL: SP5 +
/// Processor Pack 13.00.9044, SP6 12.00.9782), the linker entry LINK.EXE's.
const TOOL_FILES: [(&str, &str); 4] = [("cl", "VC98/Bin/CL.EXE"), ("c1", "VC98/Bin/C1.DLL"), ("c2", "VC98/Bin/C2.DLL"), ("link", "VC98/Bin/LINK.EXE")];
const FIXED_FILE_INFO: &[u8] = b"\xbd\x04\xef\xfe"; // VS_FIXEDFILEINFO.dwSignature

/// major.minor(2 digits).build of a PE file's version resource, None when it has none.
pub fn file_version(path: &Path) -> Option<String> {
    let b = std::fs::read(path).ok()?;
    let i = memchr::memmem::find(&b, FIXED_FILE_INFO)?;
    if i + 16 > b.len() {
        return None;
    }
    let u = |o: usize| b.get(o..o + 4).map(|x| u32::from_le_bytes(x.try_into().unwrap()));
    let (ms, ls) = (u(i + 8)?, u(i + 12)?);
    Some(format!("{}.{:02}.{}", ms >> 16, ms & 0xffff, ls >> 16))
}

/// Every root of the places VC6 lives that holds VC98/Bin/CL.EXE, in the order of the places, once each:
/// $VC6_ROOT; C:/Tools/* (a common place for unpacked toolchains); <Program Files>/Microsoft Visual Studio and
/// <Program Files (x86)>/Microsoft Visual Studio (the installer's default).
fn vc6_roots() -> Vec<String> {
    let posix = |s: &str| s.replace('\\', "/");
    let mut roots: Vec<String> = vec![];
    if let Some(r) = std::env::var("VC6_ROOT").ok().filter(|v| !v.is_empty()) {
        roots.push(posix(&r));
    }
    if let Ok(rd) = std::fs::read_dir("C:/Tools") {
        let mut subs: Vec<String> = rd.flatten().filter(|e| e.path().is_dir()).map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        subs.sort_by_key(|s| s.to_lowercase());
        roots.extend(subs.into_iter().map(|s| format!("C:/Tools/{s}")));
    }
    for (var, default) in [("ProgramFiles", "C:/Program Files"), ("ProgramFiles(x86)", "C:/Program Files (x86)")] {
        let base = std::env::var(var).unwrap_or_else(|_| default.to_string());
        roots.push(format!("{}/Microsoft Visual Studio", posix(base.trim_end_matches(['/', '\\']))));
    }
    let mut out = vec![];
    let mut seen = std::collections::HashSet::new();
    for r in roots {
        let key = std::fs::canonicalize(&r).map(|c| c.to_string_lossy().into_owned()).unwrap_or_else(|_| r.clone()).to_lowercase();
        if !Path::new(&r).join("VC98").join("Bin").join("CL.EXE").is_file() || !seen.insert(key) {
            continue;
        }
        out.push(r);
    }
    out
}
/// Strings of VC6's C run time: evidence that an image links the static CRT.
const CRT_STRINGS: &[&str] = &["Microsoft Visual C++ Runtime Library", "__MSVCRT_HEAP_SELECT", "runtime error "];

/// The major.minor a tool reports, from its Rich product name: Utc12_2_C -> 12.00, Utc1310_C -> 13.10,
/// Linker600 -> 6.00; "" for others.
pub fn tool_version(name: &str) -> String {
    let digits = |s: &str, n: usize| s.len() >= n && s.as_bytes()[..n].iter().all(u8::is_ascii_digit);
    if let Some(r) = name.strip_prefix("Utc") {
        if digits(r, 4) {
            return format!("{}.{}", &r[..2], &r[2..4]);
        }
        if digits(r, 2) {
            return format!("{}.00", &r[..2]);
        }
    }
    if let Some(r) = name.strip_prefix("Linker") {
        if digits(r, 3) {
            return format!("{}.{}", &r[..1], &r[1..3]);
        }
    }
    String::new()
}

pub struct Vc6;

impl Vc6 {
    /// The decoded Rich header (Vc6::rich_candidates): every entry with its tool, family, language, build,
    /// count and archive objects; the compiler and the linker candidates by count, build, prodid.
    pub fn rich_candidates(&self, entries: &[(u32, u32, u32)], tools: &std::collections::BTreeMap<(u32, u32), u32>) -> Value {
        let decoded: Vec<Value> = entries
            .iter()
            .map(|&(prodid, build, count)| {
                let p = self.rich_product(prodid);
                json!({"prodid": prodid, "tool": p.name, "family": p.family, "language": p.language, "build": build, "count": count,
                       "archive_objects": tools.get(&(prodid, build)).copied().unwrap_or(0)})
            })
            .collect();
        let mut order = decoded.clone();
        order.sort_by_key(|e| (-(e["count"].as_i64().unwrap_or(0)), -(e["build"].as_i64().unwrap_or(0)), e["prodid"].as_i64().unwrap_or(0)));
        let of = |fam: &str| order.iter().filter(|e| e["family"] == fam).cloned().collect::<Vec<_>>();
        json!({"entries": decoded, "compilers": of("compiler"), "linkers": of("linker")})
    }

    pub fn installs(&self) -> Vec<Install> {
        vc6_roots().iter().map(|r| self.install(r)).collect()
    }
    /// The versions of CL.EXE, C1.DLL, C2.DLL and LINK.EXE; the compiler build is C2's, the linker build LINK's.
    pub fn install(&self, root: &str) -> Install {
        let versions: Vec<(&'static str, String)> = TOOL_FILES.iter()
            .filter_map(|(k, rel)| file_version(&Path::new(root).join(rel)).map(|v| (*k, v))).collect();
        let build = |k: &str| versions.iter().find(|(x, _)| *x == k).and_then(|(_, v)| v.rsplit_once('.')).and_then(|(_, b)| b.parse().ok());
        Install { root: root.replace('\\', "/"), compiler_build: build("c2"), linker_build: build("link"), ok: versions.iter().any(|(k, _)| *k == "cl"),
                  versions }
    }
    /// LIBCMT or LIBCMT.LIB -> {toolchain.root}/VC98/Lib/LIBCMT.LIB; a name with a slash is a path.
    pub fn archive_spec(&self, name: &str) -> String {
        if name.contains('/') || name.contains('\\') {
            return name.replace('\\', "/");
        }
        let n = name.to_uppercase();
        let n = if n.ends_with(".LIB") { n } else { format!("{n}.LIB") };
        format!("{{toolchain.root}}/{}/{}/{n}", LIB_DIR[0], LIB_DIR[1])
    }
    pub fn wizard_cflags(&self) -> &'static [&'static str] {
        WIZARD_CFLAGS
    }
    pub fn keywords(&self) -> &'static [&'static str] {
        &["__cdecl", "__stdcall", "__fastcall", "__thiscall", "__int64", "__declspec", "__asm"]
    }
    /// `_f@12`, `@f@8`: the name needs the parameters.
    pub fn sized_conventions(&self) -> &'static [&'static str] {
        &["__stdcall", "__fastcall", "__thiscall"]
    }
    /// The Win32 API of every system DLL is declared through <windows.h> (it includes winsock.h and mmsystem.h unless
    /// WIN32_LEAN_AND_MEAN).
    pub fn import_header(&self, _dll: &str) -> Option<&'static str> {
        Some("windows.h")
    }
    pub fn standard_headers(&self) -> &'static [&'static str] {
        &["assert.h", "ctype.h", "errno.h", "float.h", "limits.h", "locale.h", "math.h", "setjmp.h", "signal.h", "stdarg.h", "stddef.h", "stdio.h",
          "stdlib.h", "string.h", "time.h"]
    }
    pub fn fill_forms(&self) -> &'static [&'static [u8]] {
        FILL_FORMS
    }
    pub fn function_alignment(&self) -> u32 {
        16
    }
    pub fn import_stub_size(&self) -> u32 {
        STUB_SIZE
    }
    /// cc (int3 only: LINK's padding between contributions), nop (no int3: CL's alignment), mixed.
    pub fn fill_origin(&self, run: &[u8]) -> &'static str {
        if !run.is_empty() && run.iter().all(|&c| c == INT3) {
            "cc"
        } else if !run.contains(&INT3) {
            "nop"
        } else {
            "mixed"
        }
    }
    pub fn import_stubs(&self, data: &[u8]) -> Vec<(usize, u32)> {
        memchr::memmem::find_iter(data, STUB_OPCODE)
            .filter(|&p| p + STUB_SIZE as usize <= data.len())
            .map(|p| (p, u32::from_le_bytes([data[p + 2], data[p + 3], data[p + 4], data[p + 5]])))
            .collect()
    }
    pub fn rich_product(&self, prodid: u32) -> RichProduct {
        match PRODUCTS.iter().find(|p| p.0 == prodid) {
            Some(&(p, n, f, l)) => RichProduct { prodid: p, name: n.to_string(), family: f, language: l },
            None => RichProduct { prodid, name: format!("prodid_{prodid:#x}"), family: "unknown", language: "" },
        }
    }
    pub fn build_name(&self, _family: &str, build: u32) -> &'static str {
        COMPILER_BUILDS.iter().find(|b| b.0 == build).map(|b| b.1).unwrap_or("")
    }
    pub fn declare(&self, tool: &str, family: &str, build: u32) -> String {
        let t = match family {
            "compiler" => "cl",
            "linker" => "link",
            _ => tool,
        };
        let v = tool_version(tool);
        if v.is_empty() { format!("{t} {build}") } else { format!("{t} {v}.{build}") }
    }
    /// `@comp.id` holds prodid << 16 | build.
    pub fn archive_tools(&self, stamps: &std::collections::BTreeMap<u32, u32>) -> std::collections::BTreeMap<(u32, u32), u32> {
        let mut out = std::collections::BTreeMap::new();
        for (&v, &n) in stamps {
            *out.entry((v >> 16, v & 0xffff)).or_insert(0) += n;
        }
        out
    }
    #[cfg(test)]
    pub fn crt_user_entry(&self, entry: &str) -> &'static str {
        ENTRIES.iter().find(|e| e.0 == entry).map(|e| e.2).unwrap_or("")
    }
    pub fn user_entry_names(&self) -> Vec<(&'static str, &'static str)> {
        let mut out: Vec<(&str, &str)> = vec![];
        for e in ENTRIES {
            if !out.iter().any(|x| x.0 == e.2) {
                out.push((e.2, e.3));
            }
        }
        out
    }
    pub fn library_archives(&self, root: &Path) -> Vec<PathBuf> {
        let dir = root.join(LIB_DIR[0]).join(LIB_DIR[1]);
        let mut out: Vec<PathBuf> = std::fs::read_dir(&dir)
            .map(|rd| rd.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.extension().is_some_and(|x| x == "LIB")).collect())
            .unwrap_or_default();
        out.sort();
        out
    }
    /// KERNEL32.dll -> kernel32.lib
    pub fn import_library_name(&self, dll: &str) -> String {
        let l = dll.to_lowercase();
        format!("{}.lib", l.rsplit_once('.').map(|x| x.0).unwrap_or(&l))
    }
    pub fn crt_strings(&self, img: &crate::pe::Image) -> Vec<(u32, &'static str)> {
        let mut out = vec![];
        for s in &img.sections {
            let raw = img.section_data(s);
            for needle in CRT_STRINGS {
                out.extend(memchr::memmem::find_iter(raw, needle.as_bytes()).map(|p| (s.va + p as u32, *needle)));
            }
        }
        out.sort();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rich_and_versions() {
        let t = Vc6;
        assert_eq!((tool_version("Utc12_2_C"), tool_version("Utc1310_C"), tool_version("Linker600"), tool_version("Linker512"), tool_version("Masm613")),
                   ("12.00".into(), "13.10".into(), "6.00".into(), "5.12".into(), String::new()));
        assert_eq!(t.rich_product(0x30).name, "Utc12_2_C");
        assert_eq!(t.rich_product(0x99).name, "prodid_0x99");
        assert_eq!(t.declare("Utc12_2_C", "compiler", 9044), "cl 12.00.9044");
        assert_eq!(t.declare("Linker600", "linker", 8447), "link 6.00.8447");
        let tools = t.archive_tools(&[((0x0a << 16) | 8047, 3), ((0x30 << 16) | 8168, 1)].into_iter().collect());
        let r = t.rich_candidates(&[(0x30, 9044, 3), (0x0a, 8047, 5), (0x04, 8447, 1)], &tools);
        assert_eq!(r["entries"][1]["archive_objects"], 3);
        let comp: Vec<&str> = r["compilers"].as_array().unwrap().iter().map(|e| e["tool"].as_str().unwrap()).collect();
        assert_eq!(comp, ["Utc12_C", "Utc12_2_C"]); // by count first
        assert_eq!(r["linkers"][0]["tool"], "Linker600");
        assert_eq!(t.build_name("compiler", 9044), "VC6 SP5 and SP5 + Processor Pack (cl 12.00.9044, C2 13.00.9044)");
    }

    #[test]
    fn evidence() {
        let t = Vc6;
        assert_eq!(t.wizard_cflags(), ["/O2", "/Gy"]);
        assert_eq!(t.archive_spec("libcmt"), "{toolchain.root}/VC98/Lib/LIBCMT.LIB");
        assert_eq!(t.archive_spec("LIBC.LIB"), "{toolchain.root}/VC98/Lib/LIBC.LIB");
        assert_eq!(t.archive_spec("C:\\x\\my.lib"), "C:/x/my.lib");
        let d = crate::testkit::scratch("tc");
        std::fs::create_dir_all(d.join("VC98/Bin")).unwrap();
        let mut res = vec![0u8; 8];
        res.extend(FIXED_FILE_INFO);
        res.extend(0u32.to_le_bytes());
        res.extend(((13u32 << 16) | 0).to_le_bytes());
        res.extend(((9044u32 << 16) | 1).to_le_bytes());
        std::fs::write(d.join("VC98/Bin/C2.DLL"), &res).unwrap();
        std::fs::write(d.join("VC98/Bin/CL.EXE"), b"no resource").unwrap();
        let i = t.install(&d.to_string_lossy());
        assert_eq!((i.versions.clone(), i.compiler_build, i.linker_build, i.ok), (vec![("c2", "13.00.9044".to_string())], Some(9044), None, false));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn conventions() {
        let t = Vc6;
        assert_eq!((t.fill_origin(b"\xcc\xcc"), t.fill_origin(b"\x90\x8b\xff"), t.fill_origin(b"\x90\xcc")), ("cc", "nop", "mixed"));
        assert_eq!(t.import_stubs(b"\x90\xff\x25\x00\x10\x00\x10\xff\x25\x01"), vec![(1, 0x1000_1000)]);
        assert_eq!(t.import_library_name("KERNEL32.dll"), "kernel32.lib");
        assert_eq!(t.crt_user_entry("_WinMainCRTStartup"), "_WinMain@16");
        assert_eq!(t.user_entry_names().len(), 5);
        assert_eq!(t.crt_user_entry("__DllMainCRTStartup@12"), "_DllMain@12");
        assert_eq!(t.crt_user_entry("_wWinMainCRTStartup"), "_wWinMain@16");
        let names: std::collections::BTreeMap<&str, &str> = t.user_entry_names().into_iter().collect();
        assert_eq!(names, [("_DllMain@12", "DllMain"), ("_WinMain@16", "WinMain"), ("_main", "main"), ("_wWinMain@16", "wWinMain"), ("_wmain", "wmain")]
            .into_iter().collect());
        // a truncated stub at the end is no stub
        assert_eq!(t.import_stubs(b"\xcc\xff\x25\x00\x20\x00\x10\xff\x25\x04\x20\x00\x10\xff\x25\x00"), vec![(1, 0x1000_2000), (7, 0x1000_2004)]);
        assert_eq!((t.import_stub_size(), t.function_alignment()), (6, 16));
    }
}
