//! Crash capture for `dcp run --debug` (docs/run.md "Crashes"): the program runs under a minimal Win32 debugger in
//! the process the user typed `dcp` in (the debug loop must run on the thread that created the process); a crash
//! writes build/crash/<run>-<stamp>/ with crash.txt, crash.dmp and the launch spec, and build/crash/LATEST.txt.
//!
//! First-chance exceptions go back to the program (it may handle them); a fatal-looking one (>= 0xC0000000) is kept
//! in case the process then exits on an NTSTATUS without a second chance. A second chance is the crash.
//!
//! Addresses are named from the symbol table run.rs writes at prepare time (build/run/<run>.symbols.tsv): the link
//! map's publics and statics joined with the unit (by the object's content hash), the definition's line and the
//! original's address of every function, so the client process never opens the project.

use crate::error::{Error, Result};
use std::collections::HashMap;
use std::path::Path;

// ------------------------------------------------------------------------------------------------ the symbol table

#[derive(Clone, Debug, PartialEq)]
pub struct Sym {
    pub va: u32,
    pub size: u32,
    pub code: bool,
    pub entry: bool,  // holds the program's entry point: no caller of the program's own lies beyond its frame
    pub name: String, // the C name (no leading `_`, no `@N`)
    pub unit: String,
    pub line: i64,
    pub original: Option<u32>,
}

/// The rows of a VC6 link map's "Publics by Value" / "Static symbols": (va, section, decorated name, object); and
/// the entry point's va (`entry point at 0001:<offset>`, placed by a row of its section).
pub fn map_rows(text: &str) -> (Vec<(u32, u32, String, String)>, Option<u32>) {
    let (mut out, mut entry, mut bases) = (vec![], None, HashMap::new());
    let sec_off = |s: &str| -> Option<(u32, u32)> {
        (s.len() == 13 && s.as_bytes()[4] == b':').then_some(())?;
        Some((u32::from_str_radix(&s[..4], 16).ok()?, u32::from_str_radix(&s[5..], 16).ok()?))
    };
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if line.trim_start().starts_with("entry point at") {
            entry = f.last().and_then(|s| sec_off(s));
            continue;
        }
        // ` 0001:00000040       _util_BaseName             00401040 f   <hash>.obj`
        if f.len() < 4 || f[2].len() != 8 {
            continue;
        }
        let (Some((sec, off)), Ok(va)) = (sec_off(f[0]), u32::from_str_radix(f[2], 16)) else { continue };
        bases.entry(sec).or_insert(va.wrapping_sub(off));
        let obj = f.last().map(|s| s.to_string()).unwrap_or_default();
        out.push((va, sec, f[1].to_string(), obj));
    }
    (out, entry.and_then(|(sec, off)| bases.get(&sec).map(|b: &u32| b.wrapping_add(off))))
}

/// A decorated C name as the source spells it: `_name` -> name, `_name@8` -> name; others as they are.
pub fn c_name(n: &str) -> String {
    let n = n.strip_prefix('_').filter(|_| !n.starts_with("__")).unwrap_or(n);
    match n.rfind('@') {
        Some(k) if k > 0 && n[k + 1..].bytes().all(|b| b.is_ascii_digit()) && !n.starts_with('?') => n[..k].to_string(),
        _ => n.to_string(),
    }
}

/// The symbol table of a link map: each row sized to the next row of its section, the code section's rows marked;
/// `unit_of(object file name)` and `source(unit, name)` -> (line, original address) join the decompilation.
pub fn symbols(map: &str, unit_of: impl Fn(&str) -> Option<String>, source: impl Fn(&str, &str) -> Option<(i64, Option<u32>)>) -> Vec<Sym> {
    let (mut rows, entry) = map_rows(map);
    rows.sort_by_key(|r| (r.0, r.1));
    rows.dedup_by_key(|r| r.0);
    let mut out: Vec<Sym> = vec![];
    for (k, (va, sec, name, obj)) in rows.iter().enumerate() {
        let next = rows[k + 1..].iter().find(|r| r.1 == *sec).map(|r| r.0);
        let unit = unit_of(obj).unwrap_or_default();
        let name = c_name(name);
        let (line, original) = if unit.is_empty() { (0, None) } else { source(&unit, &name).unwrap_or((0, None)) };
        let size = next.map(|n| n - va).unwrap_or(0);
        let entry = *sec == 1 && entry.is_some_and(|e| *va <= e && (size == 0 || e < va + size));
        out.push(Sym { va: *va, size, code: *sec == 1, entry, name, unit, line, original });
    }
    out
}

pub fn write_symbols(path: &str, key: &str, syms: &[Sym]) -> Result<(), String> {
    let mut s = format!("# map {key}\n");
    for y in syms {
        let kind = if y.entry { "entry" } else if y.code { "code" } else { "data" };
        s += &format!("{:08x}\t{:x}\t{kind}\t{}\t{}\t{}\t{}\n", y.va, y.size, y.name, y.unit, y.line, y.original.map(|o| format!("{o:08x}")).unwrap_or_default());
    }
    std::fs::write(path, s).map_err(|e| format!("{path}: {e}"))
}

/// The key of a written symbol table ('' when there is none).
pub fn symbols_key(path: &str) -> String {
    std::fs::read_to_string(path).ok().and_then(|t| t.lines().next().and_then(|l| l.strip_prefix("# map ")).map(|s| s.to_string())).unwrap_or_default()
}

#[derive(Default)]
pub struct Symbols {
    rows: Vec<Sym>,
}

impl Symbols {
    pub fn new(mut rows: Vec<Sym>) -> Symbols {
        rows.sort_by_key(|r| r.va);
        Symbols { rows }
    }

    pub fn load(path: &str) -> Symbols {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let rows = text.lines().filter(|l| !l.starts_with('#')).filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            if f.len() != 7 {
                return None;
            }
            Some(Sym {
                va: u32::from_str_radix(f[0], 16).ok()?, size: u32::from_str_radix(f[1], 16).ok()?, code: f[2] != "data", entry: f[2] == "entry",
                name: f[3].into(), unit: f[4].into(),
                line: f[5].parse().unwrap_or(0), original: u32::from_str_radix(f[6], 16).ok(),
            })
        }).collect();
        Symbols::new(rows)
    }

    /// The symbol `va` lies in (its size, or 0x2000 past an unsized last one); `code_only`: .text only.
    pub fn at(&self, va: u32, code_only: bool) -> Option<(&Sym, u32)> {
        let k = self.rows.partition_point(|r| r.va <= va);
        let s = self.rows.get(k.checked_sub(1)?)?;
        let off = va - s.va;
        let limit = if s.size > 0 { s.size } else { 0x2000 };
        (off < limit && (!code_only || s.code)).then_some((s, off))
    }

    /// The code section's range (first code symbol .. end of the last).
    pub fn code_range(&self) -> Option<(u32, u32)> {
        let c: Vec<&Sym> = self.rows.iter().filter(|r| r.code).collect();
        Some((c.first()?.va, c.last().map(|l| l.va + l.size.max(1))?))
    }
}

fn plus(name: &str, off: u32) -> String {
    if off == 0 { name.to_string() } else { format!("{name}+0x{off:x}") }
}

/// `name+0xNN  unit=U  src/U.c:L  original=0x...+0xNN` for a symbol of the exe.
pub fn describe(s: &Sym, off: u32) -> String {
    let mut t = plus(&s.name, off);
    if !s.unit.is_empty() {
        t += &format!("   unit={}", s.unit);
        if s.line > 0 {
            t += &format!("  src/{}.c:{}", s.unit, s.line);
        }
    }
    if let Some(o) = s.original {
        t += &format!("  original={}", plus(&format!("0x{o:08x}"), off));
    }
    t
}

// ------------------------------------------------------------------------------------------------ what a crash holds

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Regs {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub esi: u32,
    pub edi: u32,
    pub ebp: u32,
    pub esp: u32,
    pub eip: u32,
    pub eflags: u32,
}

impl Regs {
    pub fn get(&self, r: &str) -> Option<u32> {
        Some(match r {
            "eax" => self.eax, "ebx" => self.ebx, "ecx" => self.ecx, "edx" => self.edx, "esi" => self.esi, "edi" => self.edi,
            "ebp" => self.ebp, "esp" => self.esp, "eip" => self.eip,
            _ => return None,
        })
    }
}

/// Everything read out of the process at the exception.
#[derive(Clone, Debug, Default)]
pub struct Capture {
    pub code: u32,
    pub address: u32,
    pub first: bool,
    pub tid: u32,
    pub params: Vec<u32>,
    pub regs: Option<Regs>,
    pub code_bytes: Vec<u8>,   // at the faulting address
    pub stack: Vec<u8>,        // from esp
    pub below: HashMap<u32, [u8; 6]>, // the 6 bytes below each stack word inside the code range
    pub ebp_chain: Vec<u32>,
    pub modules: Vec<(u32, u32, String)>,
}

pub fn exception_name(code: u32) -> &'static str {
    match code {
        0xC0000005 => "access violation",
        0xC00000FD => "stack overflow",
        0xC0000094 => "integer divide by zero",
        0xC0000095 => "integer overflow",
        0xC000001D => "illegal instruction",
        0xC0000096 => "privileged instruction",
        0xC0000006 => "in-page error",
        0xC000008C => "array bounds exceeded",
        0xC000008E => "float divide by zero",
        0xC0000090 => "float invalid operation",
        0xC0000091 => "float overflow",
        0xC0000409 => "stack buffer overrun / fail fast",
        0xC0000374 => "heap corruption",
        0xE06D7363 => "C++ exception",
        0x80000003 => "breakpoint",
        _ => "exception",
    }
}

/// (kind, callee) when the 6 bytes just below a return address end in a call that ends exactly at it: `E8 rel32`
/// (direct), `FF 15 abs32` (import), `FF /2` through memory or a register (indirect).
pub fn call_below(b: &[u8; 6], ret: u32) -> Option<(&'static str, Option<u32>)> {
    if b[1] == 0xE8 {
        let rel = i32::from_le_bytes([b[2], b[3], b[4], b[5]]);
        return Some(("direct", Some(ret.wrapping_add(rel as u32))));
    }
    let is_call = |op: u8, modrm: u8| op == 0xFF && (modrm >> 3) & 7 == 2;
    if is_call(b[0], b[1]) && b[1] & 0xC0 == 0 && b[1] & 7 == 5 {
        return Some(("import", None)); // FF 15 disp32
    }
    if is_call(b[3], b[4]) && b[4] & 0xC0 == 0x40 && b[4] & 7 != 4 {
        return Some(("indirect", None)); // FF /2 [reg+disp8]
    }
    if is_call(b[4], b[5]) && b[5] & 0xC0 != 0x40 && b[5] & 0xC0 != 0x80 && (b[5] & 0xC0 == 0xC0 || (b[5] & 7 != 4 && b[5] & 7 != 5)) {
        return Some(("indirect", None)); // FF /2 reg or [reg]
    }
    None
}

/// The memory operand of an instruction text (capstone's Intel syntax) resolved through the registers:
/// (`[ecx + 0x40]`, effective address).
pub fn mem_operand(op_str: &str, regs: &Regs) -> Option<(String, u32)> {
    let a = op_str.find('[')?;
    let b = a + op_str[a..].find(']')?;
    let inner = &op_str[a + 1..b];
    let (mut ea, mut sign) = (0u32, 1i64);
    for tok in inner.split_whitespace() {
        match tok {
            "+" => sign = 1,
            "-" => sign = -1,
            t => {
                let v: i64 = if let Some((r, s)) = t.split_once('*') {
                    regs.get(r)? as i64 * s.parse::<i64>().ok()?
                } else if let Some(r) = regs.get(t) {
                    r as i64
                } else if let Some(h) = t.strip_prefix("0x") {
                    i64::from_str_radix(h, 16).ok()?
                } else if t.contains(':') {
                    return None; // fs:[...]
                } else {
                    t.parse().ok()?
                };
                ea = ea.wrapping_add((sign * v) as u32);
            }
        }
    }
    Some((format!("[{inner}]"), ea))
}

/// The run a crash belongs to.
pub struct Meta {
    pub run: String,
    pub exe: String,
    pub sha256: String,
    pub seconds: f64,
    pub exit_code: Option<u32>,
    pub dump: String,
}

/// crash.txt.
pub fn report(c: &Capture, syms: &Symbols, m: &Meta, insn: Option<&str>) -> String {
    let exe_name = Path::new(&m.exe).file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    let module = |va: u32| c.modules.iter().find(|(b, s, _)| *b <= va && va < b + s).map(|(b, _, n)| (n.clone(), va - b));
    let in_exe = |va: u32| module(va).map(|(n, _)| n.to_lowercase() == exe_name).unwrap_or(c.modules.is_empty());
    let name = |va: u32, code_only: bool| -> String {
        if in_exe(va) {
            if let Some((s, off)) = syms.at(va, code_only) {
                return describe(s, off);
            }
        }
        module(va).map(|(n, off)| plus(&n, off)).unwrap_or_else(|| "?".into())
    };
    let mut l = vec![
        format!("crash: {}  (run {})", m.exe, m.run),
        format!("exe sha256: {}", m.sha256),
        format!("ran: {:.1} s", m.seconds),
        format!("exception: 0x{:08X} {}  ({})", c.code, exception_name(c.code), if c.first { "first chance; the process then exited" } else { "second chance" }),
        format!("fault: 0x{:08x}  {}", c.address, name(c.address, false)),
    ];
    if c.code == 0xC0000005 && c.params.len() > 1 {
        let access = match c.params[0] { 0 => "read", 1 => "write", 8 => "execute", _ => "access" };
        let target = c.params[1];
        let what = if module(target).is_some() || syms.at(target, false).is_some() { format!(" ({})", name(target, false)) } else { String::new() };
        l.push(format!("access: {access} of 0x{target:08x}{what}"));
    }
    if let Some(i) = insn {
        let ea = c.regs.as_ref().and_then(|r| mem_operand(i, r).map(|(e, a)| {
            let regs: Vec<String> = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"].iter().filter(|x| e.contains(*x))
                .map(|x| format!("{x}=0x{:08x}", r.get(x).unwrap_or(0))).collect();
            format!("   {e} = 0x{a:08x}{}", if regs.is_empty() { String::new() } else { format!("  ({})", regs.join(", ")) })
        }));
        l.push(format!("instruction: {i}{}", ea.unwrap_or_default()));
    }
    if let Some(e) = m.exit_code {
        l.push(format!("process exit code: 0x{e:08X}"));
    }
    l.push(format!("thread: {}", c.tid));
    l.push(format!("minidump: {}", m.dump));
    l.push(String::new());
    match &c.regs {
        Some(r) => l.extend([
            "registers:".to_string(),
            format!("  eip {:08x}  esp {:08x}  ebp {:08x}  eflags {:08x}", r.eip, r.esp, r.ebp, r.eflags),
            format!("  eax {:08x}  ebx {:08x}  ecx {:08x}  edx {:08x}", r.eax, r.ebx, r.ecx, r.edx),
            format!("  esi {:08x}  edi {:08x}", r.esi, r.edi),
        ]),
        None => l.push("registers: unavailable (the thread context could not be read)".into()),
    }
    let esp = c.regs.map(|r| r.esp).unwrap_or(0);
    let words: Vec<(u32, u32)> = c.stack.chunks_exact(4).enumerate().map(|(i, w)| (esp + 4 * i as u32, u32::from_le_bytes([w[0], w[1], w[2], w[3]]))).collect();
    l.push(String::new());
    // the call chain: stack words just after a call instruction, linked: a word is the caller of the frame below
    // when its direct call reaches that frame's function (an indirect call cannot be checked: marked `?`); a call
    // into a DLL links a fault outside the exe. The chain ends at the function holding the entry point.
    let func = |va: u32| -> Option<&Sym> { if in_exe(va) { syms.at(va, true).map(|(s, _)| s) } else { None } };
    l.push("call chain (each caller's call reaches the function below it; innermost first):".into());
    l.push(format!("  #0  0x{:08x}  {}", c.address, name(c.address, true)));
    let mut cur = func(c.address).map(|s| s.va);
    let (mut n, mut done, mut others) = (0, func(c.address).is_some_and(|s| s.entry), vec![]);
    for (at, v) in &words {
        let Some(b) = c.below.get(v) else { continue };
        let Some((kind, callee)) = call_below(b, *v) else { continue };
        let target = callee.and_then(&func).map(|s| s.va);
        let to = match callee {
            Some(t) => syms.at(t, true).map(|(s, off)| plus(&s.name, off)).unwrap_or_else(|| format!("0x{t:08x}")),
            None => format!("({kind})"),
        };
        let links = !done && match (cur, kind) {
            (Some(f), "direct") => target == Some(f),
            (Some(_), "import") => false,
            (Some(_), _) => true,
            (None, "direct") => target.is_none(),
            (None, _) => true,
        };
        let line = format!("0x{v:08x}  {}   <- call {to}{}   [esp+0x{:x}]", name(*v, true), if kind == "indirect" && cur.is_some() { "?" } else { "" }, at - esp);
        if links && n < 64 {
            n += 1;
            l.push(format!("  #{n:<2} {line}"));
            cur = func(*v).map(|s| s.va);
            done = func(*v).is_some_and(|s| s.entry);
        } else if others.len() < 16 {
            others.push(format!("  {line}"));
        }
    }
    if n == 0 {
        l.push("  (no stack word links: no call instruction reaches the faulting function)".into());
    }
    if !others.is_empty() {
        l.push(String::new());
        l.push("other words after a call (stale frames, or callers the chain could not link):".into());
        l.extend(others);
    }
    if !c.ebp_chain.is_empty() {
        l.push(String::new());
        l.push("ebp chain (unreliable under /Oy, which /O2 implies):".into());
        for (i, v) in c.ebp_chain.iter().enumerate() {
            l.push(format!("  #{i:<2} 0x{v:08x}  {}", name(*v, true)));
        }
    }
    l.push(String::new());
    l.push("stack scan (words inside a function of the exe; unvalidated):".into());
    let mut k = 0;
    for (at, v) in &words {
        if in_exe(*v) && syms.at(*v, true).is_some() {
            l.push(format!("  [esp+0x{:04x}] 0x{v:08x}  {}", at - esp, name(*v, true)));
            k += 1;
            if k >= 24 {
                break;
            }
        }
    }
    l.push(String::new());
    l.push("modules:".into());
    let mut mods = c.modules.clone();
    mods.sort();
    for (b, s, n) in mods {
        l.push(format!("  0x{b:08x}-0x{:08x}  {n}", b + s));
    }
    l.join("\n") + "\n"
}

// ------------------------------------------------------------------------------------------------ the debug loop

#[cfg(windows)]
mod win {
    use super::*;
    use std::ffi::c_void;

    pub type Handle = *mut c_void;

    #[repr(C)]
    pub struct StartupInfoW {
        pub cb: u32,
        reserved: *mut u16,
        desktop: *mut u16,
        title: *mut u16,
        x: u32,
        y: u32,
        x_size: u32,
        y_size: u32,
        x_chars: u32,
        y_chars: u32,
        fill: u32,
        flags: u32,
        show: u16,
        reserved2_n: u16,
        reserved2: *mut u8,
        std_in: Handle,
        std_out: Handle,
        std_err: Handle,
    }

    #[repr(C)]
    pub struct ProcessInformation {
        pub process: Handle,
        pub thread: Handle,
        pub pid: u32,
        pub tid: u32,
    }

    #[repr(C)]
    pub struct DebugEvent {
        pub code: u32,
        pub pid: u32,
        pub tid: u32,
        pub u: [u64; 20], // the union (160 bytes), 8-aligned
    }

    #[repr(C)]
    pub struct Wow64Context {
        pub flags: u32,
        dr: [u32; 6],
        float_save: [u8; 112],
        seg: [u32; 4],
        pub edi: u32,
        pub esi: u32,
        pub ebx: u32,
        pub edx: u32,
        pub ecx: u32,
        pub eax: u32,
        pub ebp: u32,
        pub eip: u32,
        cs: u32,
        pub eflags: u32,
        pub esp: u32,
        ss: u32,
        ext: [u8; 512],
    }

    #[repr(C)]
    pub struct ModuleEntry32W {
        pub size: u32,
        module_id: u32,
        pid: u32,
        glbl: u32,
        proc_: u32,
        pub base: *mut u8,
        pub base_size: u32,
        module: Handle,
        pub name: [u16; 256],
        path: [u16; 260],
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub fn CreateProcessW(app: *const u16, cmd: *mut u16, pa: *mut c_void, ta: *mut c_void, inherit: i32, flags: u32, env: *mut c_void,
                              cwd: *const u16, si: *mut StartupInfoW, pi: *mut ProcessInformation) -> i32;
        pub fn WaitForDebugEvent(ev: *mut DebugEvent, ms: u32) -> i32;
        pub fn ContinueDebugEvent(pid: u32, tid: u32, status: u32) -> i32;
        pub fn TerminateProcess(h: Handle, code: u32) -> i32;
        pub fn OpenThread(access: u32, inherit: i32, tid: u32) -> Handle;
        pub fn Wow64GetThreadContext(h: Handle, ctx: *mut Wow64Context) -> i32;
        pub fn ReadProcessMemory(h: Handle, at: *const c_void, buf: *mut c_void, n: usize, got: *mut usize) -> i32;
        pub fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> Handle;
        pub fn Module32FirstW(snap: Handle, me: *mut ModuleEntry32W) -> i32;
        pub fn Module32NextW(snap: Handle, me: *mut ModuleEntry32W) -> i32;
        pub fn CloseHandle(h: Handle) -> i32;
        pub fn GetLastError() -> u32;
    }
    use crate::cs::{GetProcAddress, LoadLibraryW};

    pub fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn read(h: Handle, at: u32, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        let mut got = 0usize;
        let ok = unsafe { ReadProcessMemory(h, at as usize as *const c_void, buf.as_mut_ptr() as *mut c_void, n, &mut got) };
        buf.truncate(if ok != 0 { got } else { 0 });
        buf
    }

    pub fn modules(pid: u32) -> Vec<(u32, u32, String)> {
        let mut out = vec![];
        unsafe {
            let snap = CreateToolhelp32Snapshot(0x8 | 0x10, pid);
            if snap.is_null() || snap as isize == -1 {
                return out;
            }
            let mut me: ModuleEntry32W = std::mem::zeroed();
            me.size = std::mem::size_of::<ModuleEntry32W>() as u32;
            let mut ok = Module32FirstW(snap, &mut me);
            while ok != 0 {
                let n = me.name.iter().position(|c| *c == 0).unwrap_or(256);
                // the 64-bit modules of a WOW64 process (above 4 GB) are not the program's
                if (me.base as usize) <= u32::MAX as usize {
                    out.push((me.base as usize as u32, me.base_size, String::from_utf16_lossy(&me.name[..n])));
                }
                ok = Module32NextW(snap, &mut me);
            }
            CloseHandle(snap);
        }
        out.sort();
        out.dedup();
        out
    }

    pub fn regs(tid: u32) -> Option<Regs> {
        unsafe {
            let h = OpenThread(0x8 | 0x2, 0, tid);
            if h.is_null() {
                return None;
            }
            let mut c: Box<Wow64Context> = Box::new(std::mem::zeroed());
            c.flags = 0x10007;
            let ok = Wow64GetThreadContext(h, &mut *c);
            CloseHandle(h);
            (ok != 0).then(|| Regs { eax: c.eax, ebx: c.ebx, ecx: c.ecx, edx: c.edx, esi: c.esi, edi: c.edi, ebp: c.ebp, esp: c.esp, eip: c.eip, eflags: c.eflags })
        }
    }

    /// A minidump of the process into `path` (MiniDumpWriteDump of dbghelp, loaded at run time).
    pub fn minidump(h: Handle, pid: u32, path: &Path, kind: u32) -> Result<(), String> {
        use std::os::windows::io::AsRawHandle;
        type Write = unsafe extern "system" fn(Handle, u32, Handle, u32, *mut c_void, *mut c_void, *mut c_void) -> i32;
        let lib = unsafe { LoadLibraryW(wide("dbghelp.dll").as_ptr()) };
        if lib.is_null() {
            return Err("dbghelp.dll not found".into());
        }
        let f = unsafe { GetProcAddress(lib, c"MiniDumpWriteDump".as_ptr()) };
        if f.is_null() {
            return Err("dbghelp.dll has no MiniDumpWriteDump".into());
        }
        let write: Write = unsafe { std::mem::transmute(f) };
        let file = std::fs::File::create(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let ok = unsafe { write(h, pid, file.as_raw_handle() as Handle, kind, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) };
        if ok == 0 { Err(format!("MiniDumpWriteDump failed ({})", unsafe { GetLastError() })) } else { Ok(()) }
    }
}

/// How a debugged run ended.
pub struct Ended {
    pub exit_code: Option<u32>,
    pub stopped: String, // "", "time", "interrupt"
    pub crash: Option<String>,
}

/// A debug run's inputs.
pub struct Debuggee<'a> {
    pub run: &'a str,
    pub exe: &'a str,
    pub cmdline: &'a str,
    pub dir: &'a str,
    pub env: &'a [(String, String)],
    pub seconds: f64,
    pub symbols: &'a str,
    pub capstone: &'a str,
    pub crash_root: &'a str,
    pub dump: &'a str, // full | state | normal | none
    pub spec: &'a str,
}

fn dump_kind(mode: &str) -> Option<(u32, &'static str)> {
    match mode {
        "full" => Some((0x2, "MiniDumpWithFullMemory")),
        "state" => Some((0x1 | 0x10000, "MiniDumpWithDataSegs|WithPrivateReadWriteMemory")),
        "normal" => Some((0, "MiniDumpNormal")),
        _ => None,
    }
}

/// The environment block of CreateProcessW: `K=V\0` sorted case-insensitively, then `\0`.
fn env_block(env: &[(String, String)]) -> Vec<u16> {
    let mut e: Vec<&(String, String)> = env.iter().collect();
    e.sort_by_key(|(k, _)| k.to_uppercase());
    let mut out: Vec<u16> = vec![];
    for (k, v) in e {
        out.extend(format!("{k}={v}").encode_utf16());
        out.push(0);
    }
    out.push(0);
    out
}

#[cfg(windows)]
pub fn debug_run(d: &Debuggee, interrupted: &mut dyn FnMut() -> bool) -> Result<Ended, String> {
    use win::*;
    const DEBUG_ONLY_THIS_PROCESS: u32 = 0x2;
    const CREATE_UNICODE_ENVIRONMENT: u32 = 0x400;
    const DBG_CONTINUE: u32 = 0x00010002;
    const DBG_EXCEPTION_NOT_HANDLED: u32 = 0x80010001;
    const BENIGN: [u32; 5] = [0x80000003, 0x4000001F, 0x40010006, 0x4001000A, 0x406D1388]; // breakpoints, OutputDebugString, thread name

    let syms = Symbols::load(d.symbols);
    let mut si: StartupInfoW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<StartupInfoW>() as u32;
    let mut pi = ProcessInformation { process: std::ptr::null_mut(), thread: std::ptr::null_mut(), pid: 0, tid: 0 };
    let mut cmd = wide(d.cmdline);
    let mut env = env_block(d.env);
    let ok = unsafe {
        CreateProcessW(std::ptr::null(), cmd.as_mut_ptr(), std::ptr::null_mut(), std::ptr::null_mut(), 0, DEBUG_ONLY_THIS_PROCESS | CREATE_UNICODE_ENVIRONMENT,
                       env.as_mut_ptr() as *mut _, wide(d.dir).as_ptr(), &mut si, &mut pi)
    };
    if ok == 0 {
        return Err(format!("CreateProcess {}: error {}", d.exe, unsafe { GetLastError() }));
    }
    let t0 = std::time::Instant::now();
    let mut ended = Ended { exit_code: None, stopped: String::new(), crash: None };
    let mut pending: Option<Capture> = None;
    let mut crashed = false;
    let capture = |rec: &[u64; 20], tid: u32, first: bool| -> Capture {
        let w = |k: usize| rec[k];
        // EXCEPTION_RECORD (64-bit): code u32, flags u32 | record u64 | address u64 | nparams u32, pad | info[15] u64
        let code = w(0) as u32;
        let address = w(2) as u32;
        let n = (w(3) as u32).min(15) as usize;
        let params = (0..n).map(|k| w(4 + k) as u32).collect();
        let regs = win::regs(tid);
        let mut c = Capture { code, address, first, tid, params, regs, modules: win::modules(pi.pid), ..Default::default() };
        c.code_bytes = read(pi.process, address, 16);
        if let Some(r) = regs {
            c.stack = read(pi.process, r.esp, 0x2000);
            let exe = Path::new(d.exe).file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
            let range = syms.code_range().or_else(|| c.modules.iter().find(|m| m.2.to_lowercase() == exe).map(|m| (m.0, m.0 + m.1)));
            if let Some((lo, hi)) = range {
                for w in c.stack.chunks_exact(4).take(1024) {
                    let v = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
                    if lo + 6 <= v && v < hi && !c.below.contains_key(&v) {
                        if let Ok(b) = <[u8; 6]>::try_from(read(pi.process, v - 6, 6).as_slice()) {
                            c.below.insert(v, b);
                        }
                    }
                }
            }
            let (mut ebp, mut seen) = (r.ebp, std::collections::HashSet::new());
            for _ in 0..64 {
                if ebp < r.esp.saturating_sub(0x1000) || ebp >= 0x7fff0000 || !seen.insert(ebp) {
                    break;
                }
                let pair = read(pi.process, ebp, 8);
                if pair.len() < 8 {
                    break;
                }
                let next = u32::from_le_bytes([pair[0], pair[1], pair[2], pair[3]]);
                let ret = u32::from_le_bytes([pair[4], pair[5], pair[6], pair[7]]);
                if ret != 0 {
                    c.ebp_chain.push(ret);
                }
                if next <= ebp {
                    break;
                }
                ebp = next;
            }
        }
        c
    };
    let write = |c: &Capture, exit_code: Option<u32>, dump: bool| -> Result<String, String> {
        let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
        let dir = Path::new(d.crash_root).join(format!("{}-{stamp}", d.run));
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let note = match (dump, dump_kind(d.dump)) {
            (_, None) => "not written (--dump none)".to_string(),
            (false, _) => "not written (the process had already exited)".to_string(),
            (true, Some((kind, bits))) => match minidump(pi.process, pi.pid, &dir.join("crash.dmp"), kind) {
                Ok(()) => format!("crash.dmp ({} B, {bits})", std::fs::metadata(dir.join("crash.dmp")).map(|m| m.len()).unwrap_or(0)),
                Err(e) => format!("crash.dmp not written: {e}"),
            },
        };
        let insn = (!c.code_bytes.is_empty() && !d.capstone.is_empty()).then(|| crate::cs::disasm(d.capstone, &c.code_bytes, c.address).ok())
            .flatten().and_then(|v| v.into_iter().next()).map(|i| format!("{} {}", i.mnemonic, i.op_str).trim().to_string());
        let sha = crate::fsmemo::sha256(d.exe).unwrap_or_default();
        let m = Meta { run: d.run.into(), exe: d.exe.into(), sha256: sha, seconds: t0.elapsed().as_secs_f64(), exit_code, dump: note };
        std::fs::write(dir.join("crash.txt"), report(c, &syms, &m, insn.as_deref())).map_err(|e| e.to_string())?;
        let _ = std::fs::copy(d.spec, dir.join("launch.json"));
        let rel = dir.strip_prefix(Path::new(d.crash_root).parent().and_then(|b| b.parent()).unwrap_or(Path::new(""))).unwrap_or(&dir);
        let _ = std::fs::write(Path::new(d.crash_root).join("LATEST.txt"), format!("{}\n", rel.to_string_lossy().replace('\\', "/")));
        Ok(dir.to_string_lossy().into_owned())
    };
    let mut ev = DebugEvent { code: 0, pid: 0, tid: 0, u: [0; 20] };
    loop {
        if ended.stopped.is_empty() {
            let why = if d.seconds > 0.0 && t0.elapsed().as_secs_f64() >= d.seconds { "time" } else if interrupted() { "interrupt" } else { "" };
            if !why.is_empty() {
                ended.stopped = why.into();
                unsafe { TerminateProcess(pi.process, 0) };
            }
        }
        if unsafe { WaitForDebugEvent(&mut ev, 200) } == 0 {
            if unsafe { GetLastError() } == 121 {
                continue; // ERROR_SEM_TIMEOUT
            }
            break;
        }
        let (pid, tid) = (ev.pid, ev.tid);
        let mut status = DBG_CONTINUE;
        match ev.code {
            1 => {
                // EXCEPTION_DEBUG_EVENT: the record (152 bytes), then dwFirstChance
                let code = ev.u[0] as u32;
                let first = (ev.u[19] & 0xffff_ffff) != 0;
                if crashed || BENIGN.contains(&code) {
                    status = if crashed { DBG_EXCEPTION_NOT_HANDLED } else { DBG_CONTINUE };
                } else if first {
                    if code >= 0xC000_0000 {
                        pending = Some(capture(&ev.u, tid, true));
                    }
                    status = DBG_EXCEPTION_NOT_HANDLED;
                } else {
                    let c = capture(&ev.u, tid, false);
                    crashed = true;
                    ended.crash = Some(write(&c, None, true).unwrap_or_else(|e| format!("(crash report not written: {e})")));
                    unsafe {
                        ContinueDebugEvent(pid, tid, DBG_EXCEPTION_NOT_HANDLED);
                        TerminateProcess(pi.process, code);
                    }
                    continue;
                }
            }
            3 | 6 => {
                // CREATE_PROCESS / LOAD_DLL: their file handle is the debugger's to close
                let h = ev.u[0] as usize as Handle;
                if !h.is_null() {
                    unsafe { CloseHandle(h) };
                }
            }
            5 => {
                // EXIT_PROCESS_DEBUG_EVENT
                let code = ev.u[0] as u32;
                ended.exit_code = Some(code);
                if !crashed && ended.stopped.is_empty() && code >= 0xC000_0000 {
                    let c = pending.take().unwrap_or(Capture { code, address: 0, first: true, tid, ..Default::default() });
                    ended.crash = Some(write(&c, Some(code), false).unwrap_or_else(|e| format!("(crash report not written: {e})")));
                }
                unsafe { ContinueDebugEvent(pid, tid, DBG_CONTINUE) };
                break;
            }
            _ => {}
        }
        unsafe { ContinueDebugEvent(pid, tid, status) };
    }
    unsafe {
        CloseHandle(pi.thread);
        CloseHandle(pi.process);
    }
    Ok(ended)
}

#[cfg(not(windows))]
pub fn debug_run(_d: &Debuggee, _interrupted: &mut dyn FnMut() -> bool) -> Result<Ended, String> {
    Err("dcp run --debug needs Windows".into())
}

/// `launch.py`'s call: run the program under the debugger. (exit code, stopped, crash dir).
#[pyo3::pyfunction]
#[pyo3(signature = (run, exe, cmdline, dir, env, seconds, symbols, capstone, crash_root, dump, spec))]
#[allow(clippy::too_many_arguments)]
pub fn debug_launch(py: pyo3::Python<'_>, run: &str, exe: &str, cmdline: &str, dir: &str, env: Vec<(String, String)>, seconds: f64, symbols: &str,
                    capstone: &str, crash_root: &str, dump: &str, spec: &str) -> Result<(Option<u32>, String, Option<String>)> {
    let d = Debuggee { run, exe, cmdline, dir, env: &env, seconds, symbols, capstone, crash_root, dump, spec };
    let mut interrupted = || py.check_signals().is_err();
    let e = debug_run(&d, &mut interrupted).map_err(Error::runtime)?;
    Ok((e.exit_code, e.stopped, e.crash))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAP: &str = " GildeGold

  Address         Publics by Value              Rva+Base     Lib:Object

 0001:00000000       _util_Hash                 00401000 f   aaaa.obj
 0001:00000040       _util_BaseName@8           00401040 f   aaaa.obj
 0001:00000090       _memcpy                    00401090 f   LIBC:memcpy.obj
 0003:00000010       _g_count                   0059e010     bbbb.obj

 entry point at        0001:00000048

 Static symbols

 0001:00000060       _helper                    00401060 f   aaaa.obj
";

    fn table() -> Symbols {
        Symbols::new(symbols(MAP, |o| (o == "aaaa.obj").then(|| "util".to_string()),
                             |u, n| (u == "util" && n == "util_Hash").then_some((12, Some(0x0050_0000)))))
    }

    #[test]
    fn map_and_names() {
        assert_eq!(c_name("_util_BaseName@8"), "util_BaseName");
        assert_eq!(c_name("__chkstk"), "__chkstk");
        assert_eq!(c_name("?f@@YAXXZ"), "?f@@YAXXZ");
        let s = table();
        let (y, off) = s.at(0x401010, true).unwrap();
        assert_eq!((y.name.as_str(), off, y.unit.as_str(), y.line, y.original), ("util_Hash", 0x10, "util", 12, Some(0x500000)));
        assert_eq!(describe(y, off), "util_Hash+0x10   unit=util  src/util.c:12  original=0x00500000+0x10");
        assert_eq!(s.at(0x401070, true).unwrap().0.name, "helper"); // a static between two publics sizes them
        assert_eq!(s.at(0x401040, true).unwrap().0.size, 0x20);
        assert!(s.at(0x401040, true).unwrap().0.entry && !s.at(0x401000, true).unwrap().0.entry);
        assert!(s.at(0x59e010, true).is_none() && s.at(0x59e010, false).is_some());
        assert!(s.at(0x400fff, false).is_none());
        assert_eq!(s.code_range(), Some((0x401000, 0x401091)));
        let p = std::env::temp_dir().join(format!("dcp-syms-{}.tsv", std::process::id()));
        let ps = p.to_string_lossy().into_owned();
        write_symbols(&ps, "k1", &symbols(MAP, |_| None, |_, _| None)).unwrap();
        assert_eq!((symbols_key(&ps), Symbols::load(&ps).rows.len()), ("k1".to_string(), 5));
        let _ = std::fs::remove_file(p);
    }

    /// A VC6 program (C:/Tools/MSVC600-SP5PP): `cargo test -- --ignored debugger`.
    fn vc6_exe(dir: &Path, name: &str, src: &str) -> String {
        let vc = Path::new("C:/Tools/MSVC600-SP5PP/VC98");
        std::fs::write(dir.join(format!("{name}.c")), src).unwrap();
        let path = format!("{};{}", vc.join("Bin").display(), Path::new("C:/Tools/MSVC600-SP5PP/Common/MSDev98/Bin").display());
        let out = std::process::Command::new(vc.join("Bin").join("CL.EXE"))
            .args(["/nologo", "/O2", &format!("{name}.c"), "/link", "/MAP", "/FIXED"]).current_dir(dir)
            .env("PATH", path).env("INCLUDE", vc.join("Include")).env("LIB", vc.join("Lib")).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
        dir.join(format!("{name}.exe")).to_string_lossy().into_owned()
    }

    #[test]
    #[ignore]
    fn debugged_crash_and_handled_exception() {
        let dir = std::env::temp_dir().join(format!("dcp-debugger-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let crash = vc6_exe(&dir, "crash", "int *p;\nint deref(int k) { return p[k]; }\nint main(void) { return deref(16); }\n");
        let handled = vc6_exe(&dir, "handled",
            "#include <windows.h>\nint *p;\nint main(void) { __try { *p = 1; } __except (EXCEPTION_EXECUTE_HANDLER) { return 7; } return 0; }\n");
        let syms = dir.join("crash.tsv").to_string_lossy().into_owned();
        let map = std::fs::read_to_string(dir.join("crash.map")).unwrap();
        write_symbols(&syms, "k", &symbols(&map, |o| (o == "crash.obj").then(|| "crash".to_string()), |_, n| (n == "deref").then_some((2, Some(0x00401234))))).unwrap();
        let root = dir.join("build").join("crash").to_string_lossy().into_owned();
        let spec = dir.join("spec.json");
        std::fs::write(&spec, "{}").unwrap();
        let env: Vec<(String, String)> = std::env::vars().collect();
        let dirs = dir.to_string_lossy().into_owned();
        let cs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.venv/Lib/site-packages/capstone/lib/capstone.dll").to_string_lossy().into_owned();
        let run = |exe: &str, dump: &str| debug_run(&Debuggee { run: "t", exe, cmdline: &format!("\"{exe}\""), dir: &dirs, env: &env, seconds: 20.0, symbols: &syms,
                                                    capstone: &cs, crash_root: &root, dump, spec: &spec.to_string_lossy() }, &mut || false).unwrap();
        // a program that handles its own access violation: no crash report, its own exit code
        let e = run(&handled, "none");
        assert_eq!((e.exit_code, e.crash.as_deref(), e.stopped.as_str()), (Some(7), None, ""));
        // a crash: the report names the function, its unit and the original's address; the dump is written
        let e = run(&crash, "normal");
        let d = std::path::PathBuf::from(e.crash.expect("a crash folder"));
        let t = std::fs::read_to_string(d.join("crash.txt")).unwrap();
        eprintln!("{t}");
        assert!(t.contains("exception: 0xC0000005 access violation  (second chance)"), "{t}");
        assert!(t.contains("deref") && t.contains("unit=crash  src/crash.c:2  original=0x00401234"), "{t}");
        assert!(t.contains("access: read of 0x00000040"), "{t}");
        assert!(t.contains("instruction: mov eax, dword ptr [ecx + eax*4]") || t.contains("instruction: mov eax, dword ptr [eax + ecx*4]"), "{t}");
        assert!(t.contains("<- call deref") || t.contains("main"), "{t}");
        assert!(std::fs::metadata(d.join("crash.dmp")).map(|m| m.len() > 0).unwrap_or(false));
        assert!(std::fs::read_to_string(dir.join("build").join("crash").join("LATEST.txt")).unwrap().contains("t-"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn calls_below_return_addresses() {
        let ret = 0x401100;
        assert_eq!(call_below(&[0, 0xE8, 0x00, 0xFF, 0xFF, 0xFF], ret), Some(("direct", Some(0x401000)))); // call -0x100
        assert_eq!(call_below(&[0xFF, 0x15, 0x10, 0x20, 0x5d, 0x00], ret), Some(("import", None)));
        assert_eq!(call_below(&[0, 0, 0, 0xFF, 0x50, 0x08], ret), Some(("indirect", None))); // call [eax+8]
        assert_eq!(call_below(&[0, 0, 0, 0, 0xFF, 0xD0], ret), Some(("indirect", None)));    // call eax
        assert_eq!(call_below(&[0, 0, 0, 0, 0xFF, 0x10], ret), Some(("indirect", None)));    // call [eax]
        assert_eq!(call_below(&[0x8B, 0x45, 0x08, 0x50, 0x6A, 0x01], ret), None);
        assert_eq!(call_below(&[0, 0, 0, 0, 0xFF, 0xE0], ret), None);                         // jmp eax
    }

    #[test]
    fn memory_operands() {
        let r = Regs { ecx: 0, eax: 3, esi: 0x1000, ..Default::default() };
        assert_eq!(mem_operand("dword ptr [ecx + 0x40], eax", &r), Some(("[ecx + 0x40]".into(), 0x40)));
        assert_eq!(mem_operand("eax, dword ptr [esi + eax*4 - 8]", &r), Some(("[esi + eax*4 - 8]".into(), 0x1004)));
        assert_eq!(mem_operand("eax, dword ptr [0x59e010]", &r), Some(("[0x59e010]".into(), 0x59e010)));
        assert_eq!(mem_operand("eax, ecx", &r), None);
    }

    #[test]
    fn report_names_the_decompilation() {
        let s = table();
        let mut stack = vec![];
        for w in [0x1234u32, 0x401088, 0x401058, 0x401020, 0x401070] {
            stack.extend(w.to_le_bytes());
        }
        let c = Capture {
            code: 0xC0000005, address: 0x401010, tid: 7, params: vec![1, 0x40], stack,
            regs: Some(Regs { ecx: 0, esp: 0x19ff00, eip: 0x401010, ..Default::default() }),
            below: [
                (0x401088u32, [0, 0xE8, 0x08, 0x00, 0x00, 0x00]), // a stale word: helper calls memcpy (0x401088 + 8)
                (0x401058u32, [0, 0xE8, 0xA8, 0xFF, 0xFF, 0xFF]), // call util_Hash (0x401058 - 0x58): the caller
                (0x401070u32, [0, 0xE8, 0x90, 0xFF, 0xFF, 0xFF]), // call util_Hash (0x401070 - 0x70), beyond the entry function
            ].into(),
            modules: vec![(0x400000, 0x200000, "Game.exe".into()), (0x77000000, 0x1000, "ntdll.dll".into())], ..Default::default()
        };
        let m = Meta { run: "play".into(), exe: "C:/x/Game.exe".into(), sha256: "ab".into(), seconds: 1.0, exit_code: None, dump: "none".into() };
        let t = report(&c, &s, &m, Some("mov dword ptr [ecx + 0x40], eax"));
        assert!(t.contains("exception: 0xC0000005 access violation  (second chance)"), "{t}");
        assert!(t.contains("fault: 0x00401010  util_Hash+0x10   unit=util  src/util.c:12  original=0x00500000+0x10"), "{t}");
        assert!(t.contains("access: write of 0x00000040"), "{t}");
        assert!(t.contains("instruction: mov dword ptr [ecx + 0x40], eax   [ecx + 0x40] = 0x00000040  (ecx=0x00000000)"), "{t}");
        assert!(t.contains("  #1  0x00401058  util_BaseName+0x18   unit=util   <- call util_Hash   [esp+0x8]"), "{t}");
        assert!(!t.contains("  #2 "), "{t}");
        assert!(t.contains("other words after a call (stale frames, or callers the chain could not link):\n  0x00401088  helper+0x28   unit=util   <- call memcpy   [esp+0x4]\n  0x00401070  helper+0x10   unit=util   <- call util_Hash   [esp+0x10]"), "{t}");
        assert!(t.contains("  [esp+0x000c] 0x00401020  util_Hash+0x20   unit=util  src/util.c:12  original=0x00500000+0x20"), "{t}");
        assert!(!t.contains("0x00001234"), "{t}");
    }
}
