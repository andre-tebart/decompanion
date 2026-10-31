//! capstone, the very library the Python package `capstone` loaded (its lib/capstone.dll: the engine and version
//! isa/x86.py decodes with, so lengths and texts cannot differ), through its C API: x86-32, Intel syntax, no
//! operand details, as x86.capstone_lite. `disasm` is Cs.disasm_lite: every instruction from the start of the
//! bytes to the end or the first that does not decode.

use std::cell::RefCell;
use std::ffi::{c_char, c_int, c_void, CStr};

#[repr(C)]
struct CsInsn {
    id: u32,
    address: u64,
    size: u16,
    bytes: [u8; 24],
    mnemonic: [c_char; 32],
    op_str: [c_char; 160],
    detail: *mut c_void,
}

type Open = unsafe extern "C" fn(c_int, c_int, *mut usize) -> c_int;
type Disasm = unsafe extern "C" fn(usize, *const u8, usize, u64, usize, *mut *mut CsInsn) -> usize;
type Free = unsafe extern "C" fn(*mut CsInsn, usize);

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryW(name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
}

const CS_ARCH_X86: c_int = 3;
const CS_MODE_32: c_int = 1 << 2;

struct Engine {
    handle: usize,
    disasm: Disasm,
    free: Free,
}

thread_local! {
    static ENGINE: RefCell<Option<(String, Engine)>> = const { RefCell::new(None) };
}

pub struct Ins {
    pub addr: u32,
    pub size: u32,
    pub mnemonic: String,
    pub op_str: String,
}

fn engine_for(dll: &str) -> Result<Engine, String> {
    let wide: Vec<u16> = dll.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let m = LoadLibraryW(wide.as_ptr());
        if m.is_null() {
            return Err(format!("{dll}: cannot load capstone"));
        }
        let sym = |n: &CStr| {
            let p = GetProcAddress(m, n.as_ptr());
            if p.is_null() { Err(format!("{dll}: no {}", n.to_string_lossy())) } else { Ok(p) }
        };
        let open: Open = std::mem::transmute(sym(c"cs_open")?);
        let disasm: Disasm = std::mem::transmute(sym(c"cs_disasm")?);
        let free: Free = std::mem::transmute(sym(c"cs_free")?);
        let mut handle = 0usize;
        let rc = open(CS_ARCH_X86, CS_MODE_32, &mut handle);
        if rc != 0 {
            return Err(format!("{dll}: cs_open failed ({rc})"));
        }
        Ok(Engine { handle, disasm, free })
    }
}

/// (address, size) of every instruction of `code` at `va`, as disasm gives them (no text copied).
pub fn lengths(dll: &str, code: &[u8], va: u32) -> Result<Vec<(u32, u32)>, String> {
    with_engine(dll, |eng| {
        let mut insn: *mut CsInsn = std::ptr::null_mut();
        let n = unsafe { (eng.disasm)(eng.handle, code.as_ptr(), code.len(), va as u64, 0, &mut insn) };
        let out = (0..n).map(|k| unsafe { let i = &*insn.add(k); (i.address as u32, i.size as u32) }).collect();
        if n > 0 {
            unsafe { (eng.free)(insn, n) };
        }
        Ok(out)
    })
}

/// The size of the first instruction of `code` at `va`, None when it does not decode.
pub fn one(dll: &str, code: &[u8], va: u32) -> Result<Option<usize>, String> {
    with_engine(dll, |eng| {
        let mut insn: *mut CsInsn = std::ptr::null_mut();
        let len = code.len().min(16);
        let n = unsafe { (eng.disasm)(eng.handle, code.as_ptr(), len, va as u64, 1, &mut insn) };
        let out = if n > 0 { Some(unsafe { (*insn).size as usize }) } else { None };
        if n > 0 {
            unsafe { (eng.free)(insn, n) };
        }
        Ok(out)
    })
}

fn with_engine<T>(dll: &str, f: impl FnOnce(&Engine) -> Result<T, String>) -> Result<T, String> {
    ENGINE.with(|e| {
        let mut e = e.borrow_mut();
        if e.as_ref().map(|(d, _)| d != dll).unwrap_or(true) {
            *e = Some((dll.to_string(), engine_for(dll)?));
        }
        f(&e.as_ref().unwrap().1)
    })
}

/// Every instruction of `code` at `va` (Cs.disasm_lite).
pub fn disasm(dll: &str, code: &[u8], va: u32) -> Result<Vec<Ins>, String> {
    ENGINE.with(|e| {
        let mut e = e.borrow_mut();
        if e.as_ref().map(|(d, _)| d != dll).unwrap_or(true) {
            *e = Some((dll.to_string(), engine_for(dll)?));
        }
        let eng = &e.as_ref().unwrap().1;
        let mut insn: *mut CsInsn = std::ptr::null_mut();
        let n = unsafe { (eng.disasm)(eng.handle, code.as_ptr(), code.len(), va as u64, 0, &mut insn) };
        let mut out = Vec::with_capacity(n);
        for k in 0..n {
            let i = unsafe { &*insn.add(k) };
            out.push(Ins {
                addr: i.address as u32,
                size: i.size as u32,
                mnemonic: unsafe { CStr::from_ptr(i.mnemonic.as_ptr()) }.to_string_lossy().into_owned(),
                op_str: unsafe { CStr::from_ptr(i.op_str.as_ptr()) }.to_string_lossy().into_owned(),
            });
        }
        if n > 0 {
            unsafe { (eng.free)(insn, n) };
        }
        Ok(out)
    })
}

/// The first instruction of `code` at `va` with its text, None when it does not decode.
pub fn first(dll: &str, code: &[u8], va: u32) -> Result<Option<Ins>, String> {
    with_engine(dll, |eng| {
        let mut insn: *mut CsInsn = std::ptr::null_mut();
        let len = code.len().min(16);
        let n = unsafe { (eng.disasm)(eng.handle, code.as_ptr(), len, va as u64, 1, &mut insn) };
        if n == 0 {
            return Ok(None);
        }
        let i = unsafe { &*insn };
        let out = Ins {
            addr: i.address as u32,
            size: i.size as u32,
            mnemonic: unsafe { CStr::from_ptr(i.mnemonic.as_ptr()) }.to_string_lossy().into_owned(),
            op_str: unsafe { CStr::from_ptr(i.op_str.as_ptr()) }.to_string_lossy().into_owned(),
        };
        unsafe { (eng.free)(insn, n) };
        Ok(Some(out))
    })
}
