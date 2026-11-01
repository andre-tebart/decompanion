//! capstone, the very library the Python package `capstone` loaded (its lib/capstone.dll), through its C API:
//! x86-32, Intel syntax. `disasm` is Cs.disasm_lite (texts, no operand details), `disasm_detail` Cs.disasm with
//! details on (operands, groups): every instruction from the start of the bytes to the end or the first that does
//! not decode.

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
    pub(crate) fn LoadLibraryW(name: *const u16) -> *mut c_void;
    pub(crate) fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
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

// ------------------------------------------------------------------------------------------------ operand details

#[repr(C)]
#[derive(Clone, Copy)]
struct X86OpMem {
    segment: u32,
    base: u32,
    index: u32,
    scale: i32,
    disp: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
union X86OpValue {
    reg: u32,
    imm: i64,
    mem: X86OpMem,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct X86Op {
    typ: u32,
    value: X86OpValue,
    size: u8,
    access: u8,
    avx_bcast: u32,
    avx_zero_opmask: bool,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct X86Encoding {
    modrm_offset: u8,
    disp_offset: u8,
    disp_size: u8,
    imm_offset: u8,
    imm_size: u8,
}

/// capstone 5's cs_x86 (capstone/x86.py CsX86 is the same layout).
#[repr(C)]
#[derive(Clone, Copy)]
struct CsX86 {
    prefix: [u8; 4],
    opcode: [u8; 4],
    rex: u8,
    addr_size: u8,
    modrm: u8,
    sib: u8,
    disp: i64,
    sib_index: u32,
    sib_scale: i8,
    sib_base: u32,
    xop_cc: u32,
    sse_cc: u32,
    avx_cc: u32,
    avx_sae: bool,
    avx_rm: u32,
    flags: u64,
    op_count: u8,
    operands: [X86Op; 8],
    encoding: X86Encoding,
}

/// cs_detail with the x86 member of its architecture union.
#[repr(C)]
struct CsDetail {
    regs_read: [u16; 20],
    regs_read_count: u8,
    regs_write: [u16; 20],
    regs_write_count: u8,
    groups: [u8; 8],
    groups_count: u8,
    writeback: bool,
    x86: CsX86,
}

pub const OP_REG: u32 = 1;
pub const OP_IMM: u32 = 2;
pub const OP_MEM: u32 = 3;
pub const GRP_JUMP: u8 = 1;
pub const GRP_CALL: u8 = 2;
pub const GRP_RET: u8 = 3;

/// One operand: its type (OP_REG / OP_IMM / OP_MEM), the immediate, the memory operand's base, index, scale and
/// displacement (registers 0: none), its size in bytes.
#[derive(Clone, Debug)]
pub struct Op {
    pub typ: u32,
    pub reg: u32,
    pub imm: i64,
    pub base: u32,
    pub index: u32,
    pub scale: i32,
    pub disp: i64,
    pub size: u8,
}

/// An instruction with capstone's details (Cs.disasm with detail on).
#[derive(Clone, Debug)]
pub struct DIns {
    pub addr: u32,
    pub size: u32,
    pub mnemonic: String,
    pub bytes: Vec<u8>,
    pub groups: Vec<u8>,
    pub ops: Vec<Op>,
}

type SetOption = unsafe extern "C" fn(usize, c_int, usize) -> c_int;

thread_local! {
    static DETAIL: RefCell<Option<(String, Engine)>> = const { RefCell::new(None) };
}

/// Every instruction of `code` at `va` with its operand details, up to the end or the first that does not decode.
pub fn disasm_detail(dll: &str, code: &[u8], va: u32) -> Result<Vec<DIns>, String> {
    DETAIL.with(|e| {
        let mut e = e.borrow_mut();
        if e.as_ref().map(|(d, _)| d != dll).unwrap_or(true) {
            let eng = engine_for(dll)?;
            unsafe {
                let wide: Vec<u16> = dll.encode_utf16().chain(std::iter::once(0)).collect();
                let m = LoadLibraryW(wide.as_ptr());
                let p = GetProcAddress(m, c"cs_option".as_ptr());
                if p.is_null() {
                    return Err(format!("{dll}: no cs_option"));
                }
                let opt: SetOption = std::mem::transmute(p);
                if opt(eng.handle, 2, 3) != 0 {
                    // CS_OPT_DETAIL, CS_OPT_ON
                    return Err(format!("{dll}: detail mode refused"));
                }
            }
            *e = Some((dll.to_string(), eng));
        }
        let eng = &e.as_ref().unwrap().1;
        let mut insn: *mut CsInsn = std::ptr::null_mut();
        let n = unsafe { (eng.disasm)(eng.handle, code.as_ptr(), code.len(), va as u64, 0, &mut insn) };
        let mut out = Vec::with_capacity(n);
        for k in 0..n {
            let i = unsafe { &*insn.add(k) };
            let d = unsafe { &*(i.detail as *const CsDetail) };
            let x = &d.x86;
            let ops = (0..x.op_count.min(8) as usize)
                .map(|j| {
                    let o = x.operands[j];
                    let (mut op, v) = (Op { typ: o.typ, reg: 0, imm: 0, base: 0, index: 0, scale: 0, disp: 0, size: o.size }, o.value);
                    unsafe {
                        match o.typ {
                            OP_REG => op.reg = v.reg,
                            OP_IMM => op.imm = v.imm,
                            OP_MEM => {
                                op.base = v.mem.base;
                                op.index = v.mem.index;
                                op.scale = v.mem.scale;
                                op.disp = v.mem.disp;
                            }
                            _ => {}
                        }
                    }
                    op
                })
                .collect();
            out.push(DIns {
                addr: i.address as u32,
                size: i.size as u32,
                mnemonic: unsafe { CStr::from_ptr(i.mnemonic.as_ptr()) }.to_string_lossy().into_owned(),
                bytes: i.bytes[..(i.size as usize).min(24)].to_vec(),
                groups: d.groups[..(d.groups_count as usize).min(8)].to_vec(),
                ops,
            });
        }
        if n > 0 {
            unsafe { (eng.free)(insn, n) };
        }
        Ok(out)
    })
}
