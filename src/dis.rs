//! The x86-32 decoder: iced-x86, pure Rust, compiled into the binary. Two faces over one decode:
//! - `disasm`: every instruction's text, MASM syntax as iced writes it (`mov eax, dword ptr [ebp - 4]`, `fld st(1)`,
//!   `rep movsd`, hex as `0x..` from 10 up, negative immediates signed): what listings, asmdiff and disasm print;
//! - `decode`: the typed record (`Ins`): mnemonic id, flow, operands (register / immediate / memory with base,
//!   index, scale, displacement, size), the offsets of its displacement and immediate fields in the bytes (the link
//!   to a relocation), and its register def-use sets.
//!
//! Both stop at the first byte sequence that does not decode (or runs past the end).

use iced_x86::{
    ConstantOffsets, Decoder, DecoderOptions, FlowControl, Formatter, Instruction, InstructionInfoFactory, MasmFormatter, Mnemonic,
    OpAccess, OpKind,
};
use std::cell::RefCell;

pub use iced_x86::Register as Reg;

/// One instruction's text: the mnemonic with its prefixes (`rep movsd`) and the operands (`dword ptr [esi], eax`).
pub struct Text {
    pub addr: u32,
    pub size: u32,
    pub mnemonic: String,
    pub op_str: String,
}

impl Text {
    /// `mnemonic op_str`.
    pub fn line(&self) -> String {
        if self.op_str.is_empty() { self.mnemonic.clone() } else { format!("{} {}", self.mnemonic, self.op_str) }
    }
}

thread_local! {
    static FMT: RefCell<MasmFormatter> = RefCell::new(formatter());
}

/// An immediate reads as it is encoded: a sign-extended byte signed (`push -1`, `cmp word ptr [edx], -1`), a full
/// width one unsigned (`push 0xffffffff`, `cmp word ptr [edx], 0xffff`). The compiler picks the encoding from the
/// constant's type, so two encodings of the same value are a difference of the source, and the text keeps it.
struct EncodedImmediates;

impl iced_x86::FormatterOptionsProvider for EncodedImmediates {
    fn operand_options(&mut self, i: &Instruction, _operand: u32, op: Option<u32>, _options: &mut iced_x86::FormatterOperandOptions,
                       number: &mut iced_x86::NumberFormattingOptions<'_>) {
        match op.map(|k| i.op_kind(k)) {
            Some(OpKind::Immediate8to16 | OpKind::Immediate8to32 | OpKind::Immediate8to64) => number.signed_number = true,
            Some(OpKind::Immediate8 | OpKind::Immediate16 | OpKind::Immediate32 | OpKind::Immediate64 | OpKind::Immediate32to64) => {
                number.signed_number = false
            }
            _ => {} // displacements keep their sign: [ebp - 4]
        }
    }
}

fn formatter() -> MasmFormatter {
    let mut f = MasmFormatter::with_options(None, Some(Box::new(EncodedImmediates)));
    let o = f.options_mut();
    o.set_space_after_operand_separator(true);
    o.set_space_between_memory_add_operators(true);
    o.set_hex_prefix("0x");
    o.set_hex_suffix("");
    o.set_uppercase_hex(false);
    o.set_memory_size_options(iced_x86::MemorySizeOptions::Always);
    o.set_show_branch_size(false);
    o.set_branch_leading_zeros(false);
    o.set_displacement_leading_zeros(false);
    o.set_leading_zeros(false);
    o.set_signed_immediate_operands(false);
    o.set_masm_add_ds_prefix32(false);
    o.set_show_symbol_address(false);
    f
}

fn instructions(code: &[u8], va: u32, mut each: impl FnMut(&Decoder, &Instruction)) {
    let mut d = Decoder::with_ip(32, code, va as u64, DecoderOptions::NONE);
    let mut i = Instruction::default();
    while d.can_decode() {
        d.decode_out(&mut i);
        if i.is_invalid() {
            break;
        }
        each(&d, &i);
    }
}

/// The text of one decoded instruction.
pub fn text(i: &Instruction) -> Text {
    FMT.with(|f| {
        let mut f = f.borrow_mut();
        let (mut mn, mut all) = (String::new(), String::new());
        f.format_mnemonic(i, &mut mn);
        f.format(i, &mut all);
        let op_str = all.strip_prefix(mn.as_str()).unwrap_or(&all).trim().to_string();
        Text { addr: i.ip32(), size: i.len() as u32, mnemonic: mn, op_str }
    })
}

/// Every instruction of `code` at `va` as text.
pub fn disasm(code: &[u8], va: u32) -> Vec<Text> {
    let mut out = vec![];
    instructions(code, va, |_, i| out.push(text(i)));
    out
}

/// (address, size) of every instruction of `code` at `va`.
pub fn lengths(code: &[u8], va: u32) -> Vec<(u32, u32)> {
    let mut out = vec![];
    instructions(code, va, |_, i| out.push((i.ip32(), i.len() as u32)));
    out
}

// ------------------------------------------------------------------------------------------------ the typed record

/// What an operand is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OpType {
    Reg,
    Imm,
    Mem,
}

/// One operand. A register operand: `reg`. An immediate: `imm` (sign-extended where the encoding sign-extends; a
/// branch target is an immediate). A memory operand: [seg: base + index*scale + disp], `size` bytes (0: no size,
/// lea); registers Reg::None where absent; `disp` sign-extended when a register is part of the address, else the
/// absolute address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Op {
    pub typ: OpType,
    pub reg: Reg,
    pub imm: i64,
    pub seg: Reg,
    pub base: Reg,
    pub index: Reg,
    pub scale: u8,
    pub disp: i64,
    pub size: u8,
}

impl Op {
    fn reg(r: Reg) -> Op {
        Op { typ: OpType::Reg, reg: r, imm: 0, seg: Reg::None, base: Reg::None, index: Reg::None, scale: 0, disp: 0, size: r.size() as u8 }
    }
    fn imm(v: i64, size: u8) -> Op {
        Op { typ: OpType::Imm, reg: Reg::None, imm: v, seg: Reg::None, base: Reg::None, index: Reg::None, scale: 0, disp: 0, size }
    }
    fn mem(seg: Reg, base: Reg, index: Reg, scale: u8, disp: i64, size: u8) -> Op {
        Op { typ: OpType::Mem, reg: Reg::None, imm: 0, seg, base, index, scale, disp, size }
    }
}

/// How control leaves an instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Flow {
    Next,
    Call,
    Jump,
    CondJump,
    IndirectJump,
    Ret,
    /// int3, ud2, hlt, int n: the instruction does not continue normally.
    Trap,
}

/// Where a field of the instruction's bytes lies: (offset in the instruction, size in bytes); size 0: no field.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Field {
    pub at: u8,
    pub size: u8,
}

impl Field {
    fn covers(&self, off: u32) -> bool {
        self.size != 0 && self.at as u32 <= off && off < self.at as u32 + self.size as u32
    }
}

/// Which field of an instruction a byte offset (a relocation's site) falls into.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FieldKind {
    /// the memory operand's displacement (or a moffs absolute address)
    Disp,
    /// the immediate (the first, or `Imm2` the second of enter / extrq)
    Imm,
    Imm2,
    /// a relative branch target
    Branch,
}

/// The general registers as bits (eax=0 .. edi=7, the encoding order), flags as bit 8.
pub type RegSet = u16;
pub const FLAGS: RegSet = 1 << 8;

/// The bit of a register's full 32-bit register (al, ah, ax, eax: eax's bit), 0 for any other register.
pub fn gpr_bit(r: Reg) -> RegSet {
    match gpr(r) {
        Some(n) => 1 << n,
        None => 0,
    }
}

/// The general register a register is part of (eax=0 .. edi=7), None for others.
pub fn gpr(r: Reg) -> Option<u8> {
    if r == Reg::None || !r.is_gpr() || r.size() > 4 {
        return None;
    }
    let f = r.full_register32();
    Some((f as u32 - Reg::EAX as u32) as u8)
}

/// One decoded instruction, typed.
#[derive(Clone, Debug)]
pub struct Ins {
    pub addr: u32,
    pub size: u32,
    pub mnemonic: Mnemonic,
    /// the lower-case mnemonic, prefixes left out (`movsd` of `rep movsd`)
    pub mn: &'static str,
    pub flow: Flow,
    /// a direct call's or jump's target
    pub target: Option<u32>,
    pub ops: Vec<Op>,
    pub disp: Field,
    pub imm: Field,
    pub imm2: Field,
    pub branch: Field,
    /// the registers it reads and writes (partial registers as their full register; a written partial register
    /// counts as read too, the rest of it survives), flags as FLAGS
    pub uses: RegSet,
    pub defs: RegSet,
    pub rep: bool,
    pub instr: Instruction,
}

impl Ins {
    /// The field a byte offset from the instruction's start falls into.
    pub fn field_at(&self, off: u32) -> Option<FieldKind> {
        if self.disp.covers(off) {
            Some(FieldKind::Disp)
        } else if self.imm.covers(off) {
            Some(FieldKind::Imm)
        } else if self.imm2.covers(off) {
            Some(FieldKind::Imm2)
        } else if self.branch.covers(off) {
            Some(FieldKind::Branch)
        } else {
            None
        }
    }

    /// The memory operand, if any.
    pub fn mem(&self) -> Option<&Op> {
        self.ops.iter().find(|o| o.typ == OpType::Mem)
    }

    pub fn text(&self) -> Text {
        text(&self.instr)
    }
}

fn flow(i: &Instruction) -> Flow {
    match i.flow_control() {
        FlowControl::Next | FlowControl::XbeginXabortXend => Flow::Next,
        FlowControl::Call | FlowControl::IndirectCall => Flow::Call,
        FlowControl::UnconditionalBranch => Flow::Jump,
        FlowControl::ConditionalBranch => Flow::CondJump,
        FlowControl::IndirectBranch => Flow::IndirectJump,
        FlowControl::Return => Flow::Ret,
        FlowControl::Interrupt | FlowControl::Exception => Flow::Trap,
    }
}

fn operand(i: &Instruction, k: u32) -> Op {
    let size = || i.memory_size().size() as u8;
    match i.op_kind(k) {
        OpKind::Register => Op::reg(i.op_register(k)),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => Op::imm(i.near_branch_target() as u32 as i64, 4),
        OpKind::FarBranch16 | OpKind::FarBranch32 => Op::imm(i.far_branch32() as i64, 4),
        OpKind::Immediate8 => Op::imm(i.immediate8() as i64, 1),
        OpKind::Immediate8_2nd => Op::imm(i.immediate8_2nd() as i64, 1),
        OpKind::Immediate16 => Op::imm(i.immediate16() as i64, 2),
        OpKind::Immediate32 => Op::imm(i.immediate32() as i32 as i64, 4),
        OpKind::Immediate8to16 => Op::imm(i.immediate8to16() as i64, 2),
        OpKind::Immediate8to32 => Op::imm(i.immediate8to32() as i64, 4),
        OpKind::Immediate64 | OpKind::Immediate8to64 | OpKind::Immediate32to64 => Op::imm(i.immediate(k) as i64, 8),
        OpKind::Memory => {
            let (base, index) = (i.memory_base(), i.memory_index());
            let d = i.memory_displacement32();
            let disp = if base == Reg::None && index == Reg::None { d as i64 } else { d as i32 as i64 };
            let scale = if index == Reg::None { 0 } else { i.memory_index_scale() as u8 };
            Op::mem(i.segment_prefix(), base, index, scale, disp, size())
        }
        OpKind::MemorySegSI | OpKind::MemorySegESI | OpKind::MemorySegRSI => Op::mem(i.segment_prefix(), Reg::ESI, Reg::None, 0, 0, size()),
        OpKind::MemorySegDI | OpKind::MemorySegEDI | OpKind::MemorySegRDI => Op::mem(i.segment_prefix(), Reg::EDI, Reg::None, 0, 0, size()),
        OpKind::MemoryESDI | OpKind::MemoryESEDI | OpKind::MemoryESRDI => Op::mem(Reg::ES, Reg::EDI, Reg::None, 0, 0, size()),
    }
}

fn field(at: usize, size: usize) -> Field {
    if size == 0 { Field::default() } else { Field { at: at as u8, size: size as u8 } }
}

thread_local! {
    static INFO: RefCell<InstructionInfoFactory> = RefCell::new(InstructionInfoFactory::new());
}

fn def_use(i: &Instruction) -> (RegSet, RegSet) {
    INFO.with(|f| {
        let mut f = f.borrow_mut();
        let info = f.info(i);
        let (mut uses, mut defs) = (0, 0);
        for u in info.used_registers() {
            let b = gpr_bit(u.register());
            let partial = u.register().size() < 4;
            match u.access() {
                OpAccess::Read | OpAccess::CondRead => uses |= b,
                OpAccess::Write | OpAccess::CondWrite => {
                    defs |= b;
                    if partial {
                        uses |= b;
                    }
                }
                OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
                    uses |= b;
                    defs |= b;
                }
                _ => {}
            }
        }
        // the memory operands' address registers are reads (used_registers lists them as Read already)
        if i.rflags_read() != 0 {
            uses |= FLAGS;
        }
        if i.rflags_modified() != 0 {
            defs |= FLAGS;
        }
        (uses, defs)
    })
}

fn record(d: &Decoder, i: &Instruction) -> Ins {
    let c: ConstantOffsets = d.get_constant_offsets(i);
    let ops: Vec<Op> = (0..i.op_count()).map(|k| operand(i, k)).collect();
    let flow = flow(i);
    let target = match i.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 if matches!(flow, Flow::Call | Flow::Jump | Flow::CondJump) => Some(i.near_branch_target() as u32),
        _ => None,
    };
    // iced reports a relative branch's displacement as the immediate
    let (imm, branch) = match i.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 => (Field::default(), field(c.immediate_offset(), c.immediate_size())),
        _ => (field(c.immediate_offset(), c.immediate_size()), Field::default()),
    };
    let (uses, defs) = def_use(i);
    Ins {
        addr: i.ip32(),
        size: i.len() as u32,
        mnemonic: i.mnemonic(),
        mn: mnemonic_name(i.mnemonic()),
        flow,
        target,
        ops,
        disp: field(c.displacement_offset(), c.displacement_size()),
        imm,
        imm2: field(c.immediate_offset2(), c.immediate_size2()),
        branch,
        uses,
        defs,
        rep: i.has_rep_prefix() || i.has_repne_prefix(),
        instr: *i,
    }
}

/// Every instruction of `code` at `va`, typed.
pub fn decode(code: &[u8], va: u32) -> Vec<Ins> {
    let mut out = vec![];
    instructions(code, va, |d, i| out.push(record(d, i)));
    out
}

/// The lower-case name of a mnemonic (`Mnemonic::Movzx` -> "movzx"), interned once per mnemonic.
pub fn mnemonic_name(m: Mnemonic) -> &'static str {
    use std::sync::OnceLock;
    static NAMES: OnceLock<Vec<&'static str>> = OnceLock::new();
    let names = NAMES.get_or_init(|| {
        Mnemonic::values().map(|m| &*Box::leak(format!("{m:?}").to_lowercase().into_boxed_str())).collect()
    });
    names[m as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(b: &[u8]) -> String {
        disasm(b, 0x401000).first().map(|t| t.line()).unwrap_or_default()
    }

    #[test]
    fn text() {
        assert_eq!(line(&[0x8b, 0x45, 0xfc]), "mov eax, dword ptr [ebp - 4]");
        assert_eq!(line(&[0x8d, 0x44, 0x8b, 0x10]), "lea eax, [ebx + ecx*4 + 0x10]");
        assert_eq!(line(&[0x6a, 0xff]), "push -1");
        assert_eq!(line(&[0x68, 0xff, 0xff, 0xff, 0xff]), "push 0xffffffff");
        // the same comparison in two encodings reads differently (the source's constant differs in type)
        assert_eq!(line(&[0x66, 0x83, 0x3a, 0xff]), "cmp word ptr [edx], -1");
        assert_eq!(line(&[0x66, 0x81, 0x3a, 0xff, 0xff]), "cmp word ptr [edx], 0xffff");
        assert_eq!(line(&[0x83, 0xe4, 0xf8]), "and esp, -8");
        assert_eq!(line(&[0xb0, 0xff]), "mov al, 0xff");
        assert_eq!(line(&[0xa1, 0x80, 0xb7, 0x5e, 0x00]), "mov eax, dword ptr [0x5eb780]");
        assert_eq!(line(&[0x64, 0xa1, 0, 0, 0, 0]), "mov eax, dword ptr fs:[0]");
        assert_eq!(line(&[0xf3, 0xa5]), "rep movsd");
        assert_eq!(line(&[0xd9, 0xc1]), "fld st(1)");
        assert_eq!(line(&[0xe8, 0, 0, 0, 0]), "call 0x401005");
        assert_eq!(line(&[0x74, 0x05]), "je 0x401007");
        assert_eq!(line(&[0x81, 0xec, 0x00, 0x01, 0, 0]), "sub esp, 0x100");
        assert_eq!(line(&[0xdd, 0x1c, 0x24]), "fstp qword ptr [esp]");
        // stops at the first that does not decode, and at a cut instruction
        assert_eq!(disasm(&[0x90, 0x0f, 0xff, 0x90], 0).len(), 1);
        assert_eq!(disasm(&[0x90, 0xe8, 0, 0], 0).len(), 1);
    }

    #[test]
    fn typed() {
        let i = &decode(&[0x8b, 0x04, 0x8d, 0x80, 0xb7, 0x5e, 0x00], 0x401000)[0];
        assert_eq!(i.mn, "mov");
        let m = i.mem().unwrap();
        assert_eq!((m.base, m.index, m.scale, m.disp, m.size), (Reg::None, Reg::ECX, 4, 0x5eb780, 4));
        assert_eq!(i.field_at(3), Some(FieldKind::Disp));
        assert_eq!(i.field_at(6), Some(FieldKind::Disp));
        assert_eq!(i.field_at(2), None);
        assert_eq!(i.uses, gpr_bit(Reg::ECX));
        assert_eq!(i.defs, gpr_bit(Reg::EAX));
        let c = &decode(&[0xe8, 0x10, 0, 0, 0], 0x401000)[0];
        assert_eq!((c.flow, c.target, c.field_at(1)), (Flow::Call, Some(0x401015), Some(FieldKind::Branch)));
        let j = &decode(&[0x74, 0x05], 0x401000)[0];
        assert_eq!((j.flow, j.target, j.branch), (Flow::CondJump, Some(0x401007), Field { at: 1, size: 1 }));
        let p = &decode(&[0x8a, 0x60, 0x01], 0)[0]; // mov ah, [eax+1]: writes part of eax, keeps the rest
        assert_eq!((p.uses, p.defs), (gpr_bit(Reg::EAX), gpr_bit(Reg::EAX)));
        let x = &decode(&[0x83, 0xe4, 0xf8], 0)[0]; // and esp, -8
        assert_eq!((x.ops[1].imm, x.imm), (-8, Field { at: 2, size: 1 }));
        assert_eq!(x.defs & FLAGS, FLAGS);
    }
}
