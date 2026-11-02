//! isa/x86.py's instruction diff side: the normalised listing (Isa.listing: each line's text and its typed shape,
//! shape.rs, which the explanations of a differing hunk compare), the renaming `dcp asmdiff --regs` prints, and the
//! decoder the walk of an original's slot and S.codewalk read (X86Decoder, over dis.rs's typed instructions).

use crate::shape::Shape;
use regex::{Captures, Regex};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

/// One instruction of a listing (isa/base.Line): its text (numbers that are relocated fields of ours or image
/// addresses read X) and the same as a typed shape.
#[derive(Clone, Debug)]
pub struct Line {
    pub addr: u32,
    pub size: u32,
    pub text: String,
    pub fill: bool,
    pub target: Option<i64>,
    pub shape: Shape,
}

macro_rules! re {
    ($name:ident, $pat:expr) => {
        fn $name() -> &'static Regex {
            static R: OnceLock<Regex> = OnceLock::new();
            R.get_or_init(|| Regex::new($pat).unwrap())
        }
    };
}

re!(hexnum_re, r"0x[0-9a-f]+");
re!(space_re, r"\s+");
re!(reg_re, r"\b(e[abcd]x|e[sd]i|ebp|[abcd][xlh]|[sd]i|bp)\b");

/// int(s, 0) of the numbers the decoder and the listing write (an optional sign, 0x hex or decimal): the test
/// listings' (shape::parse).
#[cfg(test)]
pub fn py_int0(s: &str) -> i64 {
    let (neg, t) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let v = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(h) => i64::from_str_radix(h, 16).unwrap_or(0),
        None => t.parse::<i64>().unwrap_or(0),
    };
    if neg { -v } else { v }
}

/// Python's hex() / format(v, "#x") of a signed value.
pub fn py_hex(v: i64) -> String {
    if v < 0 { format!("-{:#x}", -(v as i128)) } else { format!("{:#x}", v) }
}

// ------------------------------------------------------------------------------------------------ the listing

/// X86.listing: the decoder's text (dis.rs), spaces normalised, and its shape; masked fields (ours: relocated) and
/// every number inside the image read X; a jump with an immediate target outside the masked fields keeps the
/// target.
pub fn listing(code: &[u8], va: u32, mask: Option<&[u8]>, range: (i64, i64), fills: &HashSet<Vec<u8>>) -> Vec<Line> {
    listing_named(code, va, mask, range, fills, &|_, _, _| None)
}

/// How a number that reads X is spelled instead: (instruction address, Some(k): the instruction's k-th masked field
/// in text order, None: a number inside the image; the value) -> the text, None for X.
pub type Namer<'a> = &'a dyn Fn(u32, Option<usize>, i64) -> Option<String>;

/// listing, the numbers that read X spelled by `name` where it gives a text (`dcp asmdiff --symbols`).
pub fn listing_named(code: &[u8], va: u32, mask: Option<&[u8]>, range: (i64, i64), fills: &HashSet<Vec<u8>>, name: Namer) -> Vec<Line> {
    let (lo, hi) = range;
    let mut data = code.to_vec();
    let dummy = (lo as u32).to_le_bytes();
    let mut runs = vec![];
    if let Some(mask) = mask {
        let mut k = 0;
        while k < mask.len() {
            if mask[k] != 0 {
                let mut e = k;
                while e < mask.len() && mask[e] != 0 {
                    e += 1;
                }
                for j in k..e {
                    if j < data.len() {
                        data[j] = dummy[(j - k) % 4];
                    }
                }
                runs.push((k, e));
                k = e;
            } else {
                k += 1;
            }
        }
    }
    let mut out = vec![];
    for ins in crate::dis::decode(&data, va) {
        let (a, size) = (ins.addr, ins.size);
        let t = ins.text();
        let text = space_re().replace_all(&t.line(), " ").into_owned();
        let o = (a - va) as usize;
        // the fields of the instruction our relocations cover, and the values the text shows for them
        let mut fields: Vec<crate::dis::FieldKind> = vec![];
        let mut masked: Vec<u64> = vec![];
        for &(s, e) in &runs {
            if s < o + size as usize && o < e {
                masked.push(lo as u64);
                masked.push((a as u64 + size as u64 + lo as u64) & 0xffff_ffff);
                fields.extend((s.max(o)..e.min(o + size as usize)).filter_map(|j| ins.field_at((j - o) as u32)));
            }
        }
        let shape = Shape::of(&ins, &|f| fields.contains(&f), range);
        let target = if masked.is_empty() && (t.mnemonic.starts_with('j') || t.mnemonic.starts_with("loop")) {
            ins.target.map(|x| x as i64)
        } else {
            None
        };
        let mut k = 0;
        let text = hexnum_re().replace_all(&text, |c: &Captures| {
            let s = &c[0];
            let v = u128::from_str_radix(&s[2..], 16).unwrap_or(u128::MAX);
            if masked.iter().any(|&m| m as u128 == v) {
                k += 1;
                name(a, Some(k - 1), v as i64).unwrap_or_else(|| "X".to_string())
            } else if lo as i128 <= v as i128 && (v as i128) < hi as i128 {
                name(a, None, v as i64).unwrap_or_else(|| "X".to_string())
            } else {
                s.to_string()
            }
        }).into_owned();
        let bytes = &code[o.min(code.len())..(o + size as usize).min(code.len())];
        out.push(Line { addr: a, size, text, fill: fills.contains(bytes), target, shape });
    }
    out
}

#[cfg(test)]
impl Line {
    /// A line of a test listing written as text (its shape parsed from the text: shape::parse).
    pub fn of(addr: u32, text: &str, fill: bool, target: Option<i64>) -> Line {
        Line { addr, size: 1, text: text.to_string(), fill, target, shape: crate::shape::parse(text) }
    }
}

/// diffclass.strip_fill: the listing without its trailing fill.
pub fn strip_fill(mut lines: Vec<Line>) -> Vec<Line> {
    while lines.last().is_some_and(|l| l.fill) {
        lines.pop();
    }
    lines
}

// ------------------------------------------------------------------------------------------------ renaming the text

const GPR_ALL: [&str; 7] = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"];

fn sub_of(r: &str) -> &'static [&'static str] {
    match r {
        "eax" => &["ax", "al", "ah"],
        "ebx" => &["bx", "bl", "bh"],
        "ecx" => &["cx", "cl", "ch"],
        "edx" => &["dx", "dl", "dh"],
        "esi" => &["si"],
        "edi" => &["di"],
        "ebp" => &["bp"],
        _ => &[],
    }
}

pub fn full_reg(r: &str) -> String {
    for big in GPR_ALL {
        if r == big || sub_of(big).contains(&r) {
            return big.to_string();
        }
    }
    r.to_string()
}

type Mapping = Vec<(String, String)>; // a dict: insertion order, unique keys

/// A line with the positions of its register tokens (REG_RE's matches), found once for every renaming tried.
struct Sited<'a> {
    text: &'a str,
    regs: Vec<(usize, usize)>,
}

fn sited(lines: &[String]) -> Vec<Sited<'_>> {
    lines.iter().map(|t| Sited { text: t, regs: reg_re().find_iter(t).map(|m| (m.start(), m.end())).collect() }).collect()
}

/// rename_regs' substitution table: each mapped register and, when both have as many, its parts.
fn sub_table(mapping: &Mapping) -> HashMap<&str, &str> {
    let mut sub: HashMap<&str, &str> = HashMap::new();
    for (k, v) in mapping {
        sub.insert(k, v);
        let (sk, sv) = (sub_of(k), sub_of(v));
        if sk.len() == sv.len() {
            for (a, b) in sk.iter().zip(sv.iter()) {
                sub.insert(a, b);
            }
        }
    }
    sub
}

/// Isa.rename_registers: the lines with the registers renamed (a mapping of full or partial registers; the partial
/// ones follow their full register where both have as many).
pub fn rename_registers(lines: &[String], mapping: &[(String, String)]) -> Vec<String> {
    let mut m: Mapping = vec![];
    for (k, v) in mapping {
        let (k, v) = (full_reg(k), full_reg(v));
        match m.iter_mut().find(|x| x.0 == k) {
            Some(x) => x.1 = v,
            None => m.push((k, v)),
        }
    }
    rename_regs(&sited(lines), &m)
}

fn rename_regs(lines: &[Sited], mapping: &Mapping) -> Vec<String> {
    let sub = sub_table(mapping);
    lines.iter().map(|l| {
        let mut out = String::with_capacity(l.text.len());
        let mut at = 0;
        for &(s, e) in &l.regs {
            out.push_str(&l.text[at..s]);
            let tok = &l.text[s..e];
            out.push_str(sub.get(tok).copied().unwrap_or(tok));
            at = e;
        }
        out.push_str(&l.text[at..]);
        out
    }).collect()
}

// ------------------------------------------------------------------------------------------------ the walk's decoder

pub const OTHER: u8 = 0;
pub const CALL: u8 = 1;
pub const JUMP: u8 = 2;
pub const CJUMP: u8 = 3;
pub const IJUMP: u8 = 4;
pub const RET: u8 = 5;

/// The decoder's text of every instruction of `code` at `va`, unchanged: (address, size, text, fill form?).
pub fn x86_disasm(code: &[u8], va: u32, fill_forms: Vec<Vec<u8>>) -> Vec<(u32, u32, String, bool)> {
    let fills: HashSet<Vec<u8>> = fill_forms.into_iter().collect();
    crate::dis::disasm(code, va).into_iter().map(|i| {
        let o = (i.addr - va) as usize;
        (i.addr, i.size, i.line(), fills.contains(&code[o..(o + i.size as usize).min(code.len())]))
    }).collect()
}

/// isa/base.Ins: one instruction as the walks read it: the typed instruction (dis.rs) and what the walks ask of
/// it, computed once.
#[derive(Clone)]
pub struct WIns {
    pub addr: u32,
    pub size: u32,
    pub mn: &'static str,
    pub flow: u8,
    pub target: Option<i64>,
    pub mem: Vec<(u32, u8)>, // (displacement, operand size) of every memory operand pointing into the image
    pub imms: Vec<i64>,
    pub table: Option<u32>,
    pub fill: bool,
    pub rep: bool, // a rep / repe / repne prefix
    pub ops: Vec<crate::dis::Op>,
}

/// X86Decoder over [lo, hi) of an image: the instruction at an address, decoded once (in batches of 0x400 bytes).
pub struct Decoder<'a> {
    pub lo: u32,
    pub hi: u32,
    pub code: Vec<u8>,
    pub fills: &'a HashSet<Vec<u8>>,
    ibase: u32,
    iend: u32,
    cache: HashMap<u32, WIns>,
}

impl<'a> Decoder<'a> {
    pub fn new(img: &crate::pe::Image, lo: u32, hi: u32, fills: &'a HashSet<Vec<u8>>) -> Decoder<'a> {
        Decoder { lo, hi, code: img.read(lo, (hi - lo) as usize), fills, ibase: img.base, iend: img.end(), cache: HashMap::new() }
    }

    fn in_image(&self, v: u32) -> bool {
        self.ibase <= v && v < self.iend
    }

    fn record(&self, d: crate::dis::Ins) -> WIns {
        use crate::dis::{Flow, OpType, Reg};
        let flow = match d.flow {
            Flow::Call => CALL,
            Flow::Jump => JUMP,
            Flow::CondJump => CJUMP,
            Flow::IndirectJump => IJUMP,
            Flow::Ret => RET,
            Flow::Next | Flow::Trap => OTHER,
        };
        let mem = d.ops.iter()
            .filter(|o| o.typ == OpType::Mem && o.disp != 0 && self.in_image(o.disp as u32))
            .map(|o| (o.disp as u32, o.size))
            .collect();
        let imms = d.ops.iter().filter(|o| o.typ == OpType::Imm).map(|o| o.imm).collect();
        let table = match d.ops.first() {
            Some(o) if flow == IJUMP && d.mn == "jmp" && o.typ == OpType::Mem && o.base == Reg::None && o.index != Reg::None && o.scale == 4 => {
                Some(o.disp as u32)
            }
            _ => None,
        };
        let o = (d.addr - self.lo) as usize;
        let fill = self.fills.contains(&self.code[o..o + d.size as usize]);
        WIns { addr: d.addr, size: d.size, mn: d.mn, flow, target: d.target.map(|t| t as i64), mem, imms, table, fill, rep: d.rep, ops: d.ops }
    }

    /// The instruction at a (None outside [lo, hi) or where the bytes do not decode).
    pub fn at(&mut self, a: u32) -> Option<&WIns> {
        if !(self.lo <= a && a < self.hi) {
            return None;
        }
        if !self.cache.contains_key(&a) {
            let o = (a - self.lo) as usize;
            let end = (o + 0x400).min(self.code.len());
            for d in crate::dis::decode(&self.code[o..end], a) {
                if !self.cache.contains_key(&d.addr) {
                    let r = self.record(d);
                    self.cache.insert(r.addr, r);
                }
            }
        }
        self.cache.get(&a)
    }

    /// X86Decoder.table_shape: (bound, byte index table) from the instructions before the jump.
    pub fn table_shape(&self, recent: &[WIns]) -> (Option<i64>, Option<u32>) {
        use crate::dis::{OpType, Reg};
        let (mut bound, mut byte_tbl) = (None, None);
        for r in recent[..recent.len() - 1].iter().rev() {
            if !matches!(r.mn, "cmp" | "movzx" | "mov") || r.ops.len() != 2 {
                continue;
            }
            let (a, b) = (&r.ops[0], &r.ops[1]);
            if r.mn == "cmp" && b.typ == OpType::Imm && a.typ == OpType::Reg && bound.is_none() && (0..0x400).contains(&b.imm) {
                bound = Some(b.imm + 1);
            }
            if r.mn != "cmp" && b.typ == OpType::Mem && b.size == 1 && (b.index != Reg::None || b.base != Reg::None) && byte_tbl.is_none() {
                let disp = b.disp as u32;
                if self.lo <= disp && disp < self.hi {
                    byte_tbl = Some(disp);
                }
            }
        }
        (bound, byte_tbl)
    }

    /// X86Decoder.field_starts: where a 4-byte immediate or displacement field may start inside ins.
    pub fn field_starts(ins: &WIns) -> std::ops::Range<u32> {
        ins.addr + 1..(ins.addr + ins.size).saturating_sub(3).max(ins.addr + 1)
    }

    pub fn read_entry(&self, a: u32) -> u32 {
        let o = (a - self.lo) as usize;
        u32::from_le_bytes([self.code[o], self.code[o + 1], self.code[o + 2], self.code[o + 3]])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::testpe::{build_with, BASE, DATA, TEXT};

    fn decoder<'a>(img: &crate::pe::Image, len: u32, fills: &'a HashSet<Vec<u8>>) -> Decoder<'a> {
        Decoder::new(img, BASE + TEXT, BASE + TEXT + len, fills)
    }

    #[test]
    fn decoder_flows_and_table_shape() {
        let a = BASE + TEXT;
        let mut code: Vec<u8> = vec![0xe8, 0x0b, 0, 0, 0, 0x74, 0x02, 0xeb, 0xfe, 0xff, 0xe0, 0xc3, 0x90, 0x8b, 0xff, 0xcc, 0xa1];
        code.extend((BASE + DATA).to_le_bytes()); // mov eax, [data]
        let img = crate::pe::Image::parse(build_with(None, Some(&code))).unwrap();
        let fills: HashSet<Vec<u8>> = [vec![0x90u8], vec![0xcc], vec![0x8b, 0xff]].into_iter().collect();
        let mut dec = decoder(&img, code.len() as u32, &fills);
        let at = |dec: &mut Decoder, x: u32| dec.at(a + x).unwrap().clone();
        let i = at(&mut dec, 0);
        assert_eq!((i.flow, i.target, i.size), (CALL, Some((a + 0x10) as i64), 5));
        let i = at(&mut dec, 5);
        assert_eq!((i.flow, i.target), (CJUMP, Some((a + 9) as i64)));
        let i = at(&mut dec, 7);
        assert_eq!((i.flow, i.target), (JUMP, Some((a + 7) as i64)));
        let i = at(&mut dec, 9);
        assert_eq!((i.flow, i.target, i.table), (IJUMP, None, None));
        assert!(at(&mut dec, 0xb).flow == RET && at(&mut dec, 0xc).fill && at(&mut dec, 0xd).fill && at(&mut dec, 0xf).fill);
        let i = at(&mut dec, 0x10);
        assert!(i.flow == OTHER && i.mem == vec![(BASE + DATA, 4)] && !i.fill);
        assert_eq!(Decoder::field_starts(&i).collect::<Vec<_>>(), vec![a + 0x11]);
        // a table jump after its bound check
        let mut code: Vec<u8> = vec![0x83, 0xf8, 0x03, 0x77, 0x00, 0xff, 0x24, 0x85];
        code.extend((a + 0x10).to_le_bytes());
        code.extend([0u8; 16]);
        let img = crate::pe::Image::parse(build_with(None, Some(&code))).unwrap();
        let mut dec = decoder(&img, code.len() as u32, &fills);
        let recent: Vec<WIns> = [0u32, 3, 5].iter().map(|&x| at(&mut dec, x)).collect();
        assert_eq!((recent[2].flow, recent[2].table), (IJUMP, Some(a + 0x10)));
        assert_eq!(dec.table_shape(&recent), (Some(4), None));
    }
}
