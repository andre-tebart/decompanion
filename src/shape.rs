//! The typed shape of a listing line and the explanations of a differing hunk over it (diffclass.rs reads them).
//!
//! A `Shape` is one instruction as the instruction diff compares it: the mnemonic, the rep prefix and the operands
//! (registers, immediates, memory with segment / size / base / index / scale / displacement), every number that
//! is a relocated field or an address inside the image reading `X`, as the listing's text does. The explanations
//! are structural checks on shapes:
//! - `regs`: equal under one bijective renaming of general registers (a part of a register follows its register);
//! - `slots`: equal under such a renaming and a bijective remap of stack slots (`[esp + N]` / `[ebp + N]`);
//! - `order`: the same instructions in another order, after a renaming; across a push / pop with the esp offsets
//!   taken at the hunk's start, also with a slot remap;
//! - `sib`: base and index of `[r1 + r2 + disp]` exchanged;
//! - `fpu`: only FPU instructions differ (and the same ones with the stack registers masked: other stack order);
//! - `frame`: stack offsets shifted by the difference of two frame sizes.
//! A renaming is found by unifying the two sides once (linear), not by trying permutations; only `order`, which
//! compares multisets, tries them.

use crate::dis::{self, Reg};
use crate::x86::py_hex;
use std::collections::{BTreeSet, HashMap, HashSet};

/// A number of an operand: its value, `X` (a relocated field of ours, an address inside the image), or masked by a
/// comparison (stack_mask's slot offsets and frame sizes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Num {
    V(i64),
    X,
    Masked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Opnd {
    Reg(Reg),
    Imm(Num),
    /// [seg: base + index*scale + disp], size bytes (0: no size, lea); registers Reg::None where absent
    Mem { seg: Reg, size: u8, base: Reg, index: Reg, scale: u8, disp: Num },
}

/// One instruction as the diff compares it.
#[derive(Clone, Debug)]
pub struct Shape {
    pub mn: &'static str,
    /// 0 none, 1 rep / repe, 2 repne
    pub rep: u8,
    pub ops: Vec<Opnd>,
    /// the first operand is a 32-bit general register written whole without being read (dis::Ins::kill): its old
    /// value dies here, so a renaming may map it anew
    pub kill: bool,
    /// a push that saves a callee-saved register for the caller (one the function has not written yet), or a pop
    /// that restores one before the return (mark_saves): which register it names is the allocation's choice. It
    /// comes from the function around the line, not from the line: equality, hashing and order leave it out, only
    /// the unification reads it
    pub save: bool,
}

impl Shape {
    fn key(&self) -> (&'static str, u8, &[Opnd], bool) {
        (self.mn, self.rep, &self.ops, self.kill)
    }
}

impl PartialEq for Shape {
    fn eq(&self, o: &Shape) -> bool {
        self.key() == o.key()
    }
}

impl Eq for Shape {}

impl std::hash::Hash for Shape {
    fn hash<H: std::hash::Hasher>(&self, h: &mut H) {
        self.key().hash(h)
    }
}

impl PartialOrd for Shape {
    fn partial_cmp(&self, o: &Shape) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}

impl Ord for Shape {
    fn cmp(&self, o: &Shape) -> std::cmp::Ordering {
        self.key().cmp(&o.key())
    }
}

/// A register no instruction of x86-32 names: what a masked register reads (shape_keys).
const ANY: Reg = Reg::EIP;

/// The general registers a renaming may exchange (esp never).
pub const RENAMABLE: u8 = 0b1110_1111;
const ESP: u8 = 4;
const EBP: u8 = 5;

impl Shape {
    /// The shape of a decoded instruction. `masked(field)`: the field is one of our relocated fields (it reads X);
    /// `range`: the image's addresses (a number inside reads X).
    pub fn of(ins: &dis::Ins, masked: &dyn Fn(dis::FieldKind) -> bool, range: (i64, i64)) -> Shape {
        let x = |v: i64| if range.0 <= v.abs() && v.abs() < range.1 { Num::X } else { Num::V(v) };
        let branch = ins.target.is_some();
        let mut imms = 0;
        let ops = ins.ops.iter().enumerate().map(|(k, o)| match o.typ {
            dis::OpType::Reg => Opnd::Reg(o.reg),
            dis::OpType::Imm => {
                let field = if branch && k == 0 {
                    dis::FieldKind::Branch
                } else {
                    imms += 1;
                    if imms == 1 { dis::FieldKind::Imm } else { dis::FieldKind::Imm2 }
                };
                Opnd::Imm(if masked(field) { Num::X } else { x(o.imm) })
            }
            dis::OpType::Mem => {
                let disp = if masked(dis::FieldKind::Disp) { Num::X } else { x(o.disp) };
                Opnd::Mem { seg: o.seg, size: o.size, base: o.base, index: o.index, scale: o.scale, disp }
            }
        }).collect();
        let rep = if ins.instr.has_repne_prefix() { 2 } else if ins.rep { 1 } else { 0 };
        Shape { mn: ins.mn, rep, ops, kill: ins.kill, save: false }
    }

    fn is(&self, mn: &str) -> bool {
        self.mn == mn
    }

    /// `sub|add esp, N`: (sub?, N).
    fn esp_adjust(&self) -> Option<(bool, i64)> {
        match (self.mn, self.ops.as_slice()) {
            ("sub" | "add", [Opnd::Reg(Reg::ESP), Opnd::Imm(Num::V(n))]) if *n >= 0 => Some((self.mn == "sub", *n)),
            _ => None,
        }
    }

    pub fn fpu(&self) -> bool {
        self.mn.starts_with('f')
    }

    fn map_ops(&self, f: impl Fn(&Opnd) -> Opnd) -> Shape {
        Shape { ops: self.ops.iter().map(f).collect(), ..self.clone() }
    }
}

/// A stack slot: a memory operand of base esp or ebp alone (`[esp + N]`).
fn slot(o: &Opnd) -> Option<(Reg, Num)> {
    match *o {
        Opnd::Mem { base: b @ (Reg::ESP | Reg::EBP), index: Reg::None, disp, .. } => Some((b, disp)),
        _ => None,
    }
}

/// The general registers (eax=0 .. edi=7) a line names, any part of them.
fn gprs(s: &Shape) -> impl Iterator<Item = u8> + '_ {
    s.ops.iter().flat_map(|o| match *o {
        Opnd::Reg(r) => [Some(r), None],
        Opnd::Mem { base, index, .. } => [Some(base), Some(index)],
        Opnd::Imm(_) => [None, None],
    }).flatten().filter_map(|r| dis::gpr(r))
}

// ------------------------------------------------------------------------------------------------ unification

/// What a renaming maps a stack slot by: its offset (explain: the base follows the register renaming), or its base
/// and offset (one_renaming: a slot is a name of its own, like a register).
#[derive(Clone, Copy, PartialEq)]
enum Slots {
    None,
    ByOffset,
    ByBaseAndOffset,
}

/// What a register of one side corresponds to while the walk goes on: nothing yet, a register of the other side,
/// or nothing any more (its partner was overwritten while it lives on: reading it does not correspond).
#[derive(Clone, Copy, PartialEq, Debug)]
enum Bind {
    Free,
    To(u8),
    Dead,
}

/// A renaming found by walking two sides together: registers ours -> theirs (bijective, over `allowed`), and with
/// slots on, stack slots ours -> theirs (bijective). With `kill` on, a register both sides overwrite at the same
/// line (Shape::kill) may be mapped anew there: the old values are dead, and the old partners lose theirs.
struct Unify {
    allowed: u8,
    fwd: [Bind; 8],
    back: [Bind; 8],
    kill: bool,
    /// every pair the renaming has made, in order (a register may map to two over a hunk: before and after it is
    /// overwritten)
    pairs: Vec<(u8, u8)>,
    slots: Slots,
    sfwd: HashMap<(Reg, Num), (Reg, Num)>,
    sback: HashMap<(Reg, Num), (Reg, Num)>,
}

impl Unify {
    fn new(allowed: u8, slots: Slots) -> Unify {
        Unify { allowed, fwd: [Bind::Free; 8], back: [Bind::Free; 8], kill: false, pairs: vec![], slots, sfwd: HashMap::new(), sback: HashMap::new() }
    }

    /// The same with the map renewed where both sides overwrite a register (explain's classes: a hunk reuses a
    /// register once its value is dead; one_renaming stays one map for the function).
    fn renewing(allowed: u8, slots: Slots) -> Unify {
        Unify { kill: true, ..Unify::new(allowed, slots) }
    }

    /// Both registers general and renamable, of the same part: Ok((ours, theirs)); else Err(whether they are the
    /// same register, which they must be).
    fn renamable(&self, a: Reg, b: Reg) -> Result<(u8, u8), bool> {
        let (Some((ga, pa)), Some((gb, pb))) = (dis::gpr_part(a), dis::gpr_part(b)) else { return Err(a == b) };
        let (ra, rb) = (self.allowed & 1 << ga != 0, self.allowed & 1 << gb != 0);
        if !ra || !rb {
            return Err(a == b && !ra && !rb);
        }
        if pa != pb {
            return Err(false);
        }
        Ok((ga, gb))
    }

    fn bind(&mut self, ga: u8, gb: u8) {
        self.fwd[ga as usize] = Bind::To(gb);
        self.back[gb as usize] = Bind::To(ga);
        if !self.pairs.contains(&(ga, gb)) {
            self.pairs.push((ga, gb));
        }
    }

    fn reg(&mut self, a: Reg, b: Reg) -> bool {
        let (ga, gb) = match self.renamable(a, b) {
            Ok(p) => p,
            Err(same) => return same,
        };
        match (self.fwd[ga as usize], self.back[gb as usize]) {
            (Bind::Free, Bind::Free) => {
                self.bind(ga, gb);
                true
            }
            (f, _) => f == Bind::To(gb),
        }
    }

    /// Both sides overwrite a and b whole: they correspond from here on. The old partners lose their
    /// correspondence: the value each of them corresponded to is gone.
    fn renew(&mut self, a: Reg, b: Reg) -> bool {
        let (ga, gb) = match self.renamable(a, b) {
            Ok(p) => p,
            Err(same) => return same,
        };
        if let Bind::To(t) = self.fwd[ga as usize] {
            if t != gb {
                self.back[t as usize] = Bind::Dead;
            }
        }
        if let Bind::To(t) = self.back[gb as usize] {
            if t != ga {
                self.fwd[t as usize] = Bind::Dead;
            }
        }
        self.bind(ga, gb);
        true
    }

    fn slot(&mut self, a: (Reg, Num), b: (Reg, Num)) -> bool {
        let (ka, kb) = match self.slots {
            Slots::ByOffset => {
                if !self.reg(a.0, b.0) {
                    return false;
                }
                ((Reg::None, a.1), (Reg::None, b.1))
            }
            _ => (a, b),
        };
        match (self.sfwd.get(&ka), self.sback.get(&kb)) {
            (None, None) => {
                self.sfwd.insert(ka, kb);
                self.sback.insert(kb, ka);
                true
            }
            (f, _) => f == Some(&kb),
        }
    }

    fn op(&mut self, a: &Opnd, b: &Opnd) -> bool {
        match (a, b) {
            (Opnd::Reg(x), Opnd::Reg(y)) => self.reg(*x, *y),
            (Opnd::Imm(x), Opnd::Imm(y)) => x == y,
            (Opnd::Mem { seg: sa, size: za, base: ba, index: ia, scale: ca, disp: da },
             Opnd::Mem { seg: sb, size: zb, base: bb, index: ib, scale: cb, disp: db }) => {
                if sa != sb || za != zb || ca != cb {
                    return false;
                }
                if self.slots != Slots::None {
                    if let (Some(x), Some(y)) = (slot(a), slot(b)) {
                        return self.slot(x, y);
                    }
                }
                da == db && self.reg(*ba, *bb) && self.reg(*ia, *ib)
            }
            _ => false,
        }
    }

    fn line(&mut self, a: &Shape, b: &Shape) -> bool {
        if a.mn != b.mn || a.rep != b.rep || a.ops.len() != b.ops.len() {
            return false;
        }
        // a register saved for the caller on both sides (or restored): the allocation picked which
        if a.save && b.save {
            return true;
        }
        if self.kill && a.kill && b.kill {
            if let (Opnd::Reg(x), Opnd::Reg(y)) = (a.ops[0], b.ops[0]) {
                // what it reads first (`mov esi, [esi + 0x10]` reads the old esi), then the overwrite
                return a.ops[1..].iter().zip(&b.ops[1..]).all(|(x, y)| self.op(x, y)) && self.renew(x, y);
            }
        }
        a.ops.iter().zip(&b.ops).all(|(x, y)| self.op(x, y))
    }

    fn all(&mut self, a: &[Shape], b: &[Shape]) -> bool {
        a.len() == b.len() && a.iter().zip(b).all(|(x, y)| self.line(x, y))
    }
}

// ------------------------------------------------------------------------------------------------ renamings

/// A renaming of the general registers, total over the 8 (identity where not renamed).
pub type RegMap = [u8; 8];

fn identity() -> RegMap {
    [0, 1, 2, 3, 4, 5, 6, 7]
}

/// The shape with its registers renamed (a part of a register follows its register; a part the other register does
/// not have stays).
pub fn rename(s: &Shape, m: &RegMap) -> Shape {
    let r = |x: Reg| match dis::gpr_part(x) {
        Some((g, p)) => dis::gpr_reg(m[g as usize], p).unwrap_or(x),
        None => x,
    };
    s.map_ops(|o| match *o {
        Opnd::Reg(x) => Opnd::Reg(r(x)),
        Opnd::Mem { seg, size, base, index, scale, disp } => Opnd::Mem { seg, size, base: r(base), index: r(index), scale, disp },
        i => i,
    })
}

/// The register map of `name->name` pairs (`asmdiff --regs`, an order note's renaming); None for a name that is no
/// general register.
pub fn reg_map(pairs: &[(String, String)]) -> Option<RegMap> {
    let full = |n: &str| (0..8u8).flat_map(|g| (0..4u8).map(move |p| (g, p))).find(|&(g, p)| dis::gpr_reg(g, p).is_some_and(|r| dis::reg_name(r) == n)).map(|x| x.0);
    let mut m = identity();
    for (k, v) in pairs {
        m[full(k)? as usize] = full(v)?;
    }
    Some(m)
}

fn name(g: u8) -> String {
    dis::reg_name(dis::gpr_reg(g, 0).unwrap())
}

/// The registers the renaming moves, as the notes write them (`eax->ecx edx->eax`: ours -> the original's), in the
/// order of our names.
fn reg_desc(u: &Unify) -> String {
    let mut pairs: Vec<(String, String)> = u.pairs.iter().filter(|p| p.0 != p.1).map(|&(g, t)| (name(g), name(t))).collect();
    pairs.sort();
    pairs.iter().map(|(k, v)| format!("{k}->{v}")).collect::<Vec<_>>().join(" ")
}

/// A stack offset as the text writes it inside the brackets (`` for 0, ` + 0x10`, ` - 4`).
fn offset(n: Num) -> String {
    let small = |v: i64| if v <= 9 { v.to_string() } else { format!("{v:#x}") };
    match n {
        Num::V(0) => String::new(),
        Num::V(v) if v > 0 => format!(" + {}", small(v)),
        Num::V(v) => format!(" - {}", small(-v)),
        Num::X => " + X".into(),
        Num::Masked => " S".into(),
    }
}

fn slot_desc(pairs: &[(String, String)]) -> String {
    let or0 = |s: &str| if s.is_empty() { "+0".to_string() } else { s.to_string() };
    pairs.iter().map(|(k, v)| format!("[{}]->[{}]", or0(k), or0(v))).collect::<Vec<_>>().join(" ")
}

/// The slot offsets the remap moves (Slots::ByOffset), ours -> the original's, in the order of ours.
fn slot_pairs(u: &Unify) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = u.sfwd.iter().filter(|(k, v)| k != v).map(|(k, v)| (offset(k.1), offset(v.1))).collect();
    pairs.sort();
    pairs
}

/// itertools.permutations(range(n)) in its order (lexicographic in the positions), until f says stop.
fn permutations(n: usize, mut f: impl FnMut(&[usize]) -> bool) {
    let mut p: Vec<usize> = (0..n).collect();
    loop {
        if f(&p) {
            return;
        }
        let Some(i) = (0..n.saturating_sub(1)).rev().find(|&i| p[i] < p[i + 1]) else { return };
        let j = (i + 1..n).rev().find(|&j| p[j] > p[i]).unwrap();
        p.swap(i, j);
        p[i + 1..].reverse();
    }
}

fn multiset_eq(a: &[Shape], b: &[Shape]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let (mut x, mut y) = (a.to_vec(), b.to_vec());
    x.sort();
    y.sort();
    x == y
}

// ------------------------------------------------------------------------------------------------ masks

/// The line with its registers masked (but esp): what a renaming cannot change.
fn mask_regs(s: &Shape) -> Shape {
    let m = |r: Reg| if dis::gpr(r).is_some_and(|g| g != ESP) { ANY } else { r };
    s.map_ops(|o| match *o {
        Opnd::Reg(r) => Opnd::Reg(m(r)),
        Opnd::Mem { seg, size, base, index, scale, disp } => Opnd::Mem { seg, size, base: m(base), index: m(index), scale, disp },
        i => i,
    })
}

/// The line with its stack slots' offsets masked: what a slot remap cannot change.
fn mask_slots(s: &Shape) -> Shape {
    s.map_ops(|o| match (*o, slot(o)) {
        (Opnd::Mem { seg, size, base, index, scale, .. }, Some(_)) => Opnd::Mem { seg, size, base, index, scale, disp: Num::Masked },
        (o, _) => o,
    })
}

/// Each line with its register names and its `[reg +- N]` offsets masked: what no class of a hunk changes but its
/// order (a hunk's lines whose multisets of these differ is code, or fpu, or fill).
pub fn shape_keys(lines: &[Shape]) -> Vec<Shape> {
    lines.iter().map(|s| {
        let m = mask_regs(s);
        m.map_ops(|o| match *o {
            Opnd::Mem { seg, size, base, index: Reg::None, scale, disp: Num::V(_) } if base != Reg::None => {
                Opnd::Mem { seg, size, base, index: Reg::None, scale, disp: Num::Masked }
            }
            o => o,
        })
    }).collect()
}

/// The esp offsets taken at the start of the lines: a push moves the later ones by 4, a pop back, `sub|add esp`.
pub fn esp_normalised(lines: &[Shape]) -> Vec<Shape> {
    let mut delta: i64 = 0;
    lines.iter().map(|s| {
        let d = delta;
        let out = s.map_ops(|o| match *o {
            Opnd::Mem { seg, size, base: Reg::ESP, index: Reg::None, scale, disp: Num::V(v) } => {
                Opnd::Mem { seg, size, base: Reg::ESP, index: Reg::None, scale, disp: Num::V(v - d) }
            }
            o => o,
        });
        if s.is("push") || s.is("pushfd") {
            delta += 4;
        } else if s.is("pop") || s.is("popfd") {
            delta -= 4;
        } else if let Some((sub, n)) = s.esp_adjust() {
            delta += if sub { n } else { -n };
        }
        out
    }).collect()
}

// ------------------------------------------------------------------------------------------------ explain

/// Whether b is a by a renaming and another order: each line of a paired with a line of b of the same masked
/// shape (registers and stack offsets masked; equal ones in their order), the pairs unified into one renaming
/// (registers over `allowed`; with slots, stack offsets too). The renaming, None when the pairs do not unify.
fn reordered(a: &[Shape], b: &[Shape], allowed: u8, slots: Slots) -> Option<Unify> {
    let key = |s: &Shape| mask_slots(&mask_regs(s));
    let mut theirs: HashMap<Shape, std::collections::VecDeque<usize>> = HashMap::new();
    for (j, s) in b.iter().enumerate() {
        theirs.entry(key(s)).or_default().push_back(j);
    }
    let mut u = Unify::new(allowed, slots);
    for x in a {
        let j = theirs.get_mut(&key(x))?.pop_front()?;
        if !u.line(x, &b[j]) {
            return None;
        }
    }
    Some(u)
}

/// The order class by trying the renamings of at most six registers: where pairing the lines by their masked
/// shapes in order pairs the wrong ones (two lines alike but for their registers, reordered).
fn order_by_permutation(xa: &[Shape], xb: &[Shape], toks: &[u8]) -> Option<String> {
    let masked = |l: &[Shape]| l.iter().map(mask_regs).collect::<Vec<_>>();
    if toks.len() > 6 || !multiset_eq(&masked(xa), &masked(xb)) {
        return None;
    }
    let mut got = None;
    permutations(toks.len(), |perm| {
        let mut m = identity();
        for (k, &g) in toks.iter().enumerate() {
            m[g as usize] = toks[perm[k]];
        }
        if m == identity() {
            return false;
        }
        if multiset_eq(&xa.iter().map(|s| rename(s, &m)).collect::<Vec<_>>(), xb) {
            let mut names: Vec<(String, String)> = toks.iter().map(|&g| (name(g), name(m[g as usize]))).filter(|p| p.0 != p.1).collect();
            names.sort();
            got = Some(format!("same instructions, other order, after {}", names.iter().map(|(k, v)| format!("{k}->{v}")).collect::<Vec<_>>().join(" ")));
            return true;
        }
        false
    });
    got
}

/// The renamable registers in a function's context: ebp is the frame pointer (not renamable) when the function
/// sets it up (`mov ebp, esp` among its first lines).
fn allowed_for(context: &[Shape]) -> u8 {
    let frame = context.iter().take(4).any(|s| s.is("mov") && s.ops == [Opnd::Reg(Reg::EBP), Opnd::Reg(Reg::ESP)]);
    if frame { RENAMABLE & !(1 << EBP) } else { RENAMABLE }
}

fn swap_sib(s: &Shape) -> Shape {
    s.map_ops(|o| match *o {
        Opnd::Mem { seg, size, base, index, scale: 1, disp } if dis::gpr_part(base).is_some_and(|p| p.1 == 0) && dis::gpr_part(index).is_some_and(|p| p.1 == 0) => {
            Opnd::Mem { seg, size, base: index, index: base, scale: 1, disp }
        }
        o => o,
    })
}

fn sib_explain(xa: &[Shape], xb: &[Shape]) -> Option<String> {
    if xa.len() != xb.len() {
        return None;
    }
    let mut changed = false;
    for (x, y) in xa.iter().zip(xb) {
        if x == y {
            continue;
        }
        let s = swap_sib(x);
        if s == *x || s != *y {
            return None;
        }
        changed = true;
    }
    changed.then(|| "base/index swapped in [r1 + r2 + disp]".to_string())
}

pub(crate) fn st_masked(s: &Shape) -> Shape {
    s.map_ops(|o| match *o {
        Opnd::Reg(r) if (Reg::ST0 as u32..=Reg::ST7 as u32).contains(&(r as u32)) => Opnd::Reg(Reg::ST0),
        o => o,
    })
}

/// The renaming of registers most of a function agrees on (`asmdiff --regs auto`): the two listings aligned with
/// their registers masked, every aligned pair votes for the registers it pairs (ours -> the original's, whole
/// registers, esp never), and the pairs with the most votes are taken while they stay one-to-one. The pairs that
/// move something, by our names.
pub fn voted_renaming(a: &[Shape], b: &[Shape]) -> Vec<(String, String)> {
    let (ma, mb): (Vec<Shape>, Vec<Shape>) = (a.iter().map(mask_regs).collect(), b.iter().map(mask_regs).collect());
    let mut votes: HashMap<(u8, u8), usize> = HashMap::new();
    let regs = |s: &Shape| -> Vec<Reg> {
        s.ops.iter().flat_map(|o| match *o {
            Opnd::Reg(r) => vec![r],
            Opnd::Mem { base, index, .. } => vec![base, index],
            Opnd::Imm(_) => vec![],
        }).collect()
    };
    for (tag, i1, i2, j1, _) in crate::difflib::opcodes(&ma, &mb) {
        if tag != crate::difflib::Tag::Equal {
            continue;
        }
        for k in 0..i2 - i1 {
            for (x, y) in regs(&a[i1 + k]).into_iter().zip(regs(&b[j1 + k])) {
                if let (Some(gx), Some(gy)) = (dis::gpr(x), dis::gpr(y)) {
                    if RENAMABLE & 1 << gx != 0 && RENAMABLE & 1 << gy != 0 {
                        *votes.entry((gx, gy)).or_default() += 1;
                    }
                }
            }
        }
    }
    let mut ranked: Vec<((u8, u8), usize)> = votes.into_iter().collect();
    ranked.sort_by(|x, y| y.1.cmp(&x.1).then(x.0.cmp(&y.0)));
    let (mut fwd, mut back) = ([false; 8], [false; 8]);
    let mut out = vec![];
    for ((x, y), _) in ranked {
        if !fwd[x as usize] && !back[y as usize] {
            fwd[x as usize] = true;
            back[y as usize] = true;
            if x != y {
                out.push((name(x), name(y)));
            }
        }
    }
    out.sort();
    out
}

/// The callee-saved registers (ebx, ebp, esi, edi).
const CALLEE_SAVED: u8 = 1 << 3 | 1 << 5 | 1 << 6 | 1 << 7;

/// Marks the saves of a function's listing (Shape::save): a `push` of a callee-saved register the function has
/// not written before it (in the listing's order), and the `pop`s of callee-saved registers in the run of pops
/// (and `add esp, N`) right before a `ret`.
pub fn mark_saves(lines: &mut [&mut Shape]) {
    let mut written = 0u8;
    for s in lines.iter_mut() {
        match (s.mn, s.ops.first()) {
            ("push", Some(Opnd::Reg(r))) => {
                if dis::gpr(*r).is_some_and(|g| r.size() == 4 && CALLEE_SAVED & 1 << g != 0 && written & 1 << g == 0) {
                    s.save = true;
                }
            }
            ("cmp" | "test", _) => {}
            (_, Some(Opnd::Reg(r))) => {
                if let Some(g) = dis::gpr(*r) {
                    written |= 1 << g;
                }
            }
            _ => {}
        }
    }
    let rets: Vec<usize> = (0..lines.len()).filter(|&t| lines[t].mn == "ret").collect();
    for t in rets {
        let mut k = t;
        while k > 0 {
            k -= 1;
            let l = &mut lines[k];
            match (l.mn, l.ops.first()) {
                ("pop", Some(Opnd::Reg(r))) if r.size() == 4 && dis::gpr(*r).is_some_and(|g| CALLEE_SAVED & 1 << g != 0) => l.save = true,
                _ if l.esp_adjust().is_some_and(|a| !a.0) => {}
                _ => break,
            }
        }
    }
}

/// Whether two runs of lines are the same code but for a renaming of registers (diffclass's tail class: a block
/// one side shares by a jump and the other has inline).
pub fn same_code(a: &[Shape], b: &[Shape], context: &[Shape]) -> bool {
    a == b || Unify::renewing(allowed_for(context), Slots::None).all(a, b)
}

/// X86.explain: (class, note) of one differing hunk, None when nothing explains it.
pub fn explain(xa: &[Shape], xb: &[Shape], context: &[Shape]) -> Option<(String, String)> {
    let allowed = allowed_for(context);
    // the registers in play, by name (the order a permutation search goes through them)
    let toks: Vec<u8> = {
        let s: BTreeSet<(String, u8)> = xa.iter().chain(xb).flat_map(gprs).filter(|g| allowed & 1 << g != 0).map(|g| (name(g), g)).collect();
        s.into_iter().map(|x| x.1).collect()
    };
    let mut u = Unify::renewing(allowed, Slots::None);
    if u.all(xa, xb) {
        let d = reg_desc(&u);
        if !d.is_empty() {
            return Some(("regs".into(), d));
        }
    }
    let mut u = Unify::renewing(allowed, Slots::ByOffset);
    if u.all(xa, xb) {
        let (rd, sd) = (reg_desc(&u), slot_desc(&slot_pairs(&u)));
        if !sd.is_empty() {
            return Some(("slots".into(), format!("{}{sd}", if rd.is_empty() { String::new() } else { rd + " " })));
        }
    }
    // the same instructions in another order, after a renaming of registers (and of stack offsets): the lines
    // pair by their masked shapes, the pairs unify into one renaming
    if xa.len() == xb.len() {
        let after = |u: &Unify| {
            let parts: Vec<String> = [reg_desc(u), slot_desc(&slot_pairs(u))].into_iter().filter(|x| !x.is_empty()).collect();
            if parts.is_empty() { String::new() } else { format!(", after {}", parts.join(" ")) }
        };
        if let Some(u) = reordered(xa, xb, allowed, Slots::None) {
            return Some(("order".into(), format!("same instructions, other order{}", after(&u))));
        }
        if let Some(note) = order_by_permutation(xa, xb, &toks) {
            return Some(("order".into(), note));
        }
        // across a push / pop the esp offsets move with the push: taken at the hunk's start first, a remap after
        if xa.iter().chain(xb).any(|s| s.is("push") || s.is("pop") || s.esp_adjust().is_some()) {
            let (na, nb) = (esp_normalised(xa), esp_normalised(xb));
            if multiset_eq(&na, &nb) {
                return Some(("order".into(), "same instructions, other order across a push / pop (esp offsets taken at the hunk's start)".into()));
            }
            if let Some(u) = reordered(&na, &nb, allowed, Slots::ByOffset) {
                return Some(("slots".into(), format!("other order across a push / pop (esp offsets taken at the hunk's start){}", after(&u))));
            }
        }
        if let Some(u) = reordered(xa, xb, allowed, Slots::ByOffset) {
            return Some(("order".into(), format!("same instructions, other order{}", after(&u))));
        }
    }
    if let Some(s) = sib_explain(xa, xb) {
        return Some(("sib".into(), s));
    }
    let (sa, sb): (HashSet<&Shape>, HashSet<&Shape>) = (xa.iter().collect(), xb.iter().collect());
    if sa.symmetric_difference(&sb).all(|s| s.fpu()) {
        let norm = |l: &[Shape]| {
            let mut v: Vec<Shape> = l.iter().map(st_masked).collect();
            v.sort();
            v
        };
        return Some(("fpu".into(), if norm(xa) == norm(xb) { "same FPU instructions, other stack order" } else { "FPU instructions differ" }.into()));
    }
    None
}

// ------------------------------------------------------------------------------------------------ dataflow

/// A value of the dataflow comparison: a register's value where the window starts, a number, a memory read at an
/// address, a part of a value (`Low`: the low 16 bits / the low byte / the high byte, gpr_part's numbering), or a
/// value whose part was overwritten (`Set`: the old value, the part, the part's new value).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Val {
    In(u8),
    N(Num),
    Load(u8, Box<Val>),
    Addr(Reg, Vec<Val>, Num),
    Scaled(Box<Val>, u8),
    Low(Box<Val>, u8),
    Set(Box<Val>, u8, Box<Val>),
}

impl Val {
    fn renamed(&self, m: &[u8; 8]) -> Val {
        match self {
            Val::In(g) => Val::In(m[*g as usize]),
            Val::N(n) => Val::N(*n),
            Val::Load(s, a) => Val::Load(*s, Box::new(a.renamed(m))),
            Val::Addr(seg, terms, d) => {
                let mut t: Vec<Val> = terms.iter().map(|x| x.renamed(m)).collect();
                t.sort();
                Val::Addr(*seg, t, *d)
            }
            Val::Scaled(v, s) => Val::Scaled(Box::new(v.renamed(m)), *s),
            Val::Low(v, p) => Val::Low(Box::new(v.renamed(m)), *p),
            Val::Set(v, p, x) => Val::Set(Box::new(v.renamed(m)), *p, Box::new(x.renamed(m))),
        }
    }

    fn inputs(&self, out: &mut BTreeSet<u8>) {
        match self {
            Val::In(g) => {
                out.insert(*g);
            }
            Val::N(_) => {}
            Val::Load(_, a) | Val::Scaled(a, _) | Val::Low(a, _) => a.inputs(out),
            Val::Addr(_, t, _) => t.iter().for_each(|x| x.inputs(out)),
            Val::Set(v, _, x) => {
                v.inputs(out);
                x.inputs(out);
            }
        }
    }
}

/// What a run of `mov`, `cmp` and `test` lines does: the stores (address, size, value), the flag tests (mnemonic,
/// operand values) in order, and the register file at its end. None for any other instruction.
#[allow(clippy::type_complexity)]
fn dataflow_of(lines: &[Shape]) -> Option<(Vec<(Val, u8, Val)>, Vec<(&'static str, Vec<Val>)>, [Val; 8])> {
    let mut regs: [Val; 8] = std::array::from_fn(|g| Val::In(g as u8));
    let (mut stores, mut tests) = (vec![], vec![]);
    let addr = |regs: &[Val; 8], seg: Reg, base: Reg, index: Reg, scale: u8, disp: Num| -> Option<Val> {
        let mut terms = vec![];
        for (r, s) in [(base, 1u8), (index, scale)] {
            if r == Reg::None {
                continue;
            }
            let (g, part) = dis::gpr_part(r)?;
            if part != 0 {
                return None;
            }
            let v = regs[g as usize].clone();
            terms.push(if s > 1 { Val::Scaled(Box::new(v), s) } else { v });
        }
        terms.sort();
        Some(Val::Addr(seg, terms, disp))
    };
    let read = |regs: &[Val; 8], o: &Opnd| -> Option<Val> {
        Some(match *o {
            Opnd::Imm(n) => Val::N(n),
            Opnd::Reg(r) => {
                let (g, part) = dis::gpr_part(r)?;
                let v = &regs[g as usize];
                match v {
                    _ if part == 0 => v.clone(),
                    Val::Set(_, p, x) if *p == part => (**x).clone(),
                    _ => Val::Low(Box::new(v.clone()), part),
                }
            }
            Opnd::Mem { seg, size, base, index, scale, disp } => Val::Load(size, Box::new(addr(regs, seg, base, index, scale, disp)?)),
        })
    };
    for s in lines {
        if s.rep != 0 {
            return None;
        }
        match (s.mn, s.ops.as_slice()) {
            ("mov", [dst, src]) => {
                let v = read(&regs, src)?;
                match *dst {
                    Opnd::Reg(r) => {
                        let (g, part) = dis::gpr_part(r)?;
                        let old = &regs[g as usize];
                        regs[g as usize] = if part == 0 { v } else { Val::Set(Box::new(old.clone()), part, Box::new(v)) };
                    }
                    Opnd::Mem { seg, size, base, index, scale, disp } => stores.push((addr(&regs, seg, base, index, scale, disp)?, size, v)),
                    Opnd::Imm(_) => return None,
                }
            }
            ("cmp" | "test", [a, b]) => tests.push((s.mn, vec![read(&regs, a)?, read(&regs, b)?])),
            _ => return None,
        }
    }
    Some((stores, tests, regs))
}

/// The dataflow class of a hunk the renamings and orders do not explain: both sides `mov`, `cmp` and `test` lines
/// only, with the run of such lines that precedes each (at most 16, as many on both sides) as their common start,
/// that store the same values to the same places, test the same values in the same order and end with the same
/// values in the registers, under one bijective renaming of the registers where the run starts. The registers
/// that hold each value, and the order of the loads and stores, are the allocation's: gildegold
/// ai_TutorialInitChapter3 stores three float constants through [esi+0x64] with the constants loaded into
/// permuted registers in another order. A load reads a value of the address alone (the two sides read the same
/// addresses; which store it follows is the order's).
pub fn dataflow(pre_a: &[Shape], xa: &[Shape], pre_b: &[Shape], xb: &[Shape], context: &[Shape]) -> Option<(String, String)> {
    let eligible = |s: &Shape| matches!(s.mn, "mov" | "cmp" | "test") && s.rep == 0;
    if xa.is_empty() || xb.is_empty() || !xa.iter().chain(xb).all(eligible) || xa.len() + xb.len() > 64 {
        return None;
    }
    let run = |pre: &[Shape]| pre.iter().rev().take(16).take_while(|s| eligible(s)).count();
    let k = run(pre_a).min(run(pre_b));
    let window = |pre: &[Shape], x: &[Shape]| -> Vec<Shape> { pre[pre.len() - k..].iter().chain(x).cloned().collect() };
    let (sa, ta, ra) = dataflow_of(&window(pre_a, xa))?;
    let (sb, tb, rb) = dataflow_of(&window(pre_b, xb))?;
    if sa.len() != sb.len() || ta.len() != tb.len() || (sa.is_empty() && ta.is_empty()) {
        return None;
    }
    let allowed = allowed_for(context);
    let mut ins = BTreeSet::new();
    for (a, _, v) in &sa {
        a.inputs(&mut ins);
        v.inputs(&mut ins);
    }
    for (_, vs) in &ta {
        vs.iter().for_each(|v| v.inputs(&mut ins));
    }
    ra.iter().for_each(|v| v.inputs(&mut ins));
    // the renamed registers: the inputs a renaming may exchange; every other register keeps its name
    let free: Vec<u8> = ins.iter().copied().filter(|g| allowed & 1 << g != 0).collect();
    if free.len() > 7 {
        return None;
    }
    let sorted = |mut v: Vec<(Val, u8, Val)>| {
        v.sort();
        v
    };
    let sb = sorted(sb);
    let mut regs_b: Vec<&Val> = rb.iter().collect();
    regs_b.sort();
    let fits = |m: &[u8; 8]| -> bool {
        sorted(sa.iter().map(|(a, s, v)| (a.renamed(m), *s, v.renamed(m))).collect()) == sb
            && ta.iter().zip(&tb).all(|(x, y)| x.0 == y.0 && x.1.iter().map(|v| v.renamed(m)).collect::<Vec<_>>() == y.1)
            && {
                // the register file at the end, as a multiset: which register holds a value is the allocation's
                let mut r: Vec<Val> = ra.iter().map(|v| v.renamed(m)).collect();
                r.sort();
                r.iter().zip(&regs_b).all(|(x, y)| x == *y) && ra[ESP as usize].renamed(m) == rb[ESP as usize]
            }
    };
    // a bijection of the free inputs onto the allowed registers, the identity first
    let targets: Vec<u8> = (0..8u8).filter(|g| allowed & 1 << g != 0).collect();
    let mut m: [u8; 8] = std::array::from_fn(|g| g as u8);
    fn search(k: usize, free: &[u8], targets: &[u8], used: &mut u8, m: &mut [u8; 8], fits: &dyn Fn(&[u8; 8]) -> bool) -> bool {
        if k == free.len() {
            return fits(m);
        }
        let g = free[k];
        for &t in std::iter::once(&g).chain(targets.iter().filter(|&&t| t != g)) {
            if *used & 1 << t != 0 {
                continue;
            }
            *used |= 1 << t;
            m[g as usize] = t;
            if search(k + 1, free, targets, used, m, fits) {
                return true;
            }
            *used &= !(1 << t);
        }
        m[g as usize] = g;
        false
    }
    let mut used = 0u8;
    if !search(0, &free, &targets, &mut used, &mut m, &fits) {
        return None;
    }
    let renamed: Vec<String> = free.iter().filter(|&&g| m[g as usize] != g).map(|&g| format!("{}->{}", name(g), name(m[g as usize]))).collect();
    let how = if renamed.is_empty() { String::new() } else { format!(", where it starts {}", renamed.join(" ")) };
    Some(("order".into(), format!("the same stores of the same values, other registers and order (dataflow{how})")))
}

// ------------------------------------------------------------------------------------------------ frames

fn frame_size(lines: &[Shape]) -> Option<i64> {
    lines.iter().take(8).find_map(|s| s.esp_adjust().filter(|a| a.0).map(|a| a.1))
}

/// X86.frame_delta: (our frame size, the original's) when both allocate one and the sizes differ.
pub fn frame_delta(a: &[Shape], b: &[Shape]) -> Option<(i64, i64)> {
    match (frame_size(a), frame_size(b)) {
        (Some(fa), Some(fb)) if fa != fb => Some((fa, fb)),
        _ => None,
    }
}

/// An operand that addresses the frame: memory based on esp or ebp, indexed or not (`[esp + eax*4 + 0x10c]`):
/// (base, offset). A frame of another size shifts all of them, not only the slots.
fn frame_off(o: &Opnd) -> Option<(Reg, Num)> {
    match *o {
        Opnd::Mem { base: b @ (Reg::ESP | Reg::EBP), disp, .. } => Some((b, disp)),
        _ => None,
    }
}

/// X86.stack_mask: every frame offset masked (frame_off), a frame-size adjustment `sub|add esp, F` masked.
pub fn stack_mask(lines: &[Shape], frame: (i64, i64)) -> Vec<Shape> {
    lines.iter().map(|s| {
        if let Some((_, n)) = s.esp_adjust() {
            if n == frame.0 || n == frame.1 {
                return Shape { ops: vec![Opnd::Reg(Reg::ESP), Opnd::Imm(Num::Masked)], ..s.clone() };
            }
        }
        s.map_ops(|o| match (*o, frame_off(o)) {
            (Opnd::Mem { seg, size, base, index, scale, .. }, Some(_)) => Opnd::Mem { seg, size, base, index, scale, disp: Num::Masked },
            (o, _) => o,
        })
    }).collect()
}

/// X86.frame_explain: the note of a `frame` hunk, None when the lines differ in more than the frame delta.
pub fn frame_explain(xa: &[Shape], xb: &[Shape], frame: (i64, i64)) -> Option<String> {
    if xa.len() != xb.len() || stack_mask(xa, frame) != stack_mask(xb, frame) {
        return None;
    }
    let d = frame.0 - frame.1;
    let value = |n: Num| match n {
        Num::V(v) => Some(v),
        _ => None,
    };
    for (x, y) in xa.iter().zip(xb) {
        if x == y {
            continue;
        }
        if let (Some(p), Some(q)) = (x.esp_adjust(), y.esp_adjust()) {
            if p.1 - q.1 != d {
                return None;
            }
            continue;
        }
        let oa: Vec<Option<i64>> = x.ops.iter().filter_map(frame_off).map(|s| value(s.1)).collect();
        let ob: Vec<Option<i64>> = y.ops.iter().filter_map(frame_off).map(|s| value(s.1)).collect();
        if oa.len() != ob.len() || oa.iter().zip(&ob).any(|(p, q)| match (p, q) {
            (Some(p), Some(q)) => {
                let e = (p - q).abs();
                e != 0 && e != d.abs()
            }
            _ => p != q,
        }) {
            return None;
        }
    }
    let sign = if d < 0 { "-" } else { "" };
    Some(format!("stack offsets shifted by {sign}{} (frame {} vs {})", py_hex(d.abs()), py_hex(frame.0), py_hex(frame.1)))
}

/// X86.one_renaming: the whole function equal under one bijective renaming of registers and stack slots.
pub fn one_renaming(a: &[Shape], b: &[Shape]) -> bool {
    Unify::new(RENAMABLE, Slots::ByBaseAndOffset).all(a, b)
}

// ------------------------------------------------------------------------------------------------ the text, for tests

/// A shape from a listing line's text (`mov eax, dword ptr [esp + 0x10]`, `je X`): the tests write listings as
/// text. Implicit operands the decoder lists (`fld st(1)`'s st) are not in the text and not in this shape.
#[cfg(test)]
pub fn parse(text: &str) -> Shape {
    fn reg(t: &str) -> Option<Reg> {
        if t == "st" {
            return Some(Reg::ST0);
        }
        if let Some(n) = t.strip_prefix("st(").and_then(|r| r.strip_suffix(')')).and_then(|n| n.parse::<u32>().ok()) {
            return Reg::values().find(|r| *r as u32 == Reg::ST0 as u32 + n);
        }
        Reg::values().find(|r| *r != Reg::None && format!("{r:?}").to_lowercase() == t)
    }
    fn num(t: &str) -> Num {
        if t == "X" { Num::X } else { Num::V(crate::x86::py_int0(t)) }
    }
    fn operand(t: &str) -> Opnd {
        let Some(open) = t.find('[') else {
            return match reg(t) {
                Some(r) => Opnd::Reg(r),
                None => Opnd::Imm(num(t)),
            };
        };
        let head = &t[..open];
        let size = match head.split_whitespace().next().unwrap_or("") {
            "byte" => 1,
            "word" => 2,
            "dword" => 4,
            "fword" => 6,
            "qword" => 8,
            "tbyte" => 10,
            _ => 0,
        };
        let seg = head.rsplit(' ').next().and_then(|s| s.strip_suffix(':')).and_then(reg).unwrap_or(Reg::None);
        let inner = &t[open + 1..t.rfind(']').unwrap()];
        let (mut base, mut index, mut scale, mut disp, mut sign) = (Reg::None, Reg::None, 0u8, Num::V(0), 1i64);
        for tok in inner.split_whitespace() {
            match tok {
                "+" => sign = 1,
                "-" => sign = -1,
                t => {
                    if let Some((r, s)) = t.split_once('*') {
                        index = reg(r).unwrap();
                        scale = s.parse().unwrap();
                    } else if let Some(r) = reg(t) {
                        if base == Reg::None {
                            base = r;
                        } else {
                            index = r;
                            scale = 1;
                        }
                    } else {
                        disp = match num(t) {
                            Num::V(v) => Num::V(sign * v),
                            n => n,
                        };
                    }
                }
            }
        }
        Opnd::Mem { seg, size, base, index, scale, disp }
    }
    let (rep, rest) = match text.split_once(' ') {
        Some(("rep" | "repe", r)) => (1, r),
        Some(("repne", r)) => (2, r),
        _ => (0, text),
    };
    let (mn, ops) = rest.split_once(' ').unwrap_or((rest, ""));
    let mn = iced_x86::Mnemonic::values().map(dis::mnemonic_name).find(|n| *n == mn).unwrap_or_else(|| panic!("no mnemonic {mn}"));
    let ops: Vec<Opnd> = if ops.is_empty() { vec![] } else { ops.split(", ").map(operand).collect() };
    // the instructions the tests write that overwrite their first operand without reading it
    let kill = matches!(mn, "mov" | "lea" | "movzx" | "movsx" | "pop")
        && matches!(ops.first(), Some(Opnd::Reg(r)) if r.size() == 4 && dis::gpr(*r).is_some());
    Shape { mn, rep, ops, kill, save: false }
}

#[cfg(test)]
pub(crate) fn parse_all(lines: &[&str]) -> Vec<Shape> {
    lines.iter().map(|t| parse(t)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cls(a: &[&str], b: &[&str]) -> Option<(String, String)> {
        let (a, b) = (parse_all(a), parse_all(b));
        let ctx: Vec<Shape> = a.iter().chain(&b).cloned().collect();
        explain(&a, &b, &ctx)
    }

    #[test]
    fn shapes_of_decoded_instructions() {
        let range = (0x40_0000, 0x60_0000);
        let one = |b: &[u8], masked: &dyn Fn(dis::FieldKind) -> bool| Shape::of(&dis::decode(b, 0x401000)[0], masked, range);
        let none = |_: dis::FieldKind| false;
        // the decoded shape and the parsed text agree where the text names every operand
        assert_eq!(one(&[0x8b, 0x44, 0x24, 0x10], &none), parse("mov eax, dword ptr [esp + 0x10]"));
        assert_eq!(one(&[0x8d, 0x44, 0x8b, 0x10], &none), parse("lea eax, [ebx + ecx*4 + 0x10]"));
        assert_eq!(one(&[0xa1, 0x80, 0xb7, 0x5e, 0x00], &none), parse("mov eax, dword ptr [X]"));
        assert_eq!(one(&[0xe8, 0, 0, 0, 0], &none), parse("call X"));
        assert_eq!(one(&[0x66, 0x83, 0x3a, 0xff], &none), parse("cmp word ptr [edx], -1"));
        assert_ne!(one(&[0x66, 0x81, 0x3a, 0xff, 0xff], &none), parse("cmp word ptr [edx], -1"));
        // a relocated field reads X whatever its bytes hold; outside the image a number is a number
        assert_eq!(one(&[0xb8, 1, 0, 0, 0], &|f| f == dis::FieldKind::Imm), parse("mov eax, X"));
        assert_eq!(one(&[0xb8, 1, 0, 0, 0], &none), parse("mov eax, 1"));
        assert_eq!(one(&[0xf3, 0xa5], &none).rep, 1);
        assert_eq!(one(&[0xf2, 0xae], &none).rep, 2);
    }

    #[test]
    fn regs_and_slots_by_unification() {
        assert_eq!(cls(&["mov eax, dword ptr [esp + 4]", "add eax, ecx"], &["mov edx, dword ptr [esp + 4]", "add edx, ecx"]),
                   Some(("regs".into(), "eax->edx".into())));
        // parts follow their register
        assert_eq!(cls(&["mov al, byte ptr [ecx]", "movzx eax, al"], &["mov dl, byte ptr [ecx]", "movzx edx, dl"]).unwrap().0, "regs");
        // not a bijection: two of ours to one of theirs
        assert_eq!(cls(&["add eax, ecx", "add edx, ecx"], &["add eax, ecx", "add eax, ecx"]), None);
        // more than six registers in play: a permutation search gave up, the unification does not
        let a = ["mov eax, ebx", "mov ecx, edx", "mov esi, edi", "mov ebp, eax", "add ebx, ecx"];
        let b = ["mov ebx, eax", "mov edx, ecx", "mov edi, esi", "mov ebp, ebx", "add eax, edx"];
        assert_eq!(cls(&a, &b).unwrap().0, "regs");
        // slots: renamed offsets (and registers)
        assert_eq!(cls(&["mov dword ptr [esp + 0x10], eax", "mov ecx, dword ptr [esp + 0x14]"],
                       &["mov dword ptr [esp + 0x14], eax", "mov ecx, dword ptr [esp + 0x10]"]),
                   Some(("slots".into(), "[ + 0x10]->[ + 0x14] [ + 0x14]->[ + 0x10]".into())));
        // the note names what the remap moves: no pair of offsets only the original has
        assert_eq!(cls(&["mov eax, dword ptr [esp + 0x38]"], &["mov eax, dword ptr [esp + 0x34]"]), Some(("slots".into(), "[ + 0x38]->[ + 0x34]".into())));
        // ebp is the frame pointer when the function sets it up: not renamable
        let ctx = parse_all(&["push ebp", "mov ebp, esp"]);
        assert_eq!(explain(&parse_all(&["mov eax, ebp"]), &parse_all(&["mov eax, esi"]), &ctx), None);
    }

    #[test]
    fn esp_offsets_normalised() {
        let lines = parse_all(&["mov dword ptr [esp + 0x10], eax", "push edx", "mov dword ptr [esp + 0x14], eax", "sub esp, 8",
                                "mov dword ptr [esp + 0x1c], eax", "pop ecx", "mov eax, dword ptr [esp]"]);
        assert_eq!(esp_normalised(&lines), parse_all(&["mov dword ptr [esp + 0x10], eax", "push edx", "mov dword ptr [esp + 0x10], eax", "sub esp, 8",
                                                       "mov dword ptr [esp + 0x10], eax", "pop ecx", "mov eax, dword ptr [esp - 8]"]));
    }

    #[test]
    fn store_moved_across_a_push() {
        // ai_CurseWindow of GildeGold.exe: ours stores before the push, the original after it
        let ours = ["mov word ptr [esp + 0xa4], ax", "mov ecx, dword ptr [ebp + 4]", "lea edx, [esp + 0x70]", "mov dword ptr [esp + 0xd0], ecx", "push edx"];
        let orig = ["mov ecx, dword ptr [ebp + 4]", "lea edx, [esp + 0x70]", "push edx", "mov word ptr [esp + 0xa8], ax", "mov dword ptr [esp + 0xd0], ecx"];
        let (c, why) = cls(&ours, &orig).unwrap();
        assert!(c == "slots" && why.contains("across a push"), "{c} {why}");
        let same = ["mov ecx, dword ptr [ebp + 4]", "lea edx, [esp + 0x70]", "push edx", "mov word ptr [esp + 0xa8], ax", "mov dword ptr [esp + 0xd4], ecx"];
        assert_eq!(cls(&ours, &same).unwrap().0, "order");
    }

    #[test]
    fn renaming_renewed_where_a_register_is_overwritten() {
        // gildegold ai_ExecuteMasterBuilder: ours reuses esi once s1 is dead, the original takes eax
        let ours = ["mov esi, dword ptr [esi + 0x10]", "test esi, esi", "cmp esi, 4", "fstp dword ptr [esi*8 + X]"];
        let orig = ["mov eax, dword ptr [esi + 0x10]", "test eax, eax", "cmp eax, 4", "fstp dword ptr [eax*8 + X]"];
        assert_eq!(cls(&ours, &orig), Some(("regs".into(), "esi->eax".into())));
        // the old partner is dead after the overwrite: the original still reading esi there is no renaming
        let orig = ["mov eax, dword ptr [esi + 0x10]", "test eax, eax", "cmp esi, 4", "fstp dword ptr [eax*8 + X]"];
        assert_eq!(cls(&ours, &orig), None);
        // one renaming for the whole function does not renew
        assert!(!one_renaming(&parse_all(&["mov esi, dword ptr [esi + 0x10]", "ret"]), &parse_all(&["mov eax, dword ptr [esi + 0x10]", "ret"])));
    }

    #[test]
    fn renaming_with_another_order() {
        // gildegold ls_ReadSceneRecords: one rotation (eax->ecx, ecx->edx, edx->eax) and a lea moved before a load
        let ours = ["mov ecx, dword ptr [esi + 0x34]", "lea eax, [esi + 0x48]", "push eax", "push ecx", "mov edx, dword ptr [esi + 0x38]", "push edx"];
        let orig = ["lea ecx, [esi + 0x48]", "mov edx, dword ptr [esi + 0x34]", "push ecx", "push edx", "mov eax, dword ptr [esi + 0x38]", "push eax"];
        let (c, n) = cls(&ours, &orig).unwrap();
        assert!(c == "order" && n.ends_with("after eax->ecx ecx->edx edx->eax"), "{c} {n}");
        // seven registers in play: beyond the permutation search, within the pairing
        let ours = ["mov eax, ebx", "mov ecx, edx", "mov esi, edi", "push ebp", "add eax, ecx", "add esi, eax"];
        let orig = ["push ebp", "mov ebx, eax", "mov edx, ecx", "mov edi, esi", "add ebx, edx", "add edi, ebx"];
        assert_eq!(cls(&ours, &orig).unwrap().0, "order");
        // another order and other stack offsets in one hunk (gildegold gv_RankCulpritsAll)
        let ours = ["xor edi, edi", "mov dword ptr [esp + 0x1c], edi", "mov esi, X", "mov dword ptr [esp + 0x20], edi"];
        let orig = ["mov esi, X", "xor edi, edi", "mov dword ptr [esp + 0x20], edi", "mov dword ptr [esp + 0x24], edi"];
        let (c, n) = cls(&ours, &orig).unwrap();
        assert!(c == "order" && n.contains("[ + 0x1c]->[ + 0x20]"), "{c} {n}");
    }

    #[test]
    fn renaming_voted_over_a_function() {
        // surf_Up16-like: one rotation over the whole function, one line that differs otherwise
        let ours = parse_all(&["mov eax, dword ptr [esp + 4]", "mov ecx, dword ptr [eax]", "add ecx, edx", "mov dword ptr [eax], ecx",
                               "inc edx", "mov eax, 1", "ret"]);
        let orig = parse_all(&["mov ecx, dword ptr [esp + 4]", "mov edx, dword ptr [ecx]", "add edx, eax", "mov dword ptr [ecx], edx",
                               "inc eax", "push ebx", "ret"]);
        let v = voted_renaming(&ours, &orig);
        assert_eq!(v, [("eax".to_string(), "ecx".to_string()), ("ecx".into(), "edx".into()), ("edx".into(), "eax".into())]);
    }

    #[test]
    fn saves_are_the_allocations_choice() {
        // gildegold evt_FindLogic: ours saves edi and zeroes it, the original zeroes esi and saves edi
        let marked = |l: &[&str]| {
            let mut v = parse_all(l);
            mark_saves(&mut v.iter_mut().collect::<Vec<_>>());
            v
        };
        let ours = marked(&["push esi", "push edi", "xor edi, edi", "mov eax, edi", "pop edi", "pop esi", "ret"]);
        let orig = marked(&["push esi", "xor esi, esi", "push edi", "mov eax, esi", "pop edi", "pop esi", "ret"]);
        assert!(ours[1].save && orig[2].save && ours[4].save && ours[5].save && !ours[2].save);
        let (c, n) = explain(&ours[1..4], &orig[1..4], &ours).unwrap();
        assert!(c == "order" && n.ends_with("after edi->esi"), "{c} {n}");
        // a push of a register the function has written is an argument, not a save
        let args = marked(&["xor edi, edi", "push edi", "ret"]);
        assert!(!args[1].save);
    }

    #[test]
    fn frame_shift_in_indexed_operands() {
        // gildegold sv_RunLocationScripts: frames 0x21c vs 0x218, an array on the stack indexed by eax
        let f = (0x21c, 0x218);
        let (a, b) = (parse_all(&["mov dword ptr [esp + eax*4 + 0x10c], 0"]), parse_all(&["mov dword ptr [esp + eax*4 + 0x108], 0"]));
        assert_eq!(stack_mask(&a, f), stack_mask(&b, f));
        assert_eq!(frame_explain(&a, &b, f).as_deref(), Some("stack offsets shifted by 0x4 (frame 0x21c vs 0x218)"));
        // another index register is no shift
        assert_eq!(frame_explain(&a, &parse_all(&["mov dword ptr [esp + ecx*4 + 0x108], 0"]), f), None);
    }

    #[test]
    fn one_function_wide_renaming() {
        let a = parse_all(&["mov eax, dword ptr [esp + 4]", "mov ecx, dword ptr [esp + 8]", "add eax, ecx", "ret"]);
        let b = parse_all(&["mov ecx, dword ptr [esp + 8]", "mov eax, dword ptr [esp + 4]", "add ecx, eax", "ret"]);
        assert!(one_renaming(&a, &b));
        let c = parse_all(&["mov ecx, dword ptr [esp + 8]", "mov ecx, dword ptr [esp + 4]", "add ecx, eax", "ret"]);
        assert!(!one_renaming(&a, &c));
        // a register and its part are not one name (gildegold ai_Unk5a91c0: `mov esi, eax` against `mov si, ax`
        // passed as a renaming while the text mapped si to esi)
        assert!(!one_renaming(&parse_all(&["mov esi, eax", "ret"]), &parse_all(&["mov si, ax", "ret"])));
    }

    #[test]
    fn same_stores_through_permuted_registers() {
        // gildegold ai_TutorialInitChapter3: three float constants stored through [esi+0x64], the constants loaded
        // into permuted registers in another order (ecx and edi exchanged where the hunk starts)
        let pre = parse_all(&["mov ebx, 0x428e0000", "mov eax, dword ptr [esi + 0x64]"]);
        let ours = parse_all(&["mov dword ptr [eax + 0x78], edi", "mov edx, dword ptr [esi + 0x64]", "mov edi, 0x447f0000", "mov dword ptr [edx + 0x7c], ecx",
                               "mov eax, dword ptr [esi + 0x64]", "mov ecx, 0x442f0000", "mov edx, 0x44670000", "mov dword ptr [eax + 0x80], ebx",
                               "mov ax, word ptr [X]", "cmp ax, 0x320"]);
        let orig = parse_all(&["mov dword ptr [eax + 0x78], ecx", "mov ecx, dword ptr [esi + 0x64]", "mov dword ptr [ecx + 0x7c], edi",
                               "mov edx, dword ptr [esi + 0x64]", "mov ecx, 0x442f0000", "mov edi, 0x447f0000", "mov dword ptr [edx + 0x80], ebx",
                               "mov ax, word ptr [X]", "cmp ax, 0x320", "mov edx, 0x44670000"]);
        assert_eq!(explain(&ours, &orig, &ours), None);
        let (c, n) = dataflow(&pre, &ours, &pre, &orig, &ours).unwrap();
        assert!(c == "order" && n.contains("ecx->edi edi->ecx"), "{c} {n}");
        // another value stored is no allocation
        let mut other = orig.clone();
        other[5] = parse("mov edi, 0x447e0000");
        assert_eq!(dataflow(&pre, &ours, &pre, &other, &ours), None);
        // nor another register left holding a value the code after reads
        let mut left = orig.clone();
        left[9] = parse("mov edx, 0x44670001");
        assert_eq!(dataflow(&pre, &ours, &pre, &left, &ours), None);
        // an instruction that computes is outside the class
        let mut add = orig.clone();
        add[4] = parse("add ecx, 0x442f0000");
        assert_eq!(dataflow(&pre, &ours, &pre, &add, &ours), None);
    }

    #[test]
    fn slot_remaps_beyond_five_offsets() {
        // gildegold sv_FlyCameraToModel: a moved push shifts three offsets by 4, a fourth local moves; eight
        // offsets in play were beyond the permutation search's limit
        let ours = ["fld dword ptr [esp + 0x38]", "fsub dword ptr [esp + 0x6c]", "fstp dword ptr [esp + 0x2c]", "lea edx, [esp + 0x44]"];
        let orig = ["fld dword ptr [esp + 0x34]", "fsub dword ptr [esp + 0x68]", "fstp dword ptr [esp + 0xb8]", "lea edx, [esp + 0x40]"];
        assert_eq!(cls(&ours, &orig), Some(("slots".into(), "[ + 0x2c]->[ + 0xb8] [ + 0x38]->[ + 0x34] [ + 0x44]->[ + 0x40] [ + 0x6c]->[ + 0x68]".into())));
    }
}
