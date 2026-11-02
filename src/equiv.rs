//! The dataflow-equivalence prover (docs/shape-equiv-plan.md Phase 2, first slice: it reports, it does not grade).
//!
//! Our function and the original's are each cut into basic blocks and walked together from their entries. A pair
//! of blocks is executed symbolically, both sides over the same inputs where a correspondence pairs their
//! locations (registers, stack slots relative to the entry esp); the pair holds when both have the same effects
//! (stores to memory, calls with their pushed arguments, in order) and end alike (a return of the same eax, a jump,
//! a conditional jump on the same condition or the complemented one with the targets swapped). The successors
//! pair up with the locations whose values agree at the end, narrowed to a fixpoint where a pair is reached again;
//! a block may pair with several (a tail one side duplicates). Values are expressions in a hash-consed arena with
//! a linear normal form, so `lea` / `add` / `shl` / a copy through another register / a constant held in a
//! register come out as the same expression.
//!
//! Sound before complete: what it does not model (the FPU, string instructions, switch tables, a stack address that
//! escapes, a carry), it reports as unknown with the place. Our relocated fields hold the addresses the original's
//! aligned fields hold (bind): a symbol is the same address on both sides only through a site where the two
//! instructions line up; an unbound one gets an address the original cannot hold, so nothing it touches is equal.

use crate::dis::{self, Flow, Ins, OpType, Reg};
use std::collections::{BTreeMap, BTreeSet, HashMap};

type E = u32;

/// What a variable stands for: the same key on both sides is the same value.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Var {
    /// the stack pointer at entry
    Sp0,
    /// an argument slot (above the return address) not written since entry, by its offset
    Arg(i32),
    /// the k-th paired location at the entry of pair p (both sides)
    In(u32, u32),
    /// a location of one side only at the entry of pair p (side, location)
    Own(u32, u8, Loc),
    /// a register after the k-th effect (a call) of pair p
    Ret(u32, u32, u8),
    /// where the escaped part of the frame begins (both sides: its layout from there is compared as memory)
    EscBase,
    /// uninitialised stack in the escaped frame, by its offset from the base
    Undef(i32),
    /// the arguments' part of the frame when an argument's address escapes (addressed by their own offsets)
    ArgBase,
    /// the float a call returns (st0 after the k-th effect of pair p)
    FRet(u32, u32),
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
enum Loc {
    Reg(u8),
    Slot(i32),
    /// an x87 register, counted from the bottom of the FPU stack
    Fpu(u8),
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Opc {
    And,
    Or,
    Xor,
    Mul,
    Shl,
    Shr,
    Sar,
    Zx8,
    Zx16,
    Sx8,
    Sx16,
    Ins8Lo,
    Ins8Hi,
    Ins16,
    MulHi,
    IMulHi,
    Div,
    Rem,
    IDiv,
    IRem,
    SxHi,
    /// floats: a 4- / 8-byte memory value read as a float, a float written as 4 / 8 bytes, an integer read as a
    /// float, a float to an integer (fistp), the arithmetic, a constant (its f64 bits, two halves)
    F32,
    F64,
    ToF32,
    ToF64,
    FInt,
    FToInt,
    FAdd,
    FSub,
    FMul,
    FDiv,
    FChs,
    FAbs,
    FSqrt,
    FUnary(u16),
    FConst,
    /// an FPU compare's condition codes (fcom: st0 against the operand), as fnstsw reads them
    FCmp,
    /// the low / high half of an 8-byte value (a double stored to the stack), and the two halves joined
    Lo32,
    Hi32,
    Join64,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Cc {
    E,
    Ne,
    L,
    Ge,
    Le,
    G,
    B,
    Ae,
    Be,
    A,
    /// the sign of a result (js / jns): only while reading flags, a condition holds it as L / Ge against 0
    S,
    Ns,
    /// the parity of a result's low byte (jp / jnp: after an FPU compare's `test ah, mask`)
    P,
    Np,
}

impl Cc {
    fn of(mn: &str) -> Option<Cc> {
        Some(match mn.strip_prefix("set").or_else(|| mn.strip_prefix('j'))? {
            "e" => Cc::E,
            "ne" => Cc::Ne,
            "l" => Cc::L,
            "ge" => Cc::Ge,
            "le" => Cc::Le,
            "g" => Cc::G,
            "b" => Cc::B,
            "ae" => Cc::Ae,
            "be" => Cc::Be,
            "a" => Cc::A,
            "s" => Cc::S,
            "ns" => Cc::Ns,
            "p" => Cc::P,
            "np" => Cc::Np,
            _ => return None,
        })
    }
    /// The same test with the operands exchanged.
    fn mirror(self) -> Cc {
        match self {
            Cc::L => Cc::G,
            Cc::G => Cc::L,
            Cc::Le => Cc::Ge,
            Cc::Ge => Cc::Le,
            Cc::B => Cc::A,
            Cc::A => Cc::B,
            Cc::Be => Cc::Ae,
            Cc::Ae => Cc::Be,
            c => c,
        }
    }
    fn not(self) -> Cc {
        match self {
            Cc::E => Cc::Ne,
            Cc::Ne => Cc::E,
            Cc::L => Cc::Ge,
            Cc::Ge => Cc::L,
            Cc::Le => Cc::G,
            Cc::G => Cc::Le,
            Cc::B => Cc::Ae,
            Cc::Ae => Cc::B,
            Cc::Be => Cc::A,
            Cc::A => Cc::Be,
            Cc::S => Cc::Ns,
            Cc::Ns => Cc::S,
            Cc::P => Cc::Np,
            Cc::Np => Cc::P,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
enum Node {
    Const(u32),
    Var(Var),
    /// c + sum of k * term (terms neither Const nor Lin, sorted, k != 0)
    Lin(u32, Vec<(E, u32)>),
    Op(Opc, Vec<E>),
    /// a load: address, width, memory state (pair, effects before it)
    Load(E, u8, u32, u32),
    /// a condition: compare a with b at a width, tested by cc (1 when it holds)
    Cond(Cc, E, E, u8),
}

#[derive(Default)]
struct Arena {
    nodes: Vec<Node>,
    ids: HashMap<Node, E>,
}

const SP0_KEY: E = 0;

impl Arena {
    fn new() -> Arena {
        let mut a = Arena::default();
        let sp0 = a.mk(Node::Var(Var::Sp0));
        debug_assert_eq!(sp0, SP0_KEY);
        a
    }

    fn mk(&mut self, n: Node) -> E {
        if let Some(&e) = self.ids.get(&n) {
            return e;
        }
        let e = self.nodes.len() as E;
        self.nodes.push(n.clone());
        self.ids.insert(n, e);
        e
    }

    fn c(&mut self, v: u32) -> E {
        self.mk(Node::Const(v))
    }

    fn var(&mut self, v: Var) -> E {
        self.mk(Node::Var(v))
    }

    fn konst(&self, e: E) -> Option<u32> {
        match self.nodes[e as usize] {
            Node::Const(v) => Some(v),
            _ => None,
        }
    }

    fn lin(&self, e: E) -> (u32, Vec<(E, u32)>) {
        match &self.nodes[e as usize] {
            Node::Const(v) => (*v, vec![]),
            Node::Lin(c, t) => (*c, t.clone()),
            _ => (0, vec![(e, 1)]),
        }
    }

    fn from_lin(&mut self, c: u32, mut terms: Vec<(E, u32)>) -> E {
        terms.sort();
        let mut out: Vec<(E, u32)> = vec![];
        for (t, k) in terms {
            match out.last_mut() {
                Some(l) if l.0 == t => l.1 = l.1.wrapping_add(k),
                _ => out.push((t, k)),
            }
        }
        out.retain(|x| x.1 != 0);
        match (c, out.as_slice()) {
            (c, []) => self.c(c),
            (0, [(t, 1)]) => *t,
            _ => self.mk(Node::Lin(c, out)),
        }
    }

    fn add(&mut self, a: E, b: E) -> E {
        let (ca, mut ta) = self.lin(a);
        let (cb, tb) = self.lin(b);
        ta.extend(tb);
        self.from_lin(ca.wrapping_add(cb), ta)
    }

    fn mul_k(&mut self, a: E, k: u32) -> E {
        let (c, t) = self.lin(a);
        let t = t.into_iter().map(|(e, x)| (e, x.wrapping_mul(k))).collect();
        self.from_lin(c.wrapping_mul(k), t)
    }

    fn sub(&mut self, a: E, b: E) -> E {
        let nb = self.mul_k(b, u32::MAX);
        self.add(a, nb)
    }

    /// The expression with a variable replaced (rebuilt through the normal forms).
    fn subst(&mut self, e: E, from: E, to: E) -> E {
        if e == from {
            return to;
        }
        match self.nodes[e as usize].clone() {
            Node::Lin(c, t) => {
                let t = t.into_iter().map(|(x, k)| (self.subst(x, from, to), k)).collect();
                self.from_lin(c, t)
            }
            Node::Op(o, a) => {
                let a = a.into_iter().map(|x| self.subst(x, from, to)).collect();
                self.op(o, a)
            }
            Node::Load(a, w, p, k) => {
                let a = self.subst(a, from, to);
                self.mk(Node::Load(a, w, p, k))
            }
            Node::Cond(cc, a, b, w) => {
                let (a, b) = (self.subst(a, from, to), self.subst(b, from, to));
                self.cond(cc, a, b, w)
            }
            _ => e,
        }
    }

    /// An expression as text (DCP_EQUIV_DEBUG).
    fn show(&self, e: E) -> String {
        match &self.nodes[e as usize] {
            Node::Const(v) => format!("{v:#x}"),
            Node::Var(v) => format!("{v:?}"),
            Node::Lin(c, t) => {
                let mut s: Vec<String> = t.iter().map(|(x, k)| if *k == 1 { self.show(*x) } else { format!("{}*{}", *k as i32, self.show(*x)) }).collect();
                if *c != 0 {
                    s.push(format!("{:#x}", c));
                }
                format!("({})", s.join(" + "))
            }
            Node::Op(o, a) => format!("{o:?}({})", a.iter().map(|&x| self.show(x)).collect::<Vec<_>>().join(", ")),
            Node::Load(a, w, p, k) => format!("[{}]{w}@{p}.{k}", self.show(*a)),
            Node::Cond(c, a, b, w) => format!("{c:?}{w}({}, {})", self.show(*a), self.show(*b)),
        }
    }

    /// Whether two memory accesses (address, width) cannot overlap: the same address but for a constant, the
    /// ranges apart.
    fn apart(&self, a: E, aw: u8, b: E, bw: u8) -> bool {
        let ((ca, ta), (cb, tb)) = (self.lin(a), self.lin(b));
        if ta != tb {
            return false;
        }
        let d = cb.wrapping_sub(ca) as i32 as i64;
        d >= aw as i64 || -d >= bw as i64
    }

    /// The SP0-relative offset of a value (`esp`, `[esp + 8]`'s address), None for anything else.
    fn sp_off(&self, e: E) -> Option<i32> {
        let (c, t) = self.lin(e);
        (t.as_slice() == [(SP0_KEY, 1)]).then_some(c as i32)
    }

    /// Whether a value holds the stack pointer in any form (an address of the frame).
    fn has_sp(&self, e: E) -> bool {
        match &self.nodes[e as usize] {
            Node::Var(Var::Sp0) => true,
            Node::Lin(_, t) => t.iter().any(|x| self.has_sp(x.0)),
            Node::Op(_, a) => a.iter().any(|&x| self.has_sp(x)),
            Node::Load(a, ..) => self.has_sp(*a),
            Node::Cond(_, a, b, _) => self.has_sp(*a) || self.has_sp(*b),
            _ => false,
        }
    }

    fn op(&mut self, o: Opc, mut a: Vec<E>) -> E {
        use Opc::*;
        let ks: Vec<Option<u32>> = a.iter().map(|&x| self.konst(x)).collect();
        if ks.iter().all(|k| k.is_some()) {
            let k: Vec<u32> = ks.into_iter().map(|x| x.unwrap()).collect();
            let v = match (o, k.as_slice()) {
                (And, [x, y]) => x & y,
                (Or, [x, y]) => x | y,
                (Xor, [x, y]) => x ^ y,
                (Mul, [x, y]) => x.wrapping_mul(*y),
                (Shl, [x, y]) => x.wrapping_shl(*y & 31),
                (Shr, [x, y]) => x.wrapping_shr(*y & 31),
                (Sar, [x, y]) => ((*x as i32) >> (*y & 31)) as u32,
                (Zx8, [x]) => x & 0xff,
                (Zx16, [x]) => x & 0xffff,
                (Sx8, [x]) => *x as u8 as i8 as i32 as u32,
                (Sx16, [x]) => *x as u16 as i16 as i32 as u32,
                (Ins8Lo, [x, y]) => (x & !0xff) | (y & 0xff),
                (Ins8Hi, [x, y]) => (x & !0xff00) | ((y & 0xff) << 8),
                (Ins16, [x, y]) => (x & !0xffff) | (y & 0xffff),
                (SxHi, [x]) => if (*x as i32) < 0 { u32::MAX } else { 0 },
                (F32 | F64 | ToF32 | ToF64 | FInt | FToInt | FAdd | FSub | FMul | FDiv | FChs | FAbs | FSqrt | FUnary(_) | FConst | FCmp | Lo32 | Hi32 | Join64, _) => {
                    return self.mk(Node::Op(o, a));
                }
                _ => return self.mk(Node::Op(o, a)),
            };
            return self.c(v);
        }
        match o {
            And | Or | Xor | Mul => {
                a.sort();
                let (x, y) = (a[0], a[1]);
                let ky = self.konst(y).or(self.konst(x));
                let other = if self.konst(y).is_some() { x } else { y };
                match (o, ky) {
                    (And, _) if x == y => return x,
                    (Or, _) if x == y => return x,
                    (Xor, _) if x == y => return self.c(0),
                    (And, Some(0)) | (Mul, Some(0)) => return self.c(0),
                    (Or, Some(u32::MAX)) => return self.c(u32::MAX),
                    (And, Some(u32::MAX)) | (Or, Some(0)) | (Xor, Some(0)) | (Mul, Some(1)) => return other,
                    (And, Some(0xff)) => return self.op(Zx8, vec![other]),
                    (And, Some(0xffff)) => return self.op(Zx16, vec![other]),
                    (Xor, Some(u32::MAX)) => {
                        // not x = -1 - x
                        let m = self.c(u32::MAX);
                        return self.sub(m, other);
                    }
                    (Mul, Some(k)) => return self.mul_k(other, k),
                    _ => {}
                }
            }
            ToF32 | ToF64 => {
                if let Node::Op(f, v) = self.nodes[a[0] as usize].clone() {
                    if (o == ToF32 && f == F32) || (o == ToF64 && f == F64) {
                        return v[0];
                    }
                }
            }
            FAdd | FMul => a.sort(),
            Join64 => {
                if let (Node::Op(Lo32, x), Node::Op(Hi32, y)) = (self.nodes[a[0] as usize].clone(), self.nodes[a[1] as usize].clone()) {
                    if x == y {
                        return x[0];
                    }
                }
            }
            Shl => {
                if let Some(k) = self.konst(a[1]) {
                    return self.mul_k(a[0], 1u32.wrapping_shl(k & 31));
                }
            }
            Zx8 => match self.nodes[a[0] as usize].clone() {
                Node::Op(Zx8, _) => return a[0],
                Node::Load(_, 1, ..) | Node::Cond(..) => return a[0],
                Node::Op(Ins8Lo | Ins16, v) => return self.op(Zx8, vec![v[1]]),
                Node::Op(Zx16 | Ins8Hi, v) => return self.op(Zx8, vec![v[0]]),
                _ => {}
            },
            Zx16 => match self.nodes[a[0] as usize].clone() {
                Node::Op(Zx16 | Zx8, _) => return a[0],
                Node::Load(_, 1 | 2, ..) | Node::Cond(..) => return a[0],
                Node::Op(Ins16, v) => return self.op(Zx16, vec![v[1]]),
                _ => {}
            },
            Sx8 | Sx16 => {
                if let Node::Op(Zx8 | Zx16, v) = self.nodes[a[0] as usize].clone() {
                    let inner = if o == Sx8 { Zx8 } else { Zx16 };
                    if self.nodes[a[0] as usize] == Node::Op(inner, v.clone()) {
                        a[0] = v[0];
                    }
                }
            }
            Ins8Lo => {
                let v = self.op(Zx8, vec![a[1]]);
                if self.konst(a[0]).is_some_and(|k| k & !0xff == 0) {
                    return v;
                }
                if let Node::Op(Ins8Lo, w) = self.nodes[a[0] as usize].clone() {
                    a[0] = w[0];
                }
                a[1] = v;
            }
            Ins16 => {
                let v = self.op(Zx16, vec![a[1]]);
                if self.konst(a[0]).is_some_and(|k| k & !0xffff == 0) {
                    return v;
                }
                a[1] = v;
            }
            _ => {}
        }
        self.mk(Node::Op(o, a))
    }

    /// The value at a width (the low byte / word, zero-extended).
    fn width(&mut self, e: E, w: u8) -> E {
        match w {
            1 => self.op(Opc::Zx8, vec![e]),
            2 => self.op(Opc::Zx16, vec![e]),
            _ => e,
        }
    }

    /// A condition in its canonical form: at 32 bits (a narrower compare's operands zero-extended for an equality or
    /// an unsigned order, sign-extended for a signed one: `cmp eax, 0xffff` on a zero-extended word is `cmp word
    /// ptr, 0xffff`), the operands ordered, cc mirrored with them.
    fn cond(&mut self, cc: Cc, a: E, b: E, w: u8) -> E {
        let (mut a, mut b) = (self.width(a, w), self.width(b, w));
        if w < 4 && matches!(cc, Cc::L | Cc::Ge | Cc::Le | Cc::G) {
            let sx = if w == 1 { Opc::Sx8 } else { Opc::Sx16 };
            a = self.op(sx, vec![a]);
            b = self.op(sx, vec![b]);
        }
        let w = 4;
        if a > b { self.mk(Node::Cond(cc.mirror(), b, a, w)) } else { self.mk(Node::Cond(cc, a, b, w)) }
    }

    /// Whether a value is the same whatever block it is read in: built from constants, the stack pointer, the
    /// arguments and the registers' values at the entry (no block's inputs, loads or call results).
    fn global(&self, e: E) -> bool {
        match &self.nodes[e as usize] {
            Node::Const(_) => true,
            Node::Var(v) => matches!(v, Var::Sp0 | Var::Arg(_) | Var::In(0, _) | Var::Undef(_) | Var::EscBase | Var::ArgBase),
            Node::Lin(_, t) => t.iter().all(|x| self.global(x.0)),
            Node::Op(_, a) => a.iter().all(|&x| self.global(x)),
            Node::Cond(_, a, b, _) => self.global(*a) && self.global(*b),
            Node::Load(..) => false,
        }
    }

    fn not_cond(&mut self, e: E) -> Option<E> {
        match self.nodes[e as usize] {
            Node::Cond(cc, a, b, w) => Some(self.mk(Node::Cond(cc.not(), a, b, w))),
            _ => None,
        }
    }
}

// ------------------------------------------------------------------------------------------------ blocks

#[derive(Clone, Debug)]
enum Term {
    /// to the block at an address
    Jmp(u32),
    /// a conditional jump: the condition's flags, the cc, taken, not taken
    Cond(Cc, u32, u32),
    Ret(u16),
    /// a jump out of the function to a fixed address
    Tail(u32),
}

struct Block {
    ins: Vec<Ins>,
    term: Term,
}

struct Cfg {
    blocks: BTreeMap<u32, Block>,
    entry: u32,
}

/// Why a proof stops: what was met and where (our address, the original's).
#[derive(Clone, Debug, PartialEq)]
pub struct Stop {
    pub why: String,
    pub ours: u32,
    pub theirs: u32,
}

fn cfg(code: &[u8], va: u32) -> Result<Cfg, String> {
    let ins = dis::decode(code, va);
    let end = va + code.len() as u32;
    let inside = |t: u32| va <= t && t < end;
    let mut leaders: BTreeSet<u32> = [va].into();
    for (k, i) in ins.iter().enumerate() {
        match i.flow {
            Flow::Jump | Flow::CondJump => {
                if let Some(t) = i.target.filter(|&t| inside(t)) {
                    leaders.insert(t);
                }
                if let Some(n) = ins.get(k + 1) {
                    leaders.insert(n.addr);
                }
            }
            Flow::Ret | Flow::IndirectJump | Flow::Trap => {
                if let Some(n) = ins.get(k + 1) {
                    leaders.insert(n.addr);
                }
            }
            _ => {}
        }
    }
    let mut blocks = BTreeMap::new();
    let mut cur: Vec<Ins> = vec![];
    // the block being read starts here (a block may be its terminator alone: `ret`, `jmp X`)
    let mut start: Option<u32> = None;
    let flush = |cur: &mut Vec<Ins>, start: &mut Option<u32>, blocks: &mut BTreeMap<u32, Block>, term: Term| {
        if let Some(a) = start.take() {
            blocks.insert(a, Block { ins: std::mem::take(cur), term });
        }
        cur.clear();
    };
    for (k, i) in ins.iter().enumerate() {
        if leaders.contains(&i.addr) && start.is_some() {
            flush(&mut cur, &mut start, &mut blocks, Term::Jmp(i.addr));
        }
        if start.is_none() && i.flow != Flow::Trap {
            start = Some(i.addr);
        }
        let next = ins.get(k + 1).map(|n| n.addr).unwrap_or(end);
        match i.flow {
            Flow::Jump => {
                let t = i.target.ok_or("a jump without a target")?;
                flush(&mut cur, &mut start, &mut blocks, if inside(t) { Term::Jmp(t) } else { Term::Tail(t) });
            }
            Flow::CondJump => {
                let t = i.target.ok_or("a conditional jump without a target")?;
                let cc = Cc::of(i.mn).ok_or_else(|| format!("{} (a condition the prover does not model)", i.mn))?;
                if !inside(t) {
                    return Err("a conditional jump out of the function".into());
                }
                cur.push(i.clone());
                flush(&mut cur, &mut start, &mut blocks, Term::Cond(cc, t, next));
            }
            Flow::Ret => {
                let pop = i.ops.first().map(|o| o.imm as u16).unwrap_or(0);
                flush(&mut cur, &mut start, &mut blocks, Term::Ret(pop));
            }
            Flow::IndirectJump => {
                // a switch's table jump: the tables are not followed yet
                cur.push(i.clone());
                flush(&mut cur, &mut start, &mut blocks, Term::Tail(0));
            }
            Flow::Trap => {
                // int3 fill: nothing reaches it
                cur.clear();
                start = None;
            }
            _ => cur.push(i.clone()),
        }
    }
    flush(&mut cur, &mut start, &mut blocks, Term::Jmp(end));
    Ok(Cfg { blocks, entry: va })
}

impl Cfg {
    /// A block's address through the blocks that are a jump only (layouts that differ by a jump).
    fn thread(&self, mut a: u32) -> u32 {
        for _ in 0..8 {
            match self.blocks.get(&a) {
                Some(b) if b.ins.is_empty() => match b.term {
                    Term::Jmp(t) => a = t,
                    _ => break,
                },
                _ => break,
            }
        }
        a
    }
}

// ------------------------------------------------------------------------------------------------ execution

#[derive(Clone, PartialEq, Debug)]
enum Effect {
    Store(E, u8, E),
    Call(E, Vec<E>),
    /// the frame from an address up becomes memory (its address escapes): the slots it holds then, by their
    /// offset from that address
    Escape(Vec<(i32, E)>),
    /// rep stos: address, count, value, width
    Fill(E, E, E, u8),
    /// rep movs: destination, source, count, width
    Copy(E, E, E, u8),
}

#[derive(Clone, Copy)]
enum Flags {
    Cmp(E, E, u8),
    Test(E, E, u8),
    Res(E, u8),
    /// sahf: the flags from ah (an FPU compare's condition codes)
    Sahf(E),
}

/// The correspondence at a pair's entry: the paired locations, whether the argument slots not yet written are
/// still the arguments (and which were written on either side), the stack pointers, the slots pushed since the
/// last call (a call's arguments), where the escaped part of each frame begins.
#[derive(Clone, PartialEq, Debug)]
struct Corr {
    pairs: Vec<(Loc, Loc)>,
    written: BTreeSet<i32>,
    sp: (i32, i32),
    pushed: (Vec<i32>, Vec<i32>),
    /// the cells a `sub esp` outside the prologue reserved for a call's arguments, not written yet
    reserved: (Vec<i32>, Vec<i32>),
    esc: (Esc, Esc),
    /// the FPU stack's depth on each side
    fpu: (u8, u8),
    /// the locations whose values are known whatever the path (constants, stack addresses, entry values: global),
    /// on each side
    known: (BTreeMap<Loc, E>, BTreeMap<Loc, E>),
}

/// The escaped parts of one side's frame: the locals from `local.1` up to the return address (addressed from the
/// first escaped address, `local.0`, so frames of other sizes line up), the arguments from `args` up (addressed by
/// their offsets).
#[derive(Clone, Copy, PartialEq, Debug, Default)]
struct Esc {
    local: Option<(i32, i32)>,
    args: Option<i32>,
}

/// Where an access goes: a stack slot the model follows as a location, or memory.
enum Place {
    Slot(i32),
    Mem(E),
}

struct Exec<'a> {
    ar: &'a mut Arena,
    pair: u32,
    side: u8,
    corr: &'a Corr,
    regs: [Option<E>; 8],
    slots: BTreeMap<i32, E>,
    read: BTreeSet<Loc>,
    sp: i32,
    /// the offsets pushed since the last call (its arguments), saves of callee-saved registers left out
    pushed: Vec<i32>,
    reserved: Vec<i32>,
    /// the escaped parts of the frame: memory from there on
    esc: Esc,
    flags: Option<Flags>,
    effects: Vec<Effect>,
    written: BTreeSet<i32>,
    /// the callee-saved registers' values at the function's entry: a push of one is a save, not an argument
    saves: Vec<E>,
    /// the instruction after the one being run is `add esp, N` (a call's caller cleans up)
    cleans_up: bool,
    /// still in the entry block's prologue (push ebp / mov ebp, esp / sub esp / saves): a `sub esp` there
    /// allocates the locals, after it the space of a call's arguments
    prologue: bool,
    /// the FPU stack, bottom first
    fpu: Vec<E>,
    /// the last FPU compare's condition codes
    fstatus: Option<E>,
    /// the float the last call returns, when the code reads st0 below the stack's bottom
    fret: Option<E>,
}

const ESP: u8 = 4;

impl Exec<'_> {
    fn new<'a>(ar: &'a mut Arena, pair: u32, side: u8, corr: &'a Corr) -> Exec<'a> {
        let (sp, pushed, esc) = if side == 0 { (corr.sp.0, corr.pushed.0.clone(), corr.esc.0) } else { (corr.sp.1, corr.pushed.1.clone(), corr.esc.1) };
        let reserved = if side == 0 { corr.reserved.0.clone() } else { corr.reserved.1.clone() };
        // the entry pair's registers are In(0, k), k in the order of prove's first correspondence (eax .. edi
        // without esp): ebx 3, ebp 4, esi 5, edi 6
        let saves = (3..7).map(|k| ar.var(Var::In(0, k))).collect();
        Exec { ar, pair, side, corr, regs: [None; 8], slots: BTreeMap::new(), read: BTreeSet::new(), sp, pushed, reserved, esc, flags: None,
               effects: vec![], written: corr.written.clone(), saves, cleans_up: false, fpu: vec![], fstatus: None, fret: None,
               prologue: pair == 0 && corr.sp == (0, 0) }
            .with_fpu(if side == 0 { corr.fpu.0 } else { corr.fpu.1 })
    }

    fn with_fpu(mut self, depth: u8) -> Self {
        self.fpu = (0..depth).map(|k| self.input(Loc::Fpu(k))).collect();
        self
    }

    // ---- the FPU

    /// st(i), reading the last call's float return below the stack's bottom.
    fn st(&mut self, i: usize) -> Result<E, String> {
        if self.fpu.len() <= i {
            match self.fret.take() {
                Some(r) if i == 0 && self.fpu.is_empty() => self.fpu.push(r),
                _ => return Err("an FPU register below the stack's bottom".into()),
            }
        }
        Ok(self.fpu[self.fpu.len() - 1 - i])
    }

    fn set_st(&mut self, i: usize, v: E) -> Result<(), String> {
        self.st(i)?;
        let n = self.fpu.len();
        self.fpu[n - 1 - i] = v;
        Ok(())
    }

    fn fpush(&mut self, v: E) -> Result<(), String> {
        if self.fpu.len() >= 8 {
            return Err("the FPU stack overflows".into());
        }
        self.fret = None;
        self.fpu.push(v);
        Ok(())
    }

    fn fpop(&mut self) -> Result<E, String> {
        self.st(0)?;
        Ok(self.fpu.pop().unwrap())
    }

    fn st_index(r: Reg) -> Option<usize> {
        let k = r as u32;
        (Reg::ST0 as u32..=Reg::ST7 as u32).contains(&k).then(|| (k - Reg::ST0 as u32) as usize)
    }

    /// A float operand: st(i), or a float in memory (4 / 8 bytes), or with `int` an integer in memory.
    fn fval(&mut self, op: &dis::Op, int: bool) -> Result<E, String> {
        match op.typ {
            OpType::Reg => self.st(Self::st_index(op.reg).ok_or("an FPU operand that is no FPU register")?),
            OpType::Mem => {
                let a = self.addr(op)?;
                let v = self.load(a, op.size)?;
                Ok(match (int, op.size) {
                    (true, 2) => {
                        let x = self.ar.op(Opc::Sx16, vec![v]);
                        self.ar.op(Opc::FInt, vec![x])
                    }
                    (true, 4) => self.ar.op(Opc::FInt, vec![v]),
                    (false, 4) => self.ar.op(Opc::F32, vec![v]),
                    (false, 8) => self.ar.op(Opc::F64, vec![v]),
                    (_, w) => return Err(format!("a {w}-byte FPU memory operand")),
                })
            }
            OpType::Imm => Err("an FPU immediate".into()),
        }
    }

    fn fconst(&mut self, v: f64) -> E {
        let b = v.to_bits();
        let (lo, hi) = (self.ar.c(b as u32), self.ar.c((b >> 32) as u32));
        self.ar.op(Opc::FConst, vec![lo, hi])
    }

    /// One x87 instruction; Ok(false) when it is not one.
    fn fstep(&mut self, i: &Ins) -> Result<bool, String> {
        let mn = i.mn;
        if !mn.starts_with('f') && mn != "sahf" {
            return Ok(false);
        }
        let ops = &i.ops;
        // the arithmetic: fadd / fsub / fsubr / fmul / fdiv / fdivr, popping with p, from an integer with fi
        let arith = |m: &str| -> Option<(Opc, bool, bool, bool)> {
            let (int, m) = match m.strip_prefix("fi") { Some(r) => (true, r), None => (false, m.strip_prefix('f')?) };
            let (pop, m) = match m.strip_suffix('p') { Some(r) => (true, r), None => (false, m) };
            let (rev, m) = match m.strip_suffix('r') { Some(r) if r == "sub" || r == "div" => (true, r), _ => (false, m) };
            let o = match m {
                "add" => Opc::FAdd,
                "sub" => Opc::FSub,
                "mul" => Opc::FMul,
                "div" => Opc::FDiv,
                _ => return None,
            };
            Some((o, rev, pop, int))
        };
        match mn {
            "fld" | "fild" => {
                let v = self.fval(&ops[ops.len() - 1], mn == "fild")?;
                self.fpush(v)?;
            }
            "fld1" | "fldz" => {
                let v = self.fconst(if mn == "fld1" { 1.0 } else { 0.0 });
                self.fpush(v)?;
            }
            "fst" | "fstp" | "fist" | "fistp" => {
                let v = self.st(0)?;
                let dst = &ops[0];
                match dst.typ {
                    OpType::Reg => {
                        let k = Self::st_index(dst.reg).ok_or("an FPU store to a register")?;
                        self.set_st(k, v)?;
                    }
                    OpType::Mem => {
                        let w = dst.size;
                        let x = match (mn.starts_with("fi"), w) {
                            (true, 2 | 4) => self.ar.op(Opc::FToInt, vec![v]),
                            (false, 4) => self.ar.op(Opc::ToF32, vec![v]),
                            (false, 8) => self.ar.op(Opc::ToF64, vec![v]),
                            (_, w) => return Err(format!("a {w}-byte FPU store")),
                        };
                        let a = self.addr(dst)?;
                        self.store(a, w, x)?;
                    }
                    _ => return Err("an FPU store to an immediate".into()),
                }
                if mn.ends_with('p') {
                    self.fpop()?;
                }
            }
            "fxch" => {
                let k = ops.iter().filter_map(|o| (o.typ == OpType::Reg).then(|| Self::st_index(o.reg)).flatten()).max().unwrap_or(1);
                let (a, b) = (self.st(0)?, self.st(k)?);
                self.set_st(0, b)?;
                self.set_st(k, a)?;
            }
            "fchs" | "fabs" | "fsqrt" | "fsin" | "fcos" | "frndint" | "f2xm1" => {
                let v = self.st(0)?;
                let o = match mn {
                    "fchs" => Opc::FChs,
                    "fabs" => Opc::FAbs,
                    "fsqrt" => Opc::FSqrt,
                    _ => Opc::FUnary(i.mnemonic as u16),
                };
                let r = self.ar.op(o, vec![v]);
                self.set_st(0, r)?;
            }
            "fcom" | "fcomp" | "fcompp" | "fucom" | "fucomp" | "fucompp" | "ficom" | "ficomp" | "ftst" => {
                let a = self.st(0)?;
                let b = match (mn, ops.len()) {
                    ("ftst", _) => self.fconst(0.0),
                    (_, 0) | (_, 1) if ops.iter().all(|o| o.typ == OpType::Reg && o.reg == Reg::ST0) => self.st(1)?,
                    _ => {
                        let o = ops.iter().rfind(|o| !(o.typ == OpType::Reg && o.reg == Reg::ST0)).copied();
                        match o {
                            Some(o) => self.fval(&o, mn.starts_with("fi"))?,
                            None => self.st(1)?,
                        }
                    }
                };
                self.fstatus = Some(self.ar.op(Opc::FCmp, vec![a, b]));
                let pops = if mn.ends_with("pp") { 2 } else if mn.ends_with('p') { 1 } else { 0 };
                for _ in 0..pops {
                    self.fpop()?;
                }
            }
            "fnstsw" | "fstsw" => {
                let st = self.fstatus.ok_or("fnstsw without an FPU compare in the block")?;
                match ops.first() {
                    Some(o) if o.typ == OpType::Reg => self.set_reg(o.reg, st)?,
                    Some(o) => {
                        let a = self.addr(o)?;
                        self.store(a, 2, st)?;
                    }
                    None => return Err("fnstsw without an operand".into()),
                }
            }
            "sahf" => {
                // CF, PF, ZF from ah: the conditions on them are conditions on ah
                let ah = self.get_reg(Reg::AH)?;
                self.flags = Some(Flags::Sahf(ah));
            }
            "fnstcw" | "fstcw" => {
                let cw = self.ar.op(Opc::FUnary(0xffff), vec![]);
                let a = self.addr(&ops[0])?;
                self.store(a, 2, cw)?;
            }
            "fwait" | "fnop" => {}
            m => {
                let Some((o, rev, pop, int)) = arith(m) else { return Err(format!("{m} (the prover does not model it yet)")) };
                // the destination and the source: (st0, mem), (st0, st(i)), (st(i), st0), or the popping form's
                // st(1), st0 without operands
                let (dk, src) = match ops.as_slice() {
                    [] => (1, self.st(0)?),
                    [d, sop] if d.typ == OpType::Reg => {
                        let dk = Self::st_index(d.reg).ok_or("an FPU destination that is no FPU register")?;
                        (dk, self.fval(sop, int)?)
                    }
                    [sop] => (0, self.fval(sop, int)?),
                    _ => return Err(format!("{m} with these operands")),
                };
                let d = self.st(dk)?;
                let (x, y) = if rev { (src, d) } else { (d, src) };
                let r = self.ar.op(o, vec![x, y]);
                self.set_st(dk, r)?;
                if pop {
                    self.fpop()?;
                }
            }
        }
        Ok(true)
    }


    fn input(&mut self, l: Loc) -> E {
        self.read.insert(l);
        if let Some(&v) = if self.side == 0 { self.corr.known.0.get(&l) } else { self.corr.known.1.get(&l) } {
            return v;
        }
        let k = self.corr.pairs.iter().position(|p| if self.side == 0 { p.0 == l } else { p.1 == l });
        if let Some(k) = k {
            return self.ar.var(Var::In(self.pair, k as u32));
        }
        if let Loc::Slot(o) = l {
            if o > 0 && !self.corr.written.contains(&o) {
                return self.ar.var(Var::Arg(o));
            }
            // a local nothing has written on any path so far (an uninitialised variable, the rest of a cell a byte
            // was stored to): stack garbage on both sides, one value (a program that read it would read garbage
            // either way)
            if o < 0 && !self.corr.written.contains(&o) {
                return self.ar.var(Var::Undef(i32::MIN));
            }
        }
        self.ar.var(Var::Own(self.pair, self.side, l))
    }

    fn reg32(&mut self, g: u8) -> E {
        if g == ESP {
            let c = self.ar.c(self.sp as u32);
            return self.ar.add(SP0_KEY, c);
        }
        match self.regs[g as usize] {
            Some(v) => v,
            None => self.input(Loc::Reg(g)),
        }
    }

    fn get_reg(&mut self, r: Reg) -> Result<E, String> {
        let (g, part) = dis::gpr_part(r).ok_or_else(|| format!("register {}", dis::reg_name(r)))?;
        let v = self.reg32(g);
        Ok(match part {
            0 => v,
            1 => self.ar.op(Opc::Zx16, vec![v]),
            2 => self.ar.op(Opc::Zx8, vec![v]),
            _ => {
                let k = self.ar.c(8);
                let s = self.ar.op(Opc::Shr, vec![v, k]);
                self.ar.op(Opc::Zx8, vec![s])
            }
        })
    }

    fn set_sp(&mut self, off: i32) {
        self.sp = off;
        self.pushed.retain(|&o| o >= off);
        self.reserved.retain(|&o| o >= off);
    }

    fn set_reg(&mut self, r: Reg, v: E) -> Result<(), String> {
        let (g, part) = dis::gpr_part(r).ok_or_else(|| format!("register {}", dis::reg_name(r)))?;
        if g == ESP {
            let off = self.ar.sp_off(v).ok_or("esp set to a value that is not the frame's")?;
            self.set_sp(off);
            return Ok(());
        }
        let nv = match part {
            0 => v,
            1 => {
                let o = self.reg32(g);
                self.ar.op(Opc::Ins16, vec![o, v])
            }
            2 => {
                let o = self.reg32(g);
                self.ar.op(Opc::Ins8Lo, vec![o, v])
            }
            _ => {
                let o = self.reg32(g);
                self.ar.op(Opc::Ins8Hi, vec![o, v])
            }
        };
        self.regs[g as usize] = Some(nv);
        Ok(())
    }

    fn slot(&mut self, o: i32) -> E {
        match self.slots.get(&o) {
            Some(&v) => v,
            None => self.input(Loc::Slot(o)),
        }
    }

    fn set_slot(&mut self, o: i32, v: E) {
        self.written.insert(o);
        // a cell reserved for a call's arguments, written: an argument
        if let Some(k) = self.reserved.iter().position(|&r| r == o) {
            self.reserved.remove(k);
            self.pushed.push(o);
        }
        self.slots.insert(o, v);
    }

    fn in_region(&self, o: i32) -> bool {
        if o < 0 { self.esc.local.is_some_and(|(_, low)| low <= o) } else { self.esc.args.is_some_and(|low| low <= o) }
    }

    fn esc_addr(&mut self, o: i32) -> E {
        let (base, d) = if o < 0 {
            (self.ar.var(Var::EscBase), o - self.esc.local.map(|e| e.0).unwrap_or(0))
        } else {
            (self.ar.var(Var::ArgBase), o)
        };
        let d = self.ar.c(d as u32);
        self.ar.add(base, d)
    }

    /// The frame from offset c up (to the return address) becomes memory: its address escapes (to a call, into
    /// memory, through an index). Its slots' values then are an effect, compared on both sides.
    fn escape(&mut self, c: i32) -> Result<E, String> {
        // the slots from c up to what has escaped before (or to the end of the locals / the arguments) become memory
        let (base, top) = if c < 0 {
            match self.esc.local {
                Some((_, low)) if c >= low => return Ok(self.esc_addr(c)),
                Some((base, low)) => (base, low),
                None => (c, 0),
            }
        } else {
            match self.esc.args {
                Some(low) if c >= low => return Ok(self.esc_addr(c)),
                Some(low) => (0, low),
                None => (0, i32::MAX),
            }
        };
        let mut offs: BTreeSet<i32> = self.slots.keys().copied().filter(|&o| c <= o && o < top).collect();
        for p in &self.corr.pairs {
            if let Loc::Slot(o) = if self.side == 0 { p.0 } else { p.1 } {
                if c <= o && o < top {
                    offs.insert(o);
                }
            }
        }
        let mut region = vec![];
        for o in offs {
            let v = self.slot(o);
            // a slot never written before (the rest of a cell a byte was stored to): uninitialised stack, named by
            // its place in the escaped frame on both sides (a program that read it would read garbage either way)
            let own = self.ar.var(Var::Own(self.pair, self.side, Loc::Slot(o)));
            let undef = self.ar.var(Var::Undef(o - base));
            let v = self.ar.subst(v, own, undef);
            if self.ar.has_sp(v) {
                return Err("a stack address stored in the frame escapes with it".into());
            }
            region.push((o - base, v));
            self.slots.remove(&o);
        }
        self.effects.push(Effect::Escape(region));
        if c < 0 {
            self.esc.local = Some((base, c));
        } else {
            self.esc.args = Some(c);
        }
        Ok(self.esc_addr(c))
    }

    /// A value that leaves the model's locations (an argument, a stored value): a stack address in it escapes.
    fn launder(&mut self, v: E) -> Result<E, String> {
        if !self.ar.has_sp(v) {
            return Ok(v);
        }
        match self.ar.sp_off(v) {
            Some(c) => self.escape(c),
            None => Err("a stack address escapes inside an expression".into()),
        }
    }

    fn place(&mut self, a: E) -> Result<Place, String> {
        if let Some(o) = self.ar.sp_off(a) {
            return Ok(if self.in_region(o) { Place::Mem(self.esc_addr(o)) } else { Place::Slot(o) });
        }
        if !self.ar.has_sp(a) {
            return Ok(Place::Mem(a));
        }
        // an indexed access to the frame: the frame from the base on escapes, the access goes to memory
        let (c, terms) = self.ar.lin(a);
        if terms.iter().filter(|t| t.0 == SP0_KEY).map(|t| t.1).sum::<u32>() != 1 || terms.iter().any(|t| t.0 != SP0_KEY && self.ar.has_sp(t.0)) {
            return Err("a stack address the model does not follow".into());
        }
        let base = self.escape(c as i32)?;
        let rest: Vec<(E, u32)> = terms.into_iter().filter(|t| t.0 != SP0_KEY).collect();
        let r = self.ar.from_lin(0, rest);
        Ok(Place::Mem(self.ar.add(base, r)))
    }

    fn addr(&mut self, op: &dis::Op) -> Result<E, String> {
        if op.seg != Reg::None && op.seg != Reg::DS && op.seg != Reg::SS && op.seg != Reg::ES {
            return Err(format!("a {} segment", dis::reg_name(op.seg)));
        }
        let mut a = self.ar.c(op.disp as u32);
        if op.base != Reg::None {
            let b = self.get_reg(op.base)?;
            a = self.ar.add(a, b);
        }
        if op.index != Reg::None {
            let i = self.get_reg(op.index)?;
            let s = self.ar.mul_k(i, op.scale as u32);
            a = self.ar.add(a, s);
        }
        Ok(a)
    }

    fn load(&mut self, a: E, w: u8) -> Result<E, String> {
        match self.place(a)? {
            Place::Slot(o) => self.slot_load(o, w),
            Place::Mem(m) => {
                // the memory as it was before the stores this load does not overlap (the same base at offsets
                // far enough apart, two constant addresses apart): a load scheduled across such a store is one
                // load; a call, a copy, a fill or an escape ends the search
                let mut k = self.effects.len();
                while k > 0 {
                    match self.effects[k - 1] {
                        Effect::Store(a, sw, _) if self.ar.apart(a, sw, m, w) => k -= 1,
                        _ => break,
                    }
                }
                Ok(self.ar.mk(Node::Load(m, w, self.pair, k as u32)))
            }
        }
    }

    fn slot_load(&mut self, o: i32, w: u8) -> Result<E, String> {
        if w == 8 && o % 4 == 0 {
            let (lo, hi) = (self.slot(o), self.slot(o + 4));
            return Ok(self.ar.op(Opc::Join64, vec![lo, hi]));
        }
        let cell = o.div_euclid(4) * 4;
        let v = self.slot(cell);
        match (w, o - cell) {
            (4, 0) => Ok(v),
            (2, 0) => Ok(self.ar.op(Opc::Zx16, vec![v])),
            (1, 0) => Ok(self.ar.op(Opc::Zx8, vec![v])),
            (1, 1) => {
                let k = self.ar.c(8);
                let s = self.ar.op(Opc::Shr, vec![v, k]);
                Ok(self.ar.op(Opc::Zx8, vec![s]))
            }
            _ => Err(format!("a {w}-byte stack access at an offset the model does not split ({o:#x})")),
        }
    }

    fn store(&mut self, a: E, w: u8, v: E) -> Result<(), String> {
        match self.place(a)? {
            Place::Slot(o) if w == 8 && o % 4 == 0 => {
                let lo = self.ar.op(Opc::Lo32, vec![v]);
                let hi = self.ar.op(Opc::Hi32, vec![v]);
                self.set_slot(o, lo);
                self.set_slot(o + 4, hi);
            }
            Place::Slot(o) => {
                let cell = o.div_euclid(4) * 4;
                let old = self.slot(cell);
                let nv = match (w, o - cell) {
                    (4, 0) => v,
                    (2, 0) => self.ar.op(Opc::Ins16, vec![old, v]),
                    (1, 0) => self.ar.op(Opc::Ins8Lo, vec![old, v]),
                    (1, 1) => self.ar.op(Opc::Ins8Hi, vec![old, v]),
                    _ => return Err(format!("a {w}-byte stack store at an offset the model does not split ({o:#x})")),
                };
                self.set_slot(cell, nv);
            }
            Place::Mem(m) => {
                let v = self.launder(v)?;
                let v = self.ar.width(v, w);
                self.effects.push(Effect::Store(m, w, v));
            }
        }
        Ok(())
    }

    fn get(&mut self, op: &dis::Op) -> Result<E, String> {
        match op.typ {
            OpType::Reg => self.get_reg(op.reg),
            OpType::Imm => Ok(self.ar.c(op.imm as u32)),
            OpType::Mem => {
                let a = self.addr(op)?;
                self.load(a, op.size)
            }
        }
    }

    fn set(&mut self, op: &dis::Op, v: E) -> Result<(), String> {
        match op.typ {
            OpType::Reg => self.set_reg(op.reg, v),
            OpType::Mem => {
                let a = self.addr(op)?;
                self.store(a, op.size, v)
            }
            OpType::Imm => Err("a store to an immediate".into()),
        }
    }

    fn width_of(op: &dis::Op) -> u8 {
        match op.typ {
            OpType::Reg => op.reg.size() as u8,
            _ => op.size,
        }
    }

    fn push(&mut self, v: E) -> Result<(), String> {
        let sp = self.sp - 4;
        self.sp = sp;
        // a save of a callee-saved register, or a push in the entry prologue (`push ecx`: VC6 allocating a local)
        let save = self.saves.contains(&v) || self.prologue;
        let a = self.reg32(ESP);
        self.store(a, 4, v)?;
        if !save {
            self.pushed.push(sp);
        }
        Ok(())
    }

    fn step(&mut self, i: &Ins) -> Result<(), String> {
        let ops = &i.ops;
        let reg0 = ops.first().filter(|o| o.typ == OpType::Reg).map(|o| o.reg);
        let prologue = matches!((i.mn, reg0), ("push", Some(_)) | ("sub", Some(Reg::ESP)))
            || (i.mn == "mov" && reg0 == Some(Reg::EBP) && ops.get(1).is_some_and(|o| o.typ == OpType::Reg && o.reg == Reg::ESP));
        self.prologue &= prologue;
        if i.mn == "sub" && reg0 == Some(Reg::ESP) && !self.prologue {
            // the space of a call's arguments (`sub esp, 8; fstp qword ptr [esp]`): its slots are arguments
            if let Some(n) = ops.get(1).filter(|o| o.typ == OpType::Imm).map(|o| o.imm as i32) {
                let top = self.sp;
                self.reserved.extend((1..=n / 4).map(|k| top - 4 * k));
            }
        }
        if self.fstep(i)? {
            return Ok(());
        }
        let w0 = ops.first().map(Self::width_of).unwrap_or(4);
        match (i.mn, ops.len()) {
            ("nop", _) => {}
            ("mov", 2) => {
                let v = self.get(&ops[1])?;
                self.set(&ops[0], v)?;
            }
            ("movzx", 2) => {
                let v = self.get(&ops[1])?;
                let v = self.ar.width(v, Self::width_of(&ops[1]));
                self.set(&ops[0], v)?;
            }
            ("movsx", 2) => {
                let v = self.get(&ops[1])?;
                let v = self.ar.op(if Self::width_of(&ops[1]) == 1 { Opc::Sx8 } else { Opc::Sx16 }, vec![v]);
                self.set(&ops[0], v)?;
            }
            ("lea", 2) => {
                let a = self.addr(&ops[1])?;
                self.set(&ops[0], a)?;
            }
            ("xchg", 2) => {
                let (a, b) = (self.get(&ops[0])?, self.get(&ops[1])?);
                self.set(&ops[0], b)?;
                self.set(&ops[1], a)?;
            }
            ("add" | "sub" | "and" | "or" | "xor", 2) => {
                let (a, b) = (self.get(&ops[0])?, self.get(&ops[1])?);
                let r = match i.mn {
                    "add" => self.ar.add(a, b),
                    "sub" => self.ar.sub(a, b),
                    "and" => self.ar.op(Opc::And, vec![a, b]),
                    "or" => self.ar.op(Opc::Or, vec![a, b]),
                    _ => self.ar.op(Opc::Xor, vec![a, b]),
                };
                let r = self.ar.width(r, w0);
                self.flags = Some(match i.mn {
                    "sub" => Flags::Cmp(a, b, w0),
                    "and" => Flags::Test(a, b, w0),
                    _ => Flags::Res(r, w0),
                });
                self.set(&ops[0], r)?;
            }
            ("sbb" | "adc", 2) => {
                let (a, b) = (self.get(&ops[0])?, self.get(&ops[1])?);
                let cf = self.carry()?;
                let r = if i.mn == "sbb" {
                    let d = self.ar.sub(a, b);
                    self.ar.sub(d, cf)
                } else {
                    let d = self.ar.add(a, b);
                    self.ar.add(d, cf)
                };
                let r = self.ar.width(r, w0);
                self.flags = Some(Flags::Res(r, w0));
                self.set(&ops[0], r)?;
            }
            ("cmp", 2) => {
                let (a, b) = (self.get(&ops[0])?, self.get(&ops[1])?);
                self.flags = Some(Flags::Cmp(a, b, w0));
            }
            ("test", 2) => {
                let (a, b) = (self.get(&ops[0])?, self.get(&ops[1])?);
                self.flags = Some(Flags::Test(a, b, w0));
            }
            ("inc" | "dec" | "neg" | "not", 1) => {
                let a = self.get(&ops[0])?;
                let r = match i.mn {
                    "inc" => {
                        let one = self.ar.c(1);
                        self.ar.add(a, one)
                    }
                    "dec" => {
                        let one = self.ar.c(1);
                        self.ar.sub(a, one)
                    }
                    "neg" => self.ar.mul_k(a, u32::MAX),
                    _ => {
                        let m = self.ar.c(u32::MAX);
                        self.ar.sub(m, a)
                    }
                };
                let r = self.ar.width(r, w0);
                if i.mn != "not" {
                    self.flags = Some(if i.mn == "neg" { Flags::Cmp(self.ar.c(0), a, w0) } else { Flags::Res(r, w0) });
                }
                self.set(&ops[0], r)?;
            }
            ("shl" | "shr" | "sar", 2) => {
                let (a, b) = (self.get(&ops[0])?, self.get(&ops[1])?);
                let o = match i.mn {
                    "shl" => Opc::Shl,
                    "shr" => Opc::Shr,
                    _ => Opc::Sar,
                };
                let r = if w0 == 4 { self.ar.op(o, vec![a, b]) } else { return Err(format!("a {w0}-byte shift")) };
                self.flags = Some(Flags::Res(r, w0));
                self.set(&ops[0], r)?;
            }
            ("imul", 2) | ("imul", 3) => {
                let (a, b) = if ops.len() == 2 { (self.get(&ops[0])?, self.get(&ops[1])?) } else { (self.get(&ops[1])?, self.get(&ops[2])?) };
                let r = self.ar.op(Opc::Mul, vec![a, b]);
                let r = self.ar.width(r, w0);
                self.flags = None;
                self.set(&ops[0], r)?;
            }
            ("mul" | "imul" | "div" | "idiv", 1) if w0 == 4 => {
                let x = self.get(&ops[0])?;
                let (eax, edx) = (self.reg32(0), self.reg32(2));
                let (lo, hi) = match i.mn {
                    "mul" | "imul" => (self.ar.op(Opc::Mul, vec![eax, x]), self.ar.op(if i.mn == "mul" { Opc::MulHi } else { Opc::IMulHi }, vec![eax, x])),
                    "div" => (self.ar.op(Opc::Div, vec![edx, eax, x]), self.ar.op(Opc::Rem, vec![edx, eax, x])),
                    _ => (self.ar.op(Opc::IDiv, vec![edx, eax, x]), self.ar.op(Opc::IRem, vec![edx, eax, x])),
                };
                self.regs[0] = Some(lo);
                self.regs[2] = Some(hi);
                self.flags = None;
            }
            ("cdq", 0) => {
                let eax = self.reg32(0);
                let hi = self.ar.op(Opc::SxHi, vec![eax]);
                self.regs[2] = Some(hi);
            }
            ("push", 1) => {
                let v = self.get(&ops[0])?;
                let v = if Self::width_of(&ops[0]) == 4 || ops[0].typ == OpType::Imm { v } else { return Err("a push of a word".into()) };
                self.push(v)?;
            }
            ("pop", 1) => {
                let a = self.reg32(ESP);
                let v = self.load(a, 4)?;
                let sp = self.sp + 4;
                self.set_sp(sp);
                self.set(&ops[0], v)?;
            }
            (m @ ("stosb" | "stosw" | "stosd" | "movsb" | "movsw" | "movsd"), _) if i.instr.has_rep_prefix() => {
                let w = match m.as_bytes()[4] {
                    b'b' => 1u8,
                    b'w' => 2,
                    _ => 4,
                };
                let (edi, ecx) = (self.reg32(7), self.reg32(1));
                let dst = match self.place(edi)? {
                    Place::Mem(m) => m,
                    Place::Slot(o) => self.escape(o)?,
                };
                if m.starts_with("stos") {
                    let eax = self.reg32(0);
                    let v = self.ar.width(eax, w);
                    self.effects.push(Effect::Fill(dst, ecx, v, w));
                } else {
                    let esi = self.reg32(6);
                    let src = match self.place(esi)? {
                        Place::Mem(m) => m,
                        Place::Slot(o) => self.escape(o)?,
                    };
                    self.effects.push(Effect::Copy(dst, src, ecx, w));
                    let n = self.ar.mul_k(ecx, w as u32);
                    let esi2 = self.ar.add(esi, n);
                    self.regs[6] = Some(esi2);
                }
                let n = self.ar.mul_k(ecx, w as u32);
                let edi2 = self.ar.add(edi, n);
                self.regs[7] = Some(edi2);
                self.regs[1] = Some(self.ar.c(0));
            }
            (m, 1) if m.starts_with("set") => {
                let cc = Cc::of(m).ok_or_else(|| format!("{m} (a condition the prover does not model)"))?;
                let c = self.condition(cc)?;
                self.set(&ops[0], c)?;
            }
            ("call", 1) => {
                let t = self.get(&ops[0])?;
                let t = self.launder(t)?;
                // the arguments: the cells from esp up that were pushed (or written into space reserved by a
                // `sub esp`), up to the first one that was not (a save, a local)
                let mut offs: Vec<i32> = vec![];
                let mut o = self.sp;
                while self.pushed.contains(&o) {
                    offs.push(o);
                    o += 4;
                }
                let mut args = vec![];
                for o in offs {
                    let c = self.ar.c(o as u32);
                    let a = self.ar.add(SP0_KEY, c);
                    let v = self.load(a, 4)?;
                    args.push(self.launder(v)?);
                }
                let n = args.len() as i32;
                // the FPU stack goes to the callee (_ftol's argument); it is empty after the call, and a float the
                // callee returns is read as st0 below the bottom
                args.extend(std::mem::take(&mut self.fpu));
                self.effects.push(Effect::Call(t, args));
                if ops[0].typ != OpType::Imm && !self.cleans_up {
                    // through memory or a register and the caller does not clean up (no `add esp` after it): the
                    // import table's Win32 functions, a COM method's vtable: stdcall, the callee pops its
                    // arguments (the same callee on both sides: a wrong guess shifts both alike)
                    let sp = self.sp + 4 * n;
                    self.set_sp(sp);
                }
                let k = self.effects.len() as u32;
                self.fret = Some(self.ar.var(Var::FRet(self.pair, k)));
                for g in [0u8, 1, 2] {
                    let v = self.ar.var(Var::Ret(self.pair, k, g));
                    self.regs[g as usize] = Some(v);
                }
                self.pushed.clear();
                self.reserved.clear();
                self.flags = None;
            }
            (m, _) => {
                return Err(format!("{}{m} (the prover does not model it yet)", if i.rep { "rep " } else { "" }));
            }
        }
        Ok(())
    }

    /// The carry flag as a value (1 / 0): a compare's or sub's `a <u b`, neg's `x != 0`, a logic operation's 0.
    fn carry(&mut self) -> Result<E, String> {
        match self.flags.ok_or("a carry set in another block")? {
            Flags::Cmp(..) => self.condition(Cc::B),
            Flags::Test(..) => Ok(self.ar.c(0)),
            _ => Err("a carry from an addition or a shift".into()),
        }
    }

    fn condition(&mut self, cc: Cc) -> Result<E, String> {
        let zero = self.ar.c(0);
        let flags = self.flags.ok_or("a condition on flags set in another block")?;
        if let Flags::Sahf(ah) = flags {
            // a condition on ah's bits as the flags (0xfe: sahf's own width, never another compare's)
            return Ok(self.ar.mk(Node::Cond(cc, ah, zero, 0xfe)));
        }
        if matches!(cc, Cc::P | Cc::Np) {
            // the parity of the result's low byte: the condition on that byte as it is
            let x = match flags {
                Flags::Cmp(a, b, _) => self.ar.sub(a, b),
                Flags::Test(a, b, _) => self.ar.op(Opc::And, vec![a, b]),
                Flags::Res(r, _) => r,
                Flags::Sahf(_) => unreachable!(),
            };
            let x = self.ar.op(Opc::Zx8, vec![x]);
            return Ok(self.ar.mk(Node::Cond(cc, x, zero, 1)));
        }
        if matches!(cc, Cc::S | Cc::Ns) {
            // the sign of the result: a compare's difference, a test's and, an operation's value; x < 0 / x >= 0
            let (x, w) = match flags {
                Flags::Cmp(a, b, w) => (self.ar.sub(a, b), w),
                Flags::Test(a, b, w) => (self.ar.op(Opc::And, vec![a, b]), w),
                Flags::Res(r, w) => (r, w),
                Flags::Sahf(_) => unreachable!(),
            };
            let x = match w {
                1 => self.ar.op(Opc::Sx8, vec![x]),
                2 => self.ar.op(Opc::Sx16, vec![x]),
                _ => x,
            };
            return Ok(self.ar.cond(if cc == Cc::S { Cc::L } else { Cc::Ge }, x, zero, 4));
        }
        match flags {
            Flags::Cmp(a, b, w) => Ok(self.ar.cond(cc, a, b, w)),
            Flags::Test(a, b, w) if a == b => Ok(self.ar.cond(cc, a, zero, w)),
            Flags::Test(a, b, w) => match cc {
                Cc::E | Cc::Ne => {
                    let x = self.ar.op(Opc::And, vec![a, b]);
                    Ok(self.ar.cond(cc, x, zero, w))
                }
                _ => Err("a test of two values by an order".into()),
            },
            Flags::Res(r, w) => match cc {
                Cc::E | Cc::Ne => Ok(self.ar.cond(cc, r, zero, w)),
                _ => Err("an order on an arithmetic result (carry / overflow)".into()),
            },
            Flags::Sahf(_) => unreachable!(),
        }
    }
}

// ------------------------------------------------------------------------------------------------ the proof

/// The prover's verdict on one function.
#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    /// the same behaviour: the block pairs checked
    Equal { pairs: usize },
    /// not shown: what stopped it
    Unknown(Stop),
}

impl Outcome {
    pub fn summary(&self, base: u32) -> String {
        match self {
            Outcome::Equal { pairs } => format!("equal ({pairs} block pairs)"),
            Outcome::Unknown(s) => {
                let at = |a: u32| if a >= base { format!("+{:#x}", a - base) } else { "-".into() };
                format!("unknown: {} (ours {}, the original {})", s.why, at(s.ours), at(s.theirs))
            }
        }
    }
}

struct Run {
    effects: Vec<Effect>,
    exit: Vec<(Loc, E)>,
    written: BTreeSet<i32>,
    sp: i32,
    pushed: Vec<i32>,
    reserved: Vec<i32>,
    esc: Esc,
    flags: Option<Flags>,
    eax: E,
    fpu: Vec<E>,
}

#[allow(clippy::too_many_arguments)]
fn run(ar: &mut Arena, b: &Block, pair: u32, side: u8, corr: &Corr) -> Result<Run, (String, u32)> {
    let mut x = Exec::new(ar, pair, side, corr);
    for (k, i) in b.ins.iter().enumerate() {
        if matches!(i.flow, Flow::CondJump | Flow::IndirectJump) {
            continue;
        }
        // a call the caller cleans up after (cdecl): `add esp, N` next
        // (or `pop ecx`, VC6's cleanup of one argument)
        x.cleans_up = b.ins.get(k + 1).is_some_and(|n| {
            let r = n.ops.first().filter(|o| o.typ == OpType::Reg).map(|o| o.reg);
            (n.mn == "add" && r == Some(Reg::ESP)) || (n.mn == "pop" && r == Some(Reg::ECX))
        });
        x.step(i).map_err(|e| (e, i.addr))?;
    }
    let mut exit: Vec<(Loc, E)> = vec![];
    for g in (0..8u8).filter(|&g| g != ESP) {
        let v = x.reg32(g);
        exit.push((Loc::Reg(g), v));
    }
    let mut slots: BTreeSet<i32> = x.slots.keys().copied().collect();
    for p in &corr.pairs {
        if let Loc::Slot(o) = if side == 0 { p.0 } else { p.1 } {
            slots.insert(o);
        }
    }
    for &l in if side == 0 { corr.known.0.keys() } else { corr.known.1.keys() } {
        if let Loc::Slot(o) = l {
            slots.insert(o);
        }
    }
    // the escaped part of the frame is memory now
    let esc = x.esc;
    slots.retain(|&o| !(if o < 0 { esc.local.is_some_and(|(_, low)| low <= o) } else { esc.args.is_some_and(|low| low <= o) }));
    for o in slots {
        let v = x.slot(o);
        exit.push((Loc::Slot(o), v));
    }
    for k in 0..x.fpu.len() {
        exit.push((Loc::Fpu(k as u8), x.fpu[k]));
    }
    let eax = x.reg32(0);
    Ok(Run { effects: x.effects, exit, written: x.written, sp: x.sp, pushed: x.pushed, reserved: x.reserved, esc: x.esc, flags: x.flags, eax, fpu: x.fpu })
}

/// The correspondence at the successors: our locations and theirs that hold the same value at the end, one to one
/// (a value two locations of a side hold pairs in order).
fn exit_corr(ar: &Arena, ra: &Run, rb: &Run, written: BTreeSet<i32>) -> Corr {
    let known = |r: &Run| -> BTreeMap<Loc, E> { r.exit.iter().filter(|(_, v)| ar.global(*v)).copied().collect() };
    let known = (known(ra), known(rb));
    let mut by: HashMap<E, Vec<Loc>> = HashMap::new();
    for (l, v) in &rb.exit {
        by.entry(*v).or_default().push(*l);
    }
    let mut pairs = vec![];
    // the same location first, then the others in order
    for (l, v) in &ra.exit {
        if let Some(ls) = by.get_mut(v) {
            let k = ls.iter().position(|x| x == l).unwrap_or(0);
            if !ls.is_empty() {
                pairs.push((*l, ls.remove(k)));
            }
        }
    }
    Corr { pairs, written, sp: (ra.sp, rb.sp), pushed: (ra.pushed.clone(), rb.pushed.clone()),
           reserved: (ra.reserved.clone(), rb.reserved.clone()), esc: (ra.esc, rb.esc), known, fpu: (ra.fpu.len() as u8, rb.fpu.len() as u8) }
}

fn meet(old: &Corr, new: &Corr) -> Option<Corr> {
    if old.sp != new.sp || old.esc != new.esc || old.fpu != new.fpu {
        return None;
    }
    // an argument slot one path wrote and the other did not: on the other, it is still the argument (an implicit
    // pair of the slot with itself), made explicit before the two meet
    let explicit = |c: &Corr, other: &Corr| -> Vec<(Loc, Loc)> {
        let mut p = c.pairs.clone();
        for &o in other.written.difference(&c.written).filter(|&&o| o > 0) {
            if !p.iter().any(|x| x.0 == Loc::Slot(o) || x.1 == Loc::Slot(o)) {
                p.push((Loc::Slot(o), Loc::Slot(o)));
            }
        }
        p
    };
    let (po, pn) = (explicit(old, new), explicit(new, old));
    let pairs = po.iter().filter(|p| pn.contains(p)).copied().collect();
    // arguments pushed on either path are compared (more is safe)
    let union = |a: &Vec<i32>, b: &Vec<i32>| -> Vec<i32> { a.iter().chain(b).copied().collect::<BTreeSet<_>>().into_iter().collect() };
    let pushed = (union(&old.pushed.0, &new.pushed.0), union(&old.pushed.1, &new.pushed.1));
    let reserved = (union(&old.reserved.0, &new.reserved.0), union(&old.reserved.1, &new.reserved.1));
    // a value known on every path into the block
    let both = |x: &BTreeMap<Loc, E>, y: &BTreeMap<Loc, E>| -> BTreeMap<Loc, E> { x.iter().filter(|(l, v)| y.get(l) == Some(v)).map(|(l, v)| (*l, *v)).collect() };
    let known = (both(&old.known.0, &new.known.0), both(&old.known.1, &new.known.1));
    Some(Corr { pairs, written: old.written.union(&new.written).copied().collect(), sp: old.sp, pushed, reserved, esc: old.esc, fpu: old.fpu, known })
}

/// Proves our function (its code at `va`, our relocated fields already bound: bind) the same as the original's.
/// A block reached both with and without an escaped frame (a loop that passes a local's address on) is proved
/// again with the frame escaped from the entry, from the lowest address that escaped on each side.
pub fn prove(ours: &[u8], theirs: &[u8], va: u32) -> Outcome {
    let unknown = |why: String, a: u32, b: u32| Outcome::Unknown(Stop { why, ours: a, theirs: b });
    let (ca, cb) = match (cfg(ours, va), cfg(theirs, va)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) => return unknown(format!("ours: {e}"), va, va),
        (_, Err(e)) => return unknown(format!("the original: {e}"), va, va),
    };
    match attempt(&ca, &cb, (Esc::default(), Esc::default())) {
        Ok(o) => o,
        Err(esc) => attempt(&ca, &cb, esc).unwrap_or_else(|_| unknown("a block reached with frames escaped differently".into(), va, va)),
    }
}

/// One proof from the entry with the frames escaped as `esc0`; Err: prove again with the frames escaped from the
/// entry as given.
fn attempt(ca: &Cfg, cb: &Cfg, esc0: (Esc, Esc)) -> Result<Outcome, (Esc, Esc)> {
    let unknown = |why: String, a: u32, b: u32| Ok(Outcome::Unknown(Stop { why, ours: a, theirs: b }));
    // the lowest escapes seen on each side
    let mut low = esc0;
    let lower = |l: &mut Esc, e: Esc| {
        if let Some((_, x)) = e.local {
            l.local = Some(l.local.map_or((x, x), |(_, y)| (x.min(y), x.min(y))));
        }
        if let Some(x) = e.args {
            l.args = Some(l.args.map_or(x, |y| x.min(y)));
        }
    };
    if std::env::var_os("DCP_EQUIV_DEBUG").is_some() {
        for (side, c) in [("ours", &ca), ("the original", &cb)] {
            eprintln!("equiv: {side}'s blocks: {}", c.blocks.iter().map(|(a, b)| format!("{a:#x}+{}:{:?}", b.ins.len(), b.term)).collect::<Vec<_>>().join(" "));
        }
    }
    let mut ar = Arena::new();
    let all: Vec<(Loc, Loc)> = (0..8u8).filter(|&g| g != ESP).map(|g| (Loc::Reg(g), Loc::Reg(g))).collect();
    let c0 = Corr { pairs: all, written: BTreeSet::new(), sp: (0, 0), pushed: (vec![], vec![]), reserved: (vec![], vec![]), esc: esc0, fpu: (0, 0),
                   known: (BTreeMap::new(), BTreeMap::new()) };
    let mut ids: HashMap<(u32, u32), u32> = HashMap::new();
    let mut seen: HashMap<(u32, u32), Corr> = HashMap::new();
    let mut work = vec![(ca.entry, cb.entry, c0)];
    let budget = 4 * (ca.blocks.len() + cb.blocks.len()) + 64;
    let mut visits = 0;
    while let Some((a, b, corr)) = work.pop() {
        let (a, b) = (ca.thread(a), cb.thread(b));
        let corr = match seen.get(&(a, b)) {
            Some(old) => match meet(old, &corr) {
                Some(m) if m == *old => continue,
                Some(m) => m,
                None if old.sp == corr.sp && esc0 == (Esc::default(), Esc::default()) => return Err(low),
                None => return unknown(if old.sp != corr.sp { "a block reached with another stack depth" } else { "a block reached with frames escaped differently" }.into(), a, b),
            },
            None => corr,
        };
        seen.insert((a, b), corr.clone());
        visits += 1;
        if visits > budget {
            return unknown("the pairing runs past its budget".into(), a, b);
        }
        let n = ids.len() as u32;
        let pair = *ids.entry((a, b)).or_insert(n);
        let (Some(ba), Some(bb)) = (ca.blocks.get(&a), cb.blocks.get(&b)) else {
            return unknown("a jump to no block".into(), a, b);
        };
        let ra = match run(&mut ar, ba, pair, 0, &corr) {
            Ok(r) => r,
            Err((e, at)) => return unknown(e, at, b),
        };
        let rb = match run(&mut ar, bb, pair, 1, &corr) {
            Ok(r) => r,
            Err((e, at)) => return unknown(e, a, at),
        };
        lower(&mut low.0, ra.esc);
        lower(&mut low.1, rb.esc);
        if ra.effects != rb.effects {
            if std::env::var_os("DCP_EQUIV_DEBUG").is_some() {
                let show = |e: &[Effect], ar: &Arena| e.iter().map(|x| match x {
                    Effect::Store(a, w, v) => format!("store{w} {} = {}", ar.show(*a), ar.show(*v)),
                    Effect::Call(t, args) => format!("call {} ({})", ar.show(*t), args.iter().map(|&a| ar.show(a)).collect::<Vec<_>>().join(", ")),
                    other => format!("{other:?}"),
                }).collect::<Vec<_>>().join("\n    ");
                eprintln!("equiv: block pair {a:#x} / {b:#x}\n  ours:\n    {}\n  the original:\n    {}", show(&ra.effects, &ar), show(&rb.effects, &ar));
            }
            let k = ra.effects.iter().zip(&rb.effects).position(|(x, y)| x != y).unwrap_or(ra.effects.len().min(rb.effects.len()));
            let what = match (ra.effects.get(k), rb.effects.get(k)) {
                (Some(Effect::Call(..)), Some(Effect::Call(..))) => "a call differs (callee or arguments)",
                (Some(Effect::Store(..)), Some(Effect::Store(..))) => "a store differs (address or value)",
                (None, Some(_)) | (Some(_), None) => "one side has an effect the other does not (a store or a call)",
                _ => "a store against a call",
            };
            return unknown(what.into(), a, b);
        }
        if ra.fpu.len() != rb.fpu.len() {
            return unknown("the FPU stacks differ in depth".into(), a, b);
        }
        let written: BTreeSet<i32> = ra.written.union(&rb.written).copied().collect();
        let next = exit_corr(&ar, &ra, &rb, written);
        if std::env::var_os("DCP_EQUIV_TRACE").is_some() {
            eprintln!("trace: pair {pair} {a:#x}/{b:#x} sp {:?} in {} out {} eax {} | {}", corr.sp, corr.pairs.len(), next.pairs.len(),
                      ar.show(ra.eax), ar.show(rb.eax));
        }
        match (&ba.term, &bb.term) {
            (Term::Ret(pa), Term::Ret(pb)) => {
                if pa != pb {
                    return unknown("the returns pop different sizes".into(), a, b);
                }
                if ra.fpu.last() != rb.fpu.last() {
                    return unknown("st0 differs at the return (a float the function returns)".into(), a, b);
                }
                if ra.eax != rb.eax && ra.fpu.is_empty() {
                    return unknown("eax differs at the return (the same if the function returns nothing)".into(), a, b);
                }
            }
            (Term::Tail(ta), Term::Tail(tb)) => {
                if ta != tb || *ta == 0 {
                    return unknown(if *ta == 0 || *tb == 0 { "a switch table's jump (not followed yet)" } else { "a jump out of the function to another place" }.into(), a, b);
                }
                if next.pairs.iter().filter(|p| p.0 == p.1).count() < 7 || ra.sp != rb.sp {
                    return unknown("a jump out of the function with other registers or stack".into(), a, b);
                }
            }
            (Term::Jmp(ta), Term::Jmp(tb)) => work.push((*ta, *tb, next)),
            (Term::Cond(cca, ta, fa), Term::Cond(ccb, tb, fb)) => {
                let (Some(fla), Some(flb)) = (ra.flags, rb.flags) else {
                    return unknown("a condition on flags set in another block".into(), a, b);
                };
                let mut xa = Exec::new(&mut ar, pair, 0, &corr);
                xa.flags = Some(fla);
                let ka = match xa.condition(*cca) {
                    Ok(k) => k,
                    Err(e) => return unknown(e, a, b),
                };
                let mut xb = Exec::new(&mut ar, pair, 1, &corr);
                xb.flags = Some(flb);
                let kb = match xb.condition(*ccb) {
                    Ok(k) => k,
                    Err(e) => return unknown(e, a, b),
                };
                if ka == kb {
                    work.push((*ta, *tb, next.clone()));
                    work.push((*fa, *fb, next));
                } else if ar.not_cond(ka) == Some(kb) {
                    work.push((*ta, *fb, next.clone()));
                    work.push((*fa, *tb, next));
                } else {
                    if std::env::var_os("DCP_EQUIV_DEBUG").is_some() {
                        eprintln!("equiv: block pair {a:#x} / {b:#x}: conditions\n  ours: {}\n  the original: {}\n  correspondence: {:?}",
                                  ar.show(ka), ar.show(kb), corr.pairs);
                    }
                    return unknown("the branches test different conditions".into(), a, b);
                }
            }
            // one side branches where the other goes on: not paired (yet)
            _ => return unknown("the blocks end differently (a branch against a jump or a return)".into(), a, b),
        }
    }
    Ok(Outcome::Equal { pairs: seen.len() })
}

// ------------------------------------------------------------------------------------------------ our relocations

/// Our function's code with each relocated field holding the address the original's field holds where the two
/// instructions line up (the listings' equal lines and same-shape lines of equal-length hunks): a symbol's
/// address is learned at its aligned sites, and the same symbol must get the same address at every one; a symbol
/// that never lines up (or gets two addresses) gets one the original cannot hold. Returns the code and how many
/// relocations stayed unbound.
pub fn bind(obj: &crate::coff::Obj, code: &crate::coff::FunctionCode, img: &crate::pe::Image, va: u32,
            la: &[crate::x86::Line], lb: &[crate::x86::Line]) -> (Vec<u8>, usize) {
    use crate::difflib::{opcodes, Tag};
    let (cd, _) = code.code();
    let ta: Vec<&str> = la.iter().map(|l| l.text.as_str()).collect();
    let tb: Vec<&str> = lb.iter().map(|l| l.text.as_str()).collect();
    let mut pairs: Vec<(usize, usize)> = vec![];
    for (tag, i1, i2, j1, j2) in opcodes(&ta, &tb) {
        if tag == Tag::Equal || i2 - i1 == j2 - j1 {
            pairs.extend((0..i2 - i1).map(|k| (i1 + k, j1 + k)).filter(|&(i, j)| la[i].shape.mn == lb[j].shape.mn));
        }
    }
    let mut bound: HashMap<u32, Option<u32>> = HashMap::new();
    for (i, j) in pairs {
        let (ia, ib) = (la[i].addr, lb[j].addr);
        let o = ia - va;
        let rs: Vec<&(u32, crate::coff::Reloc)> = code.relocs.iter().filter(|(off, _)| o <= *off && *off < o + la[i].size).collect();
        if rs.is_empty() {
            continue;
        }
        let (Some(x), Some(y)) = (dis::decode(&cd[o as usize..(o + la[i].size).min(cd.len() as u32) as usize], ia).into_iter().next(),
                                  dis::decode(&img.read(ib, lb[j].size as usize), ib).into_iter().next()) else { continue };
        for (off, r) in rs {
            let Some(kind) = x.field_at(off - o) else { continue };
            let f = match kind {
                dis::FieldKind::Disp => y.disp,
                dis::FieldKind::Imm => y.imm,
                dis::FieldKind::Imm2 => y.imm2,
                dis::FieldKind::Branch => y.branch,
            };
            if f.size != 4 {
                continue;
            }
            let site = ib + f.at as u32;
            let addend = obj.addend(code.secnum, r);
            let Some(s) = r.resolve(site, &img.bytes(site, 4), addend) else { continue };
            let e = bound.entry(r.symbol_index).or_insert(Some(s));
            if *e != Some(s) {
                *e = None; // two addresses for one symbol: no binding
            }
        }
    }
    let mut out = cd.to_vec();
    let mut unbound = 0;
    for (off, r) in &code.relocs {
        let o = *off as usize;
        if o + 4 > out.len() {
            continue;
        }
        let s = match bound.get(&r.symbol_index).copied().flatten() {
            Some(s) => s,
            None => {
                unbound += 1;
                0xf000_0000u32.wrapping_add(r.symbol_index.wrapping_mul(0x100))
            }
        };
        let addend = obj.addend(code.secnum, r);
        let v = match r.kind_width().0 {
            crate::coff::ABSOLUTE => s.wrapping_add(addend),
            crate::coff::RELATIVE => s.wrapping_add(addend).wrapping_sub(va + *off + 4),
            _ => continue,
        };
        out[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }
    (out, unbound)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(a: &[u8], b: &[u8]) -> Outcome {
        prove(a, b, 0x401000)
    }

    #[test]
    fn instruction_selection_and_copies() {
        // mov eax, [esp+4]; add eax, 1; ret  against  mov ecx, [esp+4]; lea eax, [ecx+1]; ret
        let a = [0x8b, 0x44, 0x24, 0x04, 0x83, 0xc0, 0x01, 0xc3];
        let b = [0x8b, 0x4c, 0x24, 0x04, 0x8d, 0x41, 0x01, 0xc3];
        assert_eq!(p(&a, &b), Outcome::Equal { pairs: 1 });
        // another constant: the return differs
        let c = [0x8b, 0x44, 0x24, 0x04, 0x83, 0xc0, 0x02, 0xc3];
        assert!(matches!(p(&a, &c), Outcome::Unknown(s) if s.why.contains("eax differs")));
    }

    #[test]
    fn an_extra_store_is_no_equality() {
        // mov eax, [esp+4]; mov [0x500000], eax; ret  against  mov eax, [esp+4]; ret
        let a = [0x8b, 0x44, 0x24, 0x04, 0xa3, 0x00, 0x00, 0x50, 0x00, 0xc3];
        let b = [0x8b, 0x44, 0x24, 0x04, 0xc3];
        assert!(matches!(p(&a, &b), Outcome::Unknown(s) if s.why.contains("effect")));
        // a store of another value
        let c = [0x8b, 0x4c, 0x24, 0x08, 0x89, 0x0d, 0x00, 0x00, 0x50, 0x00, 0xc3]; // mov ecx,[esp+8]; mov [0x500000],ecx
        assert!(matches!(p(&a, &c), Outcome::Unknown(_)));
    }

    #[test]
    fn inverted_branches() {
        // mov eax,[esp+4]; test eax,eax; je L; mov eax,1; ret; L: xor eax,eax; ret
        let a = [0x8b, 0x44, 0x24, 0x04, 0x85, 0xc0, 0x74, 0x06, 0xb8, 0x01, 0, 0, 0, 0xc3, 0x33, 0xc0, 0xc3];
        // mov eax,[esp+4]; cmp eax,0; jne L; xor eax,eax; ret; L: mov eax,1; ret
        let b = [0x8b, 0x44, 0x24, 0x04, 0x83, 0xf8, 0x00, 0x75, 0x03, 0x33, 0xc0, 0xc3, 0xb8, 0x01, 0, 0, 0, 0xc3];
        assert!(matches!(p(&a, &b), Outcome::Equal { .. }), "{:?}", p(&a, &b));
        // the arms exchanged: not the same
        let c = [0x8b, 0x44, 0x24, 0x04, 0x83, 0xf8, 0x00, 0x74, 0x03, 0x33, 0xc0, 0xc3, 0xb8, 0x01, 0, 0, 0, 0xc3];
        assert!(matches!(p(&a, &c), Outcome::Unknown(_)), "{:?}", p(&a, &c));
    }

    #[test]
    fn a_byte_test_against_a_byte_compare() {
        // mov esi,[esp+4]; mov cl,[esi]; test cl,cl; je L; mov eax,1; ret; L: xor eax,eax; ret
        let a = [0x8b, 0x74, 0x24, 0x04, 0x8a, 0x0e, 0x84, 0xc9, 0x74, 0x06, 0xb8, 0x01, 0, 0, 0, 0xc3, 0x33, 0xc0, 0xc3];
        // mov eax,[esp+4]; cmp byte ptr [eax],0; je L; mov eax,1; ret; L: xor eax,eax; ret
        let b = [0x8b, 0x44, 0x24, 0x04, 0x80, 0x38, 0x00, 0x74, 0x06, 0xb8, 0x01, 0, 0, 0, 0xc3, 0x33, 0xc0, 0xc3];
        assert!(matches!(p(&a, &b), Outcome::Equal { .. }), "{:?}", p(&a, &b));
    }

    #[test]
    fn calls_with_their_arguments() {
        // push dword [esp+4]; call 0x402000; add esp,4; ret  against  mov eax,[esp+4]; push eax; call 0x402000; pop ecx; ret
        let a = [0xff, 0x74, 0x24, 0x04, 0xe8, 0xf7, 0x0f, 0x00, 0x00, 0x83, 0xc4, 0x04, 0xc3];
        let b = [0x8b, 0x44, 0x24, 0x04, 0x50, 0xe8, 0xf6, 0x0f, 0x00, 0x00, 0x59, 0xc3];
        assert!(matches!(p(&a, &b), Outcome::Equal { .. }), "{:?}", p(&a, &b));
        // another callee
        let c = [0x8b, 0x44, 0x24, 0x04, 0x50, 0xe8, 0xf6, 0x1f, 0x00, 0x00, 0x59, 0xc3];
        assert!(matches!(p(&a, &c), Outcome::Unknown(s) if s.why.contains("call")));
    }

    #[test]
    fn a_local_passed_by_address() {
        // sub esp,4; lea eax,[esp]; push eax; call F; mov eax,[esp+4]; add esp,8; ret
        let a = [0x83, 0xec, 0x04, 0x8d, 0x04, 0x24, 0x50, 0xe8, 0xf4, 0x0f, 0, 0, 0x8b, 0x44, 0x24, 0x04, 0x83, 0xc4, 0x08, 0xc3];
        // the original's frame is larger: sub esp,8; lea eax,[esp]; push eax; call F; mov eax,[esp+4]; add esp,0xc; ret
        let b = [0x83, 0xec, 0x08, 0x8d, 0x04, 0x24, 0x50, 0xe8, 0xf4, 0x0f, 0, 0, 0x8b, 0x44, 0x24, 0x04, 0x83, 0xc4, 0x0c, 0xc3];
        assert!(matches!(p(&a, &b), Outcome::Equal { .. }), "{:?}", p(&a, &b));
        // reading the slot next to the one passed is another value
        let c = [0x83, 0xec, 0x08, 0x8d, 0x04, 0x24, 0x50, 0xe8, 0xf4, 0x0f, 0, 0, 0x8b, 0x44, 0x24, 0x08, 0x83, 0xc4, 0x0c, 0xc3];
        assert!(matches!(p(&a, &c), Outcome::Unknown(_)), "{:?}", p(&a, &c));
    }

    #[test]
    fn a_sign_test_against_an_order() {
        // test eax,eax; js L  against  cmp eax,0; jl L
        let a = [0x8b, 0x44, 0x24, 0x04, 0x85, 0xc0, 0x78, 0x06, 0xb8, 0x01, 0, 0, 0, 0xc3, 0x33, 0xc0, 0xc3];
        let b = [0x8b, 0x44, 0x24, 0x04, 0x83, 0xf8, 0x00, 0x7c, 0x06, 0xb8, 0x01, 0, 0, 0, 0xc3, 0x33, 0xc0, 0xc3];
        assert!(matches!(p(&a, &b), Outcome::Equal { .. }), "{:?}", p(&a, &b));
    }

    #[test]
    fn floats() {
        // fld [esp+4]; fadd [esp+8]; ret  against the operands the other way round (an add commutes)
        let a = [0xd9, 0x44, 0x24, 0x04, 0xd8, 0x44, 0x24, 0x08, 0xc3];
        let b = [0xd9, 0x44, 0x24, 0x08, 0xd8, 0x44, 0x24, 0x04, 0xc3];
        assert!(matches!(p(&a, &b), Outcome::Equal { .. }), "{:?}", p(&a, &b));
        // a subtraction does not
        let c = [0xd9, 0x44, 0x24, 0x04, 0xd8, 0x64, 0x24, 0x08, 0xc3];
        let d = [0xd9, 0x44, 0x24, 0x08, 0xd8, 0x64, 0x24, 0x04, 0xc3];
        assert!(matches!(p(&c, &d), Outcome::Unknown(s) if s.why.contains("st0")), "{:?}", p(&c, &d));
        // fsubr against fsub with the operands exchanged: the same
        let e = [0xd9, 0x44, 0x24, 0x08, 0xd8, 0x6c, 0x24, 0x04, 0xc3]; // fld [esp+8]; fsubr [esp+4]
        assert!(matches!(p(&c, &e), Outcome::Equal { .. }), "{:?}", p(&c, &e));
    }

    #[test]
    fn a_float_compare() {
        // fld [esp+4]; fcomp [esp+8]; fnstsw ax; test ah,0x41; jne L; mov eax,1; ret; L: xor eax,eax; ret
        let a = [0xd9, 0x44, 0x24, 0x04, 0xd8, 0x5c, 0x24, 0x08, 0xdf, 0xe0, 0xf6, 0xc4, 0x41, 0x75, 0x06, 0xb8, 0x01, 0, 0, 0, 0xc3,
                 0x33, 0xc0, 0xc3];
        // the same with the branch inverted: je to the 1, the 0 inline
        let b = [0xd9, 0x44, 0x24, 0x04, 0xd8, 0x5c, 0x24, 0x08, 0xdf, 0xe0, 0xf6, 0xc4, 0x41, 0x74, 0x03, 0x33, 0xc0, 0xc3,
                 0xb8, 0x01, 0, 0, 0, 0xc3];
        assert!(matches!(p(&a, &b), Outcome::Equal { .. }), "{:?}", p(&a, &b));
        // another mask is another condition
        let mut c = b;
        c[12] = 0x01;
        assert!(matches!(p(&a, &c), Outcome::Unknown(_)), "{:?}", p(&a, &c));
    }

    #[test]
    fn a_double_passed_through_the_stack() {
        // fld [esp+4]; sub esp,8; fstp qword [esp]; call F; add esp,8; ret
        let a = [0xd9, 0x44, 0x24, 0x04, 0x83, 0xec, 0x08, 0xdd, 0x1c, 0x24, 0xe8, 0xf1, 0x0f, 0, 0, 0x83, 0xc4, 0x08, 0xc3];
        assert!(matches!(p(&a, &a), Outcome::Equal { .. }), "{:?}", p(&a, &a));
        // another value passed: the call's argument differs
        let mut b = a;
        b[3] = 0x08;
        assert!(matches!(p(&a, &b), Outcome::Unknown(s) if s.why.contains("call")), "{:?}", p(&a, &b));
    }

    #[test]
    fn a_register_kept_in_a_slot() {
        // ours keeps x in esi, the original in a stack slot of a larger frame
        // push esi; mov esi,[esp+8]; inc esi; mov eax,esi; pop esi; ret
        let a = [0x56, 0x8b, 0x74, 0x24, 0x08, 0x46, 0x8b, 0xc6, 0x5e, 0xc3];
        // sub esp,4; mov eax,[esp+8]; mov [esp],eax; mov eax,[esp]; inc eax; add esp,4; ret
        let b = [0x83, 0xec, 0x04, 0x8b, 0x44, 0x24, 0x08, 0x89, 0x04, 0x24, 0x8b, 0x04, 0x24, 0x40, 0x83, 0xc4, 0x04, 0xc3];
        assert!(matches!(p(&a, &b), Outcome::Equal { .. }), "{:?}", p(&a, &b));
    }
}
