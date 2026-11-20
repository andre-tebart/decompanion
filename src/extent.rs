//! S.extent: how far the original's code proves a data object reaches. A global the sources declare smaller than
//! the original uses it links cleanly and corrupts its neighbours at run time (a play session: a save header
//! declared `int x[1]` that the loader fills up to +0xfc; a 748-byte table a loop scans up to 920 bytes).
//!
//! Every walked function is read once, bottom-up over the call graph, by a small abstract interpretation of its
//! registers and stack slots (one linear sweep in address order; a forward jump carries its state to the target,
//! a loop head forgets what the loop body writes): a register holds a constant, an address into a data section
//! (exactly, or walking upwards from it: an index added, a loop), a stack argument of the function (plus an
//! offset), or a pointer into its own frame. Evidence that bytes are one object, in C's terms (a pointer stays
//! inside its object):
//!   field  an access [r + disp] (r an address: the object holds the address and the accessed bytes)
//!   bound  `cmp r, END` before an ordering jump, r walking up from B: B .. END is one array (END one past it)
//!          (an access a guard of the body, `cmp r, LIMIT; jge past it`, skips counts up to LIMIT's last pass)
//!   copy   rep movs / stos (and the single forms) with ecx a constant: the bytes written / read
//!   call   an address passed to a function whose summary says how far it reaches through that argument
//! A function's summary: per stack argument, the range around the pointer its accesses reach, a constant or a
//! product of other arguments (fread's size * count). Seeds: the library's copiers by name (memcpy, memset,
//! fread, ...) and the project's `writes` declarations (decl/text.dcl: `0xADDR writes ptr=a0 size=a1*a2`).
//! Per base address the union of its evidence is one `evidence` fact {ekind: extent} over the proven range
//! (derived: it rests on the walk); D.data's D8 holds them against the declarations.

use crate::error::{Error, Result};
use crate::dis::{OpType, Reg};
use crate::rules::Ctx;
use crate::store::{Out, DERIVED};
use crate::x86::{Decoder, WIns, CALL, CJUMP, IJUMP, JUMP, RET};
use rusqlite::Connection;
use serde_json::json;
use std::collections::{BTreeMap, HashMap, HashSet};

const NARGS: usize = 12;
const EAX: usize = 0;
const ECX: usize = 1;
const EDX: usize = 2;
const ESP: usize = 4;
const EBP: usize = 5;
const ESI: usize = 6;
const EDI: usize = 7;
const MAX_SPAN: i64 = 0x100_0000; // larger proven spans are no evidence (a size from a wrong guess)

/// An abstract value.
#[derive(Clone, Copy, PartialEq, Debug)]
enum V {
    Unk,
    Const(i64),
    Addr(u32, i64), // a data address b plus an exact offset
    Walk(u32),      // b plus some unknown offset >= 0
    Arg(u8, i64),   // stack argument k of the function plus an offset
    Frame(i64),     // the address entry_esp - depth (a pointer into the function's frame)
}

fn merge_v(a: V, b: V) -> V {
    if a == b {
        return a;
    }
    match (a, b) {
        (V::Addr(x, _) | V::Walk(x), V::Addr(y, _) | V::Walk(y)) if x == y => V::Walk(x),
        _ => V::Unk,
    }
}

fn widen_v(a: V) -> V {
    match a {
        V::Addr(b, _) | V::Walk(b) => V::Walk(b),
        V::Frame(d) => V::Frame(d),
        _ => V::Unk,
    }
}

/// A register -> (index of its 32-bit general register, whether it is the whole register).
fn reg(r: Reg) -> Option<(usize, bool)> {
    crate::dis::gpr(r).map(|i| (i as usize, r.size() == 4))
}

#[derive(Clone, PartialEq)]
struct St {
    r: [V; 8],
    d: Option<i64>,         // esp = entry_esp - d
    slots: Vec<(i64, V)>,   // depth -> the value stored there
}

impl St {
    fn fresh(ebp_frame: bool) -> St {
        let mut r = [V::Unk; 8];
        if ebp_frame {
            r[EBP] = V::Frame(4);
        }
        St { r, d: None, slots: vec![] }
    }
    fn entry() -> St {
        St { r: [V::Unk; 8], d: Some(0), slots: vec![] }
    }
    fn slot(&self, depth: i64) -> V {
        if let Some(s) = self.slots.iter().find(|s| s.0 == depth) {
            return s.1;
        }
        if depth <= -4 && (-depth - 4) % 4 == 0 && ((-depth - 4) / 4) < NARGS as i64 {
            return V::Arg(((-depth - 4) / 4) as u8, 0);
        }
        V::Unk
    }
    fn store(&mut self, depth: i64, v: V) {
        match self.slots.iter().position(|s| s.0 == depth) {
            Some(i) => self.slots[i].1 = v,
            None if self.slots.len() < 64 => self.slots.push((depth, v)),
            None => {}
        }
    }
    fn merge(&mut self, o: &St) {
        for i in 0..8 {
            self.r[i] = merge_v(self.r[i], o.r[i]);
        }
        if self.d != o.d {
            self.d = None;
        }
        let mine = std::mem::take(&mut self.slots);
        self.slots = mine.into_iter().filter_map(|(k, v)| o.slots.iter().find(|s| s.0 == k).map(|s| (k, merge_v(v, s.1)))).collect();
    }
}

/// A summary term: through its pointer argument p a function reaches [p + lo, p + hi + mult * product of its
/// arguments f) (f empty: [p + lo, p + hi)).
#[derive(Clone, PartialEq, Debug)]
struct Term {
    lo: i64,
    hi: i64,
    mult: i64,
    f: Vec<u8>,
}

#[derive(Clone, Default, PartialEq, Debug)]
struct Summary {
    args: Vec<Vec<Term>>, // per stack argument
}

impl Summary {
    fn add(&mut self, k: usize, t: Term) {
        if k >= NARGS || t.hi.abs() > MAX_SPAN || t.lo.abs() > MAX_SPAN || t.f.len() > 3 {
            return;
        }
        if self.args.len() <= k {
            self.args.resize(k + 1, vec![]);
        }
        let ts = &mut self.args[k];
        match ts.iter().position(|x| x.f == t.f && (x.f.is_empty() || x.mult == t.mult)) {
            Some(i) => {
                ts[i].lo = ts[i].lo.min(t.lo);
                ts[i].hi = ts[i].hi.max(t.hi);
            }
            None if ts.len() < 6 => ts.push(t),
            None => {}
        }
    }
}

/// One piece of evidence: [lo, hi) is one object of the original (base: the address the code materialised).
struct Ev {
    lo: i64,
    hi: i64,
    base: u32,
    site: u32,
    how: &'static str,
    to: u32, // call: the callee
}

/// The seeds: the library's copiers by C name, (pointer argument, size factors) each.
fn library_seed(name: &str) -> Option<Vec<(u8, Vec<u8>)>> {
    Some(match name {
        "memcpy" | "memmove" | "memcmp" | "_memccpy" => vec![(0, vec![2]), (1, vec![2])],
        "memset" | "strncpy" | "strncat" | "_strnset" => vec![(0, vec![2])],
        "fread" | "fwrite" => vec![(0, vec![1, 2])],
        "_read" | "_write" => vec![(1, vec![2])],
        _ => return None,
    })
}

/// A `writes` declaration's terms: ptr=aK size=PRODUCT.
fn writes_seed(ptr: &str, size: &str) -> Option<(u8, Term)> {
    let k: u8 = ptr.strip_prefix('a')?.parse().ok()?;
    let (mut mult, mut f) = (1i64, vec![]);
    for part in size.split('*') {
        if let Some(a) = part.strip_prefix('a') {
            f.push(a.parse().ok()?);
        } else if let Some(h) = part.strip_prefix("0x") {
            mult *= i64::from_str_radix(h, 16).ok()?;
        } else {
            mult *= part.parse::<i64>().ok()?;
        }
    }
    Some((k, if f.is_empty() { Term { lo: 0, hi: mult, mult: 0, f } } else { Term { lo: 0, hi: 0, mult, f } }))
}

/// The mnemonics that read their first operand without writing it.
fn reads_only(mn: &str) -> bool {
    matches!(mn, "cmp" | "test" | "push" | "bt" | "call" | "jmp" | "ret")
}

/// The registers an instruction may write (a bit per register).
fn written(ins: &WIns) -> u8 {
    let mut m = 0u8;
    let mn = ins.mn;
    if let Some(o) = ins.ops.first() {
        if o.typ == OpType::Reg && !reads_only(mn) {
            if let Some((i, _)) = reg(o.reg) {
                m |= 1 << i;
            }
        }
    }
    if mn == "xchg" {
        for o in &ins.ops {
            if let Some((i, _)) = reg(o.reg).filter(|_| o.typ == OpType::Reg) {
                m |= 1 << i;
            }
        }
    }
    if ins.flow == CALL {
        m |= 1 << EAX | 1 << ECX | 1 << EDX;
    }
    if matches!(mn, "mul" | "div" | "idiv" | "cdq") || (mn == "imul" && ins.ops.len() == 1) {
        m |= 1 << EAX | 1 << EDX;
    }
    let base = mn.trim_start_matches("rep ").trim_start_matches("repne ").trim_start_matches("repe ");
    if matches!(base.trim_end_matches(['b', 'w', 'd']), "movs" | "stos" | "lods" | "scas" | "cmps") {
        m |= 1 << ECX | 1 << ESI | 1 << EDI | 1 << EAX;
    }
    m
}

struct Fx<'a> {
    data: &'a dyn Fn(i64) -> bool,
    summaries: &'a HashMap<u32, Summary>,
    pops_of: &'a HashMap<u32, i64>, // the bytes a callee's `ret N` pops (stdcall)
    own: Summary,
    ev: Vec<Ev>,
    callee: u32, // while a call's terms apply
    pops: i64,
    overrun: &'a HashSet<u32>, // the declared exceptions: instructions whose access overruns its object
    hit: Vec<u32>,             // the declared ones this function met
}

impl Fx<'_> {
    /// An instruction declared to overrun its object (decl `overrun`): its accesses are no evidence (an exception
    /// removes the convention's premise there: the original kept to C's object bounds).
    fn overruns(&mut self, site: u32) -> bool {
        let o = self.overrun.contains(&site);
        if o {
            self.hit.push(site);
        }
        o
    }

    /// The object around the pointer value v reaches [v + lo, v + hi): evidence or a summary term.
    fn reach(&mut self, v: V, lo: i64, hi: i64, site: u32, how: &'static str) {
        if hi <= lo || hi - lo > MAX_SPAN {
            return;
        }
        let proves = matches!(v, V::Addr(..) | V::Arg(..)) || matches!(v, V::Walk(_) if hi > 0);
        if proves && self.overruns(site) {
            return;
        }
        match v {
            V::Addr(b, o) => {
                let p = b as i64 + o;
                self.ev.push(Ev { lo: (b as i64).min(p + lo), hi: (b as i64 + 1).max(p + hi), base: b, site, how, to: self.callee });
            }
            V::Walk(b) if hi > 0 => self.ev.push(Ev { lo: b as i64, hi: b as i64 + hi, base: b, site, how, to: self.callee }),
            V::Arg(k, o) => self.own.add(k as usize, Term { lo: (o + lo).min(0), hi: o + hi, mult: 0, f: vec![] }),
            _ => {}
        }
    }
}

/// The value of an operand (a register or an immediate), or None for memory.
fn val(st: &St, o: &crate::dis::Op, data: &dyn Fn(i64) -> bool) -> Option<V> {
    match o.typ {
        OpType::Reg => Some(match reg(o.reg) {
            Some((i, true)) => st.r[i],
            _ => V::Unk,
        }),
        OpType::Imm => Some(if data(o.imm) { V::Addr(o.imm as u32, 0) } else { V::Const(o.imm) }),
        _ => None,
    }
}

/// The stack depth a memory operand addresses (esp- or frame-relative, no index).
fn depth_of(st: &St, o: &crate::dis::Op) -> Option<i64> {
    if o.typ != OpType::Mem || o.index != Reg::None {
        return None;
    }
    match reg(o.base) {
        Some((ESP, true)) => st.d.map(|d| d - o.disp),
        Some((i, true)) => match st.r[i] {
            V::Frame(fd) => Some(fd - o.disp),
            _ => None,
        },
        _ => None,
    }
}

/// The address a memory operand computes, as a value: (base value + disp [+ const index]); `exact` false when an
/// index of unknown value (taken as >= 0) is added.
fn addr_of(st: &St, o: &crate::dis::Op, data: &dyn Fn(i64) -> bool) -> Option<(V, bool)> {
    let idx = if o.index != Reg::None {
        match reg(o.index) {
            Some((i, true)) => match st.r[i] {
                V::Const(c) => Some(c * o.scale as i64),
                _ => None,
            },
            _ => return None,
        }
    } else {
        Some(0)
    };
    let base = if o.base == Reg::None {
        if data(o.disp) { V::Addr(o.disp as u32, 0) } else { return None }
    } else {
        match reg(o.base) {
            Some((i, true)) if i != ESP => st.r[i],
            Some((ESP, true)) => match st.d {
                Some(d) => V::Frame(d),
                None => return None,
            },
            _ => return None,
        }
    };
    let disp = if o.base == Reg::None { 0 } else { o.disp };
    let add = |v: V, k: i64| match v {
        V::Addr(b, x) => V::Addr(b, x + k),
        V::Arg(a, x) => V::Arg(a, x + k),
        V::Frame(f) => V::Frame(f - k),
        V::Const(c) => V::Const(c + k),
        V::Walk(b) if k == 0 => V::Walk(b),
        _ => V::Unk,
    };
    Some(match idx {
        Some(i) => (add(base, disp + i), true),
        None => (match base {
            V::Addr(b, _) | V::Walk(b) => V::Walk(b),
            _ => V::Unk,
        }, false),
    })
}

/// Analyse one function (its instructions in address order) under the callees' summaries.
fn analyse(ins: &[&WIns], lo: u32, hi: u32, fx: &mut Fx) {
    let data = fx.data;
    let ebp_frame = ins.len() > 1 && ins[0].mn == "push" && ins[1].mn == "mov"
        && ins[0].ops.first().is_some_and(|o| o.typ == OpType::Reg && reg(o.reg) == Some((EBP, true)))
        && ins[1].ops.len() == 2 && reg(ins[1].ops[0].reg) == Some((EBP, true)) && reg(ins[1].ops[1].reg) == Some((ESP, true));
    // loops: head .. the last jump back to it; what the body writes, how it steps its registers
    let mut back: HashMap<u32, u32> = HashMap::new();
    for i in ins {
        if matches!(i.flow, JUMP | CJUMP) {
            if let Some(t) = i.target {
                let t = t as u32;
                if lo <= t && t <= i.addr {
                    let e = back.entry(t).or_insert(i.addr);
                    *e = (*e).max(i.addr);
                }
            }
        }
    }
    let mut loops: Vec<(u32, u32, Steps, u8, bool)> = vec![];
    for (&h, &j) in &back {
        let (mut m, mut stores) = (0u8, false);
        let body: Vec<&WIns> = ins.iter().copied().filter(|i| h <= i.addr && i.addr <= j).collect();
        for i in &body {
            m |= written(i);
            stores |= i.ops.first().is_some_and(|o| o.typ == OpType::Mem && matches!(reg(o.base), Some((ESP, true)) | Some((EBP, true))));
        }
        loops.push((h, j, steps(&body, ins), m, stores));
    }
    loops.sort_by_key(|l| l.1 - l.0);
    // basic blocks: a leader at the start, at every jump target inside, after every jump and return
    let at: HashMap<u32, usize> = ins.iter().enumerate().map(|(n, i)| (i.addr, n)).collect();
    let mut leader = vec![false; ins.len()];
    if !leader.is_empty() {
        leader[0] = true;
    }
    for (n, i) in ins.iter().enumerate() {
        if matches!(i.flow, JUMP | CJUMP | RET | IJUMP) && n + 1 < ins.len() {
            leader[n + 1] = true;
        }
        if let Some(&k) = i.target.filter(|_| matches!(i.flow, JUMP | CJUMP)).and_then(|t| at.get(&(t as u32))) {
            leader[k] = true;
        }
    }
    // a block inside a loop starts with what the loop writes widened, its first pass too: a register a loop
    // steps never holds an exact address inside it (a strength-reduced loop reaches parallel arrays through
    // one register: [esi - 0x60], [esi], [esi + 0x68])
    let widen = |n: usize, st: &mut St| {
        let a = ins[n].addr;
        for l in loops.iter().filter(|l| l.0 <= a && a <= l.1) {
            for i in 0..8 {
                if l.3 & (1 << i) != 0 {
                    st.r[i] = widen_v(st.r[i]);
                }
            }
            if l.4 {
                for s in st.slots.iter_mut() {
                    s.1 = widen_v(s.1);
                }
            }
        }
    };
    let mut entry: Vec<Option<St>> = vec![None; ins.len()];
    let mut visits = vec![0u8; ins.len()];
    let mut work: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    let flow_in = |entry: &mut Vec<Option<St>>, work: &mut std::collections::BTreeSet<usize>, k: usize, st: &St| {
        let mut s = st.clone();
        widen(k, &mut s);
        match &mut entry[k] {
            Some(e) => {
                let before = e.clone();
                e.merge(&s);
                if *e != before {
                    work.insert(k);
                }
            }
            slot => {
                *slot = Some(s);
                work.insert(k);
            }
        }
    };
    if !ins.is_empty() {
        let mut s = St::entry();
        widen(0, &mut s);
        entry[0] = Some(s);
        work.insert(0);
    }
    let mut next_unseen = 0usize;
    loop {
        let Some(b) = work.pop_first() else {
            // blocks no path from the entry reaches here (a switch's cases, code after a call that does not
            // return): from a fresh state
            while next_unseen < ins.len() && (!leader[next_unseen] || entry[next_unseen].is_some()) {
                next_unseen += 1;
            }
            if next_unseen >= ins.len() {
                break;
            }
            let mut s = St::fresh(ebp_frame);
            widen(next_unseen, &mut s);
            entry[next_unseen] = Some(s);
            work.insert(next_unseen);
            continue;
        };
        visits[b] = visits[b].saturating_add(1);
        if visits[b] > 12 {
            continue;
        }
        let mut st = entry[b].clone().unwrap();
        let mut n = b;
        loop {
            let x = ins[n];
            let lp = loops.iter().find(|l| l.0 <= x.addr && x.addr <= l.1).map(|l| &l.2);
            step(x, ins.get(n + 1).copied(), lp, &mut st, fx, data);
            if matches!(x.flow, JUMP | CJUMP) {
                if let Some(&k) = x.target.filter(|&t| (t as u32) < hi).and_then(|t| at.get(&(t as u32))) {
                    flow_in(&mut entry, &mut work, k, &st);
                }
            }
            if matches!(x.flow, JUMP | RET | IJUMP) || n + 1 >= ins.len() {
                break;
            }
            n += 1;
            if leader[n] {
                flow_in(&mut entry, &mut work, n, &st);
                break;
            }
        }
    }
}

/// Per register of a loop body that only steps it by constants: (the step per pass, the accesses through it
/// relative to its value at the loop head: lowest displacement, highest end; its offset from that value at each
/// compare of the body; the accesses a guard of the body excludes on the passes past its limit: (the last head
/// value the guard lets through, lowest displacement, highest end)).
type Steps = HashMap<usize, (i64, Option<(i64, i64)>, HashMap<u32, i64>, Vec<(i64, i64, i64)>)>;

/// The guards of a loop body: `cmp r, LIMIT` and a forward `jge` / `jae` (`jg` / `ja`) past a region that only
/// its fall-through enters (no jump of the function from outside it lands inside): (the register, the
/// compare's address, the region (the jump, its target), the limit, whether r == LIMIT passes too).
fn guards(body: &[&WIns], all: &[&WIns]) -> Vec<(usize, u32, u32, u32, i64, bool)> {
    let mut gs = vec![];
    for w in body.windows(2) {
        let (c, j) = (w[0], w[1]);
        if c.mn != "cmp" || c.ops.len() != 2 || c.ops[1].typ != OpType::Imm || c.ops[0].typ != OpType::Reg || j.flow != CJUMP {
            continue;
        }
        let Some((r, true)) = reg(c.ops[0].reg) else { continue };
        let incl = match j.mn {
            "jge" | "jae" | "jnl" | "jnb" | "jnc" => false,
            "jg" | "ja" | "jnle" | "jnbe" => true,
            _ => continue,
        };
        let Some(t) = j.target.map(|t| t as u32).filter(|&t| t > j.addr) else { continue };
        let entered = all.iter().any(|i| {
            matches!(i.flow, JUMP | CJUMP)
                && i.target.is_some_and(|x| (x as u32) > j.addr && (x as u32) < t)
                && !(i.addr > j.addr && i.addr < t)
        });
        if !entered {
            gs.push((r, c.addr, j.addr, t, c.ops[1].imm, incl));
        }
    }
    gs
}

fn steps(body: &[&WIns], all: &[&WIns]) -> Steps {
    let mut step: [Option<i64>; 8] = [Some(0); 8];
    let mut acc: [Option<(i64, i64)>; 8] = [None; 8];
    let mut at: [HashMap<u32, i64>; 8] = Default::default();
    // per guard (as `guards` lists them): the register's offset from its head value at the compare
    let gs = guards(body, all);
    let mut gcur: Vec<Option<i64>> = vec![None; gs.len()];
    let mut gacc: [Vec<(i64, bool, i64, i64)>; 8] = Default::default();
    for i in body {
        for (g, cur) in gs.iter().zip(gcur.iter_mut()) {
            if g.1 == i.addr {
                *cur = step[g.0];
            }
        }
        if i.mn == "cmp" {
            for r in 0..8 {
                if let Some(s) = step[r] {
                    at[r].insert(i.addr, s);
                }
            }
        }
        let ops = &i.ops;
        let own = |o: &crate::dis::Op| if o.typ == OpType::Reg { reg(o.reg).filter(|r| r.1).map(|r| r.0) } else { None };
        let konst = match (i.mn, ops.len()) {
            ("add", 2) if ops[1].typ == OpType::Imm => own(&ops[0]).map(|r| (r, ops[1].imm)),
            ("sub", 2) if ops[1].typ == OpType::Imm => own(&ops[0]).map(|r| (r, -ops[1].imm)),
            ("inc", 1) => own(&ops[0]).map(|r| (r, 1)),
            ("dec", 1) => own(&ops[0]).map(|r| (r, -1)),
            ("lea", 2) if ops[1].index == Reg::None && own(&ops[0]).is_some() && reg(ops[1].base) == own(&ops[0]).map(|r| (r, true)) => {
                own(&ops[0]).map(|r| (r, ops[1].disp))
            }
            _ => None,
        };
        // only the accesses at the register itself: one register of a strength-reduced loop also reaches parallel
        // arrays through displacements ([esi - 0x60], [esi + 0x68]), which says nothing of the register's own one
        if i.mn != "lea" {
            for o in ops.iter().filter(|o| o.typ == OpType::Mem && o.index == Reg::None && o.disp == 0) {
                if let Some((r, true)) = reg(o.base) {
                    if let Some(cur) = step[r] {
                        let (lo, hi) = (cur + o.disp, cur + o.disp + o.size.max(1) as i64);
                        // inside a guard's region the access runs only while r passes the guard: on the passes whose
                        // head value h has h + cur < LIMIT (h + cur <= LIMIT); the tightest guard around it
                        let lim = gs.iter().zip(&gcur).filter(|(g, _)| g.0 == r && g.2 < i.addr && i.addr < g.3)
                            .filter_map(|(g, c)| c.map(|c| (g.4 - c, g.5))).min_by_key(|&(l, incl)| (l, !incl));
                        match lim {
                            // the step is known only at the end of the body: the last head value is taken there
                            Some((l, incl)) => gacc[r].push((l, incl, lo, hi)),
                            None => acc[r] = Some(acc[r].map_or((lo, hi), |a| (a.0.min(lo), a.1.max(hi)))),
                        }
                    }
                }
            }
        }
        // the step comes after the instruction's own accesses (`add esi, 4` reads esi first)
        let w = written(i);
        for r in 0..8 {
            match konst {
                Some((k, c)) if k == r => step[r] = step[r].map(|s| s + c),
                _ if w & (1 << r) != 0 => step[r] = None,
                _ => {}
            }
        }
    }
    (0..8)
        .filter_map(|r| {
            step[r].filter(|&s| s != 0).map(|s| {
                // a guard h + cur < L lets through the head values up to L - cur - s (aligned like the loop
                // bound's last pass), h + cur <= L up to L - cur
                let g = gacc[r].iter().map(|&(l, incl, lo, hi)| (if incl { l } else { l - s }, lo, hi)).collect();
                (r, (s, acc[r], std::mem::take(&mut at[r]), g))
            })
        })
        .collect()
}

/// One instruction's effect on the state, and its evidence.
fn step(x: &WIns, next: Option<&WIns>, lp: Option<&Steps>, st: &mut St, fx: &mut Fx, data: &dyn Fn(i64) -> bool) {
    let mn = x.mn;
    let ops = &x.ops;
    // the accesses: every memory operand of a register base
    if mn != "lea" {
        for o in ops.iter().filter(|o| o.typ == OpType::Mem && o.base != Reg::None && depth_of(st, o).is_none()) {
            if let Some((v, _)) = addr_of(st, o, data) {
                let size = o.size.max(1) as i64;
                match v {
                    V::Addr(b, off) => fx.reach(V::Addr(b, 0), off.min(0), off + size, x.addr, "field"),
                    V::Arg(k, off) => fx.reach(V::Arg(k, 0), off.min(0), off + size, x.addr, "field"),
                    // a walking register's displacements may reach parallel arrays: no evidence (the loop bound is)
                    _ => {}
                }
            }
        }
    }
    let set = |st: &mut St, o: &crate::dis::Op, v: V| {
        if o.typ == OpType::Reg {
            if let Some((i, full)) = reg(o.reg) {
                st.r[i] = if full { v } else { V::Unk };
                if i == ESP {
                    st.d = None;
                }
            }
        } else if let Some(dp) = depth_of(st, o) {
            st.store(dp, if o.size == 4 { v } else { V::Unk });
        }
    };
    let get = |st: &St, o: &crate::dis::Op| -> V {
        if let Some(v) = val(st, o, data) {
            return v;
        }
        match depth_of(st, o) {
            Some(dp) if o.size == 4 => st.slot(dp),
            _ => V::Unk,
        }
    };
    let base = mn.trim_start_matches("rep ");
    let string = matches!(base, "movsb" | "movsw" | "movsd" | "stosb" | "stosw" | "stosd");
    match mn {
        "mov" if ops.len() == 2 => {
            let v = get(st, &ops[1]);
            set(st, &ops[0], v);
        }
        "lea" if ops.len() == 2 => {
            let v = addr_of(st, &ops[1], data).map(|x| x.0).unwrap_or(V::Unk);
            set(st, &ops[0], v);
        }
        "push" => {
            let v = ops.first().map(|o| get(st, o)).unwrap_or(V::Unk);
            if let Some(d) = st.d {
                st.d = Some(d + 4);
                st.store(d + 4, v);
            }
        }
        "pop" => {
            let v = st.d.map(|d| st.slot(d)).unwrap_or(V::Unk);
            st.d = st.d.map(|d| d - 4);
            if let Some(o) = ops.first() {
                if o.typ == OpType::Reg && reg(o.reg).is_some_and(|r| r.0 == ESP) {
                    st.d = None;
                } else {
                    set(st, o, v);
                }
            }
        }
        "xor" | "sub" if ops.len() == 2 && ops[0].typ == OpType::Reg && ops[1].typ == OpType::Reg && ops[0].reg == ops[1].reg => {
            set(st, &ops[0], V::Const(0));
        }
        "add" | "sub" if ops.len() == 2 && ops[0].typ == OpType::Reg => {
            let Some((i, full)) = reg(ops[0].reg) else { return };
            let k = get(st, &ops[1]);
            let sign = if mn == "add" { 1 } else { -1 };
            if i == ESP {
                st.d = match (st.d, k, full) {
                    (Some(d), V::Const(c), true) => Some(d - sign * c),
                    _ => None,
                };
                return;
            }
            st.r[i] = match (st.r[i], k, full) {
                (_, _, false) => V::Unk,
                (V::Const(a), V::Const(c), _) => V::Const(a + sign * c),
                (V::Addr(b, o), V::Const(c), _) => V::Addr(b, o + sign * c),
                (V::Arg(a, o), V::Const(c), _) => V::Arg(a, o + sign * c),
                (V::Frame(f), V::Const(c), _) => V::Frame(f - sign * c),
                (V::Walk(b), V::Const(c), _) if sign * c >= 0 => V::Walk(b),
                (V::Addr(b, _) | V::Walk(b), _, _) if sign > 0 => V::Walk(b),
                (V::Const(_) | V::Unk, V::Addr(b, _) | V::Walk(b), _) if sign > 0 => V::Walk(b),
                _ => V::Unk,
            };
        }
        "inc" | "dec" if ops.len() == 1 && ops[0].typ == OpType::Reg => {
            let Some((i, full)) = reg(ops[0].reg) else { return };
            let c = if mn == "inc" { 1 } else { -1 };
            st.r[i] = match (st.r[i], full) {
                (V::Const(a), true) => V::Const(a + c),
                (V::Addr(b, o), true) => V::Addr(b, o + c),
                (V::Walk(b), true) if c > 0 => V::Walk(b),
                _ => V::Unk,
            };
        }
        "cmp" if ops.len() == 2 => {
            // B walking up compared with END before an ordering jump: B .. END is one array
            let ordered = next.is_some_and(|n| n.flow == CJUMP && !matches!(n.mn, "je" | "jne" | "jz" | "jnz" | "js" | "jns" | "jo" | "jno" | "jp" | "jnp"));
            // the last pass has the register at END - step: its accesses there are the array's last bytes (a
            // pointer to a field of each record ends one record past the field, not past the array)
            if ordered && ops[0].typ == OpType::Reg {
                let (a, b) = (get(st, &ops[0]), get(st, &ops[1]));
                let walk = reg(ops[0].reg).filter(|r| r.1).and_then(|r| lp.and_then(|l| l.get(&r.0)));
                if let (V::Walk(base), V::Addr(end, 0), Some((s, acc, at, guarded))) = (a, b, walk) {
                    let s = *s;
                    // the last pass starts at END - s (a test at the top: head < END; at the bottom, after the
                    // step: head + s < END); its accesses at the register reach hi
                    let cur = at.get(&x.addr).copied().unwrap_or(0);
                    if cur != 0 && cur != s {
                        return;
                    }
                    // the accesses a guard of the body excludes past its limit: from its last head value when
                    // that is below the loop bound's
                    let last = end as i64 - s;
                    let acc = match (acc, guarded.is_empty()) {
                        (None, true) => Some((0, 1)),
                        (a, _) => *a,
                    };
                    let (mut lo, mut hi) = (base as i64, i64::MIN);
                    if let Some((lo_acc, hi_acc)) = acc {
                        lo = lo.min(base as i64 + lo_acc);
                        hi = last + hi_acc;
                    }
                    for &(gl, glo, ghi) in guarded {
                        lo = lo.min(base as i64 + glo);
                        hi = hi.max(last.min(gl) + ghi);
                    }
                    if s > 0 && end > base && hi > lo && !fx.overruns(x.addr) {
                        fx.ev.push(Ev { lo, hi, base, site: x.addr, how: "bound", to: 0 });
                    }
                }
            }
        }
        "leave" => {
            st.d = match st.r[EBP] {
                V::Frame(fd) => Some(fd - 4),
                _ => None,
            };
            st.r[EBP] = st.d.map(|d| st.slot(d)).unwrap_or(V::Unk);
            st.d = st.d.map(|d| d - 4);
        }
        "ret" => {
            if let Some(o) = ops.first().filter(|o| o.typ == OpType::Imm) {
                fx.pops = fx.pops.max(o.imm);
            }
        }
        _ if string => {
            let w = match base.as_bytes().last() {
                Some(b'b') => 1,
                Some(b'w') => 2,
                _ => 4,
            };
            let n = if x.rep {
                match st.r[ECX] {
                    V::Const(c) if c >= 0 => Some(c),
                    _ => None,
                }
            } else {
                Some(1)
            };
            let regs: &[usize] = if base.starts_with("movs") { &[EDI, ESI] } else { &[EDI] };
            for &r in regs {
                let v = st.r[r];
                match n {
                    Some(n) if n > 0 => fx.reach(v, 0, n * w, x.addr, "copy"),
                    _ => {}
                }
                st.r[r] = match (v, n) {
                    (V::Addr(b, o), Some(n)) => V::Addr(b, o + n * w),
                    (V::Arg(k, o), Some(n)) => V::Arg(k, o + n * w),
                    (V::Addr(b, _) | V::Walk(b), None) => V::Walk(b),
                    _ => V::Unk,
                };
            }
            if x.rep {
                st.r[ECX] = V::Const(0);
            }
        }
        _ => {
            let m = written(x);
            for i in 0..8 {
                if m & (1 << i) != 0 {
                    if i == ESP {
                        st.d = None;
                    }
                    st.r[i] = V::Unk;
                }
            }
            if ops.first().is_some_and(|o| o.typ == OpType::Mem) && !reads_only(mn) {
                if let Some(dp) = depth_of(st, &ops[0]) {
                    st.store(dp, V::Unk);
                }
            }
        }
    }
    if x.flow == CALL {
        let args: Vec<V> = (0..NARGS as i64).map(|j| st.d.map(|d| st.slot(d - 4 * j)).unwrap_or(V::Unk)).collect();
        match x.target {
            Some(t) => {
                if let Some(s) = fx.summaries.get(&(t as u32)) {
                    fx.callee = t as u32;
                    for (j, terms) in s.args.iter().enumerate() {
                        for t in terms {
                            apply(fx, args[j], t, &args, x.addr);
                        }
                    }
                    fx.callee = 0;
                }
                let pops = fx.pops_of.get(&(t as u32)).copied().unwrap_or(0);
                st.d = st.d.map(|d| d - pops);
            }
            None => st.d = None,
        }
        st.r[EAX] = V::Unk;
        st.r[ECX] = V::Unk;
        st.r[EDX] = V::Unk;
    }
}

/// A callee's term at a call site: the passed pointer reaches as far as the term with the passed arguments.
fn apply(fx: &mut Fx, p: V, t: &Term, args: &[V], site: u32) {
    if fx.overruns(site) {
        return;
    }
    let mut mult = t.mult;
    let mut f = vec![];
    for &k in &t.f {
        match args.get(k as usize).copied().unwrap_or(V::Unk) {
            V::Const(c) if c >= 0 => mult = mult.saturating_mul(c),
            V::Arg(m, 0) => f.push(m),
            _ => return,
        }
    }
    match p {
        V::Arg(k, o) if !f.is_empty() => fx.own.add(k as usize, Term { lo: (o + t.lo).min(0), hi: o + t.hi, mult, f }),
        V::Arg(k, o) => fx.own.add(k as usize, Term { lo: (o + t.lo).min(0), hi: o + t.hi + if t.f.is_empty() { 0 } else { mult }, mult: 0, f: vec![] }),
        _ if !f.is_empty() => {}
        _ => {
            let hi = t.hi + if t.f.is_empty() { 0 } else { mult };
            fx.reach(p, t.lo.min(0), hi, site, "call");
        }
    }
}

/// S.extent (module docs).
pub fn s_extent(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let img = crate::image(&ctx.image)?;
    let code: Vec<(i64, i64)> = crate::layout::code_ranges(&img);
    if code.is_empty() {
        return Ok(());
    }
    let (clo, chi) = (code.iter().map(|c| c.0).min().unwrap() as u32, code.iter().map(|c| c.1).max().unwrap() as u32);
    let data = |v: i64| {
        v > 0 && v <= u32::MAX as i64 && img.section_of(v as u32).is_some_and(|s| !s.holds_code())
    };
    let symbols = crate::setup::facts(ctx, db, "symbol")?;
    let mut funcs: Vec<(u32, u32)> = symbols.iter()
        .filter(|f| &*f.rule == "S.codewalk" && f.s("skind") == Some("func") && f.hi > f.lo)
        .map(|f| (f.lo as u32, f.hi as u32)).collect();
    funcs.sort();
    funcs.dedup_by_key(|f| f.0);
    let mut tables: Vec<(u32, u32)> = symbols.iter().filter(|f| matches!(f.s("skind"), Some("jumptable") | Some("idxtable")))
        .map(|f| (f.lo as u32, f.hi as u32)).collect();
    tables.sort();
    // the seeds
    let mut seeds: HashMap<u32, Summary> = HashMap::new();
    for f in crate::setup::facts(ctx, db, "name")?.iter().filter(|f| f.s("origin") == Some("lib")) {
        for n in f.s("name").unwrap_or("").split('|') {
            let c = crate::coff::undecorate(n);
            if let Some(s) = library_seed(c.trim_start_matches('_')).or_else(|| library_seed(&c)) {
                let e = seeds.entry(f.lo as u32).or_default();
                for (k, fs) in s {
                    e.add(k as usize, Term { lo: 0, hi: 0, mult: 1, f: fs });
                }
            }
        }
    }
    let (decls, _, targets, target) = crate::decl::project_decls(ctx)?;
    let default = targets.first().cloned().unwrap_or_default();
    let overrun_decls: Vec<&crate::decl::Decl> = decls.iter()
        .filter(|d| d.kind == "overrun" && d.target.as_deref().unwrap_or(&default) == target).collect();
    let overrun: HashSet<u32> = overrun_decls.iter().map(|d| d.lo as u32).collect();
    let mut hit: HashSet<u32> = HashSet::new();
    for d in decls.iter().filter(|d| d.kind == "writes" && d.target.as_deref().unwrap_or(&default) == target) {
        let (Some(p), Some(s)) = (d.key("ptr"), d.key("size")) else { continue };
        if let Some((k, t)) = writes_seed(p.s(), s.s()) {
            seeds.entry(d.lo as u32).or_default().add(k as usize, t);
        }
    }
    // decode every function once: contiguous chunks of them, each on a thread of its own (a decoder per thread)
    let fills: HashSet<Vec<u8>> = ctx.fill_forms.iter().cloned().collect();
    let chunks: Vec<std::sync::Mutex<(Decoder, &[(u32, u32)])>> = funcs.chunks(funcs.len().div_ceil(64).max(1))
        .map(|fs| {
            let (lo, hi) = (fs[0].0.max(clo), fs.iter().map(|f| f.1).max().unwrap().min(chi));
            std::sync::Mutex::new((Decoder::new(&img, lo, hi, &fills), fs))
        })
        .collect();
    let decoded = crate::compile_threads(&chunks, |m| -> Result<Vec<Vec<WIns>>, String> {
        let mut g = m.lock().unwrap();
        let (dec, fs) = &mut *g;
        let mut out = Vec::with_capacity(fs.len());
        for &(lo, hi) in fs.iter() {
            let (mut a, mut l) = (lo, vec![]);
            let mut ti = tables.partition_point(|t| t.1 <= lo);
            while a < hi {
                while ti < tables.len() && tables[ti].1 <= a {
                    ti += 1;
                }
                if ti < tables.len() && tables[ti].0 <= a && a < tables[ti].1 {
                    a = tables[ti].1;
                    continue;
                }
                match dec.at(a) {
                    Some(i) => {
                        a += i.size;
                        l.push(i.clone());
                    }
                    None => a += 1,
                }
            }
            out.push(l);
        }
        Ok(out)
    });
    let mut lists: Vec<Vec<WIns>> = Vec::with_capacity(funcs.len());
    for d in decoded {
        lists.extend(d.map_err(Error::runtime)?);
    }
    let callees: Vec<Vec<u32>> = lists.iter()
        .map(|l| l.iter().filter(|i| i.flow == CALL).filter_map(|i| i.target.map(|t| t as u32)).collect()).collect();
    // bottom-up: callees before their callers (a cycle is broken where the depth-first search meets it)
    let index: HashMap<u32, usize> = funcs.iter().enumerate().map(|(i, f)| (f.0, i)).collect();
    let mut order: Vec<usize> = Vec::with_capacity(funcs.len());
    let mut state = vec![0u8; funcs.len()];
    for root in 0..funcs.len() {
        if state[root] != 0 {
            continue;
        }
        let mut stack: Vec<(usize, usize)> = vec![(root, 0)];
        state[root] = 1;
        while let Some(&mut (f, ref mut k)) = stack.last_mut() {
            if *k < callees[f].len() {
                let t = callees[f][*k];
                *k += 1;
                if let Some(&g) = index.get(&t) {
                    if state[g] == 0 {
                        state[g] = 1;
                        stack.push((g, 0));
                    }
                }
            } else {
                state[f] = 2;
                order.push(f);
                stack.pop();
            }
        }
    }
    let mut summaries = seeds.clone();
    let mut pops_of: HashMap<u32, i64> = HashMap::new();
    let mut per_base: BTreeMap<u32, (i64, i64, u32, &'static str, u32, u32)> = BTreeMap::new();
    for &f in &order {
        let (lo, hi) = funcs[f];
        let ins: Vec<&WIns> = lists[f].iter().collect();
        let mut fx = Fx { data: &data, summaries: &summaries, pops_of: &pops_of, own: Summary::default(), ev: vec![], callee: 0, pops: 0,
                          overrun: &overrun, hit: vec![] };
        analyse(&ins, lo, hi, &mut fx);
        hit.extend(fx.hit.iter().copied());
        let (own, ev, pops) = (fx.own, fx.ev, fx.pops);
        if pops > 0 {
            pops_of.insert(lo, pops);
        }
        for e in ev {
            if e.hi - e.lo > MAX_SPAN || !data(e.lo) || !data(e.hi - 1) {
                continue;
            }
            let r = per_base.entry(e.base).or_insert((e.lo, e.hi, e.site, e.how, lo, e.to));
            r.0 = r.0.min(e.lo);
            if e.hi > r.1 {
                *r = (r.0, e.hi, e.site, e.how, lo, e.to);
            }
        }
        if !own.args.is_empty() && !seeds.contains_key(&lo) {
            summaries.insert(lo, own);
        }
    }
    for (b, (lo, hi, site, how, func, to)) in per_base {
        let mut v = json!({"ekind": "extent", "base": b, "site": site, "how": how, "fn": func});
        if to != 0 {
            v["to"] = json!(to);
        }
        out.claim(lo, hi, "evidence", v, DERIVED);
    }
    // an exception without evidence: the instruction (no longer) proves anything there
    for d in overrun_decls.iter().filter(|d| !hit.contains(&(d.lo as u32))) {
        out.finding("warn", "S.extent.overrun", d.lo, d.lo + 1,
                     format!("{}:{}: overrun at {:#x}: the original's code there proves no object's extent (no access through a data address, \
                              no copy, no loop bound): the exception has no evidence; drop it", d.file, d.line, d.lo), &d.by());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::pe::testpe::{build_with, BASE, DATA, TEXT};
    use crate::rules::testkit::{of, Kit};
    use crate::rules::dispatch;
    use crate::store::DERIVED;
    use serde_json::json;

    fn le(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    /// One function per kind of evidence in .text, and their (start, end) offsets.
    fn code() -> (Vec<u8>, Vec<(u32, u32)>) {
        let d = BASE + DATA;
        let mut c = vec![0xccu8; 0x120];
        let mut fns = vec![];
        let mut put = |at: usize, b: &[u8]| {
            c[at..at + b.len()].copy_from_slice(b);
            fns.push((at as u32, (at + b.len()) as u32));
        };
        // 0x00 bound: mov eax, D+0x84; L: cmp [eax], edx; je out; add eax, 0x10; cmp eax, D+0xc4; jl L; out: ret
        put(0x00, &[&[0xb8][..], &le(d + 0x84), &[0x39, 0x10, 0x74, 0x0a, 0x83, 0xc0, 0x10, 0x3d], &le(d + 0xc4), &[0x7c, 0xf2, 0xc3]].concat());
        // 0x20 field: mov ecx, D+0x90; mov [ecx+0x20], eax; ret
        put(0x20, &[&[0xb9][..], &le(d + 0x90), &[0x89, 0x41, 0x20, 0xc3]].concat());
        // 0x40 g(p): mov eax, [esp+4]; mov [eax+8], ecx; ret     0x50: push D+0x60; call g; add esp, 4; ret
        put(0x40, &[0x8b, 0x44, 0x24, 0x04, 0x89, 0x48, 0x08, 0xc3]);
        put(0x50, &[&[0x68][..], &le(d + 0x60), &[0xe8], &(0x40i32 - 0x5a).to_le_bytes(), &[0x83, 0xc4, 0x04, 0xc3]].concat());
        // 0x70 copy: mov edi, D+0xc0; mov ecx, 8; xor eax, eax; rep stosd; ret
        put(0x70, &[&[0xbf][..], &le(d + 0xc0), &[0xb9, 8, 0, 0, 0, 0x31, 0xc0, 0xf3, 0xab, 0xc3]].concat());
        // 0x90 a reader declared `writes ptr=a0 size=a1*a2` (its body says nothing); 0xa0: reader(D+0xe0, 4, 3)
        put(0x90, &[0xc3]);
        put(0xa0, &[&[0x6a, 0x03, 0x6a, 0x04, 0x68][..], &le(d + 0xe0), &[0xe8], &(0x90i32 - 0xae).to_le_bytes(), &[0x83, 0xc4, 0x0c, 0xc3]].concat());
        // 0xc0 parallel arrays through one register (a strength-reduced loop): mov esi, D+0x2a0;
        // L: mov [esi-0x10], eax; mov [esi], eax; add esi, 4; cmp esi, D+0x2b0; jl L; ret
        put(0xc0, &[&[0xbe][..], &le(d + 0x2a0), &[0x89, 0x46, 0xf0, 0x89, 0x06, 0x83, 0xc6, 0x04, 0x81, 0xfe], &le(d + 0x2b0), &[0x7c, 0xf0, 0xc3]]
            .concat());
        // 0xe0 a guard in the body (a slot shift): mov esi, D+0x310; L: cmp esi, D+0x3c4; jge skip;
        // mov eax, [esi]; mov [esi+4], eax; skip: mov ecx, [esi-0xc]; add esi, 0xc; cmp esi, D+0x3d0; jl L; ret
        // (the last pass, esi = D+0x3c4, skips [esi]: the array ends at D+0x3c4 - 0xc + 4, not D+0x3d0 - 0xc + 4)
        put(0xe0, &[&[0xbe][..], &le(d + 0x310), &[0x81, 0xfe], &le(d + 0x3c4), &[0x7d, 0x05, 0x8b, 0x06, 0x89, 0x46, 0x04,
            0x8b, 0x4e, 0xf4, 0x83, 0xc6, 0x0c, 0x81, 0xfe], &le(d + 0x3d0), &[0x7c, 0xe5, 0xc3]].concat());
        (c, fns)
    }

    #[test]
    fn extents_the_code_proves() {
        let (c, fns) = code();
        let k = Kit::new(&build_with(None, Some(&c)));
        let t = (BASE + TEXT) as i64;
        let syms: Vec<(i64, i64, &str, serde_json::Value, crate::store::Support)> =
            fns.iter().map(|&(a, b)| (t + a as i64, t + b as i64, "symbol", json!({"skind": "func", "extent": "derived"}), DERIVED)).collect();
        k.put("S.codewalk", &syms);
        std::fs::create_dir_all(k.dir.join("decl")).unwrap();
        std::fs::write(k.dir.join("decl/text.dcl"), format!("{:#010x} writes ptr=a0 size=a1*a2 -- a reader\n", t + 0x90)).unwrap();
        let ctx = k.ctx("S.extent", &["S.codewalk"], r#"{"toolchain": "vc6"}"#);
        let (rows, conflicts) = dispatch(&ctx).unwrap().sorted();
        assert!(conflicts.is_empty());
        let d = (BASE + DATA) as i64;
        let got: Vec<(i64, i64, String)> =
            of(&rows, "evidence").into_iter().map(|(lo, hi, v)| (lo - d, hi - d, v["how"].as_str().unwrap().to_string())).collect();
        assert_eq!(got, [
            (0x60, 0x6c, "call".to_string()), // g writes p + 8 .. p + 0xc
            (0x84, 0xb8, "bound".into()),     // the last pass starts at END - 0x10 and reads 4 bytes there
            (0x90, 0xb4, "field".into()),
            (0xc0, 0xe0, "copy".into()),
            (0xe0, 0xec, "call".into()),      // the declared reader: 4 * 3 bytes
            (0x2a0, 0x2b0, "bound".into()),   // the register's own array only, not the one at -0x10
            (0x310, 0x3bc, "bound".into()),   // the guarded accesses stop at the guard's last pass
        ]);
        let call = of(&rows, "evidence").into_iter().find(|r| r.0 == d + 0xe0).unwrap().2;
        assert_eq!((call["to"].as_i64(), call["site"].as_i64()), (Some(t + 0x90), Some(t + 0xa9)));
    }

    /// An `overrun` exception (a memset of six ints into five): the rep stosd at it is no
    /// evidence; one at an instruction that proves nothing (a ret) is stale.
    #[test]
    fn an_overrun_exception_removes_its_evidence() {
        let (c, fns) = code();
        let k = Kit::new(&build_with(None, Some(&c)));
        let t = (BASE + TEXT) as i64;
        let syms: Vec<(i64, i64, &str, serde_json::Value, crate::store::Support)> =
            fns.iter().map(|&(a, b)| (t + a as i64, t + b as i64, "symbol", json!({"skind": "func", "extent": "derived"}), DERIVED)).collect();
        k.put("S.codewalk", &syms);
        std::fs::create_dir_all(k.dir.join("decl")).unwrap();
        std::fs::write(k.dir.join("decl/text.dcl"), format!("{:#010x} overrun -- six ints into five\n{:#010x} overrun -- nothing there\n",
                                                            t + 0x7c, t + 0x90)).unwrap();
        let ctx = k.ctx("S.extent", &["S.codewalk"], r#"{"toolchain": "vc6"}"#);
        let (rows, conflicts) = dispatch(&ctx).unwrap().sorted();
        let d = (BASE + DATA) as i64;
        assert!(!of(&rows, "evidence").iter().any(|r| r.0 == d + 0xc0), "the copy at the exception is no evidence");
        assert!(of(&rows, "evidence").iter().any(|r| r.0 == d + 0x84), "the rest stays");
        let stale: Vec<String> = conflicts.iter().map(|c| format!("{} {}", c.check, c.message)).collect();
        assert_eq!(stale.len(), 1, "{stale:?}");
        assert!(stale[0].contains("S.extent.overrun") && stale[0].contains(&format!("overrun at {:#x}", t + 0x90)), "{stale:?}");
    }
}
