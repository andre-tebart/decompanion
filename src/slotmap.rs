//! Slot pairing by object (tasks/slot-pairing-by-object.md): a constant-offset access into a local array that the
//! alignment pairs with another offset of the original's array than the arrays' bases pair with.
//!
//! diffclass explains a stack displacement pair (`[esp+X]` against `[esp+Y]`) per hunk as a slot renaming. A wrong
//! index into a local array (`balance[0x11]` where the original reads `balance[0]`: gildegold
//! ai_BuildingDetailWindow) is such a pair too. Here the function is read as a whole: each stack operand at its
//! entry-relative slot (esp at the instruction, taken from a walk of the code, plus the displacement), the arrays
//! as the slots whose address is taken (`lea r, [esp+S]`) or that are indexed (`[esp+S+r*k]`), each array up to the
//! next one. A plain access inside one of our arrays and inside the original's array its base is paired with must
//! lie at the same offset from both bases.
//!
//! A report, not a verdict yet: the extent of an array is a guess (up to the next base on its side), so a scalar
//! the two frames lay out differently after an array can be listed.

use crate::dis::{self, Flow, Ins, OpType, Reg};
use crate::x86::Line;
use std::collections::{BTreeSet, HashMap};

/// The saves of a function: a push of a callee-saved register the function has not written before it (in address
/// order; VC6 schedules them into the first statement's code), by address. They are no call's arguments: a stdcall
/// call through a register right after them (`call esi`, GetPrivateProfileStringA) pops its own pushes only.
pub fn save_pushes(ins: &[Ins]) -> std::collections::HashSet<u32> {
    let mut written = 0u32;
    let mut v = std::collections::HashSet::new();
    for i in ins {
        if i.mn == "push" {
            if let Some(o) = i.ops.first().filter(|o| o.typ == OpType::Reg && o.reg.size() == 4) {
                if let Some(g) = dis::gpr(o.reg) {
                    if matches!(g, 3 | 5 | 6 | 7) && written & (1 << g) == 0 {
                        v.insert(i.addr);
                    }
                }
            }
        }
        written |= (i.defs & 0xff) as u32;
        if matches!(i.flow, Flow::Ret) {
            break;
        }
    }
    v
}

/// esp relative to the entry (the return address at 0) before each instruction reached from the entry, by address;
/// None when the walk meets two depths at one address or an esp write it does not follow (an ebp frame's
/// `mov esp, ebp`, `and esp`, `leave`).
pub fn depths(ins: &[Ins], va: u32) -> Option<HashMap<u32, i32>> {
    let at: HashMap<u32, usize> = ins.iter().enumerate().map(|(k, i)| (i.addr, k)).collect();
    let mut out: HashMap<u32, i32> = HashMap::new();
    // the saves: a push of a callee-saved register the function has not written before it (in address order; VC6
    // schedules them into the first statement's code). They are no call's arguments: a stdcall call through a
    // register right after them (`call esi`, GetPrivateProfileStringA) pops its own pushes only
    let saves = save_pushes(ins);
    // (.., ebp's depth once `mov ebp, esp` set it: an ebp frame's `mov esp, ebp` and `leave` restore esp from it)
    let mut todo = vec![(va, 0i32, 0i32, None::<i32>)];
    while let Some((mut a, mut d, mut pending, mut ebp)) = todo.pop() {
        loop {
            let Some(&k) = at.get(&a) else { break };
            match out.get(&a) {
                Some(&x) if x == d => break,
                Some(_) => return None,
                None => {
                    out.insert(a, d);
                }
            }
            let i = &ins[k];
            let op0 = i.ops.first();
            let esp0 = op0.is_some_and(|o| o.typ == OpType::Reg && o.reg == Reg::ESP);
            let imm1 = i.ops.get(1).filter(|o| o.typ == OpType::Imm).map(|o| o.imm as i32);
            match i.mn {
                "push" => {
                    d -= 4;
                    if !saves.contains(&i.addr) {
                        pending += 4;
                    }
                }
                "pop" if esp0 => return None,
                "pop" => d += 4,
                "pushad" => d -= 32,
                "popad" => d += 32,
                "pushfd" => d -= 4,
                "popfd" => d += 4,
                "sub" if esp0 => d -= imm1?,
                "add" if esp0 => {
                    d += imm1?;
                    pending = 0;
                }
                "leave" => {
                    d = ebp? + 4;
                    pending = 0;
                }
                "mov" if op0.is_some_and(|o| o.typ == OpType::Reg && o.reg == Reg::EBP) && i.ops.get(1).is_some_and(|o| o.typ == OpType::Reg && o.reg == Reg::ESP) => {
                    ebp = Some(d);
                }
                "mov" if esp0 && i.ops.get(1).is_some_and(|o| o.typ == OpType::Reg && o.reg == Reg::EBP) => {
                    d = ebp?;
                    pending = 0;
                }
                "call" => {
                    // through memory or a register with no `add esp` after it: stdcall, the callee pops its arguments
                    let next = ins.get(k + 1);
                    let cleans = next.is_some_and(|n| n.mn == "add" && n.ops.first().is_some_and(|o| o.typ == OpType::Reg && o.reg == Reg::ESP));
                    if op0.is_some_and(|o| o.typ != OpType::Imm) && !cleans {
                        d += pending;
                        pending = 0;
                    }
                }
                _ if esp0 && !matches!(i.mn, "cmp" | "test") => return None,
                _ => {}
            }
            match i.flow {
                Flow::Ret | Flow::Trap | Flow::IndirectJump => break,
                Flow::Jump => match i.target {
                    Some(t) if at.contains_key(&t) => a = t,
                    _ => break,
                },
                Flow::CondJump => {
                    if let Some(t) = i.target {
                        todo.push((t, d, pending, ebp));
                    }
                    a = i.addr + i.size;
                }
                Flow::Next | Flow::Call => a = i.addr + i.size,
            }
        }
    }
    Some(out)
}

/// One stack operand of an instruction: its entry-relative slot and whether it is an array's base (the address
/// taken, or indexed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Access {
    slot: i32,
    base: bool,
}

fn accesses(i: &Ins, depth: i32, ebp: Option<i32>) -> Vec<Access> {
    i.ops.iter().filter(|o| o.typ == OpType::Mem && (o.base == Reg::ESP || o.base == Reg::EBP && ebp.is_some()))
        .map(|o| {
            let at = if o.base == Reg::ESP { depth } else { ebp.unwrap_or(0) };
            Access { slot: at + o.disp as i32, base: i.mn == "lea" || o.index != Reg::None }
        })
        .collect()
}

/// ebp's depth in an ebp frame (the depth at its `mov ebp, esp`), None without one.
pub fn ebp_base(ins: &[Ins], d: &HashMap<u32, i32>) -> Option<i32> {
    ins.iter().find(|i| i.mn == "mov" && i.ops.first().is_some_and(|o| o.typ == OpType::Reg && o.reg == Reg::EBP)
                    && i.ops.get(1).is_some_and(|o| o.typ == OpType::Reg && o.reg == Reg::ESP))
        .and_then(|i| d.get(&i.addr).copied())
}

/// A plain access whose offset into the paired arrays differs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotDiff {
    /// our instruction's offset in the function
    pub off: u32,
    /// the array bases (entry-relative) and the offsets into them, ours and the original's
    pub ours: (i32, i32),
    pub theirs: (i32, i32),
}

impl SlotDiff {
    pub fn line(&self) -> String {
        let s = |x: i32| if x < 0 { format!("-{:#x}", -x) } else { format!("{x:#x}") };
        format!("M.slotmap at +{:#x}: ours reads the local array at entry{} at offset {:#x}, the original its array at entry{} (paired \
                 with ours) at offset {:#x}: another element", self.off, s(self.ours.0), self.ours.1, s(self.theirs.0), self.theirs.1)
    }
}

/// The array of a side holding `slot`: the greatest base at or below it (each array up to the next base).
fn array_of(bases: &BTreeSet<i32>, slot: i32) -> Option<i32> {
    bases.range(..=slot).next_back().copied()
}

/// The aligned pairs of stack operands: (our instruction, ours, the original's, the hunk). The listings are aligned
/// with each stack operand read as its entry-relative slot, so two frames of other sizes (and other push depths)
/// line up where they address the same slot; `[esp + 0x2c]` on both sides is no pair when the frames differ.
fn aligned_pairs(ia: &[Ins], ib: &[Ins], da: &HashMap<u32, i32>, db: &HashMap<u32, i32>, la: &[Line], lb: &[Line]) -> Vec<(u32, Access, Access, usize)> {
    use crate::difflib::{opcodes, Tag};
    let by = |ins: &[Ins]| -> HashMap<u32, usize> { ins.iter().enumerate().map(|(k, i)| (i.addr, k)).collect() };
    let (ka, kb) = (by(ia), by(ib));
    let key = |l: &Line, ins: &[Ins], k: &HashMap<u32, usize>, d: &HashMap<u32, i32>| -> String {
        let acc = k.get(&l.addr).and_then(|&x| d.get(&ins[x].addr).map(|&dx| accesses(&ins[x], dx, ebp_base(ins, d)))).unwrap_or_default();
        match (acc.first(), l.text.find('['), l.text.find(']')) {
            (Some(a), Some(s), Some(e)) if s < e && l.text[s..e].contains("esp") => {
                format!("{}[S{}{}]{}", &l.text[..s], a.slot, if a.base { "+" } else { "" }, &l.text[e + 1..])
            }
            _ => l.text.clone(),
        }
    };
    let (ea, eb) = (ebp_base(ia, da), ebp_base(ib, db));
    let ka_keys: Vec<String> = la.iter().map(|l| key(l, ia, &ka, da)).collect();
    let kb_keys: Vec<String> = lb.iter().map(|l| key(l, ib, &kb, db)).collect();
    let ta: Vec<&str> = ka_keys.iter().map(|s| s.as_str()).collect();
    let tb: Vec<&str> = kb_keys.iter().map(|s| s.as_str()).collect();
    // (our instruction, ours, the original's, the hunk)
    let mut pairs: Vec<(u32, Access, Access, usize)> = vec![];
    for (h, (tag, i1, i2, j1, j2)) in opcodes(&ta, &tb).into_iter().enumerate() {
        if tag != Tag::Equal && i2 - i1 != j2 - j1 {
            continue;
        }
        for (i, j) in (i1..i2).zip(j1..j2) {
            if la[i].shape.mn != lb[j].shape.mn {
                continue;
            }
            let (Some(&x), Some(&y)) = (ka.get(&la[i].addr), kb.get(&lb[j].addr)) else { continue };
            let (Some(&dx), Some(&dy)) = (da.get(&ia[x].addr), db.get(&ib[y].addr)) else { continue };
            let (ax, ay) = (accesses(&ia[x], dx, ea), accesses(&ib[y], dy, eb));
            if ax.len() == ay.len() {
                pairs.extend(ax.into_iter().zip(ay).map(|(p, q)| (ia[x].addr, p, q, h)));
            }
        }
    }
    pairs
}

/// The check over a function: our code and the original's at `va`, and the two listings the alignment reads.
pub fn check(ours: &[u8], theirs: &[u8], va: u32, la: &[Line], lb: &[Line]) -> Vec<SlotDiff> {
    let (ia, ib) = (dis::decode(ours, va), dis::decode(theirs, va));
    let (Some(da), Some(db)) = (depths(&ia, va), depths(&ib, va)) else { return vec![] };
    // esp frames only: an ebp frame's arrays are guessed no better, and the check was measured on esp frames
    if ebp_base(&ia, &da).is_some() || ebp_base(&ib, &db).is_some() {
        return vec![];
    }
    // every array base of each side (the whole function, paired or not)
    let bases_of = |ins: &[Ins], d: &HashMap<u32, i32>| -> BTreeSet<i32> {
        ins.iter().filter_map(|i| d.get(&i.addr).map(|&x| accesses(i, x, ebp_base(ins, d)))).flatten().filter(|a| a.base && a.slot < 0).map(|a| a.slot).collect()
    };
    let (ba, bb) = (bases_of(&ia, &da), bases_of(&ib, &db));
    if ba.is_empty() || bb.is_empty() {
        return vec![];
    }
    let pairs = aligned_pairs(&ia, &ib, &da, &db, la, lb);
    // the base pairs: our array -> the original's (the first pairing; a base paired two ways is no evidence)
    let mut base_to: HashMap<i32, Option<i32>> = HashMap::new();
    for &(_, p, q, _) in &pairs {
        if p.base && q.base && p.slot < 0 && q.slot < 0 {
            let e = base_to.entry(p.slot).or_insert(Some(q.slot));
            if *e != Some(q.slot) {
                *e = None;
            }
        }
    }
    // the plain accesses inside paired arrays: (our instruction, our array, the original's, the two offsets, the hunk)
    let inside: Vec<(u32, i32, i32, i32, i32, usize)> = pairs.iter().filter(|(_, p, q, _)| !p.base && !q.base && p.slot < 0 && q.slot < 0)
        .filter_map(|&(at, p, q, h)| {
            let (sa, sb) = (array_of(&ba, p.slot)?, array_of(&bb, q.slot)?);
            // ours inside an array whose base is paired with the original's array holding the access
            (base_to.get(&sa).copied().flatten() == Some(sb)).then_some((at, sa, sb, p.slot - sa, q.slot - sb, h))
        }).collect();
    // per pair of arrays, the correspondence of their elements: the offset difference most accesses agree on (the
    // bases may pair a few bytes apart). An access off it whose element is paired by that difference elsewhere
    // (on either side) is another element. Without a clear majority the two frames lay out what follows the base
    // otherwise (scalars after it, a struct whose members are in another order): nothing is said.
    let mut deltas: HashMap<(i32, i32), HashMap<i32, usize>> = HashMap::new();
    for x in &inside {
        *deltas.entry((x.1, x.2)).or_default().entry(x.4 - x.3).or_default() += 1;
    }
    let dominant = |sa: i32, sb: i32| -> Option<i32> {
        let m = deltas.get(&(sa, sb))?;
        let total: usize = m.values().sum();
        let (d, n) = m.iter().map(|(&d, &n)| (d, n)).max_by_key(|&(d, n)| (n, -d.abs()))?;
        (n >= 2 && 2 * n > total).then_some(d)
    };
    let paired: BTreeSet<(i32, i32, i32, i32)> = inside.iter().map(|x| (x.1, x.2, x.3, x.4)).collect();
    // a hunk whose two sides touch the same elements of the pair of arrays (the original's offsets those of ours by
    // the correspondence, as multisets) is reordered code paired crosswise by position, no other element
    let crossed = |h: usize, sa: i32, sb: i32, d: i32| {
        let (mut xs, mut ys): (Vec<i32>, Vec<i32>) = inside.iter().filter(|x| x.5 == h && x.1 == sa && x.2 == sb).map(|x| (x.3 + d, x.4)).unzip();
        xs.sort();
        ys.sort();
        xs == ys
    };
    // how often each side touches each slot anywhere in the function (aligned or not): stores reordered across
    // hunks touch the same elements as often on both sides; another element shifts one access from one element
    // to another, so both elements' counts differ
    let touched = |ins: &[Ins], d: &HashMap<u32, i32>| -> HashMap<i32, usize> {
        let mut m = HashMap::new();
        for a in ins.iter().filter_map(|i| d.get(&i.addr).map(|&x| accesses(i, x, ebp_base(ins, d)))).flatten() {
            *m.entry(a.slot).or_insert(0) += 1;
        }
        m
    };
    let (ta_all, tb_all) = (touched(&ia, &da), touched(&ib, &db));
    let mut out = vec![];
    let mut seen = BTreeSet::new();
    for &(at, sa, sb, oa, ob, h) in &inside {
        let Some(d) = dominant(sa, sb) else { continue };
        let n = |m: &HashMap<i32, usize>, s: i32| m.get(&s).copied().unwrap_or(0);
        let missing = n(&ta_all, sa + oa) != n(&tb_all, sb + oa + d) && n(&ta_all, sa + ob - d) != n(&tb_all, sb + ob);
        if oa != ob && ob - oa != d && (paired.contains(&(sa, sb, ob - d, ob)) || paired.contains(&(sa, sb, oa, oa + d))) && !crossed(h, sa, sb, d)
            && missing && seen.insert(at) {
            out.push(SlotDiff { off: at - va, ours: (sa, oa), theirs: (sb, ob) });
        }
    }
    out
}

// ------------------------------------------------------------------------------------------------ the frame view

/// One stack slot of a side: the widest access, the reads and writes, an array base.
#[derive(Clone, Debug, Default)]
struct Slot {
    size: u8,
    reads: usize,
    writes: usize,
    base: bool,
}

/// The mnemonics whose first operand they write (a memory destination: a store).
const STORES: &[&str] = &["mov", "fstp", "fst", "fistp", "fist", "fnstsw", "fnstcw", "pop", "inc", "dec", "add", "sub", "and", "or", "xor", "neg",
                          "not", "shl", "shr", "sar", "adc", "sbb", "movsb", "movsd", "stosd", "stosb"];

type Slots = std::collections::BTreeMap<i32, Slot>;

/// The slots of one side by entry-relative offset, esp after the prologue (the saves pushed, `sub esp, N`, in either
/// order; `[esp + X]` in the body at that depth is the slot depth + X), and the saved registers' slots.
fn slots(ins: &[Ins], d: &HashMap<u32, i32>) -> (Slots, i32, BTreeSet<i32>) {
    // the body's depth: the lowest the saves and the frame's `sub esp` (or `mov eax, N; call __chkstk`) take esp
    // before the first branch or other call (VC6 schedules the saves into the first statement's code)
    let save_at = save_pushes(ins);
    let mut body = 0;
    let mut saves = BTreeSet::new();
    for (k, i) in ins.iter().enumerate() {
        let esp0 = i.ops.first().is_some_and(|o| o.typ == OpType::Reg && o.reg == Reg::ESP);
        let chkstk = i.mn == "call" && k > 0 && ins[k - 1].mn == "mov"
            && ins[k - 1].ops.first().is_some_and(|o| o.typ == OpType::Reg && o.reg == Reg::EAX)
            && ins[k - 1].ops.get(1).is_some_and(|o| o.typ == OpType::Imm && o.imm >= 0x1000);
        let frame = save_at.contains(&i.addr) || (i.mn == "sub" && esp0) || chkstk;
        if !frame && (i.mn == "call" || i.flow != Flow::Next) {
            break;
        }
        if frame {
            if let Some(&x) = d.get(&(i.addr + i.size)) {
                body = body.min(x);
            }
        }
    }
    // the saved registers' slots: where each save push wrote
    for a in save_pushes(ins) {
        if let Some(&x) = d.get(&a) {
            saves.insert(x - 4);
        }
    }
    let mut out = Slots::new();
    let ebp = ebp_base(ins, d);
    for i in ins {
        let Some(&dx) = d.get(&i.addr) else { continue };
        for (k, o) in i.ops.iter().enumerate() {
            if o.typ != OpType::Mem || !(o.base == Reg::ESP || o.base == Reg::EBP && ebp.is_some()) {
                continue;
            }
            let dx = if o.base == Reg::ESP { dx } else { ebp.unwrap_or(0) };
            if saves.contains(&(dx + o.disp as i32)) {
                continue;
            }
            let s = out.entry(dx + o.disp as i32).or_default();
            s.size = s.size.max(o.size);
            if i.mn == "lea" || o.index != Reg::None {
                s.base = true;
            } else if k == 0 && STORES.contains(&i.mn) {
                s.writes += 1;
            } else {
                s.reads += 1;
            }
        }
    }
    (out, body, saves)
}

/// `dcp frame NAME`'s lines (improvement-reports/frame-slot-map-command.md): both frames' slots as `[esp + X]` at the
/// body's depth (after the prologue), each with its size, its reads and writes, whether it is an array base (its
/// address taken or indexed), and the original's slots the alignment pairs it with; the slots of one side paired with
/// several of the other (locals that share a slot on one side only), and the holes (bytes of the locals no access
/// touches, an array up to the next slot).
pub fn frame(ours: &[u8], theirs: &[u8], va: u32, la: &[Line], lb: &[Line], names: &[(i32, String)]) -> Vec<String> {
    let (ia, ib) = (dis::decode(ours, va), dis::decode(theirs, va));
    let (Some(da), Some(db)) = (depths(&ia, va), depths(&ib, va)) else {
        return vec!["the stack depth is not followed through one of the two functions (an ebp frame, or esp written another way): no frame view".into()];
    };
    let ((sa, body_a, saves_a), (sb, body_b, saves_b)) = (slots(&ia, &da), slots(&ib, &db));
    let pairs = aligned_pairs(&ia, &ib, &da, &db, la, lb);
    let mut to: HashMap<i32, std::collections::BTreeMap<i32, usize>> = HashMap::new();
    let mut from: HashMap<i32, std::collections::BTreeMap<i32, usize>> = HashMap::new();
    for (_, p, q, _) in &pairs {
        *to.entry(p.slot).or_default().entry(q.slot).or_default() += 1;
        *from.entry(q.slot).or_default().entry(p.slot).or_default() += 1;
    }
    // a slot as the body reads it: `[esp+0x10]` (an ebp frame's `[ebp-0x18]`), the return address's place, an
    // argument
    let (ebp_a, ebp_b) = (ebp_base(&ia, &da), ebp_base(&ib, &db));
    let at = |slot: i32, body: i32| -> String {
        let ebp = if body == body_a { ebp_a } else { ebp_b };
        if slot >= 4 {
            format!("arg+{:#x}", slot - 4)
        } else if slot >= 0 {
            "ret".into()
        } else if let Some(e) = ebp {
            format!("[ebp-{:#x}]", e - slot)
        } else {
            format!("[esp+{:#x}]", slot - body)
        }
    };
    let fmt_slot = |s: &Slot| -> String {
        let mut v = vec![];
        if s.base {
            v.push("array".to_string());
        }
        if s.reads > 0 {
            v.push(format!("r{}", s.reads));
        }
        if s.writes > 0 {
            v.push(format!("w{}", s.writes));
        }
        v.join(" ")
    };
    let (va_saves, vb_saves) = (saves_a.len() as i32 * 4, saves_b.len() as i32 * 4);
    let mut out = vec![format!("frame: ours {:#x} bytes of locals ({} saved registers), the original {:#x} ({}){}",
                               -body_a - va_saves, saves_a.len(), -body_b - vb_saves, saves_b.len(),
                               if body_a == body_b { String::new() } else {
                                   let x = body_b - body_a;
                                   format!("; the original's body esp {}{:#x} from ours", if x < 0 { "-" } else { "+" }, x.unsigned_abs())
                               })];
    // our variables by slot (VC6's frame symbols, the entry-relative slot): an exact slot, or inside the nearest
    // variable below it (an element or a field)
    let mut by_slot: std::collections::BTreeMap<i32, Vec<&str>> = Default::default();
    for (o, n) in names {
        by_slot.entry(*o).or_default().push(n.as_str());
    }
    let name_of = |slot: i32| -> String {
        match by_slot.range(..=slot).next_back() {
            Some((o, ns)) if *o == slot => ns.join("/"),
            Some((o, ns)) if slot < 0 && slot - o < 0x400 && by_slot.range(o + 1..).next().is_none_or(|(n, _)| *n > slot) && sa.get(o).is_some_and(|x| x.base) => {
                format!("{}+{:#x}", ns.join("/"), slot - o)
            }
            _ => String::new(),
        }
    };
    let width = sa.keys().map(|k| name_of(*k).chars().count()).max().unwrap_or(0).clamp(4, 28);
    out.push(format!("  {:<14} {:<width$} {:>5}  {:<14} the original's slots paired (times)", "ours", if names.is_empty() { "" } else { "name" }, "size", "use"));
    for (slot, s) in &sa {
        let paired = to.get(slot).map(|m| m.iter().map(|(q, n)| format!("{} ({n})", at(*q, body_b))).collect::<Vec<_>>().join(", ")).unwrap_or_else(|| "-".into());
        let mark = match to.get(slot) {
            Some(m) if m.len() > 1 => "   <- several",
            Some(m) if m.keys().next().is_some_and(|q| at(*q, body_b) != at(*slot, body_a)) => "   <- moved",
            _ => "",
        };
        out.push(format!("  {:<14} {:<width$} {:>5}  {:<14} {paired}{mark}", at(*slot, body_a), name_of(*slot), format!("{:#x}", s.size), fmt_slot(s)));
    }
    let lone: Vec<String> = sb.iter().filter(|(q, _)| !from.contains_key(q)).map(|(q, s)| format!("{} {:#x} {}", at(*q, body_b), s.size, fmt_slot(s))).collect();
    if !lone.is_empty() {
        out.push(format!("  the original's slots no slot of ours pairs with: {}", lone.join("; ")));
    }
    // a slot of the original paired with several of ours: the original shares it between locals ours keeps apart
    for (q, m) in from.iter().filter(|(_, m)| m.len() > 1).collect::<std::collections::BTreeMap<_, _>>() {
        let ours: Vec<String> = m.iter().map(|(p, n)| format!("{} ({n})", at(*p, body_a))).collect();
        let named: Vec<String> = m.keys().map(|p| name_of(*p)).filter(|n| !n.is_empty()).collect();
        let named = if named.is_empty() { String::new() } else { format!(" ({})", named.join(", ")) };
        out.push(format!("  shared in the original: {} pairs with ours {}{named}: one slot for locals whose lifetimes do not overlap", at(*q, body_b), ours.join(", ")));
    }
    for (p, m) in to.iter().filter(|(_, m)| m.len() > 1).collect::<std::collections::BTreeMap<_, _>>() {
        let theirs: Vec<String> = m.iter().map(|(q, n)| format!("{} ({n})", at(*q, body_b))).collect();
        out.push(format!("  shared in ours: {} pairs with the original's {}", at(*p, body_a), theirs.join(", ")));
    }
    // the holes: the bytes of the locals (body .. the saves) no slot covers; an array runs to the next slot
    let holes = |sl: &Slots, body: i32, saves: &BTreeSet<i32>| -> Vec<String> {
        // the locals' bytes: body .. the entry, the saved registers' slots left out
        let mut covered: BTreeSet<i32> = saves.iter().flat_map(|&x| x..x + 4).collect();
        let keys: Vec<i32> = sl.keys().copied().filter(|&k| k >= body && k < 0).collect();
        for (n, &k) in keys.iter().enumerate() {
            let s = &sl[&k];
            let end = if s.base { keys.get(n + 1).copied().unwrap_or(0).min(saves.range(k..).next().copied().unwrap_or(0)) } else { k + s.size.max(1) as i32 };
            covered.extend(k..end);
        }
        let mut v = vec![];
        let mut x = body;
        while x < 0 {
            if covered.contains(&x) {
                x += 1;
                continue;
            }
            let s = x;
            while x < 0 && !covered.contains(&x) {
                x += 1;
            }
            v.push(format!("[esp+{:#x}..{:#x})", s - body, x - body));
        }
        v
    };
    let (ha, hb) = (holes(&sa, body_a, &saves_a), holes(&sb, body_b, &saves_b));
    out.push(format!("  holes: ours {}; the original {}", if ha.is_empty() { "none".into() } else { ha.join(" ") },
                     if hb.is_empty() { "none".into() } else { hb.join(" ") }));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const VA: u32 = 0x401000;

    #[test]
    fn the_frame_view_pairs_slots() {
        // ours reads element 0x44 of the array, the original element 0: the load's slot pairs elsewhere
        let (a, b) = (f(0x44, true), f(0, true));
        let v = frame(&a, &b, VA, &lines(&a), &lines(&b), &[(-0x50, "buf".to_string())]);
        let text = v.join("\n");
        assert!(v[0].starts_with("frame: ours 0x60 bytes of locals (0 saved registers), the original 0x60 (0)"), "{text}");
        assert!(text.contains("[esp+0x10]") && text.contains("array") && text.contains(" buf "), "{text}");
        assert!(text.contains("buf+0x44"), "{text}");
        assert!(text.contains("[esp+0x54]") && text.contains("<- moved"), "{text}");
        assert!(text.contains("holes: ours"), "{text}");
    }

    fn lines(code: &[u8]) -> Vec<Line> {
        let fills: std::collections::HashSet<Vec<u8>> = [vec![0xccu8]].into_iter().collect();
        crate::x86::strip_fill(crate::x86::listing(code, VA, None, (0x400000, 0x800000), &fills))
    }

    /// `sub esp, 0x60; lea eax, [esp+0x10]; push eax; call f; add esp, 4; mov eax, [esp+0x10+K]; (mov ecx, [esp+0x10];
    /// mov edx, [esp+0x14];) add esp, 0x60; ret`: an array at entry-0x50 whose address is passed, then element K/4 read
    /// (and elements 0 and 1: the correspondence most accesses agree on).
    fn f(k: u8, anchor: bool) -> Vec<u8> {
        let mut c = vec![0x83, 0xec, 0x60, 0x8d, 0x44, 0x24, 0x10, 0x50, 0xe8, 0xf3, 0xef, 0x0f, 0x00, 0x83, 0xc4, 0x04, 0x8b, 0x44, 0x24, 0x10 + k];
        if anchor {
            c.extend([0x8b, 0x4c, 0x24, 0x10, 0x8b, 0x54, 0x24, 0x14]);
        }
        c.extend([0x83, 0xc4, 0x60, 0xc3]);
        c
    }

    #[test]
    fn depths_follow_pushes_and_frames() {
        let ins = dis::decode(&f(0, false), VA);
        let d = depths(&ins, VA).unwrap();
        // the lea after `sub esp, 0x50`, the call after the push, the load after `add esp, 4`
        assert_eq!((d[&(VA + 3)], d[&(VA + 8)], d[&(VA + 0x10)]), (-0x60, -0x64, -0x60));
    }

    #[test]
    fn another_element_of_the_paired_array_is_listed() {
        let (a, b) = (f(0x44, true), f(0, true));
        let got = check(&a, &b, VA, &lines(&a), &lines(&b));
        assert_eq!(got, [SlotDiff { off: 0x10, ours: (-0x50, 0x44), theirs: (-0x50, 0) }], "{got:?}");
        assert!(got[0].line().starts_with("M.slotmap at +0x10: ours reads the local array at entry-0x50 at offset 0x44"), "{}", got[0].line());
        // the same element: nothing
        assert_eq!(check(&b, &b, VA, &lines(&b), &lines(&b)), []);
        // no element paired at its own offset anywhere: the frames may lay out what follows otherwise; nothing
        let (a, b) = (f(0x44, false), f(0, false));
        assert_eq!(check(&a, &b, VA, &lines(&a), &lines(&b)), []);
    }
}
