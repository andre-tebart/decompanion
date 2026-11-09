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

/// esp relative to the entry (the return address at 0) before each instruction reached from the entry, by address;
/// None when the walk meets two depths at one address or an esp write it does not follow (an ebp frame's
/// `mov esp, ebp`, `and esp`, `leave`).
pub fn depths(ins: &[Ins], va: u32) -> Option<HashMap<u32, i32>> {
    let at: HashMap<u32, usize> = ins.iter().enumerate().map(|(k, i)| (i.addr, k)).collect();
    let mut out: HashMap<u32, i32> = HashMap::new();
    // (address, depth, bytes pushed since the last `add esp`: a stdcall callee pops them)
    let mut todo = vec![(va, 0i32, 0i32)];
    while let Some((mut a, mut d, mut pending)) = todo.pop() {
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
                    pending += 4;
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
                "leave" => return None,
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
                        todo.push((t, d, pending));
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

fn accesses(i: &Ins, depth: i32) -> Vec<Access> {
    i.ops.iter().filter(|o| o.typ == OpType::Mem && o.base == Reg::ESP)
        .map(|o| Access { slot: depth + o.disp as i32, base: i.mn == "lea" || o.index != Reg::None })
        .collect()
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

/// The check over a function: our code and the original's at `va`, and the two listings the alignment reads.
pub fn check(ours: &[u8], theirs: &[u8], va: u32, la: &[Line], lb: &[Line]) -> Vec<SlotDiff> {
    use crate::difflib::{opcodes, Tag};
    let (ia, ib) = (dis::decode(ours, va), dis::decode(theirs, va));
    let (Some(da), Some(db)) = (depths(&ia, va), depths(&ib, va)) else { return vec![] };
    let by = |ins: &[Ins]| -> HashMap<u32, usize> { ins.iter().enumerate().map(|(k, i)| (i.addr, k)).collect() };
    let (ka, kb) = (by(&ia), by(&ib));
    // every array base of each side (the whole function, paired or not)
    let bases_of = |ins: &[Ins], d: &HashMap<u32, i32>| -> BTreeSet<i32> {
        ins.iter().filter_map(|i| d.get(&i.addr).map(|&x| accesses(i, x))).flatten().filter(|a| a.base && a.slot < 0).map(|a| a.slot).collect()
    };
    let (ba, bb) = (bases_of(&ia, &da), bases_of(&ib, &db));
    if ba.is_empty() || bb.is_empty() {
        return vec![];
    }
    // the aligned pairs of stack operands: (our instruction, ours, the original's). The listings are aligned with
    // each stack operand read as its entry-relative slot, so two frames of other sizes (and other push depths)
    // line up where they address the same slot; `[esp + 0x2c]` on both sides is no pair when the frames differ.
    let key = |l: &Line, ins: &[Ins], k: &HashMap<u32, usize>, d: &HashMap<u32, i32>| -> String {
        let acc = k.get(&l.addr).and_then(|&x| d.get(&ins[x].addr).map(|&dx| accesses(&ins[x], dx))).unwrap_or_default();
        match (acc.first(), l.text.find('['), l.text.find(']')) {
            (Some(a), Some(s), Some(e)) if s < e && l.text[s..e].contains("esp") => {
                format!("{}[S{}{}]{}", &l.text[..s], a.slot, if a.base { "+" } else { "" }, &l.text[e + 1..])
            }
            _ => l.text.clone(),
        }
    };
    let ka_keys: Vec<String> = la.iter().map(|l| key(l, &ia, &ka, &da)).collect();
    let kb_keys: Vec<String> = lb.iter().map(|l| key(l, &ib, &kb, &db)).collect();
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
            let (ax, ay) = (accesses(&ia[x], dx), accesses(&ib[y], dy));
            if ax.len() == ay.len() {
                pairs.extend(ax.into_iter().zip(ay).map(|(p, q)| (ia[x].addr, p, q, h)));
            }
        }
    }
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
    let mut out = vec![];
    let mut seen = BTreeSet::new();
    for &(at, sa, sb, oa, ob, h) in &inside {
        let Some(d) = dominant(sa, sb) else { continue };
        if oa != ob && ob - oa != d && (paired.contains(&(sa, sb, ob - d, ob)) || paired.contains(&(sa, sb, oa, oa + d))) && !crossed(h, sa, sb, d)
            && seen.insert(at) {
            out.push(SlotDiff { off: at - va, ours: (sa, oa), theirs: (sb, ob) });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const VA: u32 = 0x401000;

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
