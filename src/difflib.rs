//! The instruction diff's alignment: a shortest edit script (Myers' O((N+M)D) algorithm in linear space, the
//! middle-snake divide and conquer) over the lines, as opcodes in the shape of
//! difflib.SequenceMatcher.get_opcodes().
//!
//! It was SequenceMatcher (Ratcliff/Obershelp: the longest common run first, then both sides of it). On a function
//! that repeats one block (a loop unrolled per column, a chain of near-identical cases) the longest run can pair
//! the k-th copy of ours with another copy of the original's; everything on one side of it is then aligned against
//! the wrong copies or nothing, and a slot-only or one-register difference read as hundreds of `code` lines (a
//! match-base report: one 452-line code hunk of lines equal on both sides, differing=1203 where a plain diff counts
//! 645; another: one register skipped a whole case). The edit script is minimal:
//! every line it leaves unpaired is one no alignment can pair.

use std::collections::HashMap;
use std::hash::Hash;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tag {
    Replace,
    Delete,
    Insert,
    Equal,
}

pub type Opcode = (Tag, usize, usize, usize, usize);

/// The furthest-reaching x of each diagonal k of one direction.
struct V {
    off: isize,
    v: Vec<usize>,
}

impl V {
    fn new(n: usize) -> V {
        V { off: n as isize + 1, v: vec![0; 2 * n + 3] }
    }
    fn get(&self, k: isize) -> usize {
        self.v[(k + self.off) as usize]
    }
    fn set(&mut self, k: isize, x: usize) {
        self.v[(k + self.off) as usize] = x;
    }
}

/// A point (x, y) on a shortest edit script of a[alo..ahi] / b[blo..bhi] that splits it into two halves of about
/// the same cost (both ranges non-empty, no common prefix or suffix).
#[allow(clippy::too_many_arguments)]
fn middle(a: &[u32], b: &[u32], alo: usize, ahi: usize, blo: usize, bhi: usize, vf: &mut V, vb: &mut V) -> (usize, usize) {
    let (n, m) = (ahi - alo, bhi - blo);
    let delta = n as isize - m as isize;
    let odd = delta & 1 != 0;
    let dmax = (n + m).div_ceil(2) as isize;
    vf.set(1, 0);
    vb.set(1, 0);
    for d in 0..=dmax {
        // forward: the furthest x on each diagonal k = x - y after d edits from (0, 0)
        let mut k = -d;
        while k <= d {
            let mut x = if k == -d || (k != d && vf.get(k - 1) < vf.get(k + 1)) { vf.get(k + 1) } else { vf.get(k - 1) + 1 };
            let mut y = (x as isize - k) as usize;
            let (x0, y0) = (x, y);
            while x < n && y < m && a[alo + x] == b[blo + y] {
                x += 1;
                y += 1;
            }
            vf.set(k, x);
            if odd && (k - delta).abs() < d && x + vb.get(delta - k) >= n {
                return (alo + x0, blo + y0);
            }
            k += 2;
        }
        // backward: the furthest x on each diagonal k from (n, m), counted from the end
        let mut k = -d;
        while k <= d {
            let mut x = if k == -d || (k != d && vb.get(k - 1) < vb.get(k + 1)) { vb.get(k + 1) } else { vb.get(k - 1) + 1 };
            let mut y = (x as isize - k) as usize;
            while x < n && y < m && a[ahi - 1 - x] == b[bhi - 1 - y] {
                x += 1;
                y += 1;
            }
            vb.set(k, x);
            if !odd && (k - delta).abs() <= d && x + vf.get(delta - k) >= n {
                return (ahi - x, bhi - y);
            }
            k += 2;
        }
    }
    unreachable!("a shortest edit script has at most n + m edits")
}

/// The pairs of equal lines of a shortest edit script of a[alo..ahi] / b[blo..bhi], in order.
#[allow(clippy::too_many_arguments)]
fn conquer(a: &[u32], b: &[u32], mut alo: usize, mut ahi: usize, mut blo: usize, mut bhi: usize, vf: &mut V, vb: &mut V,
           out: &mut Vec<(usize, usize)>) {
    while alo < ahi && blo < bhi && a[alo] == b[blo] {
        out.push((alo, blo));
        alo += 1;
        blo += 1;
    }
    let mut tail = 0;
    while alo < ahi && blo < bhi && a[ahi - 1] == b[bhi - 1] {
        ahi -= 1;
        bhi -= 1;
        tail += 1;
    }
    if alo < ahi && blo < bhi {
        let (x, y) = middle(a, b, alo, ahi, blo, bhi, vf, vb);
        conquer(a, b, alo, x, blo, y, vf, vb, out);
        conquer(a, b, x, ahi, y, bhi, vf, vb, out);
    }
    out.extend((0..tail).map(|t| (ahi + t, bhi + t)));
}

/// The opcodes of a shortest edit script of a against b (SequenceMatcher.get_opcodes()'s shape: Equal runs, and
/// between two of them one Replace, Delete or Insert).
pub fn opcodes<T: Eq + Hash>(a: &[T], b: &[T]) -> Vec<Opcode> {
    // the lines as numbers: equal lines, equal numbers
    let mut ids: HashMap<&T, u32> = HashMap::new();
    let mut num = |x| {
        let n = ids.len() as u32;
        *ids.entry(x).or_insert(n)
    };
    let ia: Vec<u32> = a.iter().map(&mut num).collect();
    let ib: Vec<u32> = b.iter().map(&mut num).collect();
    let (la, lb) = (a.len(), b.len());
    let (mut vf, mut vb) = (V::new(la + lb), V::new(la + lb));
    let mut pairs = Vec::with_capacity(la.min(lb) + 1);
    conquer(&ia, &ib, 0, la, 0, lb, &mut vf, &mut vb, &mut pairs);
    let (mut i, mut j) = (0, 0);
    let mut out: Vec<Opcode> = vec![];
    let mut k = 0;
    loop {
        let (pi, pj) = pairs.get(k).copied().unwrap_or((la, lb));
        let tag = match (i < pi, j < pj) {
            (true, true) => Some(Tag::Replace),
            (true, false) => Some(Tag::Delete),
            (false, true) => Some(Tag::Insert),
            _ => None,
        };
        if let Some(t) = tag {
            out.push((t, i, pi, j, pj));
        }
        if k == pairs.len() {
            break;
        }
        let mut e = k + 1;
        while e < pairs.len() && pairs[e] == (pi + e - k, pj + e - k) {
            e += 1;
        }
        out.push((Tag::Equal, pi, pi + e - k, pj, pj + e - k));
        (i, j) = (pi + e - k, pj + e - k);
        k = e;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The longest common subsequence's length by the quadratic table.
    fn lcs(a: &[u8], b: &[u8]) -> usize {
        let mut t = vec![vec![0usize; b.len() + 1]; a.len() + 1];
        for i in (0..a.len()).rev() {
            for j in (0..b.len()).rev() {
                t[i][j] = if a[i] == b[j] { t[i + 1][j + 1] + 1 } else { t[i + 1][j].max(t[i][j + 1]) };
            }
        }
        t[0][0]
    }

    fn check(a: &[u8], b: &[u8]) {
        let ops = opcodes(a, b);
        let (mut i, mut j, mut eq) = (0, 0, 0);
        for (k, &(t, i1, i2, j1, j2)) in ops.iter().enumerate() {
            assert!(i1 == i && j1 == j, "{a:?} {b:?} {ops:?}");
            match t {
                Tag::Equal => {
                    assert!(i2 - i1 == j2 - j1 && i2 > i1 && a[i1..i2] == b[j1..j2]);
                    eq += i2 - i1;
                }
                Tag::Replace => assert!(i2 > i1 && j2 > j1),
                Tag::Delete => assert!(i2 > i1 && j2 == j1),
                Tag::Insert => assert!(i2 == i1 && j2 > j1),
            }
            if k > 0 {
                assert!((t == Tag::Equal) != (ops[k - 1].0 == Tag::Equal), "two equal or two differing opcodes in a row: {ops:?}");
            }
            (i, j) = (i2, j2);
        }
        assert_eq!((i, j), (a.len(), b.len()));
        assert_eq!(eq, lcs(a, b), "{a:?} {b:?} {ops:?}");
    }

    #[test]
    fn minimal_edit_script() {
        assert!(opcodes::<u8>(&[], &[]).is_empty());
        assert_eq!(opcodes(b"abc", b"abc"), [(Tag::Equal, 0, 3, 0, 3)]);
        assert_eq!(opcodes(b"abc", b""), [(Tag::Delete, 0, 3, 0, 0)]);
        assert_eq!(opcodes(b"", b"ab"), [(Tag::Insert, 0, 0, 0, 2)]);
        assert_eq!(opcodes(b"axc", b"ayc"), [(Tag::Equal, 0, 1, 0, 1), (Tag::Replace, 1, 2, 1, 2), (Tag::Equal, 2, 3, 2, 3)]);
        // a xorshift's random pairs over small alphabets, against the quadratic LCS
        let mut s: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut r = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..3000 {
            let (na, nb, k) = ((r() % 24) as usize, (r() % 24) as usize, 1 + r() % 4);
            let a: Vec<u8> = (0..na).map(|_| (r() % k) as u8).collect();
            let b: Vec<u8> = (0..nb).map(|_| (r() % k) as u8).collect();
            check(&a, &b);
        }
    }

    #[test]
    fn repeated_blocks_align_copy_by_copy() {
        // eleven copies of one loop body, ours differing in one slot per copy: each copy pairs with its own, every
        // difference one line against one
        let body = |k: usize, slot: &str| -> Vec<String> {
            vec![format!("mov edx, dword ptr [ecx + {k}]"), "push edx".into(), "call X".into(), "mov esi, eax".into(), "add esp, 4".into(),
                 "test esi, esi".into(), "je X".into(), format!("mov eax, dword ptr [esp + {slot}]"), "fstp dword ptr [edi]".into(),
                 "inc ebp".into(), "add edi, 0xc".into()]
        };
        // the original's sixth copy reads ours' slot: its longest common run (the sixth copy and its neighbours'
        // ends) is ours' third copy too, and Ratcliff/Obershelp paired those, three whole copies unpaired each side
        let a: Vec<String> = (0..11).flat_map(|k| body(k % 3, "0x10")).collect();
        let b: Vec<String> = (0..11).flat_map(|k| body(k % 3, if k == 5 { "0x10" } else { "0x18" })).collect();
        let ops = opcodes(&a, &b);
        let diff: Vec<_> = ops.iter().filter(|o| o.0 != Tag::Equal).collect();
        assert_eq!(diff.len(), 10, "{ops:?}");
        assert!(diff.iter().all(|o| o.0 == Tag::Replace && o.2 - o.1 == 1 && o.4 - o.3 == 1 && o.1 == o.3), "{ops:?}");
    }
}
