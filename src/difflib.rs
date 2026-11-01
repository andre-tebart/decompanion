//! difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes(), as Python computes it (no junk, no
//! popular elements): the instruction diff's alignment.

use std::collections::HashMap;
use std::hash::Hash;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tag {
    Replace,
    Delete,
    Insert,
    Equal,
}

impl Tag {
}

pub type Opcode = (Tag, usize, usize, usize, usize);

struct Matcher<'a, T> {
    a: &'a [T],
    b: &'a [T],
    b2j: HashMap<&'a T, Vec<usize>>,
}

impl<'a, T: Eq + Hash> Matcher<'a, T> {
    fn find_longest_match(&self, alo: usize, ahi: usize, blo: usize, bhi: usize) -> (usize, usize, usize) {
        let (a, b) = (self.a, self.b);
        let (mut besti, mut bestj, mut bestsize) = (alo, blo, 0usize);
        let mut j2len: HashMap<usize, usize> = HashMap::new();
        for i in alo..ahi {
            let mut newj2len: HashMap<usize, usize> = HashMap::new();
            if let Some(js) = self.b2j.get(&a[i]) {
                for &j in js {
                    if j < blo {
                        continue;
                    }
                    if j >= bhi {
                        break;
                    }
                    let k = if j > 0 { j2len.get(&(j - 1)).copied().unwrap_or(0) } else { 0 } + 1;
                    newj2len.insert(j, k);
                    if k > bestsize {
                        besti = i + 1 - k;
                        bestj = j + 1 - k;
                        bestsize = k;
                    }
                }
            }
            j2len = newj2len;
        }
        // no junk: only the extensions over equal non-junk elements apply
        while besti > alo && bestj > blo && a[besti - 1] == b[bestj - 1] {
            besti -= 1;
            bestj -= 1;
            bestsize += 1;
        }
        while besti + bestsize < ahi && bestj + bestsize < bhi && a[besti + bestsize] == b[bestj + bestsize] {
            bestsize += 1;
        }
        (besti, bestj, bestsize)
    }

    fn matching_blocks(&self) -> Vec<(usize, usize, usize)> {
        let (la, lb) = (self.a.len(), self.b.len());
        let mut queue = vec![(0, la, 0, lb)];
        let mut blocks = vec![];
        while let Some((alo, ahi, blo, bhi)) = queue.pop() {
            let (i, j, k) = self.find_longest_match(alo, ahi, blo, bhi);
            if k > 0 {
                blocks.push((i, j, k));
                if alo < i && blo < j {
                    queue.push((alo, i, blo, j));
                }
                if i + k < ahi && j + k < bhi {
                    queue.push((i + k, ahi, j + k, bhi));
                }
            }
        }
        blocks.sort();
        let (mut i1, mut j1, mut k1) = (0, 0, 0);
        let mut out = vec![];
        for (i2, j2, k2) in blocks {
            if i1 + k1 == i2 && j1 + k1 == j2 {
                k1 += k2;
            } else {
                if k1 > 0 {
                    out.push((i1, j1, k1));
                }
                (i1, j1, k1) = (i2, j2, k2);
            }
        }
        if k1 > 0 {
            out.push((i1, j1, k1));
        }
        out.push((la, lb, 0));
        out
    }
}

/// SequenceMatcher(None, a, b, autojunk=False).get_opcodes().
pub fn opcodes<T: Eq + Hash>(a: &[T], b: &[T]) -> Vec<Opcode> {
    let mut b2j: HashMap<&T, Vec<usize>> = HashMap::new();
    for (i, x) in b.iter().enumerate() {
        b2j.entry(x).or_default().push(i);
    }
    let m = Matcher { a, b, b2j };
    let (mut i, mut j) = (0, 0);
    let mut out = vec![];
    for (ai, bj, size) in m.matching_blocks() {
        let tag = if i < ai && j < bj {
            Some(Tag::Replace)
        } else if i < ai {
            Some(Tag::Delete)
        } else if j < bj {
            Some(Tag::Insert)
        } else {
            None
        };
        if let Some(t) = tag {
            out.push((t, i, ai, j, bj));
        }
        (i, j) = (ai + size, bj + size);
        if size > 0 {
            out.push((Tag::Equal, ai, i, bj, j));
        }
    }
    out
}
