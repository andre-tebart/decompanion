//! match/diffclass.py: the instruction diff of one function and the classification of its hunks (its module
//! docstring is the criterion), with the walk of the original's slot that finds its switch tables (rules/walk.py's
//! Walker for one root, no stops, no relocation sites).

use crate::difflib::{opcodes, Tag};
use crate::shape::{self, Shape};
use crate::x86::{self, py_hex, Line};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};

pub type Hunk = (usize, usize, usize, usize, String, String);

fn texts(l: &[Line]) -> Vec<String> {
    l.iter().map(|x| x.text.clone()).collect()
}

fn shapes(l: &[Line]) -> Vec<Shape> {
    l.iter().map(|x| x.shape.clone()).collect()
}

/// The instructions of a hunk that move the stack (pushes and pops but a callee-saved register's save or restore,
/// calls, `add` / `sub esp`), in order, their registers masked: their order decides what each call gets.
fn stack_ops(s: &[Shape]) -> Vec<Shape> {
    s.iter().filter(|x| is_stack_op(x)).map(|x| shape::mask_slots(&shape::mask_regs(x))).collect()
}

/// What the stack does around the calls of a listing, the lines of `skip` (a shared tail's hunk) left out: each
/// call with the cleanup right after it (`add esp, K`, a pop, or none: a cleanup merged into a later one), as a
/// multiset; and each basic block's pushes in order (cut before a branch target and after a jump, a branch or a
/// return). A moved block, a block split by another layout, a push moved across a call (an FPU-argument call takes
/// nothing from the stack) and another frame size keep both; a cleanup moved across a call (a nested call's partial
/// pop) or two pushes swapped (a call's two arguments in another order) change them.
fn stack_profile(l: &[Line], skip: &HashSet<usize>) -> (Vec<Option<Shape>>, Vec<Vec<Shape>>) {
    let m = |x: &Shape| shape::mask_slots(&shape::mask_regs(x));
    let targets: HashSet<i64> = l.iter().filter_map(|x| x.target).collect();
    // each call with its cleanup: the next instruction of the stack after it in its block (other instructions
    // skipped: VC6 schedules `and eax, 0xffff` between a call and its `add esp`), when that is an `add esp` or a pop
    let mut calls = vec![];
    for (k, x) in l.iter().enumerate() {
        if skip.contains(&k) || x.shape.mn != "call" {
            continue;
        }
        let mut cleanup = None;
        for (j, n) in l.iter().enumerate().skip(k + 1) {
            if targets.contains(&(n.addr as i64)) || n.shape.mn == "ret" || n.shape.mn.starts_with('j') {
                break;
            }
            if !skip.contains(&j) && is_stack_op(&n.shape) {
                if n.shape.mn != "push" && n.shape.mn != "call" {
                    cleanup = Some(m(&n.shape));
                }
                break;
            }
        }
        calls.push(cleanup);
    }
    let mut blocks: Vec<Vec<Shape>> = vec![];
    let mut cur: Vec<Shape> = vec![];
    for (k, x) in l.iter().enumerate() {
        if targets.contains(&(x.addr as i64)) && !cur.is_empty() {
            blocks.push(std::mem::take(&mut cur));
        }
        if !skip.contains(&k) && x.shape.mn == "push" && is_stack_op(&x.shape) {
            cur.push(m(&x.shape));
        }
        if (x.target.is_some() && x.shape.mn != "call" || x.shape.mn == "ret" || x.shape.mn.starts_with('j')) && !cur.is_empty() {
            blocks.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        blocks.push(cur);
    }
    (calls, blocks)
}

fn is_stack_op(x: &Shape) -> bool {
    let esp0 = matches!(x.ops.first(), Some(shape::Opnd::Reg(r)) if *r == crate::dis::Reg::ESP);
    match x.mn {
        "push" => !x.save,
        // a pop into a callee-saved register restores it (VC6 cleans arguments up with `pop ecx` or `add esp`),
        // whether or not the epilogue's run of pops marks it
        "pop" => !x.save && !matches!(x.ops.first(), Some(shape::Opnd::Reg(r)) if crate::dis::gpr(*r).is_some_and(|g| matches!(g, 3 | 5 | 6 | 7))),
        "call" => true,
        "add" | "sub" => esp0,
        _ => false,
    }
}

fn multiset_eq<T: Ord + Clone>(a: &[T], b: &[T]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let (mut x, mut y) = (a.to_vec(), b.to_vec());
    x.sort();
    y.sort();
    x == y
}

/// diffclass.distance: differing instructions on both sides.
pub fn distance(a: &[String], b: &[String]) -> usize {
    opcodes(a, b).iter().filter(|o| o.0 != Tag::Equal).map(|o| o.2 - o.1 + o.4 - o.3).sum()
}

/// The differing instructions of two listings whose frames differ in size (`frame`: ours, the original's), as
/// `dcp asmdiff` counts them: aligned with the stack offsets masked, a pair that differs only by the frame's shift
/// equal. A match-base report: `dcp grade`'s dist counted every line the shift touched, and went up on an edit that
/// took asmdiff's count down.
pub fn frame_distance(a: &[Shape], b: &[Shape], frame: (i64, i64)) -> usize {
    opcodes(&shape::stack_mask(a, frame), &shape::stack_mask(b, frame)).iter().map(|o| {
        if o.0 != Tag::Equal {
            o.2 - o.1 + o.4 - o.3
        } else {
            (o.1..o.2).filter(|&i| {
                let j = o.3 + i - o.1;
                a[i] != b[j] && shape::frame_explain(&a[i..=i], &b[j..=j], frame).is_none()
            }).count() * 2
        }
    }).sum()
}

/// diffclass.join: differing opcodes joined into hunks when within 4 equal instructions of each other, each hunk
/// with its opcodes.
fn join_parts(raw: impl IntoIterator<Item = (usize, usize, usize, usize)>) -> Vec<Vec<(usize, usize, usize, usize)>> {
    let mut hs: Vec<Vec<(usize, usize, usize, usize)>> = vec![];
    for (i1, i2, j1, j2) in raw {
        if let Some(h) = hs.last_mut() {
            let l = h[h.len() - 1];
            if i1 as i64 - l.1 as i64 <= 4 && j1 as i64 - l.3 as i64 <= 4 {
                h.push((i1, i2, j1, j2));
                continue;
            }
        }
        hs.push(vec![(i1, i2, j1, j2)]);
    }
    hs
}

fn span(ps: &[(usize, usize, usize, usize)]) -> (usize, usize, usize, usize) {
    (ps[0].0, ps[ps.len() - 1].1, ps[0].2, ps[ps.len() - 1].3)
}

fn join(raw: impl IntoIterator<Item = (usize, usize, usize, usize)>) -> Vec<(usize, usize, usize, usize)> {
    join_parts(raw).iter().map(|h| span(h)).collect()
}

fn hunks(a: &[String], b: &[String]) -> Vec<(usize, usize, usize, usize)> {
    join(opcodes(a, b).into_iter().filter(|o| o.0 != Tag::Equal).map(|o| (o.1, o.2, o.3, o.4)))
}

/// The lines of both sides hashed after shape::shape_keys: a quick test of whether a class can explain a piece.
/// Computed on the first code hunk to split.
struct Keys<'a> {
    text: (&'a [Shape], &'a [Shape]),
    keys: std::cell::OnceCell<(Vec<u64>, Vec<u64>)>,
}

impl Keys<'_> {
    fn new<'a>(a: &'a [Shape], b: &'a [Shape]) -> Keys<'a> {
        Keys { text: (a, b), keys: Default::default() }
    }

    /// Whether any class but code can explain the lines a[i1..i2] / b[j1..j2]: their masked lines the same
    /// multiset, or every line that differs an FPU one, or all fill (classify's and shape::explain's preconditions).
    fn may_explain(&self, la: &[Line], lb: &[Line], i1: usize, i2: usize, j1: usize, j2: usize) -> bool {
        if i2 - i1 == j2 - j1 {
            let (ka, kb) = self.keys.get_or_init(|| {
                let h = |t: &Shape| {
                    use std::hash::{Hash, Hasher};
                    let mut s = std::collections::hash_map::DefaultHasher::new();
                    t.hash(&mut s);
                    s.finish()
                };
                (shape::shape_keys(self.text.0).iter().map(h).collect(), shape::shape_keys(self.text.1).iter().map(h).collect())
            });
            let (mut x, mut y) = (ka[i1..i2].to_vec(), kb[j1..j2].to_vec());
            x.sort_unstable();
            y.sort_unstable();
            if x == y {
                return true;
            }
        }
        let (sa, sb): (HashSet<&Shape>, HashSet<&Shape>) = (la[i1..i2].iter().map(|l| &l.shape).collect(), lb[j1..j2].iter().map(|l| &l.shape).collect());
        sa.symmetric_difference(&sb).all(|t| t.fpu()) || la[i1..i2].iter().chain(&lb[j1..j2]).all(|l| l.fill)
            // a jump may go to a block the other side has inline (tail)
            || la[i1..i2].iter().chain(&lb[j1..j2]).any(|l| l.shape.mn == "jmp")
    }
}

/// The classified hunks of one joined hunk: the whole when a class explains it, else its pieces. A joined hunk can
/// span several places that differ each in its own way (two copies of a loop, each with its own register
/// allocation, the equal lines between them fewer than 5): no one renaming explains the whole, one explains each
/// copy. A code hunk of several opcodes is cut at its widest run of equal lines and each half classified the same
/// way; the code pieces in a row are one code hunk again.
fn classify_joined(la: &[Line], lb: &[Line], at: &[Shape], keys: &Keys, parts: &[(usize, usize, usize, usize)]) -> Vec<Hunk> {
    let (i1, i2, j1, j2) = span(parts);
    let (c, n) = classify(la, lb, at, i1, i2, j1, j2);
    if c != "code" || parts.len() == 1 {
        return vec![(i1, i2, j1, j2, c, n)];
    }
    let mut pieces: Vec<Hunk> = vec![];
    let cut = |ps: &[(usize, usize, usize, usize)]| (1..ps.len()).max_by_key(|&k| (ps[k].0 - ps[k - 1].1).max(ps[k].2 - ps[k - 1].3)).unwrap();
    let k = cut(parts);
    let mut todo = vec![&parts[k..], &parts[..k]];
    while let Some(ps) = todo.pop() {
        let (x1, x2, y1, y2) = span(ps);
        if keys.may_explain(la, lb, x1, x2, y1, y2) {
            let (c, n) = classify(la, lb, at, x1, x2, y1, y2);
            if c != "code" {
                pieces.push((x1, x2, y1, y2, c, n));
                continue;
            }
        }
        if ps.len() == 1 {
            pieces.push((x1, x2, y1, y2, "code".into(), String::new()));
            continue;
        }
        let k = cut(ps);
        todo.push(&ps[k..]);
        todo.push(&ps[..k]);
    }
    let mut out: Vec<Hunk> = vec![];
    for h in pieces {
        match out.last_mut() {
            Some(l) if l.4 == "code" && h.4 == "code" => (l.1, l.3) = (h.1, h.3),
            _ => out.push(h),
        }
    }
    out
}

fn classify(la: &[Line], lb: &[Line], at: &[Shape], i1: usize, i2: usize, j1: usize, j2: usize) -> (String, String) {
    let a = shapes(&la[i1..i2]);
    let b = shapes(&lb[j1..j2]);
    if la[i1..i2].iter().chain(&lb[j1..j2]).all(|x| x.fill) {
        return ("fill".into(), "alignment fill".into());
    }
    if multiset_eq(&a, &b) {
        // the stack's instructions in another order (pushes swapped, a push moved across a call or a cleanup): another
        // call's arguments, not scheduling (a call's two arguments swapped was classed order)
        if stack_ops(&a) != stack_ops(&b) {
            return ("code".into(), "the stack's pushes, pops and calls in another order: a call's arguments differ".into());
        }
        return ("order".into(), "same instructions, other order".into());
    }
    shape::explain(&a, &b, at).or_else(|| tail(la, lb, at, i1, i2, j1, j2))
        .or_else(|| shape::dataflow(&shapes(&la[i1.saturating_sub(16)..i1]), &a, &shapes(&lb[j1.saturating_sub(16)..j1]), &b, at))
        .unwrap_or(("code".into(), String::new()))
}

/// The block a jump goes to: from line t to its first ret or jmp (at most 16 lines), None when it runs on.
fn jump_block(l: &[Line], t: usize) -> Option<std::ops::Range<usize>> {
    let end = (t..l.len().min(t + 16)).find(|&k| matches!(l[k].shape.mn, "ret" | "jmp"))?;
    Some(t..end + 1)
}

/// The conditional jump on the opposite condition.
fn inverted(mn: &str) -> Option<&'static str> {
    const PAIRS: [(&str, &str); 8] = [("je", "jne"), ("jl", "jge"), ("jle", "jg"), ("jb", "jae"), ("jbe", "ja"), ("js", "jns"), ("jo", "jno"), ("jp", "jnp")];
    PAIRS.iter().find_map(|&(a, b)| if mn == a { Some(b) } else if mn == b { Some(a) } else { None })
}

/// The tail class: the hunk differs by blocks one side reaches by a jump and the other has inline (VC6 merges
/// identical return tails and call sequences into one and jumps to it, or keeps a copy per path: the same code
/// either way). Each `jmp` of one side's lines whose target block (jump_block) is a run of the other side's lines, the
/// same but for a renaming, is taken out with that run; the hunk is a tail when something was taken out and
/// what is left is the same on both sides (in another order or under a renaming: explain).
#[allow(clippy::too_many_arguments)]
fn tail(la: &[Line], lb: &[Line], at: &[Shape], i1: usize, i2: usize, j1: usize, j2: usize) -> Option<(String, String)> {
    let base = la.first()?.addr as i64;
    let (mut ra, mut rb): (Vec<usize>, Vec<usize>) = ((i1..i2).collect(), (j1..j2).collect());
    let mut notes = vec![];
    // side 0: ours jumps, the original has the block inline; side 1 the other way round
    for side in 0..2 {
        let (jl, il) = if side == 0 { (la, lb) } else { (lb, la) };
        let mut k = 0;
        while k < if side == 0 { ra.len() } else { rb.len() } {
            let x = if side == 0 { ra[k] } else { rb[k] };
            // a jmp to the block, or a conditional jump to it where the other side branches round its copy on the
            // inverted condition (`je X` against `jne Y; <the block>; Y:`)
            let mn = jl[x].shape.mn;
            let skip = inverted(mn);
            let jumps_to = (mn == "jmp" || skip.is_some()).then_some(jl[x].target).flatten();
            let found = jumps_to.and_then(|t| jl.iter().position(|l| l.addr as i64 == t)).and_then(|t| jump_block(jl, t)).and_then(|blk| {
                let want = shapes(&jl[blk.clone()]);
                let inline = if side == 0 { &rb } else { &ra };
                // a run of consecutive lines of the other side's hunk that is the block (behind the inverted jump)
                let pre = skip.is_some() as usize;
                (pre..inline.len()).find(|&q| {
                    let n = want.len();
                    q + n <= inline.len() && (q - pre..q + n).all(|d| inline[d] == inline[q - pre] + d - (q - pre))
                        && shape::same_code(&want, &shapes(&il[inline[q]..inline[q] + n]), at)
                        && skip.is_none_or(|s| {
                            let g = &il[inline[q - 1]];
                            g.shape.mn == s && il.get(inline[q] + n).is_some_and(|after| g.target == Some(after.addr as i64))
                        })
                }).map(|q| (q - pre, want.len() + pre, jl[blk.start].addr))
            });
            match found {
                Some((q, n, at_addr)) => {
                    let inline = if side == 0 { &mut rb } else { &mut ra };
                    let from = il[inline[q]].addr;
                    inline.drain(q..q + n);
                    if side == 0 { ra.remove(k) } else { rb.remove(k) };
                    let (who, other) = if side == 0 { ("ours", "the original") } else { ("the original", "ours") };
                    let how = if mn == "jmp" { "jumps" } else { "branches" };
                    notes.push(format!("{who} {how} to a shared block at +{} ({} instructions) {other} has inline at +{}",
                                       py_hex(at_addr as i64 - base), n - skip.is_some() as usize, py_hex(from as i64 - base)));
                }
                None => k += 1,
            }
        }
    }
    if notes.is_empty() {
        return None;
    }
    let (a, b): (Vec<Shape>, Vec<Shape>) = (ra.iter().map(|&k| la[k].shape.clone()).collect(), rb.iter().map(|&k| lb[k].shape.clone()).collect());
    let rest_same = multiset_eq(&a, &b) || shape::explain(&a, &b, at).is_some();
    rest_same.then(|| ("tail".to_string(), notes.join("; ")))
}

fn classify_hunks(la: &[Line], lb: &[Line]) -> Vec<Hunk> {
    let (a, b) = (shapes(la), shapes(lb));
    let keys = Keys::new(&a, &b);
    join_parts(opcodes(&texts(la), &texts(lb)).into_iter().filter(|o| o.0 != Tag::Equal).map(|o| (o.1, o.2, o.3, o.4)))
        .iter().flat_map(|ps| classify_joined(la, lb, &a, &keys, ps)).collect()
}

fn frame_hunks(la: &[Line], lb: &[Line], frame: (i64, i64)) -> Vec<Hunk> {
    let (a, b) = (shapes(la), shapes(lb));
    let (ma, mb) = (shape::stack_mask(&a, frame), shape::stack_mask(&b, frame));
    let (mut other, mut shifted) = (vec![], vec![]);
    for (tag, i1, i2, j1, j2) in opcodes(&ma, &mb) {
        if tag != Tag::Equal {
            other.push((i1, i2, j1, j2));
            continue;
        }
        let mut k = 0;
        while k < i2 - i1 {
            if a[i1 + k] == b[j1 + k] {
                k += 1;
                continue;
            }
            let mut e = k;
            while e < i2 - i1 && a[i1 + e] != b[j1 + e] {
                e += 1;
            }
            shifted.push((i1 + k, i1 + e, j1 + k, j1 + e));
            k = e;
        }
    }
    let mut out: Vec<Hunk> = vec![];
    for (i1, i2, j1, j2) in shifted {
        match shape::frame_explain(&a[i1..i2], &b[j1..j2], frame) {
            Some(note) => out.push((i1, i2, j1, j2, "frame".into(), note)),
            None => {
                let (c, n) = classify(la, lb, &a, i1, i2, j1, j2);
                out.push((i1, i2, j1, j2, c, n));
            }
        }
    }
    let keys = Keys::new(&a, &b);
    for ps in join_parts(other) {
        out.extend(classify_joined(la, lb, &a, &keys, &ps));
    }
    out.sort();
    out
}

// ------------------------------------------------------------------------------------------------ the verdict

#[derive(Clone, Debug)]
pub struct Tables {
    pub entries: i64,
    pub bytes: i64,
    pub diffs: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Verdict {
    pub shape: bool,
    pub hunks: Vec<(String, i64)>, // class -> instructions, in first-seen order
    pub moved: bool,
    pub renamed: bool,
    pub code: Vec<(usize, Vec<String>, Vec<String>)>,
    pub distance: usize,
    pub tables: Option<Tables>,
    pub frame: Option<(i64, i64)>,
    pub branches: Vec<String>,
    /// The jumps whose targets do not correspond for a code hunk's sake: one line per hunk, the hunk's difference.
    pub into_code: Vec<String>,
}

impl Verdict {
    /// Verdict.summary (the classes by weight, ties by name).
    pub fn summary(&self) -> String {
        self.summary_with(true)
    }

    /// The summary without the branch lines, for a reader that prints them on their own (`dcp diffclass`: one
    /// difference is reported once).
    pub fn summary_without_branches(&self) -> String {
        self.summary_with(false)
    }

    fn summary_with(&self, branches: bool) -> String {
        let mut hs = self.hunks.clone();
        hs.sort_by(|x, y| (-x.1, &x.0).cmp(&(-y.1, &y.0)));
        let mut s = hs.iter().map(|(k, v)| format!("{k} {v}")).collect::<Vec<_>>().join(", ");
        if s.is_empty() {
            s = "identical instructions".into();
        }
        if self.moved {
            s += "; the code hunks are moved instructions";
        } else if self.renamed {
            s += "; equal under one function-wide renaming";
        }
        if let Some((a, b)) = self.frame {
            s += &format!("; frame {} vs {} (stack offsets aligned)", py_hex(a), py_hex(b));
        }
        if branches && !self.into_code.is_empty() {
            s += &format!("; {}", self.into_code[..self.into_code.len().min(3)].join("; "));
        }
        if branches && !self.branches.is_empty() {
            s += &format!("; branch targets differ ({}): {}", self.branches.len(), self.branches[..self.branches.len().min(3)].join("; "));
        }
        if let Some(t) = &self.tables {
            if !t.diffs.is_empty() {
                s += &format!("; switch tables differ ({}): {}", t.diffs.len(), t.diffs[..t.diffs.len().min(3)].join("; "));
            } else {
                s += &format!("; switch tables equal ({} entries, {} index bytes)", t.entries, t.bytes);
            }
        }
        s
    }

    pub fn hunks_json(&self) -> Value {
        let mut m = serde_json::Map::new();
        for (k, v) in &self.hunks {
            m.insert(k.clone(), json!(v));
        }
        Value::Object(m)
    }
}

fn mnemonic(t: &str) -> &str {
    t.split(' ').next().unwrap_or("")
}

/// The shapes an order hunk's lines pair by (ours, the original's): the renaming its note names ("after ecx->edx
/// edx->ecx") applied to ours, the esp offsets normalised on both sides when the note says across a push / pop.
fn order_keys(la: &[Line], lb: &[Line], note: &str) -> (Vec<Shape>, Vec<Shape>) {
    let (mut a, mut b) = (shapes(la), shapes(lb));
    if note.contains("across a push / pop") {
        (a, b) = (shape::esp_normalised(&a), shape::esp_normalised(&b));
    }
    if let Some((_, m)) = note.rsplit_once(", after ") {
        // the registers renamed (the note's stack offsets, `[ + 0x10]->[ + 0x14]`, are no registers)
        let pairs: Vec<(String, String)> = m.split(' ').filter_map(|p| p.split_once("->")).filter(|(k, v)| !(k.contains(']') || v.contains('[')))
            .map(|(k, v)| (k.to_string(), v.to_string())).collect();
        if let Some(map) = shape::reg_map(&pairs).filter(|_| !pairs.is_empty()) {
            a = a.iter().map(|s| shape::rename(s, &map)).collect();
        }
    }
    (a, b)
}

/// How the inside of one aligned piece corresponds between the sides: line k of ours with line k of the original's
/// (an equal run, a renaming), or not at all (code, fill, tail), or in another order: the lines pair by the keys the
/// class compared (`pair`: order_keys), the cut after k lines of ours with the one after k lines of the original's
/// when both prefixes are the same multiset of masked lines (`prefix`: shape_keys, registers and offsets masked, as
/// the hunk's renaming of registers and stack slots leaves them).
enum Inside {
    None,
    ByIndex,
    Reordered { pair: (Vec<Shape>, Vec<Shape>), prefix: (Vec<Shape>, Vec<Shape>) },
}

struct Piece {
    i1: usize,
    i2: usize,
    j1: usize,
    j2: usize,
    cls: String, // "" for an equal run
    inside: Inside,
}

/// The cut correspondence of one function's two listings (§4: the alignment, one per function). A cut is a
/// place between instructions, cut k before line k (k = len: the end); a jump target is a cut. The equal runs and
/// the hunks of the alignment are pieces in a row on both sides; a cut corresponds:
/// - at a piece's boundary, always (an empty side's one cut with both of the other side's);
/// - in an equal run, and in a regs, sib, frame or slots hunk of equal length, by position;
/// - in an order or fpu hunk, where the prefixes before the cuts are the same multiset under the hunk's keys
///   (order_keys: the text the class compared);
/// - in a code, fill or tail hunk, not inside.
///
/// The lines the alignment pairs (`pairs`) are those of the by-position pieces and, in an order or fpu hunk, the
/// lines of equal keys in turn: never two lines of a hunk by their raw text.
pub struct Cuts {
    pieces: Vec<Piece>,
    pub pairs: Vec<(usize, usize)>,
}

fn multiset_prefix_eq(a: &[Shape], b: &[Shape], k: usize) -> bool {
    k <= a.len() && k <= b.len() && multiset_eq(&a[..k], &b[..k])
}

impl Cuts {
    /// `renamed`: the whole function equal under one renaming, so a code hunk of equal length pairs by position.
    pub fn new(la: &[Line], lb: &[Line], hs: &[Hunk], renamed: bool) -> Cuts {
        let mut all: Vec<&Hunk> = hs.iter().collect();
        all.sort();
        let mut pieces = vec![];
        let (mut i, mut j) = (0usize, 0usize);
        for (i1, i2, j1, j2, cls, note) in all {
            let (i1, i2, j1, j2) = (*i1, *i2, *j1, *j2);
            if i1 < i || j1 < j {
                continue; // overlaps the piece before (none should)
            }
            if i1 - i == j1 - j && i1 > i {
                pieces.push(Piece { i1: i, i2: i1, j1: j, j2: j1, cls: String::new(), inside: Inside::ByIndex });
            }
            let same_len = i2 - i1 == j2 - j1;
            let inside = match cls.as_str() {
                "regs" | "sib" | "frame" if same_len => Inside::ByIndex,
                "slots" if same_len && !note.contains("other order") => Inside::ByIndex,
                "code" if same_len && renamed => Inside::ByIndex,
                "order" | "slots" => {
                    let masked = |l: &[Line]| shape::shape_keys(&shapes(l));
                    Inside::Reordered { pair: order_keys(&la[i1..i2], &lb[j1..j2], note), prefix: (masked(&la[i1..i2]), masked(&lb[j1..j2])) }
                }
                "fpu" => {
                    let st = |l: &[Line]| -> Vec<Shape> { l.iter().map(|x| shape::st_masked(&x.shape)).collect() };
                    let (a, b) = (st(&la[i1..i2]), st(&lb[j1..j2]));
                    Inside::Reordered { prefix: (shape::shape_keys(&a), shape::shape_keys(&b)), pair: (a, b) }
                }
                _ => Inside::None,
            };
            pieces.push(Piece { i1, i2, j1, j2, cls: cls.clone(), inside });
            i = i2;
            j = j2;
        }
        if la.len() - i == lb.len() - j && la.len() > i {
            pieces.push(Piece { i1: i, i2: la.len(), j1: j, j2: lb.len(), cls: String::new(), inside: Inside::ByIndex });
        }
        let mut pairs = vec![];
        for p in &pieces {
            match &p.inside {
                Inside::ByIndex => pairs.extend((0..p.i2 - p.i1).map(|k| (p.i1 + k, p.j1 + k))),
                Inside::Reordered { pair: (ka, kb), .. } => {
                    let mut same: HashMap<&Shape, VecDeque<usize>> = HashMap::new();
                    for (k, s) in kb.iter().enumerate() {
                        same.entry(s).or_default().push_back(p.j1 + k);
                    }
                    pairs.extend(ka.iter().enumerate().filter_map(|(k, s)| Some((p.i1 + k, same.get_mut(s)?.pop_front()?))));
                }
                Inside::None => {}
            }
        }
        Cuts { pieces, pairs }
    }

    fn at(&self, ca: usize) -> impl Iterator<Item = &Piece> {
        let from = self.pieces.partition_point(|p| p.i2 < ca);
        self.pieces[from..].iter().take_while(move |p| p.i1 <= ca)
    }

    /// The original's cuts that correspond to our cut `ca`.
    pub fn images(&self, ca: usize) -> Vec<usize> {
        let mut out = vec![];
        for p in self.at(ca) {
            if ca == p.i1 {
                out.push(p.j1);
            }
            if ca == p.i2 {
                out.push(p.j2);
            }
            if p.i1 < ca && ca < p.i2 {
                let k = ca - p.i1;
                match &p.inside {
                    Inside::ByIndex => out.push(p.j1 + k),
                    Inside::Reordered { prefix: (ka, kb), .. } if multiset_prefix_eq(ka, kb, k) => out.push(p.j1 + k),
                    _ => {}
                }
            }
        }
        out
    }

    /// The hunk of class `cls` our cut `ca` or the original's cut `cb` lies in or on (both, when one hunk has
    /// both), as (ours' first line, the original's first line).
    fn hunk_of(&self, cls: &str, ca: Option<usize>, cb: Option<usize>) -> Option<(usize, usize)> {
        let on_a = |p: &Piece| ca.is_some_and(|c| p.i1 <= c && c <= p.i2);
        let on_b = |p: &Piece| cb.is_some_and(|c| p.j1 <= c && c <= p.j2);
        let hunks = || self.pieces.iter().filter(|p| p.cls == cls);
        hunks().find(|p| on_a(p) && on_b(p)).or_else(|| hunks().find(|p| on_a(p) || on_b(p))).map(|p| (p.i1, p.j1))
    }

    /// Whether the code from our cut `ca` and from the original's cut `cb` is the same block run to its end: the same
    /// instructions in turn (a `jmp` followed, a conditional jump's targets the same place or the same code again)
    /// up to a `ret` or to a pair of cuts that correspond. VC6 keeps a copy of a return tail per path or merges them,
    /// so two jumps the alignment pairs can go to two copies of one tail (seen: the original's copy before the loop,
    /// ours after it).
    ///
    /// `zero`: per side, the registers known to be zero at the jump (known_zero). A `xor R, R` only one side's path
    /// has is skipped when R is zero at the other side's jump and no line of either path so far names R (no flag
    /// reader after it): R is zero after it on both. VC6 threads a jump past a zeroing that is redundant on its path
    /// (seen: `test eax, eax; je` to the epilogue after its `xor eax, eax`, ours to the one before; or the original
    /// zeroes eax before its `test esi, esi; je`).
    #[allow(clippy::too_many_arguments)]
    fn same_tail(&self, la: &[Line], lb: &[Line], ca: usize, cb: usize, mut zero: [Vec<&'static str>; 2], depth: u32) -> bool {
        let (mut x, mut y) = (ca, cb);
        for _ in 0..32 {
            x = follow_jmp(la, x);
            y = follow_jmp(lb, y);
            if self.images(x).contains(&y) {
                return true;
            }
            let (Some(a), Some(b)) = (la.get(x), lb.get(y)) else { return false };
            if a.text != b.text {
                let skip = |l: &[Line], k: usize, z: &[&str]| z.iter().any(|r| l[k].text == format!("xor {r}, {r}"))
                    && !l.get(k + 1).is_some_and(|n| reads_flags(&n.text));
                if skip(la, x, &zero[1]) {
                    x += 1;
                    continue;
                }
                if skip(lb, y, &zero[0]) {
                    y += 1;
                    continue;
                }
                return false;
            }
            for z in zero.iter_mut() {
                z.retain(|r| !names_reg(&a.text, r));
            }
            if a.shape.mn == "ret" {
                return true;
            }
            if let (Some(ta), Some(tb)) = (a.target, b.target) {
                let (Some(ja), Some(jb)) = (cut_of(la, ta), cut_of(lb, tb)) else { return false };
                if !(self.images(ja).contains(&jb) || depth > 0 && self.same_tail(la, lb, ja, jb, [vec![], vec![]], depth - 1)) {
                    return false;
                }
            } else if a.target.is_some() != b.target.is_some() {
                return false;
            }
            (x, y) = (x + 1, y + 1);
        }
        false
    }

    /// The hunk our cut lies strictly inside, for a target the alignment gives no place: (its class, its first line).
    fn inside_of(&self, ca: usize) -> Option<(&str, usize)> {
        self.at(ca).find(|p| p.i1 < ca && ca < p.i2).map(|p| (p.cls.as_str(), p.i1))
    }
}

/// The cut of a target address: the line that starts there, or the end.
fn cut_of(l: &[Line], t: i64) -> Option<usize> {
    let k = l.partition_point(|x| (x.addr as i64) < t);
    let end = l.last().map(|x| (x.addr + x.size) as i64);
    (k < l.len() && l[k].addr as i64 == t || k == l.len() && end == Some(t)).then_some(k)
}

const GPRS: [(&str, &[&str]); 8] = [("eax", &["eax", "ax", "al", "ah"]), ("ecx", &["ecx", "cx", "cl", "ch"]), ("edx", &["edx", "dx", "dl", "dh"]),
                                   ("ebx", &["ebx", "bx", "bl", "bh"]), ("esi", &["esi", "si"]), ("edi", &["edi", "di"]),
                                   ("ebp", &["ebp", "bp"]), ("esp", &["esp", "sp"])];

/// Whether a line's text names register `r` (eax) or a part of it (al).
fn names_reg(text: &str, r: &str) -> bool {
    let parts = GPRS.iter().find(|g| g.0 == r).map(|g| g.1).unwrap_or(&[]);
    text.split(|c: char| !c.is_ascii_alphanumeric()).any(|t| parts.contains(&t))
}

/// Whether an instruction reads the flags (a conditional jump, setcc, cmovcc, adc, sbb).
fn reads_flags(text: &str) -> bool {
    let mn = mnemonic(text);
    mn.starts_with('j') && mn != "jmp" || mn.starts_with("set") || mn.starts_with("cmov") || matches!(mn, "adc" | "sbb" | "pushfd" | "lahf")
}

/// The registers known to be zero where the jump at line `k` is taken: R of a `je` right after `test R, R` (or
/// `or R, R`, `cmp R, 0`), and of each `xor R, R` earlier in its block with no line between naming R. Read back at
/// most 8 lines, never past a call, a jump, a return or a line some jump goes to.
fn known_zero(l: &[Line], k: usize) -> Vec<&'static str> {
    let is_target = |q: usize| l.iter().any(|x| x.target == Some(l[q].addr as i64));
    let mut out = vec![];
    if is_target(k) {
        return out;
    }
    if mnemonic(&l[k].text) == "je" && k > 0 {
        let p = &l[k - 1].text;
        if let Some(g) = GPRS.iter().find(|g| [format!("test {0}, {0}", g.0), format!("or {0}, {0}", g.0), format!("cmp {}, 0", g.0)].contains(p)) {
            out.push(g.0);
        }
    }
    for q in (k.saturating_sub(8)..k).rev() {
        let t = &l[q].text;
        if let Some(g) = GPRS.iter().find(|g| *t == format!("xor {0}, {0}", g.0)) {
            if !out.contains(&g.0) && (q + 1..k).all(|m| !names_reg(&l[m].text, g.0)) {
                out.push(g.0);
            }
        }
        if matches!(mnemonic(t), "call" | "ret" | "jmp") || l[q].target.is_some() || is_target(q) {
            break;
        }
    }
    out
}

/// A cut through the `jmp`s that start there (at most 8).
fn follow_jmp(l: &[Line], mut c: usize) -> usize {
    for _ in 0..8 {
        match l.get(c) {
            Some(x) if x.shape.mn == "jmp" => match x.target.and_then(|t| cut_of(l, t)) {
                Some(t) => c = t,
                None => break,
            },
            _ => break,
        }
    }
    c
}

/// The branch check, (the real differences, the grouped lines of jumps into code hunks): every pair of jumps the
/// alignment pairs (Cuts::pairs), their targets taken as cuts and mapped through the cut correspondence. A target
/// pair that does not correspond but goes to two copies of the same code (Cuts::same_tail) is the same jump. One
/// that does not, with a cut in or on a code hunk, is that hunk's difference: one line per hunk. Any
/// other is a real difference of the statement structure; its message names both target instructions and where the
/// alignment puts ours' target (two offsets that read the same are never printed alone: a match-base report).
fn branch_diffs(la: &[Line], lb: &[Line], hs: &[Hunk], renamed: bool) -> (Vec<String>, Vec<String>) {
    if la.is_empty() || lb.is_empty() {
        return (vec![], vec![]);
    }
    let cuts = Cuts::new(la, lb, hs, renamed);
    let base = la[0].addr as i64;
    let off = |l: &[Line], c: usize| match l.get(c) {
        Some(x) => x.addr as i64 - base,
        None => l.last().map(|x| (x.addr + x.size) as i64 - base).unwrap_or(0),
    };
    let place = |l: &[Line], c: Option<usize>| match c {
        Some(c) => format!("+{} ({})", py_hex(off(l, c)), l.get(c).map(|x| x.text.as_str()).unwrap_or("the end")),
        None => "outside the code".to_string(),
    };
    let (mut out, mut into): (Vec<String>, Vec<((usize, usize), usize)>) = (vec![], vec![]);
    for &(i, j) in &cuts.pairs {
        let (Some(ta), Some(tb)) = (la[i].target, lb[j].target) else { continue };
        let (ca, cb) = (cut_of(la, ta), cut_of(lb, tb));
        if ca.is_none() && cb.is_none() {
            continue;
        }
        let images = ca.map(|c| cuts.images(c)).unwrap_or_default();
        if cb.is_some_and(|c| images.contains(&c)) {
            continue;
        }
        if let (Some(x), Some(y)) = (ca, cb) {
            if cuts.same_tail(la, lb, x, y, [known_zero(la, i), known_zero(lb, j)], 4) {
                continue;
            }
        }
        if let Some(h) = cuts.hunk_of("code", ca, cb) {
            match into.iter_mut().find(|x| x.0 == h) {
                Some(x) => x.1 += 1,
                None => into.push((h, 1)),
            }
            continue;
        }
        let mut s = format!("{} at +{}: ours to {}, the original's to {}", mnemonic(&la[i].text), py_hex(la[i].addr as i64 - base),
                            place(la, ca), place(lb, cb));
        if let Some(c) = ca {
            match (images.first(), cuts.inside_of(c)) {
                (Some(&x), _) => s += &format!("; the alignment puts ours' target at the original's +{}", py_hex(off(lb, x))),
                (None, Some((cls, h))) => s += &format!("; ours' target lies inside the {cls} hunk at +{}, which gives it no place in the original",
                                                        py_hex(off(la, h))),
                _ => {}
            }
        }
        out.push(s);
    }
    into.sort();
    let into = into.into_iter().map(|((h, _), n)| format!("{n} jump{} into the code hunk at +{}", if n == 1 { "" } else { "s" }, py_hex(off(la, h)))).collect();
    (out, into)
}

fn bump(w: &mut Vec<(String, i64)>, k: &str, n: i64) {
    match w.iter_mut().find(|x| x.0 == k) {
        Some(x) => x.1 += n,
        None => w.push((k.to_string(), n)),
    }
}

fn judge(la: &[Line], lb: &[Line], hs: &[Hunk], tables: Option<&Tables>) -> Verdict {
    let (a, b) = (texts(la), texts(lb));
    let mut weight: Vec<(String, i64)> = vec![];
    let (mut minus, mut plus, mut code) = (vec![], vec![], vec![]);
    for (i1, i2, j1, j2, cls, _) in hs {
        bump(&mut weight, cls, (i2 - i1 + j2 - j1) as i64);
        if cls == "code" {
            minus.extend_from_slice(&a[*i1..*i2]);
            plus.extend_from_slice(&b[*j1..*j2]);
            code.push((*i1, a[*i1..*i2].iter().take(8).cloned().collect(), b[*j1..*j2].iter().take(8).cloned().collect()));
        }
    }
    // the code hunks are moved instructions: their lines the same on both sides, or with the lines of the explained
    // hunks taken as they are (a hunk-local renaming can pair a moved instruction with another one, and leave
    // its partner to a code hunk of its own: seen with two zeroings moved apart)
    // a moved push, pop, call or stack cleanup is no move: it changes what a call gets as arguments (a nested
    // call's partial cleanup against a merged one); the prover
    // judges such code. The function's whole sequence of them is compared: an instruction moved past a pop of the
    // epilogue changes nothing on the stack
    // per basic block (a moved block keeps its own order)
    let tails = |side: usize| -> HashSet<usize> {
        hs.iter().filter(|h| h.4 == "tail").flat_map(|h| if side == 0 { h.0..h.1 } else { h.2..h.3 }).collect()
    };
    let (sa, sb) = (stack_profile(la, &tails(0)), stack_profile(lb, &tails(1)));
    let stack_moved = !code.is_empty() && (!multiset_eq(&sa.0, &sb.0) || !multiset_eq(&sa.1, &sb.1));
    if stack_moved && std::env::var_os("DCP_STACK_DEBUG").is_some() {
        let at = la.first().map(|l| l.addr).unwrap_or(0);
        let mn = |v: &Option<Shape>| v.as_ref().map(|x| format!("{x:?}")).unwrap_or_else(|| "-".into());
        let (mut ca, mut cb) = (sa.0.clone(), sb.0.clone());
        ca.sort();
        cb.sort();
        eprintln!("stack {at:#x}: calls ours {:?}
  the original {:?}", ca.iter().map(mn).collect::<Vec<_>>(), cb.iter().map(mn).collect::<Vec<_>>());
        eprintln!("stack {at:#x}: push blocks ours {:?}
  the original {:?}", sa.1.iter().map(|b| b.len()).collect::<Vec<_>>(), sb.1.iter().map(|b| b.len()).collect::<Vec<_>>());
    }
    let moved = !code.is_empty() && !stack_moved && (multiset_eq(&minus, &plus) || {
        let (mut m, mut p) = (minus.clone(), plus.clone());
        for (i1, i2, j1, j2, _, _) in hs.iter().filter(|h| h.4 != "code" && h.4 != "fill") {
            m.extend_from_slice(&a[*i1..*i2]);
            p.extend_from_slice(&b[*j1..*j2]);
        }
        multiset_eq(&m, &p)
    });
    let renamed = !code.is_empty() && !moved && shape::one_renaming(&shapes(la), &shapes(lb));
    let bad = tables.is_some_and(|t| !t.diffs.is_empty());
    if bad {
        bump(&mut weight, "table", tables.unwrap().diffs.len() as i64);
    }
    let (branches, into_code) = branch_diffs(la, lb, hs, renamed);
    if !branches.is_empty() {
        bump(&mut weight, "branch", branches.len() as i64);
    }
    let shape = (code.is_empty() || moved || renamed) && !bad && branches.is_empty();
    code.truncate(6);
    Verdict { shape, hunks: weight, moved, renamed, code, distance: distance(&a, &b), tables: tables.cloned(), frame: None,
              branches: branches.into_iter().take(12).collect(), into_code }
}

/// diffclass.analyse: (the hunks, the verdict) of two listings: the plain diff, or the frame-aligned one when the
/// frames differ in size and the plain diff is no shape.
pub fn analyse(la: &[Line], lb: &[Line], tables: Option<&Tables>) -> (Vec<Hunk>, Verdict) {
    let hs = classify_hunks(la, lb);
    let mut v = judge(la, lb, &hs, tables);
    let (sa, sb) = (shapes(la), shapes(lb));
    let frame = shape::frame_delta(&sa, &sb);
    if v.shape {
        // the distance as asmdiff counts it whenever the frames differ
        if let Some(f) = frame {
            v.distance = frame_distance(&sa, &sb, f);
        }
        return (hs, v);
    }
    let Some(frame) = frame else { return (hs, v) };
    let fh = frame_hunks(la, lb, frame);
    let mut fv = judge(la, lb, &fh, tables);
    fv.frame = Some(frame);
    fv.distance = frame_distance(&sa, &sb, frame);
    (fh, fv)
}

// ------------------------------------------------------------------------------------------------ sizes, the original

pub struct Env<'a> {
    pub img: &'a crate::pe::Image,
    pub range: (i64, i64),
    pub fills: &'a HashSet<Vec<u8>>,
    pub forms: &'a [Vec<u8>], // fill_order
}

/// diffclass.code_size: the end of our last instruction that is no fill.
pub fn code_size(env: &Env, code: &[u8], mask: &[u8], addr: u32) -> i64 {
    let lines = x86::strip_fill(x86::listing(code, addr, Some(mask), env.range, env.fills));
    match lines.last() {
        Some(l) => (l.addr + l.size) as i64 - addr as i64,
        None => code.len() as i64,
    }
}

#[derive(Clone, Debug)]
pub struct Original {
    pub code: i64,
    pub tables: Vec<(i64, i64, String)>,
}

/// The walk of one root over [lo, hi) (Walker.walk_root with no stops and no relocation sites): its tables.
struct Walk<'a> {
    dec: x86::Decoder<'a>,
    kind: Vec<u8>,
    align: i64,
    tables: Vec<(i64, i64, String)>,
}

impl Walk<'_> {
    fn in_code(&self, a: i64) -> bool {
        self.dec.lo as i64 <= a && a < self.dec.hi as i64
    }

    fn claim(&mut self, lo: i64, hi: i64, k: u8) {
        let base = self.dec.lo as i64;
        for a in lo..hi {
            if let Some(x) = self.kind.get_mut((a - base) as usize) {
                *x = k;
            }
        }
    }

    fn fill_to(&mut self, a: i64, t: i64) -> bool {
        if t <= a || t % self.align != 0 {
            return false;
        }
        let mut cur = a;
        while self.in_code(cur) {
            let Some(ins) = self.dec.at(cur as u32) else { return false };
            if ins.addr as i64 >= t {
                return ins.addr as i64 == t;
            }
            if !ins.fill {
                return false;
            }
            cur = (ins.addr + ins.size) as i64;
        }
        false
    }

    fn walk_root(&mut self, root: i64) {
        let lo = self.dec.lo as i64;
        let mut work = vec![root];
        while let Some(start) = work.pop() {
            if !self.in_code(start) || self.kind[(start - lo) as usize] == 1 {
                continue;
            }
            let mut recent: Vec<x86::WIns> = vec![];
            let mut cur = start;
            while self.in_code(cur) {
                let Some(ins) = self.dec.at(cur as u32).cloned() else { break };
                let ia = ins.addr as i64;
                if self.kind[(ia - lo) as usize] == 1 {
                    break;
                }
                if ins.fill && ia != start {
                    break;
                }
                let size = ins.size as i64;
                self.claim(ia, ia + size, 1);
                recent.push(ins.clone());
                if recent.len() > 12 {
                    recent.remove(0);
                }
                match ins.flow {
                    x86::RET => break,
                    x86::JUMP | x86::CJUMP => {
                        let t = ins.target.unwrap();
                        if self.in_code(t) && !(ins.flow == x86::JUMP && self.fill_to(ia + size, t)) {
                            work.push(t);
                        }
                        if ins.flow == x86::JUMP {
                            break;
                        }
                    }
                    x86::IJUMP => {
                        if let Some(tbl) = ins.table {
                            self.jump_table(tbl as i64, &recent, root, &mut work);
                        }
                        break;
                    }
                    _ => {}
                }
                cur = ia + size;
            }
        }
    }

    fn jump_table(&mut self, tbl: i64, recent: &[x86::WIns], owner: i64, work: &mut Vec<i64>) {
        if !self.in_code(tbl) {
            return;
        }
        let (bound, byte_tbl) = self.dec.table_shape(recent);
        let (lo, hi) = (self.dec.lo as i64, self.dec.hi as i64);
        let limit = hi;
        let mut n = 0i64;
        let mut a = tbl;
        while self.in_code(a) && a + 4 <= hi {
            if let Some(b) = bound {
                if byte_tbl.unwrap_or(0) == 0 && n >= b {
                    break;
                }
            }
            let v = self.dec.read_entry(a as u32) as i64;
            if !(owner <= v && v < limit) {
                break;
            }
            if self.kind[(a - lo) as usize] != 0 {
                break;
            }
            self.claim(a, a + 4, 2);
            work.push(v);
            n += 1;
            a += 4;
        }
        if n > 0 {
            self.tables.push((tbl, a, "jumptable".into()));
        }
        if let (Some(bt), Some(b)) = (byte_tbl, bound) {
            let (bt, end) = (bt as i64, bt as i64 + b);
            let free = (bt..end).all(|p| !self.in_code(p) || self.kind[(p - lo) as usize] == 0);
            if free {
                self.claim(bt, end.min(hi), 2);
                self.tables.push((bt, end.min(hi), "idxtable".into()));
            }
        }
    }
}

/// diffclass.original: walk the original's slot, cut the extent at its first table inside it.
pub fn original(env: &Env, addr: u32, extent: i64, slot: i64, align: i64) -> Original {
    let a = addr as i64;
    let hi = a + slot.max(extent);
    let mut tables = vec![];
    if hi > a {
        let mut w = Walk { dec: x86::Decoder::new(env.img, addr, hi as u32, env.fills), kind: vec![0; (hi - a) as usize],
                           align: align.max(1), tables: vec![] };
        w.walk_root(a);
        let set: HashSet<(i64, i64, String)> = w.tables.into_iter().collect();
        tables = set.into_iter().collect();
        tables.sort();
    }
    let inside: Vec<i64> = tables.iter().map(|t| t.0).filter(|&lo| a < lo && lo < a + extent).collect();
    let Some(&end) = inside.iter().min() else { return Original { code: extent, tables } };
    let data = env.img.read(addr, (end - a) as usize);
    let lines = x86::strip_fill(x86::listing(&data, addr, None, env.range, env.fills));
    let code = match lines.last() {
        Some(l) => (l.addr + l.size) as i64 - a,
        None => end - a,
    };
    Original { code, tables }
}

// ------------------------------------------------------------------------------------------------ the tables, the compare

fn block(l: &[Line], i: usize) -> Vec<&str> {
    let mut out = vec![];
    for x in l.iter().skip(i).take(12) {
        out.push(x.text.as_str());
        if matches!(mnemonic(&x.text), "ret" | "jmp") {
            break;
        }
    }
    out
}

/// diffclass.compare_tables: the switch tables of both sides as data, None when either side has none.
pub fn compare_tables(env: &Env, obj: &crate::coff::Obj, code: &crate::coff::FunctionCode, addr: u32, la: &[Line], lb: &[Line],
                      tables: &[(i64, i64, String)]) -> Option<Tables> {
    let cl = code.code_len? as usize;
    if tables.is_empty() {
        return None;
    }
    let addr_i = addr as i64;
    let t0 = tables[0].0;
    let t1 = tables.iter().map(|t| t.1).max().unwrap();
    if t0 < addr_i {
        return None;
    }
    let ours = &code.data[cl.min(code.data.len())..];
    let mask = &code.mask[cl.min(code.mask.len())..];
    let orig = env.img.read(t0 as u32, (t1 - t0) as usize);
    let mut relocs: HashMap<i64, crate::coff::Reloc> = HashMap::new();
    for (off, r) in &code.relocs {
        if *off as usize >= cl {
            relocs.insert(*off as i64 - cl as i64, *r);
        }
    }
    let pos_a: HashMap<i64, usize> = la.iter().enumerate().map(|(i, x)| (x.addr as i64 - addr_i, i)).collect();
    let pos_b: HashMap<i64, usize> = lb.iter().enumerate().map(|(i, x)| (x.addr as i64 - addr_i, i)).collect();
    let (a, b) = (texts(la), texts(lb));
    let mut m: HashMap<usize, usize> = HashMap::new();
    for (tag, i1, i2, j1, _) in opcodes(&a, &b) {
        if tag == Tag::Equal {
            for k in 0..i2 - i1 {
                m.insert(i1 + k, j1 + k);
            }
        }
    }
    let hs = hunks(&a, &b);
    let same = |ta: Option<i64>, tb: i64| -> bool {
        if ta == Some(tb) {
            return true;
        }
        let (Some(ia), Some(&ib)) = (ta.and_then(|t| pos_a.get(&t).copied()), pos_b.get(&tb)) else { return false };
        m.get(&ia) == Some(&ib) || hs.iter().any(|&(i1, i2, j1, j2)| i1 <= ia && ia < i2 && j1 <= ib && ib < j2) || block(la, ia) == block(lb, ib)
    };
    let (mut diffs, mut entries, mut nbytes) = (vec![], 0i64, 0i64);
    let n = ours.len().min(orig.len());
    let mut k = 0usize;
    while k < n {
        if mask.get(k).copied().unwrap_or(0) != 0 {
            let r = relocs.get(&(k as i64));
            let width = r.map(|r| r.kind_width().1 as usize);
            if r.is_none() || width != Some(4) || k + 4 > n {
                diffs.push(format!("+{}: a relocated field that is no table entry", py_hex(k as i64)));
                k += 1usize.max(width.unwrap_or(1));
                continue;
            }
            let r = r.unwrap();
            entries += 1;
            let ta = obj.symbol_at(r.symbol_index).filter(|s| s.secnum as usize == code.secnum)
                .map(|s| s.value as i64 + obj.addend(code.secnum, r) as i64 - code.start as i64);
            let tb = u32::from_le_bytes([orig[k], orig[k + 1], orig[k + 2], orig[k + 3]]) as i64 - addr_i;
            if !same(ta, tb) {
                diffs.push(match ta {
                    Some(ta) => format!("entry +{}: ours to +{}, the original's to +{}", py_hex(k as i64), py_hex(ta), py_hex(tb)),
                    None => format!("entry +{}: ours points outside the function", py_hex(k as i64)),
                });
            }
            k += 4;
            continue;
        }
        nbytes += 1;
        if ours[k] != orig[k] {
            diffs.push(format!("byte +{}: {:#04x} vs {:#04x}", py_hex(k as i64), ours[k], orig[k]));
        }
        k += 1;
    }
    if ours.len() > n && !crate::compare::is_fill(&ours[n..], env.forms) {
        diffs.push(format!("ours has {} table bytes more", ours.len() - n));
    }
    if orig.len() > n {
        diffs.push(format!("the original has {} table bytes more", orig.len() - n));
    }
    diffs.truncate(12);
    Some(Tables { entries, bytes: nbytes, diffs })
}

/// One function's comparison, computed once: our object's function against the original at `addr` (as the walk of
/// its slot found it: `Original`), both listings, the switch tables, the classified hunks and the verdict. G.grade (which
/// keeps the verdict by the function's content), `dcp asmdiff`, `dcp diffclass`, `dcp level` and the header trial
/// all read it.
pub struct FunctionCompare {
    pub la: Vec<Line>,
    pub lb: Vec<Line>,
    pub tables: Option<Tables>,
    pub hunks: Vec<Hunk>,
    pub verdict: Verdict,
}

impl FunctionCompare {
    pub fn new(env: &Env, obj: &crate::coff::Obj, code: &crate::coff::FunctionCode, addr: u32, original: &Original) -> FunctionCompare {
        let (cd, cm) = code.code();
        let la = x86::strip_fill(x86::listing(cd, addr, Some(cm), env.range, env.fills));
        let data = env.img.read(addr, original.code.max(0) as usize);
        let lb = x86::strip_fill(x86::listing(&data, addr, None, env.range, env.fills));
        let tables = compare_tables(env, obj, code, addr, &la, &lb, &original.tables);
        let (hunks, verdict) = analyse(&la, &lb, tables.as_ref());
        FunctionCompare { la, lb, tables, hunks, verdict }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::testpe::{build_with, BASE, TEXT};

    fn verdict(la: &[Line], lb: &[Line], tables: Option<&Tables>) -> Verdict {
        analyse(la, lb, tables).1
    }

    fn lines(texts: &[&str]) -> Vec<Line> {
        texts.iter().enumerate().map(|(k, t)| Line::of(0x1000 + k as u32, t, *t == "nop" || *t == "int3", None)).collect()
    }

    fn classes(a: &[Line], b: &[Line]) -> Vec<String> {
        classify_hunks(a, b).into_iter().map(|h| h.4).collect()
    }

    fn weight(v: &Verdict, k: &str) -> Option<i64> {
        v.hunks.iter().find(|x| x.0 == k).map(|x| x.1)
    }

    #[test]
    fn the_stack_keeps_its_order() {
        // two pushes swapped before a call: another argument order, not scheduling
        let a = lines(&["mov edx, 1", "push edx", "push 0x101", "call 0x500000", "ret"]);
        let b = lines(&["mov edx, 1", "push 0x101", "push edx", "call 0x500000", "ret"]);
        assert_eq!(classes(&a, &b), ["code"]);
        assert!(!verdict(&a, &b, None).shape);
        // a load moved past a push: scheduling
        let a = lines(&["mov eax, 1", "push 2", "call 0x500000", "ret"]);
        let b = lines(&["push 2", "mov eax, 1", "call 0x500000", "ret"]);
        assert_eq!(classes(&a, &b), ["order"]);
        // a nested call `outer(4, inner(2, 1))`: the original pops inner's 8 bytes and leaves outer's 4 pending; ours,
        // through a cast, pops everything after the outer call: a cleanup moved across a call, no move
        let a = lines(&["push 4", "push 1", "push 2", "call 0x500000", "push eax", "call 0x500100", "add esp, 0x10", "ret"]);
        let b = lines(&["push 4", "push 1", "push 2", "call 0x500000", "add esp, 8", "push eax", "call 0x500100", "add esp, 8", "ret"]);
        let v = verdict(&a, &b, None);
        assert!(!v.moved && !v.shape, "{:?}", v.hunks);
    }

    #[test]
    fn hunk_classes() {
        let a = lines(&["push esi", "mov esi, dword ptr [esp + 8]", "mov eax, esi", "pop esi", "ret"]);
        let b = lines(&["push edi", "mov edi, dword ptr [esp + 8]", "mov eax, edi", "pop edi", "ret"]);
        let hs = classify_hunks(&a, &b);
        assert_eq!(hs.len(), 1);
        assert_eq!(hs[0].4, "regs");
        assert!(hs[0].5.contains("esi->edi"));
        assert!(verdict(&a, &b, None).shape);
        assert_eq!(classes(&lines(&["mov eax, 1", "mov ecx, 2", "ret"]), &lines(&["mov ecx, 2", "mov eax, 1", "ret"])), ["order"]);
        let c = classes(&lines(&["mov eax, dword ptr [esp + 4]", "mov ecx, dword ptr [esp + 8]", "ret"]),
                        &lines(&["mov eax, dword ptr [esp + 8]", "mov ecx, dword ptr [esp + 4]", "ret"]));
        assert!(c == ["slots"] || c == ["regs"]);
        assert_eq!(classes(&lines(&["mov eax, dword ptr [ecx + edx + 4]", "mov ebx, dword ptr [ecx + esi]", "ret"]),
                           &lines(&["mov eax, dword ptr [edx + ecx + 4]", "mov ebx, dword ptr [esi + ecx]", "ret"])), ["sib"]);
        let (a, b) = (lines(&["mov eax, 1", "ret"]), lines(&["mov eax, 2", "ret"]));
        let v = verdict(&a, &b, None);
        assert_eq!(classes(&a, &b), ["code"]);
        assert!(!v.shape && v.distance == 2);
        assert_eq!(weight(&verdict(&lines(&["ret", "nop", "nop"]), &lines(&["ret", "int3"]), None), "fill"), Some(3));
    }

    #[test]
    fn repeated_loops() {
        // eleven copies of one column loop (a match-base report): ours keeps the column
        // pointer in another stack slot, the original's sixth copy as ours. Each copy aligns with its own and every
        // difference reads slots (the longest-run alignment paired copies across: one code hunk of hundreds of lines)
        let body = |k: usize, slot: &str, r: &str| -> Vec<String> {
            vec![format!("mov {r}, dword ptr [esp + {slot}]"), format!("mov eax, dword ptr [{r} + {k}]"), "push eax".into(), "call X".into(),
                 format!("mov esi, {r}"), "add esp, 4".into(), "test esi, esi".into(), "je X".into(), "fstp dword ptr [edi]".into(),
                 format!("inc {r}"), "add edi, 0xc".into()]
        };
        let to_lines = |v: Vec<String>| lines(&v.iter().map(|s| s.as_str()).collect::<Vec<_>>());
        let a = to_lines((0..11).flat_map(|k| body(k % 3, "0x10", "edx")).chain(["ret".to_string()]).collect());
        let b = to_lines((0..11).flat_map(|k| body(k % 3, if k == 5 { "0x10" } else { "0x18" }, "edx")).chain(["ret".to_string()]).collect());
        let v = verdict(&a, &b, None);
        assert!(v.shape && v.distance == 20 && v.hunks == [("slots".to_string(), 20)], "{:?} {}", v.hunks, v.distance);
        // two copies whose differences are fewer than 5 lines apart join into one hunk; each copy has its own
        // register allocation (ours edx in both, the original's ecx in the first, ebx in the second). Each copy
        // starts by loading the register, so the renaming is renewed there and one hunk reads regs as a whole
        let a = to_lines([body(0, "0x10", "edx"), body(1, "0x10", "edx"), vec!["ret".to_string()]].concat());
        let b = to_lines([body(0, "0x10", "ecx"), body(1, "0x10", "ebx"), vec!["ret".to_string()]].concat());
        assert_eq!(hunks(&texts(&a), &texts(&b)).len(), 1);
        let hs = classify_hunks(&a, &b);
        assert!(hs.iter().all(|h| h.4 == "regs"), "{hs:?}");
        assert!(hs.iter().any(|h| h.5.contains("edx->ecx")) && hs.iter().any(|h| h.5.contains("edx->ebx")), "{hs:?}");
        assert!(verdict(&a, &b, None).shape);
        // a piece no class explains stays code beside the explained ones
        let mut c = [body(0, "0x10", "ecx"), body(1, "0x10", "ebx"), vec!["ret".to_string()]].concat();
        c[13] = "push ebx".into();
        let hs = classify_hunks(&a, &to_lines(c));
        assert!(hs.iter().any(|h| h.4 == "code") && hs.iter().any(|h| h.4 == "regs"), "{hs:?}");
    }

    #[test]
    fn shared_and_inline_tails() {
        // ours merges two identical fail tails into one and jumps to it, the original keeps
        // a copy per path
        let ours = jumps(&[("cmp eax, 1", None), ("jne X", Some(4)), ("push edx", None), ("jmp X", Some(5)), ("push ecx", None),
                           ("call X", None), ("add esp, 4", None), ("mov eax, -1", None), ("ret", None)]);
        let theirs = jumps(&[("cmp eax, 1", None), ("jne X", Some(7)), ("push edx", None), ("call X", None), ("add esp, 4", None),
                             ("mov eax, -1", None), ("ret", None), ("push ecx", None), ("call X", None), ("add esp, 4", None),
                             ("mov eax, -1", None), ("ret", None)]);
        let (hs, v) = analyse(&ours, &theirs, None);
        assert_eq!(hs.iter().map(|h| h.4.as_str()).collect::<Vec<_>>(), ["tail"], "{hs:?}");
        assert!(hs[0].5.contains("ours jumps to a shared block at +0x5 (4 instructions) the original has inline at +0x3"), "{hs:?}");
        assert!(v.shape, "{}", v.summary());
        // the other way round
        let (hs, _) = analyse(&theirs, &ours, None);
        assert!(hs[0].4 == "tail" && hs[0].5.starts_with("the original jumps to a shared block"), "{hs:?}");
        // ours branches to one shared `return -1` epilogue, the original branches round a
        // copy of it on the inverted condition
        let ours = jumps(&[("test eax, eax", None), ("je X", Some(4)), ("mov eax, 1", None), ("ret", None),
                           ("pop edi", None), ("or eax, -1", None), ("ret", None)]);
        let orig = jumps(&[("test eax, eax", None), ("jne X", Some(5)), ("pop edi", None), ("or eax, -1", None), ("ret", None),
                           ("mov eax, 1", None), ("ret", None), ("pop edi", None), ("or eax, -1", None), ("ret", None)]);
        let (hs, _) = analyse(&ours, &orig, None);
        assert!(hs.len() == 1 && hs[0].4 == "tail" && hs[0].5.contains("ours branches to a shared block at +0x4 (3 instructions)"), "{hs:?}");
        // a block that differs is no tail
        let mut other = theirs.clone();
        other[5] = Line::of(other[5].addr, "mov eax, -2", false, None);
        assert_eq!(analyse(&ours, &other, None).0[0].4, "code");
    }

    #[test]
    fn frame_class() {
        let body = ["sub esp, {f}", "mov eax, dword ptr [esp + {arg}]", "mov dword ptr [esp + 0x10], eax", "mov ecx, 3", "mov edx, 4",
                    "lea ecx, [esp + {loc}]", "push ecx", "call X", "{st}", "add esp, {f}", "ret"];
        let f = |fr: &str, arg: &str, loc: &str, st: &str| -> Vec<Line> {
            let ts: Vec<String> = body.iter().map(|t| t.replace("{f}", fr).replace("{arg}", arg).replace("{loc}", loc).replace("{st}", st)).collect();
            lines(&ts.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        };
        let st = "mov dword ptr [esp + 0x14], ecx";
        let (a, b) = (f("0xcc", "0xd0", "0x7c", st), f("0xc8", "0xcc", "0x78", st));
        assert!(!judge(&a, &b, &classify_hunks(&a, &b), None).shape);
        let (hs, v) = analyse(&a, &b, None);
        assert!(v.shape && v.frame == Some((0xcc, 0xc8)) && hs.iter().all(|h| h.4 == "frame"));
        assert_eq!(v.distance, 0); // the frame-aligned count, as asmdiff's (a report: dist counted the shifted lines)
        assert!(hs[0].5.contains("shifted by 0x4 (frame 0xcc vs 0xc8)") && v.summary().contains("frame 0xcc vs 0xc8"));
        let (hs, v) = analyse(&a, &f("0xc8", "0xcc", "0x78", "mov dword ptr [esp + 0x14], 0"), None);
        assert!(!v.shape && v.distance == 2, "{}", v.distance);
        assert_eq!(hs.iter().filter(|h| h.4 == "code").map(|h| (h.0, h.1)).collect::<Vec<_>>(), [(8, 9)]);
        let (hs, v) = analyse(&a, &f("0xc8", "0xc4", "0x78", st), None);
        assert!(!v.shape && hs.iter().any(|h| h.4 == "code"));
        let (_, v) = analyse(&f("0xcc", "0xd0", "0x7c", st), &f("0xcc", "0xd4", "0x7c", st), None);
        assert!(v.frame.is_none());
    }

    fn jumps(rows: &[(&str, Option<u32>)]) -> Vec<Line> {
        rows.iter().enumerate().map(|(k, (t, g))| Line::of(0x1000 + k as u32, t, false, g.map(|g| 0x1000 + g as i64))).collect()
    }

    #[test]
    fn branch_targets() {
        let body = [("test eax, eax", None), ("je X", Some(4)), ("mov eax, 1", None), ("jmp X", Some(5)), ("xor eax, eax", None),
                    ("pop esi", None), ("ret", None)];
        let a = jumps(&body);
        assert!(verdict(&a, &jumps(&body), None).shape);
        let mut b = body.to_vec();
        b[1] = ("je X", Some(2));
        let v = verdict(&a, &jumps(&b), None);
        assert!(!v.shape && v.hunks == [("branch".to_string(), 1)] && v.branches[0].contains("je at +0x1: ours to +0x4 (xor eax, eax), the original's to +0x2 (mov eax, 1); the alignment puts ours' target at the original's +0x4"), "{:?}", v.branches);
        let renamed: Vec<(String, Option<u32>)> = body.iter().map(|(t, g)| (t.replace("eax", "ecx"), *g)).collect();
        let renamed: Vec<(&str, Option<u32>)> = renamed.iter().map(|(t, g)| (t.as_str(), *g)).collect();
        assert!(verdict(&a, &jumps(&renamed), None).shape);
        let dup = [("test eax, eax", None), ("je X", Some(6)), ("mov eax, 1", None), ("pop esi", None), ("ret", None), ("int3", None),
                   ("pop esi", None), ("ret", None)];
        let ours = jumps(&[dup[0], ("je X", Some(3)), dup[2], dup[3], dup[4]]);
        assert!(verdict(&ours, &jumps(&dup), None).branches.is_empty());
        let mut out = body.to_vec();
        out[1] = ("je X", Some(0x40));
        let v = verdict(&a, &jumps(&out), None);
        assert!(!v.branches.is_empty() && v.branches[0].contains("outside the code"));
        // a jump to the first line of an fpu hunk on both sides is the same jump, the hunk's lines differing (a
        // match-base report: a loop head moved by a longer fpu hunk counted as a flow difference)
        let ours = [("test eax, eax", None), ("je X", Some(3)), ("mov eax, 1", None), ("fld dword ptr [ecx]", None), ("fadd st(1)", None),
                    ("fstp st(0)", None), ("ret", None)];
        let theirs = [("test eax, eax", None), ("je X", Some(3)), ("mov eax, 1", None), ("fld st(1)", None), ("fld dword ptr [ecx]", None),
                      ("faddp st(1)", None), ("fstp st(0)", None), ("ret", None)];
        let v = verdict(&jumps(&ours), &jumps(&theirs), None);
        assert!(v.branches.is_empty() && v.hunks.iter().all(|h| h.0 == "fpu"), "{:?} {:?}", v.branches, v.hunks);
        // an order hunk with a register swap, one mov moved across a jle: the je's target is the same line on both
        // sides; the hunk's lines pair by their text after the swap, not the raw text (a match-base report: "je at
        // +0x11b: ours to +0x131, the original's to +0x131")
        let ours = [("xor edx, edx", None), ("mov eax, edi", None), ("test esi, esi", None), ("mov ecx, edi", None), ("jle X", Some(12)),
                    ("cmp dword ptr [ecx], -1", None), ("je X", Some(10)), ("mov eax, ecx", None), ("inc edx", None), ("jmp X", Some(12)),
                    ("mov eax, edx", None), ("shl eax, 4", None), ("ret", None)];
        let theirs = [("xor ecx, ecx", None), ("mov eax, edi", None), ("test esi, esi", None), ("jle X", Some(12)), ("mov edx, edi", None),
                      ("cmp dword ptr [edx], -1", None), ("je X", Some(10)), ("mov eax, edx", None), ("inc ecx", None), ("jmp X", Some(12)),
                      ("mov eax, ecx", None), ("shl eax, 4", None), ("ret", None)];
        let v = verdict(&jumps(&ours), &jumps(&theirs), None);
        assert!(v.shape && v.branches.is_empty() && v.hunks.iter().all(|h| h.0 == "order"), "{:?} {:?}", v.branches, v.hunks);
        // the same hunk with the je going elsewhere in the original is still a branch difference
        let mut other = theirs.to_vec();
        other[6] = ("je X", Some(11));
        let v = verdict(&jumps(&ours), &jumps(&other), None);
        assert!(!v.shape && v.branches.len() == 1 && v.branches[0].contains("je at +0x6: ours to +0xa (mov eax, edx), the original's to +0xb (shl eax, 4)"), "{:?}", v.branches);
        // the epilogue's pops in another order (a match-base report: "jg at +0x35: ours to +0x76, the original's to
        // +0x76"): the je goes to the cut inside the order hunk after the same two movs on
        // both sides, though the instructions at the target differ
        let ours = [("test eax, eax", None), ("je X", Some(4)), ("mov ecx, 1", None), ("mov edx, 2", None), ("pop ebx", None),
                    ("pop edi", None), ("ret", None)];
        let theirs = [("test eax, eax", None), ("je X", Some(4)), ("mov edx, 2", None), ("mov ecx, 1", None), ("pop edi", None),
                      ("pop ebx", None), ("ret", None)];
        let v = verdict(&jumps(&ours), &jumps(&theirs), None);
        assert!(v.shape && v.branches.is_empty() && v.into_code.is_empty(), "{:?} {:?}", v.branches, v.hunks);
        // into the same hunk after other prefixes: a real difference, both target instructions named
        let mut other = theirs.to_vec();
        other[1] = ("je X", Some(3));
        let v = verdict(&jumps(&ours), &jumps(&other), None);
        assert!(!v.shape && v.branches.len() == 1, "{:?}", v.branches);
        assert!(v.branches[0].contains("ours to +0x4 (pop ebx), the original's to +0x3 (mov ecx, 1)"), "{:?}", v.branches);
        // one inserted instruction shifts every later target (a match-base report: ~12 "targets differ" lines for
        // one epilogue): the targets in equal runs correspond by position
        let tail = [("mov eax, 1", None), ("cmp ecx, 2", None), ("jne X", Some(9)), ("inc eax", None), ("ret", None)];
        let row = |t: &(&'static str, Option<u32>), d: u32| (t.0, t.1.map(|g| g + d));
        let ours: Vec<_> = [("test eax, eax", None), ("je X", Some(5)), ("push esi", None), ("pop esi", None), ("xor eax, eax", None)]
            .iter().map(|t| row(t, 0)).chain(tail.iter().map(|t| row(t, 0))).collect();
        let theirs: Vec<_> = [("test eax, eax", None), ("je X", Some(6)), ("push esi", None), ("mov esi, ecx", None), ("pop esi", None),
                              ("xor eax, eax", None)].iter().map(|t| row(t, 0)).chain(tail.iter().map(|t| row(t, 1))).collect();
        let (hs, v) = analyse(&jumps(&ours), &jumps(&theirs), None);
        assert!(v.branches.is_empty() && v.into_code.is_empty() && hs.len() == 1 && hs[0].4 == "code", "{:?} {:?} {hs:?}", v.branches, v.into_code);
        // two jumps into a code hunk, its lines differing: one line under the hunk, no branch difference
        let ours = [("test eax, eax", None), ("je X", Some(5)), ("cmp ecx, 1", None), ("je X", Some(6)), ("ret", None), ("mov eax, 1", None),
                    ("mov eax, 2", None), ("ret", None)];
        let theirs = [("test eax, eax", None), ("je X", Some(6)), ("cmp ecx, 1", None), ("je X", Some(5)), ("ret", None), ("mov eax, 3", None),
                      ("mov eax, 4", None), ("ret", None)];
        let v = verdict(&jumps(&ours), &jumps(&theirs), None);
        assert!(v.branches.is_empty() && v.into_code == ["2 jumps into the code hunk at +0x5"], "{:?} {:?}", v.branches, v.into_code);
        assert!(v.summary().contains("2 jumps into the code hunk at +0x5") && !v.summary_without_branches().contains("jumps into"));
        // two copies of one return tail, ours' je to the first, the original's to the second (proved equal): the
        // same code from both targets, no difference
        let body = [("test eax, eax", None), ("je X", Some(3)), ("mov eax, 1", None), ("pop esi", None), ("ret", None),
                    ("xor eax, eax", None), ("pop esi", None), ("ret", None)];
        let mut other = body.to_vec();
        other[1] = ("je X", Some(6));
        let v = verdict(&jumps(&body), &jumps(&other), None);
        assert!(v.shape && v.branches.is_empty(), "{:?}", v.branches);
        // the original's je skips the zeroing its tail does (`je` past `xor eax, eax`, eax differs at the return): a
        // real difference
        let ours = [("test ecx, ecx", None), ("je X", Some(3)), ("inc edx", None), ("pop edi", None), ("pop esi", None), ("xor eax, eax", None),
                    ("ret", None)];
        let theirs = [("test ecx, ecx", None), ("je X", Some(4)), ("inc edx", None), ("xor eax, eax", None), ("pop edi", None), ("pop esi", None),
                      ("ret", None)];
        let v = verdict(&jumps(&ours), &jumps(&theirs), None);
        assert!(!v.shape && v.branches.len() == 1 && v.branches[0].contains("ours to +0x3 (pop edi), the original's to +0x4 (pop edi)"), "{:?} {:?}", v.branches, v.hunks);
        // the same where the je is taken on eax zero: the zeroing it skips is redundant on its path, the same jump
        let zero = |t: &[(&'static str, Option<u32>)]| -> Vec<(&'static str, Option<u32>)> {
            t.iter().map(|&(x, g)| (if x == "test ecx, ecx" { "test eax, eax" } else { x }, g)).collect()
        };
        let v = verdict(&jumps(&zero(&ours)), &jumps(&zero(&theirs)), None);
        assert!(v.shape && v.branches.is_empty(), "{:?} {:?}", v.branches, v.hunks);
        // the original zeroes eax before its jump, ours on the path
        let ours = [("test esi, esi", None), ("je X", Some(4)), ("xor eax, eax", None), ("inc edx", None), ("pop edi", None),
                    ("xor eax, eax", None), ("ret", None)];
        let theirs = [("xor eax, eax", None), ("test esi, esi", None), ("je X", Some(5)), ("inc edx", None), ("xor eax, eax", None),
                      ("pop edi", None), ("ret", None)];
        let v = verdict(&jumps(&ours), &jumps(&theirs), None);
        assert!(v.shape && v.branches.is_empty() && v.into_code.is_empty(), "{:?} {:?}", v.branches, v.hunks);
        // the same where the original's eax is not zero at the jump: its path returns eax as it was
        let (mut o, mut t) = (ours.to_vec(), theirs.to_vec());
        (o[2], t[0]) = (("mov eax, ecx", None), ("mov eax, ecx", None));
        let v = verdict(&jumps(&o), &jumps(&t), None);
        assert!(!v.shape && v.branches.len() == 1, "{:?} {:?}", v.branches, v.hunks);
        // the zeroing earlier in the jump's block
        let ours = [("xor eax, eax", None), ("test edi, edi", None), ("je X", Some(5)), ("inc edx", None), ("xor eax, eax", None),
                    ("pop edi", None), ("pop esi", None), ("ret", None)];
        let theirs = [("xor eax, eax", None), ("test edi, edi", None), ("je X", Some(4)), ("inc edx", None), ("pop edi", None),
                      ("xor eax, eax", None), ("pop esi", None), ("ret", None)];
        let v = verdict(&jumps(&ours), &jumps(&theirs), None);
        assert!(v.branches.is_empty(), "{:?} {:?}", v.branches, v.hunks);
    }

    /// A switch at the function's start: three cases and a default, the 3-entry jump table at +0x28 after three
    /// bytes of fill, int3 up to the next function at +0x40.
    fn switch_fn(addr: u32, entries: [u32; 3]) -> Vec<u8> {
        let mut code: Vec<u8> = vec![0x8b, 0x44, 0x24, 0x04, 0x83, 0xf8, 0x02, 0x77, 0x19, 0xff, 0x24, 0x85];
        code.extend((addr + 0x28).to_le_bytes());
        for v in [1u8, 2, 3] {
            code.extend([0xb8, v, 0, 0, 0, 0xc3]);
        }
        code.extend([0x33, 0xc0, 0xc3]);
        code.resize(0x28, 0x90);
        for e in entries {
            code.extend((addr + e).to_le_bytes());
        }
        code.resize(0x40, 0xcc);
        code
    }

    /// Our compiled switch: the same code, the table after the $L label at +0x28 (entries relocated to the section,
    /// the target offset as the addend in place).
    fn switch_ours() -> (crate::coff::Obj, usize) {
        let mut data = switch_fn(0, [0x10, 0x16, 0x1c])[..0x34].to_vec();
        data[0x0c..0x10].copy_from_slice(&0x28u32.to_le_bytes());
        let relocs: Vec<(u32, u32, u16)> = [0x0c, 0x28, 0x2c, 0x30].iter().map(|&o| (o, 0, 6)).collect();
        let obj = crate::coff::testlib::code_obj(&data, &relocs, &[(".text", 0, 1, 3), ("_sw", 0, 1, 2), ("$L1", 0x28, 1, 3)]);
        let obj = crate::coff::Obj::parse(&obj).unwrap();
        let k = obj.function_index()["sw"];
        (obj, k)
    }

    #[test]
    fn switch_tables_are_data_and_listings_mask_relocations() {
        let addr = BASE + TEXT;
        let fills: HashSet<Vec<u8>> = [vec![0x90u8], vec![0xcc]].into_iter().collect();
        let forms = vec![vec![0x90u8], vec![0xcc]];
        let check = |entries: [u32; 3]| {
            let img = crate::pe::Image::parse(build_with(None, Some(&switch_fn(addr, entries)))).unwrap();
            let env = Env { img: &img, range: (img.base as i64, img.end() as i64), fills: &fills, forms: &forms };
            let o = original(&env, addr, 0x34, 0x40, 16);
            assert_eq!(o.code, 0x25);
            assert_eq!(o.tables, vec![(addr as i64 + 0x28, addr as i64 + 0x34, "jumptable".to_string())]);
            assert_eq!(original(&env, addr, 0x25, 0x40, 16).code, 0x25);
            let (obj, k) = switch_ours();
            let code = obj.function_code(k);
            assert_eq!(code.code_len, Some(0x28));
            let (cd, cm) = code.code();
            let la = x86::strip_fill(x86::listing(cd, addr, Some(cm), env.range, env.fills));
            let lb = x86::strip_fill(x86::listing(&img.read(addr, o.code as usize), addr, None, env.range, env.fills));
            assert_eq!(texts(&la), texts(&lb));
            let t = compare_tables(&env, &obj, &code, addr, &la, &lb, &o.tables).unwrap();
            let v = verdict(&la, &lb, Some(&t));
            (t, v)
        };
        let (t, v) = check([0x10, 0x16, 0x1c]);
        assert_eq!((t.entries, t.bytes, t.diffs.len()), (3, 0, 0));
        assert!(v.shape && v.summary().contains("switch tables equal (3 entries, 0 index bytes)"));
        let (t, v) = check([0x16, 0x10, 0x1c]);
        assert_eq!(t.diffs.len(), 2);
        assert!(t.diffs[0].contains("entry +0x0: ours to +0x10, the original's to +0x16"));
        assert!(!v.shape && v.hunks == [("table".to_string(), 2)] && v.summary().contains("switch tables differ"));
        // a relocated field of ours reads X, as the image address of the original does
        let code = [0xa1u8, 0, 0, 0, 0, 0xe8, 0, 0, 0, 0, 0xc3];
        let mask = [0u8, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0];
        let range = (0x1000_0000i64, 0x1001_0000i64);
        let ours = x86::listing(&code, 0x1000_1000, Some(&mask), range, &fills);
        let orig = x86::listing(&[0xa1, 0x00, 0x20, 0x00, 0x10, 0xe8, 0x10, 0, 0, 0, 0xc3], 0x1000_1000, None, range, &fills);
        assert_eq!(texts(&ours), texts(&orig));
        assert_eq!(texts(&ours), ["mov eax, dword ptr [X]", "call X", "ret"]);
        // asmdiff --symbols: the same listing, each X spelled by the namer (the k-th masked field, an image number)
        let named = x86::listing_named(&code, 0x1000_1000, Some(&mask), range, &fills,
                                       &|ins, k, _| Some(format!("f{:x}k{}", ins & 0xff, k.map(|k| k as i64).unwrap_or(-1))));
        assert_eq!(texts(&named), ["mov eax, dword ptr [f0k0]", "call f5k0", "ret"]);
        let named = x86::listing_named(&[0xa1, 0x00, 0x20, 0x00, 0x10, 0xc3], 0x1000_1000, None, range, &fills,
                                       &|_, k, v| k.is_none().then(|| format!("{v:#x}")));
        assert_eq!(texts(&named), ["mov eax, dword ptr [0x10002000]", "ret"]);
    }
}
