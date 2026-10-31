//! match/diffclass.py: the instruction diff of one function and the classification of its hunks (its module
//! docstring is the criterion), with the walk of the original's slot that finds its switch tables (rules/walk.py's
//! Walker for one root, no stops, no relocation sites).

use crate::difflib::{opcodes, Tag};
use crate::x86::{self, py_hex, Line};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};

pub type Hunk = (usize, usize, usize, usize, String, String);

fn texts(l: &[Line]) -> Vec<String> {
    l.iter().map(|x| x.text.clone()).collect()
}

fn multiset_eq(a: &[String], b: &[String]) -> bool {
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

/// diffclass.join: differing opcodes joined into hunks when within 4 equal instructions of each other.
fn join(raw: impl IntoIterator<Item = (usize, usize, usize, usize)>) -> Vec<(usize, usize, usize, usize)> {
    let mut hs: Vec<(usize, usize, usize, usize)> = vec![];
    for (i1, i2, j1, j2) in raw {
        if let Some(h) = hs.last_mut() {
            if i1 as i64 - h.1 as i64 <= 4 && j1 as i64 - h.3 as i64 <= 4 {
                *h = (h.0, i2, h.2, j2);
                continue;
            }
        }
        hs.push((i1, i2, j1, j2));
    }
    hs
}

fn hunks(a: &[String], b: &[String]) -> Vec<(usize, usize, usize, usize)> {
    join(opcodes(a, b).into_iter().filter(|o| o.0 != Tag::Equal).map(|o| (o.1, o.2, o.3, o.4)))
}

fn classify(la: &[Line], lb: &[Line], at: &[String], i1: usize, i2: usize, j1: usize, j2: usize) -> (String, String) {
    let a = texts(&la[i1..i2]);
    let b = texts(&lb[j1..j2]);
    if la[i1..i2].iter().chain(&lb[j1..j2]).all(|x| x.fill) {
        return ("fill".into(), "alignment fill".into());
    }
    if multiset_eq(&a, &b) {
        return ("order".into(), "same instructions, other order".into());
    }
    x86::explain(&a, &b, at).unwrap_or(("code".into(), String::new()))
}

fn classify_hunks(la: &[Line], lb: &[Line]) -> Vec<Hunk> {
    let (a, b) = (texts(la), texts(lb));
    hunks(&a, &b).into_iter().map(|(i1, i2, j1, j2)| {
        let (c, n) = classify(la, lb, &a, i1, i2, j1, j2);
        (i1, i2, j1, j2, c, n)
    }).collect()
}

fn frame_hunks(la: &[Line], lb: &[Line], frame: (i64, i64)) -> Vec<Hunk> {
    let (a, b) = (texts(la), texts(lb));
    let (ma, mb) = (x86::stack_mask(&a, frame), x86::stack_mask(&b, frame));
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
        match x86::frame_explain(&a[i1..i2], &b[j1..j2], frame) {
            Some(note) => out.push((i1, i2, j1, j2, "frame".into(), note)),
            None => {
                let (c, n) = classify(la, lb, &a, i1, i2, j1, j2);
                out.push((i1, i2, j1, j2, c, n));
            }
        }
    }
    for (i1, i2, j1, j2) in join(other) {
        let (c, n) = classify(la, lb, &a, i1, i2, j1, j2);
        out.push((i1, i2, j1, j2, c, n));
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
}

impl Verdict {
    /// Verdict.summary (the classes by weight, ties by name).
    pub fn summary(&self) -> String {
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
        if !self.branches.is_empty() {
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

type Aligned = (Vec<(usize, usize)>, HashMap<usize, usize>, HashSet<(usize, usize)>);

fn aligned(la: &[Line], lb: &[Line], hs: &[Hunk]) -> Aligned {
    let (mut jumps, mut m, mut starts) = (vec![], HashMap::new(), HashSet::new());
    let (mut i, mut j) = (0usize, 0usize);
    let mut all: Vec<Hunk> = hs.to_vec();
    all.sort();
    all.push((la.len(), la.len(), lb.len(), lb.len(), String::new(), String::new()));
    for (i1, i2, j1, j2, cls, _) in all {
        let (di, dj) = (i1 as i64 - i as i64, j1 as i64 - j as i64);
        if di == dj && dj > 0 {
            for k in i..i1 {
                m.insert(k, j + k - i);
                if la[k].target.is_some() && lb[j + k - i].target.is_some() {
                    jumps.push((k, j + k - i));
                }
            }
        }
        if cls == "order" {
            let mut same: HashMap<&str, VecDeque<usize>> = HashMap::new();
            for k in j1..j2 {
                same.entry(&lb[k].text).or_default().push_back(k);
            }
            let mut rest = vec![];
            for k in i1..i2 {
                match same.get_mut(la[k].text.as_str()).and_then(|q| q.pop_front()) {
                    Some(x) => {
                        m.insert(k, x);
                    }
                    None => rest.push(k),
                }
            }
            let mut left: Vec<usize> = same.values().flat_map(|q| q.iter().copied()).collect();
            left.sort();
            for (k, x) in rest.into_iter().zip(left) {
                m.insert(k, x);
            }
            starts.insert((i1, j1));
        } else if i2 - i1 == j2 - j1 && cls != "fill" {
            for k in 0..i2 - i1 {
                m.insert(i1 + k, j1 + k);
            }
        }
        let mut theirs: HashMap<&str, VecDeque<usize>> = HashMap::new();
        for k in j1..j2 {
            if lb[k].target.is_some() {
                theirs.entry(&lb[k].text).or_default().push_back(k);
            }
        }
        for k in i1..i2 {
            if la[k].target.is_some() {
                if let Some(x) = theirs.get_mut(la[k].text.as_str()).and_then(|q| q.pop_front()) {
                    jumps.push((k, x));
                }
            }
        }
        i = i.max(i2);
        j = j.max(j2);
    }
    (jumps, m, starts)
}

struct Pos {
    a: HashMap<i64, usize>,
    b: HashMap<i64, usize>,
}

fn follow(l: &[Line], pos: &HashMap<i64, usize>, mut i: Option<usize>) -> Option<usize> {
    for _ in 0..8 {
        let Some(k) = i else { break };
        if k >= l.len() || l[k].target.is_none() || mnemonic(&l[k].text) != "jmp" {
            break;
        }
        i = pos.get(&l[k].target.unwrap()).copied();
    }
    i.filter(|&k| k < l.len())
}

#[allow(clippy::too_many_arguments)]
fn same_code(la: &[Line], lb: &[Line], ia: usize, ib: usize, m: &HashMap<usize, usize>, starts: &HashSet<(usize, usize)>,
             pos: &Pos, depth: u32, steps: u32) -> bool {
    let (mut ia, mut ib) = (Some(ia), Some(ib));
    for _ in 0..steps {
        ia = follow(la, &pos.a, ia);
        ib = follow(lb, &pos.b, ib);
        let (Some(x), Some(y)) = (ia, ib) else { return false };
        if m.get(&x) == Some(&y) || starts.contains(&(x, y)) {
            return true;
        }
        if la[x].text != lb[y].text {
            return false;
        }
        let mn = mnemonic(&la[x].text);
        if mn == "ret" || mn == "jmp" {
            return true;
        }
        if la[x].target.is_some() || lb[y].target.is_some() {
            let ja = la[x].target.and_then(|t| pos.a.get(&t).copied());
            let jb = lb[y].target.and_then(|t| pos.b.get(&t).copied());
            match (ja, jb) {
                (Some(ja), Some(jb)) if depth > 0 && same_code(la, lb, ja, jb, m, starts, pos, depth - 1, steps) => {}
                _ => return false,
            }
        }
        ia = Some(x + 1);
        ib = Some(y + 1);
    }
    false
}

fn positions(l: &[Line]) -> HashMap<i64, usize> {
    l.iter().enumerate().map(|(i, x)| (x.addr as i64, i)).collect()
}

fn branch_diffs(la: &[Line], lb: &[Line], hs: &[Hunk]) -> Vec<String> {
    if la.is_empty() || lb.is_empty() {
        return vec![];
    }
    let (jumps, m, starts) = aligned(la, lb, hs);
    let pos = Pos { a: positions(la), b: positions(lb) };
    let base = la[0].addr as i64;
    let place = |t: i64, p: &HashMap<i64, usize>| if p.contains_key(&t) { format!("+{}", py_hex(t - base)) } else { "outside the code".to_string() };
    let mut out = vec![];
    for (i, j) in jumps {
        let (ta, tb) = (la[i].target.unwrap(), lb[j].target.unwrap());
        let (ia, ib) = (pos.a.get(&ta).copied(), pos.b.get(&tb).copied());
        if ia.is_none() && ib.is_none() {
            continue;
        }
        if let (Some(x), Some(y)) = (ia, ib) {
            if same_code(la, lb, x, y, &m, &starts, &pos, 4, 24) {
                continue;
            }
        }
        out.push(format!("{} at +{}: ours to {}, the original's to {}", mnemonic(&la[i].text), py_hex(la[i].addr as i64 - base),
                         place(ta, &pos.a), place(tb, &pos.b)));
    }
    out
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
    let moved = !code.is_empty() && multiset_eq(&minus, &plus);
    let renamed = !code.is_empty() && !moved && x86::one_renaming(&a, &b);
    let bad = tables.is_some_and(|t| !t.diffs.is_empty());
    if bad {
        bump(&mut weight, "table", tables.unwrap().diffs.len() as i64);
    }
    let branches = branch_diffs(la, lb, hs);
    if !branches.is_empty() {
        bump(&mut weight, "branch", branches.len() as i64);
    }
    let shape = (code.is_empty() || moved || renamed) && !bad && branches.is_empty();
    code.truncate(6);
    Verdict { shape, hunks: weight, moved, renamed, code, distance: distance(&a, &b), tables: tables.cloned(), frame: None,
              branches: branches.into_iter().take(12).collect() }
}

/// diffclass.verdict: the plain diff's, or the frame-aligned one's when the frames differ and the plain one is no shape.
pub fn verdict(la: &[Line], lb: &[Line], tables: Option<&Tables>) -> Verdict {
    analyse(la, lb, tables).1
}

/// diffclass.analyse: (the hunks, the verdict) of two listings: the plain diff, or the frame-aligned one when the
/// frames differ in size and the plain diff is no shape.
pub fn analyse(la: &[Line], lb: &[Line], tables: Option<&Tables>) -> (Vec<Hunk>, Verdict) {
    let hs = classify_hunks(la, lb);
    let v = judge(la, lb, &hs, tables);
    if v.shape {
        return (hs, v);
    }
    let Some(frame) = x86::frame_delta(&texts(la), &texts(lb)) else { return (hs, v) };
    let fh = frame_hunks(la, lb, frame);
    let mut fv = judge(la, lb, &fh, tables);
    fv.frame = Some(frame);
    (fh, fv)
}

// ------------------------------------------------------------------------------------------------ sizes, the original

pub struct Env<'a> {
    pub dll: &'a str,
    pub img: &'a crate::pe::Image,
    pub range: (i64, i64),
    pub fills: &'a HashSet<Vec<u8>>,
    pub forms: &'a [Vec<u8>], // fill_order
}

/// diffclass.code_size: the end of our last instruction that is no fill.
pub fn code_size(env: &Env, code: &[u8], mask: &[u8], addr: u32) -> Result<i64, String> {
    let lines = x86::strip_fill(x86::listing(env.dll, code, addr, Some(mask), env.range, env.fills)?);
    Ok(match lines.last() {
        Some(l) => (l.addr + l.size) as i64 - addr as i64,
        None => code.len() as i64,
    })
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

    fn fill_to(&mut self, a: i64, t: i64) -> Result<bool, String> {
        if t <= a || t % self.align != 0 {
            return Ok(false);
        }
        let mut cur = a;
        while self.in_code(cur) {
            let Some(ins) = self.dec.at(cur as u32)?.cloned() else { return Ok(false) };
            if ins.addr as i64 >= t {
                return Ok(ins.addr as i64 == t);
            }
            if !ins.fill {
                return Ok(false);
            }
            cur = (ins.addr + ins.size) as i64;
        }
        Ok(false)
    }

    fn walk_root(&mut self, root: i64) -> Result<(), String> {
        let lo = self.dec.lo as i64;
        let mut work = vec![root];
        while let Some(start) = work.pop() {
            if !self.in_code(start) || self.kind[(start - lo) as usize] == 1 {
                continue;
            }
            let mut recent: Vec<x86::WIns> = vec![];
            let mut cur = start;
            while self.in_code(cur) {
                let Some(ins) = self.dec.at(cur as u32)?.cloned() else { break };
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
                        if self.in_code(t) && !(ins.flow == x86::JUMP && self.fill_to(ia + size, t)?) {
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
        Ok(())
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
pub fn original(env: &Env, addr: u32, extent: i64, slot: i64, align: i64) -> Result<Original, String> {
    let a = addr as i64;
    let hi = a + slot.max(extent);
    let mut tables = vec![];
    if hi > a {
        let mut w = Walk { dec: x86::Decoder::new(env.dll, env.img, addr, hi as u32, env.fills), kind: vec![0; (hi - a) as usize],
                           align: align.max(1), tables: vec![] };
        w.walk_root(a)?;
        let set: HashSet<(i64, i64, String)> = w.tables.into_iter().collect();
        tables = set.into_iter().collect();
        tables.sort();
    }
    let inside: Vec<i64> = tables.iter().map(|t| t.0).filter(|&lo| a < lo && lo < a + extent).collect();
    let Some(&end) = inside.iter().min() else { return Ok(Original { code: extent, tables }) };
    let data = env.img.read(addr, (end - a) as usize);
    let lines = x86::strip_fill(x86::listing(env.dll, &data, addr, None, env.range, env.fills)?);
    let code = match lines.last() {
        Some(l) => (l.addr + l.size) as i64 - a,
        None => end - a,
    };
    Ok(Original { code, tables })
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

/// diffclass.compare_function + verdict: our function against the original at addr, given the Original.
pub fn function_verdict(env: &Env, obj: &crate::coff::Obj, code: &crate::coff::FunctionCode, addr: u32, o: &Original)
                        -> Result<Verdict, String> {
    let (cd, cm) = code.code();
    let la = x86::strip_fill(x86::listing(env.dll, cd, addr, Some(cm), env.range, env.fills)?);
    let data = env.img.read(addr, o.code.max(0) as usize);
    let lb = x86::strip_fill(x86::listing(env.dll, &data, addr, None, env.range, env.fills)?);
    let t = compare_tables(env, obj, code, addr, &la, &lb, &o.tables);
    Ok(verdict(&la, &lb, t.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::testpe::{build_with, BASE, TEXT};

    fn lines(texts: &[&str]) -> Vec<Line> {
        texts.iter().enumerate().map(|(k, t)| Line { addr: 0x1000 + k as u32, size: 1, text: t.to_string(), fill: *t == "nop" || *t == "int3", target: None }).collect()
    }

    fn classes(a: &[Line], b: &[Line]) -> Vec<String> {
        classify_hunks(a, b).into_iter().map(|h| h.4).collect()
    }

    fn weight(v: &Verdict, k: &str) -> Option<i64> {
        v.hunks.iter().find(|x| x.0 == k).map(|x| x.1)
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
        assert!(hs[0].5.contains("shifted by 0x4 (frame 0xcc vs 0xc8)") && v.summary().contains("frame 0xcc vs 0xc8"));
        let (hs, v) = analyse(&a, &f("0xc8", "0xcc", "0x78", "mov dword ptr [esp + 0x14], 0"), None);
        assert!(!v.shape);
        assert_eq!(hs.iter().filter(|h| h.4 == "code").map(|h| (h.0, h.1)).collect::<Vec<_>>(), [(8, 9)]);
        let (hs, v) = analyse(&a, &f("0xc8", "0xc4", "0x78", st), None);
        assert!(!v.shape && hs.iter().any(|h| h.4 == "code"));
        let (_, v) = analyse(&f("0xcc", "0xd0", "0x7c", st), &f("0xcc", "0xd4", "0x7c", st), None);
        assert!(v.frame.is_none());
    }

    fn jumps(rows: &[(&str, Option<u32>)]) -> Vec<Line> {
        rows.iter().enumerate().map(|(k, (t, g))| Line { addr: 0x1000 + k as u32, size: 1, text: t.to_string(), fill: false,
                                                         target: g.map(|g| 0x1000 + g as i64) }).collect()
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
        assert!(!v.shape && v.hunks == [("branch".to_string(), 1)] && v.branches[0].contains("je at +0x1: ours to +0x4, the original's to +0x2"));
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
        let dll = crate::walk::tests::capstone();
        let addr = BASE + TEXT;
        let fills: HashSet<Vec<u8>> = [vec![0x90u8], vec![0xcc]].into_iter().collect();
        let forms = vec![vec![0x90u8], vec![0xcc]];
        let check = |entries: [u32; 3]| {
            let img = crate::pe::Image::parse(build_with(None, Some(&switch_fn(addr, entries)))).unwrap();
            let env = Env { dll: &dll, img: &img, range: (img.base as i64, img.end() as i64), fills: &fills, forms: &forms };
            let o = original(&env, addr, 0x34, 0x40, 16).unwrap();
            assert_eq!(o.code, 0x25);
            assert_eq!(o.tables, vec![(addr as i64 + 0x28, addr as i64 + 0x34, "jumptable".to_string())]);
            assert_eq!(original(&env, addr, 0x25, 0x40, 16).unwrap().code, 0x25);
            let (obj, k) = switch_ours();
            let code = obj.function_code(k);
            assert_eq!(code.code_len, Some(0x28));
            let (cd, cm) = code.code();
            let la = x86::strip_fill(x86::listing(env.dll, cd, addr, Some(cm), env.range, env.fills).unwrap());
            let lb = x86::strip_fill(x86::listing(env.dll, &img.read(addr, o.code as usize), addr, None, env.range, env.fills).unwrap());
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
        let ours = x86::listing(&dll, &code, 0x1000_1000, Some(&mask), range, &fills).unwrap();
        let orig = x86::listing(&dll, &[0xa1, 0x00, 0x20, 0x00, 0x10, 0xe8, 0x10, 0, 0, 0, 0xc3], 0x1000_1000, None, range, &fills).unwrap();
        assert_eq!(texts(&ours), texts(&orig));
        assert_eq!(texts(&ours), ["mov eax, dword ptr [X]", "call X", "ret"]);
        // asmdiff --symbols: the same listing, each X spelled by the namer (the k-th masked field, an image number)
        let named = x86::listing_named(&dll, &code, 0x1000_1000, Some(&mask), range, &fills,
                                       &|ins, k, _| Some(format!("f{:x}k{}", ins & 0xff, k.map(|k| k as i64).unwrap_or(-1)))).unwrap();
        assert_eq!(texts(&named), ["mov eax, dword ptr [f0k0]", "call f5k0", "ret"]);
        let named = x86::listing_named(&dll, &[0xa1, 0x00, 0x20, 0x00, 0x10, 0xc3], 0x1000_1000, None, range, &fills,
                                       &|_, k, v| k.is_none().then(|| format!("{v:#x}"))).unwrap();
        assert_eq!(texts(&named), ["mov eax, dword ptr [0x10002000]", "ret"]);
    }
}
