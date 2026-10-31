//! isa/x86.py's instruction diff side: the normalised listing (Isa.listing), the explanations of a differing
//! hunk (explain, frame_delta, stack_mask, frame_explain, one_renaming), and the decoder the walk of an
//! original's slot reads (X86Decoder, from capstone's text: the flow by mnemonic, as capstone's groups give it).

use regex::{Captures, Regex};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

pub const M32: u64 = 0xffff_ffff;

/// One instruction of a listing (isa/base.Line).
#[derive(Clone, Debug)]
pub struct Line {
    pub addr: u32,
    pub size: u32,
    pub text: String,
    pub fill: bool,
    pub target: Option<i64>,
}

macro_rules! re {
    ($name:ident, $pat:expr) => {
        fn $name() -> &'static Regex {
            static R: OnceLock<Regex> = OnceLock::new();
            R.get_or_init(|| Regex::new($pat).unwrap())
        }
    };
}

const NUM: &str = r"(?:0x[0-9a-f]+|\d+)";
re!(number_re, r"^(?:0x[0-9a-f]+|[0-9]+)$");
re!(hexnum_re, r"0x[0-9a-f]+");
re!(space_re, r"\s+");
re!(reg_re, r"\b(e[abcd]x|e[sd]i|ebp|[abcd][xlh]|[sd]i|bp)\b");
fn slot_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(&format!(r"\[(esp|ebp)((?: [+-] {NUM})?)\]")).unwrap())
}
fn sib_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(&format!(r"\[(e[abcd]x|e[sd]i|ebp) \+ (e[abcd]x|e[sd]i|ebp)((?: [+-] {NUM})?)\]")).unwrap())
}
fn token_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(&format!(r"\[(?:esp|ebp)(?: [+-] {NUM})?\]|\b(?:e[abcd]x|e[sd]i|ebp|[abcd][xlh]|[sd]i|bp)\b")).unwrap())
}
fn esp_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(&format!(r"\[esp((?: [+-] {NUM})?)\]")).unwrap())
}
fn esp_adj() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(&format!(r"^(sub|add) esp, ({NUM})$")).unwrap())
}
re!(st_re, r"st\(\d\)");
fn rslot_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(&format!(r"\[(esp|R)((?: [+-] {NUM})?)\]")).unwrap())
}

// What a renaming cannot change, for pruning the searches (a renaming exists only when these agree): the texts
// with every register name masked (renaming registers keeps a register token a register token), with every
// stack slot's offset masked (renaming slots changes offsets only), and both.
fn t_reg(lines: &[String]) -> Vec<String> {
    lines.iter().map(|t| reg_re().replace_all(t, "R").into_owned()).collect()
}

fn t_slot(lines: &[String]) -> Vec<String> {
    lines.iter().map(|t| slot_re().replace_all(t, "[$1 S]").into_owned()).collect()
}

fn t_both(lines: &[String]) -> Vec<String> {
    t_reg(lines).iter().map(|t| rslot_re().replace_all(t, "[$1 S]").into_owned()).collect()
}

/// int(s, 0) of the numbers capstone and the listing write (an optional sign, 0x hex or decimal).
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

/// X86.listing: capstone's Intel text, spaces normalised; masked fields hold the image's first address, every
/// number inside the image (and a masked field's value) reads X; a jump with an immediate target outside the
/// masked fields keeps the target.
pub fn listing(dll: &str, code: &[u8], va: u32, mask: Option<&[u8]>, range: (i64, i64), fills: &HashSet<Vec<u8>>)
               -> Result<Vec<Line>, String> {
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
    for ins in crate::cs::disasm(dll, &data, va)? {
        let (a, size) = (ins.addr, ins.size);
        let raw = if ins.op_str.is_empty() { ins.mnemonic.clone() } else { format!("{} {}", ins.mnemonic, ins.op_str).trim().to_string() };
        let text = space_re().replace_all(&raw, " ").into_owned();
        let o = (a - va) as usize;
        let mut masked: Vec<u64> = vec![];
        for &(s, e) in &runs {
            if s < o + size as usize && o < e {
                masked.push(lo as u64);
                masked.push((a as u64 + size as u64 + lo as u64) & M32);
            }
        }
        let mn = &ins.mnemonic;
        let target = if masked.is_empty() && (mn.starts_with('j') || mn.starts_with("loop")) && number_re().is_match(&ins.op_str) {
            Some(py_int0(&ins.op_str))
        } else {
            None
        };
        let text = hexnum_re().replace_all(&text, |c: &Captures| {
            let s = &c[0];
            let v = u128::from_str_radix(&s[2..], 16).unwrap_or(u128::MAX);
            if masked.iter().any(|&m| m as u128 == v) || (lo as i128 <= v as i128 && (v as i128) < hi as i128) { "X".to_string() } else { s.to_string() }
        }).into_owned();
        let bytes = &code[o.min(code.len())..(o + size as usize).min(code.len())];
        out.push(Line { addr: a, size, text, fill: fills.contains(bytes), target });
    }
    Ok(out)
}

/// diffclass.strip_fill: the listing without its trailing fill.
pub fn strip_fill(mut lines: Vec<Line>) -> Vec<Line> {
    while lines.last().is_some_and(|l| l.fill) {
        lines.pop();
    }
    lines
}

// ------------------------------------------------------------------------------------------------ explanations

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

fn rename_slots(lines: &[String], mapping: &Mapping) -> Vec<String> {
    let get = |k: &str| mapping.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone()).unwrap_or_else(|| k.to_string());
    lines.iter().map(|t| slot_re().replace_all(t, |c: &Captures| format!("[{}{}]", &c[1], get(&c[2]))).into_owned()).collect()
}

/// itertools.permutations(range(n)) in its order (lexicographic in the positions).
fn permutations(n: usize, mut f: impl FnMut(&[usize]) -> bool) {
    let mut p: Vec<usize> = (0..n).collect();
    loop {
        if f(&p) {
            return;
        }
        // next permutation
        let Some(i) = (0..n.saturating_sub(1)).rev().find(|&i| p[i] < p[i + 1]) else { return };
        let j = (i + 1..n).rev().find(|&j| p[j] > p[i]).unwrap();
        p.swap(i, j);
        p[i + 1..].reverse();
    }
}

fn mapping_of(toks: &[String], perm: &[usize]) -> Mapping {
    toks.iter().zip(perm.iter()).filter(|(k, v)| **k != toks[**v]).map(|(k, v)| (k.clone(), toks[*v].clone())).collect()
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

fn sorted_set(items: impl Iterator<Item = String>) -> Vec<String> {
    let mut v: Vec<String> = items.collect::<HashSet<_>>().into_iter().collect();
    v.sort();
    v
}

fn find_map_regs(xa: &[String], sa: &[Sited], xb: &[String], gpr: &[&str]) -> Option<Mapping> {
    if xa.len() != xb.len() || t_reg(xa) != t_reg(xb) {
        return None;
    }
    // equal outside the registers: a renaming makes the lines equal when it maps every token to the other's
    let tb: Vec<Vec<&str>> = xb.iter().map(|t| reg_re().find_iter(t).map(|m| m.as_str()).collect()).collect();
    let toks: Vec<String> = sorted_set(xa.iter().chain(xb).flat_map(|t| reg_re().captures_iter(t).map(|c| full_reg(&c[1])).collect::<Vec<_>>()))
        .into_iter().filter(|t| gpr.contains(&t.as_str())).collect();
    if toks.len() > 6 {
        return None;
    }
    let mut found = None;
    permutations(toks.len(), |perm| {
        let m = mapping_of(&toks, perm);
        if m.is_empty() {
            return false;
        }
        let sub = sub_table(&m);
        let ok = sa.iter().zip(&tb).all(|(l, b)| {
            l.regs.iter().zip(b).all(|(&(s, e), tb)| {
                let tok = &l.text[s..e];
                sub.get(tok).copied().unwrap_or(tok) == *tb
            })
        });
        if ok {
            found = Some(m);
            return true;
        }
        false
    });
    found
}

fn find_map_slots(xa: &[String], xb: &[String], limit: usize) -> Option<Mapping> {
    if xa.len() != xb.len() || t_slot(xa) != t_slot(xb) {
        return None;
    }
    let toks = sorted_set(xa.iter().chain(xb).flat_map(|t| slot_re().captures_iter(t).map(|c| c[2].to_string()).collect::<Vec<_>>()));
    if toks.len() > limit {
        return None;
    }
    let mut found = None;
    permutations(toks.len(), |perm| {
        let m = mapping_of(&toks, perm);
        if !m.is_empty() && rename_slots(xa, &m) == xb {
            found = Some(m);
            return true;
        }
        false
    });
    found
}

fn slot_desc(m: &Mapping) -> String {
    let or0 = |s: &str| if s.is_empty() { "+0".to_string() } else { s.to_string() };
    m.iter().map(|(k, v)| format!("[{}]->[{}]", or0(k), or0(v))).collect::<Vec<_>>().join(" ")
}

fn reg_desc(m: &Mapping) -> String {
    m.iter().map(|(k, v)| format!("{k}->{v}")).collect::<Vec<_>>().join(" ")
}

fn mnemonic(t: &str) -> &str {
    t.split(' ').next().unwrap_or("")
}

fn esp_normalised(lines: &[String]) -> Vec<String> {
    let mut out = vec![];
    let mut delta: i64 = 0;
    for t in lines {
        let d = delta;
        out.push(esp_re().replace_all(t, |c: &Captures| {
            let v = if c[1].is_empty() { 0 } else { py_int0(&c[1].replace(' ', "")) } - d;
            if v == 0 { "[esp]".to_string() } else if v > 0 { format!("[esp + {}]", py_hex(v)) } else { format!("[esp - {}]", py_hex(-v)) }
        }).into_owned());
        let mn = mnemonic(t);
        if mn == "push" || mn == "pushfd" {
            delta += 4;
        } else if mn == "pop" || mn == "popfd" {
            delta -= 4;
        } else if let Some(a) = esp_adj().captures(t) {
            delta += py_int0(&a[2]) * if &a[1] == "sub" { 1 } else { -1 };
        }
    }
    out
}

fn swap_sib(t: &str) -> String {
    sib_re().replace_all(t, |c: &Captures| format!("[{} + {}{}]", &c[2], &c[1], c.get(3).map(|m| m.as_str()).unwrap_or(""))).into_owned()
}

fn sib_explain(xa: &[String], xb: &[String]) -> Option<String> {
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
    if changed { Some("base/index swapped in [r1 + r2 + disp]".to_string()) } else { None }
}

fn gpr_for(a: &[String]) -> Vec<&'static str> {
    if a.iter().take(4).any(|t| t == "mov ebp, esp") {
        GPR_ALL.iter().copied().filter(|r| *r != "ebp").collect()
    } else {
        GPR_ALL.to_vec()
    }
}

/// X86.explain: (class, note) of one differing hunk, None when nothing explains it.
pub fn explain(xa: &[String], xb: &[String], context: &[String]) -> Option<(String, String)> {
    let gpr = gpr_for(context);
    let sa = sited(xa);
    if let Some(m) = find_map_regs(xa, &sa, xb, &gpr) {
        return Some(("regs".into(), reg_desc(&m)));
    }
    let toks: Vec<String> = sorted_set(xa.iter().chain(xb).flat_map(|t| reg_re().captures_iter(t).map(|c| full_reg(&c[1])).collect::<Vec<_>>()))
        .into_iter().filter(|t| gpr.contains(&t.as_str())).collect();
    if xa.len() == xb.len() && toks.len() <= 6 {
        let mut got = None;
        let both = t_both(xa) == t_both(xb);
        permutations(if both { toks.len() } else { 0 }, |perm| {
            if !both {
                return true;
            }
            let rm = mapping_of(&toks, perm);
            let ra = if rm.is_empty() { xa.to_vec() } else { rename_regs(&sa, &rm) };
            if let Some(sm) = find_map_slots(&ra, xb, 5) {
                let desc = reg_desc(&rm);
                got = Some(("slots".to_string(), format!("{}{}", if desc.is_empty() { String::new() } else { desc + " " }, slot_desc(&sm))));
                return true;
            }
            false
        });
        if got.is_some() {
            return got;
        }
        let same_shape = multiset_eq(&t_reg(xa), &t_reg(xb));
        permutations(if same_shape { toks.len() } else { 0 }, |perm| {
            if !same_shape {
                return true;
            }
            let rm = mapping_of(&toks, perm);
            if !rm.is_empty() && multiset_eq(&rename_regs(&sa, &rm), xb) {
                got = Some(("order".to_string(), format!("same instructions, other order, after {}", reg_desc(&rm))));
                return true;
            }
            false
        });
        if got.is_some() {
            return got;
        }
    }
    if xa.len() == xb.len() && xa.iter().chain(xb).any(|t| matches!(mnemonic(t), "push" | "pop") || esp_adj().is_match(t)) {
        let (na, nb) = (esp_normalised(xa), esp_normalised(xb));
        if multiset_eq(&na, &nb) {
            return Some(("order".into(), "same instructions, other order across a push / pop (esp offsets taken at the hunk's start)".into()));
        }
        let slots = sorted_set(na.iter().chain(&nb).flat_map(|t| slot_re().captures_iter(t).filter(|c| &c[1] == "esp").map(|c| c[2].to_string()).collect::<Vec<_>>()));
        if slots.len() <= 5 && multiset_eq(&t_slot(&na), &t_slot(&nb)) {
            let mut got = None;
            permutations(slots.len(), |perm| {
                let sm = mapping_of(&slots, perm);
                if !sm.is_empty() && multiset_eq(&rename_slots(&na, &sm), &nb) {
                    got = Some(("slots".to_string(), format!("other order across a push / pop (esp offsets taken at the hunk's start), {}", slot_desc(&sm))));
                    return true;
                }
                false
            });
            if got.is_some() {
                return got;
            }
        }
    }
    if let Some(s) = sib_explain(xa, xb) {
        return Some(("sib".into(), s));
    }
    let (sa, sb): (HashSet<&String>, HashSet<&String>) = (xa.iter().collect(), xb.iter().collect());
    if sa.symmetric_difference(&sb).all(|t| t.starts_with('f')) {
        let norm = |ls: &[String]| {
            let mut v: Vec<String> = ls.iter().map(|t| st_re().replace_all(t, "st(N)").into_owned()).collect();
            v.sort();
            v
        };
        return Some(("fpu".into(), if norm(xa) == norm(xb) { "same FPU instructions, other stack order" } else { "FPU instructions differ" }.into()));
    }
    None
}

fn frame_size(lines: &[String]) -> Option<i64> {
    for t in lines.iter().take(8) {
        if let Some(m) = esp_adj().captures(t) {
            if &m[1] == "sub" {
                return Some(py_int0(&m[2]));
            }
        }
    }
    None
}

/// X86.frame_delta: (our frame size, the original's) when both allocate one and the sizes differ.
pub fn frame_delta(a: &[String], b: &[String]) -> Option<(i64, i64)> {
    match (frame_size(a), frame_size(b)) {
        (Some(fa), Some(fb)) if fa != fb => Some((fa, fb)),
        _ => None,
    }
}

/// X86.stack_mask: every stack operand reads `[esp S]` / `[ebp S]`, a frame-size adjustment `sub|add esp, F`.
pub fn stack_mask(lines: &[String], frame: (i64, i64)) -> Vec<String> {
    lines.iter().map(|t| {
        if let Some(m) = esp_adj().captures(t) {
            let v = py_int0(&m[2]);
            if v == frame.0 || v == frame.1 {
                return format!("{} esp, F", &m[1]);
            }
        }
        slot_re().replace_all(t, |c: &Captures| format!("[{} S]", &c[1])).into_owned()
    }).collect()
}

fn slot_value(c: &Captures) -> i64 {
    let s = c[2].replace(' ', "");
    if s.is_empty() { 0 } else { py_int0(&s) }
}

/// X86.frame_explain: the note of a `frame` hunk, None when the lines differ in more than the frame delta.
pub fn frame_explain(xa: &[String], xb: &[String], frame: (i64, i64)) -> Option<String> {
    if xa.len() != xb.len() || stack_mask(xa, frame) != stack_mask(xb, frame) {
        return None;
    }
    let d = frame.0 - frame.1;
    for (x, y) in xa.iter().zip(xb) {
        if x == y {
            continue;
        }
        if let (Some(ma), Some(mb)) = (esp_adj().captures(x), esp_adj().captures(y)) {
            if py_int0(&ma[2]) - py_int0(&mb[2]) != d {
                return None;
            }
            continue;
        }
        let oa: Vec<i64> = slot_re().captures_iter(x).map(|c| slot_value(&c)).collect();
        let ob: Vec<i64> = slot_re().captures_iter(y).map(|c| slot_value(&c)).collect();
        if oa.len() != ob.len() || oa.iter().zip(&ob).any(|(p, q)| { let e = (p - q).abs(); e != 0 && e != d.abs() }) {
            return None;
        }
    }
    let sign = if d < 0 { "-" } else { "" };
    Some(format!("stack offsets shifted by {sign}{} (frame {} vs {})", py_hex(d.abs()), py_hex(frame.0), py_hex(frame.1)))
}

/// X86.one_renaming: the whole function equal under one bijective renaming of registers and stack slots.
pub fn one_renaming(a: &[String], b: &[String]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut fwd: HashMap<String, String> = HashMap::new();
    let mut back: HashMap<String, String> = HashMap::new();
    for (x, y) in a.iter().zip(b) {
        let ta: Vec<&str> = token_re().find_iter(x).map(|m| m.as_str()).collect();
        let tb: Vec<&str> = token_re().find_iter(y).map(|m| m.as_str()).collect();
        if ta.len() != tb.len() || token_re().replace_all(x, "T") != token_re().replace_all(y, "T") {
            return false;
        }
        for (p, q) in ta.iter().zip(&tb) {
            let p = if p.starts_with('[') { p.to_string() } else { full_reg(p) };
            let q = if q.starts_with('[') { q.to_string() } else { full_reg(q) };
            if *fwd.entry(p.clone()).or_insert_with(|| q.clone()) != q || *back.entry(q.clone()).or_insert_with(|| p.clone()) != p {
                return false;
            }
        }
    }
    true
}

// ------------------------------------------------------------------------------------------------ the walk's decoder

pub const OTHER: u8 = 0;
pub const CALL: u8 = 1;
pub const JUMP: u8 = 2;
pub const CJUMP: u8 = 3;
pub const IJUMP: u8 = 4;
pub const RET: u8 = 5;

/// isa/base.Ins, the fields the walk of an original's slot reads.
#[derive(Clone)]
pub struct WIns {
    pub addr: u32,
    pub size: u32,
    pub mn: String,
    pub ops: String,
    pub flow: u8,
    pub target: Option<i64>,
    pub table: Option<u32>,
    pub fill: bool,
}

/// capstone's group of a mnemonic (a `bnd` / `notrack` / `repz` prefix keeps it): 1 call, 2 jump, 3 ret, 0 none.
fn group(mn: &str) -> u8 {
    let last = mn.rsplit(' ').next().unwrap_or(mn);
    match last {
        "call" | "lcall" => 1,
        "ret" | "retf" => 3,
        "ljmp" | "xbegin" => 2,
        _ if last.starts_with('j') => 2,
        _ => 0,
    }
}

/// A memory operand's text `size ptr seg:[base + index*scale + disp]`: (size, base, index, scale, disp & M32).
pub struct Mem {
    pub size: u32,
    pub base: bool,
    pub index: bool,
    pub scale: u32,
    pub disp: u64,
}

pub fn parse_mem(op: &str) -> Option<Mem> {
    let open = op.find('[')?;
    let close = op.rfind(']')?;
    let size = match op[..open].split(' ').next().unwrap_or("") {
        "byte" => 1,
        "word" => 2,
        "dword" => 4,
        "qword" => 8,
        "tbyte" => 10,
        "xmmword" => 16,
        _ => 0,
    };
    let inner = &op[open + 1..close];
    let (mut base, mut index, mut scale, mut disp) = (false, false, 1u32, 0i64);
    let mut sign = 1i64;
    for tok in inner.split(' ') {
        match tok {
            "+" => sign = 1,
            "-" => sign = -1,
            "" => {}
            t if t.starts_with("0x") || t.chars().all(|c| c.is_ascii_digit()) => disp += sign * py_int0(t),
            t if t.contains('*') => {
                index = true;
                scale = t.split('*').nth(1).and_then(|s| s.parse().ok()).unwrap_or(1);
            }
            _ => base = true,
        }
    }
    Some(Mem { size, base, index, scale, disp: (disp as u64) & M32 })
}

/// X86Decoder over [lo, hi) of an image: the instruction at an address (memoised for one walk).
pub struct Decoder<'a> {
    pub dll: &'a str,
    pub lo: u32,
    pub hi: u32,
    pub code: Vec<u8>,
    pub fills: &'a HashSet<Vec<u8>>,
    cache: HashMap<u32, Option<WIns>>,
}

impl<'a> Decoder<'a> {
    pub fn new(dll: &'a str, img: &crate::pe::Image, lo: u32, hi: u32, fills: &'a HashSet<Vec<u8>>) -> Decoder<'a> {
        Decoder { dll, lo, hi, code: img.read(lo, (hi - lo) as usize), fills, cache: HashMap::new() }
    }

    pub fn at(&mut self, a: u32) -> Result<Option<WIns>, String> {
        if !(self.lo <= a && a < self.hi) {
            return Ok(None);
        }
        if let Some(x) = self.cache.get(&a) {
            return Ok(x.clone());
        }
        let o = (a - self.lo) as usize;
        let got = crate::cs::first(self.dll, &self.code[o..], a)?.map(|ins| {
            let g = group(&ins.mnemonic);
            let target = if g == 1 || g == 2 {
                if number_re().is_match(&ins.op_str) {
                    Some(py_int0(&ins.op_str))
                } else {
                    // the first operand when it is an immediate (capstone's operand details)
                    let first = ins.op_str.split(", ").next().unwrap_or("");
                    if number_re().is_match(first) { Some(py_int0(first)) } else { None }
                }
            } else {
                None
            };
            let flow = match g {
                1 => CALL,
                2 => match target {
                    None => IJUMP,
                    Some(_) if ins.mnemonic == "jmp" => JUMP,
                    Some(_) => CJUMP,
                },
                3 => RET,
                _ => OTHER,
            };
            let mut table = None;
            if ins.mnemonic == "jmp" {
                if let Some(m) = parse_mem(&ins.op_str) {
                    if !m.base && m.index && m.scale == 4 {
                        table = Some(m.disp as u32);
                    }
                }
            }
            let bytes = &self.code[o..o + ins.size as usize];
            WIns { addr: ins.addr, size: ins.size, mn: ins.mnemonic, ops: ins.op_str, flow, target, table, fill: self.fills.contains(bytes) }
        });
        self.cache.insert(a, got.clone());
        Ok(got)
    }

    /// X86Decoder.table_shape: (bound, byte index table) from the instructions before the jump.
    pub fn table_shape(&self, recent: &[WIns]) -> (Option<i64>, Option<u32>) {
        let (mut bound, mut byte_tbl) = (None, None);
        for r in recent[..recent.len() - 1].iter().rev() {
            if !matches!(r.mn.as_str(), "cmp" | "movzx" | "mov") {
                continue;
            }
            let ops: Vec<&str> = r.ops.split(", ").collect();
            if ops.len() != 2 {
                continue;
            }
            if r.mn == "cmp" && bound.is_none() && is_reg(ops[0]) && is_imm(ops[1]) {
                let v = py_int0(ops[1]);
                if (0..0x400).contains(&v) {
                    bound = Some(v + 1);
                }
            }
            if (r.mn == "movzx" || r.mn == "mov") && byte_tbl.is_none() {
                if let Some(m) = parse_mem(ops[1]) {
                    if m.size == 1 && (m.index || m.base) && self.lo as u64 <= m.disp && m.disp < self.hi as u64 {
                        byte_tbl = Some(m.disp as u32);
                    }
                }
            }
        }
        (bound, byte_tbl)
    }

    pub fn read_entry(&self, a: u32) -> u32 {
        let o = (a - self.lo) as usize;
        u32::from_le_bytes([self.code[o], self.code[o + 1], self.code[o + 2], self.code[o + 3]])
    }
}

fn is_imm(op: &str) -> bool {
    let t = op.strip_prefix('-').unwrap_or(op);
    number_re().is_match(t)
}

fn is_reg(op: &str) -> bool {
    !op.is_empty() && !op.contains('[') && !op.contains(' ') && !is_imm(op)
}
