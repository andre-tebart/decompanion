//! The reference check of the object experiment (docs/mental-model.md §4, §8.4): a relocated field's value is
//! masked by the compare, so the experiment checks instead that the field refers to the same thing on both sides.
//! For each relocation of ours whose instruction lines up with the original's (a byte match: every one, at its
//! offset; else the instruction alignment's pairs, the one φ inside the function), the address the original's
//! field refers to is compared with φ(our symbol):
//!
//! - equal: the reference is reproduced;
//! - different: the experiment fails (a concrete difference naming both targets);
//! - φ undefined (our symbol has no address comment, declaration or library placement): open, listed, never learned.
//!
//! A literal (a string, a floating constant) has no name of H: its bytes are its identity, and the original's field
//! must refer to the same bytes. Where φ gives that address one of our data objects, the two declarations
//! contradict each other (our literal, or the datum the original loads: VC6 pools its literals, and a layout may
//! have named one as a datum): open, listed, and the literal binds only in read-only data. G.grade, `dcp asmdiff`, `dcp
//! diffclass`, `dcp escalate` and the prover's binding (equiv::bind) all read this one check; M8 / M9 / M10 are
//! its findings.

use crate::coff::{Obj, FunctionCode, Reloc};
use crate::phi::{Origin, Phi};
use crate::x86::Line;

/// One of our relocated fields whose instruction lines up with one of the original's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Site {
    /// the index of the relocation in the function's relocations
    pub k: usize,
    /// our instruction's address (the function at the original's address)
    pub ins: u32,
    /// the address the original's field refers to, as the field holds it (an addend included)
    pub to: u32,
    /// the two instructions are one by the alignment (equal texts, or a byte match); else they are paired by
    /// position in a hunk of equal length
    pub exact: bool,
    /// a positional pair: the addresses the original's instructions of that hunk refer to (a reordered pair
    /// crosses: the target is still the original's when that side of the hunk refers to it)
    pub near: Vec<u32>,
}

/// What a relocation of ours refers to.
#[derive(Clone, Debug)]
pub enum Target {
    /// a label of the function's own section (a jump, a switch table): the tables compare checks it
    Own,
    /// a string literal or a floating constant: its bytes and its rule (M9 / M10); `delta` the offset of the
    /// literal from the symbol the field is relocated against
    Lit { bytes: Vec<u8>, rule: &'static str, delta: u32 },
    /// a named object of H: its C name and its offset from the symbol the field is relocated against (a section
    /// symbol plus an addend: the object at that offset of the section)
    Name { name: String, delta: u32 },
    /// a symbol nothing names (a section without a named object at the offset)
    Anon(String),
}

fn text_of(lit: &[u8]) -> String {
    let t: String = lit.iter().take_while(|&&c| c != 0).take(48).map(|&c| match c {
        b'\n' => "\\n".to_string(),
        b'\t' => "\\t".to_string(),
        b'\\' => "\\\\".to_string(),
        b'"' => "\\\"".to_string(),
        0x20..=0x7e => (c as char).to_string(),
        _ => format!("\\x{c:02x}"),
    }).collect();
    format!("\"{t}\"")
}

fn float_text(b: &[u8]) -> String {
    match b.len() {
        4 => format!("{:?}", f32::from_le_bytes(b.try_into().unwrap_or([0; 4]))),
        8 => format!("{:?}", f64::from_le_bytes(b.try_into().unwrap_or([0; 8]))),
        _ => "?".into(),
    }
}

fn lit_target(obj: &Obj, s: u32, delta: u32) -> Option<Target> {
    let kind = obj.symbol_at(s)?.constant()?;
    let bytes = crate::equiv::literal(obj, s)?;
    Some(Target::Lit { bytes, rule: if kind == "float" { "M10" } else { "M9" }, delta })
}

/// How a literal reads: a string's text, a floating constant's value and its symbol (`1.0 (__real@3f800000)`).
fn lit_text(bytes: &[u8], rule: &str) -> String {
    if rule != "M10" {
        return text_of(bytes);
    }
    let bits = match bytes.len() {
        4 => format!("{:08x}", u32::from_le_bytes(bytes.try_into().unwrap_or([0; 4]))),
        _ => format!("{:016x}", u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]))),
    };
    format!("{} (__real@{bits})", float_text(bytes))
}

/// What relocation `r` of the function refers to.
pub fn target(obj: &Obj, code: &FunctionCode, r: &Reloc) -> Target {
    let Some(sym) = obj.symbol_at(r.symbol_index) else { return Target::Anon("?".into()) };
    if sym.secnum as usize == code.secnum {
        return Target::Own;
    }
    if let Some(t) = lit_target(obj, r.symbol_index, 0) {
        return t;
    }
    // a section symbol (`.data` + addend): the named object of that section at the offset
    if sym.name.starts_with('.') && sym.cls == 3 && sym.value == 0 && sym.secnum > 0 {
        let addend = obj.addend(code.secnum, r);
        let at = obj.symbols.iter().filter(|t| t.secnum == sym.secnum && t.named() && !t.name.starts_with('.') && t.value <= addend)
            .max_by_key(|t| t.value);
        return match at {
            Some(t) => match lit_target(obj, t.index as u32, t.value) {
                Some(l) => l,
                None => Target::Name { name: crate::coff::undecorate(&t.name), delta: t.value },
            },
            None => Target::Anon(format!("{}+{addend:#x}", sym.name)),
        };
    }
    Target::Name { name: crate::coff::undecorate(sym.name.strip_prefix("__imp_").unwrap_or(&sym.name)), delta: 0 }
}

/// φ(name): the addresses φ gives an object of H, sorted; without any, the address a placeholder name spells
/// (`ai_Unk5eb9b8`).
pub fn phi_addrs(phi: &Phi, name: &str) -> Vec<i64> {
    match phi.of(name) {
        Some(m) if !m.is_empty() => m.keys().copied().collect(),
        _ => crate::srcscan::placeholder_whole(name).map(|a| vec![a as i64]).unwrap_or_default(),
    }
}

/// What each relocation of a function refers to (Target) and, for a named object, φ's addresses of it: computed
/// once per run and function, read by G.grade's key, the check and the prover's binding.
pub struct Refs {
    pub targets: Vec<Target>,
    pub expect: Vec<Vec<i64>>,
    /// our references outside their object (containment, docs/mental-model.md §8.7): ill-formed
    pub outside: Vec<Outside>,
}

/// A reference of ours at `name + within` outside the object's declared size (`size` bytes; one past the end is
/// inside): an absolute memory operand without a register, or an immediate more than one object size past either
/// end. The compiler's own arithmetic is no such reference: an indexed operand's displacement (`[arr-4+ecx*4]`),
/// and the pointers strength reduction makes of a loop over the elements' field (`cmp esi, &arr[N].f`: one element
/// past the end at most, an element no larger than the object). `&cm_SendRing + 0x4973c0` is the constant
/// 0xf00500 spelled as an address: it moves with cm_SendRing in a relinked image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outside {
    /// the relocated field's offset in the function
    pub off: u32,
    pub name: String,
    pub within: i64,
    pub size: i64,
    /// the field is an immediate (else a memory operand's displacement)
    pub imm: bool,
}

impl Outside {
    /// `M.contain at +0x1c: &cm_SendRing + 0x4973c0 (an immediate) lies outside cm_SendRing (4 bytes): ...`
    pub fn line(&self) -> String {
        let at = if self.within < 0 { format!("- {:#x}", self.within.unsigned_abs()) } else { format!("+ {:#x}", self.within) };
        let what = if self.imm { "an immediate" } else { "an absolute memory operand" };
        format!("M.contain at +{:#x}: &{} {at} ({what}) lies outside {} ({} bytes, declared): no address of it; write the number \
                 when the original's is a constant, else the object the address belongs to", self.off, self.name, self.name, self.size)
    }
}

/// The instruction of a decoded listing that holds the byte at `off` and the field that byte lies in.
pub fn field_at(ins: &[crate::dis::Ins], off: u32) -> Option<(&crate::dis::Ins, crate::dis::FieldKind)> {
    let i = ins.partition_point(|x| x.addr <= off);
    let x = ins.get(i.checked_sub(1)?)?;
    Some((x, x.field_at(off - x.addr)?))
}

/// The kind of the field at an offset of our function's code, for the containment check: Some(true) an
/// immediate, Some(false) a memory operand's displacement with no base and no index register; None any other.
fn bare_field(code: &FunctionCode, off: u32, ins: &[crate::dis::Ins]) -> Option<bool> {
    let (x, kind) = field_at(ins, off)?;
    match kind {
        crate::dis::FieldKind::Imm | crate::dis::FieldKind::Imm2 => Some(true),
        crate::dis::FieldKind::Disp => {
            let m = x.ops.iter().find(|o| o.typ == crate::dis::OpType::Mem)?;
            (m.base == crate::dis::Reg::None && m.index == crate::dis::Reg::None).then_some(false)
        }
        crate::dis::FieldKind::Branch => None,
    }
    .filter(|_| off < code.code_len.unwrap_or(u32::MAX))
}

impl Refs {
    pub fn new(obj: &Obj, code: &FunctionCode, phi: &Phi) -> Refs {
        let targets: Vec<Target> = code.relocs.iter().map(|(_, r)| target(obj, code, r)).collect();
        let expect = targets.iter().map(|t| match t {
            Target::Name { name, .. } => phi_addrs(phi, name),
            _ => vec![],
        }).collect();
        // containment: the decode only for a function with a reference past its object's declared size
        let mut outside = vec![];
        let mut ins: Option<Vec<crate::dis::Ins>> = None;
        for ((off, r), t) in code.relocs.iter().zip(&targets) {
            let Target::Name { name, delta } = t else { continue };
            let Some(size) = phi.size_of(name) else { continue };
            let within = obj.addend(code.secnum, r).wrapping_sub(*delta) as i32 as i64;
            if (0..=size).contains(&within) {
                continue;
            }
            let ins = ins.get_or_insert_with(|| crate::dis::decode(code.code().0, 0));
            match bare_field(code, *off, ins) {
                Some(true) if (-size..=2 * size).contains(&within) => {} // a loop pointer of strength reduction
                Some(imm) => outside.push(Outside { off: *off, name: name.clone(), within, size, imm }),
                None => {}
            }
        }
        Refs { targets, expect, outside }
    }
}

/// The datum of ours φ gives the address, if any: an address comment's or a declaration's name, not a placeholder
/// (a placeholder names bytes not yet explained, a pooled literal among them).
pub fn datum_at(phi: &Phi, a: i64) -> Option<String> {
    phi.at(a).find(|e| matches!(e.origin, Origin::Source | Origin::Decl) && crate::srcscan::placeholder_whole(&e.name).is_none())
        .map(|e| e.name.clone())
}

/// The address a 4-byte field holds as a reference: an absolute one's value, a relative one's target.
fn field_to(r: &Reloc, field: u32, v: u32) -> Option<u32> {
    match r.kind_width() {
        (crate::coff::ABSOLUTE, 4) => Some(v),
        (crate::coff::RELATIVE, 4) => Some(field.wrapping_add(4).wrapping_add(v)),
        _ => None,
    }
}

/// The sites of a byte match: every relocation at its own offset (the compare already lined them up).
pub fn sites_matched(code: &FunctionCode, img: &crate::pe::Image, va: u32) -> Vec<Site> {
    let end = code.code_len.unwrap_or(code.data.len() as u32);
    let ins: Vec<(u32, u32)> = crate::dis::lengths(code.code().0, va);
    code.relocs.iter().enumerate().filter(|(_, (off, _))| *off < end).filter_map(|(k, (off, r))| {
        let field = va.wrapping_add(*off);
        let b = img.bytes(field, 4);
        let to = field_to(r, field, u32::from_le_bytes(b.get(..4)?.try_into().ok()?))?;
        let i = ins.partition_point(|l| l.0 <= field);
        let at = if i > 0 { ins[i - 1].0 } else { field };
        Some(Site { k, ins: at, to, exact: true, near: vec![] })
    }).collect()
}

/// The 4-byte reference fields of one of the original's instructions (displacement, immediates, branch target),
/// as addresses.
fn fields_of(x: &crate::dis::Ins, img: &crate::pe::Image) -> Vec<u32> {
    let mut out = vec![];
    for f in [x.disp, x.imm, x.imm2] {
        if f.size == 4 {
            let b = img.bytes(x.addr + f.at as u32, 4);
            out.push(u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
        }
    }
    if x.branch.size == 4 {
        out.extend(x.target);
    }
    out
}

/// The sites of a function that is no byte match: our relocations at the instructions the alignment pairs with
/// the original's (difflib over the listings' texts, relocated fields and image addresses read X): the equal
/// lines, exact; the same-mnemonic lines of a hunk of equal length on both sides, by position.
pub fn sites_aligned(code: &FunctionCode, img: &crate::pe::Image, va: u32, la: &[Line], lb: &[Line]) -> Vec<Site> {
    use crate::difflib::{opcodes, Tag};
    let (cd, _) = code.code();
    let ta: Vec<&str> = la.iter().map(|l| l.text.as_str()).collect();
    let tb: Vec<&str> = lb.iter().map(|l| l.text.as_str()).collect();
    let decode = |l: &Line, ours: bool| -> Option<crate::dis::Ins> {
        let o = (l.addr - va) as usize;
        if ours {
            crate::dis::decode(&cd[o.min(cd.len())..(o + l.size as usize).min(cd.len())], l.addr).into_iter().next()
        } else {
            crate::dis::decode(&img.read(l.addr, l.size as usize), l.addr).into_iter().next()
        }
    };
    let mut out = vec![];
    for (tag, i1, i2, j1, j2) in opcodes(&ta, &tb) {
        let exact = tag == Tag::Equal;
        if !exact && i2 - i1 != j2 - j1 {
            continue;
        }
        let mut near: Option<Vec<u32>> = None;
        for (i, j) in (i1..i2).zip(j1..j2) {
            if la[i].shape.mn != lb[j].shape.mn {
                continue;
            }
            let o = la[i].addr - va;
            let rs: Vec<(usize, &(u32, Reloc))> = code.relocs.iter().enumerate().filter(|(_, (off, _))| o <= *off && *off < o + la[i].size).collect();
            if rs.is_empty() {
                continue;
            }
            let (Some(x), Some(y)) = (decode(&la[i], true), decode(&lb[j], false)) else { continue };
            for (k, (off, r)) in rs {
                let Some(kind) = x.field_at(off - o) else { continue };
                let f = match kind {
                    crate::dis::FieldKind::Disp => y.disp,
                    crate::dis::FieldKind::Imm => y.imm,
                    crate::dis::FieldKind::Imm2 => y.imm2,
                    crate::dis::FieldKind::Branch => y.branch,
                };
                if f.size != 4 {
                    continue;
                }
                let field = lb[j].addr + f.at as u32;
                let b = img.bytes(field, 4);
                let Some(to) = field_to(r, field, u32::from_le_bytes([b[0], b[1], b[2], b[3]])) else { continue };
                let near = if exact {
                    vec![]
                } else {
                    near.get_or_insert_with(|| lb[j1..j2].iter().filter_map(|l| decode(l, false)).flat_map(|y| fields_of(&y, img)).collect()).clone()
                };
                out.push(Site { k, ins: la[i].addr, to, exact, near });
            }
        }
    }
    out
}

/// How one reference compares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// the original's field refers to φ(our symbol), or to our literal's bytes
    Same,
    /// it refers to something else
    Differs,
    /// our literal's bytes, at an address φ gives one of our data objects: the original loads the datum, or φ
    /// names a literal as one (open: two declarations contradict each other)
    Datum(String),
    /// φ says nothing about our symbol
    Open,
}

/// One reference of ours compared with the original's field.
#[derive(Clone, Debug)]
pub struct Ref {
    /// our instruction's address
    pub ins: u32,
    /// our relocated field's offset in the function
    pub off: u32,
    /// our symbol's C name, or a literal's text
    pub ours: String,
    /// M8 for a named object, M9 a string literal, M10 a floating constant
    pub rule: &'static str,
    /// the address the original's field refers to (the object's start: the addend taken off)
    pub theirs: u32,
    /// the address the original's field holds (the addend in it) and our offset into our object (`name+0x10`)
    pub raw: u32,
    pub within: i64,
    /// φ(our symbol), for a named object
    pub expect: Vec<i64>,
    pub state: State,
    /// literals: our bytes and the original's at `theirs`
    pub bytes: Option<(Vec<u8>, Vec<u8>)>,
}

impl Ref {
    /// A concrete difference: the experiment fails on it.
    pub fn differs(&self) -> bool {
        self.state == State::Differs
    }

    /// Our object with the offset into it: `name`, `name+0x10`.
    pub fn ours_at(&self) -> String {
        match self.within {
            0 => self.ours.clone(),
            n => format!("{}{}{:#x}", self.ours, if n < 0 { "-" } else { "+" }, n.unsigned_abs()),
        }
    }

    /// Where our field refers to and where the original's does, for a listing: `name+0x10 0x5f0010 | 0x5f0014`.
    pub fn pair(&self) -> String {
        match &self.state {
            State::Datum(d) => format!("{} | the datum {d} {:#x}", self.ours, self.raw),
            _ if self.expect.is_empty() => format!("{} | {:#x}", self.ours_at(), self.raw),
            _ => format!("{} {} | {:#x}", self.ours_at(), self.ours_addrs(), self.raw),
        }
    }

    /// φ's addresses of our field's target, the offset in.
    fn ours_addrs(&self) -> String {
        self.expect.iter().map(|a| format!("{:#x}", a + self.within)).collect::<Vec<_>>().join("/")
    }
}

/// The references of one function that differ or that φ cannot decide, in site order: each site once (a reference
/// that agrees is left out).
#[derive(Clone, Debug, Default)]
pub struct Check {
    pub refs: Vec<Ref>,
}

/// The reference check over a function's sites, against φ (`refs`: Refs::new with the same φ) and the image.
pub fn check(obj: &Obj, code: &FunctionCode, img: &crate::pe::Image, sites: &[Site], refs_of: &Refs, phi: &Phi) -> Check {
    let mut refs = vec![];
    for s in sites {
        let (off, r) = &code.relocs[s.k];
        let t = &refs_of.targets[s.k];
        let addend = obj.addend(code.secnum, r);
        // the object's start, as the original's field refers to it
        let base = |to: u32, delta: u32| to.wrapping_sub(addend).wrapping_add(delta);
        let lit_ok = |a: u32, b: &[u8]| img.in_image(a) && *img.bytes(a, b.len()) == *b;
        let within = match t {
            Target::Lit { delta, .. } | Target::Name { delta, .. } => addend.wrapping_sub(*delta) as i32 as i64,
            _ => addend as i32 as i64,
        };
        let (ours, rule, theirs, expect, state, bytes) = match t {
            Target::Own => continue,
            Target::Anon(n) => (n.clone(), "M8", base(s.to, 0), vec![], State::Open, None),
            Target::Lit { bytes, rule, delta } => {
                let a = base(s.to, *delta);
                let state = if lit_ok(a, bytes) {
                    match datum_at(phi, a as i64) {
                        Some(d) => State::Datum(d),
                        None => State::Same,
                    }
                } else if !s.exact && s.near.iter().any(|&n| lit_ok(base(n, *delta), bytes)) {
                    State::Same
                } else {
                    State::Differs
                };
                if state == State::Same {
                    continue;
                }
                let have = if img.in_image(a) { img.bytes(a, bytes.len()).to_vec() } else { vec![] };
                (lit_text(bytes, rule), *rule, a, vec![], state, Some((bytes.clone(), have)))
            }
            Target::Name { name, delta } => {
                let a = base(s.to, *delta);
                let expect = &refs_of.expect[s.k];
                let state = if expect.is_empty() {
                    State::Open
                } else if expect.contains(&(a as i64)) || (!s.exact && s.near.iter().any(|&n| expect.contains(&(base(n, *delta) as i64)))) {
                    State::Same
                } else {
                    State::Differs
                };
                if state == State::Same {
                    continue;
                }
                (name.clone(), "M8", a, expect.clone(), state, None)
            }
        };
        refs.push(Ref { ins: s.ins, off: *off, ours, rule, theirs, raw: s.to, within, expect, state, bytes });
    }
    Check { refs }
}

impl Check {
    /// The concrete differences.
    pub fn differs(&self) -> impl Iterator<Item = &Ref> {
        self.refs.iter().filter(|r| r.differs())
    }

    /// The references the check cannot decide: φ says nothing about our symbol, or names a datum where ours is a
    /// literal.
    pub fn open(&self) -> impl Iterator<Item = &Ref> {
        self.refs.iter().filter(|r| matches!(r.state, State::Open | State::Datum(_)))
    }

    /// Whether a symbol of ours (no literal) refers elsewhere than the original's field: the one difference a
    /// proof may still explain (two stores reordered pair the fields crosswise).
    pub fn named_differs(&self) -> bool {
        self.refs.iter().any(|r| r.state == State::Differs && r.rule == "M8")
    }

    /// Whether a literal differs (its bytes): a meaning difference whatever the code does.
    pub fn literal_differs(&self) -> bool {
        self.refs.iter().any(|r| r.differs() && r.rule != "M8")
    }

    /// The concrete differences, the same reference (our object and offset, the original's address) once.
    pub fn firsts(&self) -> Vec<&Ref> {
        let mut seen = std::collections::HashSet::new();
        self.differs().filter(|r| seen.insert((r.rule, r.ours.clone(), r.raw, r.within))).collect()
    }

    /// One line per concrete difference (firsts), `M8 at +0x1c: ...`, at the function at `va`; `unit`: a literal
    /// that spells the unit's source path hints at its file declaration.
    pub fn lines(&self, phi: &Phi, va: u32, unit: Option<&str>) -> Vec<String> {
        self.firsts().into_iter().map(|r| line(r, phi, va, unit)).collect()
    }

    /// One line per open reference (each symbol once).
    pub fn open_lines(&self, phi: &Phi, va: u32) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        self.open().filter(|r| seen.insert(r.ours.clone())).map(|r| match &r.state {
            State::Datum(d) => format!("{} at +{:#x}: our literal {} where the original refers to the datum {d} at {:#x} (φ): write the object; \
                                        or, when those bytes are a literal of the original, {d}'s address is wrong (not checked)",
                                       r.rule, r.ins - va, r.ours, r.theirs),
            _ => format!("{} at +{:#x}: {} has no address in φ (no address comment, declaration or placement): the original's field refers \
                          to {}; open, not checked", r.rule, r.ins - va, r.ours, named(phi, r.raw)),
        }).collect()
    }
}

/// An address with the names φ gives it.
fn named(phi: &Phi, a: u32) -> String {
    let ns: Vec<String> = phi.names_at(a as i64).into_iter().collect();
    if ns.is_empty() { format!("{a:#x}") } else { format!("{a:#x} ({})", ns.join(", ")) }
}

/// The address the original's field holds, with φ's names there, else as an offset into our object when it lies
/// in its first 64 KB (another element or field of the same object).
fn theirs_named(phi: &Phi, r: &Ref) -> String {
    if !phi.names_at(r.raw as i64).is_empty() {
        return named(phi, r.raw);
    }
    match r.expect.iter().find(|&&e| e <= r.raw as i64 && (r.raw as i64) - e < 0x10000) {
        Some(&e) if r.raw as i64 != e => format!("{:#x} ({}+{:#x})", r.raw, r.ours, r.raw as i64 - e),
        Some(_) => format!("{:#x} ({})", r.raw, r.ours),
        None => format!("{:#x}", r.raw),
    }
}

fn line(r: &Ref, phi: &Phi, va: u32, unit: Option<&str>) -> String {
    let at = r.ins - va;
    match (&r.state, &r.bytes) {
        (_, Some((_, have))) => {
            let theirs = if have.is_empty() {
                "outside the image".to_string()
            } else if r.rule == "M10" {
                float_text(have)
            } else {
                text_of(have)
            };
            let mut hint = String::new();
            if let Some(u) = unit.filter(|_| r.rule == "M9") {
                if r.ours.trim_matches('"').replace("\\\\", "/").starts_with(&format!("src/{u}/")) {
                    hint = format!("; the unit's original file name? dcp decl add \"{:#010x} file tu={u} path={} -- ...\"", r.theirs, theirs.trim_matches('"'));
                }
            }
            format!("{} at +{at:#x}: our {} {} where the original's field refers to {theirs} at {:#x}{hint}", r.rule,
                    if r.rule == "M9" { "literal" } else { "constant" }, r.ours, r.theirs)
        }
        _ => format!("{} at +{at:#x}: ours refers to {} ({}), the original's field to {}", r.rule, r.ours_at(), r.ours_addrs(), theirs_named(phi, r)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::testpe::{build_with, BASE, DATA, TEXT};
    use serde_json::json;
    use std::rc::Rc;

    const VA: u32 = BASE + TEXT;
    const A: u32 = BASE + DATA;
    const B: u32 = BASE + DATA + 4;
    const C: u32 = BASE + DATA + 8;

    #[test]
    fn text_and_float() {
        assert_eq!(text_of(b"a\\b\n\0"), "\"a\\\\b\\n\"");
        assert_eq!(float_text(&50.0f32.to_le_bytes()), "50.0");
        assert_eq!(float_text(&(-0.5f64).to_le_bytes()), "-0.5");
        assert_eq!(lit_text(&1.0f32.to_le_bytes(), "M10"), "1.0 (__real@3f800000)");
    }

    /// Our f: `mov eax, [g_a]; mov ecx, [g_b]; fld [__real@3f800000]; mov eax, [g_c]; ret`, every field relocated.
    fn ours() -> (Obj, FunctionCode) {
        let code = [0xa1u8, 0, 0, 0, 0, 0x8b, 0x0d, 0, 0, 0, 0, 0xd9, 0x05, 0, 0, 0, 0, 0xa1, 0, 0, 0, 0, 0xc3];
        let relocs = [(1u32, 2u32, 6u16), (7, 3, 6), (13, 4, 6), (18, 5, 6)];
        let syms = [(".text", 0, 1, 3), ("_f", 0, 1, 2), ("_g_a", 0, 0, 2), ("_g_b", 0, 0, 2), ("__real@3f800000", 0, 0, 2), ("_g_c", 0, 0, 2)];
        let obj = Obj::parse(&crate::coff::testlib::code_obj(&code, &relocs, &syms)).unwrap();
        let code = obj.function_code(obj.function_index()["f"]);
        (obj, code)
    }

    /// The original: our instructions with these addresses in the first three fields and g_c's, 1.0 at +0x40 and
    /// 2.0 at +0x44.
    fn image(a: u32, b: u32, f: u32) -> crate::pe::Image {
        let mut t = vec![0xa1u8];
        t.extend(a.to_le_bytes());
        t.extend([0x8b, 0x0d]);
        t.extend(b.to_le_bytes());
        t.extend([0xd9, 0x05]);
        t.extend(f.to_le_bytes());
        t.push(0xa1);
        t.extend(C.to_le_bytes());
        t.push(0xc3);
        t.resize(0x40, 0xcc);
        t.extend(1.0f32.to_le_bytes());
        t.extend(2.0f32.to_le_bytes());
        t.resize(0x60, 0xcc);
        crate::pe::Image::parse(build_with(None, Some(&t))).unwrap()
    }

    /// φ: g_a and g_b at their addresses (address comments), and these names; g_c has none.
    fn phi(extra: &[(u32, &str)]) -> Phi {
        let claim = |lo: u32, n: &str| {
            let v = json!({"name": n, "origin": "source"});
            let mut text = String::new();
            crate::store::canon(&mut text, &v);
            Rc::new(crate::store::Claim { id: lo as i64, rule: Rc::from("L.src"), lo: lo as i64, hi: lo as i64 + 1, text, value: v,
                                          support: crate::store::DECLARED, by: "t".into(), reason: None })
        };
        let mut cs = vec![claim(A, "g_a"), claim(B, "g_b")];
        cs.extend(extra.iter().map(|&(a, n)| claim(a, n)));
        Phi::new(&cs, &[])
    }

    fn run(img: &crate::pe::Image, phi: &Phi) -> Check {
        let (obj, code) = ours();
        let refs = Refs::new(&obj, &code, phi);
        check(&obj, &code, img, &sites_matched(&code, img, VA), &refs, phi)
    }

    #[test]
    fn a_byte_match_checks_every_reference_through_phi() {
        // every field where φ puts our object, the constant's bytes where the original's field refers: byte; g_c
        // has no φ: open and listed, not failing
        let (img, p) = (image(A, B, VA + 0x40), phi(&[]));
        let c = run(&img, &p);
        assert_eq!(c.differs().count(), 0);
        assert_eq!(c.open().map(|r| r.ours.as_str()).collect::<Vec<_>>(), ["g_c"]);
        assert!(c.open_lines(&p, VA)[0].starts_with("M8 at +0x11: g_c has no address in φ"), "{:?}", c.open_lines(&p, VA));
        assert_eq!(crate::grade::code_grade(true, false, false, &c), "byte");
        // the two loads swapped (a match-base report: v1a4 / v1a0, the bytes equal at this layout): two concrete
        // differences naming both targets; draft, unless a proof shows the effects the same
        let c = run(&image(B, A, VA + 0x40), &p);
        assert!(c.named_differs() && !c.literal_differs());
        let lines = c.lines(&p, VA, None);
        assert_eq!(lines[0], format!("M8 at +0x0: ours refers to g_a ({A:#x}), the original's field to {B:#x} (g_b)"));
        assert_eq!(lines.len(), 2);
        assert_eq!(crate::grade::code_grade(true, false, false, &c), "draft");
        assert_eq!(crate::grade::code_grade(true, false, true, &c), "shape");
        assert_eq!(c.refs[0].pair(), format!("g_a {A:#x} | {B:#x}"));
    }

    #[test]
    fn a_literal_is_checked_by_its_bytes_and_is_no_datum() {
        let p = phi(&[]);
        // the original's constant is 2.0: a meaning difference, a proof does not lift it
        let c = run(&image(A, B, VA + 0x44), &p);
        assert!(c.literal_differs() && !c.named_differs());
        assert_eq!(c.lines(&p, VA, None), [format!("M10 at +0xb: our constant 1.0 (__real@3f800000) where the original's field refers to 2.0 at {:#x}",
                                                   VA + 0x44)]);
        assert_eq!(crate::grade::code_grade(true, true, true, &c), "draft");
        // the bytes agree, but φ gives the address one of our data objects: the original loads the datum, or the
        // datum is a literal of the original's: open (no binding), listed
        let p = phi(&[(VA + 0x40, "one")]);
        let c = run(&image(A, B, VA + 0x40), &p);
        assert_eq!(c.refs[0].state, State::Datum("one".into()));
        assert_eq!(c.differs().count(), 0);
        assert!(c.open_lines(&p, VA)[0].contains("where the original refers to the datum one at"));
        // a placeholder name is no datum (a pooled literal the layout has not explained yet)
        let p = phi(&[(VA + 0x40, "ai_Unk10001040")]);
        assert_eq!(run(&image(A, B, VA + 0x40), &p).differs().count(), 0);
    }

    /// Containment: `mov eax, [g_a+0x10]` and `mov eax, offset g_b+9` lie outside the 4-byte objects (one past the end
    /// is inside); `mov eax, [g_c-4+ecx*4]` is the compiler's indexing and `cmp esi, offset g_b+6` a loop pointer
    /// one element past the end, not checked.
    #[test]
    fn a_reference_outside_its_declared_object_is_listed() {
        let code = [0xa1u8, 0x10, 0, 0, 0, 0xb8, 0x09, 0, 0, 0, 0x8b, 0x04, 0x8d, 0xfc, 0xff, 0xff, 0xff, 0xa1, 0x04, 0, 0, 0, 0x81, 0xfe, 0x06, 0, 0, 0,
                    0xc3];
        let relocs = [(1u32, 2u32, 6u16), (6, 3, 6), (13, 4, 6), (18, 2, 6), (24, 3, 6)];
        let syms = [(".text", 0, 1, 3), ("_f", 0, 1, 2), ("_g_a", 0, 0, 2), ("_g_b", 0, 0, 2), ("_g_c", 0, 0, 2)];
        let obj = Obj::parse(&crate::coff::testlib::code_obj(&code, &relocs, &syms)).unwrap();
        let code = obj.function_code(obj.function_index()["f"]);
        let claim = |lo: u32, n: &str| {
            let v = json!({"name": n, "origin": "source", "size": 4});
            Rc::new(crate::store::Claim { id: lo as i64, rule: Rc::from("L.src"), lo: lo as i64, hi: lo as i64 + 1, text: String::new(), value: v,
                                          support: crate::store::DECLARED, by: "t".into(), reason: None })
        };
        let p = Phi::new(&[claim(A, "g_a"), claim(B, "g_b"), claim(C, "g_c")], &[]);
        let refs = Refs::new(&obj, &code, &p);
        let got: Vec<(u32, &str, i64, bool)> = refs.outside.iter().map(|o| (o.off, o.name.as_str(), o.within, o.imm)).collect();
        assert_eq!(got, [(1, "g_a", 0x10, false), (6, "g_b", 9, true)]);
        assert!(refs.outside[0].line().starts_with("M.contain at +0x1: &g_a + 0x10 (an absolute memory operand) lies outside g_a (4 bytes, declared)"),
                "{}", refs.outside[0].line());
    }

    #[test]
    fn the_alignment_lines_up_the_same_sites_and_bind_takes_phi() {
        let (obj, code) = ours();
        let img = image(B, A, VA + 0x40);
        let p = phi(&[]);
        let fills: std::collections::HashSet<Vec<u8>> = [vec![0xccu8]].into_iter().collect();
        let range = (img.base as i64, img.end() as i64);
        let (cd, cm) = code.code();
        let la = crate::x86::strip_fill(crate::x86::listing(cd, VA, Some(cm), range, &fills));
        let lb = crate::x86::strip_fill(crate::x86::listing(&img.read(VA, 0x17), VA, None, range, &fills));
        let aligned = sites_aligned(&code, &img, VA, &la, &lb);
        assert_eq!(aligned, sites_matched(&code, &img, VA));
        assert!(aligned.iter().all(|s| s.exact));
        // the prover's binding: φ's addresses whatever the original's swapped fields hold; the literal and g_c
        // (no φ: open) where the original's field refers
        let refs = Refs::new(&obj, &code, &p);
        let (bound, unbound) = crate::equiv::bind(&obj, &code, &img, VA, &aligned, &refs, &p);
        let at = |o: usize| u32::from_le_bytes(bound[o..o + 4].try_into().unwrap());
        assert_eq!((at(1), at(7), at(13), at(18), unbound), (A, B, VA + 0x40, C, 0));
        // φ names a datum where the constant lies: read-only data holds these bytes for good, the literal binds
        let p = phi(&[(VA + 0x40, "one")]);
        let refs = Refs::new(&obj, &code, &p);
        let (bound, unbound) = crate::equiv::bind(&obj, &code, &img, VA, &aligned, &refs, &p);
        assert_eq!((u32::from_le_bytes(bound[13..17].try_into().unwrap()), unbound), (VA + 0x40, 0));
    }
}
