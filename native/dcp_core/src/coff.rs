//! COFF objects as objfmt/coff.py reads them (VC6's CL, i386): sections with their relocations, symbols, the
//! function symbols, a function's code with its relocation mask. Names are Latin-1, as Python decodes them.

pub const ABSOLUTE: u8 = 1;
pub const RELATIVE: u8 = 2;
pub const ABSOLUTE_RVA: u8 = 3;

const SCN_CODE: u32 = 0x20;
const SCN_UDATA: u32 = 0x80;
const SCN_LNK_INFO: u32 = 0x200;
const SCN_LNK_REMOVE: u32 = 0x800;

#[derive(Clone, Copy)]
pub struct Reloc {
    pub offset: u32,
    pub symbol_index: u32,
    pub typ: u16,
}

impl Reloc {
    /// (kind, width): DIR32 absolute, DIR32NB absolute-rva, REL32 relative; (0, 0) for any other type.
    pub fn kind_width(&self) -> (u8, u32) {
        match self.typ {
            0x06 => (ABSOLUTE, 4),
            0x07 => (ABSOLUTE_RVA, 4),
            0x14 => (RELATIVE, 4),
            _ => (0, 0),
        }
    }
}

pub struct Section {
    pub name: String,
    pub chars: u32,
    pub data: Option<Vec<u8>>,
    pub size: u32,
    pub relocs: Vec<Reloc>,
    pub syms: Vec<usize>, // symbol indices, sorted by value (stable: symbol-table order among equals)
}

impl Section {
    pub fn code(&self) -> bool {
        self.chars & SCN_CODE != 0
    }
    pub fn discard(&self) -> bool {
        self.chars & (SCN_LNK_INFO | SCN_LNK_REMOVE) != 0
    }
    pub fn mask(&self) -> Vec<u8> {
        let mut m = vec![0u8; self.size as usize];
        for r in &self.relocs {
            let (_, w) = r.kind_width();
            if w > 0 {
                let hi = (r.offset + w).min(self.size);
                for k in r.offset..hi.max(r.offset) {
                    m[k as usize] = 1;
                }
            }
        }
        m
    }
}

pub struct Symbol {
    pub index: usize,
    pub name: String,
    pub value: u32,
    pub secnum: i16,
    pub typ: u16,
    pub cls: u8,
}

impl Symbol {
    pub fn named(&self) -> bool {
        self.cls == 2 || self.cls == 3
    }
    pub fn defined(&self) -> bool {
        self.secnum > 0
    }
    pub fn function(&self) -> bool {
        (self.typ >> 4) == 2
    }
}

pub struct Obj {
    pub sections: Vec<Section>, // index 0: unused (sections count from 1)
    pub symbols: Vec<Symbol>,   // in symbol-table order (auxiliary records skipped)
    pub by_index: std::collections::HashMap<usize, usize>,
}

pub struct FunctionCode {
    pub data: Vec<u8>,
    pub mask: Vec<u8>,
    pub relocs: Vec<(u32, Reloc)>, // (offset from the function start, relocation)
    pub code_len: Option<u32>,
}

fn latin1(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

fn u16_at(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([d[o], d[o + 1]])
}

fn u32_at(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}

fn cstr(d: &[u8], s: usize) -> String {
    let e = d[s..].iter().position(|&c| c == 0).map(|p| s + p).unwrap_or(d.len());
    latin1(&d[s..e])
}

fn rstrip_nul(b: &[u8]) -> &[u8] {
    let mut e = b.len();
    while e > 0 && b[e - 1] == 0 {
        e -= 1;
    }
    &b[..e]
}

/// Python's str.isdigit of a Latin-1 name part: 0-9 and the superscripts ¹ ² ³; false when empty.
fn isdigit(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit() || c == '\u{b2}' || c == '\u{b3}' || c == '\u{b9}')
}

/// toolchains/vc6 undecorate: `_f` (cdecl) and `_f@12` (stdcall) -> f, `@f@8` (fastcall) -> f; `?..` (C++) stays.
pub fn undecorate(symbol: &str) -> String {
    if symbol.starts_with('?') {
        return symbol.to_string();
    }
    let mut s: &str = symbol;
    if let Some(r) = s.strip_prefix('@') {
        s = r;
    } else if let Some(r) = s.strip_prefix('_') {
        s = r;
    }
    if let Some(at) = s.rfind('@') {
        if at > 0 && isdigit(&s[at + 1..]) {
            return s[..at].to_string();
        }
    }
    s.to_string()
}

impl Obj {
    pub fn parse(b: &[u8]) -> Result<Obj, String> {
        if b.len() < 20 {
            return Err("object too short".into());
        }
        let nsec = u16_at(b, 2) as usize;
        let symptr = u32_at(b, 8) as usize;
        let nsym = u32_at(b, 12) as usize;
        let optsz = u16_at(b, 16) as usize;
        let strtab = symptr + 18 * nsym;
        let mut sections = vec![Section { name: String::new(), chars: 0, data: None, size: 0, relocs: vec![], syms: vec![] }];
        for k in 0..nsec {
            let h = 20 + optsz + 40 * k;
            let mut name = latin1(rstrip_nul(&b[h..h + 8]));
            if let Some(num) = name.strip_prefix('/') {
                if !num.is_empty() && num.bytes().all(|c| c.is_ascii_digit()) {
                    name = cstr(b, strtab + num.parse::<usize>().unwrap());
                }
            }
            let size = u32_at(b, h + 16);
            let rawptr = u32_at(b, h + 20) as usize;
            let relptr = u32_at(b, h + 24) as usize;
            let nrel = u16_at(b, h + 32) as usize;
            let chars = u32_at(b, h + 36);
            let data = if chars & SCN_UDATA != 0 {
                None
            } else {
                let e = (rawptr + size as usize).min(b.len());
                Some(b[rawptr.min(e)..e].to_vec())
            };
            let relocs = (0..nrel)
                .map(|r| {
                    let o = relptr + 10 * r;
                    Reloc { offset: u32_at(b, o), symbol_index: u32_at(b, o + 4), typ: u16_at(b, o + 8) }
                })
                .collect();
            sections.push(Section { name, chars, data, size, relocs, syms: vec![] });
        }
        let mut symbols = Vec::new();
        let mut by_index = std::collections::HashMap::new();
        let mut i = 0;
        while i < nsym {
            let o = symptr + 18 * i;
            let raw = &b[o..o + 8];
            let name = if raw[..4] == [0, 0, 0, 0] {
                cstr(b, strtab + u32_at(raw, 4) as usize)
            } else {
                latin1(rstrip_nul(raw))
            };
            let value = u32_at(b, o + 8);
            let secnum = u16_at(b, o + 12) as i16;
            let typ = u16_at(b, o + 14);
            let cls = b[o + 16];
            let naux = b[o + 17] as usize;
            let pos = symbols.len();
            if secnum > 0 && (secnum as usize) < sections.len() {
                if (cls == 2 || cls == 3 || cls == 6) && !(cls == 3 && value == 0 && naux > 0) {
                    sections[secnum as usize].syms.push(pos);
                }
            }
            by_index.insert(i, pos);
            symbols.push(Symbol { index: i, name, value, secnum, typ, cls });
            i += 1 + naux;
        }
        for s in sections.iter_mut().skip(1) {
            s.syms.sort_by_key(|&k| symbols[k].value);
        }
        Ok(Obj { sections, symbols, by_index })
    }

    pub fn section_of(&self, s: &Symbol) -> Option<&Section> {
        if s.secnum > 0 { self.sections.get(s.secnum as usize) } else { None }
    }

    /// The defined function symbols of the code sections (external or static), in symbol-table order.
    pub fn functions(&self) -> Vec<usize> {
        (0..self.symbols.len())
            .filter(|&k| {
                let s = &self.symbols[k];
                s.defined()
                    && s.named()
                    && s.function()
                    && self.section_of(s).map(|sec| sec.code() && sec.data.is_some()).unwrap_or(false)
            })
            .collect()
    }

    /// C name -> function symbol (the first of a name), as match/compare.function_index.
    pub fn function_index(&self) -> std::collections::HashMap<String, usize> {
        let mut out = std::collections::HashMap::new();
        for k in self.functions() {
            out.entry(undecorate(&self.symbols[k].name)).or_insert(k);
        }
        out
    }

    /// Obj.function_code: from the symbol to the next named non-`$` symbol of its section (else the section
    /// end); the first named `$` label inside marks the end of the instructions.
    pub fn function_code(&self, k: usize) -> FunctionCode {
        let sym = &self.symbols[k];
        let sec = self.section_of(sym).expect("a function symbol has a section");
        let start = sym.value;
        let named = |j: &usize| self.symbols[*j].named();
        let end = sec
            .syms
            .iter()
            .filter(|j| named(j))
            .map(|&j| &self.symbols[j])
            .find(|s| s.value > start && !s.name.starts_with('$'))
            .map(|s| s.value)
            .unwrap_or(sec.size);
        let table = sec
            .syms
            .iter()
            .filter(|j| named(j))
            .map(|&j| &self.symbols[j])
            .find(|s| start < s.value && s.value < end && s.name.starts_with('$'))
            .map(|s| s.value);
        // Section.mask()[start:end]: the relocated bytes of the function's range only
        let (lo, hi) = (start as usize, end as usize);
        let size = sec.size as usize;
        let mut mask = vec![0u8; hi.min(size).saturating_sub(lo.min(size))];
        for r in &sec.relocs {
            let (_, w) = r.kind_width();
            if w == 0 {
                continue;
            }
            let (a, b) = (r.offset as usize, (r.offset as usize + w as usize).min(size));
            for k in a.max(lo)..b.min(hi) {
                mask[k - lo] = 1;
            }
        }
        let d = sec.data.as_ref().unwrap();
        let data = d[lo.min(d.len())..hi.min(d.len())].to_vec();
        let relocs = sec
            .relocs
            .iter()
            .filter(|r| start <= r.offset && r.offset < end)
            .map(|r| (r.offset - start, *r))
            .collect();
        FunctionCode { data, mask, relocs, code_len: table.map(|t| t - start) }
    }
}
