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
    pub name: String,           // the archive member's or file's name ("" when parsed without one)
    pub sections: Vec<Section>, // index 0: unused (sections count from 1)
    pub symbols: Vec<Symbol>,   // in symbol-table order (auxiliary records skipped)
    pub by_index: std::collections::HashMap<usize, usize>,
}

pub struct FunctionCode {
    pub secnum: usize, // the function's section
    pub data: Vec<u8>,
    pub mask: Vec<u8>,
    pub relocs: Vec<(u32, Reloc)>, // (offset from the function start, relocation)
    pub code_len: Option<u32>,
    pub start: u32, // the function symbol's value
}

impl FunctionCode {
    /// (code_data, code_mask): the instructions up to the first compiler label after the code.
    pub fn code(&self) -> (&[u8], &[u8]) {
        match self.code_len {
            None => (&self.data, &self.mask),
            Some(n) => (&self.data[..(n as usize).min(self.data.len())], &self.mask[..(n as usize).min(self.mask.len())]),
        }
    }
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

/// undecorate: `_f` (cdecl) and `_f@12` (stdcall) -> f, `@f@8` (fastcall) -> f; `?..` (C++) stays.
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
        Ok(Obj { name: String::new(), sections, symbols, by_index })
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
        FunctionCode { secnum: sym.secnum as usize, data, mask, relocs, code_len: table.map(|t| t - start), start }
    }
}

impl Obj {
    /// The symbol of a symbol-table index (None for an auxiliary record or an index past the table).
    pub fn symbol_at(&self, index: u32) -> Option<&Symbol> {
        self.by_index.get(&(index as usize)).map(|&k| &self.symbols[k])
    }

    /// Section.addend: the 4 bytes a relocation of width 4 rewrites, as the object holds them (0 otherwise).
    pub fn addend(&self, secnum: usize, r: &Reloc) -> u32 {
        let (_, w) = r.kind_width();
        match self.sections.get(secnum).and_then(|s| s.data.as_ref()) {
            Some(d) if w == 4 && (r.offset as usize) + 4 <= d.len() => {
                let o = r.offset as usize;
                u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
            }
            _ => 0,
        }
    }
}

impl Reloc {
    /// Reloc.resolve: the address the linked site refers to (ABSOLUTE: value - addend; RELATIVE: the field's end +
    /// value - addend), None for the other kinds.
    pub fn resolve(&self, site_va: u32, site: &[u8], addend: u32) -> Option<u32> {
        let (kind, w) = self.kind_width();
        if w != 4 || site.len() < 4 {
            return None;
        }
        let v = u32::from_le_bytes([site[0], site[1], site[2], site[3]]);
        match kind {
            ABSOLUTE => Some(v.wrapping_sub(addend)),
            RELATIVE => Some(site_va.wrapping_add(w).wrapping_add(v).wrapping_sub(addend)),
            _ => None,
        }
    }
}

impl Symbol {
    /// "string" for a string literal COMDAT (`??_C@`), "float" for a floating constant (`__real@`).
    pub fn constant(&self) -> Option<&'static str> {
        if self.name.starts_with("??_C@") {
            Some("string")
        } else if self.name.starts_with("__real@") {
            Some("float")
        } else {
            None
        }
    }
}

impl Symbol {
    /// A tentative definition: external, no section, the value is its size.
    pub fn common(&self) -> bool {
        self.cls == 2 && self.secnum == 0 && self.value > 0
    }
}

/// One named data symbol of an object (Obj.data_symbols): the symbol, its kind (data / rdata / bss / common) and
/// size (to the next named symbol of its section or the section's end; a common's value).
pub struct DataSym {
    pub sym: usize,
    pub kind: &'static str,
    pub size: u32,
}

impl Obj {
    pub fn data_symbols(&self) -> Vec<DataSym> {
        let mut out = Vec::new();
        for sec in self.sections.iter().skip(1) {
            if sec.code() || sec.discard() {
                continue;
            }
            let kind = if sec.data.is_none() { "bss" } else if sec.name.starts_with(".rdata") { "rdata" } else { "data" };
            let named: Vec<usize> = sec
                .syms
                .iter()
                .copied()
                .filter(|&k| {
                    let s = &self.symbols[k];
                    s.named() && s.constant().is_none() && !s.name.starts_with('$') && !s.name.starts_with('.')
                })
                .collect();
            for (i, &k) in named.iter().enumerate() {
                let end = if i + 1 < named.len() { self.symbols[named[i + 1]].value } else { sec.size };
                out.push(DataSym { sym: k, kind, size: end.wrapping_sub(self.symbols[k].value) });
            }
        }
        for (k, s) in self.symbols.iter().enumerate() {
            if s.common() {
                out.push(DataSym { sym: k, kind: "common", size: s.value });
            }
        }
        out
    }
}

// ------------------------------------------------------------------------------------------------ symbols, sections

pub const IMPORT_PREFIX: &str = "__imp_"; // the pointer symbol of a dllimport reference (its IAT slot)
pub const COMP_ID: &str = "@comp.id"; // the absolute symbol MSVC-era tools stamp every object with
// String literals and float constants are COMDATs that VC6's LINK keeps per object: they resolve per object.

/// Names of the compiler's constants (string literals, floating constants): no object's own symbol.
#[cfg(test)]
const CONSTANT_PREFIXES: [&str; 2] = ["??_C@", "__real@"];


impl Symbol {
    pub fn external(&self) -> bool {
        self.cls == 2
    }
    /// An external this object references and another defines.
    pub fn unresolved(&self) -> bool {
        self.cls == 2 && self.secnum == 0
    }
    /// The pointer of a dllimport reference (`__imp_X`: X's import address-table slot).
    pub fn dllimport(&self) -> bool {
        self.name.starts_with(IMPORT_PREFIX)
    }
    #[cfg(test)]
    /// The linker symbol a dllimport reference imports (`__imp__Sleep@4` -> `_Sleep@4`).
    pub fn imported(&self) -> Option<&str> {
        self.name.strip_prefix(IMPORT_PREFIX)
    }
    #[cfg(test)]
    /// The name the link resolves: an external's own (not a constant's), else `<object>:<name>`.
    pub fn key(&self, obj: &str) -> String {
        if self.external() && !CONSTANT_PREFIXES.iter().any(|p| self.name.starts_with(p)) {
            self.name.clone()
        } else {
            format!("{obj}:{}", self.name)
        }
    }
}

impl Obj {
    /// An object as its archive member or file names it.
    pub fn parse_named(name: &str, b: &[u8]) -> Result<Obj, String> {
        let mut o = Obj::parse(b)?;
        o.name = name.to_string();
        Ok(o)
    }

    /// The section numbers of the code sections with data.
    pub fn code_sections(&self) -> Vec<usize> {
        (1..self.sections.len()).filter(|&k| self.sections[k].code() && self.sections[k].data.as_ref().is_some_and(|d| !d.is_empty())).collect()
    }

    /// The value of the `@comp.id` symbol (the tool that built the object), None without one.
    pub fn comp_id(&self) -> Option<u32> {
        self.symbols.iter().find(|s| s.name == COMP_ID).map(|s| s.value)
    }
}

// ------------------------------------------------------------------------------------------------ archives

/// (member name, bytes) of every member of a COFF archive, long names resolved, the linker members (`/`, `//`)
/// skipped; import-library short members are kept (is_import_member tells them).
pub fn archive_members(b: &[u8]) -> Result<Vec<(String, &[u8])>, String> {
    if b.len() < 8 || &b[..8] != b"!<arch>\n" {
        return Err("not an archive".into());
    }
    let (mut i, mut longnames, mut out): (usize, &[u8], Vec<(String, &[u8])>) = (8, &[], vec![]);
    while i + 60 <= b.len() {
        let name = latin1(&b[i..i + 16]).trim().to_string();
        let size: usize = std::str::from_utf8(&b[i + 48..i + 58]).ok().and_then(|s| s.trim().parse().ok()).ok_or("bad member size")?;
        let d = &b[i + 60..(i + 60 + size).min(b.len())];
        if name == "//" {
            longnames = d;
        } else if let Some(num) = name.strip_prefix('/').filter(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit())) {
            let o: usize = num.parse().unwrap_or(0);
            let e = memchr::memchr(0, &longnames[o.min(longnames.len())..]).map(|k| o + k).unwrap_or(longnames.len());
            out.push((latin1(&longnames[o.min(e)..e]), d));
        } else if name != "/" {
            out.push((name.trim_end_matches('/').to_string(), d));
        }
        i += 60 + size + (size & 1);
    }
    Ok(out)
}

/// The public symbols of an archive's first linker member (`/`): a big-endian count N, N offsets, N names;
/// empty without one.
pub fn archive_symbol_table(b: &[u8]) -> Result<Vec<String>, String> {
    if b.len() < 8 || &b[..8] != b"!<arch>\n" {
        return Err("not an archive".into());
    }
    if b.len() < 68 || latin1(&b[8..24]).trim() != "/" {
        return Ok(vec![]);
    }
    let size: usize = std::str::from_utf8(&b[56..66]).ok().and_then(|s| s.trim().parse().ok()).ok_or("bad member size")?;
    let d = &b[68..(68 + size).min(b.len())];
    let n = u32::from_be_bytes([d[0], d[1], d[2], d[3]]) as usize;
    let names = &d[(4 + 4 * n).min(d.len())..];
    Ok(names.split(|&c| c == 0).take(n).map(latin1).collect())
}

pub fn is_import_member(d: &[u8]) -> bool {
    d.len() >= 4 && d[..4] == [0, 0, 0xff, 0xff]
}

/// Every real COFF object of an archive (import-library short members skipped), named by its member's file name.
pub fn archive_objects(b: &[u8]) -> Result<Vec<Obj>, String> {
    let mut out = vec![];
    for (name, d) in archive_members(b)? {
        if is_import_member(d) || d.len() < 20 {
            continue;
        }
        let base = name.rsplit(['/', '\\']).next().unwrap_or(&name).to_string();
        out.push(Obj::parse_named(&base, d)?);
    }
    Ok(out)
}

#[cfg(test)]
/// symbol -> (dll, import name or `#ordinal`) of an import library's short members.
pub fn import_symbols(b: &[u8]) -> Result<Vec<(String, String, String)>, String> {
    let mut out = vec![];
    for (_, d) in archive_members(b)? {
        if !is_import_member(d) || d.len() < 20 {
            continue;
        }
        let hint = u16_at(d, 16);
        let typ = u16_at(d, 18);
        let strings: Vec<String> = d[20..].split(|&c| c == 0).map(latin1).collect();
        if strings.len() < 2 {
            continue;
        }
        let (sym, dll) = (strings[0].clone(), strings[1].clone());
        let stripped = sym.trim_start_matches(['?', '@', '_']);
        let name = match typ >> 2 & 7 {
            0 => format!("#{hint}"),
            1 => sym.clone(),
            2 => stripped.to_string(),
            3 => stripped.split('@').next().unwrap_or("").to_string(),
            _ => sym.clone(),
        };
        out.push((sym, dll, name));
    }
    Ok(out)
}

/// raw `@comp.id` value -> the number of objects that carry it.
pub fn comp_ids<'a>(objs: impl IntoIterator<Item = &'a Obj>) -> std::collections::BTreeMap<u32, u32> {
    let mut out = std::collections::BTreeMap::new();
    for o in objs {
        if let Some(v) = o.comp_id() {
            *out.entry(v).or_insert(0) += 1;
        }
    }
    out
}

/// An object whose only content is one weak external per (alias, canonical) pair (storage class
/// WEAK_EXTERNAL, aux characteristics 3: search alias): LINK resolves the alias to the canonical symbol.
pub fn alias_object(aliases: &[(String, String)]) -> Vec<u8> {
    let mut strtab: Vec<u8> = vec![];
    let mut namefield = |n: &str| -> Vec<u8> {
        if n.len() <= 8 {
            let mut f = n.as_bytes().to_vec();
            f.resize(8, 0);
            f
        } else {
            let off = 4 + strtab.len() as u32;
            strtab.extend(n.as_bytes());
            strtab.push(0);
            [0u32.to_le_bytes(), off.to_le_bytes()].concat()
        }
    };
    let sym = |field: Vec<u8>, cls: u8, naux: u8| -> Vec<u8> { [field, 0u32.to_le_bytes().to_vec(), 0i16.to_le_bytes().to_vec(), 0u16.to_le_bytes().to_vec(), vec![cls, naux]].concat() };
    let mut idx = 2 * aliases.len() as u32;
    let mut target: Vec<(String, u32)> = vec![];
    for (_, c) in aliases {
        if !target.iter().any(|(t, _)| t == c) {
            target.push((c.clone(), idx));
            idx += 1;
        }
    }
    let mut body = vec![];
    for (a, c) in aliases {
        body.extend(sym(namefield(a), 105, 1));
        let t = target.iter().find(|(x, _)| x == c).unwrap().1;
        body.extend(t.to_le_bytes());
        body.extend(3u32.to_le_bytes());
        body.extend([0u8; 10]);
    }
    for (c, _) in &target {
        body.extend(sym(namefield(c), 2, 0));
    }
    let mut out = vec![];
    out.extend(0x14cu16.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out.extend(0u32.to_le_bytes());
    out.extend(20u32.to_le_bytes());
    out.extend(idx.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out.extend(body);
    out.extend((4 + strtab.len() as u32).to_le_bytes());
    out.extend(strtab);
    out
}

// ------------------------------------------------------------------------------------------------ tests

#[cfg(test)]
pub(crate) mod testlib {
    //! An archive of objects that carry only an `@comp.id` symbol (tests/conftest.py build_lib), plus an import
    //! member, a long-named member and a linker member.
    fn member(name: &[u8], d: &[u8]) -> Vec<u8> {
        let mut h = name.to_vec();
        h.resize(16, b' ');
        for f in [&b"0"[..], b"0", b"0", b"644"].iter().zip([12usize, 6, 6, 8]) {
            let mut x = f.0.to_vec();
            x.resize(f.1, b' ');
            h.extend(x);
        }
        let mut sz = d.len().to_string().into_bytes();
        sz.resize(10, b' ');
        h.extend(sz);
        h.extend(b"`\n");
        h.extend(d);
        if d.len() & 1 == 1 {
            h.push(b'\n');
        }
        h
    }

    /// An object with no sections and one absolute `@comp.id` symbol.
    pub fn comp_obj(prodid: u32, build: u32) -> Vec<u8> {
        let mut o = vec![];
        for v in [0x14cu16, 0] {
            o.extend(v.to_le_bytes());
        }
        for v in [0u32, 20, 1] {
            o.extend(v.to_le_bytes());
        }
        o.extend([0u8; 4]); // optional header size 0, characteristics 0
        o.extend(b"@comp.id");
        o.extend(((prodid << 16) | build).to_le_bytes());
        o.extend((-1i16).to_le_bytes());
        o.extend(0u16.to_le_bytes());
        o.extend([3u8, 0]);
        o.extend(4u32.to_le_bytes());
        o
    }

    /// A COFF object: one .text section of these bytes with these relocations (offset, symbol index, type) and
    /// symbols (name, value, section number, storage class), names of at most 8 bytes; a section symbol first.
    pub fn code_obj(code: &[u8], relocs: &[(u32, u32, u16)], syms: &[(&str, u32, i16, u8)]) -> Vec<u8> {
        let (hdr, sec) = (20usize, 40usize);
        let raw = hdr + sec;
        let rel = raw + code.len();
        let symptr = rel + 10 * relocs.len();
        let mut o = vec![];
        o.extend(0x14cu16.to_le_bytes());
        o.extend(1u16.to_le_bytes());
        o.extend(0u32.to_le_bytes());
        o.extend((symptr as u32).to_le_bytes());
        o.extend((syms.len() as u32).to_le_bytes());
        o.extend([0u8; 4]);
        let mut name = b".text".to_vec();
        name.resize(8, 0);
        o.extend(name);
        for v in [0u32, 0, code.len() as u32, raw as u32, rel as u32, 0] {
            o.extend(v.to_le_bytes());
        }
        o.extend((relocs.len() as u16).to_le_bytes());
        o.extend(0u16.to_le_bytes());
        o.extend(0x6050_0020u32.to_le_bytes());
        o.extend(code);
        for &(off, si, typ) in relocs {
            o.extend(off.to_le_bytes());
            o.extend(si.to_le_bytes());
            o.extend(typ.to_le_bytes());
        }
        for &(n, value, secnum, cls) in syms {
            let mut f = n.as_bytes().to_vec();
            f.resize(8, 0);
            o.extend(f);
            o.extend(value.to_le_bytes());
            o.extend(secnum.to_le_bytes());
            o.extend((if cls == 2 && secnum > 0 { 0x20u16 } else { 0 }).to_le_bytes());
            o.extend([cls, 0]);
        }
        o.extend(4u32.to_le_bytes());
        o
    }

    /// An archive of these named members (no linker member).
    pub fn archive(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut out = b"!<arch>\n".to_vec();
        for (n, d) in members {
            out.extend(member(format!("{n}/").as_bytes(), d));
        }
        out
    }

    pub fn build(comp_ids: &[(u32, u32)]) -> Vec<u8> {
        let mut out = b"!<arch>\n".to_vec();
        // the linker member: 2 symbols of member offsets (unused here)
        let mut lm = 2u32.to_be_bytes().to_vec();
        lm.extend([0u8; 8]);
        lm.extend(b"_first\0_second\0");
        out.extend(member(b"/", &lm));
        out.extend(member(b"//", b"a_rather_long_member_name.obj\0"));
        for (k, &(p, b)) in comp_ids.iter().enumerate() {
            let name = if k == 0 { b"/0".to_vec() } else { format!("o{k}.obj/").into_bytes() };
            out.extend(member(&name, &comp_obj(p, b)));
        }
        // an import member: _GetTickCount@0 of KERNEL32.dll, by name without decoration (type 3 << 2)
        let mut im = vec![0u8, 0, 0xff, 0xff];
        im.extend([0u8; 12]);
        im.extend(7u16.to_le_bytes());
        im.extend((3u16 << 2).to_le_bytes());
        im.extend(b"_GetTickCount@0\0KERNEL32.dll\0");
        out.extend(member(b"k32.obj/", &im));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archives() {
        let a = testlib::build(&[(0x30, 9044), (0x0a, 8047), (0x30, 9044)]);
        let members = archive_members(&a).unwrap();
        let names: Vec<&str> = members.iter().map(|m| m.0.as_str()).collect();
        assert_eq!(names, ["a_rather_long_member_name.obj", "o1.obj", "o2.obj", "k32.obj"]);
        assert_eq!(archive_symbol_table(&a).unwrap(), ["_first", "_second"]);
        let objs = archive_objects(&a).unwrap();
        assert_eq!(objs.len(), 3);
        assert_eq!(objs[0].name, "a_rather_long_member_name.obj");
        let ids = comp_ids(&objs);
        assert_eq!(ids.into_iter().collect::<Vec<_>>(), [((0x0a << 16) | 8047, 1), ((0x30 << 16) | 9044, 2)]);
        assert_eq!(import_symbols(&a).unwrap(), [("_GetTickCount@0".to_string(), "KERNEL32.dll".to_string(), "GetTickCount".to_string())]);
        assert!(archive_members(b"MZ").is_err());
    }

    #[test]
    fn alias_objects_parse_back() {
        let o = Obj::parse(&alias_object(&[("_a".into(), "_canonical_target".into()), ("_b".into(), "_canonical_target".into())])).unwrap();
        let names: Vec<&str> = o.symbols.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["_a", "_b", "_canonical_target"]);
        assert_eq!((o.symbols[0].cls, o.symbols[2].cls, o.symbols[2].external()), (105, 2, true));
        let s = Symbol { index: 0, name: "__imp__Sleep@4".into(), value: 0, secnum: 0, typ: 0, cls: 2 };
        assert!(s.unresolved() && s.dllimport() && s.imported() == Some("_Sleep@4") && s.key("x.obj") == "__imp__Sleep@4");
        let c = Symbol { index: 0, name: "??_C@_05hello".into(), value: 0, secnum: 1, typ: 0, cls: 2 };
        assert_eq!(c.key("x.obj"), "x.obj:??_C@_05hello");
    }
}

#[cfg(test)]
mod reloc_tests {
    use super::*;

    #[test]
    fn reloc_view() {
        let r = |typ| Reloc { offset: 0, symbol_index: 0, typ };
        assert_eq!((r(0x06).kind_width(), r(0x14).kind_width().0, r(0x07).kind_width().0), ((ABSOLUTE, 4), RELATIVE, ABSOLUTE_RVA));
        assert_eq!(r(0x0b).kind_width(), (0, 0)); // SECREL: no image bytes
        let site = 0x401010u32;
        // absolute: the image holds target + addend
        assert_eq!(r(0x06).resolve(site, &0x405008u32.to_le_bytes(), 8), Some(0x405000));
        // relative: the image holds target - (site + 4) + addend
        let disp = 0x402000u32.wrapping_sub(site + 4);
        assert_eq!(r(0x14).resolve(site, &disp.to_le_bytes(), 0), Some(0x402000));
        assert_eq!(r(0x07).resolve(site, &[0, 0, 0, 0], 0), None);
    }

    #[test]
    fn section_mask_and_addend() {
        let data: Vec<u8> = [&[0xe8u8][..], &(-4i32).to_le_bytes(), &[0xa1], &0x10u32.to_le_bytes(), &[0xc3]].concat();
        let relocs = vec![Reloc { offset: 1, symbol_index: 0, typ: 0x14 }, Reloc { offset: 6, symbol_index: 0, typ: 0x06 }, Reloc { offset: 0, symbol_index: 0, typ: 0x0b }];
        let sec = Section { name: ".text".into(), chars: 0x6000_0020, size: data.len() as u32, data: Some(data), relocs: relocs.clone(), syms: vec![] };
        assert_eq!(sec.mask(), [0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0]);
        let obj = Obj { name: String::new(), sections: vec![Section { name: String::new(), chars: 0, data: None, size: 0, relocs: vec![], syms: vec![] }, sec],
                        symbols: vec![], by_index: Default::default() };
        assert_eq!((obj.addend(1, &relocs[1]), obj.addend(1, &relocs[0])), (0x10, 0xffff_fffc));
    }
}
