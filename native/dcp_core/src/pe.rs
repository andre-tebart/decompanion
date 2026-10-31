//! PE32 images, as image/base.py and image/pe32.py read them: the headers and sections, `read` (bytes without
//! file backing read as zero, like the loader maps them), the absolute base-relocation sites, the data
//! directories, the imports and exports with the byte ranges of their machinery, the Rich header.

use std::collections::HashMap;

pub struct Section {
    pub index: usize,
    pub name: String, // the table's 8 bytes up to the first NUL, latin-1
    pub va: u32,
    pub vsize: u32,
    pub raw_off: u32,
    pub raw_size: u32,
    pub chars: u32,
}

impl Section {
    pub fn end(&self) -> u32 {
        self.va + self.vsize.max(self.raw_size)
    }
    pub fn uninitialized(&self) -> bool {
        self.chars & 0x80 != 0
    }
    /// The file bytes of the section (its raw data, as far as the file holds it).
    pub fn holds_code(&self) -> bool {
        self.code() || self.executable()
    }
    pub fn code(&self) -> bool {
        self.chars & 0x20 != 0
    }
    pub fn executable(&self) -> bool {
        self.chars & 0x2000_0000 != 0
    }
    pub fn writable(&self) -> bool {
        self.chars & 0x8000_0000 != 0
    }
}

pub struct Image {
    pub data: Vec<u8>,
    pub base: u32,
    pub headers_size: u32,
    pub image_size: u32,
    pub sections: Vec<Section>,
    pub entry: u32, // VA of the entry point, 0 when none
    pub machine: u16,
    pub timestamp: u32,
    pub file_chars: u16,
    pub is_dll: bool,
    pub subsystem: u16,
    pub linker_version: (u8, u8),
    pub directories: Vec<Directory>,
    pe: usize, // the PE signature's file offset (the Rich header lies before it)
    reloc_dir: Option<(u32, u32)>,
}

fn u16_at(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([d[o], d[o + 1]])
}

fn u32_at(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}

impl Image {
    pub fn parse(data: Vec<u8>) -> Result<Image, String> {
        let d = &data;
        if d.len() < 0x40 || &d[..2] != b"MZ" {
            return Err("no MZ header".into());
        }
        let pe = u32_at(d, 0x3c) as usize;
        if d.len() < pe + 24 || &d[pe..pe + 4] != b"PE\0\0" {
            return Err(format!("no PE signature at {pe:#x}"));
        }
        let machine = u16_at(d, pe + 4);
        let nsec = u16_at(d, pe + 6) as usize;
        let timestamp = u32_at(d, pe + 8);
        let optsz = u16_at(d, pe + 20) as usize;
        let file_chars = u16_at(d, pe + 22);
        let opt = pe + 24;
        if u16_at(d, opt) != 0x10b {
            return Err("optional header is not PE32".into());
        }
        let linker_version = (d[opt + 2], d[opt + 3]);
        let entry_rva = u32_at(d, opt + 16);
        let base = u32_at(d, opt + 28);
        let image_size = u32_at(d, opt + 56);
        let headers_size = u32_at(d, opt + 60);
        let subsystem = u16_at(d, opt + 68);
        let ndirs = u32_at(d, opt + 92) as usize;
        let directories: Vec<Directory> = (0..ndirs.min(16))
            .map(|i| {
                let (rva, size) = (u32_at(d, opt + 96 + 8 * i), u32_at(d, opt + 100 + 8 * i));
                Directory { index: i, name: DIRECTORY_NAMES[i], va: if rva != 0 { base.wrapping_add(rva) } else { 0 }, size }
            })
            .collect();
        let reloc_dir = directories.get(5).filter(|dd| dd.va != 0).map(|dd| (dd.va, dd.size));
        let table = opt + optsz;
        let mut sections = Vec::with_capacity(nsec);
        for k in 0..nsec {
            let h = table + 40 * k;
            let raw_name = &d[h..h + 8];
            let name_end = raw_name.iter().rposition(|&c| c != 0).map(|i| i + 1).unwrap_or(0);
            sections.push(Section {
                index: k,
                name: raw_name[..name_end].iter().map(|&c| c as char).collect(),
                vsize: u32_at(d, h + 8),
                va: base + u32_at(d, h + 12),
                raw_size: u32_at(d, h + 16),
                raw_off: u32_at(d, h + 20),
                chars: u32_at(d, h + 36),
            });
        }
        let entry = if entry_rva != 0 { base.wrapping_add(entry_rva) } else { 0 };
        Ok(Image { data, base, headers_size, image_size, sections, entry, machine, timestamp, file_chars, is_dll: file_chars & 0x2000 != 0,
                   subsystem, linker_version, directories, pe, reloc_dir })
    }

    pub fn end(&self) -> u32 {
        self.base.wrapping_add(self.image_size)
    }

    pub fn section_of(&self, va: u32) -> Option<&Section> {
        self.sections.iter().find(|s| s.va <= va && va < s.end())
    }

    /// The file offset of a VA and the file bytes available from there, None without file backing.
    pub fn off(&self, va: u32) -> Option<(usize, usize)> {
        match self.section_of(va) {
            None => {
                if self.base <= va && va < self.base + self.headers_size {
                    let o = (va - self.base) as usize;
                    Some((o, self.headers_size as usize - o))
                } else {
                    None
                }
            }
            Some(s) => {
                let o = va - s.va;
                if o >= s.raw_size {
                    None
                } else {
                    Some(((s.raw_off + o) as usize, (s.raw_size - o) as usize))
                }
            }
        }
    }

    /// n bytes at va as a slice of the file when they all lie in one section's file data (the common case),
    /// else read() (zeros without file backing, several sections).
    pub fn bytes(&self, va: u32, n: usize) -> std::borrow::Cow<'_, [u8]> {
        if let Some((o, avail)) = self.off(va) {
            if n <= avail && o + n <= self.data.len() {
                return std::borrow::Cow::Borrowed(&self.data[o..o + n]);
            }
        }
        std::borrow::Cow::Owned(self.read(va, n))
    }

    /// n bytes at va, bytes without file backing as zero.
    pub fn read(&self, mut va: u32, mut n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        while n > 0 {
            match self.off(va) {
                None => {
                    out.push(0);
                    va = va.wrapping_add(1);
                    n -= 1;
                }
                Some((o, avail)) => {
                    let k = n.min(avail);
                    // a section running past the file end gives fewer bytes, as Python's slice does
                    let end = (o + k).min(self.data.len());
                    out.extend_from_slice(&self.data[o.min(end)..end]);
                    va = va.wrapping_add(k as u32);
                    n -= k;
                }
            }
        }
        out
    }

    /// The sorted IMAGE_REL_BASED_HIGHLOW sites of the base-relocation directory (empty without one).
    pub fn relocations(&self) -> Vec<u32> {
        let mut out = Vec::new();
        let Some((va, size)) = self.reloc_dir else { return out };
        let (mut p, end) = (va, va + size);
        while p + 8 <= end {
            let h = self.read(p, 8);
            let page = u32_at(&h, 0);
            let block = u32_at(&h, 4);
            if block < 8 {
                break;
            }
            let entries = self.read(p + 8, (block - 8) as usize);
            let mut i = 0;
            while i + 1 < entries.len() {
                let e = entries[i] as u32 | (entries[i + 1] as u32) << 8;
                if e >> 12 == 3 {
                    out.push(self.base.wrapping_add(page).wrapping_add(e & 0xfff));
                }
                i += 2;
            }
            p += block;
        }
        out.sort_unstable();
        out
    }
}

impl Image {
    /// Image.section_data: the file bytes of a section (its raw data, without the zero tail the loader adds).
    pub fn section_data(&self, s: &Section) -> &[u8] {
        let a = (s.raw_off as usize).min(self.data.len());
        let b = (s.raw_off as usize + s.raw_size as usize).min(self.data.len());
        &self.data[a..b]
    }
}

// ------------------------------------------------------------------------------------------------ the format's tables

pub const DIRECTORY_NAMES: [&str; 16] = ["export", "import", "resource", "exception", "security", "basereloc", "debug", "architecture",
                                         "globalptr", "tls", "load_config", "bound_import", "iat", "delay_import", "com_descriptor", "reserved"];
/// The directories S.imports / S.exports walk themselves (import, export, iat) or that lie outside the mapped image
/// (security: a file offset, not an RVA).
const NOT_REGIONS: [&str; 4] = ["import", "export", "iat", "security"];

/// An import: the DLL, the name (None by ordinal), the ordinal (None by name), the VA of its address-table slot,
/// the hint stored with a name.
#[derive(Clone, Debug, PartialEq)]
pub struct Import {
    pub dll: String,
    pub name: Option<String>,
    pub ordinal: Option<u32>,
    pub slot: u32,
    pub hint: Option<u16>,
}

impl Import {
    /// DLL!name or DLL!#ordinal
    pub fn label(&self) -> String {
        match &self.name {
            Some(n) => format!("{}!{n}", self.dll),
            None => format!("{}!#{}", self.dll, self.ordinal.unwrap_or(0)),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Export {
    pub ordinal: u32,
    pub name: Option<String>,
    pub va: u32,
    pub forwarder: Option<String>,
}

/// A data directory: (index, name, VA or 0, size).
#[derive(Clone, Debug, PartialEq)]
pub struct Directory {
    pub index: usize,
    pub name: &'static str,
    pub va: u32,
    pub size: u32,
}

/// (what, lo, hi): a region of the format's own machinery.
pub type Region = (String, u32, u32);

fn latin1(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

impl Image {
    pub fn u16(&self, va: u32) -> u16 {
        let b = self.read(va, 2);
        u16::from_le_bytes([b[0], b[1]])
    }

    pub fn u32(&self, va: u32) -> u32 {
        let b = self.read(va, 4);
        u32_at(&b, 0)
    }

    /// The address stored at va.
    pub fn read_ptr(&self, va: u32) -> u32 {
        self.u32(va)
    }

    /// The bytes from va up to a NUL (at most `limit`), as the file holds them; empty without file backing.
    pub fn cstr_n(&self, va: u32, limit: usize) -> &[u8] {
        let Some((o, _)) = self.off(va) else { return &[] };
        let end = (o + limit).min(self.data.len());
        let o = o.min(end);
        match memchr::memchr(0, &self.data[o..end]) {
            Some(k) => &self.data[o..o + k],
            None => &self.data[o..end],
        }
    }

    pub fn cstr(&self, va: u32) -> &[u8] {
        self.cstr_n(va, 4096)
    }

    pub fn in_image(&self, va: u32) -> bool {
        self.base <= va && va < self.end()
    }

    /// dll (the DLL characteristic), gui (subsystem 2), console (3), else exe.
    pub fn kind(&self) -> &'static str {
        if self.is_dll {
            "dll"
        } else {
            match self.subsystem {
                2 => "gui",
                3 => "console",
                _ => "exe",
            }
        }
    }

    pub fn directory(&self, name: &str) -> Option<&Directory> {
        self.directories.iter().find(|d| d.name == name && d.va != 0)
    }

    /// The Rich header's file range [DanS, after the key); None without one.
    fn rich_span(&self) -> Option<(usize, usize, u32)> {
        let d = &self.data[..self.pe.min(self.data.len())];
        let i = memchr::memmem::find(d, b"Rich")?;
        if i + 8 > d.len() {
            return None;
        }
        let key = u32_at(d, i + 4);
        let mut j = i as isize - 4;
        while j >= 0 {
            if u32_at(d, j as usize) ^ key == 0x536e6144 {
                return Some((j as usize, i, key));
            }
            j -= 4;
        }
        None
    }

    /// (product id, build, count) of the Rich header's entries in file order; empty without one.
    pub fn rich(&self) -> Vec<(u32, u32, u32)> {
        let Some((start, i, key)) = self.rich_span() else { return vec![] };
        let d = &self.data;
        let mut out = vec![];
        let mut p = start + 16; // DanS and three padding dwords
        while p + 8 <= i {
            let a = u32_at(d, p) ^ key;
            let b = u32_at(d, p + 4) ^ key;
            out.push((a >> 16, a & 0xffff, b));
            p += 8;
        }
        out
    }

    pub fn rich_range(&self) -> Option<(u32, u32)> {
        let (start, i, _) = self.rich_span()?;
        Some((self.base + start as u32, self.base + i as u32 + 8))
    }

    /// pe.header over [base, base + SizeOfHeaders), and pe.rich where the linker wrote a Rich header.
    pub fn header_regions(&self) -> Vec<Region> {
        let (lo, hi) = (self.base, self.base + self.headers_size);
        match self.rich_range() {
            Some((a, b)) => {
                let mut out: Vec<Region> = [(lo, a), (b, hi)].iter().filter(|(x, y)| y > x).map(|&(x, y)| ("pe.header".to_string(), x, y)).collect();
                out.push(("pe.rich".to_string(), a, b));
                out
            }
            None => vec![("pe.header".to_string(), lo, hi)],
        }
    }

    /// pe.<directory> for every directory with an address and a size inside a section, but import / export / iat
    /// / security.
    pub fn directory_regions(&self) -> Vec<Region> {
        self.directories
            .iter()
            .filter(|d| d.va != 0 && d.size != 0 && !NOT_REGIONS.contains(&d.name) && self.section_of(d.va).is_some())
            .map(|d| (format!("pe.{}", d.name), d.va, d.va + d.size))
            .collect()
    }

    pub fn imports(&self) -> Vec<Import> {
        let Some(dd) = self.directory("import") else { return vec![] };
        let mut out = vec![];
        let mut desc = dd.va;
        loop {
            let b = self.read(desc, 20);
            let (ilt, name, iat) = (u32_at(&b, 0), u32_at(&b, 12), u32_at(&b, 16));
            if name == 0 && iat == 0 {
                break;
            }
            let dll = latin1(self.cstr(self.base.wrapping_add(name)));
            let lookup = self.base.wrapping_add(if ilt != 0 { ilt } else { iat });
            let slot = self.base.wrapping_add(iat);
            let mut k = 0u32;
            loop {
                let e = self.u32(lookup.wrapping_add(4 * k));
                if e == 0 {
                    break;
                }
                if e & 0x8000_0000 != 0 {
                    out.push(Import { dll: dll.clone(), name: None, ordinal: Some(e & 0xffff), slot: slot + 4 * k, hint: None });
                } else {
                    let hn = self.base.wrapping_add(e);
                    out.push(Import { dll: dll.clone(), name: Some(latin1(self.cstr(hn + 2))), ordinal: None, slot: slot + 4 * k, hint: Some(self.u16(hn)) });
                }
                k += 1;
            }
            desc += 20;
        }
        out
    }

    /// The import machinery's byte ranges: pe.import_desc, pe.ilt, pe.iat, pe.names.
    pub fn import_ranges(&self) -> HashMap<&'static str, Vec<(u32, u32)>> {
        let mut out: HashMap<&'static str, Vec<(u32, u32)>> = ["pe.import_desc", "pe.ilt", "pe.iat", "pe.names"].iter().map(|k| (*k, vec![])).collect();
        let Some(dd) = self.directory("import") else { return out };
        let desc = dd.va;
        let mut n = 0u32;
        loop {
            let b = self.read(desc + 20 * n, 20);
            let (ilt, name, iat) = (u32_at(&b, 0), u32_at(&b, 12), u32_at(&b, 16));
            if name == 0 && iat == 0 {
                break;
            }
            let dn = self.base.wrapping_add(name);
            out.get_mut("pe.names").unwrap().push((dn, dn + self.cstr(dn).len() as u32 + 1));
            for (key, rva) in [("pe.ilt", ilt), ("pe.iat", iat)] {
                if rva == 0 {
                    continue;
                }
                let t = self.base.wrapping_add(rva);
                let mut k = 0u32;
                loop {
                    let e = self.u32(t + 4 * k);
                    if e == 0 {
                        break;
                    }
                    if e & 0x8000_0000 == 0 && key == "pe.ilt" {
                        let hn = self.base.wrapping_add(e);
                        out.get_mut("pe.names").unwrap().push((hn, hn + 2 + self.cstr(hn + 2).len() as u32 + 1));
                    }
                    k += 1;
                }
                out.get_mut(key).unwrap().push((t, t + 4 * (k + 1)));
            }
            n += 1;
        }
        out.get_mut("pe.import_desc").unwrap().push((desc, desc + 20 * (n + 1)));
        out
    }

    /// pe.import_desc, pe.ilt, pe.names (sorted, once each), pe.iat (each address table's terminating slot).
    pub fn import_regions(&self) -> Vec<Region> {
        let r = self.import_ranges();
        let mut out: Vec<Region> = vec![];
        for key in ["pe.import_desc", "pe.ilt"] {
            out.extend(r[key].iter().map(|&(a, b)| (key.to_string(), a, b)));
        }
        let names: std::collections::BTreeSet<(u32, u32)> = r["pe.names"].iter().copied().collect();
        out.extend(names.into_iter().map(|(a, b)| ("pe.names".to_string(), a, b)));
        out.extend(r["pe.iat"].iter().map(|&(_, b)| ("pe.iat".to_string(), b - 4, b)));
        out
    }

    fn export_header(&self) -> Option<(u32, [u32; 7])> {
        let dd = self.directory("export")?;
        let b = self.read(dd.va, 40);
        // name, ordinal base, functions, names, address table, name table, ordinal table
        Some((dd.va, [u32_at(&b, 12), u32_at(&b, 16), u32_at(&b, 20), u32_at(&b, 24), u32_at(&b, 28), u32_at(&b, 32), u32_at(&b, 36)]))
    }

    pub fn exports(&self) -> Vec<Export> {
        let Some(dd) = self.directory("export").cloned() else { return vec![] };
        let Some((_, [_, obase, nfunc, nnames, eat, ent, eot])) = self.export_header() else { return vec![] };
        let mut names: HashMap<u32, String> = HashMap::new();
        for i in 0..nnames {
            let nr = self.u32(self.base.wrapping_add(ent) + 4 * i);
            let oi = self.u16(self.base.wrapping_add(eot) + 2 * i) as u32;
            names.insert(oi, latin1(self.cstr(self.base.wrapping_add(nr))));
        }
        let mut out = vec![];
        for i in 0..nfunc {
            let rva = self.u32(self.base.wrapping_add(eat) + 4 * i);
            if rva == 0 {
                continue;
            }
            let va = self.base.wrapping_add(rva);
            let forwarder = (dd.va <= va && va < dd.va + dd.size).then(|| latin1(self.cstr(va)));
            out.push(Export { ordinal: obase + i, name: names.get(&i).cloned(), va, forwarder });
        }
        out
    }

    /// The export machinery's byte ranges: pe.export_dir, pe.eat, pe.ent, pe.eot, pe.names.
    pub fn export_ranges(&self) -> HashMap<&'static str, Vec<(u32, u32)>> {
        let mut out: HashMap<&'static str, Vec<(u32, u32)>> =
            ["pe.export_dir", "pe.eat", "pe.ent", "pe.eot", "pe.names"].iter().map(|k| (*k, vec![])).collect();
        let Some((e, [name, _, nfunc, nnames, eat, ent, eot])) = self.export_header() else { return out };
        out.get_mut("pe.export_dir").unwrap().push((e, e + 40));
        let b = self.base;
        out.get_mut("pe.eat").unwrap().push((b.wrapping_add(eat), b.wrapping_add(eat) + 4 * nfunc));
        if nnames != 0 {
            out.get_mut("pe.ent").unwrap().push((b.wrapping_add(ent), b.wrapping_add(ent) + 4 * nnames));
            out.get_mut("pe.eot").unwrap().push((b.wrapping_add(eot), b.wrapping_add(eot) + 2 * nnames));
        }
        let mut vas = vec![b.wrapping_add(name)];
        vas.extend((0..nnames).map(|i| b.wrapping_add(self.u32(b.wrapping_add(ent) + 4 * i))));
        for va in vas {
            out.get_mut("pe.names").unwrap().push((va, va + self.cstr(va).len() as u32 + 1));
        }
        out
    }

    /// pe.export_dir, pe.eat, pe.ent, pe.eot, then pe.names (sorted, once each).
    pub fn export_regions(&self) -> Vec<Region> {
        let r = self.export_ranges();
        let mut out: Vec<Region> = vec![];
        for key in ["pe.export_dir", "pe.eat", "pe.ent", "pe.eot"] {
            out.extend(r[key].iter().map(|&(a, b)| (key.to_string(), a, b)));
        }
        let names: std::collections::BTreeSet<(u32, u32)> = r["pe.names"].iter().copied().collect();
        out.extend(names.into_iter().map(|(a, b)| ("pe.names".to_string(), a, b)));
        out
    }
}

// ------------------------------------------------------------------------------------------------ tests

#[cfg(test)]
pub(crate) mod testpe {
    //! A synthetic PE32 dll for the tests (tests/conftest.py build_pe's, with an import and an export directory):
    //! base 0x10000000; .text 0x1000 (f1 calls f2 and f3, f2 reads a dword of .data, f3 and f4 push strings);
    //! .data 0x2000 (a dword, strings, a pointer to f4; the import and export tables); .reloc 0x3000.
    pub const BASE: u32 = 0x1000_0000;
    pub const TEXT: u32 = 0x1000;
    pub const DATA: u32 = 0x2000;
    pub const RELOC: u32 = 0x3000;

    fn put32(b: &mut [u8], o: usize, v: u32) {
        b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn put16(b: &mut [u8], o: usize, v: u16) {
        b[o..o + 2].copy_from_slice(&v.to_le_bytes());
    }

    /// The Rich header of these entries (prodid, build, count), xor key.
    pub fn rich_header(entries: &[(u32, u32, u32)], key: u32) -> Vec<u8> {
        let mut out = vec![];
        for v in [0x536e6144 ^ key, key, key, key] {
            out.extend(v.to_le_bytes());
        }
        for &(p, b, c) in entries {
            out.extend((((p << 16) | b) ^ key).to_le_bytes());
            out.extend((c ^ key).to_le_bytes());
        }
        out.extend(b"Rich");
        out.extend(key.to_le_bytes());
        out
    }

    pub fn build(rich: Option<&[(u32, u32, u32)]>) -> Vec<u8> {
        let va = |rva: u32| BASE + rva;
        let mut code = vec![0x90u8; 0x60];
        let mut relocs = vec![];
        let f1: Vec<u8> = [&[0x55u8, 0x8b, 0xec, 0xe8][..], &(0x20i32 - 8).to_le_bytes(), &[0xe8], &(0x30i32 - 13).to_le_bytes(), &[0x5d, 0xc3]].concat();
        code[..f1.len()].copy_from_slice(&f1);
        let f2: Vec<u8> = [&[0xa1u8][..], &va(DATA).to_le_bytes(), &[0xc3]].concat();
        code[0x20..0x20 + f2.len()].copy_from_slice(&f2);
        relocs.push(TEXT + 0x21);
        let f3: Vec<u8> = [&[0x68u8][..], &va(DATA + 0x10).to_le_bytes(), &[0x68], &va(DATA + 0x30).to_le_bytes(), &[0x83, 0xc4, 0x08, 0xc3]].concat();
        code[0x30..0x30 + f3.len()].copy_from_slice(&f3);
        relocs.extend([TEXT + 0x31, TEXT + 0x36]);
        let f4: Vec<u8> = [&[0x68u8][..], &va(DATA + 0x38).to_le_bytes(), &[0x58, 0xc3]].concat();
        code[0x50..0x50 + f4.len()].copy_from_slice(&f4);
        relocs.push(TEXT + 0x51);
        // .data: the dword, strings, a pointer to f4; at 0x100 the import tables, at 0x200 the export tables
        let mut data = vec![0u8; 0x300];
        put32(&mut data, 0, 0x1234);
        data[0x10..0x10 + 17].copy_from_slice(b"c:\\src\\net\\net.c\0");
        data[0x30..0x36].copy_from_slice(b"hello\0");
        data[0x38..0x3e].copy_from_slice(b"world\0");
        put32(&mut data, 0x40, va(TEXT + 0x50));
        relocs.push(DATA + 0x40);
        // imports: one descriptor for KERNEL32.dll (by name GetTickCount hint 7, by ordinal 3) and the terminator
        let (desc, ilt, iat, dll, hn) = (0x100usize, 0x140usize, 0x150usize, 0x160usize, 0x170usize);
        put32(&mut data, desc, DATA + ilt as u32);
        put32(&mut data, desc + 12, DATA + dll as u32);
        put32(&mut data, desc + 16, DATA + iat as u32);
        for t in [ilt, iat] {
            put32(&mut data, t, DATA + hn as u32);
            put32(&mut data, t + 4, 0x8000_0003);
        }
        data[dll..dll + 13].copy_from_slice(b"KERNEL32.dll\0");
        put16(&mut data, hn, 7);
        data[hn + 2..hn + 15].copy_from_slice(b"GetTickCount\0");
        // exports: net.dll, ordinal base 1, f1 (named "Start"), f4 (by ordinal only), a forwarder "Fwd"
        let (ed, eat, ent, eot, names) = (0x200usize, 0x230usize, 0x240usize, 0x248usize, 0x250usize);
        put32(&mut data, ed + 12, DATA + names as u32);
        put32(&mut data, ed + 16, 1);
        put32(&mut data, ed + 20, 3);
        put32(&mut data, ed + 24, 2);
        put32(&mut data, ed + 28, DATA + eat as u32);
        put32(&mut data, ed + 32, DATA + ent as u32);
        put32(&mut data, ed + 36, DATA + eot as u32);
        put32(&mut data, eat, TEXT);
        put32(&mut data, eat + 4, TEXT + 0x50);
        put32(&mut data, eat + 8, DATA + names as u32 + 20);       // inside the directory: a forwarder
        put32(&mut data, ent, DATA + names as u32 + 8);
        put32(&mut data, ent + 4, DATA + names as u32 + 14);
        put16(&mut data, eot, 0);
        put16(&mut data, eot + 2, 2);
        data[names..names + 8].copy_from_slice(b"net.dll\0");
        data[names + 8..names + 14].copy_from_slice(b"Start\0");
        data[names + 14..names + 18].copy_from_slice(b"Fwd\0");
        data[names + 20..names + 30].copy_from_slice(b"K32.Sleep\0");
        let export_size = (names + 30 - ed) as u32;
        // .reloc: one block per page
        let mut blocks = vec![];
        let mut pages: Vec<u32> = relocs.iter().map(|r| r & !0xfff).collect();
        pages.sort();
        pages.dedup();
        for page in pages {
            let mut ents: Vec<u16> = relocs.iter().filter(|r| *r & !0xfff == page).map(|r| (3 << 12) | (r & 0xfff) as u16).collect();
            if ents.len() % 2 == 1 {
                ents.push(0);
            }
            blocks.extend(page.to_le_bytes());
            blocks.extend((8 + 2 * ents.len() as u32).to_le_bytes());
            for e in ents {
                blocks.extend(e.to_le_bytes());
            }
        }
        let secs: [(&[u8; 8], u32, Vec<u8>, u32); 3] =
            [(b".text\0\0\0", TEXT, code, 0x6000_0020), (b".data\0\0\0", DATA, data, 0xC000_0040), (b".reloc\0\0", RELOC, blocks.clone(), 0x4200_0040)];
        let (falign, hdr) = (0x200usize, 0x400usize);
        let mut raw = vec![];
        let mut off = hdr;
        for (name, rva, body, ch) in &secs {
            let rs = body.len().div_ceil(falign) * falign;
            raw.push((*name, *rva, body.clone(), *ch, off, rs));
            off += rs;
        }
        let mut out = vec![0u8; off];
        out[0..2].copy_from_slice(b"MZ");
        let mut pe = 0x80usize;
        if let Some(r) = rich {
            let h = rich_header(r, 0x1234abcd);
            out[0x80..0x80 + h.len()].copy_from_slice(&h);
            pe = (0x80 + h.len() + 0xf) & !0xf;
        }
        put32(&mut out, 0x3c, pe as u32);
        out[pe..pe + 4].copy_from_slice(b"PE\0\0");
        put16(&mut out, pe + 4, 0x14c);
        put16(&mut out, pe + 6, secs.len() as u16);
        put32(&mut out, pe + 8, 0x3f7a0000);
        put16(&mut out, pe + 20, 0xE0);
        put16(&mut out, pe + 22, 0x2102);
        let opt = pe + 24;
        put16(&mut out, opt, 0x10b);
        out[opt + 2] = 6;
        put32(&mut out, opt + 16, TEXT); // entry: f1
        put32(&mut out, opt + 28, BASE);
        put32(&mut out, opt + 32, 0x1000);
        put32(&mut out, opt + 36, falign as u32);
        put32(&mut out, opt + 56, RELOC + 0x1000);
        put32(&mut out, opt + 60, hdr as u32);
        put16(&mut out, opt + 68, 2);
        put32(&mut out, opt + 92, 16);
        let dd = opt + 96;
        put32(&mut out, dd, DATA + ed as u32);
        put32(&mut out, dd + 4, export_size);
        put32(&mut out, dd + 8, DATA + desc as u32);
        put32(&mut out, dd + 12, 40);
        put32(&mut out, dd + 8 * 5, RELOC);
        put32(&mut out, dd + 8 * 5 + 4, blocks.len() as u32);
        put32(&mut out, dd + 8 * 12, DATA + iat as u32);
        put32(&mut out, dd + 8 * 12 + 4, 12);
        let st = opt + 0xE0;
        for (k, (name, rva, body, ch, roff, rs)) in raw.iter().enumerate() {
            let h = st + 40 * k;
            out[h..h + 8].copy_from_slice(&name[..]);
            put32(&mut out, h + 8, body.len() as u32);
            put32(&mut out, h + 12, *rva);
            put32(&mut out, h + 16, *rs as u32);
            put32(&mut out, h + 20, *roff as u32);
            put32(&mut out, h + 36, *ch);
            out[*roff..*roff + body.len()].copy_from_slice(body);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::testpe::*;
    use super::*;

    fn img(rich: bool) -> Image {
        Image::parse(build(rich.then_some(&[(0x30, 9044, 3), (0x0a, 8047, 5), (0x04, 8447, 1)][..]))).unwrap()
    }

    #[test]
    fn headers_and_sections() {
        let i = img(false);
        assert_eq!((i.base, i.entry, i.machine, i.kind(), i.is_dll), (BASE, BASE + TEXT, 0x14c, "dll", true));
        let names: Vec<&str> = i.sections.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, [".text", ".data", ".reloc"]);
        assert!(i.sections[0].code() && i.sections[0].executable() && !i.sections[1].holds_code() && i.sections[1].writable());
        assert_eq!(i.header_regions(), vec![("pe.header".to_string(), BASE, BASE + 0x400)]);
        assert_eq!(i.cstr(BASE + DATA + 0x30), b"hello");
        assert_eq!(i.read_ptr(BASE + DATA + 0x40), BASE + TEXT + 0x50);
        assert_eq!(i.relocations(), vec![BASE + TEXT + 0x21, BASE + TEXT + 0x31, BASE + TEXT + 0x36, BASE + TEXT + 0x51, BASE + DATA + 0x40]);
        // basereloc is a region of its own; import, export and iat are walked by their rules
        assert_eq!(i.directory_regions(), vec![("pe.basereloc".to_string(), BASE + RELOC, BASE + RELOC + 0x1c)]);
    }

    #[test]
    fn rich_header() {
        let i = img(true);
        assert_eq!(i.rich(), vec![(0x30, 9044, 3), (0x0a, 8047, 5), (0x04, 8447, 1)]);
        let (a, b) = i.rich_range().unwrap();
        assert_eq!((a, b), (BASE + 0x80, BASE + 0x80 + 16 + 24 + 8));
        let r = i.header_regions();
        assert_eq!(r[0], ("pe.header".to_string(), BASE, a));
        assert_eq!(r[1], ("pe.header".to_string(), b, BASE + 0x400));
        assert_eq!(r[2], ("pe.rich".to_string(), a, b));
        assert!(img(false).rich().is_empty());
    }

    #[test]
    fn imports() {
        let i = img(false);
        let im = i.imports();
        assert_eq!(im.len(), 2);
        assert_eq!(im[0], Import { dll: "KERNEL32.dll".into(), name: Some("GetTickCount".into()), ordinal: None, slot: BASE + DATA + 0x150, hint: Some(7) });
        assert_eq!((im[1].label(), im[1].slot), ("KERNEL32.dll!#3".to_string(), BASE + DATA + 0x154));
        let r = i.import_regions();
        let d = BASE + DATA;
        assert_eq!(r, vec![
            ("pe.import_desc".to_string(), d + 0x100, d + 0x128),
            ("pe.ilt".to_string(), d + 0x140, d + 0x14c),
            ("pe.names".to_string(), d + 0x160, d + 0x16d),
            ("pe.names".to_string(), d + 0x170, d + 0x17f),
            ("pe.iat".to_string(), d + 0x158, d + 0x15c),
        ]);
    }

    #[test]
    fn exports() {
        let i = img(false);
        let d = BASE + DATA;
        let ex = i.exports();
        assert_eq!(ex, vec![
            Export { ordinal: 1, name: Some("Start".into()), va: BASE + TEXT, forwarder: None },
            Export { ordinal: 2, name: None, va: BASE + TEXT + 0x50, forwarder: None },
            Export { ordinal: 3, name: Some("Fwd".into()), va: d + 0x264, forwarder: Some("K32.Sleep".into()) },
        ]);
        let r = i.export_regions();
        assert_eq!(r[..4], [
            ("pe.export_dir".to_string(), d + 0x200, d + 0x228),
            ("pe.eat".to_string(), d + 0x230, d + 0x23c),
            ("pe.ent".to_string(), d + 0x240, d + 0x248),
            ("pe.eot".to_string(), d + 0x248, d + 0x24c),
        ]);
        assert_eq!(r[4..], [
            ("pe.names".to_string(), d + 0x250, d + 0x258),
            ("pe.names".to_string(), d + 0x258, d + 0x25e),
            ("pe.names".to_string(), d + 0x25e, d + 0x262),
        ]);
    }
}
