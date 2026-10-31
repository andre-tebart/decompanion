//! PE32 images, as image/base.py and image/pe32.py read them: the sections, `read` (bytes without file backing
//! read as zero, like the loader maps them) and the absolute base-relocation sites.

pub struct Section {
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
    pub fn holds_code(&self) -> bool {
        self.chars & 0x20 != 0 || self.chars & 0x2000_0000 != 0
    }
}

pub struct Image {
    pub data: Vec<u8>,
    pub base: u32,
    pub headers_size: u32,
    pub image_size: u32,
    pub sections: Vec<Section>,
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
        let nsec = u16_at(d, pe + 6) as usize;
        let optsz = u16_at(d, pe + 20) as usize;
        let opt = pe + 24;
        if u16_at(d, opt) != 0x10b {
            return Err("optional header is not PE32".into());
        }
        let base = u32_at(d, opt + 28);
        let image_size = u32_at(d, opt + 56);
        let headers_size = u32_at(d, opt + 60);
        let ndirs = u32_at(d, opt + 92) as usize;
        let reloc_dir = if ndirs > 5 {
            let rva = u32_at(d, opt + 96 + 8 * 5);
            let size = u32_at(d, opt + 96 + 8 * 5 + 4);
            if rva != 0 { Some((base + rva, size)) } else { None }
        } else {
            None
        };
        let table = opt + optsz;
        let mut sections = Vec::with_capacity(nsec);
        for k in 0..nsec {
            let h = table + 40 * k;
            sections.push(Section {
                vsize: u32_at(d, h + 8),
                va: base + u32_at(d, h + 12),
                raw_size: u32_at(d, h + 16),
                raw_off: u32_at(d, h + 20),
                chars: u32_at(d, h + 36),
            });
        }
        Ok(Image { data, base, headers_size, image_size, sections, reloc_dir })
    }

    pub fn end(&self) -> u32 {
        self.base.wrapping_add(self.image_size)
    }

    pub fn section_of(&self, va: u32) -> Option<&Section> {
        self.sections.iter().find(|s| s.va <= va && va < s.end())
    }

    /// The file offset of a VA and the file bytes available from there, None without file backing.
    fn off(&self, va: u32) -> Option<(usize, usize)> {
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
