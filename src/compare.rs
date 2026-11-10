//! One compiled function against the original's bytes (masked byte compare, the
//! tail check, the DLL aid of the base relocations).

use crate::coff::{FunctionCode, ABSOLUTE};
use crate::pe::Image;

pub struct Compared {
    pub size: usize,
    pub diffs: Vec<u32>,
    pub tail_ok: bool,
    pub tail: (u32, u32),
    pub abs_ours: usize,
    pub abs_image: Option<usize>,
    pub sites_ok: bool,
    pub missing_sites: Vec<u32>,
}

/// The fill forms longest first (stable among equal lengths): the
/// order is_fill tries them in.
pub fn fill_order(forms: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut fs: Vec<Vec<u8>> = forms.to_vec();
    fs.sort_by(|a, b| b.len().cmp(&a.len()));
    fs
}

/// Every byte of data belongs to a run of the fill forms (`fs` in fill_order, greedy); empty: true.
pub fn is_fill(data: &[u8], fs: &[Vec<u8>]) -> bool {
    let mut i = 0;
    while i < data.len() {
        match fs.iter().find(|f| !f.is_empty() && data[i..].starts_with(f)) {
            Some(f) => i += f.len(),
            None => {
                // an empty form matches without advancing: skipped (VC6 has none)
                return false;
            }
        }
    }
    true
}

/// `forms`: the fill forms in fill_order.
pub fn compare(img: &Image, code: &FunctionCode, addr: u32, reloc_sites: Option<&[u32]>, next_start: u32, forms: &[Vec<u8>]) -> Compared {
    let n = code.data.len();
    let orig = img.bytes(addr, n);
    let diffs = (0..n)
        .filter(|&k| code.mask.get(k).copied().unwrap_or(0) == 0 && Some(&code.data[k]) != orig.get(k))
        .map(|k| k as u32)
        .collect();
    let end = addr.wrapping_add(n as u32);
    let (mut tail_ok, mut tail) = (true, (0u32, 0u32));
    if next_start > end {
        tail = (end, next_start);
        tail_ok = is_fill(&img.bytes(end, (next_start - end) as usize), forms);
    } else if next_start < end {
        tail = (next_start, end);
        tail_ok = false;
    }
    let abs_sites: Vec<u32> = code
        .relocs
        .iter()
        .filter(|(_, r)| r.kind_width().0 == ABSOLUTE)
        .map(|(off, _)| addr.wrapping_add(*off))
        .collect();
    let mut c = Compared {
        size: n,
        diffs,
        tail_ok,
        tail,
        abs_ours: abs_sites.len(),
        abs_image: None,
        sites_ok: true,
        missing_sites: vec![],
    };
    if let Some(sites) = reloc_sites {
        let lo = sites.partition_point(|&s| s < addr);
        let hi = sites.partition_point(|&s| s < end);
        c.abs_image = Some(hi - lo);
        let have: std::collections::HashSet<u32> = sites[lo..hi].iter().copied().collect();
        c.missing_sites = abs_sites.into_iter().filter(|s| !have.contains(s)).collect();
        c.sites_ok = c.missing_sites.is_empty();
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coff::Reloc;
    use crate::pe::testpe::{build, BASE, DATA, TEXT};

    /// f2 of the synthetic dll (`mov eax, [.data]; ret` at 0x10001020, its address relocated), as our object holds it.
    fn ours(data: &[u8], relocs: &[u32]) -> FunctionCode {
        let mut mask = vec![0u8; data.len()];
        for &o in relocs {
            mask[o as usize..o as usize + 4].fill(1);
        }
        FunctionCode { secnum: 1, data: data.to_vec(), mask, relocs: relocs.iter().map(|&o| (o, Reloc { offset: o, symbol_index: 0, typ: 0x06 })).collect(),
                       code_len: None, start: 0 }
    }

    #[test]
    fn masked_compare_tail_and_aid() {
        let img = Image::parse(build(None)).unwrap();
        let forms = fill_order(&[b"\x90".to_vec(), b"\xcc".to_vec()]);
        let f2 = BASE + TEXT + 0x20;
        let code = ours(b"\xa1\x00\x00\x00\x00\xc3", &[1]);
        let c = compare(&img, &code, f2, Some(&[f2 + 1]), f2 + 0x10, &forms);
        assert!(c.diffs.is_empty() && c.tail_ok && c.abs_image == Some(1) && c.abs_ours == 1 && c.matched());
        // a relocated field of ours where the original has a plain number: the aid fails
        let c = compare(&img, &code, f2, Some(&[]), f2 + 0x10, &forms);
        assert!(c.diffs.is_empty() && !c.aid_ok() && c.abs_image == Some(0) && !c.matched() && c.why().contains("no base relocation"));
        // the original continues after our end (f3 follows at +0x10): no match although the prefix is equal
        let c = compare(&img, &code, f2, None, f2 + 0x20, &forms);
        assert!(c.diffs.is_empty() && !c.tail_ok && !c.matched() && c.abs_image.is_none());
        // one differing byte
        let c = compare(&img, &ours(b"\xa1\x00\x00\x00\x00\xc2", &[1]), f2, Some(&[f2 + 1]), f2 + 0x10, &forms);
        assert!(c.diffs == [5] && !c.matched());
        assert_eq!(&img.bytes(f2 + 1, 4)[..], &(BASE + DATA).to_le_bytes()[..]);
    }
}
