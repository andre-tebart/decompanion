//! match/compare.py's compare: one compiled function against the original's bytes (masked byte compare, the
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

/// Every byte of data belongs to a run of the fill forms (longest form first, greedy); empty: true.
pub fn is_fill(data: &[u8], forms: &[Vec<u8>]) -> bool {
    let mut fs: Vec<&Vec<u8>> = forms.iter().collect();
    fs.sort_by(|a, b| b.len().cmp(&a.len())); // stable, as Python's sorted(key=len, reverse=True)
    let mut i = 0;
    while i < data.len() {
        match fs.iter().find(|f| !f.is_empty() && data[i..].starts_with(f)) {
            Some(f) => i += f.len(),
            None => {
                // an empty form matches without advancing: Python loops forever there; no toolchain has one
                return false;
            }
        }
    }
    true
}

pub fn compare(img: &Image, code: &FunctionCode, addr: u32, reloc_sites: Option<&[u32]>, next_start: u32, forms: &[Vec<u8>]) -> Compared {
    let n = code.data.len();
    let orig = img.read(addr, n);
    let diffs = (0..n)
        .filter(|&k| code.mask.get(k).copied().unwrap_or(0) == 0 && Some(&code.data[k]) != orig.get(k))
        .map(|k| k as u32)
        .collect();
    let end = addr.wrapping_add(n as u32);
    let (mut tail_ok, mut tail) = (true, (0u32, 0u32));
    if next_start > end {
        tail = (end, next_start);
        tail_ok = is_fill(&img.read(end, (next_start - end) as usize), forms);
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
