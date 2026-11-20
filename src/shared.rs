//! `dcp --target T layout shared [--from F] [--write]`: the functions of the sources that target T holds byte for
//! byte, found by the objects another target of the project was built from.
//!
//! The targets of a project are built from one source tree, so most functions of a second target exist already as
//! the source of the first. Each function of F's objects (build/obj/<hash>.obj, as F's last build left them) is
//! searched in T's code: every byte no relocation covers is equal, and where T keeps its base relocations an
//! absolute reference of the object lies on one of them, a relative one on none, and the range holds no other. A
//! function with exactly one such place, which no other function claims, is placed: `--write` adds `T:0xADDR` to its
//! address comment (an `unlinked` function of F gets the address in place of the word). What is not placed is left
//! to the layout: a function found more than once (identical bodies), one that differs in T (its `#if`, another
//! constant), and one T does not hold.
//!
//! The addresses are declarations as any address comment is: `dcp --target T build` compiles the units they make
//! units of T, and the grade says whether T's own compile of each function is byte-identical.

use crate::coff::FunctionCode;
use crate::error::{Error, Result};
use crate::project::{native_path, Project};
use regex::Regex;
use std::collections::{BTreeMap, HashMap};
use std::sync::LazyLock;

const IMAGE_REL_I386_DIR32: u16 = 6;
/// The fewest bytes outside relocations a function is searched by: below it a place proves nothing.
const MIN_LITERAL: usize = 12;

/// A code section of the image to search: its address, its bytes.
pub struct Code<'a> {
    pub va: u32,
    pub data: &'a [u8],
}

/// The places of a function's bytes in the code: every literal byte equal; with `relocs` (the image's base
/// relocations, sorted: None when the image keeps none), the absolute references on relocations and no other
/// relocation in the range.
pub fn places(f: &FunctionCode, code: &[Code], relocs: Option<&[u32]>) -> Vec<u32> {
    let (data, mask) = (&f.data, &f.mask);
    // the longest run of literal bytes is the needle
    let (mut best, mut i) = ((0usize, 0usize), 0usize);
    while i < data.len() {
        if mask[i] != 0 {
            i += 1;
            continue;
        }
        let j = (i..data.len()).find(|&j| mask[j] != 0).unwrap_or(data.len());
        if j - i > best.1 {
            best = (i, j - i);
        }
        i = j;
    }
    let (at, len) = best;
    if len < 4 {
        return vec![];
    }
    let absolute: Vec<u32> = f.relocs.iter().filter(|(_, r)| r.typ == IMAGE_REL_I386_DIR32).map(|(o, _)| *o).collect();
    let finder = memchr::memmem::Finder::new(&data[at..at + len]);
    let mut out = vec![];
    for c in code {
        for hit in finder.find_iter(c.data) {
            let Some(start) = hit.checked_sub(at) else { continue };
            if start + data.len() > c.data.len() {
                continue;
            }
            let there = &c.data[start..start + data.len()];
            if !(0..data.len()).all(|k| mask[k] != 0 || data[k] == there[k]) {
                continue;
            }
            let va = c.va + start as u32;
            if let Some(rs) = relocs {
                let lo = rs.partition_point(|&r| r < va);
                let hi = rs.partition_point(|&r| r < va + data.len() as u32);
                if hi - lo != absolute.len() || !absolute.iter().all(|o| rs[lo..hi].binary_search(&(va + o)).is_ok()) {
                    continue;
                }
            }
            out.push(va);
        }
    }
    out
}

static LEAD: LazyLock<Regex> = LazyLock::new(|| {
    let item = r"(?:[A-Za-z][A-Za-z0-9_-]*:)?0x[0-9a-fA-F]+";
    Regex::new(&format!(r"\A(\s*{item}(?:\s*[,/]\s*{item})*)")).unwrap()
});
static UNLINKED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\A(\s*)unlinked\b").unwrap());

/// The line of an address comment with `target:0xADDR` added: after the addresses it lists, or in place of the
/// word `unlinked`. None when the line opens no such comment.
pub fn with_address(line: &str, target: &str, addr: u32) -> Option<String> {
    let open = line.find("/*")? + 2;
    let (head, rest) = line.split_at(open);
    let item = format!("{target}:{addr:#x}");
    if let Some(m) = LEAD.captures(rest) {
        let end = m.get(1).unwrap().end();
        return Some(format!("{head}{}, {item}{}", &rest[..end], &rest[end..]));
    }
    let m = UNLINKED.captures(rest)?;
    Some(format!("{head}{}{item}{}", &m[1], &rest[m.get(0).unwrap().end()..]))
}

struct Found {
    unit: String,
    name: String,
    file: String,
    comment: i64,
    size: usize,
    places: Vec<u32>,
}

/// `dcp --target T layout shared`: (lines, error, exit code).
pub fn shared_command(p: &Project, from: Option<&str>, write: bool, verbose: bool) -> Result<(Vec<String>, Option<String>, i32)> {
    let err = |m: String| Error::runtime(m);
    let fail = |m: String| Ok((vec![], Some(m), 1));
    let default = p.targets[0].name.clone();
    let target = p.target_name.clone();
    let from_name = match from {
        Some(f) => p.target_named(f).map_err(Error::config)?.name.clone(),
        None => default.clone(),
    };
    if from_name == target {
        return fail(format!("target {target} is the one to search by: name the target to place in (dcp --target NAME layout shared) or another one to search by (--from NAME); targets: {}",
                            p.target_names().join(", ")));
    }
    let root = p.root.to_string_lossy().into_owned();
    let from_db = native_path(&p.root.join("build").join(format!("{from_name}.sqlite")).to_string_lossy());
    if !std::path::Path::new(&from_db).exists() {
        return fail(format!("target {from_name} has no build yet: dcp --target {from_name} build"));
    }
    crate::storedb::st_open(&from_db)?;
    let rows = crate::compile::tu_rows(&from_db)?;
    let scan = crate::frontend::scan(&root, Some(&p.input_hash("src").map_err(err)?.unwrap_or_default())).map_err(err)?;
    let img = crate::image(&p.target.path)?;
    let code: Vec<Code> = img.sections.iter().filter(|s| s.code()).map(|s| Code { va: s.va, data: img.section_data(s) }).collect();
    let relocs = img.relocations();
    let relocs = (!relocs.is_empty()).then_some(relocs.as_slice());
    let has = |addrs: &[(Option<String>, u64)], t: &str| addrs.iter().any(|(x, _)| x.as_deref().unwrap_or(&default) == t);

    let (mut found, mut already, mut small, mut stale) = (vec![], 0usize, 0usize, vec![]);
    let mut parts: Vec<&crate::srcscan::FilePart> = scan.parts.iter().map(|x| &**x).collect();
    parts.sort_by(|a, b| a.rel.cmp(&b.rel));
    for part in parts {
        let Some(unit) = part.rel.strip_prefix("src/").and_then(|r| r.strip_suffix(".c")).filter(|u| !u.contains('/')) else { continue };
        if part.functions.is_empty() {
            continue;
        }
        let Some(row) = rows.get(unit).filter(|r| r.ok) else { continue }; // no unit of the other target, or one that did not compile
        if row.src_hash != crate::fsmemo::sha256(&native_path(&format!("{root}/{}", part.rel))).unwrap_or_default() {
            stale.push(unit.to_string());
        }
        let Some(obj) = crate::object_if(&crate::compile::obj_path(&root, &row.obj_hash))? else { continue };
        let index = &obj.1;
        for f in &part.functions {
            let (name, addrs) = (&f.0 .3, &f.0 .4);
            if has(addrs, &target) {
                already += 1;
                continue;
            }
            let Some(&k) = index.get(name) else { continue }; // the other target's compile does not hold it
            let fc = obj.0.function_code(k);
            if fc.mask.iter().filter(|&&m| m == 0).count() < MIN_LITERAL {
                small += 1;
                continue;
            }
            found.push(Found { unit: unit.to_string(), name: name.clone(), file: part.rel.clone(), comment: f.1 .3, size: fc.data.len(), places: places(&fc, &code, relocs) });
        }
    }
    // a place is a function's when it is its only one and no other function has it
    let mut claims: HashMap<u32, usize> = HashMap::new();
    for f in &found {
        for a in &f.places {
            *claims.entry(*a).or_default() += 1;
        }
    }
    let placed = |f: &Found| f.places.len() == 1 && claims[&f.places[0]] == 1;
    let (n_placed, n_absent) = (found.iter().filter(|f| placed(f)).count(), found.iter().filter(|f| f.places.is_empty()).count());
    let n_amb = found.len() - n_placed - n_absent;
    let mut out = vec![format!("target={target}  from={from_name}  searched={}  placed={n_placed}  ambiguous={n_amb}  absent={n_absent}  already={already}  small={small}",
                               found.len())];
    if !stale.is_empty() {
        out.push(format!("  warning: {} unit(s) changed since {from_name}'s build, searched by the older object (dcp --target {from_name} build): {}", stale.len(),
                         stale.iter().take(8).cloned().collect::<Vec<_>>().join(", ")));
    }
    let mut units: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    let mut by_unit: BTreeMap<&str, Vec<&Found>> = BTreeMap::new();
    for f in &found {
        by_unit.entry(f.unit.as_str()).or_default().push(f);
    }
    for (unit, fs) in &by_unit {
        let mut here: Vec<&&Found> = fs.iter().filter(|f| placed(f)).collect();
        here.sort_by_key(|f| f.places[0]);
        let amb = fs.iter().filter(|f| !f.places.is_empty() && !placed(f)).count();
        let Some(first) = here.first() else {
            if amb > 0 && verbose {
                units.entry(u32::MAX).or_default().push(format!("  unit={unit}  placed=0/{}  ambiguous={amb}", fs.len()));
            }
            continue;
        };
        let last = here.last().unwrap();
        let mut lines = vec![format!("  unit={unit}  placed={}/{}  range={:#x}..{:#x}  ambiguous={amb}", here.len(), fs.len(), first.places[0],
                                     last.places[0] + last.size as u32)];
        if verbose {
            lines.extend(here.iter().map(|f| format!("    {:#x}  {}  size={}", f.places[0], f.name, f.size)));
            lines.extend(fs.iter().filter(|f| !f.places.is_empty() && !placed(f))
                .map(|f| format!("    ambiguous  {}  size={}  at {}", f.name, f.size, f.places.iter().take(4).map(|a| format!("{a:#x}")).collect::<Vec<_>>().join(", "))));
        }
        units.entry(first.places[0]).or_default().extend(lines);
    }
    out.extend(units.into_values().flatten());
    if !write {
        if n_placed > 0 {
            out.push(format!("nothing written: --write adds `{target}:0xADDR` to the {n_placed} address comments (then: dcp --target {target} build)"));
        }
        return Ok((out, None, 0));
    }
    let mut by_file: BTreeMap<&str, Vec<&Found>> = BTreeMap::new();
    for f in found.iter().filter(|f| placed(f)) {
        by_file.entry(f.file.as_str()).or_default().push(f);
    }
    let (mut written, mut skipped) = (0usize, vec![]);
    for (rel, fs) in &by_file {
        let path = native_path(&format!("{root}/{rel}"));
        let text = crate::edit::read(&path);
        let mut lines: Vec<String> = text.split_inclusive('\n').map(|l| l.to_string()).collect();
        for f in fs {
            let k = (f.comment - 1) as usize;
            match lines.get(k).and_then(|l| with_address(l, &target, f.places[0])) {
                Some(l) => {
                    lines[k] = l;
                    written += 1;
                }
                None => skipped.push(format!("{rel}:{} {}", f.comment, f.name)),
            }
        }
        crate::edit::write(&path, &lines.concat()).map_err(err)?;
    }
    crate::fsmemo::new_epoch();
    p.forget_input("src");
    out.push(format!("wrote {written} address comments in {} files (then: dcp --target {target} build)", by_file.len()));
    for s in skipped.iter().take(20) {
        out.push(format!("  not written (the line opens no address comment): {s}"));
    }
    Ok((out, None, 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coff::Reloc;

    fn function(data: &[u8], relocs: &[(u32, u16)]) -> FunctionCode {
        let mut mask = vec![0u8; data.len()];
        for (o, _) in relocs {
            mask[*o as usize..*o as usize + 4].fill(1);
        }
        FunctionCode { secnum: 1, data: data.to_vec(), mask, relocs: relocs.iter().map(|(o, t)| (*o, Reloc { offset: *o, symbol_index: 0, typ: *t })).collect(),
                       code_len: None, start: 0 }
    }

    #[test]
    fn places_by_literal_bytes_and_relocations() {
        // mov eax, [abs32]; add eax, 0x11223344; call rel32; ret
        let f = function(&[0xa1, 0, 0, 0, 0, 0x05, 0x44, 0x33, 0x22, 0x11, 0xe8, 0, 0, 0, 0, 0xc3], &[(1, 6), (11, 20)]);
        let mut text = vec![0x90u8; 0x40];
        let body = [0xa1, 0x10, 0x20, 0x00, 0x10, 0x05, 0x44, 0x33, 0x22, 0x11, 0xe8, 0x70, 0xff, 0xff, 0xff, 0xc3];
        text[0x10..0x20].copy_from_slice(&body);
        text[0x30..0x40].copy_from_slice(&body);
        let code = [Code { va: 0x1000_1000, data: &text }];
        // an image without relocations: both places
        assert_eq!(places(&f, &code, None), [0x1000_1010, 0x1000_1030]);
        // with them: the absolute reference lies on one, the range holds no other
        assert_eq!(places(&f, &code, Some(&[0x1000_1011])), [0x1000_1010]);
        assert_eq!(places(&f, &code, Some(&[0x1000_1011, 0x1000_1031, 0x1000_1036])), [0x1000_1010]);
        assert!(places(&f, &code, Some(&[0x1000_101b])).is_empty()); // a relocation on the relative call
        // another literal byte
        text[0x16] = 0x45;
        assert_eq!(places(&f, &[Code { va: 0x1000_1000, data: &text }], None), [0x1000_1030]);
    }

    #[test]
    fn address_comments() {
        let a = |l: &str| with_address(l, "server", 0x10001000);
        assert_eq!(a("/* 0x4616d0, computes the checksum */\n").unwrap(), "/* 0x4616d0, server:0x10001000, computes the checksum */\n");
        assert_eq!(a("/* 0x4616d0 */").unwrap(), "/* 0x4616d0, server:0x10001000 */");
        assert_eq!(a("/* 0x4616d0, tl:0x4720a0, both */").unwrap(), "/* 0x4616d0, tl:0x4720a0, server:0x10001000, both */");
        assert_eq!(a("  /* unlinked, dropped by /OPT:REF */").unwrap(), "  /* server:0x10001000, dropped by /OPT:REF */");
        assert!(a("/* computes the checksum */").is_none() && a("int f(void)").is_none());
    }
}
