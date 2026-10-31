//! The setup rules (rules/setup.py documents each criterion; checks.py the numbered setup checks): what the
//! image gives away before a line of source exists.

use crate::image;
use crate::rules::Ctx;
use crate::store::{self, Out, PROVEN};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use rusqlite::Connection;
use serde_json::json;

fn err(e: rusqlite::Error) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

fn region(out: &mut Out, what: &str, lo: u32, hi: u32) {
    out.fact(lo as i64, hi as i64, "region", json!({"what": what}), PROVEN);
}

/// S.headers: the format's headers, one region each (pe.header, pe.rich).
pub fn s_headers(ctx: &Ctx, _db: &Connection, out: &mut Out) -> PyResult<()> {
    let img = image(&ctx.image)?;
    for (what, lo, hi) in img.header_regions() {
        region(out, &what, lo, hi);
    }
    Ok(())
}

/// S.sections: a section fact per table entry; pad past VirtualSize, unmapped between sections.
pub fn s_sections(ctx: &Ctx, _db: &Connection, out: &mut Out) -> PyResult<()> {
    let img = image(&ctx.image)?;
    let mut secs: Vec<&crate::pe::Section> = img.sections.iter().collect();
    secs.sort_by_key(|s| s.va);
    let mut prev = img.base + img.headers_size;
    for s in secs {
        if s.va > prev {
            region(out, "unmapped", prev, s.va);
        }
        out.fact(s.va as i64, s.end() as i64, "section",
                 json!({"name": s.name, "chars": s.chars, "raw_lo": s.raw_off, "raw_hi": s.raw_off + s.raw_size, "code": s.code(),
                        "vsize": s.vsize, "rsize": s.raw_size}), PROVEN);
        if s.raw_size > s.vsize {
            region(out, "pad", s.va + s.vsize, s.va + s.raw_size);
        }
        prev = s.end();
    }
    if img.end() > prev {
        region(out, "unmapped", prev, img.end());
    }
    Ok(())
}

/// S.datadirs: the directories that are byte ranges of their own inside a section.
pub fn s_datadirs(ctx: &Ctx, _db: &Connection, out: &mut Out) -> PyResult<()> {
    let img = image(&ctx.image)?;
    for (what, lo, hi) in img.directory_regions() {
        region(out, &what, lo, hi);
    }
    Ok(())
}

/// S.imports: the import machinery as regions, an iat symbol and a name per address-table slot.
pub fn s_imports(ctx: &Ctx, _db: &Connection, out: &mut Out) -> PyResult<()> {
    let img = image(&ctx.image)?;
    for (what, lo, hi) in img.import_regions() {
        if hi > lo {
            region(out, &what, lo, hi);
        }
    }
    for imp in img.imports() {
        let (lo, hi, label) = (imp.slot as i64, imp.slot as i64 + 4, imp.label());
        out.fact(lo, hi, "symbol", json!({"skind": "iat", "name": label, "extent": "proven"}), PROVEN);
        out.fact(lo, hi, "name", json!({"name": label, "origin": "import"}), PROVEN);
    }
    Ok(())
}

/// S.exports: the export machinery as regions, a start and a name per exported address (no forwarders).
pub fn s_exports(ctx: &Ctx, _db: &Connection, out: &mut Out) -> PyResult<()> {
    let img = image(&ctx.image)?;
    for (what, lo, hi) in img.export_regions() {
        if hi > lo {
            region(out, &what, lo, hi);
        }
    }
    for e in img.exports() {
        if e.forwarder.is_some() {
            continue;
        }
        let label = e.name.clone().unwrap_or_else(|| format!("#{}", e.ordinal));
        out.fact(e.va as i64, e.va as i64 + 1, "start", json!({"skind": "func", "how": "export"}), PROVEN);
        out.fact(e.va as i64, e.va as i64 + 1, "name", json!({"name": label, "origin": "export", "ordinal": e.ordinal}), PROVEN);
    }
    Ok(())
}

/// S.entry: AddressOfEntryPoint is a function start.
pub fn s_entry(ctx: &Ctx, _db: &Connection, out: &mut Out) -> PyResult<()> {
    let img = image(&ctx.image)?;
    if img.entry != 0 {
        out.fact(img.entry as i64, img.entry as i64 + 1, "start", json!({"skind": "func", "how": "entry"}), PROVEN);
    }
    Ok(())
}

/// S.relocs: a reloc reference per absolute relocation site, to the address its field holds.
pub fn s_relocs(ctx: &Ctx, _db: &Connection, out: &mut Out) -> PyResult<()> {
    let img = image(&ctx.image)?;
    for site in img.relocations() {
        out.fact(site as i64, site as i64 + 4, "ref", json!({"rkind": "reloc", "to": img.read_ptr(site)}), PROVEN);
    }
    Ok(())
}

/// S7.entry.section: the entry point and every export lie in a code section.
pub fn s7_entry_section(ctx: &Ctx, db: &Connection, out: &mut Out) -> PyResult<()> {
    let img = image(&ctx.image)?;
    let secs: Vec<(i64, i64)> = store::facts(db, &ctx.db, "section", &ctx.needed, |_| true).map_err(err)?.iter().map(|f| (f.lo, f.hi)).collect();
    for s in store::facts(db, &ctx.db, "start", &ctx.needed, |_| true).map_err(err)?.iter() {
        let sec = secs.iter().find(|&&(a, b)| a <= s.lo && s.lo < b).and_then(|&(a, _)| img.section_of(a as u32));
        if !sec.is_some_and(|x| x.holds_code()) {
            out.conflict("error", "S7", s.lo, s.lo + 1, format!("{} start outside an executable section", s.s("how").unwrap_or("")), "");
        }
    }
    Ok(())
}

/// S4.import.libs: every imported DLL's import library is among the toolchain's archives or the target's
/// (native_inputs: the toolchain's key and root, the target's archives).
pub fn s4_import_libs(ctx: &Ctx, _db: &Connection, out: &mut Out) -> PyResult<()> {
    let img = image(&ctx.image)?;
    let x: serde_json::Value = serde_json::from_str(&ctx.extra).map_err(|e| PyRuntimeError::new_err(format!("S4: native inputs: {e}")))?;
    let tc = crate::toolchain::of(x["toolchain"].as_str().unwrap_or("")).ok_or_else(|| PyRuntimeError::new_err("S4: no such toolchain"))?;
    let name = |p: &std::path::Path| p.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    let mut have: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Some(root) = x["root"].as_str() {
        have.extend(tc.library_archives(std::path::Path::new(root)).iter().map(|p| name(p)));
    }
    have.extend(x["libs"].as_array().into_iter().flatten().filter_map(|p| p.as_str()).map(|p| name(std::path::Path::new(p))));
    let dlls: std::collections::BTreeSet<String> = img.imports().into_iter().map(|i| i.dll).collect();
    for dll in dlls {
        if !have.contains(&tc.import_library_name(&dll).to_lowercase()) {
            out.conflict("warn", "S4", img.base as i64, img.base as i64 + 1, format!("no import library for {dll} in the toolchain"), "");
        }
    }
    Ok(())
}
