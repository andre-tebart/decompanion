//! The setup rules (rules/setup.py documents each criterion; checks.py the numbered setup checks): what the
//! image gives away before a line of source exists.

use crate::error::{Error, Result};
use crate::image;
use crate::rules::Ctx;
use crate::store::{self, Out, Support, OBSERVED};
use rusqlite::Connection;
use serde_json::json;

fn err(e: rusqlite::Error) -> Error {
    Error::runtime(e.to_string())
}

fn region(out: &mut Out, what: &str, lo: u32, hi: u32) {
    out.claim(lo as i64, hi as i64, "region", json!({"what": what}), OBSERVED);
}

/// S.headers: the format's headers, one region each (pe.header, pe.rich).
pub fn s_headers(ctx: &Ctx, _db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    for (what, lo, hi) in img.header_regions() {
        region(out, &what, lo, hi);
    }
    Ok(())
}

/// S.sections: a section fact per table entry; pad past VirtualSize, unmapped between sections.
pub fn s_sections(ctx: &Ctx, _db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    let mut secs: Vec<&crate::pe::Section> = img.sections.iter().collect();
    secs.sort_by_key(|s| s.va);
    let mut prev = img.base + img.headers_size;
    for s in secs {
        if s.va > prev {
            region(out, "unmapped", prev, s.va);
        }
        out.claim(s.va as i64, s.end() as i64, "section",
                 json!({"name": s.name, "chars": s.chars, "raw_lo": s.raw_off, "raw_hi": s.raw_off + s.raw_size, "code": s.code(),
                        "vsize": s.vsize, "rsize": s.raw_size}), OBSERVED);
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
pub fn s_datadirs(ctx: &Ctx, _db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    for (what, lo, hi) in img.directory_regions() {
        region(out, &what, lo, hi);
    }
    Ok(())
}

/// S.imports: the import machinery as regions, an iat symbol and a name per address-table slot.
pub fn s_imports(ctx: &Ctx, _db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    for (what, lo, hi) in img.import_regions() {
        if hi > lo {
            region(out, &what, lo, hi);
        }
    }
    for imp in img.imports() {
        let (lo, hi, label) = (imp.slot as i64, imp.slot as i64 + 4, imp.label());
        out.claim(lo, hi, "symbol", json!({"skind": "iat", "name": label, "extent": "observed"}), OBSERVED);
        out.claim(lo, hi, "name", json!({"name": label, "origin": "import"}), OBSERVED);
    }
    Ok(())
}

/// S.exports: the export machinery as regions, a start and a name per exported address (no forwarders).
pub fn s_exports(ctx: &Ctx, _db: &Connection, out: &mut Out) -> Result<()> {
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
        out.claim(e.va as i64, e.va as i64 + 1, "start", json!({"skind": "func", "how": "export"}), OBSERVED);
        out.claim(e.va as i64, e.va as i64 + 1, "name", json!({"name": label, "origin": "export", "ordinal": e.ordinal}), OBSERVED);
    }
    Ok(())
}

/// S.entry: AddressOfEntryPoint is a function start.
pub fn s_entry(ctx: &Ctx, _db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    if img.entry != 0 {
        out.claim(img.entry as i64, img.entry as i64 + 1, "start", json!({"skind": "func", "how": "entry"}), OBSERVED);
    }
    Ok(())
}

/// S.relocs: a reloc reference per absolute relocation site, to the address its field holds.
pub fn s_relocs(ctx: &Ctx, _db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    for site in img.relocations() {
        out.claim(site as i64, site as i64 + 4, "ref", json!({"rkind": "reloc", "to": img.read_ptr(site)}), OBSERVED);
    }
    Ok(())
}

/// S7.entry.section: the entry point and every export lie in a code section.
pub fn s7_entry_section(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    let secs: Vec<(i64, i64)> = store::claims(db, &ctx.db, "section", &ctx.needed, |_| true).map_err(err)?.iter().map(|f| (f.lo, f.hi)).collect();
    for s in store::claims(db, &ctx.db, "start", &ctx.needed, |_| true).map_err(err)?.iter() {
        let sec = secs.iter().find(|&&(a, b)| a <= s.lo && s.lo < b).and_then(|&(a, _)| img.section_of(a as u32));
        if !sec.is_some_and(|x| x.holds_code()) {
            out.finding("error", "S7", s.lo, s.lo + 1, format!("{} start outside an executable section", s.s("how").unwrap_or("")), "");
        }
    }
    Ok(())
}

/// S4.import.libs: every imported DLL's import library is among the toolchain's archives or the target's
/// (native_inputs: the toolchain's key and root, the target's archives).
pub fn s4_import_libs(ctx: &Ctx, _db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    let x = &ctx.inputs;
    let tc = crate::toolchain::of(&x.toolchain).ok_or_else(|| Error::runtime("S4: no such toolchain"))?;
    let name = |p: &std::path::Path| p.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    let mut have: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Some(root) = x.root.as_deref() {
        have.extend(tc.library_archives(std::path::Path::new(root)).iter().map(|p| name(p)));
    }
    have.extend(x.libs.iter().map(|p| name(std::path::Path::new(p))));
    let dlls: std::collections::BTreeSet<String> = img.imports().into_iter().map(|i| i.dll).collect();
    for dll in dlls {
        if !have.contains(&tc.import_library_name(&dll).to_lowercase()) {
            out.finding("warn", "S4", img.base as i64, img.base as i64 + 1, format!("no import library for {dll} in the toolchain"), "");
        }
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ facts-only rules

use crate::store::{Claim, DERIVED, OPEN};
use std::rc::Rc;

pub(crate) fn facts(ctx: &Ctx, db: &Connection, kind: &str) -> Result<Vec<Rc<Claim>>> {
    store::claims(db, &ctx.db, kind, &ctx.needed, |_| true).map_err(err)
}

/// Store.facts(kind, lo, hi): the facts of a kind that intersect [lo, hi), in the store's order.
fn facts_in(ctx: &Ctx, db: &Connection, kind: &str, lo: i64, hi: i64) -> Result<Vec<Rc<Claim>>> {
    store::claims(db, &ctx.db, kind, &ctx.needed, |f| f.hi > lo && f.lo < hi).map_err(err)
}

/// A contradiction's severity: top against top (observed or reproduced on both sides) is a bug in a rule, else an
/// error.
pub(crate) fn severity_of(a: Support, b: Support) -> &'static str {
    if a.is_top() && b.is_top() { "bug" } else { "error" }
}

/// A value as Python's str() spells it in a message.
pub(crate) fn py_str(v: Option<&serde_json::Value>) -> String {
    match v {
        None | Some(serde_json::Value::Null) => "None".into(),
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Bool(b)) => if *b { "True".into() } else { "False".into() },
        Some(x) => x.to_string(),
    }
}

/// The toolchain native_inputs name ({"toolchain": key}).
pub(crate) fn toolchain_of(ctx: &Ctx) -> Result<Box<dyn crate::toolchain::Toolchain>> {
    crate::toolchain::of(&ctx.inputs.toolchain).ok_or_else(|| Error::runtime(format!("{}: no toolchain in its inputs", ctx.rule)))
}

/// C.overlap: two symbol or region facts that overlap contradict each other.
pub fn c_overlap(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let mut items: Vec<(&'static str, Rc<Claim>)> = facts(ctx, db, "symbol")?.into_iter().filter(|f| f.support > OPEN).map(|f| ("symbol", f)).collect();
    items.extend(facts(ctx, db, "region")?.into_iter().map(|f| ("region", f)));
    items.sort_by_key(|(_, f)| (f.lo, f.hi));
    let label = |f: &Claim| py_str(f.value.get("skind").or(Some(f.value.get("what").unwrap_or(&serde_json::Value::String(String::new())))));
    let mut active: Vec<&(&str, Rc<Claim>)> = vec![];
    for item in &items {
        let (fk, f) = item;
        active.retain(|(_, g)| g.hi > f.lo);
        for (gk, g) in &active {
            if (g.lo, g.hi, gk, g.value.get("skind")) == (f.lo, f.hi, fk, f.value.get("skind")) {
                continue;
            }
            if g.lo < f.hi && f.lo < g.hi {
                out.finding2(severity_of(f.support, g.support), "C.overlap", f.lo.max(g.lo), f.hi.min(g.hi),
                              format!("{gk} {} {:#x}..{:#x} overlaps {fk} {} {:#x}..{:#x}", label(g), g.lo, g.hi, label(f), f.lo, f.hi), &g.by, &f.by);
            }
        }
        active.push(item);
    }
    Ok(())
}

/// C.ref.target: a direct call whose target lies strictly inside a function contradicts it.
pub fn c_ref_target(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let mut funcs: Vec<Rc<Claim>> = facts(ctx, db, "symbol")?.into_iter().filter(|f| f.s("skind") == Some("func") && f.support > OPEN).collect();
    funcs.sort_by_key(|f| (f.lo, f.hi));
    let mut starts: std::collections::HashSet<i64> = facts(ctx, db, "start")?.iter().map(|f| f.lo).collect();
    for f in &funcs {
        starts.extend(f.value.get("inner").and_then(|v| v.as_array()).into_iter().flatten().filter_map(|x| x.as_i64()));
    }
    for r in facts(ctx, db, "ref")?.iter().filter(|r| r.s("rkind") == Some("call")) {
        let Some(t) = r.value.get("to").and_then(|v| v.as_i64()) else { continue };
        if starts.contains(&t) {
            continue;
        }
        let i = funcs.partition_point(|f| f.lo <= t);
        if i > 0 {
            let f = &funcs[i - 1];
            if f.lo < t && t < f.hi {
                out.finding2(severity_of(f.support, r.support), "C.ref.target", t, t + 1,
                              format!("call from {:#x} targets the inside of the function at {:#x}..{:#x}", r.lo, f.lo, f.hi), &f.by, &r.by);
            }
        }
    }
    Ok(())
}

/// S5.crt.gaps: unknown code between the first and the last placed library function.
pub fn s5_crt_gaps(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let crt: Vec<Rc<Claim>> = facts(ctx, db, "symbol")?.into_iter()
        .filter(|f| f.s("unit").is_some_and(|u| u.starts_with("lib:")) && f.s("skind") == Some("func")).collect();
    if crt.is_empty() {
        return Ok(());
    }
    let lo = crt.iter().map(|f| f.lo).min().unwrap();
    let hi = crt.iter().map(|f| f.hi).max().unwrap();
    for f in facts_in(ctx, db, "symbol", lo, hi)? {
        if f.s("skind") == Some("unknown.code") {
            let (a, b) = (f.lo.max(lo), f.hi.min(hi));
            out.finding("warn", "S5", a, b, format!("{} unknown bytes inside the library region", b - a), "");
        }
    }
    Ok(())
}

/// S.entry.user: the user entry the CRT start-up calls, as its C name.
pub fn s_entry_user(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let tc = toolchain_of(ctx)?;
    let user: std::collections::HashMap<&str, &str> = tc.user_entry_names().into_iter().collect();
    for f in facts(ctx, db, "name")? {
        if f.s("origin") == Some("lib") {
            if let Some(c) = f.s("name").and_then(|n| user.get(n)) {
                out.claim(f.lo, f.lo + 1, "name", json!({"name": c, "origin": "entry"}), DERIVED);
            }
        }
    }
    Ok(())
}

/// S.strings: a relocation target in a data section that holds at least 4 printable characters and a NUL.
pub fn s_strings(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    let targets: std::collections::BTreeSet<i64> = facts(ctx, db, "ref")?.iter()
        .filter(|f| f.s("rkind") == Some("reloc")).filter_map(|f| f.value.get("to").and_then(|v| v.as_i64())).collect();
    let mut placed: Vec<(i64, i64)> = facts(ctx, db, "symbol")?.iter().filter(|f| f.s("skind") == Some("crt.data")).map(|f| (f.lo, f.hi)).collect();
    placed.sort();
    let mut last_hi = 0i64;
    for t in targets {
        if t < last_hi || placed.iter().any(|&(a, b)| a <= t && t < b) {
            continue;
        }
        let Some(s) = img.section_of(t as u32) else { continue };
        if s.holds_code() {
            continue;
        }
        let Some((o, _)) = img.off(t as u32) else { continue };
        let end = (o + 4096).min((s.raw_off + s.raw_size) as usize).min(img.data.len());
        if o >= end {
            continue;
        }
        let Some(e) = memchr::memchr(0, &img.data[o..end]).map(|k| o + k) else { continue };
        if e - o < 4 {
            continue;
        }
        let run = &img.data[o..e];
        if !run.iter().all(|&c| (0x20..0x7f).contains(&c) || c == 9 || c == 10 || c == 13) {
            continue;
        }
        last_hi = t + run.len() as i64 + 1;
        let text: String = run.iter().take(60).map(|&c| c as char).collect();
        out.claim(t, last_hi, "symbol", json!({"skind": "string", "extent": "derived", "text": text}), DERIVED);
    }
    Ok(())
}

/// S.fill: an unclaimed run of a code section made only of the fill forms, up to a claim or VirtualSize.
pub fn s_fill(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    let forms = crate::compare::fill_order(&ctx.fill_forms);
    for s in img.sections.iter().filter(|s| s.holds_code()) {
        let (va, end) = (s.va as i64, s.end() as i64);
        let mut claimed: Vec<(i64, i64)> = facts_in(ctx, db, "symbol", va, end)?.iter().map(|f| (f.lo, f.hi)).collect();
        claimed.extend(facts_in(ctx, db, "region", va, end)?.iter().map(|f| (f.lo, f.hi)));
        claimed.sort();
        let mut pos = va;
        let mut gaps = vec![];
        for &(a, b) in &claimed {
            if a > pos {
                gaps.push((pos, a));
            }
            pos = pos.max(b);
        }
        if va + s.vsize as i64 > pos {
            gaps.push((pos, va + s.vsize as i64));
        }
        for (lo, hi) in gaps {
            let b = img.read(lo as u32, (hi - lo) as usize);
            let mut i = 0;
            let ok = loop {
                if i >= b.len() {
                    break true;
                }
                match forms.iter().find(|f| b[i..].starts_with(f)) {
                    Some(f) => i += f.len(),
                    None => break false,
                }
            };
            if ok && !b.is_empty() {
                out.claim(lo, hi, "symbol", json!({"skind": "fill", "extent": "derived"}), DERIVED);
            }
        }
    }
    Ok(())
}

/// S.unknown: every mapped byte no symbol and no region claims.
pub fn s_unknown(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let img = image(&ctx.image)?;
    for s in &img.sections {
        let (va, end) = (s.va as i64, s.end() as i64);
        let mut claimed: std::collections::BTreeSet<(i64, i64)> = facts_in(ctx, db, "symbol", va, end)?.iter().map(|f| (f.lo, f.hi)).collect();
        claimed.extend(facts_in(ctx, db, "region", va, end)?.iter().map(|f| (f.lo, f.hi)));
        let sk = if s.holds_code() { "unknown.code" } else { "unknown.data" };
        let mut pos = va;
        for (a, b) in claimed {
            if a > pos {
                out.claim(pos, a, "symbol", json!({"skind": sk, "extent": "open"}), OPEN);
            }
            pos = pos.max(b);
        }
        if end > pos {
            out.claim(pos, end, "symbol", json!({"skind": sk, "extent": "open"}), OPEN);
        }
    }
    Ok(())
}


#[cfg(test)]
mod tests {
    use crate::pe::testpe::{build, BASE, DATA, RELOC, TEXT};
    use crate::rules::testkit::{of, Kit};
    use serde_json::json;

    const RICH: &[(u32, u32, u32)] = &[(0x30, 9044, 3), (0x0a, 8047, 5), (0x04, 8447, 1)];

    #[test]
    fn headers_sections_datadirs() {
        let k = Kit::new(&build(Some(RICH)));
        let (rows, _) = k.run("S.headers", &[], "");
        let r = of(&rows, "region");
        assert_eq!(r.iter().map(|x| x.2["what"].as_str().unwrap()).collect::<Vec<_>>(), ["pe.header", "pe.rich", "pe.header"]);
        let (rows, _) = k.run("S.sections", &[], "");
        let s = of(&rows, "section");
        assert_eq!(s.len(), 3);
        assert_eq!(s[0], (BASE as i64 + TEXT as i64, BASE as i64 + TEXT as i64 + 0x200,
                          json!({"name": ".text", "chars": 0x6000_0020u32, "raw_lo": 0x400, "raw_hi": 0x600, "code": true, "vsize": 0x60, "rsize": 0x200})));
        // pad past each VirtualSize, unmapped between the sections and after the last
        let what: Vec<&str> = of(&rows, "region").iter().map(|x| x.2["what"].as_str().unwrap().to_string()).map(|s| if s == "pad" { "pad" } else { "unmapped" }).collect();
        assert_eq!(what, ["unmapped", "pad", "unmapped", "pad", "unmapped", "pad", "unmapped"]);
        let (rows, _) = k.run("S.datadirs", &[], "");
        assert_eq!(of(&rows, "region"), vec![(BASE as i64 + RELOC as i64, BASE as i64 + RELOC as i64 + 0x1c, json!({"what": "pe.basereloc"}))]);
    }

    #[test]
    fn imports_exports_entry_relocs() {
        let k = Kit::new(&build(None));
        let (rows, _) = k.run("S.imports", &[], "");
        let d = (BASE + DATA) as i64;
        assert_eq!(of(&rows, "symbol"), vec![(d + 0x150, d + 0x154, json!({"skind": "iat", "name": "KERNEL32.dll!GetTickCount", "extent": "observed"})),
                                             (d + 0x154, d + 0x158, json!({"skind": "iat", "name": "KERNEL32.dll!#3", "extent": "observed"}))]);
        assert_eq!(of(&rows, "name")[1].2, json!({"name": "KERNEL32.dll!#3", "origin": "import"}));
        assert_eq!(of(&rows, "region").len(), 5);
        let (rows, _) = k.run("S.exports", &[], "");
        let t = (BASE + TEXT) as i64;
        assert_eq!(of(&rows, "start"), vec![(t, t + 1, json!({"skind": "func", "how": "export"})), (t + 0x50, t + 0x51, json!({"skind": "func", "how": "export"}))]);
        assert_eq!(of(&rows, "name").iter().map(|x| x.2["name"].as_str().unwrap().to_string()).collect::<Vec<_>>(), ["Start", "#2"]);
        let (rows, _) = k.run("S.entry", &[], "");
        assert_eq!(of(&rows, "start"), vec![(t, t + 1, json!({"skind": "func", "how": "entry"}))]);
        let (rows, _) = k.run("S.relocs", &[], "");
        let refs = of(&rows, "ref");
        assert_eq!(refs.len(), 5);
        assert_eq!(refs[0], (t + 0x21, t + 0x25, json!({"rkind": "reloc", "to": BASE + DATA})));
    }

    #[test]
    fn fill_unknown_strings() {
        let k = Kit::new(&build(None));
        let t = (BASE + TEXT) as i64;
        k.record("S.sections", &[], "");
        k.record("S.relocs", &[], "");
        let func = |lo: i64, hi: i64| (lo, hi, "symbol", json!({"skind": "func"}), crate::store::DERIVED);
        k.put("S.codewalk", &[func(t, t + 0x0f), func(t + 0x20, t + 0x26), func(t + 0x30, t + 0x3e), func(t + 0x50, t + 0x57)]);
        let (rows, _) = k.run("S.fill", &["S.sections", "S.codewalk"], "");
        let fills: Vec<(i64, i64)> = of(&rows, "symbol").iter().map(|x| (x.0 - t, x.1 - t)).collect();
        assert_eq!(fills, [(0x0f, 0x20), (0x26, 0x30), (0x3e, 0x50), (0x57, 0x60)]);
        k.record("S.fill", &["S.sections", "S.codewalk"], "");
        let (rows, _) = k.run("S.unknown", &["S.sections", "S.codewalk", "S.fill"], "");
        let u: Vec<(i64, i64, String)> = of(&rows, "symbol").iter().map(|x| (x.0, x.1, x.2["skind"].as_str().unwrap().to_string())).collect();
        // .text: functions, fill, and past VirtualSize S.sections' pad: no unknown code; the data unclaimed
        assert!(!u.is_empty() && u.iter().all(|x| x.2 == "unknown.data" && x.0 >= (BASE + DATA) as i64));
        k.put("S.crt.data", &[]);
        let (rows, _) = k.run("S.strings", &["S.relocs", "S.sections", "S.crt.data"], "");
        let d = (BASE + DATA) as i64;
        let s: Vec<(i64, i64, String)> = of(&rows, "symbol").iter().map(|x| (x.0 - d, x.1 - d, x.2["text"].as_str().unwrap().to_string())).collect();
        assert_eq!(s, [(0x10, 0x21, r"c:\src\net\net.c".to_string()), (0x30, 0x36, "hello".to_string()), (0x38, 0x3e, "world".to_string())]);
    }

    #[test]
    fn overlaps_and_call_targets() {
        let k = Kit::new(&build(None));
        let t = (BASE + TEXT) as i64;
        k.put("A", &[(t, t + 0x10, "symbol", json!({"skind": "func"}), crate::store::REPRODUCED), (t + 0x20, t + 0x30, "symbol", json!({"skind": "func"}), crate::store::REPRODUCED)]);
        k.put("B", &[(t + 8, t + 0x18, "symbol", json!({"skind": "func"}), crate::store::REPRODUCED), (t + 0x20, t + 0x30, "symbol", json!({"skind": "func"}), crate::store::DERIVED),
                     (t, t + 4, "symbol", json!({"skind": "string"}), crate::store::OPEN), (t + 0x40, t + 0x41, "ref", json!({"rkind": "call", "to": t + 0x24}), crate::store::REPRODUCED)]);
        let (_, c) = k.run("C.overlap", &["A", "B"], "");
        // the same interval and kind of symbol is no contradiction; open facts are not counted
        assert_eq!(c.iter().map(|x| (x.severity.as_str(), x.lo - t, x.hi - t)).collect::<Vec<_>>(), [("bug", 8, 0x10)]);
        assert_eq!(c[0].message, format!("symbol func {:#x}..{:#x} overlaps symbol func {:#x}..{:#x}", t, t + 0x10, t + 8, t + 0x18));
        k.put("S.thunk", &[]);
        let (_, c) = k.run("C.ref.target", &["A", "B"], "");
        assert_eq!(c.iter().map(|x| (x.severity.as_str(), x.lo - t)).collect::<Vec<_>>(), [("error", 0x24)]);
    }

    #[test]
    fn entry_section_and_import_libs() {
        let k = Kit::new(&build(None));
        for r in ["S.sections", "S.exports", "S.entry"] {
            k.record(r, &[], "");
        }
        let (_, c) = k.run("S7.entry.section", &["S.sections", "S.exports", "S.entry"], "");
        assert!(c.is_empty());
        let (_, c) = k.run("S4.import.libs", &[], r#"{"toolchain": "vc6", "root": null, "libs": []}"#);
        assert_eq!(c.iter().map(|x| (x.severity.as_str(), x.message.as_str())).collect::<Vec<_>>(),
                   [("warn", "no import library for KERNEL32.dll in the toolchain")]);
        let (_, c) = k.run("S4.import.libs", &[], r#"{"toolchain": "vc6", "root": null, "libs": ["C:/x/KERNEL32.LIB"]}"#);
        assert!(c.is_empty());
    }

    /// Names of ours at one address are one object under several names (an error, functions too); a view is
    /// another object.
    #[test]
    fn name_alias() {
        let k = Kit::new(&build(None));
        let mut out = crate::store::Out::new("L.src", "1");
        for (a, n, why, by) in [(0x1000, "ai_Unk1000", "data address comment (def)", "src:src/a.c:3"),
                                (0x1000, "d3_Origin", "data address comment (extern)", "src:include/d3.h:9"),
                                (0x2000, "x", "data address comment (def)", "src:src/a.c:4"), (0x2000, "xB", "view of x +0x0", "src:include/v.h:1"),
                                (0x3000, "f", "address comment", "src:src/a.c:9"), (0x3000, "g", "address comment", "src:src/b.c:9")] {
            let mut v = json!({"name": n, "origin": "source"});
            if n == "xB" {
                v["view"] = json!("x");
            }
            out.claim(a, a + 1, "name", v, crate::store::DECLARED);
            let r = out.rows.last_mut().unwrap();
            (r.reason, r.by) = (Some(why.to_string()), by.to_string());
        }
        let (rows, confl) = out.sorted();
        crate::with_db(&k.db, |db| crate::write_run(db, &k.db, "L.src", "1", "test", "put:L.src", &rows, &confl, 0, true)).unwrap();
        let (_, c) = k.run("C.name.alias", &["L.src"], "");
        let c: Vec<(String, i64, String)> = c.into_iter().map(|c| (c.severity, c.lo, c.message)).collect();
        let tail = |a: &str| format!("; one object has one name (dcp rename the others to it, or declare an alias: #define B A  /* {a} */)");
        assert_eq!(c, [("error".to_string(), 0x1000, format!("2 names of ours at 0x1000: ai_Unk1000 (src/a.c:3), d3_Origin (include/d3.h:9){}", tail("0x1000"))),
                       ("error".to_string(), 0x3000, format!("2 names of ours at 0x3000: f (src/a.c:9), g (src/b.c:9){}", tail("0x3000")))]);
    }
}
