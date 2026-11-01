//! `dcp asmdiff` and `dcp diffclass`: one graded function's reading as G.grade takes it (diffclass.rs: our
//! listing against the original's, the switch tables, the hunks and the verdict), for the commands to print.

use crate::error::{Error, Result};
use crate::diffclass::{self, Env, Hunk, Tables, Verdict};
use crate::project::Project;
use crate::store;
use crate::x86::Line;
use serde_json::Value;
use std::collections::{BTreeSet, HashSet};

/// A function's reading: its grade row, our listing, the original's, the tables compare, the hunks and the verdict.
pub struct Reading {
    pub row: Value,
    pub la: Vec<Line>,
    pub lb: Vec<Line>,
    pub tables: Option<Tables>,
    pub hunks: Vec<Hunk>,
    pub verdict: Verdict,
    /// the texts of la and lb with names for X (reading's `names`): our relocations' symbols, the ledger's labels
    pub named: Option<(Vec<String>, Vec<String>)>,
    /// with `named`, per line the values behind its X fields in text order: ours what each resolves to, the
    /// original's the number (Reading::same_values)
    pub values: Option<(Vec<Vec<Val>>, Vec<Vec<i64>>)>,
}

/// What one of our X fields refers to, for comparing it with the original's number: the addresses its symbol
/// has in the ledger (with the addend), the bytes of our literal (a string or a floating constant: the original
/// holds the same bytes at its address), or nothing known.
#[derive(Clone, Debug)]
pub enum Val {
    Addrs(Vec<i64>),
    Lit(Vec<u8>),
    Unknown,
}

impl Reading {
    /// Whether line i of ours and line j of the original's refer to the same things by their X fields although
    /// they name them differently (`asmdiff --symbols` `=`: an alias, a placeholder and its name, `sym+off` and the
    /// bare address, a literal and the original's datum holding the same bytes). A match-base report: such lines
    /// were marked `!`, a wrong datum, and every one cost a `dcp why`.
    pub fn same_values(&self, img: &crate::pe::Image, i: usize, j: usize) -> bool {
        let Some((va, vb)) = &self.values else { return false };
        let (Some(xs), Some(ys)) = (va.get(i), vb.get(j)) else { return false };
        !xs.is_empty() && xs.len() == ys.len() && xs.iter().zip(ys).all(|(x, &y)| match x {
            Val::Addrs(a) => a.contains(&y),
            Val::Lit(b) => !b.is_empty() && img.in_image(y as u32) && *img.bytes(y as u32, b.len()) == **b,
            Val::Unknown => false,
        })
    }
}

/// Whether the instruction at `ins` compares a register with an immediate image address (`cmp ecx, X`).
fn bound(lines: &[Line], ins: u32) -> bool {
    lines.iter().find(|l| l.addr == ins).is_some_and(|l| l.text.starts_with("cmp ") && l.text.ends_with(", X") && !l.text.contains('['))
}

/// What our relocated field refers to (Val), independent of where the original's field lies.
fn reloc_val(obj: &crate::coff::Obj, code: &crate::coff::FunctionCode, r: &crate::coff::Reloc, names: &crate::names::Names) -> Val {
    let Some(sym) = obj.symbol_at(r.symbol_index) else { return Val::Unknown };
    let addend = obj.addend(code.secnum, r) as i32 as i64;
    let data = if sym.secnum > 0 { obj.sections.get(sym.secnum as usize).and_then(|s| s.data.as_ref()) } else { None };
    match sym.constant() {
        Some("string") => {
            let Some(d) = data else { return Val::Unknown };
            let lit = d.get(sym.value as usize..).unwrap_or(&[]);
            let lit = &lit[..lit.iter().position(|&c| c == 0).map(|z| z + 1).unwrap_or(lit.len())];
            match lit.get(addend.max(0) as usize..) {
                Some(rest) if addend >= 0 => Val::Lit(rest.to_vec()),
                _ => Val::Unknown,
            }
        }
        Some("float") => {
            // __real@3f800000 (4 bytes) / __real@3ff0000000000000 (8): the constant's bytes, little-endian
            let hex = sym.name.rsplit('@').next().unwrap_or("");
            let Ok(v) = u64::from_str_radix(hex, 16) else { return Val::Unknown };
            let n = hex.len() / 2;
            if !(n == 4 || n == 8) || addend != 0 {
                return Val::Unknown;
            }
            Val::Lit(v.to_le_bytes()[..n].to_vec())
        }
        _ => {
            let cname = crate::coff::undecorate(sym.name.strip_prefix("__imp_").unwrap_or(&sym.name));
            let mut at: Vec<i64> = names.by_name.iter().find(|(n, _)| *n == cname).map(|(_, a)| a.clone()).unwrap_or_default();
            if let Some(v) = crate::srcscan::placeholder_whole(&cname) {
                at.push(v as i64);
            }
            if at.is_empty() {
                Val::Unknown
            } else {
                Val::Addrs(at.into_iter().map(|a| a + addend).collect())
            }
        }
    }
}

/// How an address of the original reads by name (`asmdiff --symbols`): a number inside the function's slot `own`
/// (a jump of its own) as the number, else the ledger's label (dcp disasm's), else the printable C string the
/// image holds there, else the number. `bound`: the number is the immediate a compare tests against (a loop's end
/// pointer), the function's image addresses with it: the label adds the reading from an object below that the
/// function refers to (Names::end_label).
fn label(names: &crate::names::Names, img: &crate::pe::Image, own: (i64, i64), v: i64, bound: Option<&[i64]>) -> String {
    if own.0 <= v && v < own.1 {
        return format!("{v:#x}");
    }
    if let Ok(Some(l)) = names.label_of(v) {
        if let Some(e) = bound.and_then(|u| names.end_label(v, u)) {
            return format!("{l} (or {e})");
        }
        return l;
    }
    if let Some(e) = bound.and_then(|u| names.end_label(v, u)) {
        return format!("{v:#x} (or {e})");
    }
    let s = img.cstr_n(v as u32, 256);
    if s.len() >= 2 && s.len() < 256 && s.iter().all(|&c| (0x20..0x7f).contains(&c) || c == b'\t' || c == b'\n') {
        let t: String = s.iter().take(40).map(|&c| c as char).collect();
        return format!("\"{}\"", t.replace('\n', "\\n"));
    }
    format!("{v:#x}")
}

/// How our relocated field (at `off` of the function at `a`) reads by name: what the original's field refers to
/// (label) when that is our symbol (the ledger registers its C name there) or our literal's bytes (M8 / M9 hold);
/// else our symbol (a string literal as its text), `+off` for an addend.
#[allow(clippy::too_many_arguments)]
fn reloc_name(obj: &crate::coff::Obj, code: &crate::coff::FunctionCode, r: &crate::coff::Reloc, a: u32, off: u32,
              img: &crate::pe::Image, names: &crate::names::Names, own: (i64, i64)) -> String {
    let Some(sym) = obj.symbol_at(r.symbol_index) else { return "?".into() };
    let addend = obj.addend(code.secnum, r);
    let site = a.wrapping_add(off);
    let to = r.resolve(site, &img.bytes(site, r.kind_width().1 as usize), addend).filter(|&t| img.in_image(t));
    let theirs = |t: u32| label(names, img, own, t.wrapping_add(addend) as i64, None);
    let data = if sym.secnum > 0 { obj.sections.get(sym.secnum as usize).and_then(|s| s.data.as_ref()) } else { None };
    let base = match (sym.constant(), data) {
        (Some("string"), Some(d)) => {
            let lit = d.get(sym.value as usize..).unwrap_or(&[]);
            let lit = &lit[..lit.iter().position(|&c| c == 0).map(|z| z + 1).unwrap_or(lit.len())];
            if let Some(t) = to.filter(|&t| *img.bytes(t, lit.len()) == *lit) {
                return theirs(t);
            }
            let t: String = lit.iter().take_while(|&&c| c != 0).take(40).map(|&c| match c {
                b'\n' => "\\n".to_string(),
                0x20..=0x7e => (c as char).to_string(),
                _ => format!("\\x{c:02x}"),
            }).collect();
            format!("\"{t}\"")
        }
        _ => {
            let cname = crate::coff::undecorate(sym.name.strip_prefix("__imp_").unwrap_or(&sym.name));
            if let Some(t) = to.filter(|&t| names.by_name.iter().any(|(n, at)| *n == cname && at.contains(&(t as i64)))) {
                return theirs(t);
            }
            crate::coff::undecorate(&sym.name)
        }
    };
    match addend as i32 {
        0 => base,
        n => format!("{base}{}{:#x}", if n < 0 { "-" } else { "+" }, n.unsigned_abs()),
    }
}

fn py_int0(s: &str) -> Option<i64> {
    let t = s.trim().to_lowercase();
    t.strip_prefix("0x").map(|h| i64::from_str_radix(h, 16).ok()).unwrap_or_else(|| t.parse().ok())
}

/// The function grade row named `key` (a function name or an address).
pub fn find_function(db: &str, key: &str) -> Result<Option<Value>> {
    let a = if key.to_lowercase().starts_with("0x") { py_int0(key) } else { None };
    Ok(crate::queues::function_grades(db)?.iter().cloned()
        .find(|r| r.get("name").and_then(|v| v.as_str()) == Some(key) || (a.is_some() && r["addr"].as_i64() == a))
        .map(Value::Object))
}

/// Every known function start (start facts, function and thunk symbols above open) and the end of every code
/// section: what bounds a function's slot.
pub fn all_starts(db: &str, img: &crate::pe::Image) -> Result<Vec<i64>> {
    let mut s: BTreeSet<i64> = crate::with_db(db, |c| store::facts_of(c, db, "start", None, |_| true))?.iter().map(|f| f.lo).collect();
    s.extend(crate::with_db(db, |c| store::facts_of(c, db, "symbol", None, |f| matches!(f.s("skind"), Some("func" | "thunk")) && f.level > store::OPEN))?
        .iter().map(|f| f.lo));
    s.extend(img.sections.iter().filter(|x| x.holds_code()).map(|x| x.end() as i64));
    Ok(s.into_iter().collect())
}

/// The reading of a graded function (its object's code against the original), or why there is none; with `names`,
/// the texts with names for X too.
pub fn reading(p: &Project, capstone: &str, row: Value, names: Option<&crate::names::Names>) -> Result<Result<Reading, String>, Error> {
    let db = p.store_path();
    let unit = row["unit"].as_str().unwrap_or("").to_string();
    let name = row["name"].as_str().unwrap_or("").to_string();
    let a = row["addr"].as_i64().unwrap_or(0);
    let tus = crate::compile::tu_rows(&db)?;
    let Some(t) = tus.get(&unit).filter(|t| t.ok) else { return Ok(Err(format!("unit {unit} has no object (dcp build)"))) };
    let root = p.root.to_string_lossy().into_owned();
    let obj = std::fs::read(crate::compile::obj_path(&root, &t.obj_hash)).ok().and_then(|d| crate::coff::Obj::parse(&d).ok());
    let Some((obj, k)) = obj.and_then(|o| o.function_index().get(&name).copied().map(|k| (o, k))) else {
        return Ok(Err(format!("the object of unit {unit} defines no {name}")));
    };
    let code = obj.function_code(k);
    let img = crate::image(&p.target(None).map_err(Error::runtime)?.path)?;
    let tc = crate::toolchain::of(&p.toolchain_key()).ok_or_else(|| Error::runtime("no toolchain"))?;
    let fill_forms: Vec<Vec<u8>> = tc.fill_forms().iter().map(|f| f.to_vec()).collect();
    let fills: HashSet<Vec<u8>> = fill_forms.iter().cloned().collect();
    let forms = crate::compare::fill_order(&fill_forms);
    let env = Env { dll: capstone, img: &img, range: (img.base as i64, img.end() as i64), fills: &fills, forms: &forms };
    let e = |s: String| Error::runtime(s);
    let d = &row["dist"];
    let (extent, slot) = match (d.get("extent").and_then(|v| v.as_i64()), d.get("slot").and_then(|v| v.as_i64())) {
        (Some(x), Some(s)) => (x, s),
        _ => {
            let walk = crate::with_db(&db, |c| store::facts_of(c, &db, "symbol", None, |f| {
                f.lo == a && matches!(&*f.rule, "S.codewalk" | "L.src.extent") && f.s("skind") == Some("func")
            }))?;
            let extent = match walk.first() {
                Some(w) => w.hi - w.lo,
                None => {
                    let (cd, cm) = code.code();
                    diffclass::code_size(&env, cd, cm, a as u32).map_err(e)?
                }
            };
            let st = all_starts(&db, &img)?;
            let nxt = st.get(st.partition_point(|&x| x <= a)).copied().unwrap_or(img.end() as i64);
            (extent, extent.max(nxt - a))
        }
    };
    let o = diffclass::original(&env, a as u32, extent, slot, tc.function_alignment() as i64).map_err(e)?;
    let (cd, cm) = code.code();
    let la = crate::x86::strip_fill(crate::x86::listing(env.dll, cd, a as u32, Some(cm), env.range, env.fills).map_err(e)?);
    let data = img.read(a as u32, o.code.max(0) as usize);
    let lb = crate::x86::strip_fill(crate::x86::listing(env.dll, &data, a as u32, None, env.range, env.fills).map_err(e)?);
    let tables = diffclass::compare_tables(&env, &obj, &code, a as u32, &la, &lb, &o.tables);
    let (hunks, verdict) = diffclass::analyse(&la, &lb, tables.as_ref());
    let (named, values) = match names {
        None => (None, None),
        Some(names) => {
            // the same listings (strip_fill drops trailing lines only): ours by the relocations inside each
            // instruction in offset order, the original's by the ledger; a number inside the function's slot (a
            // jump of its own) stays a number on both sides
            let own = (a, a + slot);
            // the original's image addresses outside its own slot (a compare bound's other reading: Names::end_label)
            let used: Vec<i64> = {
                let seen: std::cell::RefCell<Vec<i64>> = Default::default();
                crate::x86::listing_named(env.dll, &data, a as u32, None, env.range, env.fills, &|_, _, v| {
                    if !(own.0 <= v && v < own.1) {
                        seen.borrow_mut().push(v);
                    }
                    None
                }).map_err(e)?;
                seen.into_inner()
            };
            // the values behind the X fields, by instruction address, in text order (Reading::same_values)
            let vals_a: std::cell::RefCell<std::collections::HashMap<u32, Vec<Val>>> = Default::default();
            let vals_b: std::cell::RefCell<std::collections::HashMap<u32, Vec<i64>>> = Default::default();
            let ours = |ins: u32, k: Option<usize>, v: i64| -> Option<String> {
                let o = ins - a as u32;
                let size = la.iter().find(|l| l.addr == ins).map(|l| l.size).unwrap_or(0);
                match k {
                    Some(k) => {
                        let hit = code.relocs.iter().filter(|(off, _)| o <= *off && *off < o + size).nth(k);
                        vals_a.borrow_mut().entry(ins).or_default().push(hit.map(|(_, r)| reloc_val(&obj, &code, r, names)).unwrap_or(Val::Unknown));
                        hit.map(|(off, r)| reloc_name(&obj, &code, r, a as u32, *off, &img, names, own))
                    }
                    None => {
                        vals_a.borrow_mut().entry(ins).or_default().push(if own.0 <= v && v < own.1 { Val::Unknown } else { Val::Addrs(vec![v]) });
                        Some(label(names, &img, own, v, bound(&la, ins).then_some(used.as_slice())))
                    }
                }
            };
            let theirs = |ins: u32, _: Option<usize>, v: i64| -> Option<String> {
                vals_b.borrow_mut().entry(ins).or_default().push(v);
                Some(label(names, &img, own, v, bound(&lb, ins).then_some(used.as_slice())))
            };
            let na = crate::x86::listing_named(env.dll, cd, a as u32, Some(cm), env.range, env.fills, &ours).map_err(e)?;
            let nb = crate::x86::listing_named(env.dll, &data, a as u32, None, env.range, env.fills, &theirs).map_err(e)?;
            let (va, vb) = (vals_a.into_inner(), vals_b.into_inner());
            let values = (la.iter().map(|l| va.get(&l.addr).cloned().unwrap_or_default()).collect(),
                          lb.iter().map(|l| vb.get(&l.addr).cloned().unwrap_or_default()).collect());
            (Some((na.into_iter().take(la.len()).map(|l| l.text).collect(), nb.into_iter().take(lb.len()).map(|l| l.text).collect())),
             Some(values))
        }
    };
    Ok(Ok(Reading { row, la, lb, tables, hunks, verdict, named, values }))
}

// ------------------------------------------------------------------------------------------------ entry points
