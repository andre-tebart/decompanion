//! `dcp asmdiff` and `dcp diffclass`: one graded function's reading as G.grade takes it (diffclass.rs: our
//! listing against the original's, the switch tables, the hunks and the verdict), for the commands to print.

use crate::error::{Error, Result};
use crate::diffclass::{self, Env, FunctionCompare};
use crate::project::Project;
use crate::store;
use crate::x86::Line;
use serde_json::Value;
use std::collections::{BTreeSet, HashSet};

/// A function's reading: its grade row and its comparison (our listing, the original's, the tables compare, the
/// hunks and the verdict: `FunctionCompare`, which it derefs to).
pub struct Reading {
    pub row: Value,
    pub fc: FunctionCompare,
    /// the texts of la and lb with names for X (reading's `names`): our relocations' symbols, the ledger's labels
    pub named: Option<(Vec<String>, Vec<String>)>,
    /// with `named`, per line the values behind its X fields in text order: ours what each resolves to, the
    /// original's the number (Reading::same_values)
    pub values: Option<(Vec<Vec<Val>>, Vec<Vec<i64>>)>,
    /// the dataflow-equivalence prover's verdict (equiv.rs), and how many of our relocations it could not bind to
    /// the original's addresses
    pub proof: (crate::equiv::Outcome, usize),
    /// a concrete difference (equiv::witness: a call or a global store one side has and the other never refers
    /// to), said with the ledger's name of its address
    pub witness: Option<String>,
    /// the callees the two sides call a different number of times (equiv::calls_differ), named by φ: (name, ours,
    /// the original's), and how many of our calls go to a symbol bind could not place
    pub calls: (Vec<(String, usize, usize)>, usize),
    /// the reference check (refcheck.rs, G.grade's): each of our relocations at an aligned instruction against
    /// φ, a literal by its bytes
    pub refs: crate::refcheck::Check,
    /// its concrete differences, one line each (`M8 at +0x1c: ...`), and the references φ says nothing about
    pub ref_lines: Vec<String>,
    pub open_lines: Vec<String>,
    /// our references outside their object's declared size (refcheck::Outside, M.contain): (our field's address,
    /// its line)
    pub outside: Vec<(u32, String)>,
    /// the reference census (refcheck::census): an object one side refers to and the
    /// other never refers into, one line each
    pub census: Vec<String>,
    /// our code (the function's bytes, relocated fields as compiled) and the original's at the function's address
    pub code: (Vec<u8>, Vec<u8>),
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

impl std::ops::Deref for Reading {
    type Target = FunctionCompare;
    fn deref(&self) -> &FunctionCompare {
        &self.fc
    }
}

impl Reading {
    /// The addresses behind the X fields of line i of ours and line j of the original's (a `!` line: the names
    /// differ, the addresses say whether they are one datum): `0x770ae4 | 0x770ae0`.
    pub fn addresses(&self, i: usize, j: usize) -> Option<String> {
        let (va, vb) = self.values.as_ref()?;
        // where a value of ours is unknown (a jump of our own, a symbol the ledger does not place) there is nothing
        // to compare
        let ours: Vec<String> = va.get(i)?.iter().map(|v| match v {
            Val::Addrs(a) => Some(a.iter().map(|x| format!("{x:#x}")).collect::<Vec<_>>().join("/")),
            Val::Lit(_) => Some("literal".into()),
            Val::Unknown => None,
        }).collect::<Option<_>>()?;
        let theirs: Vec<String> = vb.get(j)?.iter().map(|v| format!("{v:#x}")).collect();
        (!ours.is_empty() || !theirs.is_empty()).then(|| format!("{} | {}", ours.join(", "), theirs.join(", ")))
    }

    /// The calls line (equiv::calls_differ, the call set witness reads): each callee whose count differs, with
    /// both counts, `calls: _ftol ours x2, the original x1`; None when every count agrees.
    pub fn calls_line(&self) -> Option<String> {
        let (diff, unbound) = &self.calls;
        if diff.is_empty() {
            return None;
        }
        let each: Vec<String> = diff.iter().map(|(n, a, b)| format!("{n} ours x{a}, the original x{b}")).collect();
        let tail = if *unbound > 0 { format!(" ({unbound} of our calls to a symbol not placed: left out)") } else { String::new() };
        Some(format!("calls: {}{tail}", each.join("; ")))
    }

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
fn reloc_val(obj: &crate::coff::Obj, code: &crate::coff::FunctionCode, r: &crate::coff::Reloc, names: &crate::names::Names,
             tables: &[(i64, i64)]) -> Val {
    let Some(sym) = obj.symbol_at(r.symbol_index) else { return Val::Unknown };
    let addend = obj.addend(code.secnum, r) as i32 as i64;
    // a label of our function's own section ($L16004, a switch table): the original's table at the same index,
    // when the tables compare equal (tables: (our offset, the original's address))
    if sym.secnum as usize == code.secnum {
        let off = sym.value as i64 + addend - code.start as i64;
        if let Some(t) = tables.iter().find(|t| t.0 == off) {
            return Val::Addrs(vec![t.1]);
        }
    }
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
            let mut at: Vec<i64> = names.addrs_of(&cname).to_vec();
            if let Some(v) = crate::srcscan::placeholder_whole(&cname) {
                at.push(v as i64);
            }
            // `&sym + N` outside sym's declared size is no address of sym (M.contain): whatever number the sum
            // makes, it equals nothing of the original's
            let outside = names.phi.size_of(&cname).is_some_and(|n| sym.secnum as usize != code.secnum && !(0..=n).contains(&addend));
            if at.is_empty() || outside {
                Val::Unknown
            } else {
                Val::Addrs(at.into_iter().map(|a| a + addend).collect())
            }
        }
    }
}

/// The value of a floating constant of `size` bytes (4 or 8) at an address of the image's read-only data, as the
/// text writes it.
fn float_at(img: &crate::pe::Image, v: i64, size: u8) -> Option<String> {
    if img.section_of(v as u32).is_none_or(|s| s.writable()) {
        return None; // a variable: its initial value says nothing
    }
    let b = img.bytes(v as u32, size as usize);
    match size {
        4 => Some(format!("{:?}", f32::from_le_bytes(b[..4].try_into().ok()?))),
        8 => Some(format!("{:?}", f64::from_le_bytes(b[..8].try_into().ok()?))),
        _ => None,
    }
}

/// The size of the floating constant line `ins` of `lines` loads from memory (an FPU instruction with a dword /
/// qword operand at an X address), None for any other line.
fn float_operand(lines: &[Line], ins: u32) -> Option<u8> {
    let l = lines.iter().find(|l| l.addr == ins)?;
    if !l.shape.fpu() {
        return None;
    }
    l.shape.ops.iter().find_map(|o| match *o {
        crate::shape::Opnd::Mem { size: z @ (4 | 8), disp: crate::shape::Num::X, .. } => Some(z),
        _ => None,
    })
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
    let text = || {
        let s = img.cstr_n(v as u32, 256);
        (s.len() >= 2 && s.len() < 256 && s.iter().all(|&c| (0x20..0x7f).contains(&c) || c == b'\t' || c == b'\n')).then(|| {
            let t: String = s.iter().take(40).map(|&c| c as char).collect();
            format!("\"{}\"", t.replace('\n', "\\n"))
        })
    };
    if let Ok(Some(l)) = names.label_of(v) {
        if let Some(e) = bound.and_then(|u| names.end_label(v, u)) {
            return format!("{l} (or {e})");
        }
        // a placeholder name the ledger gave a pooled string literal (net_Unk5fe7d0 for "%i") reads as the string
        if l.contains("_Unk") && crate::srcscan::placeholder_whole(&l).is_some() {
            if let Some(t) = text() {
                return t;
            }
        }
        return l;
    }
    if let Some(e) = bound.and_then(|u| names.end_label(v, u)) {
        return format!("{v:#x} (or {e})");
    }
    text().unwrap_or_else(|| format!("{v:#x}"))
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
        // __real@42480000: the name with its bits (undecorate would take an all-digit suffix for stdcall's @N) and
        // the value
        (Some("float"), _) => {
            let hex = sym.name.rsplit('@').next().unwrap_or("");
            let value = u64::from_str_radix(hex, 16).ok().map(|b| if hex.len() == 8 { format!("{:?}", f32::from_bits(b as u32)) } else { format!("{:?}", f64::from_bits(b)) });
            let theirs_too = to.and_then(|t| float_at(img, t as i64, (hex.len() / 2) as u8)).filter(|v| Some(v) == value.as_ref());
            if let (Some(t), Some(_)) = (to, theirs_too) {
                return format!("{} ({})", theirs(t), value.unwrap_or_default());
            }
            format!("{} ({})", sym.name.strip_prefix('_').unwrap_or(&sym.name), value.unwrap_or_else(|| "?".into()))
        }
        _ => {
            let cname = crate::coff::undecorate(sym.name.strip_prefix("__imp_").unwrap_or(&sym.name));
            if let Some(t) = to.filter(|&t| names.addrs_of(&cname).contains(&(t as i64))) {
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
    let mut s: BTreeSet<i64> = crate::with_db(db, |c| store::claims_of(c, db, "start", None, |_| true))?.iter().map(|f| f.lo).collect();
    s.extend(crate::with_db(db, |c| store::claims_of(c, db, "symbol", None, |f| matches!(f.s("skind"), Some("func" | "thunk")) && f.support > store::OPEN))?
        .iter().map(|f| f.lo));
    s.extend(img.sections.iter().filter(|x| x.holds_code()).map(|x| x.end() as i64));
    Ok(s.into_iter().collect())
}

/// The reading of a graded function (its object's code against the original), or why there is none; with `names`,
/// the texts with names for X too.
pub fn reading(p: &Project, row: Value, names: Option<&crate::names::Names>) -> Result<Result<Reading, String>, Error> {
    let db = p.store_path();
    let unit = row["unit"].as_str().unwrap_or("").to_string();
    let name = row["name"].as_str().unwrap_or("").to_string();
    let a = row["addr"].as_i64().unwrap_or(0);
    let tus = crate::timing::phase("r.tus", || crate::compile::tu_rows(&db))?;
    let Some(t) = tus.get(&unit).filter(|t| t.ok) else { return Ok(Err(format!("unit {unit} has no object (dcp build)"))) };
    let root = p.root.to_string_lossy().into_owned();
    let obj = crate::timing::phase("r.obj", || std::fs::read(crate::compile::obj_path(&root, &t.obj_hash)).ok().and_then(|d| crate::coff::Obj::parse(&d).ok()));
    let Some((obj, k)) = obj.and_then(|o| o.function_index().get(&name).copied().map(|k| (o, k))) else {
        return Ok(Err(format!("the object of unit {unit} defines no {name}")));
    };
    let code = obj.function_code(k);
    let img = crate::timing::phase("r.img", || crate::image(&p.target.path))?;
    let tc = crate::toolchain::Vc6;
    let fill_forms: Vec<Vec<u8>> = tc.fill_forms().iter().map(|f| f.to_vec()).collect();
    let fills: HashSet<Vec<u8>> = fill_forms.iter().cloned().collect();
    let forms = crate::compare::fill_order(&fill_forms);
    let env = Env { img: &img, range: (img.base as i64, img.end() as i64), fills: &fills, forms: &forms };
    let d = &row["dist"];
    let (extent, slot) = match (d.get("extent").and_then(|v| v.as_i64()), d.get("slot").and_then(|v| v.as_i64())) {
        (Some(x), Some(s)) => (x, s),
        _ => {
            let walk = crate::with_db(&db, |c| store::claims_of(c, &db, "symbol", None, |f| {
                f.lo == a && matches!(&*f.rule, "S.codewalk" | "L.src.extent") && f.s("skind") == Some("func")
            }))?;
            let extent = match walk.first() {
                Some(w) => w.hi - w.lo,
                None => {
                    let (cd, cm) = code.code();
                    diffclass::code_size(&env, cd, cm, a as u32)
                }
            };
            let st = crate::timing::phase("r.starts", || all_starts(&db, &img))?;
            let nxt = st.get(st.partition_point(|&x| x <= a)).copied().unwrap_or(img.end() as i64);
            (extent, extent.max(nxt - a))
        }
    };
    let o = diffclass::original(&env, a as u32, extent, slot, tc.function_alignment() as i64);
    let data = img.read(a as u32, o.code.max(0) as usize);
    let fc = crate::timing::phase("r.compare", || FunctionCompare::new(&env, &obj, &code, a as u32, &o));
    let (cd, cm) = code.code();
    let (la, lb) = (&fc.la, &fc.lb);
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
                crate::x86::listing_named(&data, a as u32, None, env.range, env.fills, &|_, _, v| {
                    if !(own.0 <= v && v < own.1) {
                        seen.borrow_mut().push(v);
                    }
                    None
                });
                seen.into_inner()
            };
            // our switch tables against the original's, in order, when they compare equal: (our offset, the address)
            let table_pairs: Vec<(i64, i64)> = if fc.tables.as_ref().is_some_and(|t| t.diffs.is_empty()) {
                let mut ours: Vec<i64> = code.relocs.iter().filter_map(|(_, r)| {
                    let sym = obj.symbol_at(r.symbol_index).filter(|s| s.secnum as usize == code.secnum)?;
                    let off = sym.value as i64 + obj.addend(code.secnum, r) as i32 as i64 - code.start as i64;
                    (off >= code.code_len.unwrap_or(u32::MAX) as i64).then_some(off)
                }).collect::<BTreeSet<_>>().into_iter().collect();
                ours.sort();
                let theirs: Vec<i64> = o.tables.iter().map(|t| t.0).collect();
                if ours.len() == theirs.len() { ours.into_iter().zip(theirs).collect() } else { vec![] }
            } else {
                vec![]
            };
            // our code's own extent: a jump inside it is ours, whatever the original has at that address
            let ours_end = la.last().map(|l| (l.addr + l.size) as i64).unwrap_or(a);
            // the values behind the X fields, by instruction address, in text order (Reading::same_values)
            let vals_a: std::cell::RefCell<std::collections::HashMap<u32, Vec<Val>>> = Default::default();
            let vals_b: std::cell::RefCell<std::collections::HashMap<u32, Vec<i64>>> = Default::default();
            let ours = |ins: u32, k: Option<usize>, v: i64| -> Option<String> {
                let o = ins - a as u32;
                let size = la.iter().find(|l| l.addr == ins).map(|l| l.size).unwrap_or(0);
                match k {
                    Some(k) => {
                        let hit = code.relocs.iter().filter(|(off, _)| o <= *off && *off < o + size).nth(k);
                        let val = hit.map(|(_, r)| reloc_val(&obj, &code, r, names, &table_pairs)).unwrap_or(Val::Unknown);
                        let name = hit.map(|(off, r)| reloc_name(&obj, &code, r, a as u32, *off, &img, names, own));
                        // a floating constant we load through a symbol the ledger places (extern net_Unk5eb9b8): its
                        // value there, as the original's line shows it (a __real@ constant names its own)
                        let value = match (&val, float_operand(la, ins)) {
                            (Val::Addrs(xs), Some(z)) if !xs.is_empty() && name.as_ref().is_some_and(|n| !n.ends_with(')')) => float_at(&img, xs[0], z),
                            _ => None,
                        };
                        vals_a.borrow_mut().entry(ins).or_default().push(val);
                        name.map(|n| match value {
                            Some(f) => format!("{n} ({f})"),
                            None => n,
                        })
                    }
                    // a number of ours no relocation covers: a jump inside our own code, or a constant (every address
                    // an object holds is relocated): the number, never a name
                    None => {
                        let inside = (own.0 <= v && v < own.1) || (a <= v && v < ours_end);
                        vals_a.borrow_mut().entry(ins).or_default().push(if inside { Val::Unknown } else { Val::Addrs(vec![v]) });
                        Some(format!("{v:#x}"))
                    }
                }
            };
            let theirs = |ins: u32, _: Option<usize>, v: i64| -> Option<String> {
                vals_b.borrow_mut().entry(ins).or_default().push(v);
                let l = label(names, &img, own, v, bound(lb, ins).then_some(used.as_slice()));
                // a floating constant the original loads: its value too
                Some(match float_operand(lb, ins).and_then(|z| float_at(&img, v, z)) {
                    Some(f) => format!("{l} ({f})"),
                    None => l,
                })
            };
            let na = crate::x86::listing_named(cd, a as u32, Some(cm), env.range, env.fills, &ours);
            let nb = crate::x86::listing_named(&data, a as u32, None, env.range, env.fills, &theirs);
            let (va, vb) = (vals_a.into_inner(), vals_b.into_inner());
            let values = (la.iter().map(|l| va.get(&l.addr).cloned().unwrap_or_default()).collect(),
                          lb.iter().map(|l| vb.get(&l.addr).cloned().unwrap_or_default()).collect());
            (Some((na.into_iter().take(la.len()).map(|l| l.text).collect(), nb.into_iter().take(lb.len()).map(|l| l.text).collect())),
             Some(values))
        }
    };
    // φ: the one --symbols built, else the ledger's names (names::NAME_RULES, as G.grade reads them)
    let built_phi;
    let phi: &crate::phi::Phi = match names {
        Some(n) => &n.phi,
        None => {
            built_phi = crate::timing::phase("r.phi", || crate::names::ledger_phi(&db))?;
            &built_phi
        }
    };
    let sites = crate::refcheck::sites_aligned(&code, &img, a as u32, &fc.la, &fc.lb);
    let refs_of = crate::refcheck::Refs::new(&obj, &code, phi);
    let refs = crate::refcheck::check(&obj, &code, &img, &sites, &refs_of, phi).settle_calls(&obj, &code, &refs_of, &data, a as u32);
    let ref_lines = refs.lines(phi, a as u32, Some(&unit));
    let open_lines = refs.open_lines(phi, a as u32);
    let outside = refs_of.outside.iter().map(|o| (a as u32 + o.off, o.line())).collect();
    let mut witness = None;
    let mut census = vec![];
    let mut calls = (vec![], 0);
    let proof = crate::timing::phase("r.proof", || -> Result<_, Error> { Ok({
        let (ours, unbound) = crate::equiv::bind(&obj, &code, &img, a as u32, &sites, &refs_of, phi);
        if let Some(dir) = std::env::var_os("DCP_EQUIV_DUMP") {
            // the prover's inputs, for its corpus test (equiv::tests::corpus)
            let grade = row["grade"].as_str().or(row["outcome"].as_str()).unwrap_or("?");
            crate::equiv::dump(std::path::Path::new(&dir), &name, grade, a as u32, &ours, &data, unbound);
        }
        if let Some(w) = crate::equiv::witness(&ours, &data, a as u32, unbound) {
            let name = phi.names_at(w.addr as i64).into_iter().next();
            let (who, other) = if w.ours { ("ours", "the original") } else { ("the original", "ours") };
            witness = Some(format!("{who} +{:#x} {} {:#x}{}; {other} never refers to it", w.at - a as u32, w.what, w.addr,
                                   name.map(|n| format!(" ({n})")).unwrap_or_default()));
        }
        let inp = crate::refcheck::census_input(&obj, &code, &refs_of, &ours, unbound, &data, a as u32, &img);
        census = crate::refcheck::census(&inp, phi).iter().map(|c| c.line()).collect();
        let (diff, unbound) = crate::equiv::calls_differ(&ours, &data, a as u32);
        let named = |t: u32| phi.names_at(t as i64).into_iter().next().unwrap_or_else(|| format!("{t:#x}"));
        calls = (diff.into_iter().map(|(t, x, y)| (named(t), x, y)).collect(), unbound);
        (crate::timing::phase("r.prove", || crate::equiv::prove(&ours, &data, a as u32)), unbound)
    }) })?;
    let code = (code.code().0.to_vec(), data.clone());
    Ok(Ok(Reading { row, fc, named, values, proof, witness, calls, refs, ref_lines, open_lines, outside, census, code }))
}

// ------------------------------------------------------------------------------------------------ entry points
