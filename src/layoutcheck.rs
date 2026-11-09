//! Record layout across the relink (bug-reports/split-record-table-scaled-index-not-caught.md): symbols of ours
//! that one function addresses through the same register expression are fields of one record of the original's
//! (`mov [eax*4 + cm_KindRun], ..; mov [eax*4 + cm_KindCheck], ..` with eax = kind*5: a table of 0x14-byte records).
//! The original keeps them at fixed distances; our link must keep the same distances, or every record but the
//! first reads its neighbour's fields. Byte-identical code does not show it: each field's reference agrees with φ
//! at the original's layout, and the relink is what moves them apart (gildegold: cm_KindCheck 0x14 after
//! cm_KindRun where the original has 0x10; the tutorial crashed).
//!
//! The groups come from our objects: within a straight run of code (a branch target, a jump or a return ends it),
//! the relocated displacements of memory operands with a register in the address, per (base, index, scale), until
//! an instruction writes one of those registers. A group of two or more named data objects is a constraint: each
//! pair's distance in our link map must equal its distance in φ.

use crate::coff::Obj;
use crate::dis::{self, Flow, OpType, Reg};
use crate::phi::Phi;
use crate::refcheck::Target;
use std::collections::{BTreeSet, HashMap, HashSet};

/// The objects of ours one function addresses through one register expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    pub function: String,
    /// the register expression, as it reads (`[eax*4 + X]`)
    pub expr: String,
    /// (object, our offset into it), in first-seen order, each object once
    pub objects: Vec<(String, i64)>,
}

fn expr(base: Reg, index: Reg, scale: u8) -> String {
    let mut parts = vec![];
    if base != Reg::None {
        parts.push(format!("{base:?}").to_lowercase());
    }
    if index != Reg::None {
        parts.push(if scale > 1 { format!("{:?}*{scale}", index).to_lowercase() } else { format!("{index:?}").to_lowercase() });
    }
    parts.push("X".into());
    format!("[{}]", parts.join(" + "))
}

/// The groups of one object's functions.
pub fn groups(obj: &Obj) -> Vec<Group> {
    let mut out = vec![];
    for (name, k) in obj.function_index() {
        let code = obj.function_code(k);
        let (cd, _) = code.code();
        let ins = dis::decode(cd, 0);
        let end = code.code_len.unwrap_or(cd.len() as u32);
        let relocs: HashMap<u32, usize> = code.relocs.iter().enumerate().filter(|(_, (off, _))| *off < end).map(|(i, (off, _))| (*off, i)).collect();
        let targets: HashSet<u32> = ins.iter().filter(|i| matches!(i.flow, Flow::Jump | Flow::CondJump)).filter_map(|i| i.target).collect();
        // open groups: (base, index, scale) -> the objects
        let mut open: HashMap<(Reg, Reg, u8), Vec<(String, i64)>> = HashMap::new();
        let close = |open: &mut HashMap<(Reg, Reg, u8), Vec<(String, i64)>>, keep: &dyn Fn(&(Reg, Reg, u8)) -> bool, out: &mut Vec<Group>| {
            let mut gone: Vec<(Reg, Reg, u8)> = open.keys().filter(|k| !keep(k)).copied().collect();
            gone.sort_by_key(|k| (k.0 as u32, k.1 as u32, k.2));
            for k in gone {
                let objs = open.remove(&k).unwrap_or_default();
                if objs.len() >= 2 {
                    out.push(Group { function: name.clone(), expr: expr(k.0, k.1, k.2), objects: objs });
                }
            }
        };
        for i in &ins {
            if targets.contains(&i.addr) {
                close(&mut open, &|_| false, &mut out);
            }
            if i.disp.size == 4 {
                if let Some(&ri) = relocs.get(&(i.addr + i.disp.at as u32)) {
                    if let Some(m) = i.ops.iter().find(|o| o.typ == OpType::Mem && (o.base != Reg::None || o.index != Reg::None) && o.base != Reg::ESP) {
                        if let Target::Name { name: obj_name, delta } = crate::refcheck::target(obj, &code, &code.relocs[ri].1) {
                            let within = obj.addend(code.secnum, &code.relocs[ri].1).wrapping_sub(delta) as i32 as i64;
                            let key = (m.base, m.index, m.scale);
                            let g = open.entry(key).or_default();
                            if !g.iter().any(|(n, _)| *n == obj_name) {
                                g.push((obj_name, within));
                            }
                        }
                    }
                }
            }
            // a register of a group's expression written: that group ends
            let defs = i.defs;
            close(&mut open, &|k: &(Reg, Reg, u8)| defs & (dis::gpr_bit(k.0) | dis::gpr_bit(k.1)) == 0, &mut out);
            if matches!(i.flow, Flow::Jump | Flow::Ret | Flow::IndirectJump | Flow::Trap) {
                close(&mut open, &|_| false, &mut out);
            }
        }
        close(&mut open, &|_| false, &mut out);
    }
    out
}

/// One pair of objects whose distance our link does not keep.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    pub function: String,
    pub expr: String,
    pub a: String,
    pub b: String,
    pub theirs: i64,
    pub ours: i64,
}

impl Violation {
    pub fn line(&self) -> String {
        let off = |x: i64| if x < 0 { format!("-{:#x}", -x) } else { format!("+{x:#x}") };
        format!("M.layout: {} addresses {} and {} through one register expression {}: the original keeps {} at {}{}, our link at {}{}; \
                 they are fields of one record table: declare the record (a struct array) instead of separate objects",
                self.function, self.a, self.b, self.expr, self.b, self.a, off(self.theirs), self.a, off(self.ours))
    }
}

/// How far apart two fields of one record lie at most, for the check to call them a record's: objects further apart
/// are parallel arrays indexed alike (txt_Ptrs[i], txt_Random[i]) or buffers addressed through one computed offset,
/// unless one of them is declared as a single element (indexing a one-element object only makes sense for a split
/// table).
const RECORD_SPAN: i64 = 0x100;

/// The violations of every group: our link map's addresses (`map`: name -> address) against φ's.
pub fn check(groups: &[Group], map: &HashMap<String, u32>, phi: &Phi) -> Vec<Violation> {
    let phi_one = |n: &str| -> Option<i64> {
        let m = phi.of(n)?;
        (m.len() == 1).then(|| *m.keys().next().unwrap())
    };
    let mut out = vec![];
    let mut seen = BTreeSet::new();
    for g in groups {
        let Some((a, _)) = g.objects.first() else { continue };
        let (Some(pa), Some(&oa)) = (phi_one(a), map.get(a)) else { continue };
        for (b, _) in &g.objects[1..] {
            let (Some(pb), Some(&ob)) = (phi_one(b), map.get(b)) else { continue };
            let (theirs, ours) = (pb - pa, ob as i64 - oa as i64);
            let single = |n: &str| phi.size_of(n).is_some_and(|z| z <= 4);
            let record = theirs.abs() <= RECORD_SPAN || single(a) || single(b);
            if theirs != ours && record && seen.insert((a.clone(), b.clone())) {
                out.push(Violation { function: g.function.clone(), expr: g.expr.clone(), a: a.clone(), b: b.clone(), theirs, ours });
            }
        }
    }
    out
}

/// Our link map's data and function addresses by C name (debugger::map_rows: publics and statics).
pub fn map_addresses(text: &str) -> HashMap<String, u32> {
    let (rows, _) = crate::debugger::map_rows(text);
    let mut m = HashMap::new();
    for (va, _, name, _) in rows {
        m.entry(crate::debugger::c_name(&name)).or_insert(va);
    }
    m
}

/// The check over the linked objects (unit, path) and the link map: the violation lines.
pub fn run(objects: &[(String, String)], map_path: &str, phi: &Phi) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(map_path) else { return vec![] };
    let map = map_addresses(&text);
    let mut gs = vec![];
    for (_, path) in objects {
        if let Ok(data) = std::fs::read(path) {
            if let Ok(obj) = Obj::parse(&data) {
                gs.extend(groups(&obj));
            }
        }
    }
    check(&gs, &map, phi).iter().map(|v| v.line()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::rc::Rc;

    /// `mov [eax+A], ecx; mov [eax+B], edx; mov eax, 1; mov [eax+C], ecx; ret`: A and B through one expression, C after
    /// eax is written (another group).
    fn obj() -> Obj {
        let code = [0x89u8, 0x88, 0, 0, 0, 0, 0x89, 0x90, 0, 0, 0, 0, 0xb8, 1, 0, 0, 0, 0x89, 0x88, 0, 0, 0, 0, 0xc3];
        let relocs = [(2u32, 2u32, 6u16), (8, 3, 6), (19, 4, 6)];
        let syms = [(".text", 0, 1, 3), ("_f", 0, 1, 2), ("_g_a", 0, 0, 2), ("_g_b", 0, 0, 2), ("_g_c", 0, 0, 2)];
        Obj::parse(&crate::coff::testlib::code_obj(&code, &relocs, &syms)).unwrap()
    }

    fn phi(at: &[(u32, &str, i64)]) -> Phi {
        let claims: Vec<Rc<crate::store::Claim>> = at.iter().map(|&(lo, n, size)| {
            let v = json!({"name": n, "origin": "source", "size": size});
            Rc::new(crate::store::Claim { id: lo as i64, rule: Rc::from("L.src"), lo: lo as i64, hi: lo as i64 + 1, text: String::new(), value: v,
                                          support: crate::store::DECLARED, by: "t".into(), reason: None })
        }).collect();
        Phi::new(&claims, &[])
    }

    #[test]
    fn fields_of_one_record_keep_their_distance() {
        let gs = groups(&obj());
        assert_eq!(gs.len(), 1, "{gs:?}");
        assert_eq!(gs[0].objects.iter().map(|o| o.0.as_str()).collect::<Vec<_>>(), ["g_a", "g_b"]);
        assert_eq!(gs[0].expr, "[eax + X]");
        // the original: g_b 0x10 after g_a (one record), our link: 0x14 after (cm_KindRun / cm_KindCheck)
        let p = phi(&[(0x92c500, "g_a", 4), (0x92c510, "g_b", 0xf0)]);
        let map: HashMap<String, u32> = [("g_a".to_string(), 0x7000), ("g_b".to_string(), 0x7014)].into_iter().collect();
        let v = check(&gs, &map, &p);
        assert_eq!(v.len(), 1);
        assert!(v[0].line().contains("the original keeps g_b at g_a+0x10, our link at g_a+0x14"), "{}", v[0].line());
        // the same distance: nothing
        let map: HashMap<String, u32> = [("g_a".to_string(), 0x7000), ("g_b".to_string(), 0x7010)].into_iter().collect();
        assert!(check(&gs, &map, &p).is_empty());
        // parallel arrays far apart (each sized for its elements): nothing whatever the link does
        let p = phi(&[(0x500000, "g_a", 0x400), (0x600000, "g_b", 0x400)]);
        let map: HashMap<String, u32> = [("g_a".to_string(), 0x7000), ("g_b".to_string(), 0x9000)].into_iter().collect();
        assert!(check(&gs, &map, &p).is_empty());
    }
}
