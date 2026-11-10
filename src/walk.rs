//! The code walk (rule S.codewalk): recursive descent over the code sections, and the Walker it uses.
//!
//! Conventions it rests on (derived level; VC6 / LINK are the toolchain they were stated for):
//!   W1  a function's code is contiguous: every block of a function lies between its start and the next
//!       function's start, and its jump tables follow its code. A direct jump that crosses a known start is
//!       therefore a tail call to another function (VC6 emits `pop ..; jmp f` for `return f(args)`), and a
//!       jump-table entry never points past the next start.
//!   W2  a direct call target is a function start, unless it lies inside the calling function's own range
//!       (a local subroutine of assembly-written library code): then it is an inner label of that function.
//!   W3  a code address pushed or stored as an immediate at a relocation site, and a code address stored in a
//!       data section (a function pointer), is a function start.
//!   W4  a function ends at a return, at an unconditional jump (direct or indirect), and at alignment fill
//!       (Vc6::fill_forms) reached by fall-through; a jump target is code whatever its first instruction.
//!       A call followed directly by a known start ends the function too: the callee does not return (VC6
//!       emits nothing after a call to a noreturn function such as _exit or _endthread).
//!   W5  an unconditional direct jump followed only by alignment fill up to its target, the target at the
//!       toolchain's function alignment, is a tail call to a function starting there: the toolchain pads between
//!       functions, never inside one. The alignment keeps an inline `int 3` jumped over inside a function
//!       (`__asm int 3`, the same byte as int3 fill) from passing for padding.
//! Declared starts (decl/text.dcl `start`, rule L.decl.start) are roots like the others; every fact that rests on
//! one (its function, its references, the starts only its code reaches, and so on) is declared, not derived.
//! The walk is repeated with the growing set of starts until that set is stable, so no walk ever runs into a
//! start found later. A walk that still runs into bytes another function owns is a conflict (C.walk): one of the
//! two starts is wrong.
//!
//! Instructions come from x86::Decoder (dis.rs's typed instructions), fill forms from the toolchain.
//!
//! How it is computed (none of this changes a result):
//! - Every instruction is decoded once per rule run (the decoder memoises its records by address).
//! - A root's walk is a function of the bytes, the claims of other rules, and the starts between the root and
//!   the next start (W1 confines it there). Each iteration therefore replays a root's recorded walk instead of
//!   repeating it when the next start after the root is unchanged and the walk saw no byte another walk owns;
//!   everything else is walked again, in the same order as a walk from scratch.

use crate::error::{Error, Result};
use crate::rules::Ctx;
use crate::store::{Out, DECLARED, DERIVED};
use crate::x86::{Decoder, WIns, CALL, CJUMP, IJUMP, JUMP, RET};
use rusqlite::Connection;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// What one root's walk did: its claims in order, its references, the positions where it stopped for a reason
/// other than a foreign byte (probes), whether it saw a byte another walk owns (foreign), the next start after
/// the root when it walked (ns), its extent.
#[derive(Default)]
struct Record {
    claims: Vec<(u32, u32, u8)>,
    calls: Vec<(u32, u32, u32)>,
    tails: Vec<(u32, u32)>,
    imms: Vec<(u32, u32)>,
    operands: Vec<(u32, u32, u32, u8)>,
    tables: Vec<(u32, u32, u32, &'static str)>,
    overlaps: Vec<(u32, u32, u32)>,
    probes: Vec<u32>,
    foreign: bool,
    ns: u32,
    extent: u32,
}

struct Walker<'a> {
    dec: Decoder<'a>,
    align: u32,
    lo: u32,
    hi: u32,
    owner: Vec<u32>,
    kind: Vec<u8>, // 1 code, 2 table data, 3 placed by another rule
    calls: BTreeMap<u32, BTreeSet<u32>>, // target -> call sites
    call_size: HashMap<u32, u32>,
    tails: BTreeMap<u32, BTreeSet<u32>>,
    imms: BTreeMap<u32, BTreeSet<u32>>,
    operands: Vec<(u32, u32, u32, u8)>, // (site, size, target, operand size)
    tables: Vec<(u32, u32, u32, &'static str)>,
    overlaps: Vec<(u32, u32, u32)>,
    extent: HashMap<u32, u32>,
    claimed: HashMap<u32, Vec<(u32, u32, u8)>>,
    reloc_sites: &'a HashSet<u32>,
    stops: HashSet<u32>,
    sorted_stops: Vec<u32>,
    rec: Option<Record>,
}

impl Walker<'_> {
    fn in_code(&self, a: u32) -> bool {
        self.lo <= a && a < self.hi
    }

    /// Is there a stop s with min(a, b) < s <= max(a, b)? (a jump from a to b leaves the function)
    fn crosses_stop(&self, a: u32, b: u32) -> bool {
        let (lo, hi) = if a < b { (a, b) } else { (b, a) };
        let i = self.sorted_stops.partition_point(|&s| s <= lo);
        i < self.sorted_stops.len() && self.sorted_stops[i] <= hi
    }

    /// W5: the bytes from a up to t are alignment fill only (at least one byte), t at the function alignment.
    fn fill_to(&mut self, a: u32, t: u32) -> Result<bool, String> {
        if t <= a || t % self.align != 0 {
            return Ok(false);
        }
        let mut cur = a;
        while let Some(ins) = self.dec.at(cur) {
            if ins.addr >= t {
                return Ok(ins.addr == t);
            }
            if !ins.fill {
                return Ok(false);
            }
            cur = ins.addr + ins.size;
        }
        Ok(false)
    }

    fn next_stop(&self, a: u32) -> u32 {
        let i = self.sorted_stops.partition_point(|&s| s <= a);
        self.sorted_stops.get(i).copied().unwrap_or(self.hi)
    }

    fn claim(&mut self, lo: u32, hi: u32, owner: u32, kind: u8) {
        let n = self.owner.len();
        let (a, b) = (((lo - self.lo) as usize).min(n), ((hi - self.lo) as usize).min(n));
        self.owner[a..b].fill(owner);
        self.kind[a..b].fill(kind);
        if kind != 3 {
            self.claimed.entry(owner).or_default().push((lo, hi, kind));
            if let Some(r) = self.rec.as_mut() {
                r.claims.push((lo, hi, kind));
            }
        }
        if kind == 1 {
            let e = self.extent.entry(owner).or_insert(owner);
            *e = (*e).max(hi);
        }
    }

    /// Add a record's references to the walk's (claims are applied separately).
    fn merge(&mut self, rec: &Record) {
        for &(t, s, n) in &rec.calls {
            self.calls.entry(t).or_default().insert(s);
            self.call_size.insert(s, n);
        }
        for &(t, s) in &rec.tails {
            self.tails.entry(t).or_default().insert(s);
        }
        for &(t, s) in &rec.imms {
            self.imms.entry(t).or_default().insert(s);
        }
        self.operands.extend_from_slice(&rec.operands);
        self.tables.extend_from_slice(&rec.tables);
        self.overlaps.extend_from_slice(&rec.overlaps);
    }

    /// Apply a recorded walk of root when it is what walking again would do now: the next start after the root
    /// is the same, the walk saw no byte another walk owned, and none of its claimed or probed bytes is owned by
    /// another walk now. False (and nothing applied) otherwise.
    fn replay(&mut self, root: u32, rec: &Record) -> bool {
        if rec.foreign || rec.ns != self.next_stop(root) {
            return false;
        }
        let l = self.lo;
        for &(lo, hi, _) in &rec.claims {
            if self.kind[(lo - l) as usize..(hi - l) as usize].iter().any(|&k| k != 0) {
                return false;
            }
        }
        for &(lo, hi, k) in &rec.claims {
            self.owner[(lo - l) as usize..(hi - l) as usize].fill(root);
            self.kind[(lo - l) as usize..(hi - l) as usize].fill(k);
        }
        for &p in &rec.probes {
            let o = (p - l) as usize;
            if self.kind[o] != 0 && self.owner[o] != root {
                for &(lo, hi, _) in &rec.claims {
                    self.owner[(lo - l) as usize..(hi - l) as usize].fill(0);
                    self.kind[(lo - l) as usize..(hi - l) as usize].fill(0);
                }
                return false;
            }
        }
        self.claimed.entry(root).or_default().extend_from_slice(&rec.claims);
        self.extent.insert(root, rec.extent);
        self.merge(rec);
        true
    }

    /// Walk a root from scratch, recording what it did, and add its references.
    fn walk_root(&mut self, root: u32) -> Result<Record, String> {
        self.rec = Some(Record { ns: self.next_stop(root), ..Default::default() });
        let r = self.walk(root, root);
        let mut rec = self.rec.take().unwrap();
        r?;
        rec.extent = self.extent[&root];
        self.merge(&rec);
        Ok(rec)
    }

    /// Walk from start on behalf of owner (the function start; start itself for a root, an inner label
    /// otherwise). The references go to the record of the root's walk, or straight to the walk's.
    fn walk(&mut self, start: u32, owner: u32) -> Result<(), String> {
        self.extent.entry(owner).or_insert(owner);
        let recording = self.rec.is_some();
        let mut local = Record::default();
        let mut work = vec![start];
        while let Some(a) = work.pop() {
            let target = a;
            let mut recent: Vec<WIns> = vec![];
            if !self.in_code(a) {
                continue;
            }
            let o = (a - self.lo) as usize;
            {
                let rec = if recording { self.rec.as_mut().unwrap() } else { &mut local };
                if self.kind[o] == 1 && self.owner[o] == owner {
                    rec.probes.push(a);
                    continue;
                }
                if self.kind[o] != 0 && self.owner[o] != owner {
                    rec.overlaps.push((owner, a, self.owner[o]));
                    rec.foreign = rec.foreign || self.kind[o] != 3;
                    continue;
                }
                if a != owner && self.stops.contains(&a) {
                    rec.probes.push(a);
                    continue;
                }
            }
            let mut cur = a;
            while let Some(ins) = self.dec.at(cur).cloned() {
                cur = ins.addr + ins.size;
                let ia = ins.addr;
                let io = (ia - self.lo) as usize;
                let (k, ow) = (self.kind[io], self.owner[io]);
                let rec = if recording { self.rec.as_mut().unwrap() } else { &mut local };
                if k == 1 && ow == owner {
                    rec.probes.push(ia);
                    break;
                }
                if ia != owner && self.stops.contains(&ia) && recent.last().is_some_and(|r| r.flow == CALL) {
                    rec.probes.push(ia); // W4: a call that does not return
                    break;
                }
                if k != 0 && ow != owner {
                    rec.overlaps.push((owner, ia, ow));
                    rec.foreign = rec.foreign || k != 3;
                    break;
                }
                if ia != owner && self.stops.contains(&ia) {
                    rec.probes.push(ia);
                    break;
                }
                if ins.fill && ia != target {
                    rec.probes.push(ia);
                    break;
                }
                let size = ins.size;
                for &(disp, osize) in &ins.mem {
                    rec.operands.push((ia, size, disp, osize));
                }
                let flow = ins.flow;
                if flow == CALL && ins.target.is_some() {
                    // W2
                    let t = ins.target.unwrap();
                    if self.lo as i64 <= t && t < self.hi as i64 {
                        rec.calls.push((t as u32, ia, size));
                    }
                } else if !matches!(flow, JUMP | CJUMP | IJUMP) {
                    // W3: a code immediate in a relocated field
                    for &v in &ins.imms {
                        if self.lo as i64 <= v && v < self.hi as i64 && Decoder::field_starts(&ins).any(|k| self.reloc_sites.contains(&k)) {
                            rec.imms.push((v as u32, ia));
                        }
                    }
                }
                self.claim(ia, ia + size, owner, 1);
                recent.push(ins.clone());
                if recent.len() > 12 {
                    recent.remove(0);
                }
                if flow == RET {
                    break; // W4
                }
                if flow == JUMP || flow == CJUMP {
                    let t = ins.target.unwrap();
                    if self.lo as i64 <= t && t < self.hi as i64 {
                        let t = t as u32;
                        // W1: a tail call; W5: over fill
                        let tail = self.crosses_stop(ia, t) || self.stops.contains(&t) && t != owner
                            || flow == JUMP && self.fill_to(ia + size, t)?;
                        let rec = if recording { self.rec.as_mut().unwrap() } else { &mut local };
                        if tail {
                            rec.tails.push((t, ia));
                        } else {
                            work.push(t);
                        }
                    }
                    if flow == JUMP {
                        break; // W4
                    }
                    continue;
                }
                if flow == IJUMP {
                    // W4
                    if let Some(tbl) = ins.table {
                        if recording {
                            let mut rec = self.rec.take().unwrap();
                            self.jump_table(tbl, &recent, owner, &mut work, &mut rec, true);
                            self.rec = Some(rec);
                        } else {
                            self.jump_table(tbl, &recent, owner, &mut work, &mut local, false);
                        }
                    }
                    break;
                }
            }
        }
        if !recording {
            self.merge(&local);
        }
        Ok(())
    }

    /// The table an indirect jump reads (W1: its entries are code of the owner, before the next start): entries
    /// are claimed while each holds an address in [owner, next start) and the bound the decoder found (unless an
    /// index table selects the entry) is not reached; an index table of `bound` entries is claimed when none of
    /// its bytes is owned yet. The claims go to `rec` (taken out of the walker while it runs).
    fn jump_table(&mut self, tbl: u32, recent: &[WIns], owner: u32, work: &mut Vec<u32>, rec: &mut Record, recording: bool) {
        if !self.in_code(tbl) {
            return;
        }
        let (bound, byte_tbl) = self.dec.table_shape(recent);
        let limit = self.next_stop(owner);
        let mut n = 0i64;
        let mut a = tbl;
        let mut claims = vec![];
        while self.in_code(a) && a as u64 + 4 <= self.hi as u64 {
            if bound.is_some_and(|b| byte_tbl.unwrap_or(0) == 0 && n >= b) {
                break;
            }
            let v = self.dec.read_entry(a);
            if !(owner <= v && v < limit) {
                break;
            }
            let o = (a - self.lo) as usize;
            if self.kind[o] != 0 {
                if self.owner[o] != owner {
                    rec.foreign = rec.foreign || self.kind[o] != 3;
                } else {
                    rec.probes.push(a);
                }
                break;
            }
            self.claim(a, a + 4, owner, 2);
            claims.push((a, a + 4, 2));
            work.push(v);
            n += 1;
            a += 4;
        }
        if n > 0 {
            rec.tables.push((tbl, a, owner, "jumptable"));
        }
        if let (Some(bt), Some(b)) = (byte_tbl, bound) {
            let end = bt as i64 + b;
            let mut free = true;
            for p in bt as i64..end {
                if !(self.lo as i64 <= p && p < self.hi as i64) {
                    continue;
                }
                let o = (p - self.lo as i64) as usize;
                if self.kind[o] != 0 {
                    free = false;
                    if self.owner[o] != owner {
                        rec.foreign = rec.foreign || self.kind[o] != 3;
                    }
                } else {
                    rec.probes.push(p as u32);
                }
            }
            if free {
                let e = end.min(self.hi as i64) as u32;
                self.claim(bt, e, owner, 2);
                claims.push((bt, e, 2));
                rec.tables.push((bt, e, owner, "idxtable"));
            }
        }
        // claim() records into self.rec, which the caller took out while recording
        if recording {
            rec.claims.extend(claims);
        }
    }

    /// (code bytes, table bytes) the owner claimed inside [lo, hi).
    fn counts(&self, owner: u32, lo: u32, hi: u32) -> (i64, i64) {
        let (mut code, mut table) = (0i64, 0i64);
        for &(a, b, k) in self.claimed.get(&owner).map(|v| v.as_slice()).unwrap_or(&[]) {
            let n = b.min(hi) as i64 - a.max(lo) as i64;
            if n > 0 {
                if k == 1 { code += n } else { table += n }
            }
        }
        (code, table)
    }
}

/// S.codewalk: recursive descent over the code sections from every known start, adding the starts the walk
/// reveals (W1..W5) until the set of starts is stable; functions, their tables, calls, tail calls, immediates and
/// memory operands as facts, a walk into bytes another function owns as a C.walk conflict.
pub fn s_codewalk(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let err = |e: String| Error::runtime(e);
    let img = crate::image(&ctx.image)?;
    let tc = crate::toolchain::Vc6;
    let code_secs: Vec<(u32, u32)> = img.sections.iter().filter(|s| s.holds_code()).map(|s| (s.va, s.end())).collect();
    if code_secs.is_empty() {
        return Ok(());
    }
    let lo = code_secs.iter().map(|s| s.0).min().unwrap();
    let hi = code_secs.iter().map(|s| s.1).max().unwrap();
    let (li, hii) = (lo as i64, hi as i64);
    let refs = crate::setup::facts(ctx, db, "ref")?;
    let reloc_sites: HashSet<u32> = refs.iter().filter(|f| f.s("rkind") == Some("reloc")).map(|f| f.lo as u32).collect();
    let data_ptrs: BTreeSet<i64> = refs.iter()
        .filter(|f| f.s("rkind") == Some("reloc") && !code_secs.iter().any(|&(a, b)| a as i64 <= f.lo && f.lo < b as i64))
        .filter_map(|f| f.value.get("to").and_then(|v| v.as_i64())).collect();
    let mut claimed: Vec<(i64, i64)> = crate::setup::facts(ctx, db, "symbol")?.iter()
        .filter(|f| matches!(f.s("skind"), Some("func") | Some("thunk")) && li <= f.lo && f.lo < hii).map(|f| (f.lo, f.hi)).collect();
    claimed.sort();
    let claimed_starts: HashSet<u32> = claimed.iter().map(|c| c.0 as u32).collect();
    let inside_claimed = |t: i64| {
        let mut i = claimed.partition_point(|c| c.0 <= t) as i64 - 1;
        while i >= 0 {
            let (a, b) = claimed[i as usize];
            if a <= t && t < b {
                return true;
            }
            i -= 1;
            if i >= 0 && claimed[i as usize].0 < t - 0x100000 {
                break;
            }
        }
        false
    };
    let mut known: BTreeMap<u32, String> = BTreeMap::new();
    for f in crate::setup::facts(ctx, db, "start")? {
        if li <= f.lo && f.lo < hii && !inside_claimed(f.lo) {
            known.entry(f.lo as u32).or_insert_with(|| f.s("how").unwrap_or("").to_string());
        }
    }
    let fills: HashSet<Vec<u8>> = ctx.fill_forms.iter().cloned().collect();
    let mut first = Some(Decoder::new(&img, lo, hi, &fills));
    let mut derived: BTreeMap<u32, String> = BTreeMap::new();
    let mut records: HashMap<u32, Record> = HashMap::new();
    let roots_of = |known: &BTreeMap<u32, String>, derived: &BTreeMap<u32, String>| {
        let mut r = known.clone();
        for (k, v) in derived {
            r.entry(*k).or_insert_with(|| v.clone());
        }
        r
    };
    let n = (hi - lo) as usize;
    let mut last: Option<Walker> = None;
    let mut inner: BTreeMap<u32, u32> = BTreeMap::new();
    for _ in 0..25 {
        let roots = roots_of(&known, &derived);
        let dec = match last.take() {
            Some(w) => w.dec,
            None => first.take().unwrap(),
        };
        let mut stops: HashSet<u32> = roots.keys().copied().collect();
        stops.extend(&claimed_starts);
        let mut sorted_stops: Vec<u32> = stops.iter().copied().collect();
        sorted_stops.sort();
        let mut w = Walker {
            dec, align: tc.function_alignment().max(1), lo, hi, owner: vec![0; n], kind: vec![0; n],
            calls: BTreeMap::new(), call_size: HashMap::new(), tails: BTreeMap::new(),
            imms: BTreeMap::new(), operands: vec![], tables: vec![], overlaps: vec![], extent: HashMap::new(),
            claimed: HashMap::new(), reloc_sites: &reloc_sites, stops, sorted_stops, rec: None,
        };
        for &(a, b) in &claimed {
            w.claim(a as u32, b as u32, a as u32, 3);
            w.extent.remove(&(a as u32));
        }
        for &r in roots.keys() {
            let replayed = match records.get(&r) {
                Some(rec) => w.replay(r, rec),
                None => false,
            };
            if !replayed {
                let rec = w.walk_root(r).map_err(err)?;
                records.insert(r, rec);
            }
        }
        // W2: a call target called only from inside the one function whose range holds it is an inner label of
        // that function (walked on its behalf when the function's own walk did not reach it)
        inner = BTreeMap::new();
        let mut changed = true;
        while changed {
            changed = false;
            let targets: Vec<u32> = w.calls.keys().copied().collect();
            for t in targets {
                if roots.contains_key(&t) || inner.contains_key(&t) {
                    continue;
                }
                let owners: BTreeSet<u32> = w.calls[&t].iter()
                    .filter(|&&s| w.kind[(s - lo) as usize] == 1).map(|&s| w.owner[(s - lo) as usize]).collect();
                if owners.len() != 1 {
                    continue;
                }
                let o = *owners.iter().next().unwrap();
                if w.extent.get(&o).is_some_and(|&e| o < t && t < e) {
                    inner.insert(t, o);
                    if w.kind[(t - lo) as usize] == 0 {
                        w.walk(t, o).map_err(err)?;
                    }
                    changed = true;
                }
            }
        }
        let mut new: BTreeMap<u32, String> = BTreeMap::new();
        for (table, how) in [(&w.calls, "call"), (&w.tails, "tail"), (&w.imms, "immediate")] {
            for &t in table.keys() {
                if roots.contains_key(&t) || inner.contains_key(&t) || inside_claimed(t as i64) || !(lo <= t && t < hi) {
                    continue;
                }
                new.entry(t).or_insert_with(|| how.to_string());
            }
        }
        if new.is_empty() {
            for &t in &data_ptrs {
                if li <= t && t < hii && !roots.contains_key(&(t as u32)) && !inner.contains_key(&(t as u32)) && !inside_claimed(t)
                    && w.kind[(t - li) as usize] == 0 {
                    new.insert(t as u32, "fptr".into());
                }
            }
        }
        let stable = new.is_empty() && derived.keys().all(|k| roots.contains_key(k));
        derived.extend(new);
        last = Some(w);
        if stable {
            break;
        }
    }
    let w = last.unwrap();
    let roots = roots_of(&known, &derived);
    let owner_at = |s: u32| if lo <= s && s < hi && w.kind[(s - lo) as usize] == 1 { Some(w.owner[(s - lo) as usize]) } else { None };

    // the roots that rest on a declared start: the declared ones, then every start found only from their code
    let mut premise: HashSet<u32> = roots.iter().filter(|(_, how)| how.as_str() == "decl").map(|(r, _)| *r).collect();
    let mut found: HashMap<u32, HashSet<Option<u32>>> = HashMap::new();
    for table in [&w.calls, &w.tails, &w.imms] {
        for (&t, sites) in table {
            found.entry(t).or_default().extend(sites.iter().map(|&s| owner_at(s)));
        }
    }
    let mut grew = !premise.is_empty();
    while grew {
        grew = false;
        for &r in roots.keys() {
            if !premise.contains(&r) && derived.contains_key(&r)
                && found.get(&r).is_some_and(|f| !f.is_empty() && f.iter().all(|o| o.is_some_and(|o| premise.contains(&o)))) {
                premise.insert(r);
                grew = true;
            }
        }
    }
    let level_of = |o: Option<u32>| if o.is_some_and(|o| premise.contains(&o)) { DECLARED } else { DERIVED };

    for (&r, how) in &roots {
        let e = w.extent.get(&r).copied().unwrap_or(r);
        if e <= r {
            continue;
        }
        let (walked, table) = w.counts(r, r, e);
        let holes = (e - r) as i64 - walked - table;
        out.claim(r as i64, r as i64 + 1, "start", json!({"skind": "func", "how": how}), level_of(Some(r)));
        let mut v = json!({"skind": "func", "extent": "derived", "walked": walked, "holes": holes});
        let labels: Vec<u32> = inner.iter().filter(|(_, o)| **o == r).map(|(&t, _)| t).collect();
        if !labels.is_empty() {
            v["inner"] = json!(labels);
        }
        out.claim(r as i64, e as i64, "symbol", v, level_of(Some(r)));
    }
    for &(tlo, thi, owner, sk) in &w.tables {
        if thi > tlo {
            out.claim(tlo as i64, thi as i64, "symbol", json!({"skind": sk, "extent": "derived", "fn": owner}), level_of(Some(owner)));
        }
    }
    for (&t, sites) in &w.calls {
        for &s in sites {
            out.claim(s as i64, (s + w.call_size[&s]) as i64, "ref", json!({"rkind": "call", "to": t}), level_of(owner_at(s)));
        }
    }
    for (table, rk) in [(&w.tails, "tail"), (&w.imms, "immediate")] {
        for (&t, sites) in table {
            for &s in sites {
                out.claim(s as i64, s as i64 + 1, "ref", json!({"rkind": rk, "to": t}), level_of(owner_at(s)));
            }
        }
    }
    let mut seen = HashSet::new();
    for &(site, size, target, osize) in &w.operands {
        if seen.insert((site, target)) {
            out.claim(site as i64, (site + size) as i64, "ref", json!({"rkind": "operand", "to": target, "size": osize}), level_of(owner_at(site)));
        }
    }
    let overlaps: BTreeSet<(u32, u32, u32)> = w.overlaps.iter().copied().collect();
    for (owner, addr, other) in overlaps {
        let how = roots.get(&owner).map(|s| s.as_str()).unwrap_or("inner");
        out.finding2("error", "C.walk", addr as i64, addr as i64 + 1,
                      format!("the walk from {owner:#x} ({how}) runs into bytes owned by {other:#x}: one start is wrong"),
                      &format!("start:{owner:#x}"), &format!("start:{other:#x}"));
    }
    Ok(())
}

/// L.src.refs: the references of the sourced functions the walk does not reach (an image without base relocations
/// hides most functions only a pointer reaches: on one project more than half of them). Each function the ledger
/// gives an extent (L.src.extent's convention, M.match's comparison) and no S.codewalk function starts at is
/// descended inside its extent (W4: a return or an unconditional jump ends a path; a jump out of the extent is a
/// tail call; a jump table's entries inside the extent are paths), and its calls, tail calls, code immediates at
/// relocation sites and memory operands into the image are `ref` facts like the walk's, declared (they rest on
/// the address comment's start). A match-base report: `dcp refs` missed `test byte ptr [0xfd7f78], 2` in
/// a function no walk reached.
pub fn l_src_refs(ctx: &Ctx, db: &Connection, out: &mut Out) -> Result<()> {
    let err = |e: String| Error::runtime(e);
    let img = crate::image(&ctx.image)?;
    let code_secs: Vec<(u32, u32)> = img.sections.iter().filter(|s| s.holds_code()).map(|s| (s.va, s.end())).collect();
    if code_secs.is_empty() {
        return Ok(());
    }
    let lo = code_secs.iter().map(|s| s.0).min().unwrap();
    let hi = code_secs.iter().map(|s| s.1).max().unwrap();
    let symbols = crate::setup::facts(ctx, db, "symbol")?;
    let walked: HashSet<i64> = symbols.iter().filter(|f| &*f.rule == "S.codewalk" && f.s("skind") == Some("func")).map(|f| f.lo).collect();
    let mut todo: BTreeMap<i64, i64> = BTreeMap::new();
    for f in symbols.iter().filter(|f| matches!(&*f.rule, "L.src.extent" | "M.match") && f.s("skind") == Some("func")) {
        if !walked.contains(&f.lo) && lo as i64 <= f.lo && f.hi <= hi as i64 && f.hi > f.lo {
            let e = todo.entry(f.lo).or_insert(f.hi);
            *e = (*e).max(f.hi);
        }
    }
    if todo.is_empty() {
        return Ok(());
    }
    let reloc_sites: HashSet<u32> = crate::setup::facts(ctx, db, "ref")?.iter().filter(|f| f.s("rkind") == Some("reloc")).map(|f| f.lo as u32).collect();
    let fills: HashSet<Vec<u8>> = ctx.fill_forms.iter().cloned().collect();
    // contiguous chunks of the functions, each decoded on a thread of its own (one decoder per thread)
    let fns: Vec<(u32, u32)> = todo.into_iter().map(|(f, e)| (f as u32, e as u32)).collect();
    let per = fns.len().div_ceil(64).max(1);
    let chunks: Vec<std::sync::Mutex<(Decoder, &[(u32, u32)])>> = fns.chunks(per)
        .map(|c| std::sync::Mutex::new((Decoder::new(&img, c[0].0, c[c.len() - 1].1, &fills), c))).collect();
    let found = crate::compile_threads(&chunks, |m| -> Result<Vec<Ref>, String> {
        let mut g = m.lock().unwrap();
        let (dec, fs) = &mut *g;
        let mut out = vec![];
        for &(f, e) in fs.iter() {
            out.extend(refs_inside(dec, f, e, (lo, hi), &reloc_sites)?);
        }
        Ok(out)
    });
    for r in found {
        for (site, size, rk, to, osize) in r.map_err(err)? {
            let v = if rk == "operand" { json!({"rkind": rk, "to": to, "size": osize}) } else { json!({"rkind": rk, "to": to}) };
            out.claim(site as i64, (site + size) as i64, "ref", v, DECLARED);
        }
    }
    Ok(())
}

/// A reference L.src.refs finds: (site, size, kind, to, operand size).
type Ref = (u32, u32, &'static str, i64, u8);

/// The references of the function at f confined to [f, e) (L.src.refs), in order; `code` the code sections' span.
fn refs_inside(dec: &mut Decoder, f: u32, e: u32, code: (u32, u32), reloc_sites: &HashSet<u32>) -> Result<BTreeSet<Ref>, String> {
    let (lo, hi) = (code.0 as i64, code.1 as i64);
    let mut seen: HashSet<u32> = HashSet::new();
    let mut work = vec![f];
    let mut refs: BTreeSet<Ref> = BTreeSet::new();
    while let Some(start) = work.pop() {
        let mut cur = start;
        while f <= cur && cur < e && seen.insert(cur) {
            let Some(ins) = dec.at(cur) else { break };
            if ins.fill && cur != start {
                break;
            }
            let (addr, size, flow, target, table) = (ins.addr, ins.size, ins.flow, ins.target, ins.table);
            cur = addr + size;
            for &(disp, osize) in &ins.mem {
                refs.insert((addr, size, "operand", disp as i64, osize));
            }
            if !matches!(flow, RET | CALL | JUMP | CJUMP | IJUMP) {
                for &v in &ins.imms {
                    if lo <= v && v < hi && Decoder::field_starts(ins).any(|k| reloc_sites.contains(&k)) {
                        refs.insert((addr, 1, "immediate", v, 0));
                    }
                }
            }
            match flow {
                RET => break,
                CALL => {
                    if let Some(t) = target.filter(|&t| lo <= t && t < hi) {
                        refs.insert((addr, size, "call", t, 0));
                    }
                }
                JUMP | CJUMP => {
                    if let Some(t) = target {
                        if f as i64 <= t && t < e as i64 {
                            work.push(t as u32);
                        } else if lo <= t && t < hi {
                            refs.insert((addr, 1, "tail", t, 0));
                        }
                    }
                    if flow == JUMP {
                        break;
                    }
                }
                IJUMP => {
                    // the entries of its table that lie inside the extent, up to the first that does not
                    if let Some(tbl) = table.filter(|&t| f <= t && t + 4 <= e) {
                        let mut k = tbl;
                        while k + 4 <= e {
                            let v = dec.read_entry(k);
                            if !(f <= v && v < e) {
                                break;
                            }
                            work.push(v);
                            k += 4;
                        }
                    }
                    break;
                }
                _ => {}
            }
        }
    }
    Ok(refs)
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::pe::testpe::{build, BASE, DATA, TEXT};
    use crate::rules::testkit::{of, Kit};
    use crate::rules::dispatch;
    use crate::store::DERIVED;
    use serde_json::json;

    #[test]
    fn walks_calls_operands_and_function_pointers() {
        let k = Kit::new(&build(None));
        let (t, d) = ((BASE + TEXT) as i64, (BASE + DATA) as i64);
        k.put("S.exports", &[(t, t + 1, "start", json!({"skind": "func", "how": "export"}), DERIVED)]);
        let relocs: Vec<(i64, i64, &str, serde_json::Value, crate::store::Support)> = [(t + 0x21, d), (t + 0x31, d + 0x10), (t + 0x36, d + 0x30), (t + 0x51, d + 0x38), (d + 0x40, t + 0x50)]
            .iter().map(|&(s, to)| (s, s + 4, "ref", json!({"rkind": "reloc", "to": to}), DERIVED)).collect();
        k.put("S.relocs", &relocs);
        let ctx = k.ctx("S.codewalk", &["S.exports", "S.relocs"], r#"{"toolchain": "vc6"}"#);
        let (rows, conflicts) = dispatch(&ctx).unwrap().sorted();
        assert!(conflicts.is_empty());
        let starts: Vec<(i64, String)> = of(&rows, "start").into_iter().map(|(lo, _, v)| (lo - t, v["how"].as_str().unwrap().to_string())).collect();
        assert_eq!(starts, [(0, "export".into()), (0x20, "call".into()), (0x30, "call".into()), (0x50, "fptr".into())]);
        let funcs: Vec<(i64, i64, i64)> = of(&rows, "symbol").into_iter().map(|(lo, hi, v)| (lo - t, hi - t, v["walked"].as_i64().unwrap())).collect();
        assert_eq!(funcs, [(0, 0xf, 0xf), (0x20, 0x26, 6), (0x30, 0x3e, 0xe), (0x50, 0x57, 7)]);
        let refs: Vec<(i64, i64, serde_json::Value)> = of(&rows, "ref").into_iter().map(|(lo, hi, v)| (lo - t, hi - t, v)).collect();
        assert_eq!(refs, [(3, 8, json!({"rkind": "call", "to": t + 0x20})), (8, 0xd, json!({"rkind": "call", "to": t + 0x30})),
                          (0x20, 0x25, json!({"rkind": "operand", "to": d, "size": 4}))]);
    }

    /// A sourced function no walk reached keeps its references (L.src.refs: a match-base report, `dcp refs` missed
    /// an operand in such a function); one the walk reached is the walk's alone.
    #[test]
    fn refs_of_the_functions_no_walk_reached() {
        let k = Kit::new(&build(None));
        let t = (BASE + TEXT) as i64;
        let d = (BASE + DATA) as i64;
        k.put("L.src.extent", &[(t + 0x20, t + 0x26, "symbol", json!({"skind": "func", "extent": "source"}), crate::store::DECLARED)]);
        k.put("M.match", &[(t + 0x30, t + 0x3e, "symbol", json!({"skind": "func", "extent": "matched"}), crate::store::REPRODUCED)]);
        k.put("S.codewalk", &[(t + 0x30, t + 0x3e, "symbol", json!({"skind": "func", "extent": "derived"}), DERIVED)]);
        let ctx = k.ctx("L.src.refs", &["L.src.extent", "M.match", "S.codewalk"], r#"{"toolchain": "vc6"}"#);
        let (rows, _) = dispatch(&ctx).unwrap().sorted();
        let refs: Vec<(i64, i64, serde_json::Value, crate::store::Support)> = rows.iter().filter(|r| r.kind == "ref")
            .map(|r| (r.lo - t, r.hi - t, serde_json::from_str(&r.value).unwrap(), r.support)).collect();
        assert_eq!(refs, [(0x20, 0x25, json!({"rkind": "operand", "to": d, "size": 4}), crate::store::DECLARED)]);
    }
}
