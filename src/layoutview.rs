//! What `dcp layout next|units|unit propose` print, computed from the current facts of one target's store
//!.
//!
//! Nothing here decides anything new: the units are L.unit.extent's facts, the evidence L.analyze's, the checks are
//! layout.rs's pure functions (run again on the units as a proposal would make them).

use crate::error::Result;
use crate::layout::{self, Bound as Boundary, Issue, Leak, Lit, Unit};
use crate::store::{self, SFact, OPEN};
use crate::with_db;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::rc::Rc;

const LEVEL_NAMES: [&str; 4] = ["open", "declared", "derived", "proven"];

/// The layout-relevant facts of one store, indexed.
pub struct View {
    pub(crate) image: String,
    pub(crate) syms: Vec<Rc<SFact>>,
    pub(crate) game: (i64, i64, i64),
    pub(crate) funcs: Vec<Rc<SFact>>,                 // function symbols above open, by (lo, hi)
    pub(crate) starts: BTreeMap<i64, Vec<Rc<SFact>>>, // addr -> start facts
    pub(crate) sources: HashMap<i64, Rc<SFact>>,      // addr -> source fact (functions)
    pub(crate) src_facts: Vec<Rc<SFact>>,
    pub(crate) units: Vec<Unit>,
    pub(crate) unit_facts: Vec<Rc<SFact>>,
    pub(crate) lits: Vec<Lit>,
    pub(crate) leaks: Vec<Leak>,
    pub(crate) fills: HashMap<i64, Value>,            // start -> fill evidence value
    pub(crate) bounds: Vec<Boundary>,
    pub(crate) refs: Vec<Rc<SFact>>,
    pub(crate) drafted: HashSet<i64>,
}

impl View {
    pub fn load(db: &str, main: &str, image: &str) -> Result<View> {
        let img = crate::image(image)?;
        let all = |k: &str| with_db(db, |c| store::facts_of(c, db, k, None, |_| true));
        let syms: Vec<Rc<SFact>> = all("symbol")?.into_iter().filter(|f| !f.rule.starts_with("M.")).collect();
        let libs = layout::lib_starts_of(&syms);
        let (glo, ghi) = layout::game_range(&img, &libs);
        let rs = layout::code_ranges(&img);
        let derived = libs.iter().any(|&a| rs.iter().any(|&(l, h)| l <= a && a < h));
        let game = (glo, ghi, if derived { store::DERIVED } else { store::PROVEN });
        let mut funcs: Vec<Rc<SFact>> = syms.iter().filter(|f| f.s("skind") == Some("func") && f.level > OPEN).cloned().collect();
        funcs.sort_by_key(|f| (f.lo, f.hi));
        let mut starts: BTreeMap<i64, Vec<Rc<SFact>>> = BTreeMap::new();
        for f in all("start")? {
            starts.entry(f.lo).or_default().push(f);
        }
        let src_facts = all("source")?;
        let sources = src_facts.iter().filter(|f| f.s("what") == Some("func")).map(|f| (f.lo, f.clone())).collect();
        let unit_facts: Vec<Rc<SFact>> = all("unit")?.into_iter().filter(|f| f.value.get("status").is_some()).collect();
        let units = layout::game_units(&unit_facts);
        let ev = all("evidence")?;
        let fills = ev.iter().filter(|f| f.s("ekind") == Some("fill")).map(|f| (f.lo, f.value.clone())).collect();
        let drafted = with_db(db, |c| crate::names::draft_values(c, main))?.iter().filter_map(|v| v.get("start").and_then(|s| s.as_i64())).collect();
        Ok(View {
            image: image.to_string(), game, funcs, starts, sources, units, lits: layout::lits_of(&ev), leaks: layout::leaks_of(&ev), fills,
            bounds: layout::bounds_of(&all("boundary")?), refs: all("ref")?, drafted, syms, unit_facts, src_facts,
        })
    }

    /// The game code in address order as (lo, hi, what, fact): func (a function symbol), start (a declared start
    /// inside unknown code), unknown (open bytes no start explains); other symbols skipped.
    pub(crate) fn items_of(&self) -> Vec<(i64, i64, &'static str, Rc<SFact>)> {
        let (glo, ghi, _) = self.game;
        let mut out = vec![];
        for f in &self.syms {
            if !(glo <= f.lo && f.lo < ghi) {
                continue;
            }
            match f.s("skind") {
                Some("func") if f.level > OPEN => out.push((f.lo, f.hi, "func", f.clone())),
                Some("unknown.code") => {
                    let mut pos = f.lo;
                    let inner: Vec<i64> = self.starts.range(f.lo..f.hi).map(|(a, _)| *a).collect();
                    for (k, &a) in inner.iter().enumerate() {
                        if a > pos {
                            out.push((pos, a, "unknown", f.clone()));
                        }
                        let nxt = inner.get(k + 1).copied().unwrap_or(f.hi);
                        out.push((a, nxt, "start", f.clone()));
                        pos = nxt;
                    }
                    if pos < f.hi {
                        out.push((pos, f.hi, "unknown", f.clone()));
                    }
                }
                _ => {}
            }
        }
        out.sort_by_key(|t| t.0);
        out
    }

    /// The first open item of the game code: (address, kind, size), None when there is none.
    pub(crate) fn first_open_item(&self) -> Option<(i64, &'static str, i64)> {
        let items = self.items_of();
        let mut starts: Vec<i64> = items.iter().filter(|t| t.2 == "func" || t.2 == "start").map(|t| t.0).collect();
        starts.push(self.game.1);
        starts.sort();
        starts.dedup();
        items.iter().find(|(lo, _, what, _)| !((*what == "func" || *what == "start") && self.sources.contains_key(lo))).map(|(lo, hi, what, _)| {
            let k = starts.partition_point(|x| x <= lo);
            let nxt = starts.get(k).copied().unwrap_or(self.game.1);
            (*lo, *what, if *what != "unknown" { nxt - lo } else { hi - lo })
        })
    }

    /// The hows of the starts at an address (`-` when none).
    pub(crate) fn start_hows(&self, a: i64) -> String {
        let hows: BTreeSet<&str> = self.starts.get(&a).into_iter().flatten().filter_map(|s| s.s("how")).collect();
        if hows.is_empty() { "-".to_string() } else { hows.into_iter().collect::<Vec<_>>().join(",") }
    }

    pub(crate) fn unit_index(&self, a: i64) -> Option<usize> {
        layout::unit_at(&self.units, a)
    }

    fn unit_fact(&self, u: &Unit) -> Option<&Rc<SFact>> {
        self.unit_facts.iter().find(|f| f.lo == u.lo && f.s("tu") == Some(u.tu.as_str()))
    }

    pub(crate) fn container(&self, a: i64) -> Option<&Rc<SFact>> {
        let i = self.funcs.partition_point(|f| f.lo <= a);
        (i > 0 && a < self.funcs[i - 1].hi && self.funcs[i - 1].lo <= a).then(|| &self.funcs[i - 1])
    }

    fn callers_of(&self, a: i64) -> Vec<(i64, String, Option<i64>)> {
        let mut out: Vec<(i64, String, Option<i64>)> = self.refs.iter()
            .filter(|r| r.value.get("to").and_then(|v| v.as_i64()) == Some(a)
                && matches!(r.s("rkind"), Some("call" | "tail" | "immediate" | "reloc" | "operand")))
            .map(|r| (r.lo, r.s("rkind").unwrap_or("").to_string(), self.container(r.lo).map(|f| f.lo))).collect();
        out.sort();
        out
    }

    /// Per game unit and data section: [min, max) of the literals whose first user lies in the unit.
    fn lit_blocks(&self) -> Vec<((usize, String), (i64, i64))> {
        let mut blocks: Vec<((usize, String), (i64, i64))> = vec![];
        for l in &self.lits {
            let Some(i) = self.unit_index(l.first) else { continue };
            let k = (i, l.section.clone());
            match blocks.iter_mut().find(|b| b.0 == k) {
                Some(b) => b.1 = (b.1 .0.min(l.lo), b.1 .1.max(l.hi)),
                None => blocks.push((k, (l.lo, l.hi))),
            }
        }
        blocks
    }

    fn first_lits(&self, f: i64) -> Vec<&Lit> {
        let mut out: Vec<&Lit> = self.lits.iter().filter(|l| l.first == f).collect();
        out.sort_by_key(|l| l.lo);
        out
    }

    /// For each section: (this function's lowest first literal) - (the highest literal first used by an earlier
    /// function): a big forward jump skips another unit's block (D8).
    fn lit_jump(&self, f: i64) -> Vec<(String, Option<i64>)> {
        let mine = self.first_lits(f);
        let secs: BTreeSet<&str> = mine.iter().map(|l| l.section.as_str()).collect();
        secs.into_iter().map(|sec| {
            let lo = mine.iter().filter(|l| l.section == sec).map(|l| l.lo).min().unwrap();
            let prev = self.lits.iter().filter(|l| l.section == sec && l.first < f).map(|l| l.hi).max();
            (sec.to_string(), prev.map(|p| lo - p))
        }).collect()
    }

    fn all_issues(&self, units: &[Unit], bounds: &[Boundary]) -> Vec<Issue> {
        let mut starts: HashSet<i64> = self.starts.keys().copied().collect();
        for f in &self.funcs {
            starts.insert(f.lo);
            starts.extend(f.value.get("inner").and_then(|v| v.as_array()).into_iter().flatten().filter_map(|x| x.as_i64()));
        }
        let mut fills: Vec<(i64, i64)> = self.syms.iter().filter(|f| f.s("skind") == Some("fill")).map(|f| (f.lo, f.hi)).collect();
        fills.sort();
        let funcs: Vec<(i64, i64)> = self.funcs.iter().map(|f| (f.lo, f.hi)).collect();
        let mut out = layout::lit_issues(units, &self.lits);
        out.extend(layout::boundary_issues(bounds, &starts, &funcs, &fills, self.game.1));
        out.extend(layout::leak_issues(units, &self.leaks));
        out
    }
}

impl View {
    /// The skind of the first symbol (not the match phase's) that starts at a, or None.
    pub(crate) fn symbol_kind(&self, a: i64) -> Option<String> {
        self.syms.iter().find(|f| f.lo == a).and_then(|f| f.s("skind")).map(|s| s.to_string())
    }
}

/// A value of a layout record (clicmd.rs prints it as a token or writes it as JSON).
pub enum LVal {
    Null,
    B(bool),
    I(i64),
    S(String),
    R(i64, i64),
    L(Vec<String>),
    V(Value),
}

fn ls(x: Option<&str>) -> LVal {
    x.map(|s| LVal::S(s.to_string())).unwrap_or(LVal::Null)
}

/// One open item of the game code with its evidence lines.
pub struct NextItem {
    pub addr: i64,
    pub kind: &'static str,
    pub size: i64,
    pub next_start: i64,
    pub unit: Option<String>,
    pub unit_status: Option<String>,
    pub analyzed: bool,
    pub extent: Option<(i64, i64)>,
    pub lines: Vec<(&'static str, Vec<(&'static str, LVal)>)>,
}

/// One function of a unit proposal.
pub struct PropRow {
    pub lo: i64,
    pub size: i64,
    pub fill: Option<Value>,
    pub drafted: bool,
    pub lits: i64,
    pub first_lit: Option<i64>,
    pub leaks: Vec<String>,
}

/// A unit proposal evaluated: its range, the decl lines to write (addr, side), the evidence per function, the issues
/// the current state does not have.
pub struct Proposal {
    pub lo: i64,
    pub end: i64,
    pub lines: Vec<(i64, &'static str)>,
    pub table: Vec<PropRow>,
    pub new: Vec<Issue>,
}

impl View {
    /// The first `count` open items of the game code from `start`: a function without a source, a declared start in
    /// unknown code, or unknown code no start explains, each with its evidence lines.
    pub(crate) fn next_items(&self, count: usize, start: Option<i64>) -> Result<Vec<NextItem>> {
        let img = crate::image(&self.image)?;
        let items = self.items_of();
        let mut starts_sorted: Vec<i64> = items.iter().filter(|t| t.2 == "func" || t.2 == "start").map(|t| t.0).collect();
        starts_sorted.push(self.game.1);
        starts_sorted.sort();
        starts_sorted.dedup();
        let blocks = self.lit_blocks();
        let mut out = vec![];
        for (lo, hi, what, f) in &items {
            if start.is_some_and(|s| *lo < s) {
                continue;
            }
            if (*what == "func" || *what == "start") && self.sources.contains_key(lo) {
                continue;
            }
            let ui = self.unit_index(*lo);
            let u = ui.map(|i| &self.units[i]);
            let k = starts_sorted.partition_point(|x| x <= lo);
            let nxt = starts_sorted.get(k).copied().unwrap_or(self.game.1);
            let mut lines: Vec<(&'static str, Vec<(&'static str, LVal)>)> = vec![];
            for s in self.starts.get(lo).into_iter().flatten() {
                lines.push(("start", vec![("how", ls(s.s("how"))), ("level", LVal::S(LEVEL_NAMES[s.level as usize].into())), ("by", LVal::S(s.by.clone()))]));
            }
            for (site, rk, fnx) in self.callers_of(*lo) {
                lines.push(("caller", vec![("site", LVal::I(site)), ("rkind", LVal::S(rk)), ("fn", fnx.map(LVal::I).unwrap_or(LVal::Null)),
                                           ("unit", ls(fnx.and_then(|a| self.unit_index(a)).map(|i| self.units[i].tu.as_str())))]));
            }
            if let Some(fl) = self.fills.get(lo) {
                lines.push(("fill", vec![("before", LVal::V(fl["pre"].clone())), ("run", LVal::V(fl["run"].clone()))]));
            }
            for l in self.first_lits(*lo) {
                let inblk: Vec<&str> = blocks.iter().filter(|((i, sec), (blo, bhi))| {
                    *sec == l.section && *blo <= l.lo && l.lo < *bhi && Some(*i) != ui && self.units[*i].lo < *lo
                }).map(|((i, _), _)| self.units[*i].tu.as_str()).collect();
                lines.push(("literal", vec![("range", LVal::R(l.lo, l.hi)), ("section", LVal::S(l.section.clone())), ("data_refs", LVal::I(l.data_refs)),
                                            ("earlier_unit_block", ls(inblk.first().copied())),
                                            ("text", LVal::S(img.cstr(l.lo as u32).iter().take(48).map(|&c| c as char).collect()))]));
            }
            for (sec, j) in self.lit_jump(*lo) {
                lines.push(("literal_jump", vec![("section", LVal::S(sec)), ("jump", j.map(LVal::I).unwrap_or(LVal::Null))]));
            }
            for l in self.leaks.iter().filter(|l| l.func == *lo) {
                lines.push(("leak", vec![("path", LVal::S(l.path.clone())), ("header", LVal::B(l.header))]));
            }
            out.push(NextItem {
                addr: *lo, kind: what, size: if *what != "unknown" { nxt - lo } else { hi - lo }, next_start: nxt, unit: u.map(|u| u.tu.clone()),
                unit_status: u.and_then(|u| self.unit_fact(u)).and_then(|f| f.s("status")).map(|s| s.to_string()),
                analyzed: self.drafted.contains(lo), extent: (*what == "func").then_some((f.lo, f.hi)), lines,
            });
            if out.len() >= count {
                break;
            }
        }
        Ok(out)
    }

    /// L2: function starts inside game units without a source (informational).
    pub(crate) fn undrafted_items(&self) -> Vec<i64> {
        self.items_of().into_iter().filter(|(lo, _, what, _)| {
            (*what == "func" || *what == "start") && !self.sources.contains_key(lo) && self.unit_index(*lo).is_some()
        }).map(|t| t.0).collect()
    }

    /// The unit table: one row per game unit (L.unit.extent's facts), by address.
    pub(crate) fn unit_table(&self) -> Vec<Vec<(&'static str, LVal)>> {
        let mut ufs: Vec<&Rc<SFact>> = self.unit_facts.iter().collect();
        ufs.sort_by_key(|f| f.lo);
        ufs.into_iter().map(|f| {
            let v = &f.value;
            let leaks: BTreeSet<&str> = self.leaks.iter().filter(|l| f.lo <= l.func && l.func < f.hi && !l.header).map(|l| l.path.as_str()).collect();
            let g = |k: &str| LVal::V(v.get(k).cloned().unwrap_or(Value::Null));
            let n = |k: &str| v.get(k).and_then(|x| x.as_i64()).unwrap_or(0);
            vec![("unit", g("tu")), ("range", LVal::R(f.lo, f.hi)), ("status", g("status")), ("start", g("start_level")), ("end", g("end_level")),
                 ("named_by", g("named_by")), ("open_bytes", g("open_bytes")), ("functions", g("functions")), ("sourced", g("sourced")),
                 ("undrafted", LVal::I(n("functions") - n("sourced"))), ("dead_bytes", LVal::I(n("dead_bytes"))), ("walk_conflicts", LVal::I(n("walk_conflicts"))),
                 ("start_by", g("start_by")), ("end_by", g("end_by")), ("leaks", LVal::L(leaks.into_iter().map(|x| x.to_string()).collect())),
                 ("level", LVal::S(LEVEL_NAMES[f.level as usize].into()))]
        }).collect()
    }

    /// Evaluate a unit lo..hi named `name` against the current units: the units with the proposed boundaries added,
    /// L3 / L4 / L7 / L8 on them, the issues the current state does not have.
    pub(crate) fn proposal(&self, lo: i64, hi: Option<i64>, name: &str) -> Proposal {
        let (glo, ghi, _) = self.game;
        let srcs: Vec<layout::SrcFn> = self.src_facts.iter().filter(|f| f.s("what") == Some("func")).map(|f| {
            (f.lo, f.s("unit").unwrap_or("").to_string(), f.s("symbol").unwrap_or("").to_string(), f.by.clone())
        }).collect();
        let fstarts: Vec<i64> = self.funcs.iter().map(|f| f.lo).filter(|&a| glo <= a && a < ghi).collect();
        let (cur_units, cur_l7) = layout::compute_units(self.game, &self.bounds, &srcs, &fstarts);
        let mut cur = cur_l7;
        cur.extend(self.all_issues(&cur_units, &self.bounds));
        let mut new_bounds = self.bounds.clone();
        new_bounds.push((lo, "start".into(), name.into(), "proposal".into(), None));
        let (mut units, mut l7) = layout::compute_units(self.game, &new_bounds, &srcs, &fstarts);
        let mut lines = vec![(lo, "start")];
        if let Some(hi) = hi {
            if units.iter().find(|u| u.tu == name).is_none_or(|m| m.hi != hi) {
                new_bounds.push((hi, "end".into(), name.into(), "proposal".into(), None));
                (units, l7) = layout::compute_units(self.game, &new_bounds, &srcs, &fstarts);
                lines.push((hi, "end"));
            }
        }
        let mut hyp = l7;
        hyp.extend(self.all_issues(&units, &new_bounds));
        let seen: HashSet<(&str, &str)> = cur.iter().map(|i| (i.0.as_str(), i.3.as_str())).collect();
        let new: Vec<Issue> = hyp.iter().filter(|i| !seen.contains(&(i.0.as_str(), i.3.as_str()))).cloned().collect();
        let end = units.iter().find(|u| u.tu == name).map(|u| u.hi).unwrap_or(hi.unwrap_or(lo + 1));
        let table = self.funcs.iter().filter(|f| lo <= f.lo && f.lo < end).map(|f| {
            let lits = self.first_lits(f.lo);
            PropRow { lo: f.lo, size: f.hi - f.lo, fill: self.fills.get(&f.lo).and_then(|v| v.get("pre")).cloned(), drafted: self.sources.contains_key(&f.lo),
                      lits: lits.len() as i64, first_lit: lits.first().map(|l| l.lo),
                      leaks: self.leaks.iter().filter(|l| l.func == f.lo).map(|l| l.path.clone()).collect::<BTreeSet<_>>().into_iter().collect() }
        }).collect();
        Proposal { lo, end, lines, table, new }
    }
}
