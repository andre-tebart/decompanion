//! What `dcp layout next|units|unit propose` print, computed from the current facts of one target's store
//! (ledger/layoutview.py is its face).
//!
//! Nothing here decides anything new: the units are L.unit.extent's facts, the evidence L.analyze's, the checks are
//! layout.rs's pure functions (run again on the units as a proposal would make them).

use crate::layout::{self, Bound as Boundary, Issue, Leak, Lit, Unit};
use crate::pystore::{json_py, level_obj, object};
use crate::store::{self, SFact, OPEN};
use crate::with_db;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyTuple};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::rc::Rc;

const LEVEL_NAMES: [&str; 4] = ["open", "declared", "derived", "proven"];

/// The layout-relevant facts of one store, indexed.
#[pyclass(unsendable)]
pub struct View {
    image: String,
    syms: Vec<Rc<SFact>>,
    game: (i64, i64, i64),
    funcs: Vec<Rc<SFact>>,                 // function symbols above open, by (lo, hi)
    starts: BTreeMap<i64, Vec<Rc<SFact>>>, // addr -> start facts
    sources: HashMap<i64, Rc<SFact>>,      // addr -> source fact (functions)
    src_facts: Vec<Rc<SFact>>,
    units: Vec<Unit>,
    unit_facts: Vec<Rc<SFact>>,
    lits: Vec<Lit>,
    leaks: Vec<Leak>,
    fills: HashMap<i64, Value>,            // start -> fill evidence value
    bounds: Vec<Boundary>,
    refs: Vec<Rc<SFact>>,
    drafted: HashSet<i64>,
}

fn py_layout(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    py.import("decompanion.rules.layout")
}

fn unit_py<'py>(py: Python<'py>, u: &Unit) -> PyResult<Bound<'py, PyAny>> {
    py_layout(py)?.getattr("UnitX")?.call1((u.tu.clone(), u.lo, u.hi, level_obj(py, u.start_level)?, level_obj(py, u.end_level)?,
                                             u.start_by.clone(), u.end_by.clone(), u.named_by.clone()))
}

fn issue_py<'py>(py: Python<'py>, i: &Issue) -> PyResult<Bound<'py, PyAny>> {
    py_layout(py)?.getattr("Issue")?.call1((i.0.clone(), i.1, i.2, i.3.clone(), i.4.clone(), i.5.clone()))
}

impl View {
    pub fn load(db: &str, main: &str, image: &str) -> PyResult<View> {
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
    fn items_of(&self) -> Vec<(i64, i64, &'static str, Rc<SFact>)> {
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

    fn unit_index(&self, a: i64) -> Option<usize> {
        layout::unit_at(&self.units, a)
    }

    fn unit_fact(&self, u: &Unit) -> Option<&Rc<SFact>> {
        self.unit_facts.iter().find(|f| f.lo == u.lo && f.s("tu") == Some(u.tu.as_str()))
    }

    fn container(&self, a: i64) -> Option<&Rc<SFact>> {
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

#[pymethods]
impl View {
    #[new]
    fn new(db: &str, main: &str, image: &str) -> PyResult<View> {
        View::load(db, main, image)
    }

    /// (lo, hi, level of hi) of the game code.
    #[getter]
    fn game<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
        PyTuple::new(py, [self.game.0.into_pyobject(py)?.into_any(), self.game.1.into_pyobject(py)?.into_any(), level_obj(py, self.game.2)?.into_bound(py)])
    }

    /// [(lo, hi, fact)] of the function symbols above open.
    #[getter]
    fn funcs<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let l = PyList::empty(py);
        for f in &self.funcs {
            l.append((f.lo, f.hi, object(py, "symbol", f)?))?;
        }
        Ok(l)
    }

    /// The symbol facts (not the match phase's).
    #[getter]
    fn syms<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        PyList::new(py, self.syms.iter().map(|f| object(py, "symbol", f)).collect::<PyResult<Vec<_>>>()?)
    }

    /// addr -> its start facts.
    #[getter]
    fn starts<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        for (a, fs) in &self.starts {
            d.set_item(a, PyList::new(py, fs.iter().map(|f| object(py, "start", f)).collect::<PyResult<Vec<_>>>()?)?)?;
        }
        Ok(d)
    }

    /// addr -> the source fact of the function there.
    #[getter]
    fn sources<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        for (a, f) in &self.sources {
            d.set_item(a, object(py, "source", f)?)?;
        }
        Ok(d)
    }

    /// The game units (layout.UnitX), by address.
    #[getter]
    fn units<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        PyList::new(py, self.units.iter().map(|u| unit_py(py, u)).collect::<PyResult<Vec<_>>>()?)
    }

    /// start -> its fill evidence value.
    #[getter]
    fn fills<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        for (a, v) in &self.fills {
            d.set_item(a, json_py(py, v)?)?;
        }
        Ok(d)
    }

    /// The declared boundaries (layout.Bound).
    #[getter]
    fn bounds<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let cls = py_layout(py)?.getattr("Bound")?;
        PyList::new(py, self.bounds.iter().map(|b| cls.call1((b.0, b.1.clone(), b.2.clone(), b.3.clone(), b.4.clone()))).collect::<PyResult<Vec<_>>>()?)
    }

    /// The skind of the first symbol (not the match phase's) that starts at a, or None.
    fn symbol_kind(&self, a: i64) -> Option<String> {
        self.syms.iter().find(|f| f.lo == a).and_then(|f| f.s("skind")).map(|s| s.to_string())
    }

    /// The game unit holding a (layout.UnitX), else None.
    fn unit_at<'py>(&self, py: Python<'py>, a: i64) -> PyResult<Option<Bound<'py, PyAny>>> {
        self.unit_index(a).map(|i| unit_py(py, &self.units[i])).transpose()
    }

    fn items<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let l = PyList::empty(py);
        for (lo, hi, what, f) in self.items_of() {
            l.append((lo, hi, what, object(py, "symbol", &f)?))?;
        }
        Ok(l)
    }

    /// The first `count` open items of the game code from `start`: a function without a source, a declared start
    /// in unknown code, or unknown code no start explains. One record per item (a dict), with its evidence lines.
    #[pyo3(signature = (count=1, start=None))]
    fn next_records<'py>(&self, py: Python<'py>, count: usize, start: Option<i64>) -> PyResult<Bound<'py, PyList>> {
        let img = crate::image(&self.image)?;
        let items = self.items_of();
        let mut starts_sorted: Vec<i64> = items.iter().filter(|t| t.2 == "func" || t.2 == "start").map(|t| t.0).collect();
        starts_sorted.push(self.game.1);
        starts_sorted.sort();
        starts_sorted.dedup();
        let blocks = self.lit_blocks();
        let out = PyList::empty(py);
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
            let rec = PyDict::new(py);
            rec.set_item("addr", lo)?;
            rec.set_item("kind", what)?;
            rec.set_item("size", if *what != "unknown" { nxt - lo } else { hi - lo })?;
            rec.set_item("next_start", nxt)?;
            rec.set_item("unit", u.map(|u| u.tu.clone()))?;
            let status = match u {
                Some(u) => self.unit_fact(u).and_then(|f| f.s("status")).map(|s| s.to_string()),
                None => None,
            };
            rec.set_item("unit_status", status)?;
            rec.set_item("analyzed", self.drafted.contains(lo))?;
            let lines = PyList::empty(py);
            if *what == "func" {
                rec.set_item("extent", (f.lo, f.hi))?;
            }
            for s in self.starts.get(lo).into_iter().flatten() {
                let d = PyDict::new(py);
                d.set_item("how", s.s("how"))?;
                d.set_item("level", LEVEL_NAMES[s.level as usize])?;
                d.set_item("by", &s.by)?;
                lines.append(("start", d))?;
            }
            for (site, rk, fnx) in self.callers_of(*lo) {
                let d = PyDict::new(py);
                d.set_item("site", site)?;
                d.set_item("rkind", rk)?;
                d.set_item("fn", fnx)?;
                d.set_item("unit", fnx.and_then(|a| self.unit_index(a)).map(|i| self.units[i].tu.clone()))?;
                lines.append(("caller", d))?;
            }
            if let Some(fl) = self.fills.get(lo) {
                let d = PyDict::new(py);
                d.set_item("before", json_py(py, &fl["pre"])?)?;
                d.set_item("run", json_py(py, &fl["run"])?)?;
                lines.append(("fill", d))?;
            }
            for l in self.first_lits(*lo) {
                let inblk: Vec<&str> = blocks.iter().filter(|((i, sec), (blo, bhi))| {
                    *sec == l.section && *blo <= l.lo && l.lo < *bhi && Some(*i) != ui && self.units[*i].lo < *lo
                }).map(|((i, _), _)| self.units[*i].tu.as_str()).collect();
                let d = PyDict::new(py);
                d.set_item("range", (l.lo, l.hi))?;
                d.set_item("section", &l.section)?;
                d.set_item("data_refs", l.data_refs)?;
                d.set_item("earlier_unit_block", inblk.first().copied())?;
                d.set_item("text", img.cstr(l.lo as u32).iter().take(48).map(|&c| c as char).collect::<String>())?;
                lines.append(("literal", d))?;
            }
            for (sec, j) in self.lit_jump(*lo) {
                let d = PyDict::new(py);
                d.set_item("section", sec)?;
                d.set_item("jump", j)?;
                lines.append(("literal_jump", d))?;
            }
            for l in self.leaks.iter().filter(|l| l.func == *lo) {
                let d = PyDict::new(py);
                d.set_item("path", &l.path)?;
                d.set_item("header", l.header)?;
                lines.append(("leak", d))?;
            }
            rec.set_item("lines", lines)?;
            out.append(rec)?;
            if out.len() >= count {
                break;
            }
        }
        Ok(out)
    }

    /// The first open item of the game code (what `dcp layout next` shows first, without its evidence lines):
    /// {addr, kind, size, unit, how (its starts' hows), analyzed}, None when there is none.
    fn first_open<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyDict>>> {
        let items = self.items_of();
        let mut starts: Vec<i64> = items.iter().filter(|t| t.2 == "func" || t.2 == "start").map(|t| t.0).collect();
        starts.push(self.game.1);
        starts.sort();
        starts.dedup();
        for (lo, hi, what, _) in &items {
            if (*what == "func" || *what == "start") && self.sources.contains_key(lo) {
                continue;
            }
            let k = starts.partition_point(|x| x <= lo);
            let nxt = starts.get(k).copied().unwrap_or(self.game.1);
            let hows: BTreeSet<&str> = self.starts.get(lo).into_iter().flatten().filter_map(|s| s.s("how")).collect();
            let d = PyDict::new(py);
            d.set_item("addr", lo)?;
            d.set_item("kind", what)?;
            d.set_item("size", if *what != "unknown" { nxt - lo } else { hi - lo })?;
            d.set_item("unit", self.unit_index(*lo).map(|i| self.units[i].tu.clone()))?;
            d.set_item("how", if hows.is_empty() { "-".to_string() } else { hows.into_iter().collect::<Vec<_>>().join(",") })?;
            d.set_item("analyzed", self.drafted.contains(lo))?;
            return Ok(Some(d));
        }
        Ok(None)
    }

    /// L2: function starts inside game units without a source (informational).
    fn undrafted(&self) -> Vec<i64> {
        self.items_of().into_iter().filter(|(lo, _, what, _)| {
            (*what == "func" || *what == "start") && !self.sources.contains_key(lo) && self.unit_index(*lo).is_some()
        }).map(|t| t.0).collect()
    }

    fn unit_rows<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let out = PyList::empty(py);
        let mut ufs: Vec<&Rc<SFact>> = self.unit_facts.iter().collect();
        ufs.sort_by_key(|f| f.lo);
        for f in ufs {
            let v = &f.value;
            let leaks: BTreeSet<&str> = self.leaks.iter().filter(|l| f.lo <= l.func && l.func < f.hi && !l.header).map(|l| l.path.as_str()).collect();
            let d = PyDict::new(py);
            let g = |k: &str| json_py(py, v.get(k).unwrap_or(&Value::Null));
            d.set_item("unit", g("tu")?)?;
            d.set_item("range", (f.lo, f.hi))?;
            for (k, src) in [("status", "status"), ("start", "start_level"), ("end", "end_level"), ("named_by", "named_by"),
                             ("open_bytes", "open_bytes"), ("functions", "functions"), ("sourced", "sourced")] {
                d.set_item(k, g(src)?)?;
            }
            let n = |k: &str| v.get(k).and_then(|x| x.as_i64()).unwrap_or(0);
            d.set_item("undrafted", n("functions") - n("sourced"))?;
            d.set_item("dead_bytes", n("dead_bytes"))?;
            d.set_item("walk_conflicts", n("walk_conflicts"))?;
            d.set_item("start_by", g("start_by")?)?;
            d.set_item("end_by", g("end_by")?)?;
            d.set_item("leaks", PyList::new(py, leaks)?)?;
            d.set_item("level", LEVEL_NAMES[f.level as usize])?;
            out.append(d)?;
        }
        Ok(out)
    }

    /// Evaluate a unit lo..hi named `name` against the current units: the units with the proposed boundaries
    /// added, L3 / L4 / L7 / L8 on them, the issues the current state does not have. (lo, end, name, decl lines
    /// [(addr, side)], evidence rows per function, new issues, current issues).
    #[pyo3(signature = (lo, hi, name))]
    #[allow(clippy::type_complexity)]
    fn propose<'py>(&self, py: Python<'py>, lo: i64, hi: Option<i64>, name: &str)
        -> PyResult<(i64, i64, String, Vec<(i64, &'static str)>, Bound<'py, PyList>, Bound<'py, PyList>, Bound<'py, PyList>)> {
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
        let new: Vec<&Issue> = hyp.iter().filter(|i| !seen.contains(&(i.0.as_str(), i.3.as_str()))).collect();
        let end = units.iter().find(|u| u.tu == name).map(|u| u.hi).unwrap_or(hi.unwrap_or(lo + 1));
        let table = PyList::empty(py);
        for f in self.funcs.iter().filter(|f| lo <= f.lo && f.lo < end) {
            let lits = self.first_lits(f.lo);
            let d = PyDict::new(py);
            d.set_item("fn", f.lo)?;
            d.set_item("size", f.hi - f.lo)?;
            d.set_item("fill", match self.fills.get(&f.lo).and_then(|v| v.get("pre")) { Some(v) => Some(json_py(py, v)?), None => None })?;
            d.set_item("drafted", self.sources.contains_key(&f.lo))?;
            d.set_item("lits", lits.len())?;
            d.set_item("first_lit", lits.first().map(|l| l.lo))?;
            let leaks: BTreeSet<&str> = self.leaks.iter().filter(|l| l.func == f.lo).map(|l| l.path.as_str()).collect();
            d.set_item("leaks", PyList::new(py, leaks)?)?;
            table.append(d)?;
        }
        let new_py = PyList::new(py, new.iter().map(|i| issue_py(py, i)).collect::<PyResult<Vec<_>>>()?)?;
        let cur_py = PyList::new(py, cur.iter().map(|i| issue_py(py, i)).collect::<PyResult<Vec<_>>>()?)?;
        Ok((lo, end, name.to_string(), lines, table, new_py, cur_py))
    }
}
