//! The rule engine: every rule of the registry (registry.rs) runs in the order of its needs, keyed by the hash of
//! its inputs, so a run whose inputs did not change is never repeated.
//!
//! - A rule's run key is sha256(code hash, version, image, the core's hash, the out_hash of every needed rule's current run,
//!   the hash of every named input it reads). A run with the same key is made current instead of running
//!   again.
//! - A rule's code hash is the core's source hash with its id and version.
//! - A rule whose inputs wait on a human's declaration (Project.waiting_for: `libs` without archives, `toolchain`
//!   without compiler / linker) does not run its criterion: its run is empty, keyed by what it waits on, so the
//!   rules that need it run on its (empty) output and the declaration that ends the wait changes the key.
//! - A native rule's output is checked against its declaration: only its declared outputs, no level above its
//!   max support, declared producers (decl: / src:) only from a loader.
//!

use crate::error::{Error, Result};
use crate::project::{sha256_parts, Project};
use crate::registry::{RuleDef, RULES};
use crate::rules::{dispatch, Ctx, Inputs};
use crate::store::DECLARED;
use crate::{with_db, write_run, ClaimRow};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::rc::Rc;

fn rule_err(msg: String) -> Error {
    Error::rule(msg)
}

pub fn rule(id: &str) -> Result<&'static RuleDef> {
    RULES.iter().find(|r| r.id == id).ok_or_else(|| rule_err(format!("unknown rule {id}")))
}

/// The rules a rule needs: `kind:<k>` expands to every other rule that outputs k (registry order), once each.
pub fn resolve_needs(r: &RuleDef) -> Result<Vec<&'static str>> {
    let mut out: Vec<&'static str> = vec![];
    for n in r.needs {
        if let Some(k) = n.strip_prefix("kind:") {
            out.extend(RULES.iter().filter(|x| x.outputs.contains(&k) && x.id != r.id).map(|x| x.id));
        } else {
            out.push(rule(n).map_err(|_| rule_err(format!("{} needs unknown rule {n}", r.id)))?.id);
        }
    }
    let mut seen = HashSet::new();
    out.retain(|x| seen.insert(*x));
    Ok(out)
}

/// Every rule's resolved needs (resolve_needs), computed once: the registry is static.
fn needs(r: &RuleDef) -> Result<&'static [&'static str]> {
    type All = std::result::Result<HashMap<&'static str, Vec<&'static str>>, String>;
    static ALL: std::sync::OnceLock<All> = std::sync::OnceLock::new();
    let all = ALL.get_or_init(|| RULES.iter().map(|x| resolve_needs(x).map(|n| (x.id, n)).map_err(|e| e.to_string())).collect());
    match all {
        Ok(m) => Ok(m.get(r.id).map(|v| v.as_slice()).unwrap_or(&[])),
        Err(e) => Err(rule_err(e.clone())),
    }
}

/// Rules in dependency order (Kahn, the ready ones sorted by id), restricted to `ids` and everything they need. The
/// order of every rule is computed once: the registry is static.
pub fn order(ids: Option<&[String]>) -> Result<Vec<&'static RuleDef>> {
    static ALL: std::sync::OnceLock<std::result::Result<Vec<&'static RuleDef>, String>> = std::sync::OnceLock::new();
    match ids {
        None => ALL.get_or_init(|| order_of(None).map_err(|e| e.to_string())).clone().map_err(rule_err),
        Some(_) => order_of(ids),
    }
}

fn order_of(ids: Option<&[String]>) -> Result<Vec<&'static RuleDef>> {
    let mut wanted: HashSet<&'static str> = HashSet::new();
    match ids {
        None => wanted.extend(RULES.iter().map(|r| r.id)),
        Some(ids) => {
            let mut stack: Vec<&'static str> = ids.iter().map(|i| rule(i).map(|r| r.id)).collect::<Result<_>>()?;
            while let Some(i) = stack.pop() {
                if wanted.insert(i) {
                    stack.extend(needs(rule(i)?)?.iter().copied());
                }
            }
        }
    }
    let mut deps: HashMap<&'static str, HashSet<&'static str>> = HashMap::new();
    for &i in &wanted {
        deps.insert(i, needs(rule(i)?)?.iter().copied().filter(|d| wanted.contains(d)).collect());
    }
    let (mut done, mut out) = (HashSet::new(), vec![]);
    while !deps.is_empty() {
        let ready: BTreeSet<&'static str> = deps.iter().filter(|(_, d)| d.is_subset(&done)).map(|(i, _)| *i).collect();
        if ready.is_empty() {
            let mut left: Vec<&str> = deps.keys().copied().collect();
            left.sort();
            return Err(rule_err(format!("cycle among rules: {}", left.join(", "))));
        }
        for i in ready {
            out.push(rule(i)?);
            done.insert(i);
            deps.remove(i);
        }
    }
    Ok(out)
}

/// The code hash of a native rule: the core's sources, its id and version.
pub fn native_code_hash(r: &RuleDef, core_hash: &str) -> String {
    sha256_parts(&["rule", r.id, r.version, core_hash])[..16].to_string()
}

/// Its output against its declaration: declared outputs only, no support above the max, decl: / src: producers
/// only from a loader (and then with a reason).
fn check_output(r: &RuleDef, rows: &[ClaimRow]) -> Result<()> {
    for f in rows {
        if !r.outputs.contains(&f.kind.as_str()) {
            return Err(rule_err(format!("{} emits {} but lists outputs {:?}", r.id, f.kind, r.outputs)));
        }
        if f.support > r.max_support {
            return Err(rule_err(format!("{} emits {} at {:#x} as {} above its max support {}", r.id, f.kind, f.lo, f.support, r.max_support)));
        }
        if f.by.starts_with("decl:") || f.by.starts_with("src:") {
            if !r.loader {
                return Err(rule_err(format!("{} is not a loader: it may not emit {} facts", r.id, f.by)));
            }
            if f.support != DECLARED || f.reason.as_deref().is_none_or(|s| s.trim().is_empty()) {
                return Err(rule_err(format!("{}: declared {} at {:#x} ({}) without a reason", r.id, f.kind, f.lo, f.by)));
            }
        }
    }
    Ok(())
}

/// A native rule computed and recorded: (facts, conflicts, out_hash, ms computing, ms recording).
pub fn run_native(r: &RuleDef, ctx: &Ctx) -> Result<(usize, usize, String, f64, f64)> {
    let t0 = std::time::Instant::now();
    let out = dispatch(ctx)?;
    let ms = t0.elapsed().as_millis() as i64;
    let computed = t0.elapsed().as_secs_f64() * 1000.0;
    let t1 = std::time::Instant::now();
    let (rows, confl) = out.sorted();
    check_output(r, &rows)?;
    let (nf, nc) = (rows.len(), confl.len());
    let (_, h) = with_db(&ctx.db, |db| {
        write_run(db, &ctx.db, &ctx.rule, &ctx.version, &ctx.code_hash, &ctx.input_hash, &rows, &confl, ms, ctx.shortcuts)
    })?;
    Ok((nf, nc, h, computed, t1.elapsed().as_secs_f64() * 1000.0))
}

/// One rule of a refresh: whether it ran, its time, its output's size, the obligations it waits on, and the time
/// its run took to compute and to record.
#[derive(Default)]
pub struct Result_ {
    pub rule: &'static str,
    pub ran: bool,
    pub ms: i64,
    pub facts: usize,
    pub conflicts: usize,
    pub waiting: Vec<String>,
    pub ms_run: f64,
    pub ms_rec: f64,
}

/// The engine over one project's current target and store.
pub struct Engine<'a> {
    pub project: &'a Project,
    pub db: String,
    pub core_hash: String,
    base: Option<Rc<Inputs>>,
    scans: Vec<Rc<crate::frontend::Scan>>, // the scans whose pieces the rules of this run read
}

impl<'a> Engine<'a> {
    pub fn new(project: &'a Project, core_hash: &str) -> Engine<'a> {
        Engine { project, db: project.store_path(), core_hash: core_hash.into(), base: None, scans: vec![] }
    }

    pub fn code_hash(&self, r: &RuleDef) -> Result<String> {
        Ok(native_code_hash(r, &self.core_hash))
    }

    pub fn input_hash_of(&self, name: &str) -> Result<String> {
        Ok(self.project.input_hash(name).map_err(Error::config)?.unwrap_or_default())
    }

    /// The key of a rule's run: its code, version, the image, the core's hash, the output of every rule it needs (`outs`:
    /// the out_hash of each rule's current run) and its named inputs.
    fn run_key(&self, r: &RuleDef, code: &str, needed: &[&str], outs: &HashMap<String, String>) -> Result<String> {
        let mut parts = vec![code.to_string(), r.version.to_string(), self.input_hash_of("image")?, self.project.core_hash.clone()];
        for n in needed {
            let Some(out) = outs.get(*n) else { return Err(rule_err(format!("{} needs {n}, which has no current run", r.id))) };
            parts.push(format!("{n}={out}"));
        }
        for name in r.inputs {
            parts.push(format!("{name}={}", self.input_hash_of(name)?));
        }
        Ok(sha256_parts(&parts))
    }

    /// The inputs of the configuration every native rule reads (once per engine).
    fn base_inputs(&mut self) -> Result<Rc<Inputs>> {
        if let Some(b) = &self.base {
            return Ok(b.clone());
        }
        let p = self.project;
        let cfg = |e: String| Error::config(e);
        let tc = crate::toolchain::Vc6;
        let waits = !p.waiting("libs").map_err(cfg)?.is_empty();
        // the libraries: none while they wait, else the declared ones (an archive that does not exist is an error then)
        let libs = if waits { vec![] } else { p.lib_archives().map_err(cfg)? };
        let root = p.toolchain_root();
        let b = Rc::new(Inputs {
            root,
            archives: libs.clone(),
            libs,
            decl: p.toolchain_decl().map_err(cfg)?,
            target: p.target_name.clone(),
            targets: vec![p.target_name.clone()],
            images: [(p.target_name.clone(), p.target.path.clone())].into_iter().collect(),
            function_alignment: tc.function_alignment() as i64,
            code_rank: crate::grade::CODE.iter().enumerate().map(|(i, c)| (c.to_string(), i as i64)).collect(),
            max_debt: p.max_debt(),
            ..Default::default()
        });
        self.base = Some(b.clone());
        Ok(b)
    }

    /// A rule's inputs: the configuration's, with what the front end computes for the rules of the sources.
    fn inputs(&mut self, r: &RuleDef) -> Result<Rc<Inputs>> {
        let base = self.base_inputs()?;
        let front = matches!(r.id, "L.src" | "L5.placeholder" | "C.name.alias" | "A1.addr.cast" | "L13.data.code" | "G.grade" | "M.lint");
        if !front {
            return Ok(base);
        }
        let mut x = Inputs {
            root: base.root.clone(), archives: base.archives.clone(), libs: base.libs.clone(),
            decl: base.decl.clone(), target: base.target.clone(), targets: base.targets.clone(), images: base.images.clone(),
            function_alignment: base.function_alignment, code_rank: base.code_rank.clone(), ..Default::default()
        };
        if r.id != "M.lint" {
            let root = self.project.root.to_string_lossy().into_owned();
            let src = self.input_hash_of("src")?;
            let s = crate::frontend::scan(&root, Some(&src)).map_err(rule_err)?;
            x.scan = crate::layout::ScanRef {
                pieces: s.piece_ids(),
                errors: s.own_errors.iter().map(|(f, l, c, m)| (c.clone(), f.clone(), *l, m.clone())).collect(),
            };
            if r.id == "G.grade" {
                (x.raw, x.described) = crate::frontend::context(&s);
            }
            self.scans.push(s);
        }
        if r.id == "M.lint" || r.id == "G.grade" {
            let units = crate::plan::plan(self.project).map_err(rule_err)?;
            let lint = with_db(&self.db, |c| Ok(crate::lintrun::last(c)))?;
            if r.id == "M.lint" {
                x.units = units.iter().map(|a| (a.unit.clone(), a.src_hash.clone())).collect();
            } else if let Some(l) = lint {
                let current: HashMap<&str, &str> = units.iter().map(|a| (a.unit.as_str(), a.src_hash.as_str())).collect();
                x.lint_calls = l["calls"].as_object().map(|cs| cs.iter().map(|(f, xs)| {
                    (f.clone(), xs.as_array().into_iter().flatten().map(|c| (c[0].as_i64().unwrap_or(0), c[1].as_str().unwrap_or("").to_string())).collect())
                }).collect());
                let mut linted: Vec<String> = l["units"].as_object().into_iter().flatten()
                    .filter(|(u, h)| current.get(u.as_str()).copied() == h.as_str()).map(|(u, _)| u.clone()).collect();
                linted.sort();
                x.linted = linted;
            }
        }
        Ok(Rc::new(x))
    }

    /// Make the run current unless it is already (`was`: the rule's current run id before this refresh).
    fn make_current_if(&self, r: &RuleDef, run_id: i64, was: Option<i64>) -> Result<()> {
        if was != Some(run_id) {
            crate::storedb::st_make_current(&self.db, r.id, run_id)?;
        }
        Ok(())
    }

    /// Bring the rules (all, or `ids` and what they need) up to date.
    pub fn run(&mut self, ids: Option<&[String]>, force: bool) -> Result<Vec<Result_>> {
        crate::storedb::st_open(&self.db)?;
        // each rule's current run, read once: the engine is the store's one writer during a refresh, and each rule's
        // step names the output of the run it makes current (its needs come before it in the order)
        let was = crate::storedb::st_current_runs(&self.db)?;
        let mut outs: HashMap<String, String> = was.iter().map(|(rule, (_, out))| (rule.clone(), out.clone())).collect();
        let mut results = vec![];
        for r in order(ids)? {
            let out = self.step(r, force, was.get(r.id).map(|c| c.0), &outs, &mut results)?;
            outs.insert(r.id.to_string(), out);
        }
        // a full refresh that recorded runs: the runs of rules the core no longer has stop being current (M8.reloc's
        // findings, now G.grade's, would otherwise stay in the gate)
        if ids.is_none() && results.iter().any(|r| r.ran) {
            let live: Vec<&str> = crate::registry::RULES.iter().map(|r| r.id).collect();
            crate::storedb::st_retire(&self.db, &live)?;
        }
        Ok(results)
    }

    /// One rule of a refresh: made current from a run with its inputs, else run and recorded; the out_hash of the run
    /// now current. `was`: its current run id before this refresh.
    fn step(&mut self, r: &'static RuleDef, force: bool, was: Option<i64>, outs: &HashMap<String, String>, results: &mut Vec<Result_>) -> Result<String> {
        let needed = needs(r)?;
        let inputs: Vec<String> = r.inputs.iter().map(|s| s.to_string()).collect();
        let waits = self.project.waiting_for(&inputs).map_err(Error::config)?;
        let code = self.code_hash(r)?;
        if !waits.is_empty() {
            let mut parts = vec![code.clone(), r.version.to_string(), "waiting".into()];
            parts.extend(waits.iter().cloned());
            let ih = sha256_parts(&parts);
            if let Some((run_id, out)) = crate::storedb::st_find_run(&self.db, r.id, &ih)? {
                self.make_current_if(r, run_id, was)?;
                results.push(Result_ { rule: r.id, waiting: waits, ..Default::default() });
                return Ok(out);
            }
            let (_, out) = with_db(&self.db, |db| write_run(db, &self.db, r.id, r.version, &code, &ih, &[], &[], 0, true))?;
            results.push(Result_ { rule: r.id, ran: true, waiting: waits, ..Default::default() });
            return Ok(out);
        }
        let ih = self.run_key(r, &code, needed, outs)?;
        let found = if force { None } else { crate::storedb::st_find_run(&self.db, r.id, &ih)? };
        if let Some((run_id, out)) = found {
            self.make_current_if(r, run_id, was)?;
            results.push(Result_ { rule: r.id, ..Default::default() });
            return Ok(out);
        }
        let t0 = std::time::Instant::now();
        let inputs = self.inputs(r)?;
        let ctx = Ctx {
            rule: r.id.into(), version: r.version.into(), code_hash: code, input_hash: ih, db: self.db.clone(),
            needed: needed.iter().map(|s| s.to_string()).collect(), root: self.project.root.to_string_lossy().into_owned(),
            image: self.project.target.path.clone(),
            fill_forms: crate::toolchain::Vc6.fill_forms().iter().map(|f| f.to_vec()).collect(),
            record: true,
            shortcuts: std::env::var_os("DCP_NO_SHORTCUTS").is_none_or(|v| v.is_empty()), inputs,
        };
        let (nf, nc, out, ms_run, ms_rec) = run_native(r, &ctx)?;
        results.push(Result_ { rule: r.id, ran: true, ms: t0.elapsed().as_millis() as i64, facts: nf, conflicts: nc, ms_run, ms_rec,
                               ..Default::default() });
        Ok(out)
    }
}

/// Refresh the rules (all, or `ids` and what they need) of a project's current target: [(rule, ran, ms, facts,
/// conflicts, waiting, ms computing, ms recording)].
pub fn engine_run(p: &crate::project::Project, ids: Option<&[String]>, force: bool) -> Result<Vec<Result_>> {
    Engine::new(p, &p.core_hash).run(ids, force)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_follows_needs() {
        let all = order(None).unwrap();
        let pos: HashMap<&str, usize> = all.iter().enumerate().map(|(i, r)| (r.id, i)).collect();
        for r in &all {
            for n in resolve_needs(r).unwrap() {
                assert!(pos[n] < pos[r.id], "{} before {n}", r.id);
            }
        }
        let some = order(Some(&["S.unknown".to_string()])).unwrap();
        assert_eq!(some.last().unwrap().id, "S.unknown");
        assert!(some.iter().any(|r| r.id == "S.codewalk") && !some.iter().any(|r| r.id == "G.grade"));
    }

    #[test]
    fn kind_needs_expand_to_every_other_producer() {
        let r = rule("S.unknown").unwrap();
        let needs = resolve_needs(r).unwrap();
        assert!(!needs.contains(&"S.unknown"));
        let producers = RULES.iter().filter(|x| x.outputs.contains(&"symbol") && x.id != "S.unknown").count();
        assert!(needs.len() >= producers.min(1));
    }

    #[test]
    fn runs_are_keyed_by_their_inputs() {
        let d = crate::testkit::scratch("engine");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("net.dll"), crate::pe::testpe::build(None)).unwrap();
        std::fs::write(d.join("decompanion.toml"), "[target]\nname = \"net\"\npath = \"net.dll\"\n").unwrap();
        let p = Project::open(&d, "core").unwrap();
        let mut e = Engine::new(&p, "core");
        let ids = ["S.sections".to_string()];
        let ran = |res: Vec<Result_>| res.iter().filter(|r| r.ran).map(|r| r.rule).collect::<Vec<_>>();
        assert_eq!(ran(e.run(Some(&ids), false).unwrap()), ["S.sections"]);
        assert!(ran(e.run(Some(&ids), false).unwrap()).is_empty()); // the same inputs: made current, not run
        assert_eq!(ran(e.run(Some(&ids), true).unwrap()), ["S.sections"]);
        let mut e2 = Engine::new(&p, "core2"); // another core: another code hash, another key
        assert_eq!(ran(e2.run(Some(&ids), false).unwrap()), ["S.sections"]);
        let path = p.store_path();
        let n = with_db(&path, |db| crate::store::claims_of(db, &path, "section", None, |_| true)).unwrap().len();
        assert!(n >= 3, "{n} sections");
        crate::forget_conn(&p.store_path());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn outputs_checked_against_the_declaration() {
        let r = rule("S.sections").unwrap();
        let row = |kind: &str, support: crate::store::Support, by: &str| ClaimRow { lo: 0, hi: 1, kind: kind.into(), value: "{}".into(), support, by: by.into(), reason: None };
        assert!(check_output(r, &[row("section", crate::store::OBSERVED, "rule:S.sections@1")]).is_ok());
        assert!(check_output(r, &[row("name", crate::store::OBSERVED, "rule:S.sections@1")]).is_err());
        let d = rule("S.unknown").unwrap();
        assert!(check_output(d, &[row("symbol", crate::store::DECLARED, "rule:x")]).is_err());
        assert!(check_output(r, &[row("section", crate::store::DECLARED, "decl:decl/text.dcl:3")]).is_err());
        // a loader's declared fact carries its reason
        let l = rule("L.decl").unwrap();
        let k = l.outputs[0];
        assert!(check_output(l, &[row(k, crate::store::DECLARED, "decl:decl/text.dcl:3")]).is_err());
        assert!(check_output(l, &[ClaimRow { reason: Some("a leaked path".into()), ..row(k, crate::store::DECLARED, "decl:decl/text.dcl:3") }]).is_ok());
    }
}
