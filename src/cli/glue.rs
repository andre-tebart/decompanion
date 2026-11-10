//! What the commands share: the project of the command line, the rule refresh, the compile, the build of a target.

use super::Io;
use crate::cliread::{record, Tok};
use crate::error::Result;
use crate::project::Project;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Instant, SystemTime};

/// The global options of the command line: the project root.
#[derive(Clone, Default)]
pub struct Sel {
    pub root: Option<String>,
}

/// The store files this process has open, by path: (size-independent identity) — a store deleted and made again
/// is closed and opened afresh (a daemon keeps its connections across requests).
static OPEN: Mutex<Option<HashMap<String, Option<SystemTime>>>> = Mutex::new(None);

fn identity(path: &str) -> Option<SystemTime> {
    std::fs::metadata(path).ok().and_then(|m| m.created().ok())
}

/// The project, its file memo attached and its store open.
pub fn open(sel: &Sel) -> Result<Project> {
    crate::timing::phase("open", || {
        let p = Project::find(sel.root.as_deref())?;
        crate::fsmemo::attach(&p.root.to_string_lossy());
        let db = p.store_path();
        let id = identity(&db);
        let mut open = OPEN.lock().unwrap();
        let m = open.get_or_insert_with(HashMap::new);
        let known = m.get(&db).cloned();
        if known.is_none() || known != Some(id) || id.is_none() {
            crate::storedb::st_close(&db);
        }
        crate::storedb::st_open(&db, &p.main_uri())?;
        m.insert(db.clone(), identity(&db));
        Ok(p)
    })
}

/// The project without a store (the configuration only).
pub fn config(sel: &Sel) -> Result<Project> {
    let p = Project::find(sel.root.as_deref())?;
    crate::fsmemo::attach(&p.root.to_string_lossy());
    Ok(p)
}

/// Refresh the rules of the project's target (nothing changed: nothing runs); `rules: N ran of M, X ms (target T)`
/// on stderr when one ran or `verbose` (with a line per rule).
pub fn refresh(io: &mut Io, p: &Project, verbose: bool, force: bool) -> Result<Vec<crate::engine::Result_>> {
    let t0 = Instant::now();
    crate::fsmemo::new_epoch();
    if force {
        crate::fsmemo::forget_all(); // a forced refresh trusts no persisted hash
    }
    for name in ["src", "decl"] {
        p.forget_input(name); // a command may have written either since its last refresh; the file memo keeps the rehash cheap
    }
    let res = crate::timing::phase("refresh", || crate::engine::engine_run(p, None, force))?;
    for r in &res {
        if r.ran && r.waiting.is_empty() {
            crate::timing::add("refresh.rules", r.ms as f64);
            crate::timing::add(&format!("rule.{}", r.rule), r.ms as f64);
            crate::timing::add(&format!("rule.{}.run", r.rule), r.ms_run);
            crate::timing::add(&format!("rule.{}.record", r.rule), r.ms_rec);
        }
        if verbose && r.ran {
            if r.waiting.is_empty() {
                io.warn(&format!("ran {}: {} claims, {} findings, {} ms", r.rule, r.facts, r.conflicts, r.ms));
            } else {
                io.warn(&format!("waiting {}: {}", r.rule, r.waiting.join(", ")));
            }
        }
    }
    let ran = res.iter().filter(|r| r.ran).count();
    if verbose || ran > 0 {
        io.warn(&format!("rules: {ran} ran of {}, {} ms (target {})", res.len(), t0.elapsed().as_millis(), p.target_name));
    }
    Ok(res)
}

/// The project, refreshed.
pub fn refreshed(io: &mut Io, sel: &Sel) -> Result<Project> {
    let p = open(sel)?;
    refresh(io, &p, false, false)?;
    Ok(p)
}

/// What a compile did: (units, compiled, removed, ms).
#[derive(Clone, Copy, Default)]
pub struct Compiled {
    pub units: i64,
    pub compiled: i64,
    pub removed: i64,
    pub ms: i64,
}

/// Bring the objects of the target up to date (compile.rs); the inputs the compile changed are forgotten. `log`:
/// print the compile's lines.
pub fn ensure(io: &mut Io, p: &Project, log: bool, force: bool) -> Result<Compiled> {
    let (_, units, compiled, _failed, removed, _pre, ms, _unavailable, lines) = crate::compile::compile_ensure(p, force, None)?;
    for name in ["objects", "src", "decl"] {
        p.forget_input(name);
    }
    if log {
        for l in &lines {
            io.say(l);
        }
    }
    Ok(Compiled { units: units as i64, compiled: compiled.len() as i64, removed: removed.len() as i64, ms })
}

/// A project that lints (a `dcp lint` ran before, libclang is there): lint the units that changed since, before the
/// refresh, so the one refresh of a build sees the objects and the lint together.
pub fn lint_built(p: &Project) -> Result<()> {
    if crate::matchcmd::lint_plan(p)?.0 == "lint" {
        crate::timing::phase("lint", || crate::matchcmd::lint_command(p))?;
    }
    Ok(())
}

/// Compile the stale units and refresh the rules: (project, compile report).
pub fn build_target(io: &mut Io, sel: &Sel, quiet: bool, force: bool) -> Result<(Project, Compiled)> {
    let p = open(sel)?;
    let rep = ensure(io, &p, !quiet, force)?;
    lint_built(&p)?;
    refresh(io, &p, false, false)?;
    Ok((p, rep))
}

/// Whether the target was built before (a `build` fact in its store).
pub fn has_build(p: &Project) -> Result<bool> {
    Ok(!crate::storedb::st_facts(&p.store_path(), Some("build"), None, None, None)?.is_empty())
}

/// The project after an edit of the sources: the stale units compiled (when the toolchain is installed and the
/// target was built: the objects must define the new names) and the rules refreshed. `p`: a project the command
/// opened already (its inputs are hashed afresh: refresh forgets src and decl).
pub fn rebuilt(io: &mut Io, sel: &Sel, p: Option<&Project>) -> Result<()> {
    if let Some(p) = p {
        if p.toolchain_available() && has_build(p)? {
            ensure(io, p, false, false)?;
            lint_built(p)?;
        }
        refresh(io, p, false, false)?;
        return Ok(());
    }
    let p = open(sel)?;
    if p.toolchain_available() && has_build(&p)? {
        build_target(io, sel, true, false)?;
    } else {
        refresh(io, &p, false, false)?;
    }
    Ok(())
}

pub fn s(x: impl Into<String>) -> Tok {
    Tok::S(x.into())
}

/// A record line (key=value tokens).
pub fn rec(kv: &[(&str, Tok)]) -> String {
    record(kv)
}
