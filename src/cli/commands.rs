//! The commands: each opens the project, refreshes or builds the target, then prints what the core returns (the
//! modules named per command). The order of their output and their exit codes are the output contract.

use super::args::*;
use super::glue::{self, build_target, every_target, open, rec, refresh, refreshed, s, target_names, Sel};
use super::Io;
use crate::cliread::Tok;
use crate::error::{Error, Result};
use crate::project::Project;
use std::collections::HashMap;

pub fn dispatch(io: &mut Io, cli: Cli) -> Result<i32> {
    let sel = Sel { root: cli.root.clone(), target: cli.target.clone() };
    let sel = &sel;
    match cli.cmd {
        Cmd::Setup { verbose, force, all_targets, no_analyzer, analyzer_force } => setup(io, sel, verbose, force, all_targets, no_analyzer, analyzer_force),
        Cmd::Report { all_targets, verbose } => {
            for (i, name) in target_names(sel, all_targets)?.iter().enumerate() {
                if i > 0 {
                    io.say("");
                }
                let p = refreshed(io, sel, name.as_deref())?;
                let lines = crate::clicmd::report_command(&p, verbose)?;
                io.report("report", &lines, None, 0);
            }
            Ok(0)
        }
        Cmd::Why { addr, refs } => {
            let p = refreshed(io, sel, None)?;
            let (l, e, c) = crate::clicmd::why_command(&p, addr, refs)?;
            Ok(io.report("why", &l, e.as_deref(), c))
        }
        Cmd::Facts { range, kind, json } => {
            let p = refreshed(io, sel, None)?;
            let l = crate::clicmd::facts_command(&p, &range, kind, json)?;
            Ok(io.report("facts", &l, None, 0))
        }
        Cmd::Map { range } => {
            let p = refreshed(io, sel, None)?;
            let l = crate::clicmd::map_command(&p, range)?;
            Ok(io.report("map", &l, None, 0))
        }
        Cmd::Conflicts { severity, json } => {
            let p = refreshed(io, sel, None)?;
            let l = crate::clicmd::conflicts_command(&p, severity.map(|s| s.as_str().to_string()), json)?;
            Ok(io.report("conflicts", &l, None, 0))
        }
        Cmd::Check { strict, against } => check(io, sel, strict, against),
        Cmd::Serve { stop, status, foreground } => Ok(crate::client::serve(io, sel.root.as_deref(), stop, status, foreground)),
        Cmd::Rules { verbose } => {
            let p = refreshed(io, sel, None)?;
            let l = crate::clicmd::rules_command(&p, verbose)?;
            Ok(io.report("rules", &l, None, 0))
        }
        Cmd::Status { json } => status(io, sel, json),
        Cmd::Toolchain { verbose, sub } => match sub {
            None => {
                let _ = verbose;
                let names = every_target(sel)?;
                for (i, name) in names.iter().enumerate() {
                    if i > 0 {
                        io.say("");
                    }
                    let p = refreshed(io, sel, Some(name))?;
                    let l = crate::decide::decide_toolchain_view(&p)?;
                    io.report("toolchain", &l, None, 0);
                }
                Ok(0)
            }
            Some(ToolchainCmd::Probe { verbose }) => probe(io, sel, verbose),
            Some(ToolchainCmd::Declare { pairs, why }) => toolchain_declare(io, sel, pairs, why),
        },
        Cmd::Libs { sub } => match sub {
            LibsCmd::Candidates { force, verbose } => {
                let p = open(sel, None)?;
                if p.toolchain_root().is_none() {
                    return Ok(io.report("libs candidates", &[], Some("no toolchain root declared: dcp toolchain declare root=DIR --why \"...\" first"), 2));
                }
                refresh(io, &p, false, false)?;
                let (lines, log) = crate::libcand::libs_candidates_lines(&p, crate::CORE_HASH, force)?;
                if verbose {
                    for l in &log {
                        io.warn(l);
                    }
                }
                Ok(io.report("libs candidates", &lines, None, 0))
            }
            LibsCmd::Declare { archives, why } => {
                let p = glue::config(sel, None)?;
                let (l, e, c) = crate::decide::decide_libs_declare(&p, archives, why)?;
                let code = io.report("libs declare", &l, e.as_deref(), c);
                if code != 0 {
                    return Ok(code);
                }
                if let Some(p) = rerun(io, sel, &p.target_name)? {
                    let l = crate::decide::decide_libs_after(&p)?;
                    io.report("libs declare", &l, None, 0);
                }
                Ok(0)
            }
        },
        Cmd::Analyzer { sub: AnalyzerCmd::Declare { plugin, pairs, why } } => {
            let p = glue::config(sel, None)?;
            let (l, e, c) = crate::decide::decide_analyzer_declare(&p, &plugin, pairs, why)?;
            let code = io.report("analyzer declare", &l, e.as_deref(), c);
            if code != 0 {
                return Ok(code);
            }
            if let Some(p) = rerun(io, sel, &p.target_name)? {
                status_tail(io, &p)?;
            }
            Ok(0)
        }
        Cmd::Data { sub } => match sub {
            DataCmd::Map { unit, externs } => {
                let p = refreshed(io, sel, None)?;
                let (lines, status) = crate::datafix::data_map(&p, unit, externs)?;
                io.say(&lines.join("\n"));
                Ok(status)
            }
            DataCmd::Fix { check, unit, write, limit, verbose } => {
                let p = open(sel, None)?;
                let (out, err) = (std::cell::RefCell::new(Vec::<u8>::new()), ());
                let _ = (&out, err);
                // sync: build and refresh the store; emit: a line on stdout
                let io_cell = std::cell::RefCell::new(io);
                let mut sync = || -> Result<()> {
                    let mut io = io_cell.borrow_mut();
                    glue::ensure(&mut io, &p, false, false)?;
                    refresh(&mut io, &p, false, false)?;
                    Ok(())
                };
                let mut emit = |line: String| -> Result<()> {
                    io_cell.borrow_mut().say(&line);
                    Ok(())
                };
                crate::datafix::data_fix(&p, check, unit, write, limit, verbose, &mut sync, &mut emit)
            }
        },
        Cmd::Headers { sub: HeadersCmd::Conflicts { unit, headers, write, trial, at } } => {
            let p = refreshed(io, sel, None)?;
            let (lines, status) = crate::headers::headers_conflicts(&p, &crate::cs::library(""), &unit, headers, write, at, trial)?;
            io.say(&lines.join("\n"));
            Ok(status)
        }
        Cmd::Grade { what } => {
            let (p, _) = build_target(io, sel, None, true, false)?;
            let q7 = current_lint(io, &p)?;
            let (l, e, c) = crate::matchcmd::grade_command(&p, what, &q7)?;
            Ok(io.report("grade", &l, e.as_deref(), c))
        }
        Cmd::Next { base, deep, names, n, unit, shard } => {
            let _ = base;
            let (p, _) = build_target(io, sel, None, true, false)?;
            current_lint(io, &p)?;
            let which = if deep { "deep" } else if names { "names" } else { "base" };
            let (l, e, c) = crate::matchcmd::next_command(&p, which, shard, unit, n)?;
            Ok(io.report("next", &l, e.as_deref(), c))
        }
        Cmd::Asmdiff { name, regs, all, symbols, plain } => {
            let (p, _) = build_target(io, sel, None, true, false)?;
            let (l, e, c) = crate::matchcmd::asmdiff_command(&p, &crate::cs::library(""), &name, regs, all, symbols, plain)?;
            Ok(io.report("asmdiff", &l, e.as_deref(), c))
        }
        Cmd::Diffclass { name, all } => {
            let (p, _) = build_target(io, sel, None, true, false)?;
            let (l, e, c) = crate::matchcmd::diffclass_command(&p, &crate::cs::library(""), &name, all)?;
            Ok(io.report("diffclass", &l, e.as_deref(), c))
        }
        Cmd::Escalate { name, why, clear, size_explained } => level(io, sel, "deep", &name, why, clear, size_explained),
        Cmd::Stuck { name, why, clear } => level(io, sel, "stuck", &name, why, clear, None),
        Cmd::Promote { accept_falls } => promote(io, sel, accept_falls),
        Cmd::Accept { name, to, readability, why } => {
            if in_worktree(io, sel, "accept", "changed")? {
                return Ok(1);
            }
            let blank = why.split_whitespace().next().is_none();
            if blank || (to.is_none() && readability.is_none()) {
                let (l, e, c) = crate::matchcmd::accept_command(None, &name, to, readability, Some(why))?;
                return Ok(io.report("accept", &l, e.as_deref(), c));
            }
            let p = refreshed(io, sel, None)?;
            let (l, e, c) = crate::matchcmd::accept_command(Some(&p), &name, to, readability, Some(why))?;
            Ok(io.report("accept", &l, e.as_deref(), c))
        }
        Cmd::Link { all_targets } => {
            let mut failed = false;
            for name in target_names(sel, all_targets)? {
                let (p, _) = build_target(io, sel, name.as_deref(), true, false)?;
                let (lines, ok, _, _, _) = crate::matchcmd::link_command(&p)?;
                io.report("link", &lines, None, 0);
                failed = failed || !ok;
            }
            Ok(failed as i32)
        }
        Cmd::Lint { all_targets } => {
            let mut failed = false;
            for name in target_names(sel, all_targets)? {
                let (p, _) = build_target(io, sel, name.as_deref(), true, false)?;
                if !crate::lintrun::lint_available(&p) {
                    return Ok(io.report("lint", &[], Some(crate::matchcmd::lint_not_found()), 2));
                }
                let (lines, bad) = crate::matchcmd::lint_command(&p)?;
                refresh(io, &p, false, false)?;
                io.report("lint", &lines, None, 0);
                failed = failed || bad;
            }
            Ok(failed as i32)
        }
        Cmd::Init { dir, target_path, name, target_name } => {
            let (lines, error) = crate::init::init_project(&dir, &target_path, name, target_name);
            if let Some(e) = error {
                io.warn(&e);
                return Ok(1);
            }
            Ok(io.report("init", &lines, None, 0))
        }
        Cmd::Target { sub } => match sub {
            TargetCmd::List { json } => {
                let p = glue::config(sel, None)?;
                let l = crate::clicmd::target_list(&p, json)?;
                Ok(io.report("target list", &l, None, 0))
            }
            TargetCmd::Add { name, path } => {
                let p = glue::config(sel, None)?;
                let (lines, error) = crate::init::target_add(&p.root.to_string_lossy(), &name, &path);
                if let Some(e) = error {
                    io.warn(&e);
                    return Ok(1);
                }
                Ok(io.report("target add", &lines, None, 0))
            }
        },
        Cmd::Decl { sub: DeclCmd::Add { line } } => {
            let p = open(sel, None)?;
            let (lines, error, code, made) = crate::clicmd::decl_add(&p, &line)?;
            io.report("decl add", &lines, error.as_deref(), 0);
            let Some((target, by)) = made else { return Ok(code) };
            let p = refreshed(io, sel, Some(&target))?;
            let (lines, code) = crate::clicmd::decl_conflicts(&p, &by)?;
            Ok(io.report("decl add", &lines, None, code))
        }
        Cmd::Layout { sub } => layout(io, sel, sub),
        Cmd::Build { all_targets, force, units, variant } => build(io, sel, all_targets, force, units, variant),
        Cmd::Unit { sub } => unit(io, sel, sub),
        Cmd::Fn { key } => {
            let p = open(sel, None)?;
            let (l, e, c) = crate::clicmd::fn_command(&p, &key)?;
            Ok(io.report("fn", &l, e.as_deref(), c))
        }
        Cmd::Disasm { addr, len, ours } => match ours {
            Some(n) => read(io, sel, "disasm", "disasm-ours", &[("name", Some(n))]),
            None => read(io, sel, "disasm", "disasm", &[("addr", addr), ("len", len)]),
        },
        Cmd::Dump { addr, len, str, dword, float } => {
            read(io, sel, "dump", "dump", &[("addr", Some(addr)), ("len", len), ("str", flag(str)), ("dword", flag(dword)), ("float", flag(float))])
        }
        Cmd::Refs { what } => read(io, sel, "refs", "refs", &[("what", Some(what))]),
        Cmd::Draft { addr, next, show, unit } => {
            let p = refreshed(io, sel, None)?;
            let key = p.analyzer_key()?;
            let (l, e, c) = crate::draft::draft_command(&p, &crate::cs::library(""), addr, next, show, unit, &key)?;
            Ok(draft_report(io, "draft", l, e, c))
        }
        Cmd::Rename { pairs, from_file, why } => rename(io, sel, pairs, from_file, why),
        Cmd::Session { sub } => session(io, sel, sub),
        Cmd::Skills { sub: SkillsCmd::Install { force } } => {
            let p = glue::config(sel, None)?;
            let written = crate::init::skills_install(&p.root.to_string_lossy(), force)?;
            io.say(&rec(&[("skills", Tok::I(written.len() as i64)), ("into", s(".claude/skills"))]));
            for w in &written {
                io.say(&format!("  wrote {w}"));
            }
            Ok(0)
        }
        Cmd::Run(a) => run(io, sel, a),
        Cmd::Wt { sub } => match sub {
            WtCmd::New { name } => wt(io, sel, "new", Some(name), false),
            WtCmd::List => wt(io, sel, "list", None, false),
            WtCmd::Drop { name, force } => wt(io, sel, "drop", Some(name), force),
        },
        Cmd::Seed { path } => wt(io, sel, "seed", Some(path), false),
        Cmd::SelfCmd { sub: SelfSub::Install } => Ok(crate::selfinstall::install(io)),
    }
}

fn flag(b: bool) -> Option<String> {
    b.then(|| "1".to_string())
}

/// draft / unit reports: the lines joined, the error as `dcp CMD: error` (exit 1), else the status.
fn draft_report(io: &mut Io, cmd: &str, lines: Vec<String>, error: Option<String>, status: i32) -> i32 {
    if !lines.is_empty() {
        io.say(&lines.join("\n"));
    }
    match error.filter(|e| !e.is_empty()) {
        Some(e) => {
            io.warn(&format!("dcp {cmd}: {e}"));
            1
        }
        None => status,
    }
}

// ------------------------------------------------------------------------------------------------ setup / check

fn setup(io: &mut Io, sel: &Sel, verbose: bool, force: bool, all_targets: bool, no_analyzer: bool, analyzer_force: bool) -> Result<i32> {
    let mut failed = false;
    for (i, name) in target_names(sel, all_targets)?.iter().enumerate() {
        if i > 0 {
            io.say("");
        }
        let p = open(sel, name.as_deref())?;
        refresh(io, &p, verbose, force)?;
        if !no_analyzer {
            let (out, errs, ok, exported) = crate::analyzers::analyzer_step(&p, analyzer_force)?;
            io.report("setup", &out, None, 0);
            for l in &errs {
                io.warn(l);
            }
            if exported {
                refresh(io, &p, verbose, false)?;
            }
            failed = failed || !ok;
        }
        let l = crate::clicmd::report_command(&p, verbose)?;
        io.report("setup", &l, None, 0);
        status_tail(io, &p)?;
    }
    Ok(failed as i32)
}

fn check(io: &mut Io, sel: &Sel, strict: bool, against: Option<String>) -> Result<i32> {
    let p0 = glue::config(sel, None)?;
    let mut failed = false;
    let base = against.as_ref().map(|rev| crate::queues::grades_baseline_at(&p0.root.to_string_lossy(), rev));
    for name in every_target(sel)? {
        let (p, _) = build_target(io, sel, Some(&name), true, false)?;
        let built = glue::has_build(&p)?;
        if built && crate::lintrun::lint_available(&p) {
            crate::matchcmd::lint_command(&p)?;
            refresh(io, &p, false, false)?;
        }
        let (lines, mut reasons) = crate::clicmd::check_conflicts(&p, strict)?;
        io.report("check", &lines, None, 0);
        if built && p.toolchain_available() {
            let (lines, ok, why, _, _) = crate::matchcmd::link_command(&p)?;
            io.report("check", &lines, None, 0);
            if !ok {
                reasons.push(why.unwrap_or_default());
            }
        } else if built {
            io.say(&rec(&[("link", s(name.clone())), ("skipped", s("the toolchain is not available"))]));
        }
        let open_ = crate::decide::decide_gate(&p)?; // after the link: libs.archives reads the link's `library` class
        io.report("check", &open_, None, 0);
        if !open_.is_empty() {
            reasons.insert(0, format!("obligations={}", open_.len()));
        }
        if let (Some(rev), Some(base)) = (&against, &base) {
            let falls = crate::queues::grades_regressions(&p.target_name, &p.store_path(), base)?;
            io.say(&rec(&[("against", s(rev.clone())), ("target", s(name.clone())), ("falls", Tok::I(falls.len() as i64))]));
            let fell: Vec<String> = falls.iter().map(|l| format!("  fell: {l}")).collect();
            io.report("check", &fell, None, 0);
            if !falls.is_empty() {
                reasons.push(format!("falls={}", falls.len()));
            }
        }
        let mut kv = vec![("gate", s(if reasons.is_empty() { "ok" } else { "FAIL" })), ("target", s(name.clone()))];
        if !reasons.is_empty() {
            kv.push(("why", s(reasons.join(";"))));
        }
        io.say(&rec(&kv));
        failed = failed || !reasons.is_empty();
    }
    Ok(failed as i32)
}

// ------------------------------------------------------------------------------------------------ status / decisions

/// The status of one target (decide.rs); `shown`: the project-wide obligations already printed, returned extended.
fn print_status(io: &mut Io, p: &Project, shown: Vec<String>, work: bool, json: bool) -> Result<Vec<String>> {
    let (lines, shown) = crate::decide::decide_status(p, shown, work, json)?;
    for l in &lines {
        io.say(l);
    }
    Ok(shown)
}

/// The tail other commands print (setup, session start).
fn status_tail(io: &mut Io, p: &Project) -> Result<()> {
    io.say("");
    print_status(io, p, vec![], true, false)?;
    Ok(())
}

fn status(io: &mut Io, sel: &Sel, json: bool) -> Result<i32> {
    let mut shown = vec![];
    for (i, name) in every_target(sel)?.iter().enumerate() {
        if i > 0 {
            io.say("");
        }
        let p = refreshed(io, sel, Some(name))?;
        shown = print_status(io, &p, shown, true, json)?;
    }
    Ok(0)
}

/// The rules again after a declaration, so the next obligation shows at once: the project, or None before the first
/// `dcp setup` of the target (no store yet: setup runs the rules the first time, a declaration made before it only
/// writes).
fn rerun(io: &mut Io, sel: &Sel, target: &str) -> Result<Option<Project>> {
    let p = glue::config(sel, Some(target))?;
    if !std::path::Path::new(&p.store_path()).exists() {
        io.say("rules: not run yet (no store): `dcp setup` runs them and prints the next obligations");
        return Ok(None);
    }
    Ok(Some(refreshed(io, sel, Some(target))?))
}

fn toolchain_declare(io: &mut Io, sel: &Sel, pairs: Vec<String>, why: Option<String>) -> Result<i32> {
    let p = glue::config(sel, None)?;
    let (lines, error, code, root) = crate::decide::decide_toolchain_declare(&p, pairs, why)?;
    if error.is_some() || code != 0 {
        return Ok(io.report("toolchain declare", &lines, error.as_deref(), code));
    }
    io.report("toolchain declare", &lines, None, 0);
    let Some(p) = rerun(io, sel, &p.target_name)? else { return Ok(0) };
    let (lines, code) = crate::decide::decide_toolchain_after(&p, root)?;
    Ok(io.report("toolchain declare", &lines, None, code))
}

// ------------------------------------------------------------------------------------------------ match

/// Lint again when a unit changed since the last lint (only the changed units parse) so Q7 is current; the note on
/// where Q7 comes from.
fn current_lint(io: &mut Io, p: &Project) -> Result<String> {
    let (action, note) = crate::matchcmd::lint_plan(p)?;
    if action == "lint" {
        crate::matchcmd::lint_command(p)?;
        refresh(io, p, false, false)?;
    }
    Ok(note)
}

fn level(io: &mut Io, sel: &Sel, lvl: &str, name: &str, why: Option<String>, clear: bool, size_explained: Option<String>) -> Result<i32> {
    let p = refreshed(io, sel, None)?;
    let (lines, error, status) = crate::queues::level_command(&p, lvl, name, clear, why, Some(crate::cs::library("")), size_explained)?;
    let label = if error.as_deref().is_some_and(|e| e.starts_with("refused")) { "escalate" } else { lvl };
    Ok(io.report(label, &lines, error.as_deref(), status))
}

/// Refused in a worktree: the baseline changes on main only.
fn in_worktree(io: &mut Io, sel: &Sel, cmd: &str, what: &str) -> Result<bool> {
    let p0 = Project::find(sel.root.as_deref(), None)?;
    if p0.main_build_dir().is_some() {
        io.warn(&format!("dcp {cmd}: refused in a worktree (the baseline is {what} on main only)"));
        return Ok(true);
    }
    Ok(false)
}

fn promote(io: &mut Io, sel: &Sel, accept_falls: bool) -> Result<i32> {
    if in_worktree(io, sel, "promote", "promoted")? {
        return Ok(1);
    }
    let p0 = Project::find(sel.root.as_deref(), None)?;
    let mut projects = vec![];
    for t in &p0.targets {
        projects.push(build_target(io, sel, Some(&t.name), true, false)?.0);
    }
    let (l, e, c) = crate::matchcmd::promote_command(&projects[0].root.to_string_lossy(), &projects, accept_falls)?;
    Ok(io.report("promote", &l, e.as_deref(), c))
}

fn probe(io: &mut Io, sel: &Sel, verbose: bool) -> Result<i32> {
    let (p, _) = build_target(io, sel, None, true, false)?;
    let (result, line) = crate::probe::probe_run(&p)?;
    if verbose {
        io.say(&line);
    }
    p.forget_input("probe");
    refresh(io, &p, false, false)?;
    let l = crate::matchcmd::probe_report(&p, &result)?;
    Ok(io.report("toolchain probe", &l, None, 0))
}

fn build(io: &mut Io, sel: &Sel, all_targets: bool, force: bool, units: bool, variant: Option<String>) -> Result<i32> {
    let mut failed = false;
    for (i, name) in target_names(sel, all_targets)?.iter().enumerate() {
        if i > 0 {
            io.say("");
        }
        let (mut p, rep) = build_target(io, sel, name.as_deref(), false, force)?;
        let (lines, bad) = crate::clicmd::build_summary(&p, (rep.units, rep.compiled, rep.removed, rep.ms), units)?;
        io.report("build", &lines, None, 0);
        failed = failed || bad;
        let cleared = crate::queues::grades_auto_clear(&p)?;
        let cl: Vec<String> = cleared.iter().map(|l| format!("  {l}")).collect();
        io.report("build", &cl, None, 0);
        if !cleared.is_empty() {
            p = build_target(io, sel, name.as_deref(), true, force)?.0;
        }
        if let Some(v) = &variant {
            let (lines, ok) = crate::run::variant_build_command(&p, v, force)?;
            io.report("build", &lines, None, 0);
            failed = failed || !ok;
        }
    }
    Ok(failed as i32)
}

// ------------------------------------------------------------------------------------------------ layout / reading

fn layout(io: &mut Io, sel: &Sel, sub: LayoutCmd) -> Result<i32> {
    match sub {
        LayoutCmd::Next { n, start, json } => {
            let p = refreshed(io, sel, None)?;
            let l = crate::clicmd::layout_next(&p, n, start, json)?;
            Ok(io.report("layout next", &l, None, 0))
        }
        LayoutCmd::Units { verbose, json } => {
            let p = refreshed(io, sel, None)?;
            let l = crate::clicmd::layout_units(&p, verbose, json)?;
            Ok(io.report("layout units", &l, None, 0))
        }
        LayoutCmd::Literals { what } => read(io, sel, "layout literals", "literals", &[("what", what)]),
        LayoutCmd::Fptrs { what } => read(io, sel, "layout fptrs", "fptrs", &[("what", what)]),
        LayoutCmd::Starts { range } => {
            let r = (!range.is_empty()).then(|| range.join(".."));
            read(io, sel, "layout starts", "starts", &[("range", r)])
        }
        LayoutCmd::Unit { sub: LayoutUnitCmd::Propose(a) } => propose(io, sel, a),
    }
}

fn propose(io: &mut Io, sel: &Sel, a: ProposeArgs) -> Result<i32> {
    let p = refreshed(io, sel, None)?;
    let (lines, error, code, written) = crate::clicmd::propose_command(&p, &a.range, &a.name, &a.why, a.by.clone(), a.dry_run)?;
    io.report("layout unit propose", &lines, error.as_deref(), 0);
    if !written {
        return Ok(code);
    }
    let p = refreshed(io, sel, None)?;
    let (lines, code) = crate::clicmd::propose_verdict(&p, &a.name)?;
    Ok(io.report("layout unit propose", &lines, None, code))
}

/// A reading command (cliread.rs): its lines, its error as `dcp TITLE: error` (exit 1).
fn read(io: &mut Io, sel: &Sel, title: &str, cmd: &str, args: &[(&str, Option<String>)]) -> Result<i32> {
    let p = refreshed(io, sel, None)?;
    let vals: HashMap<String, Option<String>> = args.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
    let (lines, error) = crate::cliread::read_command(&p, &crate::cs::library(""), cmd, vals)?;
    if !lines.is_empty() {
        io.say(&lines.join("\n"));
    }
    match error {
        Some(e) => {
            io.warn(&format!("dcp {title}: {e}"));
            Ok(1)
        }
        None => Ok(0),
    }
}

fn unit(io: &mut Io, sel: &Sel, sub: UnitCmd) -> Result<i32> {
    match sub {
        UnitCmd::New { name, range, by, why } => {
            let code = propose(io, sel, ProposeArgs { range: range.clone(), name: name.clone(), why: why.clone(), by: Some(by.clone()), dry_run: false })?;
            if code != 0 {
                return Ok(code);
            }
            let p = glue::config(sel, None)?;
            for l in crate::units::unit_create(&p.root.to_string_lossy(), &name, &range, Some(by), &why)? {
                io.say(&l);
            }
            io.say("next: dcp draft --next  (the unit's functions in address order)");
            Ok(0)
        }
        UnitCmd::Join { a, b, why } => {
            let p = refreshed(io, sel, None)?;
            let cell = std::cell::RefCell::new(&mut *io);
            let mut build = || -> Result<()> {
                build_target(&mut cell.borrow_mut(), sel, sel.target.as_deref(), true, false)?;
                Ok(())
            };
            let (l, e, c) = crate::units::unit_join(&p, &a, &b, &why, &mut build)?;
            Ok(draft_report(cell.into_inner(), "unit join", l, e, c))
        }
        UnitCmd::Rename { old, new, why, by } => {
            let p = refreshed(io, sel, None)?;
            let cell = std::cell::RefCell::new(&mut *io);
            let mut rebuild = || glue::rebuilt(&mut cell.borrow_mut(), sel, None);
            let (l, e, c) = crate::units::unit_rename(&p, &old, &new, by, &why, &mut rebuild)?;
            Ok(draft_report(cell.into_inner(), "unit rename", l, e, c))
        }
    }
}

fn rename(io: &mut Io, sel: &Sel, words: Vec<String>, from_file: Option<String>, why: Option<String>) -> Result<i32> {
    let mut first2 = words.clone();
    first2.extend(["".to_string(), "".to_string()]);
    let (old0, new0) = (first2[0].clone(), first2[1].clone());
    let fail = |io: &mut Io, msg: &str, old: Option<&str>, new: Option<&str>| -> i32 {
        io.say(&rec(&[("rename", s(old.unwrap_or(&old0))), ("to", s(new.unwrap_or(&new0))), ("error", s(msg))]));
        io.warn(&format!("dcp rename: {msg}"));
        1
    };
    let (error, pairs, tgt, first) = crate::rename::rename_pairs(words, from_file, why);
    if let Some(e) = error {
        return Ok(fail(io, &e, None, None));
    }
    let p = match open(sel, tgt.as_deref().filter(|t| !t.is_empty())) {
        Ok(p) => p,
        Err(Error::Config(m)) => {
            let first = first.unwrap_or_default();
            return Ok(fail(io, &format!("{first}: {m}"), Some(&first), pairs.first().map(|x| x.1.as_str())));
        }
        Err(e) => return Err(e),
    };
    glue::rebuilt(io, sel, Some(&p))?; // the tree as it stands: the errors of an edit not built yet are from before
    let cell = std::cell::RefCell::new(&mut *io);
    let mut rebuild = || glue::rebuilt(&mut cell.borrow_mut(), sel, Some(&p));
    let (out, errs, status) = crate::rename::rename_command(&p, pairs, &mut rebuild)?;
    let io = cell.into_inner();
    if !out.is_empty() {
        io.say(&out.join("\n"));
    }
    for m in &errs {
        io.warn(m);
    }
    Ok(status)
}

// ------------------------------------------------------------------------------------------------ session

const MINUTES: i64 = 30;

/// The line after `gate: ok`: what bounds the session of this kind.
pub(crate) fn guidance(kind: Option<&str>) -> String {
    let clock = format!("the session clock runs ({MINUTES} minutes): `dcp session status`, and the first line of `dcp layout next`; wrap up once it says over=yes");
    let functions = "a match-base session is counted in functions (the skill's count), not minutes: `dcp next` for the first item";
    match kind {
        Some("layout") => format!("gate: ok. The {clock}."),
        Some("match-base") => format!("gate: ok. This is {functions}."),
        _ => format!("gate: ok. A layout session: {clock}. A match-base session: counted in functions, not minutes (`dcp next`)."),
    }
}

/// No open toolchain or libs obligation; then build, check and link every target: (ok, [(target, project, link ok,
/// undrafted)], {target: state}).
#[allow(clippy::type_complexity)]
fn gate(io: &mut Io, sel: &Sel) -> Result<(bool, Vec<(String, Project, Option<bool>, Option<usize>)>, serde_json::Value)> {
    let p0 = Project::find(sel.root.as_deref(), None)?;
    let (mut ok, mut out, mut states) = (true, vec![], serde_json::Map::new());
    for t in &p0.targets {
        let (p, rep) = build_target(io, sel, Some(&t.name), true, false)?;
        let (lines, good, link_ok, undrafted) = crate::clicmd::gate_target(&p, rep.units, false)?;
        for l in &lines {
            io.say(l);
        }
        ok = ok && good;
        states.insert(t.name.clone(), crate::session::session_state(&p)?);
        out.push((t.name.clone(), p, link_ok, undrafted));
    }
    Ok((ok, out, serde_json::Value::Object(states)))
}

fn session(io: &mut Io, sel: &Sel, sub: SessionCmd) -> Result<i32> {
    let p0 = Project::find(sel.root.as_deref(), None)?;
    let root = p0.root.to_string_lossy().into_owned();
    match sub {
        SessionCmd::Start { kind } => {
            let head = crate::session::session_head(&root);
            if head.is_empty() {
                io.warn("dcp session start: no commit yet: commit the project first (git add -A && git commit)");
                return Ok(1);
            }
            let d = crate::session::session_dirty(&root);
            let checkout = if p0.main_build_dir().is_some() { "worktree" } else { "main" };
            io.say(&rec(&[("session", s("start")), ("checkout", s(checkout)), ("base", s(head.chars().take(8).collect::<String>())),
                          ("clean", Tok::B(d.is_empty()))]));
            for l in d.iter().take(10) {
                io.say(&format!("  dirty {l}"));
            }
            let (ok, targets, states) = gate(io, sel)?;
            if !(ok && d.is_empty()) {
                io.say("gate: FAIL (resolve the obligations above (dcp status), commit or revert the working tree, fix the errors above, then start again)");
                return Ok(1);
            }
            for (_, p, _, _) in &targets {
                for l in crate::session::session_overview(p, &p.analyzer_key()?)? {
                    io.say(&l);
                }
                status_tail(io, p)?;
            }
            crate::session::session_save(&root, &head, &states)?;
            io.say(&guidance(kind.as_deref()));
            Ok(0)
        }
        SessionCmd::Status { minutes } => match crate::session::session_clock(&root, minutes) {
            None => {
                io.warn("dcp session status: no session started (dcp session start)");
                Ok(1)
            }
            Some((line, _)) => {
                io.say(&line);
                Ok(0)
            }
        },
        SessionCmd::Wrap => {
            let (base, started) = crate::session::session_record(&root);
            let base = base.filter(|b| !b.is_empty()).unwrap_or_else(|| crate::session::session_head(&root));
            io.say(&rec(&[("session", s("wrap")), ("base", s(base.chars().take(8).collect::<String>())),
                          ("started", started.map(Tok::S).unwrap_or(Tok::No))]));
            let (mut ok, targets, states) = gate(io, sel)?;
            let (mut promoted, mut refused) = (None, false);
            if ok && p0.main_build_dir().is_none() {
                // the gate passed M1, so promote finds no fall; it still checks
                let mut buf: Vec<u8> = vec![];
                let code = {
                    let mut cap = Io { out: &mut buf, err: &mut *io.err };
                    promote(&mut cap, sel, false)?
                };
                refused = code != 0;
                promoted = Some(String::from_utf8_lossy(&buf).trim().to_string());
                ok = ok && !refused;
            }
            let links: Vec<(String, &Project, Option<bool>, Option<usize>)> = targets.iter().map(|(n, p, l, u)| (n.clone(), p, *l, *u)).collect();
            let report = crate::session::session_report(&root, &base, links, &states, promoted, refused, ok)?;
            let _ = write!(io.out, "{report}");
            Ok(if ok { 0 } else { 1 })
        }
    }
}

// ------------------------------------------------------------------------------------------------ run / worktrees

fn run(io: &mut Io, sel: &Sel, a: RunArgs) -> Result<i32> {
    let p = open(sel, None)?;
    let Some(name) = a.name.clone().filter(|_| !a.list) else {
        let l = crate::run::run_list(&p)?;
        return Ok(io.report("run", &l, None, 0));
    };
    let Some(target) = crate::run::run_target(&p, &name)? else {
        let (l, e, _) = crate::run::run_prepare(&p, &name, false, None, vec![], None, None, String::new())?;
        return Ok(io.report("run", &l, e.as_deref(), 2));
    };
    let p = if a.no_build { open(sel, Some(&target))? } else { build_target(io, sel, Some(&target), true, false)?.0 };
    let debug = if a.debug { Some(true) } else if a.no_debug { Some(false) } else { None };
    let (lines, error, spec) = crate::run::run_prepare(&p, &name, a.no_build, a.seconds, a.extra.clone(), debug, a.dump.clone(), crate::cs::library(""))?;
    io.report("run", &lines, error.as_deref(), 0);
    let Some(spec) = spec.filter(|_| error.is_none()) else { return Ok(1) };
    if a.prepare_only || crate::launch::handoff(&spec) {
        io.say(&format!("spec={spec}"));
        return Ok(0);
    }
    Ok(crate::launch::launch(io, &spec))
}

/// `dcp wt new|list|drop`, `dcp seed` (wt.rs); its error exits 2.
fn wt(io: &mut Io, sel: &Sel, cmd: &str, arg: Option<String>, force: bool) -> Result<i32> {
    let p = glue::config(sel, None)?;
    let (lines, error) = crate::wt::wt_command(&p.root.to_string_lossy(), cmd, arg, force);
    if let Some(e) = error {
        io.warn(&format!("dcp: {e}"));
        return Ok(2);
    }
    Ok(io.report(cmd, &lines, None, 0))
}
