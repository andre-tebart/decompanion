//! dcp-bench: the speed of the match loop on a target project: edit -> build -> diffclass / asmdiff -> grade, timed
//! per command.
//!
//!     dcp-bench --root ../gildegold --fn 0x5dcf00 --swap "ai_ShotHitHeight + height::height + ai_ShotHitHeight" \
//!         --rename ai_ShotHitsGround [--runs 3] [--scenarios S0,S1,...] [--dcp PATH] [--verify] [--budget MS] [--label NAME]
//!
//! Every command runs as its own process (`dcp` beside this executable, or --dcp), with DCP_TIMING=1, in the
//! project's daemon (started on demand). Scenarios, each applied inside the function's span of its unit file
//! src/<unit>.c (found with `dcp fn`) and reverted (the tree is left as it was found; a dirty tree is refused):
//!
//!   S0  nothing changed (the floor of every command)
//!   S1  a body edit that changes the object (--swap OLD::NEW, a text replaced in the function's span)
//!   S2  a comment-only edit in the function's address comment
//!   S3  a blank line before the function's address comment (only line numbers move)
//!   S4  a comment line appended to the unit's first project header (--header, default include/<unit>.h)
//!   S5  `dcp rename` of the first --rename name to a new name and back
//!   S6  `dcp rename` of every --rename name (comma-separated) in a row, and back
//!   S7  one `dcp rename` of every --rename name (all pairs in one call), and back
//!
//! After each scenario's edit: build, diffclass FN, asmdiff FN, grade FN, next, dump FN 4, why FN, draft FN --show,
//! -h; after the revert: build. The table (median / min / max wall seconds per scenario and command) goes to stdout,
//! the raw runs to <root>/build/bench/<date>-<rev>-<label>.json.
//!
//! --verify (--verify-build: also `dcp build --force`): after each scenario's revert, the store is checked against a
//! forced recompute: the current runs' (rule, out_hash) and the tu rows are read, `dcp --no-daemon setup --force
//! --no-analyzer` reruns every rule with every shortcut off (DCP_NO_SHORTCUTS=1) in a fresh process, and the two
//! must be equal. --budget MS: S0's commands other than build must take at most MS milliseconds (median, end to
//! end); the run fails otherwise.

use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

struct Args {
    root: PathBuf,
    func: String,
    swap: Option<String>,
    rename: Option<String>,
    header: Option<String>,
    runs: usize,
    scenarios: Vec<String>,
    dcp: PathBuf,
    verify: bool,
    verify_build: bool,
    budget: Option<f64>,
    label: String,
    verbose: bool,
}

fn usage(msg: &str) -> ! {
    eprintln!("dcp-bench: {msg}\nusage: dcp-bench --root DIR --fn ADDR [--swap OLD::NEW] [--rename N[,N..]] [--header H] [--runs N] \
               [--scenarios S0,..] [--dcp PATH] [--verify | --verify-build] [--budget MS] [--label L] [-v]");
    std::process::exit(2)
}

fn parse() -> Args {
    let mut a = Args { root: PathBuf::new(), func: String::new(), swap: None, rename: None, header: None, runs: 3,
                       scenarios: "S0,S1,S2,S3,S4,S5,S6,S7".split(',').map(String::from).collect(), dcp: PathBuf::new(), verify: false,
                       verify_build: false, budget: None, label: String::new(), verbose: false };
    let me = std::env::current_exe().unwrap_or_default();
    a.dcp = me.with_file_name(if cfg!(windows) { "dcp.exe" } else { "dcp" });
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    let mut val = |i: &mut usize| -> String {
        *i += 1;
        argv.get(*i).cloned().unwrap_or_else(|| usage(&format!("{} needs a value", argv[*i - 1])))
    };
    let mut root = None;
    while i < argv.len() {
        match argv[i].as_str() {
            "--root" => root = Some(val(&mut i)),
            "--fn" => a.func = val(&mut i),
            "--swap" => a.swap = Some(val(&mut i)),
            "--rename" => a.rename = Some(val(&mut i)),
            "--header" => a.header = Some(val(&mut i)),
            "--runs" => a.runs = val(&mut i).parse().unwrap_or_else(|_| usage("--runs N")),
            "--scenarios" => a.scenarios = val(&mut i).split(',').map(String::from).collect(),
            "--dcp" => a.dcp = PathBuf::from(val(&mut i)),
            "--verify" => a.verify = true,
            "--verify-build" => a.verify_build = true,
            "--budget" => a.budget = Some(val(&mut i).parse().unwrap_or_else(|_| usage("--budget MS"))),
            "--label" => a.label = val(&mut i),
            "-v" | "--verbose" => a.verbose = true,
            "-h" | "--help" => usage("the speed of the match loop"),
            x => usage(&format!("unknown argument {x}")),
        }
        i += 1;
    }
    let root = root.unwrap_or_else(|| usage("--root is required"));
    if a.func.is_empty() {
        usage("--fn is required");
    }
    a.root = std::fs::canonicalize(&root).unwrap_or_else(|_| PathBuf::from(&root));
    a.root = PathBuf::from(a.root.to_string_lossy().trim_start_matches(r"\\?\"));
    a
}

fn git(root: &Path, args: &[&str]) -> String {
    let o = Command::new("git").args(args).current_dir(root).output().expect("git");
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

struct Bench {
    a: Args,
    runs: Vec<Value>,
    facts: BTreeMap<String, BTreeSet<String>>,
}

impl Bench {
    fn dcp(&mut self, scenario: &str, step: &str, argv: &[&str], env: &[(&str, &str)], record: bool, fresh: bool) -> (i32, String) {
        let mut c = Command::new(&self.a.dcp);
        if fresh {
            c.arg("--no-daemon");
        }
        c.args(argv).current_dir(&self.a.root).env("DCP_TIMING", std::env::var("DCP_TIMING").unwrap_or_else(|_| "1".into()));
        for (k, v) in env {
            c.env(k, v);
        }
        let t = Instant::now();
        let o = c.output().expect("dcp");
        let wall = t.elapsed().as_secs_f64();
        let rc = o.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&o.stderr).into_owned();
        let lines: Vec<&str> = stderr.lines().filter(|l| l.starts_with("rules:") || l.starts_with("timing:")).collect();
        let mut row = json!({"scenario": scenario, "step": step, "argv": argv, "wall": (wall * 1000.0).round() / 1000.0, "rc": rc, "lines": lines});
        if rc != 0 && rc != 1 {
            row["stderr"] = json!(stderr.chars().rev().take(2000).collect::<String>().chars().rev().collect::<String>());
            eprintln!("  ! {step}: exit {rc}\n{}", &stderr[stderr.len().saturating_sub(800)..]);
        }
        if self.a.verbose {
            println!("  {scenario} {step:<10} {wall:6.3}s rc={rc} {}", lines.join(" | "));
        }
        if record {
            self.runs.push(row);
        }
        (rc, String::from_utf8_lossy(&o.stdout).into_owned())
    }

    fn step(&mut self, scenario: &str, step: &str, argv: &[&str]) {
        self.dcp(scenario, step, argv, &[], true, false);
    }

    fn lp(&mut self, s: &str) {
        let f = self.a.func.clone();
        self.step(s, "build", &["build"]);
        self.step(s, "diffclass", &["diffclass", &f]);
        self.step(s, "asmdiff", &["asmdiff", &f]);
        self.step(s, "grade", &["grade", &f]);
        self.step(s, "next", &["next"]);
        self.step(s, "dump", &["dump", &f, "4"]);
        self.step(s, "why", &["why", &f]);
        self.step(s, "draft", &["draft", &f, "--show"]);
        self.step(s, "-h", &["-h"]);
    }

    /// The function's unit file and its span (first, last line, 1-based): `dcp fn`'s record `at=FILE:A-B`.
    fn span(&mut self) -> (PathBuf, usize, usize) {
        let f = self.a.func.clone();
        let (rc, out) = self.dcp("span", "fn", &["fn", &f], &[], false, false);
        let re = regex::Regex::new(r"\bat=(\S+):(\d+)-(\d+)").unwrap();
        match re.captures(out.lines().next().unwrap_or("")) {
            Some(m) if rc == 0 => (self.a.root.join(&m[1]), m[2].parse().unwrap(), m[3].parse().unwrap()),
            _ => usage(&format!("`dcp fn {f}` found no function")),
        }
    }

    fn scenario(&mut self, name: &str) {
        if name == "S0" {
            self.lp(name);
            return;
        }
        if ["S5", "S6", "S7"].contains(&name) {
            let mut names: Vec<String> = self.a.rename.clone().unwrap_or_default().split(',').filter(|x| !x.is_empty()).map(String::from).collect();
            if names.is_empty() {
                eprintln!("bench: {name} needs --rename NAME[,NAME...]; skipped");
                return;
            }
            if name == "S5" {
                names.truncate(1);
            }
            let log = self.a.root.join("names.log"); // append-only: the bench lines are taken out again
            let saved = std::fs::read(&log).ok();
            let there: Vec<String> = names.iter().flat_map(|o| [o.clone(), format!("{o}Bench")]).collect();
            let back: Vec<String> = names.iter().flat_map(|o| [format!("{o}Bench"), o.clone()]).collect();
            let with_why = |v: &[String]| -> Vec<String> { ["rename".to_string()].into_iter().chain(v.iter().cloned()).chain(["--why".into(), "bench".into()]).collect() };
            if name == "S7" {
                let a = with_why(&there);
                self.step(name, "rename", &a.iter().map(|s| s.as_str()).collect::<Vec<_>>());
            } else {
                for o in &names {
                    let a = with_why(&[o.clone(), format!("{o}Bench")]);
                    self.step(name, "rename", &a.iter().map(|s| s.as_str()).collect::<Vec<_>>());
                }
            }
            self.lp(name);
            let b = with_why(&back);
            self.dcp(name, "rename", &b.iter().map(|s| s.as_str()).collect::<Vec<_>>(), &[], false, false);
            if let Some(s) = saved {
                let _ = std::fs::write(&log, s);
            }
            self.step(name, "revert-build", &["build"]);
            return;
        }
        let (unit, a, b) = self.span();
        let in_span = |text: &str, a: usize, b: usize, f: &dyn Fn(&str) -> String| -> String {
            let lines: Vec<&str> = text.split('\n').collect();
            let mid = f(&lines[a - 1..b].join("\n"));
            let mut parts: Vec<&str> = lines[..a - 1].to_vec();
            parts.extend(mid.split('\n'));
            parts.extend(&lines[b..]);
            parts.join("\n")
        };
        let (path, new): (PathBuf, Box<dyn Fn(&str) -> String>) = match name {
            "S1" => {
                let Some((o, n)) = self.a.swap.clone().and_then(|s| s.split_once("::").map(|(o, n)| (o.to_string(), n.to_string()))) else {
                    eprintln!("bench: S1 needs --swap OLD::NEW; skipped");
                    return;
                };
                (unit.clone(), Box::new(move |t: &str| in_span(t, a, b, &|s: &str| s.replacen(&o, &n, 1))))
            }
            "S2" => (unit.clone(), Box::new(move |t: &str| in_span(t, a, a, &|s: &str| s.replacen("*/", " (bench) */", 1)))),
            "S3" => (unit.clone(), Box::new(move |t: &str| in_span(t, a, a, &|s: &str| format!("\n{s}")))),
            "S4" => {
                let h = match &self.a.header {
                    Some(h) => self.a.root.join(h),
                    None => self.a.root.join("include").join(format!("{}.h", unit.file_stem().unwrap().to_string_lossy())),
                };
                if !h.exists() {
                    usage(&format!("no {}; name one with --header", h.display()));
                }
                (h, Box::new(|t: &str| format!("{t}/* bench */\n")))
            }
            x => usage(&format!("unknown scenario {x}")),
        };
        let orig = std::fs::read_to_string(&path).unwrap();
        let changed = new(&orig);
        if changed == orig {
            usage(&format!("the edit of {} changed nothing", path.display()));
        }
        std::fs::write(&path, changed).unwrap();
        self.lp(name);
        std::fs::write(&path, orig).unwrap();
        self.step(name, "revert-build", &["build"]);
    }

    fn state(&mut self, target: &str) -> (BTreeMap<String, String>, Vec<Vec<String>>) {
        let db = rusqlite::Connection::open_with_flags(self.a.root.join("build").join(format!("{target}.sqlite")), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let runs: BTreeMap<String, String> = db.prepare("SELECT rule, out_hash FROM run WHERE current=1").unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().flatten().collect();
        let tus: Vec<Vec<String>> = db.prepare("SELECT unit, src_hash, flags_hash, include_hash, obj_hash, ok FROM tu ORDER BY unit").unwrap()
            .query_map([], |r| Ok((0..6).map(|i| r.get::<_, rusqlite::types::Value>(i).map(|v| format!("{v:?}")).unwrap_or_default()).collect())).unwrap().flatten().collect();
        self.facts.clear();
        let mut st = db.prepare("SELECT r.rule, f.lo, f.hi, f.kind, f.value, f.level, f.by FROM fact f JOIN run r ON r.id=f.run_id \
                                 WHERE r.current=1 AND r.rule NOT IN ('L.src', 'L.decl')").unwrap();
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, format!("{:?}", (r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?, r.get::<_, i64>(5)?, r.get::<_, String>(6)?))))).unwrap();
        for (rule, f) in rows.flatten() {
            self.facts.entry(rule).or_default().insert(f);
        }
        (runs, tus)
    }

    fn target(&self) -> String {
        let cfg = std::fs::read_to_string(self.a.root.join("decompanion.toml")).unwrap_or_default();
        regex::Regex::new(r#"(?m)^name\s*=\s*"([^"]+)""#).unwrap().captures(&cfg).map(|c| c[1].to_string()).unwrap_or_else(|| "exe".into())
    }

    fn verify(&mut self, scenario: &str) -> bool {
        let t = self.target();
        let mut before = self.state(&t);
        let facts_before = self.facts.clone();
        let env = [("DCP_NO_SHORTCUTS", "1")];
        if self.a.verify_build {
            self.dcp(scenario, "verify", &["build", "--force"], &env, false, true);
        }
        self.dcp(scenario, "verify", &["setup", "--force", "--no-analyzer"], &env, false, true);
        let mut after = self.state(&t);
        let keys: BTreeSet<&String> = before.0.keys().chain(after.0.keys()).collect();
        let mut bad: Vec<String> = keys.into_iter().filter(|r| before.0.get(*r) != after.0.get(*r)).cloned().collect();
        if self.a.verify_build {
            // CL stamps every object with the time of the compile: a recompile gives another object hash
            bad.retain(|r| r != "M.compile");
            for x in [&mut before.1, &mut after.1] {
                for row in x.iter_mut() {
                    row.remove(4);
                }
            }
        }
        let ok = bad.is_empty() && before.1 == after.1;
        for r in &bad {
            let (a, b) = (facts_before.get(r).cloned().unwrap_or_default(), self.facts.get(r).cloned().unwrap_or_default());
            for x in a.difference(&b).take(3) {
                println!("  {r} incremental only: {}", &x[..x.len().min(300)]);
            }
            for x in b.difference(&a).take(3) {
                println!("  {r} recomputed only:  {}", &x[..x.len().min(300)]);
            }
        }
        println!("verify {scenario}: {}{}{}", if ok { "ok" } else { "FAIL" }, if bad.is_empty() { String::new() } else { format!("  rules differ: {}", bad.join(", ")) },
                 if before.1 == after.1 { "" } else { "  tu rows differ" });
        ok
    }

    fn report(&self) -> bool {
        let mut groups: Vec<((String, String), Vec<f64>)> = vec![];
        for r in &self.runs {
            let k = (r["scenario"].as_str().unwrap().to_string(), r["step"].as_str().unwrap().to_string());
            match groups.iter_mut().find(|g| g.0 == k) {
                Some(g) => g.1.push(r["wall"].as_f64().unwrap()),
                None => groups.push((k, vec![r["wall"].as_f64().unwrap()])),
            }
        }
        println!("| scenario | step | n | median s | min | max |\n|---|---|---|---|---|---|");
        let mut over = vec![];
        for ((s, st), ws) in &mut groups {
            ws.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let med = if ws.len() % 2 == 1 { ws[ws.len() / 2] } else { (ws[ws.len() / 2 - 1] + ws[ws.len() / 2]) / 2.0 };
            println!("| {s} | {st} | {} | {med:.3} | {:.3} | {:.3} |", ws.len(), ws[0], ws[ws.len() - 1]);
            if let Some(b) = self.a.budget {
                if s == "S0" && st != "build" && med * 1000.0 > b {
                    over.push(format!("{st} {:.0} ms", med * 1000.0));
                }
            }
        }
        let checkout = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let rev = git(&checkout, &["rev-parse", "--short", "HEAD"]);
        let out = self.a.root.join("build").join("bench");
        let _ = std::fs::create_dir_all(&out);
        let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
        let label = if self.a.label.is_empty() { "exe".to_string() } else { self.a.label.clone() };
        let path = out.join(format!("{stamp}-{rev}-{label}.json"));
        let _ = std::fs::write(&path, serde_json::to_string_pretty(&json!({"fn": self.a.func, "dcp": self.a.dcp.to_string_lossy(), "runs": self.runs})).unwrap());
        eprintln!("raw: {}", path.display());
        if !over.is_empty() {
            println!("budget: FAIL ({} ms): {}", self.a.budget.unwrap(), over.join(", "));
            return false;
        }
        if let Some(b) = self.a.budget {
            println!("budget: ok ({b} ms)");
        }
        true
    }
}

fn main() {
    let a = parse();
    if !git(&a.root, &["status", "--porcelain", "--untracked-files=no"]).is_empty() {
        eprintln!("bench: {} has uncommitted changes; commit or stash them first", a.root.display());
        std::process::exit(2);
    }
    let mut b = Bench { a, runs: vec![], facts: BTreeMap::new() };
    b.dcp("warm", "build", &["build"], &[], false, false); // every scenario starts from a current store
    let mut ok = true;
    for i in 0..b.a.runs {
        for s in b.a.scenarios.clone() {
            eprintln!("run {}/{} {s}", i + 1, b.a.runs);
            b.scenario(&s);
            if b.a.verify || b.a.verify_build {
                ok = b.verify(&s) && ok;
            }
        }
    }
    if !git(&b.a.root, &["status", "--porcelain", "--untracked-files=no"]).is_empty() {
        eprintln!("bench: WARNING: the tree is not clean after the run");
    }
    ok = b.report() && ok;
    std::process::exit(if ok { 0 } else { 1 });
}
