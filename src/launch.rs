//! Launching a staged run: the steps of the setup, the program, the `after` steps.
//!
//! The core builds and stages and writes the launch spec build/run/<run>.json (run.rs); this module runs it in the
//! process the user typed `dcp` in (the daemon has no window to start a program in: it hands the spec to the client,
//! `handoff`). Ctrl+C stops the program (a plain one is terminated, a debugged one through debugger::INTERRUPTED).

use crate::cli::Io;
use serde_json::Value;
use std::collections::BTreeMap;
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

/// Inside a daemon request: the spec `dcp run` hands to the client (None: not in the daemon, the run launches here).
static HANDOFF: Mutex<Option<Option<String>>> = Mutex::new(None);

/// The daemon's side: start (Some) or end (None, taking the spec handed off) a request.
pub fn handoff_slot(on: bool) -> Option<String> {
    let mut h = HANDOFF.lock().unwrap();
    if on {
        *h = Some(None);
        None
    } else {
        h.take().flatten()
    }
}

/// In the daemon: hand the spec to the client that asked (true), instead of launching here.
pub fn handoff(spec: &str) -> bool {
    let mut h = HANDOFF.lock().unwrap();
    match h.as_mut() {
        Some(slot) => {
            *slot = Some(spec.to_string());
            true
        }
        None => false,
    }
}

/// subprocess.list2cmdline: the Windows command line of an argument list (MS C runtime quoting).
pub fn list2cmdline(args: &[String]) -> String {
    let mut out = String::new();
    for arg in args {
        if !out.is_empty() {
            out.push(' ');
        }
        let quote = arg.contains(' ') || arg.contains('\t') || arg.is_empty();
        if quote {
            out.push('"');
        }
        let mut bs = 0usize;
        for c in arg.chars() {
            match c {
                '\\' => bs += 1,
                '"' => {
                    out.push_str(&"\\".repeat(bs * 2));
                    bs = 0;
                    out.push_str("\\\"");
                }
                _ => {
                    out.push_str(&"\\".repeat(bs));
                    bs = 0;
                    out.push(c);
                }
            }
        }
        out.push_str(&"\\".repeat(bs));
        if quote {
            out.push_str(&"\\".repeat(bs));
            out.push('"');
        }
    }
    out
}

#[cfg(windows)]
mod ctrlc {
    use std::sync::Once;
    type Handler = unsafe extern "system" fn(u32) -> i32;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetConsoleCtrlHandler(handler: Option<Handler>, add: i32) -> i32;
    }
    unsafe extern "system" fn on_ctrl(kind: u32) -> i32 {
        if kind == 0 || kind == 1 {
            // CTRL_C_EVENT, CTRL_BREAK_EVENT: the run stops its program, dcp itself goes on to report
            crate::debugger::INTERRUPTED.store(true, std::sync::atomic::Ordering::Relaxed);
            return 1;
        }
        0
    }
    pub fn install() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| unsafe {
            SetConsoleCtrlHandler(Some(on_ctrl), 1);
        });
    }
}

#[cfg(not(windows))]
mod ctrlc {
    pub fn install() {}
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().map(|x| x.as_str().map(|s| s.to_string()).unwrap_or_else(|| x.to_string())).collect()).unwrap_or_default()
}

fn env_of(spec: &Value, extra: &[(&str, String)]) -> BTreeMap<String, String> {
    let mut env: BTreeMap<String, String> = std::env::vars().collect();
    if let Some(h) = spec["hook_env"].as_object() {
        for (k, v) in h {
            env.insert(k.clone(), v.as_str().map(|s| s.to_string()).unwrap_or_else(|| v.to_string()));
        }
    }
    for (k, v) in extra {
        env.insert(k.to_string(), v.clone());
    }
    env
}

fn step(io: &mut Io, cmd: &[String], spec: &Value, env: &BTreeMap<String, String>, what: &str) -> i32 {
    io.say(&format!("run {what}: {}", list2cmdline(cmd)));
    let _ = io.out.flush();
    let Some(prog) = cmd.first() else { return 127 };
    match Command::new(prog).args(&cmd[1..]).current_dir(spec["root"].as_str().unwrap_or(".")).env_clear().envs(env).status() {
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => {
            io.warn(&format!("dcp run: {what} {prog}: {e}"));
            127
        }
    }
}

/// The path of `p` relative to `root` (os.path.relpath of a path inside root; else p as it is).
fn relpath(p: &str, root: &str) -> String {
    let (pn, rn) = (p.replace('/', "\\"), root.replace('/', "\\").trim_end_matches('\\').to_string());
    if pn.to_lowercase().starts_with(&(rn.to_lowercase() + "\\")) { pn[rn.len() + 1..].to_string() } else { pn }
}

/// Run a launch spec: each step (a failing one stops the run), the program in the run directory (terminated after
/// `seconds` when > 0, or on Ctrl+C), then each `after` step with DCP_EXIT. The exit code.
pub fn launch(io: &mut Io, spec_path: &str) -> i32 {
    let spec: Value = match std::fs::read_to_string(spec_path).map_err(|e| e.to_string()).and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string())) {
        Ok(v) => v,
        Err(e) => {
            io.warn(&format!("dcp run: {spec_path}: {e}"));
            return 1;
        }
    };
    ctrlc::install();
    crate::debugger::INTERRUPTED.store(false, Ordering::Relaxed);
    let env = env_of(&spec, &[]);
    for (i, cmd) in spec["steps"].as_array().cloned().unwrap_or_default().iter().enumerate() {
        let rc = step(io, &strs(cmd), &spec, &env, &format!("step {}", i + 1));
        if rc != 0 {
            io.warn(&format!("dcp run: step {} exited with {rc}: the program is not started", i + 1));
            return rc;
        }
    }
    let mut run_env = env.clone();
    if let Some(e) = spec["env"].as_object() {
        for (k, v) in e {
            run_env.insert(k.clone(), v.as_str().map(|s| s.to_string()).unwrap_or_else(|| v.to_string()));
        }
    }
    let run = spec["run"].as_str().unwrap_or("").to_string();
    let exe = spec["exe"].as_str().unwrap_or("").to_string();
    let dir = spec["dir"].as_str().unwrap_or(".").to_string();
    let root = spec["root"].as_str().unwrap_or("").to_string();
    let mut argv = vec![exe.clone()];
    argv.extend(strs(&spec["args"]));
    let seconds = spec["seconds"].as_f64().unwrap_or(0.0);
    let debug = spec["debug"].as_bool().unwrap_or(false);
    let t0 = Instant::now();
    io.say(&format!("run {run}: {}  (in {dir}{})", list2cmdline(&argv), if debug { ", under the debugger" } else { "" }));
    let _ = io.out.flush();
    let (code, stopped, crash): (Option<i64>, String, Option<String>) = if debug {
        let mut env = run_env.clone();
        env.entry("_NO_DEBUG_HEAP".into()).or_insert_with(|| "1".into());
        let st = |k: &str| spec[k].as_str().unwrap_or("").to_string();
        let dump = spec["dump"].as_str().filter(|d| !d.is_empty()).unwrap_or("full").to_string();
        match crate::debugger::debug_launch(&run, &exe, &list2cmdline(&argv), &dir, env.into_iter().collect(), seconds, &st("symbols"),
                                            &st("crash_root"), &dump, spec_path) {
            Ok((c, s, cr)) => (c.map(|c| c as i64), s, cr),
            Err(e) => {
                io.warn(&format!("dcp run: {e}"));
                return 127;
            }
        }
    } else {
        match plain(&exe, &argv[1..], &dir, &run_env, seconds) {
            Ok((c, s)) => (c, s, None),
            Err(e) => {
                io.warn(&format!("dcp run: {exe}: {e}"));
                return 127;
            }
        }
    };
    let ms = t0.elapsed().as_millis();
    if let Some(c) = &crash {
        io.say(&format!("run {run}: crashed; report {}", std::path::Path::new(c).join("crash.txt").to_string_lossy()));
    }
    let code_s = code.map(|c| c.to_string()).unwrap_or_else(|| "none".into());
    let after_env = env_of(&spec, &[("DCP_EXIT", code_s.clone()), ("DCP_CRASH", crash.clone().unwrap_or_default())]);
    for (i, cmd) in spec["after"].as_array().cloned().unwrap_or_default().iter().enumerate() {
        let rc = step(io, &strs(cmd), &spec, &after_env, &format!("after {}", i + 1));
        if rc != 0 {
            io.warn(&format!("dcp run: after {} exited with {rc}", i + 1));
        }
    }
    let mut line = format!("run={run}  exit={code_s}  ms={ms}");
    if !stopped.is_empty() {
        line.push_str(&format!("  stopped={stopped}"));
    }
    if let Some(c) = &crash {
        line.push_str(&format!("  crash={}", relpath(c, &root)));
    }
    io.say(&line);
    if crash.is_some() {
        return 1;
    }
    if stopped == "time" {
        return 0;
    }
    code.map(|c| c as i32).unwrap_or(1)
}

/// The program as a plain child process: (exit code, stopped: '' | time | interrupt).
fn plain(exe: &str, args: &[String], dir: &str, env: &BTreeMap<String, String>, seconds: f64) -> std::io::Result<(Option<i64>, String)> {
    let mut child = Command::new(exe).args(args).current_dir(dir).env_clear().envs(env).spawn()?;
    let deadline = (seconds > 0.0).then(|| Instant::now() + Duration::from_secs_f64(seconds));
    let mut stopped = String::new();
    loop {
        if let Some(s) = child.try_wait()? {
            return Ok((s.code().map(|c| c as u32 as i64), stopped));
        }
        if crate::debugger::INTERRUPTED.load(Ordering::Relaxed) {
            stopped = "interrupt".into();
        } else if deadline.is_some_and(|d| Instant::now() >= d) {
            stopped = "time".into();
        }
        if !stopped.is_empty() {
            let _ = child.kill();
            let s = child.wait()?;
            return Ok((s.code().map(|c| c as u32 as i64), stopped));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
