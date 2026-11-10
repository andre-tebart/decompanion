//! launch.rs: a launch spec's steps, program and `after` steps (cmd.exe is the program), the hand-off from the daemon,
//! and run's options never becoming program arguments.

use super::*;
use crate::cli::Io;
use clap::Parser;
use serde_json::json;

fn spec(dir: &Path, kw: serde_json::Value) -> String {
    let cmd = std::env::var("ComSpec").unwrap_or_else(|_| "C:\\Windows\\System32\\cmd.exe".into());
    let mut s = json!({"run": "play", "root": dir.to_string_lossy(), "dir": dir.to_string_lossy(), "exe": cmd, "args": [], "env": {},
                       "seconds": 0, "steps": [], "after": [], "hook_env": {"DCP_RUN_DIR": dir.to_string_lossy(), "DCP_EXE": cmd}});
    for (k, v) in kw.as_object().unwrap() {
        s[k] = v.clone();
    }
    let p = dir.join("spec.json");
    std::fs::write(&p, s.to_string()).unwrap();
    p.to_string_lossy().into_owned()
}

fn launch(spec: &str) -> (i32, String) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let rc = crate::launch::launch(&mut Io { out: &mut out, err: &mut err }, spec);
    (rc, String::from_utf8_lossy(&out).into_owned())
}

#[test]
#[ignore = "e2e: starts processes"]
fn steps_program_and_after() {
    let d = tmp("launch");
    let log = d.join("log").to_string_lossy().into_owned();
    let step = json!(["cmd", "/c", format!("echo step %DCP_RUN_DIR%>>{log}")]);
    let prog = json!(["/c", format!("echo prog %START% x>>{log}& exit 3")]);
    let after = json!(["cmd", "/c", format!("echo after %DCP_EXIT% >>{log}")]);
    let (rc, out) = launch(&spec(&d, json!({"steps": [step], "args": prog, "env": {"START": "new"}, "after": [after]})));
    assert_eq!(rc, 3, "{out}");
    let got: Vec<String> = std::fs::read_to_string(&log).unwrap().lines().map(|l| l.trim_end().to_string()).collect();
    assert_eq!(got, [format!("step {}", d.to_string_lossy()), "prog new x".to_string(), "after 3".to_string()]);
}

#[test]
#[ignore = "e2e: starts processes"]
fn failing_step_stops_the_run() {
    let d = tmp("launch");
    let log = d.join("log");
    let prog = json!(["/c", format!("echo started>{}", log.to_string_lossy())]);
    let (rc, _) = launch(&spec(&d, json!({"steps": [["cmd", "/c", "exit 5"]], "args": prog})));
    assert_eq!(rc, 5);
    assert!(!log.exists());
}

#[test]
#[ignore = "e2e: starts processes"]
fn time_limit_terminates() {
    let d = tmp("launch");
    let (rc, out) = launch(&spec(&d, json!({"args": ["/c", "ping -n 30 127.0.0.1 >nul"], "seconds": 0.3})));
    assert_eq!(rc, 0, "{out}");
    assert!(out.contains("stopped=time"), "{out}");
}

#[test]
fn handoff() {
    assert!(!crate::launch::handoff("x.json")); // not in a daemon request
    crate::launch::handoff_slot(true);
    assert!(crate::launch::handoff("x.json"));
    assert_eq!(crate::launch::handoff_slot(false).as_deref(), Some("x.json"));
    assert!(!crate::launch::handoff("y.json"));
}

#[test]
fn run_options_are_never_program_arguments() {
    use crate::cli::args::{Cli, Cmd};
    let Cmd::Run(a) = Cli::parse_from(["dcp", "run", "play", "--prepare-only", "--seconds", "5"]).cmd else { panic!() };
    assert!(a.name.as_deref() == Some("play") && a.prepare_only && a.seconds == Some(5.0) && a.extra.is_empty());
    let Cmd::Run(a) = Cli::parse_from(["dcp", "run", "play", "--no-build", "--", "-x", "--prepare-only"]).cmd else { panic!() };
    assert!(a.no_build && !a.prepare_only && a.extra == ["-x", "--prepare-only"]);
}

#[test]
fn list2cmdline() {
    let l = |a: &[&str]| crate::launch::list2cmdline(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    assert_eq!(l(&["a", "b c", ""]), r#"a "b c" """#);
    assert_eq!(l(&[r#"x"y"#, r"a\b\", r"c d\"]), r#"x\"y a\b\ "c d\\""#);
}
