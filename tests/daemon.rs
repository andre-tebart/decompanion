//! The dcp binary end to end: a command through the project's daemon (started on demand) answers as the same command
//! in one process; `dcp serve` starts, refuses a second daemon, reports and stops (tests/test_speed.py). Starts
//! processes: `cargo test --test daemon -- --ignored`.

use std::path::{Path, PathBuf};
use std::process::Command;

fn dcp(root: &Path, args: &[&str]) -> (i32, String, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_dcp")).arg("--root").arg(root).args(args).output().unwrap();
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

fn project(name: &str) -> PathBuf {
    dcp::testkit::make_project(&dcp::testkit::scratch(&format!("daemon-{name}")).join("proj"), false)
}

fn stop(root: &Path) {
    let _ = dcp(root, &["serve", "--stop"]);
}

#[test]
#[ignore = "e2e: starts the daemon"]
fn daemon_answers_like_the_process() {
    let root = project("answers");
    let (code, out, err) = dcp(&root, &["--no-daemon", "setup", "--no-analyzer"]);
    assert_eq!(code, 0, "{out}{err}");
    for args in [&["why", "0x10001020"][..], &["facts", "0x10001000..0x10001060"], &["map"], &["nosuchcommand"]] {
        let a = dcp(&root, args); // the first one starts the daemon
        let mut local = vec!["--no-daemon"];
        local.extend(args);
        let b = dcp(&root, &local);
        assert_eq!((a.0, &a.1), (b.0, &b.1), "{args:?}: {}", a.2);
    }
    let (code, out, _) = dcp(&root, &["serve", "--status"]);
    assert!(code == 0 && out.contains("requests=4"), "{out}");
    let info = root.join("build").join("dcp-daemon.json");
    assert!(info.exists());
    let (code, out, _) = dcp(&root, &["serve", "--stop"]);
    assert!(code == 0 && out.contains("stopped"), "{out}");
    assert!(!info.exists());
}

#[test]
#[ignore = "e2e: starts the daemon"]
fn serve_starts_refuses_reports_stops() {
    let root = project("serve");
    assert_eq!(dcp(&root, &["--no-daemon", "setup", "--no-analyzer"]).0, 0);
    let info = root.join("build").join("dcp-daemon.json");
    let (code, out, err) = dcp(&root, &["serve"]);
    assert!(code == 0 && out.contains("started"), "{out}{err}");
    assert!(info.exists());
    let (_, out, _) = dcp(&root, &["serve", "--status"]);
    assert!(out.contains("pid=") && out.contains("build="), "{out}");
    assert_eq!(dcp(&root, &["serve"]).0, 1); // one daemon per root
    stop(&root);
    assert!(!info.exists());
    let (code, out, _) = dcp(&root, &["serve", "--status"]);
    assert!(code == 1 && out.contains("no daemon runs"), "{out}");
}

#[test]
#[ignore = "e2e: starts the daemon"]
fn concurrent_clients_are_served_in_turn() {
    let root = project("turns");
    assert_eq!(dcp(&root, &["--no-daemon", "setup", "--no-analyzer"]).0, 0);
    let want = dcp(&root, &["--no-daemon", "why", "0x10001020"]).1;
    let handles: Vec<_> = (0..6).map(|_| {
        let r = root.clone();
        std::thread::spawn(move || dcp(&r, &["why", "0x10001020"]))
    }).collect();
    for h in handles {
        let (code, out, err) = h.join().unwrap();
        assert!(code == 0 && out == want, "{out}{err}");
    }
    stop(&root);
}
