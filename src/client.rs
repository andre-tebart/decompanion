//! Th    c.spawn().map_err(|e| format!("{}: {e}", copy.display())) `dcp` command: a command of a project runs in the project's daemon (daemon.rs), which keeps what a command
//! would otherwise read again (the image, the scans, the store, the objects). The client finds the project, sends
//! the command line, its working directory and environment, and prints what comes back; it starts the daemon when
//! none answers, and again when the daemon is of another build (the code changed). `dcp init`, `dcp serve`,
//! `dcp self`, `--no-daemon` and a command line outside any project run in this process.

use crate::cli::Io;
use crate::ipc;
use serde_json::{json, Value};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const CONFIG_NAME: &str = "decompanion.toml";
/// The build id (build.rs): the client and the daemon of one build talk; another build restarts the daemon.
pub const BUILD: &str = env!("DCP_BUILD_ID");
/// The daemon's exit code when another daemon owns the project's address already.
const TAKEN: i32 = 3;

/// The command of the command line: its first word that is neither an option nor an option's value.
fn command(argv: &[String]) -> Option<&str> {
    let mut skip = false;
    for a in argv {
        if skip {
            skip = false;
        } else if a == "--root" || a == "--target" {
            skip = true;
        } else if !a.starts_with('-') {
            return Some(a);
        }
    }
    None
}

/// The --root of the command line when it holds decompanion.toml, else the first directory from the cwd up holding
/// one.
fn project_root(argv: &[String]) -> Option<PathBuf> {
    for (i, a) in argv.iter().enumerate() {
        let r = if a == "--root" { argv.get(i + 1).cloned() } else { a.strip_prefix("--root=").map(|s| s.to_string()) };
        if let Some(r) = r {
            let r = std::path::absolute(&r).unwrap_or_else(|_| PathBuf::from(&r));
            return r.join(CONFIG_NAME).is_file().then_some(r);
        }
    }
    let mut d = std::env::current_dir().ok()?;
    loop {
        if d.join(CONFIG_NAME).is_file() {
            return Some(d);
        }
        if !d.pop() {
            return None;
        }
    }
}

pub fn main() -> i32 {
    let argv: Vec<String> = std::env::args().collect();
    let rest = &argv[1..];
    let cmd = command(rest);
    let local = matches!(cmd, None | Some("init") | Some("serve") | Some("self")) || rest.iter().any(|a| a == "--no-daemon")
        || std::env::var("DCP_NO_DAEMON").is_ok_and(|v| !v.is_empty());
    let (mut out, mut err) = (std::io::stdout(), std::io::stderr());
    if !local {
        if let Some(root) = project_root(rest) {
            return via_daemon(&root, &argv);
        }
    }
    crate::cli::run(&argv, &mut out, &mut err)
}

// ------------------------------------------------------------------------------------------------ the connection

struct Info {
    pid: u64,
    address: String,
    key: String,
    build: String,
}

fn info(root: &Path) -> Option<Info> {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(ipc::info_path(root)).ok()?).ok()?;
    Some(Info { pid: v["pid"].as_u64()?, address: v["address"].as_str()?.into(), key: v["key"].as_str()?.into(), build: v["build"].as_str().unwrap_or("").into() })
}

/// A connection to the running daemon of root (and its key), or None.
fn connect(root: &Path) -> Option<(ipc::Conn, Info)> {
    let i = info(root)?;
    let c = ipc::connect(&i.address).ok()?;
    Some((c, i))
}

/// The daemon of root, started when none answers: a copy of this executable (build/daemon/dcp-<build>.exe, so a
/// running daemon never locks the installed dcp or cargo's output) in the background, its output appended to
/// build/daemon.log.
fn start(root: &Path) -> Result<std::process::Child, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = root.join("build").join("daemon");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let ext = exe.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
    let copy = dir.join(format!("dcp-{BUILD}{ext}"));
    if !copy.exists() {
        let tmp = dir.join(format!("dcp-{BUILD}.{}.tmp", std::process::id()));
        std::fs::copy(&exe, &tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
        if std::fs::rename(&tmp, &copy).is_err() {
            let _ = std::fs::remove_file(&tmp); // another client placed it meanwhile
        }
    }
    // the copies of earlier builds go (a running one refuses: it goes next time)
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p != copy && p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("dcp-")) {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
    let log_path = root.join("build").join("daemon.log");
    let log = std::fs::OpenOptions::new().create(true).append(true).open(&log_path).map_err(|e| format!("{}: {e}", log_path.display()))?;
    let log2 = log.try_clone().map_err(|e| e.to_string())?;
    let mut c = std::process::Command::new(&copy);
    c.args(["serve", "--foreground", "--root"]).arg(root).current_dir(root).stdin(std::process::Stdio::null()).stdout(log).stderr(log2);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // a console without a window (not DETACHED_PROCESS): the daemon's children (CL, clang) share it instead of
        // each getting a visible console of its own
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        c.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    }
    c.spawn().map_err(|e| format!("{}: {e}", copy.display()))
}

/// The daemon of root, started and waited for when none of this build answers: a connection, or the reason.
fn daemon(root: &Path) -> Result<ipc::Conn, String> {
    if let Some((c, i)) = connect(root) {
        if i.build == BUILD {
            return Ok(c);
        }
        drop(c);
        stop_daemon(root); // another build: it goes, ours comes
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut child = start(root)?;
    loop {
        if let Some((c, i)) = connect(root) {
            if i.build == BUILD {
                return Ok(c);
            }
        }
        if let Ok(Some(st)) = child.try_wait() {
            if st.code() != Some(TAKEN) {
                return Err(format!("the daemon exited with {} (see {})", st.code().unwrap_or(-1), root.join("build").join("daemon.log").display()));
            }
            // the address is taken: another client started a daemon meanwhile, or the previous one is still going
            std::thread::sleep(Duration::from_millis(20));
            if connect(root).is_none_or(|(_, i)| i.build != BUILD) {
                child = start(root)?;
            }
        }
        if Instant::now() >= deadline {
            return Err(format!("the daemon does not answer (see {})", root.join("build").join("daemon.log").display()));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn stop_daemon(root: &Path) {
    if let Some((mut c, i)) = connect(root) {
        let _ = ipc::send(&mut c, &json!({"op": "stop", "key": i.key}));
        let _ = ipc::recv(&mut c);
        // the old daemon releases the address when it exits
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && info(root).is_some_and(|x| x.pid == i.pid) {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Run the command in the daemon: its exit code. The daemon's output is read to the end even when our stdout is
/// closed, so the request finishes as it would have.
fn via_daemon(root: &Path, argv: &[String]) -> i32 {
    let (mut out, mut err) = (std::io::stdout(), std::io::stderr());
    let (mut live_out, mut live_err) = (true, true);
    let env: serde_json::Map<String, Value> = std::env::vars().map(|(k, v)| (k, Value::String(v))).collect();
    let cwd = std::env::current_dir().map(|d| d.to_string_lossy().into_owned()).unwrap_or_default();
    for _attempt in 0..3 {
        let mut conn = match daemon(root) {
            Ok(c) => c,
            Err(e) => {
                let _ = writeln!(err, "dcp: {e}");
                return 2;
            }
        };
        let key = info(root).map(|i| i.key).unwrap_or_default();
        let req = json!({"op": "run", "key": key, "argv": argv, "cwd": cwd, "env": env, "build": BUILD});
        if let Err(e) = ipc::send(&mut conn, &req) {
            let _ = writeln!(err, "dcp: lost the daemon ({e})");
            return 1;
        }
        let mut spec: Option<String> = None;
        loop {
            let msg = match ipc::recv(&mut conn) {
                Ok(m) => m,
                Err(e) => {
                    let _ = writeln!(err, "dcp: lost the daemon ({e})");
                    return 1;
                }
            };
            if let Some(t) = msg["out"].as_str() {
                if live_out {
                    live_out = out.write_all(t.as_bytes()).and_then(|_| out.flush()).is_ok();
                }
            } else if let Some(t) = msg["err"].as_str() {
                if live_err {
                    live_err = err.write_all(t.as_bytes()).and_then(|_| err.flush()).is_ok();
                }
            } else if let Some(s) = msg["launch"].as_str() {
                spec = Some(s.to_string());
            } else if let Some(r) = msg["restart"].as_str() {
                let _ = writeln!(err, "dcp: the daemon restarts ({r})");
                break;
            } else if !msg["exit"].is_null() {
                let code = msg["exit"].as_i64().unwrap_or(1) as i32;
                if let (0, Some(spec)) = (code, spec) {
                    let mut io = Io { out: &mut out, err: &mut err };
                    return crate::launch::launch(&mut io, &spec);
                }
                return code;
            }
        }
        // the daemon of another build has gone: the next attempt starts ours
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && connect(root).is_some_and(|(_, i)| i.build != BUILD) {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let _ = writeln!(err, "dcp: the daemon keeps restarting");
    1
}

// ------------------------------------------------------------------------------------------------ dcp serve

/// `dcp serve [--stop | --status | --foreground]`.
pub fn serve(io: &mut Io, root: Option<&str>, stop: bool, status: bool, foreground: bool) -> i32 {
    let root = match root {
        Some(r) => std::path::absolute(r).unwrap_or_else(|_| PathBuf::from(r)),
        None => match project_root(&[]) {
            Some(r) => r,
            None => {
                let cwd = std::env::current_dir().map(|d| d.display().to_string()).unwrap_or_default();
                io.warn(&format!("dcp serve: no {CONFIG_NAME} in {cwd} or above"));
                return 2;
            }
        },
    };
    let rs = root.display().to_string();
    if stop || status {
        let Some((mut c, i)) = connect(&root) else {
            io.say(&format!("dcp serve: no daemon runs for {rs}"));
            return 1;
        };
        let op = if stop { "stop" } else { "status" };
        if let Err(e) = ipc::send(&mut c, &json!({"op": op, "key": i.key})) {
            io.say(&format!("dcp serve: {e}"));
            return 1;
        }
        return match ipc::recv(&mut c) {
            Ok(v) if status => {
                let s = &v["status"];
                let f = |k: &str| match &s[k] {
                    Value::Null => "None".to_string(),
                    Value::String(x) => x.clone(),
                    x => x.to_string(),
                };
                io.say(&["pid", "root", "uptime", "requests", "memory_mb", "build"].iter().map(|k| format!("{k}={}", f(k))).collect::<Vec<_>>().join("  "));
                0
            }
            Ok(_) => {
                let deadline = Instant::now() + Duration::from_secs(5);
                while Instant::now() < deadline && info(&root).is_some_and(|x| x.pid == i.pid) {
                    std::thread::sleep(Duration::from_millis(10));
                }
                io.say(&format!("dcp serve: stopped ({rs})"));
                0
            }
            Err(e) => {
                io.say(&format!("dcp serve: {e}"));
                1
            }
        };
    }
    if foreground {
        return crate::daemon::run(&root);
    }
    if let Some((_, i)) = connect(&root) {
        if i.build == BUILD {
            io.warn(&format!("dcp serve: a daemon runs already for {rs} (dcp serve --status)"));
            return 1;
        }
    }
    match daemon(&root) {
        Ok(_) => {
            let pid = info(&root).map(|i| i.pid).unwrap_or(0);
            io.say(&format!("dcp serve: started for {rs} (pid {pid}, log build/daemon.log)"));
            0
        }
        Err(e) => {
            io.warn(&format!("dcp serve: {e}"));
            1
        }
    }
}
