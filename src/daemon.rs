//! The project's daemon (`dcp serve --foreground`; the client starts it on demand): one resident process per project
//! root that runs the dcp commands, so a command does not pay the first read of the image, the sources, the store and
//! the objects again. It only keeps what the process memos keep anyway (fsmemo, the source scan, the plans, the parsed
//! objects, the compares, the decoded facts); every memo is keyed by the content it was computed from, and every
//! request opens the project afresh and starts a new file epoch, so a request sees every change made since the last
//! one, by dcp or by anyone else.
//!
//! Requests run one at a time, in the order they connect (the store has one writer; a request runs in the client's
//! working directory and environment). stdout and stderr are streamed back as they are written. A client of
//! another build gets `restart` and the daemon exits: the client starts the daemon of its own build. The store stays
//! open in the daemon: stop it (`dcp serve --stop`) before deleting build/ (Windows refuses to delete an open file).

use crate::client::BUILD;
use crate::ipc;
use serde_json::{json, Value};
use std::cell::RefCell;
use std::io::Write;
use std::path::Path;
use std::rc::Rc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// A stream of the request's output: each write that ends a line goes to the client as one frame.
struct Frames {
    conn: Rc<RefCell<ipc::Server>>,
    kind: &'static str,
    buf: Vec<u8>,
}

impl Frames {
    fn send(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        let text = String::from_utf8_lossy(&self.buf[..n]).into_owned();
        self.buf.drain(..n);
        let _ = ipc::send(self.conn.borrow_mut().file(), &json!({ self.kind: text })); // a client gone: the command still finishes
    }
}

impl Write for Frames {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(b);
        if let Some(i) = self.buf.iter().rposition(|&c| c == b'\n') {
            self.send(i + 1);
        }
        Ok(b.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let n = self.buf.len();
        self.send(n);
        Ok(())
    }
}

fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

#[cfg(windows)]
fn memory_mb() -> Option<u64> {
    #[repr(C)]
    #[derive(Default)]
    struct Pmc {
        cb: u32,
        page_faults: u32,
        peak_ws: usize,
        ws: usize,
        a: usize,
        b: usize,
        c: usize,
        d: usize,
        pagefile: usize,
        peak_pagefile: usize,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut std::ffi::c_void;
        fn K32GetProcessMemoryInfo(p: *mut std::ffi::c_void, c: *mut Pmc, cb: u32) -> i32;
    }
    let mut c = Pmc { cb: std::mem::size_of::<Pmc>() as u32, ..Default::default() };
    let ok = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) } != 0;
    ok.then(|| ((c.ws as f64) / (1u64 << 20) as f64).round() as u64)
}

#[cfg(not(windows))]
fn memory_mb() -> Option<u64> {
    None
}

/// A random key per daemon start (the OS's randomness through std's hasher seeds plus time and pid).
fn key() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut out = String::new();
    for i in 0..4u64 {
        let mut h = RandomState::new().build_hasher();
        h.write_u64(i ^ std::process::id() as u64);
        h.write_u128(SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0));
        out.push_str(&format!("{:016x}", h.finish()));
    }
    out
}

/// Run the daemon of root in this process until it is stopped (or a client of another build comes): the exit code.
pub fn run(root: &Path) -> i32 {
    let root = std::fs::canonicalize(root).map(|r| std::path::PathBuf::from(r.to_string_lossy().trim_start_matches(r"\\?\"))).unwrap_or_else(|_| root.to_path_buf());
    let addr = ipc::address(&root);
    let mut listener = match ipc::Listener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("dcp serve: {} is taken ({e}): another daemon runs for {}", addr, root.display());
            return 3;
        }
    };
    let key = key();
    let started = now();
    let info = ipc::info_path(&root);
    let _ = std::fs::create_dir_all(info.parent().unwrap());
    let tmp = info.with_file_name(format!("dcp-daemon.{}.tmp", std::process::id()));
    let rec = json!({"pid": std::process::id(), "address": addr, "key": key, "root": root.to_string_lossy(), "build": BUILD, "started": started});
    if std::fs::write(&tmp, format!("{rec}\n")).and_then(|_| std::fs::rename(&tmp, &info)).is_err() {
        eprintln!("dcp serve: cannot write {}", info.display());
        return 1;
    }
    eprintln!("dcp serve: {} (pid {}, {addr}, build {BUILD})", root.display(), std::process::id());
    let mut requests = 0u64;
    loop {
        let conn = match listener.accept() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("dcp serve: refused a connection: {e}");
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
        };
        let conn = Rc::new(RefCell::new(conn));
        let req = match ipc::recv(conn.borrow_mut().file()) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if req["key"].as_str() != Some(key.as_str()) {
            eprintln!("dcp serve: refused a request without the key");
            continue;
        }
        match req["op"].as_str().unwrap_or("run") {
            "stop" => {
                let _ = ipc::send(conn.borrow_mut().file(), &json!({"exit": 0}));
                break;
            }
            "status" => {
                let st = json!({"pid": std::process::id(), "root": root.to_string_lossy(), "uptime": (now() - started) as u64, "requests": requests,
                                "memory_mb": memory_mb(), "build": BUILD});
                let _ = ipc::send(conn.borrow_mut().file(), &json!({"status": st}));
            }
            _ => {
                if req["build"].as_str() != Some(BUILD) {
                    let _ = ipc::send(conn.borrow_mut().file(), &json!({"restart": "the decompanion code changed"}));
                    eprintln!("dcp serve: a client of build {} came: exiting for it", req["build"].as_str().unwrap_or("?"));
                    break;
                }
                requests += 1;
                handle(&conn, &req);
            }
        }
    }
    drop(listener);
    if std::fs::read_to_string(&info).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()).is_some_and(|v| v["pid"].as_u64() == Some(std::process::id() as u64)) {
        let _ = std::fs::remove_file(&info);
    }
    0
}

/// One command: in the client's environment and working directory, its output streamed back, then its exit code
/// (and the launch spec a `dcp run` hands over).
fn handle(conn: &Rc<RefCell<ipc::Server>>, req: &Value) {
    let t0 = Instant::now();
    let saved_env: Vec<(String, String)> = std::env::vars().collect();
    let saved_cwd = std::env::current_dir().ok();
    set_env(req["env"].as_object().map(|m| m.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string())).collect()).unwrap_or_else(|| saved_env.clone()));
    if let Some(cwd) = req["cwd"].as_str() {
        let _ = std::env::set_current_dir(cwd);
    }
    let argv: Vec<String> = req["argv"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect()).unwrap_or_default();
    let mut out = Frames { conn: conn.clone(), kind: "out", buf: vec![] };
    let mut err = Frames { conn: conn.clone(), kind: "err", buf: vec![] };
    crate::launch::handoff_slot(true);
    let code = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| crate::cli::run(&argv, &mut out, &mut err))) {
        Ok(c) => c,
        Err(p) => {
            let m = p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
            let _ = writeln!(err, "dcp: internal error: {m}");
            1
        }
    };
    if crate::timing::level() > 0 {
        let _ = writeln!(err, "timing: daemon request={:.0}", t0.elapsed().as_secs_f64() * 1000.0);
    }
    let _ = out.flush();
    let _ = err.flush();
    let spec = crate::launch::handoff_slot(false);
    set_env(saved_env);
    if let Some(d) = saved_cwd {
        let _ = std::env::set_current_dir(d);
    }
    let mut c = conn.borrow_mut();
    if let Some(s) = spec {
        let _ = ipc::send(c.file(), &json!({"launch": s}));
    }
    let _ = ipc::send(c.file(), &json!({"exit": code, "ms": t0.elapsed().as_millis() as u64}));
}

/// The process environment replaced by `vars`. Requests run one at a time and no thread of a request outlives it,
/// so nothing reads the environment while it changes.
fn set_env(vars: Vec<(String, String)>) {
    let keep: std::collections::HashSet<&str> = vars.iter().map(|(k, _)| k.as_str()).collect();
    for (k, _) in std::env::vars() {
        if !keep.contains(k.as_str()) {
            unsafe { std::env::remove_var(&k) };
        }
    }
    for (k, v) in &vars {
        if !k.is_empty() && !k.contains('=') {
            unsafe { std::env::set_var(k, v) };
        }
    }
}
