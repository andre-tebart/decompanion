//! `dcp self install`: build the decompanion checkout this dcp was built from (cargo build --release) and put the
//! result where the running dcp lies (after a first `cargo install --path .`: ~/.cargo/bin). Windows refuses to
//! overwrite a running executable but lets it be renamed: the old one moves aside (dcp.old-<n>.exe) and goes on the
//! next install. A daemon runs a copy of its own (build/daemon/), so it never holds the installed file; the next
//! command of a project restarts it with the new build.

use crate::cli::Io;
use std::path::PathBuf;
use std::process::Command;

pub fn install(io: &mut Io) -> i32 {
    let checkout = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    io.say(&format!("self install: cargo build --release in {}", checkout.display()));
    let _ = io.out.flush();
    let st = Command::new("cargo").args(["build", "--release", "--bin", "dcp"]).current_dir(&checkout).status();
    match st {
        Ok(s) if s.success() => {}
        Ok(s) => {
            io.warn(&format!("dcp self install: cargo build failed ({s})"));
            return 1;
        }
        Err(e) => {
            io.warn(&format!("dcp self install: cargo: {e} (rustup's stable-x86_64-pc-windows-gnu toolchain on PATH)"));
            return 1;
        }
    }
    let exe = if cfg!(windows) { "dcp.exe" } else { "dcp" };
    let built = checkout.join("target").join("release").join(exe);
    let here = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            io.warn(&format!("dcp self install: {e}"));
            return 1;
        }
    };
    let same = |a: &PathBuf, b: &PathBuf| std::fs::canonicalize(a).ok() == std::fs::canonicalize(b).ok();
    if same(&here, &built) {
        io.say(&format!("self install: built {} (this dcp is cargo's own output: `cargo install --path .` installs it once)", built.display()));
        return 0;
    }
    let dir = here.parent().map(|d| d.to_path_buf()).unwrap_or_default();
    // the files an earlier install moved aside
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with("dcp.old-") {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
    let aside = dir.join(format!("dcp.old-{stamp}{}", if cfg!(windows) { ".exe" } else { "" }));
    if here.exists() {
        if let Err(e) = std::fs::rename(&here, &aside) {
            io.warn(&format!("dcp self install: {} cannot move aside: {e}", here.display()));
            return 1;
        }
    }
    if let Err(e) = std::fs::copy(&built, &here) {
        let _ = std::fs::rename(&aside, &here);
        io.warn(&format!("dcp self install: {}: {e}", here.display()));
        return 1;
    }
    io.say(&format!("self install: {} (build {})", here.display(), crate::client::BUILD));
    0
}
