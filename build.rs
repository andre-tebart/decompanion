//! DCP_CORE_HASH: the hash of the core's sources (Cargo.toml, Cargo.lock and every file below src/, by relative
//! path), the first 12 hex digits of sha256 over `path \0 bytes \0` per file. It is part of every rule run's key, so
//! a changed core reruns every rule; it is also the build id the client and the daemon compare.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).expect("src/ readable").flatten() {
        let p = e.path();
        if p.is_dir() {
            files(&p, out);
        } else if p.is_file() {
            out.push(p);
        }
    }
}

/// $OUT_DIR/skills.rs: the shipped skills (skills/<name>/... of the decompanion repository) as (relative path,
/// bytes), in the order `dcp skills install` writes them: by skill name, then by path, both ignoring case.
fn skills(crate_dir: &Path) {
    let dir = [crate_dir.join("skills"), crate_dir.join("../../skills")].into_iter().find(|d| d.is_dir()).expect("the skills/ directory");
    println!("cargo:rerun-if-changed={}", dir.display());
    let mut items = vec![];
    for d in std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.path()).filter(|p| p.is_dir()) {
        let name = d.file_name().unwrap().to_string_lossy().into_owned();
        let mut fs = vec![];
        files(&d, &mut fs);
        for f in fs {
            let rel = f.strip_prefix(&d).unwrap().to_string_lossy().replace('\\', "/");
            items.push((name.to_lowercase(), rel.to_lowercase(), format!("{name}/{rel}"), f.canonicalize().unwrap()));
        }
    }
    items.sort();
    let mut out = String::from("pub static SKILLS: &[(&str, &[u8])] = &[\n");
    for (_, _, rel, path) in items {
        out.push_str(&format!("    ({rel:?}, include_bytes!({:?})),\n", path.to_string_lossy()));
    }
    out.push_str("];\n");
    std::fs::write(PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("skills.rs"), out).unwrap();
}

fn main() {
    let crate_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let mut src = vec![];
    files(&crate_dir.join("src"), &mut src);
    let rel = |p: &Path| p.strip_prefix(&crate_dir).unwrap().to_string_lossy().replace('\\', "/");
    src.sort_by_key(|p| rel(p).to_lowercase());
    let mut all = vec![crate_dir.join("Cargo.toml"), crate_dir.join("Cargo.lock")];
    all.extend(src);
    let mut h = Sha256::new();
    for f in &all {
        if let Ok(b) = std::fs::read(f) {
            h.update(rel(f).as_bytes());
            h.update(b"\0");
            h.update(&b);
            h.update(b"\0");
        }
    }
    let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    println!("cargo:rustc-env=DCP_CORE_HASH={}", &hex[..12]);
    skills(&crate_dir);
    // the build id the client and the daemon compare: the core's hash and everything else the binary embeds
    let mut b = Sha256::new();
    b.update(hex.as_bytes());
    let mut more = vec![crate_dir.join("build.rs")];
    for d in ["skills", "data"] {
        if crate_dir.join(d).is_dir() {
            files(&crate_dir.join(d), &mut more);
        }
    }
    more.sort();
    for f in &more {
        if let Ok(x) = std::fs::read(f) {
            b.update(rel(f).as_bytes());
            b.update(b"\0");
            b.update(&x);
        }
    }
    let id: String = b.finalize().iter().map(|x| format!("{x:02x}")).collect();
    println!("cargo:rustc-env=DCP_BUILD_ID={}", &id[..12]);
    println!("cargo:rerun-if-changed=data");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=Cargo.lock");
}
