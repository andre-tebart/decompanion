//! The target dimension: [[target]] tables, one store per target, --target, `dcp target add|list`, the
//! milestone-1 [target] form, and the worktree overlay per target (tests/test_targets.py).

use super::*;

#[test]
fn two_targets_two_stores() {
    let t = tiny2();
    let p = project(&t, None);
    assert_eq!(p.targets.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(), ["tiny", "other"]);
    assert_eq!(p.target_name, "tiny");
    let q = project(&t, Some("other"));
    assert!(q.store_path().ends_with("other.sqlite"));
    assert_ne!(sha256_of(Path::new(&q.target(None).unwrap().path)), sha256_of(Path::new(&p.target(None).unwrap().path)));
    let (code, out) = dcp(&t, &["setup"]);
    assert!(code == 0 && out.contains("target=tiny"), "{out}");
    let (code, out) = dcp(&t, &["--target", "other", "setup"]);
    assert!(code == 0 && out.contains("target=other"), "{out}");
    assert!(t.join("build/tiny.sqlite").exists() && t.join("build/other.sqlite").exists());
    // --target after the command works too, and why answers for both
    let (code, out) = dcp(&t, &["why", "0x10001020", "--target", "other"]);
    assert!(code == 0 && out.contains("target=other") && out.contains("owner=func"), "{out}");
    let (_, out) = dcp(&t, &["why", "0x10001020"]);
    assert!(out.contains("target=tiny"));
    let (code, out) = dcp(&t, &["check"]);
    assert!(code == 0 && out.contains("check target=tiny") && out.contains("check target=other"), "{out}");
    assert!(crate::project::Project::find(Some(&t.to_string_lossy()), Some("nope")).is_err());
}

#[test]
fn target_add_and_list() {
    let t = tiny();
    let other = build_pe(&t.join("second.dll"), 2, None);
    let (code, out) = dcp(&t, &["target", "add", "second", &other.to_string_lossy()]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(project(&t, None).targets.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(), ["tiny", "second"]);
    let (_, out) = dcp(&t, &["target", "list"]);
    assert!(out.contains("targets=2") && out.contains("target=second") && out.contains("default=yes"), "{out}");
    let (code, _) = dcp(&t, &["--target", "second", "setup"]);
    assert!(code == 0 && t.join("build/second.sqlite").exists());
}

#[test]
fn legacy_target_form() {
    let d = tmp("old").join("old");
    std::fs::create_dir_all(&d).unwrap();
    let pe = build_pe(&d.join("Server.dll"), 0, None);
    write(&d, "decompanion.toml", &format!("[target]\npath = \"{}\"\n\n[toolchain]\nreason = \"x\"\n\n[libs]\narchives = []\n", posix(&pe)));
    let p = project(&d, None);
    assert!(p.target_name == "server" && p.targets[0].legacy);
    assert!(p.store_path().ends_with("server.sqlite"));
    let other = build_pe(&d.join("b.dll"), 1, None);
    let (code, _) = dcp(&d, &["target", "add", "b", &other.to_string_lossy()]);
    assert_eq!(code, 0);
    let p = project(&d, None);
    assert_eq!(p.targets.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(), ["server", "b"]);
    assert!(!p.targets[0].legacy);
}

fn copy_tree(from: &Path, to: &Path, skip: &str) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        let name = e.file_name();
        if name.to_string_lossy() == skip {
            continue;
        }
        let (s, d) = (e.path(), to.join(&name));
        if s.is_dir() {
            copy_tree(&s, &d, skip);
        } else {
            std::fs::copy(&s, &d).unwrap();
        }
    }
}

/// A worktree's store reads main's runs: the first setup there copies them instead of recomputing.
#[test]
fn overlay_per_target() {
    let t = tiny2();
    assert_eq!(dcp(&t, &["setup"]).0, 0);
    assert_eq!(dcp(&t, &["--target", "other", "setup"]).0, 0);
    let wt = t.parent().unwrap().join("wt1");
    copy_tree(&t, &wt, "build");
    write(&wt, ".dcp/main_store", &format!("{}\n", posix(&t.join("build"))));
    let p = project(&wt, Some("other"));
    assert!(p.main_uri().contains("other.sqlite"), "{}", p.main_uri());
    assert!(!engine_ran(&wt, Some("other"))); // every run found in main's store (same inputs)
}

fn git(dir: &Path, args: &[&str]) {
    let st = std::process::Command::new("git").args(args).current_dir(dir).output().unwrap();
    assert!(st.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&st.stderr));
}

#[test]
#[ignore = "e2e: starts git"]
fn wt_commands() {
    let t = tiny();
    write(&t, ".gitignore", "build/\n.dcp/\n");
    git(&t, &["init", "-q", "-b", "main"]);
    git(&t, &["add", "-A"]);
    git(&t, &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "init"]);
    let (code, out) = dcp(&t, &["wt", "new", "w1"]);
    assert_eq!(code, 0, "{out}");
    let path = t.parent().unwrap().join(format!("{}-wt", t.file_name().unwrap().to_string_lossy())).join("w1");
    let main_store = std::fs::read_to_string(path.join(".dcp/main_store")).unwrap();
    let want = posix(&std::fs::canonicalize(t.join("build")).unwrap_or(t.join("build"))).trim_start_matches("//?/").to_string();
    assert_eq!(main_store.trim().to_lowercase(), want.to_lowercase());
    let (_, out) = dcp(&t, &["wt", "list"]);
    assert!(out.contains("worktree=w1"), "{out}");
    let (code, _) = dcp(&t, &["seed", &path.to_string_lossy()]);
    assert_eq!(code, 0);
    let (code, _) = dcp(&t, &["wt", "drop", "w1"]);
    assert!(code == 0 && !path.exists());
}
