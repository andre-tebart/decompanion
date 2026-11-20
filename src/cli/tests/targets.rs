//! The target dimension: [[target]] tables, one store per target, --target, `dcp target add|list`, and the single
//! table `[target]` of a project of one binary.

use super::*;

#[test]
fn two_targets_two_stores() {
    let t = tiny2();
    let p = project(&t, None);
    assert_eq!(p.targets.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(), ["tiny", "other"]);
    assert_eq!(p.target_name, "tiny");
    let q = project(&t, Some("other"));
    assert!(q.store_path().ends_with("other.sqlite"));
    assert_ne!(sha256_of(Path::new(&q.target.path)), sha256_of(Path::new(&p.target.path)));
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

/// A project of one binary writes the single table `[target]`; `dcp target add` makes it the first of the list.
#[test]
fn single_table_form() {
    let d = tmp("old").join("old");
    std::fs::create_dir_all(&d).unwrap();
    let pe = build_pe(&d.join("Server.dll"), 0, None);
    write(&d, "decompanion.toml", &format!("[target]\npath = \"{}\"\narchives = []\n\n[toolchain]\nreason = \"x\"\n", posix(&pe)));
    let p = project(&d, None);
    assert!(p.target_name == "server" && p.targets.len() == 1 && p.is_default_target());
    assert!(p.store_path().ends_with("server.sqlite"));
    let other = build_pe(&d.join("b.dll"), 1, None);
    let (code, out) = dcp(&d, &["target", "add", "b", &other.to_string_lossy()]);
    assert_eq!(code, 0, "{out}");
    let p = project(&d, None);
    assert_eq!(p.targets.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(), ["server", "b"]);
    assert!(read(&d, "decompanion.toml").starts_with("[[target]]\nname = \"server\"\npath = "));
    // the first target keeps its declarations, the new one has none
    assert!(p.waiting("libs").unwrap().is_empty());
    assert_eq!(project(&d, Some("b")).waiting("libs").unwrap(), ["libs.archives"]);
}
