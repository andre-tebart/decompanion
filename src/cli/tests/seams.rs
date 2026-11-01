//! The plugin seams: the image and instruction-set keys of a target, and `dcp init` naming its plugins
//! (tests/test_seams.py).

use super::*;

#[test]
fn project_plugins() {
    let t = tiny();
    let p = project(&t, None);
    assert_eq!(p.image_checked().unwrap().default_isa(), Some("x86"));
    assert_eq!(p.isa().unwrap(), "x86");
    assert_eq!(p.toolchain_key(), "vc6");
}

#[test]
fn declared_isa() {
    let t = tiny();
    set_config(&t, "image = \"pe32\"\n", "image = \"pe32\"\nisa = \"x86\"\n");
    assert_eq!(project(&t, None).isa().unwrap(), "x86");
    set_config(&t, "isa = \"x86\"", "isa = \"z80\"");
    let e = project(&t, None).isa().unwrap_err();
    assert!(matches!(&e, crate::error::Error::Config(m) if m.contains("unknown instruction set 'z80'")), "{e}");
}

#[test]
fn init_names_plugins() {
    let d = tmp("init");
    let pe = build_pe(&d.join("t.dll"), 0, None);
    let proj = d.join("proj");
    let (code, out, err) = dcp_bare(&["init", &proj.to_string_lossy(), &pe.to_string_lossy()]);
    assert_eq!(code, 0, "{out}{err}");
    let text = read(&proj, "decompanion.toml");
    assert!(text.contains("image = \"pe32\"\nisa = \"x86\"\n"), "{text}"); // computed from the file; nothing is declared
    let p = project(&proj, None);
    assert_eq!(p.toolchain_key(), "vc6"); // the only registered plugin, without a [toolchain] table
    assert_eq!(p.target(None).unwrap().isa.as_deref(), Some("x86"));
    assert_eq!(p.isa().unwrap(), "x86");
    let (_, out) = dcp(&proj, &["target", "list"]);
    assert!(out.contains("isa=x86"), "{out}");
}
