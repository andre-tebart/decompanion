//! VC6's own assembly listing of a unit (`/FAc`: each instruction with its offset and bytes, `; Line N` before the
//! code of each source line, and the frame symbols `_name$ = N` before each function): `dcp listing NAME`, the
//! names of `dcp frame`, the source lines of `dcp asmdiff --lines` (improvement-reports/build-listing-command.md,
//! frame-slot-map-command.md, asmdiff-hunk-to-source-line.md). The unit is compiled as the build compiles it (the
//! trial bench's flags and include order), into build/trial/, the files removed after.

use crate::error::{Error, Result};
use crate::project::{py_path, Project};

fn err(e: impl std::fmt::Display) -> Error {
    Error::value(e.to_string())
}

/// The unit's listing (`text`: the unit's source as compiled), or the compiler's first error.
pub fn unit_listing(p: &Project, tu: &crate::plan::Tu, text: &str) -> Result<std::result::Result<String, String>> {
    let root = p.root.to_string_lossy().into_owned();
    let tools = crate::vc6::Tools::of(p);
    if !tools.available() {
        return Ok(Err("the toolchain is not available".into()));
    }
    let full = |r: &str| py_path(&format!("{root}/{r}"));
    for d in ["build/trial", "build/obj/trial"] {
        let _ = std::fs::create_dir_all(full(d));
    }
    let mut flags = crate::plan::compile_flags(p, &tu.target, &tu.unit).map_err(err)?;
    let (src, obj, asm) = (format!("build/trial/{}-lst.c", tu.unit), format!("build/obj/trial/{}-lst.obj", tu.unit), format!("build/trial/{}-lst.asm", tu.unit));
    flags.push("/FAc".into());
    flags.push(format!("/Fa{}", asm.replace('/', "\\")));
    let file = tu.file.replace('/', "\\");
    let mut dirs = vec![];
    if let Some((d, _)) = tu.file.rsplit_once('/') {
        dirs.push(d.replace('/', "\\"));
    }
    dirs.push("include".to_string());
    std::fs::write(full(&src), format!("#line 1 \"{}\"\n{text}", file.replace('\\', "\\\\"))).map_err(err)?;
    let r = tools.compile(&src, &obj, &flags, &dirs, &root);
    let out = std::fs::read(full(&asm)).map(|b| String::from_utf8_lossy(&b).replace("\r\n", "\n"));
    // DCP_KEEP_LISTING keeps the files (build/trial/<unit>-lst.*) for reading
    if std::env::var_os("DCP_KEEP_LISTING").is_none() {
        for f in [&src, &obj, &asm] {
            let _ = std::fs::remove_file(full(f));
        }
    }
    let r = r.map_err(err)?;
    if !r.ok {
        return Ok(Err(r.diags.iter().find(|d| d.severity == "error").map(|d| format!("{}({}): {} {}", d.file, d.line, d.code, d.message))
            .unwrap_or_else(|| "does not compile".into())));
    }
    Ok(out.map_err(|e| format!("no listing: {e}")))
}

/// One function's part of a unit listing: its frame symbols (`_x$ = N` lines before it) and its lines from `PROC`
/// to `ENDP`; None when the listing has no such function.
pub fn function_part(asm: &str, name: &str) -> Option<Vec<String>> {
    let lines: Vec<&str> = asm.lines().collect();
    let is = |l: &str, kw: &str| {
        let mut w = l.split_whitespace();
        let (a, b) = (w.next().unwrap_or(""), w.next().unwrap_or(""));
        (a == format!("_{name}") || a == name) && b == kw
    };
    let start = lines.iter().position(|l| is(l, "PROC"))?;
    let end = lines[start..].iter().position(|l| is(l, "ENDP")).map(|k| k + start)?;
    // the symbols right above PROC
    let mut first = start;
    while first > 0 && symbol(lines[first - 1]).is_some() {
        first -= 1;
    }
    Some(lines[first..=end].iter().map(|l| l.to_string()).collect())
}

/// A frame symbol line: `_name$ = N`, or a block's local numbered by VC6, `__zn$61442 = -28`: (N, the name).
fn symbol(l: &str) -> Option<(i32, String)> {
    let (lhs, v) = l.split_once(" = ")?;
    let (name, num) = lhs.trim().split_once('$')?;
    if !num.chars().all(|c| c.is_ascii_digit()) || !name.starts_with('_') {
        return None;
    }
    Some((v.trim().parse::<i32>().ok()?, name.trim_start_matches('_').to_string()))
}

/// The frame symbols of a function's part: (the offset VC6 writes, the name) in listing order.
pub fn frame_symbols(part: &[String]) -> Vec<(i32, String)> {
    part.iter().take_while(|l| !l.contains(" PROC")).filter_map(|l| symbol(l)).collect()
}

/// The source line of each instruction of a function's part: (offset in the function, line), from the `; Line N`
/// markers and the `  0001a\t8b ...` code lines.
pub fn line_map(part: &[String]) -> Vec<(u32, u32)> {
    let mut out = vec![];
    let mut line = None;
    for l in part {
        let t = l.trim_start();
        if let Some(n) = t.strip_prefix("; Line ") {
            line = n.trim().parse::<u32>().ok();
            continue;
        }
        let Some(off) = t.split(['\t', ' ']).next().filter(|x| x.len() == 5 && x.chars().all(|c| c.is_ascii_hexdigit())) else { continue };
        if let (Ok(o), Some(n)) = (u32::from_str_radix(off, 16), line) {
            out.push((o, n));
        }
    }
    out
}

/// The listing of one function as the build compiles its unit now: (the unit's file, the part), or why there is
/// none.
pub fn of_function(p: &Project, name: &str) -> Result<std::result::Result<(String, Vec<String>), String>> {
    let rows = crate::queues::function_grades(&p.store_path())?;
    let Some(row) = rows.iter().find(|r| r["name"].as_str() == Some(name)) else { return Ok(Err(format!("no graded function {name} (dcp build first)"))) };
    let unit = row["unit"].as_str().unwrap_or("").to_string();
    let plan = crate::plan::plan(p).map_err(err)?;
    let Some(tu) = plan.iter().find(|t| t.unit == unit) else { return Ok(Err(format!("no unit {unit} in target {}", p.target_name))) };
    let root = p.root.to_string_lossy().into_owned();
    let text = crate::fsmemo::read_text(&py_path(&format!("{root}/{}", tu.file))).map_err(err)?;
    let asm = match unit_listing(p, tu, &text)? {
        Ok(a) => a,
        Err(e) => return Ok(Err(e)),
    };
    Ok(function_part(&asm, name).map(|part| (tu.file.clone(), part)).ok_or_else(|| format!("the listing of {} has no {name}", tu.file)))
}

/// `dcp listing NAME`: the function's part of VC6's listing.
pub fn listing_command(p: &Project, name: &str) -> Result<(Vec<String>, i32)> {
    use crate::cliread::{record, Tok};
    match of_function(p, name)? {
        Err(e) => Ok((vec![record(&[("name", Tok::S(name.into())), ("error", Tok::S(e))])], 1)),
        Ok((file, part)) => {
            let mut out = vec![record(&[("name", Tok::S(name.into())), ("file", Tok::S(file)), ("lines", Tok::I(part.len() as i64))])];
            out.extend(part);
            Ok((out, 0))
        }
    }
}

/// Each code line of a function's part that addresses a frame symbol through esp: (offset, the symbol, K of
/// `_x$[esp+K]`). The symbol's address is esp + K + N (N its `_x$ = N`).
pub fn symbol_depths(part: &[String]) -> Vec<(u32, String, i32)> {
    let mut out = vec![];
    for l in part {
        let t = l.trim_start();
        let Some(off) = t.split(['\t', ' ']).next().filter(|x| x.len() == 5 && x.chars().all(|c| c.is_ascii_hexdigit())) else { continue };
        let Some(i) = t.find("$[esp") else { continue };
        let sym: String = t[..i].chars().rev().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect::<Vec<_>>().into_iter().rev().collect();
        let sym = sym.trim_start_matches('_').to_string();
        // `$[esp+436]`, `$[esp-4]`, `$[esp+esi*4+436]`: K is the last term, with its sign
        let inner = &t[i + 5..t[i..].find(']').map(|e| e + i).unwrap_or(t.len())];
        let at = inner.rfind(['+', '-']).unwrap_or(0);
        let Ok(k) = inner[at..].trim_start_matches('+').parse::<i32>() else { continue };
        if let Ok(o) = u32::from_str_radix(off, 16) {
            out.push((o, sym, k));
        }
    }
    out
}
