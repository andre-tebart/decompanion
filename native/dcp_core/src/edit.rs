//! Edits of the typed state the layout commands make (dcp unit new / join / rename, dcp draft, dcp rename): the
//! whole-word rename over src/ and include/, the append-only names.log, include lines and declaration blocks in a
//! unit's head region (the lines before its first function: head_end) and the unit headers, a function inserted into
//! its unit's file, `git mv`. Every edit writes UTF-8 with LF.
//!
//! names.log (plan section 4): one line per rename event, appended, never rewritten (merge=union):
//!
//!     <ts> <addr|-> <kind> <old> -> <new> by:<checkout> why:<text>
//!
//! ts is the local time in ISO form to the second; addr the target address the name belongs to (`-` for a unit, a
//! type or a name without one); kind one of func, data, ident, unit; checkout `main` or the worktree's name.
//! Positions (a skip's (line, column)) are in characters, from 1.

use crate::project::py_path;
use regex::Regex;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::LazyLock;

pub const DCP_BLOCK: &str = "/* dcp draft: declarations of functions and data the unit uses that no included header declares */";

static TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?s)"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|//[^\n]*|/\*.*?\*/"#).unwrap());
static STRINGS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?m)"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|^[ \t]*#[ \t]*include\b[^\n]*"#).unwrap());
static INCLUDE_LINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^[ \t]*#[ \t]*include\b[^\n]*").unwrap());
pub static IDENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z_]\w*$").unwrap());

/// (file, line) per occurrence; {file: {(line, column)}} of positions to leave alone.
pub type Skip = HashMap<String, HashSet<(i64, i64)>>;

fn word(name: &str) -> Regex {
    Regex::new(&format!(r"\b{}\b", regex::escape(name))).unwrap()
}

/// str.splitlines.
pub fn splitlines(t: &str) -> Vec<&str> {
    let mut out = vec![];
    let mut start = 0;
    let mut it = t.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        if matches!(c, '\n' | '\r' | '\x0b' | '\x0c' | '\x1c' | '\x1d' | '\x1e' | '\u{85}' | '\u{2028}' | '\u{2029}') {
            out.push(&t[start..i]);
            let mut next = i + c.len_utf8();
            if c == '\r' {
                if let Some(&(j, '\n')) = it.peek() {
                    it.next();
                    next = j + 1;
                }
            }
            start = next;
        }
    }
    if start < t.len() {
        out.push(&t[start..]);
    }
    out
}

/// Every .c / .h file of src/ and include/: (project-relative posix path, full path).
pub fn sources(root: &str) -> Vec<(String, String)> {
    let mut out = vec![];
    for d in ["src", "include"] {
        let base = py_path(&format!("{root}/{d}"));
        if Path::new(&base).exists() {
            let mut fs: Vec<(String, String)> = crate::fsmemo::walk(&base, &["*.c".into(), "*.h".into()]).into_iter()
                .filter(|(_, p)| p.ends_with(".c") || p.ends_with(".h"))
                .map(|(r, p)| (format!("{d}/{}", r.replace('\\', "/")), p)).collect();
            fs.sort_by_key(|x| x.1.to_lowercase());
            out.extend(fs);
        }
    }
    out
}

pub fn read(path: &str) -> String {
    crate::fsmemo::read_text(path).unwrap_or_default()
}

/// Write a text (UTF-8, LF), the directories made; the file memo forgets its stamps.
pub fn write(path: &str, text: &str) -> Result<(), String> {
    write_bytes(path, text.as_bytes())
}

/// Windows refuses to truncate a file while another process holds a section of it mapped (ERROR_USER_MAPPED_FILE,
/// 1224: Git for Windows maps the working-tree files `git diff` reads, an editor or indexer may too); a sharing
/// violation (32, 33) is as passing. Such a refusal is waited out a while.
fn transient(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(1224 | 32 | 33))
}

/// Retry `f` while it fails transiently, up to about 3 s.
fn patiently<T>(mut f: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    let mut wait = 10;
    let mut spent = 0;
    loop {
        match f() {
            Err(e) if transient(&e) && spent < 3000 => {
                std::thread::sleep(std::time::Duration::from_millis(wait));
                spent += wait;
                wait = (wait * 2).min(400);
            }
            r => return r,
        }
    }
}

/// The bytes written in place, the directories made: the file is opened without truncation (a mapped section of it
/// held by another process refuses only a shrink), shrunk first when the new bytes are shorter (a refused shrink
/// leaves the file as it was), then written and cut to length. The file memo forgets its stamps.
pub fn write_bytes(path: &str, data: &[u8]) -> Result<(), String> {
    use std::io::{Seek, Write};
    if let Some(d) = Path::new(path).parent() {
        std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    let r = patiently(|| {
        let mut f = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
        let len = data.len() as u64;
        if f.metadata()?.len() > len {
            f.set_len(len)?;
        }
        f.seek(std::io::SeekFrom::Start(0))?;
        f.write_all(data)?;
        f.set_len(len)
    });
    crate::fsmemo::new_epoch();
    r.map_err(|e| format!("{path}: {e}"))
}

/// Append bytes to a file (made when missing); appending never truncates, so a mapped section held by another
/// process does not refuse it. The file memo forgets its stamps.
pub fn append(path: &str, text: &str) -> Result<(), String> {
    use std::io::Write;
    let r = patiently(|| {
        let mut f = std::fs::OpenOptions::new().append(true).create(true).open(path)?;
        f.write_all(text.as_bytes())
    });
    crate::fsmemo::new_epoch();
    r.map_err(|e| format!("{path}: {e}"))
}

/// (file, line) of every whole-word occurrence of name in src/ and include/ (comments included).
pub fn uses(root: &str, name: &str) -> Vec<(String, i64)> {
    let pat = word(name);
    let mut out = vec![];
    for (rel, p) in sources(root) {
        let text = read(&p);
        if !text.contains(name) || !pat.is_match(&text) {
            continue;
        }
        for (i, line) in splitlines(&text).iter().enumerate() {
            if pat.is_match(line) {
                out.push((rel.clone(), i as i64 + 1));
            }
        }
    }
    out
}

/// Every whole-word occurrence of an old name in code and comments replaced by its new one; string and character
/// literals and #include lines are left alone, and the occurrences at the (line, column) positions of `skip`.
/// Returns (text, replacements).
pub fn replace_words(text: &str, mapping: &BTreeMap<String, String>, skip: Option<&HashSet<(i64, i64)>>) -> (String, usize) {
    let mut olds: Vec<&String> = mapping.keys().collect();
    olds.sort_by_key(|o| std::cmp::Reverse(o.len()));
    let pat = Regex::new(&format!(r"\b({})\b", olds.iter().map(|o| regex::escape(o)).collect::<Vec<_>>().join("|"))).unwrap();
    let skip = skip.filter(|s| !s.is_empty());
    // line starts in characters, and the char index of every byte boundary of a line (for a skip's column)
    let starts: Vec<usize> = if skip.is_some() { std::iter::once(0).chain(text.match_indices('\n').map(|(i, _)| i + 1)).collect() } else { vec![] };
    let mut n = 0;
    let mut sub = |seg: &str, base: usize, out: &mut String| {
        let mut last = 0;
        for m in pat.captures_iter(seg) {
            let g = m.get(0).unwrap();
            out.push_str(&seg[last..g.start()]);
            let at = base + g.start();
            let keep = skip.is_some_and(|s| {
                let line = starts.partition_point(|&x| x <= at);
                let col = text[starts[line - 1]..at].chars().count() as i64 + 1;
                s.contains(&(line as i64, col))
            });
            if keep {
                out.push_str(g.as_str());
            } else {
                n += 1;
                out.push_str(&mapping[&m[1]]);
            }
            last = g.end();
        }
        out.push_str(&seg[last..]);
    };
    let mut out = String::with_capacity(text.len());
    let mut pos = 0;
    for m in STRINGS.find_iter(text) {
        sub(&text[pos..m.start()], pos, &mut out);
        out.push_str(m.as_str());
        pos = m.end();
    }
    sub(&text[pos..], pos, &mut out);
    (out, n)
}

/// Replace every whole-word occurrence of each old name by its new one in one pass over src/ and include/ (not
/// inside string literals or #include lines; not at the positions skip[file] gives). {file: replacements};
/// `dry` counts them and writes nothing.
pub fn rename_words(root: &str, mapping: &BTreeMap<String, String>, dry: bool, skip: Option<&Skip>) -> Result<BTreeMap<String, usize>, String> {
    let mut out = BTreeMap::new();
    if mapping.is_empty() {
        return Ok(out);
    }
    for (rel, p) in sources(root) {
        let text = read(&p);
        if !mapping.keys().any(|o| text.contains(o.as_str())) {
            continue;
        }
        let (new, n) = replace_words(&text, mapping, skip.and_then(|s| s.get(&rel)));
        if n > 0 {
            if !dry {
                write(&p, &new)?;
            }
            out.insert(rel, n);
        }
    }
    Ok(out)
}

/// Every identifier of src/ and include/ that starts with prefix (prefix itself included when it occurs).
pub fn words_with_prefix(root: &str, prefix: &str) -> HashSet<String> {
    let pat = Regex::new(&format!(r"\b{}\w*", regex::escape(prefix))).unwrap();
    let mut out = HashSet::new();
    for (_, p) in sources(root) {
        let text = read(&p);
        if text.contains(prefix) {
            out.extend(pat.find_iter(&text).map(|m| m.as_str().to_string()));
        }
    }
    out
}

/// (file, line) of every occurrence of name as an identifier of the code (comments, strings and #include lines
/// blanked), but those at the (line, column) positions skip[file] gives: what a rename to `name` would collide with.
pub fn code_uses(root: &str, name: &str, skip: Option<&Skip>) -> Vec<(String, i64)> {
    let pat = word(name);
    let mut out = vec![];
    let empty = HashSet::new();
    for (rel, p) in sources(root) {
        let text = read(&p);
        if !text.contains(name) || !pat.is_match(&text) {
            continue;
        }
        let blank = TOKEN.replace_all(&text, |c: &regex::Captures| c[0].chars().map(|ch| if ch == '\n' { '\n' } else { ' ' }).collect::<String>());
        let blank = INCLUDE_LINE.replace_all(&blank, "");
        let local = skip.and_then(|s| s.get(&rel)).unwrap_or(&empty);
        for (i, line) in splitlines(&blank).iter().enumerate() {
            let ln = i as i64 + 1;
            if pat.find_iter(line).any(|m| !local.contains(&(ln, line[..m.start()].chars().count() as i64 + 1))) {
                out.push((rel.clone(), ln));
            }
        }
    }
    out
}

pub fn checkout_name(root: &str) -> String {
    if Path::new(root).join(".dcp").join("main_store").exists() {
        Path::new(root).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
    } else {
        "main".into()
    }
}

/// Append one names.log line per (addr, kind, old, new).
pub fn log_names(root: &str, events: &[(Option<i64>, &str, String, String)], why: &str) -> Result<(), String> {
    let events: Vec<(Option<i64>, &str, String, String, &str)> = events.iter().map(|(a, k, o, n)| (*a, *k, o.clone(), n.clone(), why)).collect();
    log_names_each(root, &events)
}

/// Append one names.log line per (addr, kind, old, new, why), all in one append: the log is never rewritten (a write
/// that truncated it would be refused while another process maps it).
pub fn log_names_each(root: &str, events: &[(Option<i64>, &str, String, String, &str)]) -> Result<(), String> {
    if events.is_empty() {
        return Ok(());
    }
    let ts = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S").to_string();
    let by = checkout_name(root);
    let mut lines: String = events.iter().map(|(a, k, o, n, why)| {
        let why = why.split(crate::srcscan::py_space).filter(|w| !w.is_empty()).collect::<Vec<_>>().join(" ");
        let a = a.map(|a| format!("{a:#010x}")).unwrap_or_else(|| "-".into());
        format!("{ts} {a} {k} {o} -> {n} by:{by} why:{why}\n")
    }).collect();
    let path = py_path(&format!("{root}/names.log"));
    let last = std::fs::read(&path).ok().and_then(|b| b.last().copied());
    if last.is_some_and(|c| c != b'\n') {
        lines.insert(0, '\n');
    }
    append(&path, &lines)
}

fn git(root: &str, args: &[&str]) -> std::process::Output {
    std::process::Command::new("git").args(args).current_dir(root).output()
        .unwrap_or_else(|e| std::process::Output { status: std::process::ExitStatus::default(), stdout: vec![], stderr: e.to_string().into_bytes() })
}

fn rel_of(root: &str, p: &str) -> String {
    Path::new(p).strip_prefix(root).map(|r| r.to_string_lossy().replace('\\', "/")).unwrap_or_else(|_| p.replace('\\', "/"))
}

fn tracked(root: &str, p: &str) -> bool {
    git(root, &["ls-files", "--error-unmatch", &rel_of(root, p)]).status.success()
}

/// git mv when the file is tracked, else a plain rename.
pub fn move_file(root: &str, src: &str, dst: &str) -> Result<(), String> {
    if let Some(d) = Path::new(dst).parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    if Path::new(root).join(".git").exists() && tracked(root, src) {
        let r = git(root, &["mv", &rel_of(root, src), &rel_of(root, dst)]);
        if !r.status.success() {
            return Err(format!("git mv {src} {dst}: {}", String::from_utf8_lossy(&r.stderr).trim()));
        }
    } else {
        std::fs::rename(src, dst).map_err(|e| format!("{src} -> {dst}: {e}"))?;
    }
    crate::fsmemo::new_epoch();
    Ok(())
}

/// git rm (tracked) or delete a file.
pub fn remove(root: &str, p: &str) -> Result<(), String> {
    if !Path::new(p).exists() {
        return Ok(());
    }
    if Path::new(root).join(".git").exists() && tracked(root, p) {
        let r = git(root, &["rm", "-q", "-f", &rel_of(root, p)]);
        if !r.status.success() {
            return Err(format!("git rm {p}: {}", String::from_utf8_lossy(&r.stderr).trim()));
        }
    }
    if Path::new(p).exists() {
        std::fs::remove_file(p).map_err(|e| e.to_string())?;
    }
    crate::fsmemo::new_epoch();
    Ok(())
}

// ------------------------------------------------------------------------------------------------ head region / headers

/// The 0-based line index where a unit file's head region ends: its first function's address comment (else its first
/// definition; the file's end without one), from the scan.
pub fn head_end(root: &str, rel: &str) -> Result<usize, String> {
    let sc = crate::frontend::scan(root, None)?;
    let mut lines: Vec<i64> = sc.functions().filter(|f| f.0 .0 == rel).map(|f| f.1 .3).collect();
    if let Some(m) = sc.models.get(rel) {
        lines.extend(m.defs.iter().map(|d| d.0));
    }
    let p = py_path(&format!("{root}/{rel}"));
    let n = if Path::new(&p).exists() { read(&p).matches('\n').count() as i64 + 1 } else { 0 };
    Ok((lines.into_iter().min().unwrap_or(n + 1) - 1).max(0) as usize)
}

fn text_or_empty(path: &str) -> String {
    if Path::new(path).exists() { std::fs::read_to_string(path).unwrap_or_default().replace("\r\n", "\n") } else { String::new() }
}

/// Insert a function's text (its address comment first) into a unit's file before the line `before` (1-based: the
/// next function's address comment), else at the end, a blank line between it and its neighbours.
pub fn insert_function(path: &str, block: &str, before: Option<i64>) -> Result<(), String> {
    let text = text_or_empty(path);
    let mut lines: Vec<String> = if text.trim().is_empty() { vec![] } else { text.trim_end_matches('\n').split('\n').map(|l| l.to_string()).collect() };
    let new: Vec<String> = block.trim_end_matches('\n').split('\n').map(|l| l.to_string()).collect();
    match before {
        Some(b) if b >= 1 && (b as usize) <= lines.len() => {
            let at = b as usize - 1;
            lines.splice(at..at, new.into_iter().chain(std::iter::once(String::new())));
        }
        _ => {
            lines.push(String::new());
            lines.extend(new);
        }
    }
    write(path, &(lines.join("\n") + "\n"))
}

fn block_line(lines: &[String]) -> Option<usize> {
    lines.iter().position(|l| l == DCP_BLOCK)
}

fn non_word(unit: &str) -> String {
    unit.chars().map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' }).collect()
}

pub fn guard(unit: &str) -> String {
    non_word(unit).to_uppercase() + "_H"
}

/// The unit name as part of a C identifier (`.` and `-` become `_`).
pub fn c_name(unit: &str) -> String {
    non_word(unit)
}

fn lines_of(text: &str) -> Vec<String> {
    splitlines(text).into_iter().map(|l| l.to_string()).collect()
}

/// Add an #include line after the last #include of the file's first `end` lines (the whole file without), else
/// after its leading comment; false when the file has it already.
pub fn ensure_include(path: &str, line: &str, end: Option<usize>) -> Result<bool, String> {
    let text = text_or_empty(path);
    if splitlines(&text).iter().any(|l| l.trim() == line.trim()) {
        return Ok(false);
    }
    let mut lines = lines_of(&text);
    let head = &lines[..end.unwrap_or(lines.len()).min(lines.len())];
    let at: i64 = match head.iter().rposition(|l| l.trim_start().starts_with("#include")) {
        Some(i) => i as i64,
        None if lines.first().is_some_and(|l| l.trim_start().starts_with("/*")) => lines.iter().position(|l| l.contains("*/")).map(|i| i as i64).unwrap_or(-1),
        None => -1,
    };
    lines.insert((at + 1) as usize, line.to_string());
    write(path, &(lines.join("\n") + "\n"))?;
    Ok(true)
}

/// A declaration or definition of `name` (a function or an extern) in a C text.
pub fn declared_in(text: &str, name: &str) -> bool {
    let code = TOKEN.replace_all(text, " ");
    let e = regex::escape(name);
    Regex::new(&format!(r"\b{e}\s*\(")).unwrap().is_match(&code) || Regex::new(&format!(r"\bextern\b[^;]*\b{e}\b")).unwrap().is_match(&code)
}

/// Append a declaration line to the dcp draft block of a unit's file (created at the end of its head region, the
/// first `end` lines; at the end of the file without); false when the head declares the name already.
pub fn add_declaration(path: &str, decl: &str, name: &str, end: Option<usize>) -> Result<bool, String> {
    let mut lines = lines_of(&text_or_empty(path));
    let head_n = end.unwrap_or(lines.len()).min(lines.len());
    if declared_in(&lines[..head_n].join("\n"), name) {
        return Ok(false);
    }
    if block_line(&lines).is_none() {
        let mut at = match end { None => lines.len(), Some(e) => e.min(lines.len()) };
        while at > 0 && lines[at - 1].trim().is_empty() {
            at -= 1;
        }
        let mut add = if at > 0 { vec![String::new()] } else { vec![] };
        add.extend([DCP_BLOCK.to_string(), String::new()]);
        lines.splice(at..at, add);
    }
    let mut i = block_line(&lines).unwrap() + 1;
    while i < lines.len() && !lines[i].trim().is_empty() && !lines[i].starts_with("/*") {
        i += 1;
    }
    lines.insert(i, decl.to_string());
    write(path, &(lines.join("\n") + "\n"))?;
    Ok(true)
}

/// Remove the lines of the dcp draft block that declare `name`.
pub fn drop_declarations(path: &str, name: &str) -> Result<bool, String> {
    if !Path::new(path).exists() {
        return Ok(false);
    }
    let lines = lines_of(&text_or_empty(path));
    let Some(b) = block_line(&lines) else { return Ok(false) };
    let e = regex::escape(name);
    let pat = Regex::new(&format!(r"\b{e}\s*\(|\b{e}\s*;")).unwrap();
    let mut i = b + 1;
    let mut out: Vec<String> = lines[..i].to_vec();
    let mut changed = false;
    while i < lines.len() && !lines[i].trim().is_empty() && !lines[i].starts_with("/*") {
        if pat.is_match(&lines[i]) {
            changed = true;
        } else {
            out.push(lines[i].clone());
        }
        i += 1;
    }
    out.extend(lines[i..].iter().cloned());
    if changed {
        write(path, &(out.join("\n") + "\n"))?;
    }
    Ok(changed)
}

/// Insert a prototype / extern line before the header's closing #endif (the guard is created when the header is
/// new); false when the header declares the name already.
pub fn add_to_header(path: &str, unit: &str, line: &str, name: &str) -> Result<bool, String> {
    let text = if Path::new(path).exists() { text_or_empty(path) } else { header_text(unit, "") };
    if declared_in(&text, name) {
        return Ok(false);
    }
    let mut lines = lines_of(text.trim_end_matches('\n'));
    let at = lines.iter().rposition(|l| l.trim().starts_with("#endif")).unwrap_or(lines.len());
    lines.insert(at, line.to_string());
    write(path, &(lines.join("\n") + "\n"))?;
    Ok(true)
}

/// Put a line (an #include) right after the header's `#define <GUARD>`; false when the header has it.
pub fn ensure_after_guard(path: &str, unit: &str, line: &str) -> Result<bool, String> {
    let text = text_or_empty(path);
    if splitlines(&text).iter().any(|l| l.trim() == line.trim()) {
        return Ok(false);
    }
    let mut lines = lines_of(&text);
    let g = format!("#define {}", guard(unit));
    let at = lines.iter().position(|l| l.trim() == g).map(|i| i + 1).unwrap_or(0);
    lines.insert(at, line.to_string());
    write(path, &(lines.join("\n") + "\n"))?;
    Ok(true)
}

pub fn header_text(unit: &str, what: &str) -> String {
    let g = guard(unit);
    let what = if what.is_empty() { String::new() } else { format!(": {what}") };
    format!("/* {unit}.h: the public prototypes and extern declarations of unit {unit}{what} */\n#ifndef {g}\n#define {g}\n\n#endif\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rename_leaves_strings_and_includes() {
        let m: BTreeMap<String, String> = [("old".to_string(), "new".to_string())].into_iter().collect();
        let (t, n) = replace_words("#include \"old.h\"\nint old; /* old */ char *s = \"old\"; int older;\n", &m, None);
        assert_eq!((t.as_str(), n), ("#include \"old.h\"\nint new; /* new */ char *s = \"old\"; int older;\n", 2));
        // a skipped position (line 2, column 5) stays
        let skip: HashSet<(i64, i64)> = [(2, 5)].into_iter().collect();
        let (t, n) = replace_words("x\nint old; old = 1;\n", &m, Some(&skip));
        assert_eq!((t.as_str(), n), ("x\nint old; new = 1;\n", 1));
    }

    #[test]
    fn rename_follows_comments_not_strings() {
        let m: BTreeMap<String, String> = [("net".to_string(), "socket_net".to_string())].into_iter().collect();
        let text = "/* net: f calls net */\n#include \"net.h\"\nchar *s = \"net\";\nint net(void);\nint f(void) { return net(); }\n";
        let (new, n) = replace_words(text, &m, None);
        assert_eq!(n, 4);
        assert!(new.contains("#include \"net.h\"") && new.contains("\"net\"") && new.contains("int socket_net(void);"));
        assert!(new.contains("/* socket_net: f calls socket_net */"));
    }

    #[test]
    fn write_in_place_and_append() {
        let dir = std::env::temp_dir().join(format!("dcp-write-{}", std::process::id()));
        let p = dir.join("f.txt").to_string_lossy().into_owned();
        write(&p, "a longer first text\n").unwrap();
        write(&p, "short\n").unwrap(); // shrunk: no tail of the old text stays
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "short\n");
        write(&p, "grown past the old length\n").unwrap();
        append(&p, "more\n").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "grown past the old length\nmore\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn head_edits() {
        assert_eq!(guard("d3.io-x"), "D3_IO_X_H");
        assert!(declared_in("int f(void);", "f") && declared_in("extern int x[3];", "x") && !declared_in("/* f( */ int g;", "f"));
        let dir = std::env::temp_dir().join(format!("dcp-edit-{}", std::process::id()));
        let p = dir.join("u.c").to_string_lossy().into_owned();
        write(&p, "/* u: the unit\n   more */\nint a;\n").unwrap();
        assert!(ensure_include(&p, "#include \"u.h\"", None).unwrap());
        assert!(!ensure_include(&p, "#include \"u.h\"", None).unwrap());
        assert!(add_declaration(&p, "int f();", "f", None).unwrap());
        assert!(add_declaration(&p, "extern int g;", "g", None).unwrap());
        assert_eq!(read(&p), format!("/* u: the unit\n   more */\n#include \"u.h\"\nint a;\n\n{DCP_BLOCK}\nint f();\nextern int g;\n\n"));
        assert!(drop_declarations(&p, "f").unwrap());
        insert_function(&p, "/* 0x1000, f */\nvoid f(void)\n{\n}\n", None).unwrap();
        assert!(read(&p).ends_with("extern int g;\n\n/* 0x1000, f */\nvoid f(void)\n{\n}\n"));
        let h = dir.join("u.h").to_string_lossy().into_owned();
        assert!(add_to_header(&h, "u", "void f(void);", "f").unwrap());
        assert!(ensure_after_guard(&h, "u", "#include \"t.h\"").unwrap());
        assert_eq!(read(&h), "/* u.h: the public prototypes and extern declarations of unit u */\n#ifndef U_H\n#define U_H\n#include \"t.h\"\n\nvoid f(void);\n#endif\n");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
