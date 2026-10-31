//! Writing declarations into decompanion.toml without losing its comments: a line editor for the one-line
//! `key = value` form the project file uses (strings, integers and arrays of strings on one line,
//! `reason.<key>` dotted keys). Every edit is checked by parsing the result and comparing the value that was set.
//!
//! A table is `[name]` (the first table of that name) or the n-th `[[target]]`; a key is set in place when the
//! table has it, else appended after the table's last key line. A missing `[name]` table is appended at the end
//! of the file. The older one-reason form `reason = "..."` of a table is spelled out per key first
//! (`reason.<key> = "..."` for every key of the table it covered) so that a per-key reason can join it.

use regex::Regex;
use std::sync::LazyLock;

static HEADER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*\[\[?\s*([A-Za-z0-9_.\-]+)\s*\]\]?\s*(#.*)?$").unwrap());

/// A value the editor writes.
#[derive(Clone, Debug, PartialEq)]
pub enum TV {
    S(String),
    I(i64),
    L(Vec<String>),
}

fn str_text(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n"))
}

/// A TOML value on one line.
pub fn value_text(v: &TV) -> String {
    match v {
        TV::S(s) => str_text(s),
        TV::I(i) => i.to_string(),
        TV::L(l) => format!("[{}]", l.iter().map(|s| str_text(s)).collect::<Vec<_>>().join(", ")),
    }
}

fn same(v: &TV, got: Option<&toml::Value>) -> bool {
    match (v, got) {
        (TV::S(s), Some(toml::Value::String(g))) => s == g,
        (TV::I(i), Some(toml::Value::Integer(g))) => i == g,
        (TV::L(l), Some(toml::Value::Array(a))) => l.len() == a.len() && l.iter().zip(a).all(|(x, y)| y.as_str() == Some(x.as_str())),
        _ => false,
    }
}

/// (header line, end exclusive) of the table, None when absent. `index`: the n-th [[table]].
fn span(lines: &[String], table: &str, index: Option<usize>) -> Option<(usize, usize)> {
    let heads: Vec<(usize, String, bool)> = lines.iter().enumerate()
        .filter_map(|(i, l)| HEADER.captures(l).map(|m| (i, m[1].to_string(), l.trim_start().starts_with("[["))))
        .collect();
    let mut k = 0;
    for (j, (i, name, arr)) in heads.iter().enumerate() {
        if name != table || *arr != index.is_some() {
            continue;
        }
        if let Some(n) = index {
            if k != n {
                k += 1;
                continue;
            }
        }
        return Some((*i, heads.get(j + 1).map(|h| h.0).unwrap_or(lines.len())));
    }
    None
}

fn key_line(lines: &[String], lo: usize, hi: usize, key: &str) -> Option<usize> {
    let pat = Regex::new(&format!(r"^\s*{}\s*=", regex::escape(key).replace(r"\.", r"\s*\.\s*"))).unwrap();
    (lo + 1..hi).find(|&i| pat.is_match(&lines[i]))
}

fn last_key(lines: &[String], lo: usize, hi: usize) -> usize {
    (lo + 1..hi).filter(|&i| {
        let s = lines[i].trim();
        !s.is_empty() && !s.starts_with('#')
    }).last().unwrap_or(lo)
}

fn table_of<'a>(cfg: &'a toml::Table, table: &str, index: Option<usize>) -> Option<&'a toml::Table> {
    match (cfg.get(table), index) {
        (Some(toml::Value::Table(t)), None) | (Some(toml::Value::Table(t)), Some(0)) => Some(t),
        (Some(toml::Value::Array(a)), Some(i)) => a.get(i).and_then(|v| v.as_table()),
        _ => None,
    }
}

fn parse(text: &str, file: &str) -> Result<toml::Table, String> {
    text.parse::<toml::Table>().map_err(|e| format!("{file}: {}", e.message()))
}

/// Set `values` (dotted keys such as `reason.root`, in order) in one table of the file's text; the new text.
/// `covered`: the keys an older one-reason `reason = "..."` of the table speaks for.
pub fn set_keys_text(text: &str, file: &str, table: &str, values: &[(String, TV)], index: Option<usize>, covered: &[&str]) -> Result<String, String> {
    let mut lines: Vec<String> = text.split('\n').map(|s| s.to_string()).collect();
    let (lo, mut hi) = match span(&lines, table, index) {
        Some(s) => s,
        None => {
            if let Some(i) = index {
                return Err(format!("no [[{table}]] #{} in {file}", i + 1));
            }
            while lines.last().is_some_and(|l| l.trim().is_empty()) {
                lines.pop();
            }
            lines.extend(["".to_string(), format!("[{table}]"), "".to_string()]);
            (lines.len() - 2, lines.len())
        }
    };
    if values.iter().any(|(k, _)| k.starts_with("reason.")) {
        if let Some(old) = key_line(&lines, lo, hi, "reason") {
            if let Some(toml::Value::String(cur)) = parse(&lines[old], file)?.get("reason") {
                let cfg = parse(text, file)?;
                let tab = table_of(&cfg, table, index);
                let spelled: Vec<String> = covered.iter().filter(|k| tab.is_some_and(|t| t.contains_key(**k)))
                    .map(|k| format!("reason.{k} = {}", str_text(cur))).collect();
                hi = hi + spelled.len() - 1;
                lines.splice(old..old + 1, spelled);
            }
        }
    }
    for (key, v) in values {
        let line = format!("{key} = {}", value_text(v));
        match key_line(&lines, lo, hi, key) {
            Some(at) => lines[at] = line,
            None => {
                let at = last_key(&lines, lo, hi) + 1;
                lines.insert(at, line);
                hi += 1;
            }
        }
    }
    let mut new = lines.join("\n");
    if !new.ends_with('\n') {
        new.push('\n');
    }
    let cfg = parse(&new, file)?;
    let tab = table_of(&cfg, table, index);
    for (key, v) in values {
        let mut parts = key.split('.');
        let mut got = tab.and_then(|t| t.get(parts.next().unwrap()));
        for part in parts {
            got = got.and_then(|g| g.as_table()).and_then(|t| t.get(part));
        }
        if !same(v, got) {
            let g = got.map(|g| crate::project::toml_json(g).to_string()).unwrap_or_else(|| "None".into());
            return Err(format!("{file}: setting {key} in [{table}] gave {g}, not {}", value_text(v)));
        }
    }
    Ok(new)
}

/// set_keys_text on a file, written back (LF).
pub fn set_keys(path: &str, table: &str, values: &[(String, TV)], index: Option<usize>, covered: &[&str]) -> Result<String, String> {
    let text = crate::fsmemo::read_text(path).map_err(|e| format!("{path}: {e}"))?;
    let file = std::path::Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let new = set_keys_text(&text, &file, table, values, index, covered)?;
    std::fs::write(path, &new).map_err(|e| format!("{path}: {e}"))?;
    crate::fsmemo::new_epoch();
    Ok(new)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kv(pairs: &[(&str, TV)]) -> Vec<(String, TV)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    #[test]
    fn edits_keep_comments() {
        let text = "# top\n[[target]]\nname = \"a\"\n# a comment\n\n[[target]]\nname = \"b\"\n\n[analyzer]\n# why\nplugin = \"ghidra\"\n";
        let new = set_keys_text(text, "f", "target", &kv(&[("compiler", TV::S("cl 12".into())), ("reason.compiler", TV::S("x".into()))]), Some(1), &[]).unwrap();
        assert_eq!(new, "# top\n[[target]]\nname = \"a\"\n# a comment\n\n[[target]]\nname = \"b\"\ncompiler = \"cl 12\"\nreason.compiler = \"x\"\n\n[analyzer]\n# why\nplugin = \"ghidra\"\n");
        let new = set_keys_text(&new, "f", "analyzer", &kv(&[("plugin", TV::S("none".into())), ("timeout", TV::I(5)), ("reason", TV::S("r\"q".into()))]), None, &[]).unwrap();
        assert!(new.ends_with("[analyzer]\n# why\nplugin = \"none\"\ntimeout = 5\nreason = \"r\\\"q\"\n"), "{new}");
        let new = set_keys_text(&new, "f", "toolchain", &kv(&[("root", TV::S("C:/x".into()))]), None, &[]).unwrap();
        assert!(new.ends_with("reason = \"r\\\"q\"\n\n[toolchain]\nroot = \"C:/x\"\n"), "{new}");
        assert_eq!(set_keys_text(&new, "f", "target", &[], Some(5), &[]).unwrap_err(), "no [[target]] #6 in f");
        let flags = set_keys_text(&new, "f", "target", &kv(&[("cflags", TV::L(vec!["/O2".into(), "/Gy".into()]))]), Some(0), &[]).unwrap();
        assert!(flags.contains("name = \"a\"\ncflags = [\"/O2\", \"/Gy\"]\n# a comment"), "{flags}");
    }

    #[test]
    fn one_reason_spelled_out() {
        let text = "[toolchain]\nplugin = \"vc6\"\nroot = \"C:/a\"\nreason = \"old\"\n";
        let new = set_keys_text(text, "f", "toolchain", &kv(&[("root", TV::S("C:/b".into())), ("reason.root", TV::S("new".into()))]), None,
                                &["plugin", "root", "compiler"]).unwrap();
        assert_eq!(new, "[toolchain]\nplugin = \"vc6\"\nroot = \"C:/b\"\nreason.plugin = \"old\"\nreason.root = \"new\"\n");
    }
}
