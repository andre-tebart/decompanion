//! `dcp try NAME [FILE] [--move-line N --to A..B] [--apply LABEL]` (improvement-reports/variant-runner.md): source
//! variants of one function, each compiled in a scratch copy of its unit (build/trial/, as the tie-break probes
//! compile: the unit's flags, its directory before include/, in parallel) and graded as G.grade grades it. Nothing
//! in the tree or the ledger changes unless `--apply` names the variant to write.
//!
//! The variants file: each variant starts with a line `### label`. Its body is either the function's whole new text
//! (from its address comment to the end of its definition) or one or more replacements within the function's text:
//!
//! ```text
//! ### index loop
//! <<<
//!     for (p = list; *p; p++)
//! ===
//!     for (i = 0; list[i]; i++)
//! >>>
//! ```
//!
//! An old text must occur exactly once in the function (not in the file: a twin function's equal lines are never
//! touched, improvement-reports/fn-edit-by-name.md). `--move-line N --to A..B` adds a variant for each place in
//! A..B the file's line N (a declaration inside the function) can move to.
//!
//! The table: one row per variant with the grade, the distance (differing instructions on both sides, differing
//! bytes) and the hunk classes, and a hash of the object code (the relocated fields masked, the compiler's numbered
//! names by kind): variants with the same code are listed as `= label`, which shows the source levers VC6 ignores.

use crate::error::{Error, Result};
use crate::project::{py_path, Project};
use std::collections::HashMap;

fn err(e: impl std::fmt::Display) -> Error {
    Error::value(e.to_string())
}

/// One variant: its label and its edit of the function's text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Variant {
    pub label: String,
    pub edit: Edit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Edit {
    /// the function's whole new text
    Whole(String),
    /// (old, new) replacements within the function's text, in order
    Pairs(Vec<(String, String)>),
    /// the function's line (an index into its lines) moved before another (an index; the length: after the last)
    Move(usize, usize),
}

/// The variants of a variants file, or what is wrong with it.
pub fn parse(text: &str) -> std::result::Result<Vec<Variant>, String> {
    let text = text.replace("\r\n", "\n");
    let mut out: Vec<Variant> = vec![];
    let mut cur: Option<(String, Vec<&str>, usize)> = None;
    let finish = |cur: Option<(String, Vec<&str>, usize)>, out: &mut Vec<Variant>| -> std::result::Result<(), String> {
        let Some((label, body, line)) = cur else { return Ok(()) };
        // trailing blank lines are the gap before the next variant
        let mut body = body;
        while body.last().is_some_and(|l| l.trim().is_empty()) {
            body.pop();
        }
        while body.first().is_some_and(|l| l.trim().is_empty()) {
            body.remove(0);
        }
        if body.is_empty() {
            return Err(format!("line {line}: variant `{label}` is empty"));
        }
        if out.iter().any(|v| v.label == label) {
            return Err(format!("line {line}: a second variant `{label}`"));
        }
        let edit = if body[0].trim() == "<<<" {
            let mut pairs = vec![];
            let mut k = 0;
            while k < body.len() {
                if body[k].trim().is_empty() {
                    k += 1;
                    continue;
                }
                if body[k].trim() != "<<<" {
                    return Err(format!("variant `{label}`: `{}` outside a <<< === >>> block", body[k]));
                }
                let mid = body[k..].iter().position(|l| l.trim() == "===").map(|i| i + k).ok_or_else(|| format!("variant `{label}`: <<< without ==="))?;
                let end = body[mid..].iter().position(|l| l.trim() == ">>>").map(|i| i + mid).ok_or_else(|| format!("variant `{label}`: === without >>>"))?;
                let old = body[k + 1..mid].join("\n");
                if old.trim().is_empty() {
                    return Err(format!("variant `{label}`: an empty old text"));
                }
                pairs.push((old, body[mid + 1..end].join("\n")));
                k = end + 1;
            }
            Edit::Pairs(pairs)
        } else {
            Edit::Whole(body.join("\n"))
        };
        out.push(Variant { label, edit });
        Ok(())
    };
    for (i, l) in text.lines().enumerate() {
        if let Some(label) = l.strip_prefix("###") {
            finish(cur.take(), &mut out)?;
            let label = label.trim().to_string();
            if label.is_empty() || label.contains(char::is_whitespace) && label.len() > 60 {
                return Err(format!("line {}: a variant needs a short label after ###", i + 1));
            }
            cur = Some((label, vec![], i + 1));
        } else if let Some(c) = cur.as_mut() {
            c.1.push(l);
        } else if !l.trim().is_empty() {
            return Err(format!("line {}: text before the first ### label", i + 1));
        }
    }
    finish(cur, &mut out)?;
    Ok(out)
}

/// The function's text with a variant applied (the text: its lines joined by \n), or why it does not apply.
pub fn apply(func: &str, edit: &Edit) -> std::result::Result<String, String> {
    match edit {
        Edit::Whole(t) => Ok(t.clone()),
        Edit::Pairs(pairs) => {
            let mut t = func.to_string();
            for (old, new) in pairs {
                let n = t.matches(old.as_str()).count();
                if n != 1 {
                    let first = old.lines().find(|l| !l.trim().is_empty()).unwrap_or("").trim();
                    return Err(format!("the old text `{first}`.. occurs {n} times in the function (once needed)"));
                }
                t = t.replacen(old.as_str(), new, 1);
            }
            Ok(t)
        }
        Edit::Move(from, to) => {
            let mut lines: Vec<&str> = func.split('\n').collect();
            if *from >= lines.len() || *to > lines.len() {
                return Err("the line is outside the function".into());
            }
            let l = lines.remove(*from);
            let at = if to > from { to - 1 } else { *to };
            lines.insert(at, l);
            Ok(lines.join("\n"))
        }
    }
}

/// The variants that move the function's line `line` (a file line) before each line of `to` (file lines, `hi + 1`:
/// after the line hi), its own place left out. `first`: the function's first file line, `n`: its line count.
pub fn moves(line: i64, to: (i64, i64), first: i64, n: usize) -> std::result::Result<Vec<Variant>, String> {
    let idx = |l: i64| -> Option<usize> { (l >= first && ((l - first) as usize) <= n).then(|| (l - first) as usize) };
    let from = idx(line).filter(|&k| k < n).ok_or_else(|| format!("line {line} is not in the function (lines {first}..{})", first + n as i64 - 1))?;
    let mut out = vec![];
    for t in to.0..=to.1 {
        let k = idx(t).ok_or_else(|| format!("line {t} is not in the function (lines {first}..{})", first + n as i64 - 1))?;
        if k == from || k == from + 1 {
            continue;
        }
        out.push(Variant { label: format!("L{line}->before-L{t}"), edit: Edit::Move(from, k) });
    }
    Ok(out)
}

/// A short hash of a compiled function's code key (tiebreak::code_key): FNV-1a, 8 hex digits.
fn short_hash(key: &(Vec<u8>, Vec<(u32, String)>)) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |b: u8| {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    };
    key.0.iter().for_each(|&b| eat(b));
    for (off, n) in &key.1 {
        off.to_le_bytes().iter().for_each(|&b| eat(b));
        n.bytes().for_each(&mut eat);
        eat(0);
    }
    format!("{:08x}", (h ^ (h >> 32)) as u32)
}

/// One row of the table.
struct Row {
    label: String,
    outcome: std::result::Result<(String, usize, usize, String, String), String>, // grade, ins, bytes, hunks, hash
    same_as: Option<String>,
}

/// `dcp try`: the lines and the exit status.
pub fn try_command(p: &Project, name: &str, file: Option<&str>, move_line: Option<i64>, to: Option<&str>, apply_label: Option<&str>) -> Result<(Vec<String>, i32)> {
    use crate::cliread::{fmt_addr, record, Tok};
    let s = |x: &str| Tok::S(x.to_string());
    let fail = |e: String| -> Result<(Vec<String>, i32)> { Ok((vec![record(&[("name", s(name)), ("error", s(&e))])], 1)) };
    let root = p.root.to_string_lossy().into_owned();
    let db = p.store_path();
    let rows = crate::queues::function_grades(&db)?;
    let Some(row) = rows.iter().find(|r| r["name"].as_str() == Some(name)) else { return fail(format!("no graded function {name} (dcp build first)")) };
    let (a, unit, built) = (row["addr"].as_i64().unwrap_or(0), row["unit"].as_str().unwrap_or("").to_string(), row["code"].as_str().unwrap_or("").to_string());
    let plan = crate::plan::plan(p).map_err(err)?;
    let Some(t) = plan.iter().find(|t| t.unit == unit) else { return fail(format!("no unit {unit} in target {}", p.target_name)) };
    let srcs = crate::with_db(&db, |c| crate::store::claims_of(c, &db, "source", None, |f| &*f.rule == "L.src" && f.s("what") == Some("func") && f.lo == a))?;
    let Some(src) = srcs.first() else { return fail(format!("{name} has no source span")) };
    let (sfile, comment, end) = (src.s("file").unwrap_or("").to_string(), src.value["comment"].as_i64().unwrap_or(0), src.value["end"].as_i64().unwrap_or(0));
    if sfile != t.file {
        return fail(format!("{name} is defined in {sfile}, not in its unit's file {} (an included file: not supported)", t.file));
    }
    let path = py_path(&format!("{root}/{sfile}"));
    let raw = crate::fsmemo::read_text(&path).map_err(err)?;
    let crlf = raw.contains("\r\n");
    let text = raw.replace("\r\n", "\n");
    let lines: Vec<&str> = text.split('\n').collect();
    let (lo, hi) = ((comment.max(1) - 1) as usize, (end.max(comment) as usize).min(lines.len()));
    if lo >= hi {
        return fail(format!("{name}: its span {comment}..{end} is not in {sfile}"));
    }
    let func = lines[lo..hi].join("\n");
    let unit_text = |f: &str| -> String {
        let mut v: Vec<&str> = lines[..lo].to_vec();
        v.extend(f.split('\n'));
        v.extend(&lines[hi..]);
        v.join("\n")
    };
    // the variants: the file's, then the generated moves
    let mut variants = match file {
        Some(f) => match std::fs::read_to_string(f) {
            Ok(x) => match parse(&x) {
                Ok(v) => v,
                Err(e) => return fail(format!("{f}: {e}")),
            },
            Err(e) => return fail(format!("{f}: {e}")),
        },
        None => vec![],
    };
    if let Some(l) = move_line {
        let range = match to.and_then(|x| x.split_once("..")).and_then(|(x, y)| Some((x.trim().parse::<i64>().ok()?, y.trim().parse::<i64>().ok()?))) {
            Some(r) => r,
            None => return fail("--move-line needs --to A..B (file lines)".into()),
        };
        match moves(l, range, comment, hi - lo) {
            Ok(v) => variants.extend(v),
            Err(e) => return fail(e),
        }
    }
    if variants.is_empty() {
        return fail("no variants (a variants file, or --move-line N --to A..B)".into());
    }
    if let Some(lb) = apply_label {
        let Some(v) = variants.iter().find(|v| v.label == lb) else { return fail(format!("no variant `{lb}`")) };
        let new = apply(&func, &v.edit).map_err(err)?;
        let out = unit_text(&new);
        crate::edit::write(&path, &if crlf { out.replace('\n', "\r\n") } else { out }).map_err(Error::value)?;
        return Ok((vec![record(&[("fn", s(&fmt_addr(a))), ("name", s(name)), ("applied", s(lb)), ("file", s(&sfile))]),
                        format!("{sfile}: {name} replaced by variant `{lb}`; dcp build to grade it")], 0));
    }
    // the control (the unit as it is) and the variants that apply, compiled together
    let texts: Vec<std::result::Result<String, String>> = variants.iter().map(|v| apply(&func, &v.edit)).collect();
    let mut jobs = vec![crate::tiebreak::Job { unit: t, tag: "tctl".into(), prefix: String::new(), text: text.clone() }];
    let mut job_of: HashMap<usize, usize> = HashMap::new();
    for (k, x) in texts.iter().enumerate() {
        if let Ok(f) = x {
            job_of.insert(k, jobs.len());
            jobs.push(crate::tiebreak::Job { unit: t, tag: format!("t{k}"), prefix: String::new(), text: unit_text(f) });
        }
    }
    let objs = crate::tiebreak::compile(p, &jobs)?;
    let bench = crate::tiebreak::Bench::of(p)?;
    let mut seen: Vec<(String, String, (String, usize, usize, String, String))> = vec![]; // hash, label, outcome
    let mut measure = |label: &str, o: &std::result::Result<crate::coff::Obj, String>| -> (std::result::Result<(String, usize, usize, String, String), String>, Option<String>) {
        let o = match o {
            Err(e) => return (Err(format!("does not compile: {e}")), None),
            Ok(o) => o,
        };
        let Some(&j) = o.function_index().get(name) else { return (Err(format!("{name} is not in the compiled unit")), None) };
        let c = o.function_code(j);
        let h = short_hash(&crate::tiebreak::code_key(o, &c));
        if let Some(x) = seen.iter().find(|x| x.0 == h) {
            return (Ok(x.2.clone()), Some(x.1.clone()));
        }
        let g = bench.grade(o, &c, a).to_string();
        let (ins, bytes, hunks) = bench.distance(o, &c, a);
        let r = (g, ins, bytes, hunks, h.clone());
        seen.push((h, label.to_string(), r.clone()));
        (Ok(r), None)
    };
    let mut table: Vec<Row> = vec![];
    let (c, _) = measure("control", &objs[0]);
    if let Ok(x) = &c {
        if x.0 != built {
            table.push(Row { label: "(note)".into(), outcome: Err(format!("the control compiles to {}, the build says {built}: a stale build (dcp build) or a \
                                                                          tie-break of the trial's form", x.0)), same_as: None });
        }
    }
    table.insert(0, Row { label: "control".into(), outcome: c, same_as: None });
    for (k, v) in variants.iter().enumerate() {
        let (outcome, same_as) = match (&texts[k], job_of.get(&k)) {
            (Err(e), _) => (Err(format!("does not apply: {e}")), None),
            (Ok(_), Some(&j)) => measure(&v.label, &objs[j]),
            (Ok(_), None) => (Err("not compiled".into()), None),
        };
        table.push(Row { label: v.label.clone(), outcome, same_as });
    }
    let width = table.iter().map(|r| r.label.chars().count()).max().unwrap_or(7).clamp(7, 40);
    let rank = |g: &str| ["draft", "shape", "byte"].iter().position(|x| *x == g);
    let ok: Vec<&Row> = table.iter().filter(|r| r.label != "control" && r.outcome.is_ok()).collect();
    let mut out = vec![record(&[("fn", s(&fmt_addr(a))), ("name", s(name)), ("unit", s(&unit)), ("built", s(&built)), ("variants", Tok::I(variants.len() as i64)),
                                ("compiled", Tok::I(ok.len() as i64)), ("codegens", Tok::I(seen.len() as i64))])];
    out.push(format!("  {:<width$}  {:<5}  {:>5}  {:>5}  {:<8}  hunks", "variant", "grade", "ins", "bytes", "code"));
    for r in &table {
        match (&r.outcome, &r.same_as) {
            (Ok((g, ins, bytes, hunks, h)), None) => {
                let mark = if g == "byte" { "  BYTE" } else { "" };
                out.push(format!("  {:<width$}  {g:<5}  {ins:>5}  {bytes:>5}  {h:<8}  {hunks}{mark}", r.label));
            }
            (Ok((g, ins, bytes, _, h)), Some(x)) => out.push(format!("  {:<width$}  {g:<5}  {ins:>5}  {bytes:>5}  {h:<8}  = {x} (the same code)", r.label)),
            (Err(e), _) => out.push(format!("  {:<width$}  {e}", r.label)),
        }
    }
    // the best variant: the highest grade, then the fewest differing instructions, then bytes
    let best = ok.iter().filter_map(|r| r.outcome.as_ref().ok().map(|o| (r, o))).min_by_key(|(_, o)| (std::cmp::Reverse(rank(&o.0)), o.1, o.2));
    if let Some((r, o)) = best {
        let ctl = table[0].outcome.as_ref().ok();
        let better = ctl.is_none_or(|c| (std::cmp::Reverse(rank(&o.0)), o.1, o.2) < (std::cmp::Reverse(rank(&c.0)), c.1, c.2));
        out.push(if better {
            format!("best: {} ({}, {} ins / {} bytes): dcp try {name} ... --apply {} writes it", r.label, o.0, o.1, o.2, r.label)
        } else {
            "best: none closer than the control".to_string()
        });
    }
    let same = table.iter().filter(|r| r.same_as.as_deref() == Some("control")).count();
    if same > 0 {
        out.push(format!("{same} variant(s) compile to the control's code: those source changes are no lever for VC6 here"));
    }
    Ok((out, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_parse_and_apply() {
        let file = "### whole\n/* 0x1 */\nint f(void) { return 2; }\n\n### pairs\n<<<\n  a = 1;\n===\n  a = 2;\n>>>\n<<<\nb\n===\nc\n>>>\n";
        let v = parse(file).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0], Variant { label: "whole".into(), edit: Edit::Whole("/* 0x1 */\nint f(void) { return 2; }".into()) });
        assert_eq!(v[1].edit, Edit::Pairs(vec![("  a = 1;".into(), "  a = 2;".into()), ("b".into(), "c".into())]));
        let func = "/* 0x1 */\nvoid f(void)\n{\n  a = 1;\n  b;\n}";
        assert_eq!(apply(func, &v[1].edit).unwrap(), "/* 0x1 */\nvoid f(void)\n{\n  a = 2;\n  c;\n}");
        // an old text twice in the function: refused (a twin's lines are another function's)
        assert!(apply("x\nx", &Edit::Pairs(vec![("x".into(), "y".into())])).unwrap_err().contains("occurs 2 times"));
        assert!(parse("junk\n### a\nx\n").is_err());
        assert!(parse("### a\n\n### b\nx\n").is_err());
        assert!(parse("### a\n<<<\nx\n>>>\n").is_err());
    }

    #[test]
    fn a_line_moves_through_a_range() {
        // lines 10..15: the function; line 12 moves before 11, (12, 13: its own place), before 14, 15, after 15
        let v = moves(12, (11, 16), 10, 6).unwrap();
        assert_eq!(v.iter().map(|x| x.label.as_str()).collect::<Vec<_>>(), ["L12->before-L11", "L12->before-L14", "L12->before-L15", "L12->before-L16"]);
        let func = "a\nb\nc\nd\ne\nf";
        assert_eq!(apply(func, &v[0].edit).unwrap(), "a\nc\nb\nd\ne\nf");
        assert_eq!(apply(func, &v[1].edit).unwrap(), "a\nb\nd\nc\ne\nf");
        assert_eq!(apply(func, &v[3].edit).unwrap(), "a\nb\nd\ne\nf\nc");
        assert!(moves(30, (11, 12), 10, 6).is_err());
    }
}
