//! `dcp try NAME [FILE] [--move-line N --to A..B] [--apply LABEL]`: source
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
//! A block whose new text is empty (`===` then `>>>`) deletes its old text. Each marker stands on a line of its own,
//! and a marker out of order is an error. An old text must occur exactly once in the function (not in the file: a twin function's equal lines are never
//! touched). `--move-line N --to A..B` adds a variant for each place in
//! A..B the file's line N (a declaration inside the function) can move to.
//!
//! The table: one row per variant with the grade, the distance (differing instructions on both sides, differing
//! bytes) and the hunk classes, and a hash of the object code (the relocated fields' targets masked, their addends
//! kept: a field displacement is code; the compiler's numbered names by kind): variants with the same code are
//! listed as `= label`, which shows the source levers VC6 ignores. A reference that differs from the original's (a
//! crossed field: M8) is in the grade but in no instruction: the hunks name it first (`references differ: M8 x2`).

use crate::error::{Error, Result};
use crate::project::{native_path, Project};
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
        // a block's markers, each on a line of its own, read in order: `<<<` opens, `===` ends the old text, `>>>` the
        // new one (empty: a deletion). A marker out of order is an error, never text: the first block of a variant
        // whose block lacked its `===` (a deletion written `<<< old >>>`) took the next block's `===` for its own, and
        // the next block into its old text
        // (a marker: the line is one, or starts with one and a space: `=== >>>`; `=====` in a comment is text)
        let marker = |l: &str| -> Option<&'static str> {
            let t = l.trim();
            ["<<<", "===", ">>>"].into_iter().find(|m| t.strip_prefix(m).is_some_and(|r| r.is_empty() || r.starts_with(char::is_whitespace)))
        };
        let edit = if body[0].trim() == "<<<" {
            let mut pairs = vec![];
            let (mut old, mut new): (Option<Vec<&str>>, Option<Vec<&str>>) = (None, None);
            for (k, l) in body.iter().enumerate() {
                let at = format!("variant `{label}`, line {} of its text", k + 1);
                match (marker(l), l.trim()) {
                    (Some(_), t) if !["<<<", "===", ">>>"].contains(&t) => return Err(format!("{at}: `{t}`: a <<< / === / >>> marker stands on a line of its own")),
                    (Some("<<<"), _) if old.is_none() => old = Some(vec![]),
                    (Some("==="), _) if old.is_some() && new.is_none() => new = Some(vec![]),
                    (Some(">>>"), _) if new.is_some() => {
                        let o = old.take().unwrap().join("\n");
                        if o.trim().is_empty() {
                            return Err(format!("{at}: an empty old text"));
                        }
                        pairs.push((o, new.take().unwrap().join("\n")));
                    }
                    (Some(m), _) => {
                        let why = match (m, old.is_some(), new.is_some()) {
                            ("<<<", _, false) => "<<< inside a block's old text: the block before it has no === (an empty replacement is `===` then `>>>`)",
                            ("<<<", _, true) => "<<< inside a block's new text: the block before it has no >>>",
                            ("===", false, _) => "=== outside a <<< === >>> block",
                            ("===", true, _) => "a second === in one block: the block has no >>>",
                            (_, false, _) => ">>> outside a <<< === >>> block",
                            _ => ">>> without === (an empty replacement is `===` then `>>>`)",
                        };
                        return Err(format!("{at}: {why}"));
                    }
                    (None, t) => match (&mut old, &mut new) {
                        (_, Some(n)) => n.push(l),
                        (Some(o), None) => o.push(l),
                        (None, None) if t.is_empty() => {}
                        (None, None) => return Err(format!("{at}: `{l}` outside a <<< === >>> block")),
                    },
                }
            }
            if old.is_some() {
                return Err(format!("variant `{label}`: its last block has no {}", if new.is_some() { ">>>" } else { "=== and >>>" }));
            }
            Edit::Pairs(pairs)
        } else {
            if let Some(l) = body.iter().find(|l| ["<<<", "===", ">>>"].contains(&l.trim())) {
                return Err(format!("variant `{label}`: `{}` in a whole-function variant (a variant of <<< === >>> blocks starts with <<<)", l.trim()));
            }
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
                    // the old text with each backslash doubled is there: the file lost every other backslash on its
                    // way (dcp reads it byte for byte)
                    let halved = n == 0 && old.contains('\\') && t.matches(old.replace('\\', "\\\\").as_str()).count() == 1;
                    let why = if halved { format!(" ({HALVED})") } else { String::new() };
                    return Err(format!("the old text `{first}`.. occurs {n} times in the function (once needed){why}"));
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

/// Why a variant's text has one backslash where the function has two: dcp takes the variants file byte for byte, so
/// the file was written through something that halves backslashes (a shell's echo or heredoc, a tool's escaping).
const HALVED: &str = "the function has `\\\\` where the variants file has `\\`: the file lost a backslash on its way (dcp reads it byte \
                      for byte); write the variants file with a file-writing tool, not through a shell";

/// The function's C string literals with an escaped backslash that a whole-function variant has with every
/// backslash halved (and not as the function has them): the variant's file lost its backslashes on its way.
pub fn halved_literals(func: &str, new: &str) -> Vec<String> {
    use std::sync::LazyLock;
    static LIT: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r#""(?:[^"\\\n]|\\.)*""#).unwrap());
    let mut out: Vec<String> = vec![];
    for m in LIT.find_iter(func) {
        let l = m.as_str();
        if l.contains("\\\\") && !new.contains(l) && new.contains(&l.replace("\\\\", "\\")) && !out.iter().any(|x| x == l) {
            out.push(l.to_string());
        }
    }
    out
}

/// The leading `/* */` comment of a text: (its end, the comment), after leading white space.
fn leading_comment(t: &str) -> Option<(usize, &str)> {
    let start = t.len() - t.trim_start().len();
    let rest = &t[start..];
    if !rest.starts_with("/*") {
        return None;
    }
    let end = start + rest.find("*/")? + 2;
    Some((end, &t[start..end]))
}

/// A whole-function variant with the function's own address comment (its description and @deep note) in place of
/// the variant's first comment, or before the variant when it has none: the comment is not what `dcp try` compiles,
/// and a function without its address comment leaves the grades. The white space between the comment and the
/// function stays as the source has it (a blank line, or none).
pub fn keep_comment(func: &str, new: &str) -> String {
    let Some((fend, own)) = leading_comment(func) else { return new.to_string() };
    let lead = &func[..func.len() - func.trim_start().len()];
    let gap = &func[fend..];
    let sep = &gap[..gap.len() - gap.trim_start().len()];
    let body = match leading_comment(new) {
        Some((end, _)) => new[end..].trim_start(),
        None => new.trim_start(),
    };
    format!("{lead}{own}{sep}{body}")
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
pub(crate) fn short_hash(key: &(Vec<u8>, Vec<(u32, String)>)) -> String {
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

/// `--apply`: the variant written into the unit's file in place of the function's lines comment..end (from 1), every
/// other byte of the file as it was (edit::read_src / edit::write: a Latin-1 byte of another function's string once
/// came back as U+FFFD, and that function fell). A whole-function variant's first comment only marks its text as the
/// whole function: the function keeps its own address comment (its description and its @deep note). (the function's
/// text, its new text)
pub(crate) fn apply_to_file(path: &str, comment: i64, end: i64, edit: &Edit) -> std::result::Result<(String, String), String> {
    let text = crate::edit::read_src(path).map_err(|e| format!("{path}: {e}"))?;
    let lines: Vec<&str> = text.split('\n').collect();
    let (lo, hi) = ((comment.max(1) - 1) as usize, (end.max(comment) as usize).min(lines.len()));
    if lo >= hi {
        return Err(format!("the span {comment}..{end} is not in {path}"));
    }
    let func = lines[lo..hi].join("\n");
    let new = apply(&func, edit)?;
    let new = if matches!(edit, Edit::Whole(_)) { keep_comment(&func, &new) } else { new };
    let out: Vec<&str> = lines[..lo].iter().copied().chain(new.split('\n')).chain(lines[hi..].iter().copied()).collect();
    crate::edit::write(path, &out.join("\n"))?;
    Ok((func, new))
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
    let path = native_path(&format!("{root}/{sfile}"));
    // every byte kept (a Latin-1 byte of another function's string stays that byte when --apply writes the unit)
    let text = crate::edit::read_src(&path).map_err(err)?;
    let crlf = crate::edit::crlf_file(&path);
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
        Some(f) => match std::fs::read(f) {
            Ok(x) => match parse(&crate::edit::decode(&x)) {
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
        let (func, new) = apply_to_file(&path, comment, end, &v.edit).map_err(err)?;
        let mut lines = vec![record(&[("fn", s(&fmt_addr(a))), ("name", s(name)), ("applied", s(lb)), ("file", s(&sfile))]),
                             format!("{sfile}: {name} replaced by variant `{lb}`; dcp build to grade it")];
        if matches!(v.edit, Edit::Whole(_)) {
            lines.extend(halved_literals(&func, &new).iter().map(|l| format!("warning: variant `{lb}` has the string {l} with one backslash ({HALVED})")));
        }
        return Ok((lines, 0));
    }
    // the control (the unit as it is) and the variants that apply, compiled together
    // a whole function compiled as --apply writes it: with the function's own address comment
    let texts: Vec<std::result::Result<String, String>> = variants.iter()
        .map(|v| apply(&func, &v.edit).map(|t| if matches!(v.edit, Edit::Whole(_)) { keep_comment(&func, &t) } else { t })).collect();
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
        let (g, refs) = bench.grade_refs(o, &c, a);
        let (ins, bytes, hunks) = bench.distance(o, &c, a);
        // a reference that differs (a crossed field: M8) is in the grade, not in the instructions: named first
        let (g, hunks) = (g.to_string(), if refs.is_empty() { hunks } else { format!("references differ: {refs}; {hunks}") });
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
    for (k, v) in variants.iter().enumerate() {
        if let (Edit::Whole(_), Ok(t)) = (&v.edit, &texts[k]) {
            out.extend(halved_literals(&func, t).iter().map(|l| format!("warning: variant `{}` has the string {l} with one backslash ({HALVED})", v.label)));
        }
    }
    let same = table.iter().filter(|r| r.same_as.as_deref() == Some("control")).count();
    if same > 0 {
        out.push(format!("{same} variant(s) compile to the control's code: those source changes are no lever for VC6 here"));
    }
    // the declaration set (tiebreak.rs): the closest row, when it is close and below byte, swept over every
    // symbol-count shift (cached by its text and the unit's inputs), so that a text only the declaration set keeps
    // from byte is known as done
    let closest = table.iter().filter_map(|r| r.outcome.as_ref().ok().map(|o| (r, o)))
        .min_by_key(|(r, o)| (std::cmp::Reverse(rank(&o.0)), o.1, o.2, r.label != "control"));
    if let Some((r, o)) = closest.filter(|(_, o)| o.0 != "byte" && crate::tiebreak::close(&o.0, Some(o.1 as i64))) {
        let k = variants.iter().position(|v| v.label == r.label);
        let f = match k {
            Some(k) => texts[k].clone().ok(),
            None => Some(func.clone()),
        };
        if let Some(f) = f {
            let ut = unit_text(&f);
            let bytes = if crlf { ut.replace('\n', "\r\n") } else { ut.clone() };
            if let Some(rec) = crate::tiebreak::try_sweep(p, t, &ut, &bytes, name, a, comment, &f)? {
                let set = rec.witness.split(" by ").nth(1).and_then(|x| x.split(';').next()).unwrap_or("").to_string();
                let v = crate::tiebreak::verdict(&rec.best, &o.0, &set, crate::tiebreak::complete(&rec));
                let apply = if rec.best == "byte" && r.label != "control" { format!(" (dcp try {name} ... --apply {}, dcp build)", r.label) } else { String::new() };
                out.push(format!("declaration set of `{}`: {v}{apply}", r.label));
            }
        }
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
        // --apply of a whole function keeps the function's address comment (its description and @deep note)
        let own = "/* 0x1, adds @deep round 3: shape\n   prior: round 1 */\nint f(void) { return 1; }";
        assert_eq!(keep_comment(own, "/* 0x1 */\nint f(void) { return 2; }"), "/* 0x1, adds @deep round 3: shape\n   prior: round 1 */\nint f(void) { return 2; }");
        // a variant without a comment: the function's own comment stays before it
        assert_eq!(keep_comment(own, "int f(void) { return 2; }"), "/* 0x1, adds @deep round 3: shape\n   prior: round 1 */\nint f(void) { return 2; }");
        assert_eq!(keep_comment(own, "\n\nint f(void) { return 2; }"), "/* 0x1, adds @deep round 3: shape\n   prior: round 1 */\nint f(void) { return 2; }");
        // the blank-line layout between the comment and the function is the source's, whatever the variant's
        let spaced = "/* 0x1 @deep x */\n\nint f(void) { return 1; }";
        assert_eq!(keep_comment(spaced, "int f(void) { return 2; }"), "/* 0x1 @deep x */\n\nint f(void) { return 2; }");
        assert_eq!(keep_comment(spaced, "/* 0x1 */\nint f(void) { return 2; }"), "/* 0x1 @deep x */\n\nint f(void) { return 2; }");
        assert_eq!(keep_comment(own, "/* 0x1 */\n\n\nint f(void) { return 2; }"), "/* 0x1, adds @deep round 3: shape\n   prior: round 1 */\nint f(void) { return 2; }");
        // a function without a comment takes the variant as it is
        assert_eq!(keep_comment("int f(void) { return 1; }", "/* c */\nint f(void) { return 2; }"), "/* c */\nint f(void) { return 2; }");
    }

    #[test]
    fn backslashes_are_taken_byte_for_byte() {
        // a C string with an escaped backslash: the variants file's text is the function's text, no escape processing
        let func = "/* 0x1 \"misc\\quickchat\" */\nvoid f(void)\n{\n    g(\"misc\\\\quickchat\");\n}";
        let file = "### blk\n<<<\n    g(\"misc\\\\quickchat\");\n===\n    g(\"misc\\\\quickchat\", 1);\n>>>\n\n### whole\nvoid f(void)\n{\n    g(\"misc\\\\quickchat\");\n}\n";
        let v = parse(file).unwrap();
        assert_eq!(v[0].edit, Edit::Pairs(vec![("    g(\"misc\\\\quickchat\");".into(), "    g(\"misc\\\\quickchat\", 1);".into())]));
        assert_eq!(apply(func, &v[0].edit).unwrap(), "/* 0x1 \"misc\\quickchat\" */\nvoid f(void)\n{\n    g(\"misc\\\\quickchat\", 1);\n}");
        let whole = keep_comment(func, &apply(func, &v[1].edit).unwrap());
        assert_eq!(whole, func);
        assert!(halved_literals(func, &whole).is_empty());
        // a file that lost a backslash on its way: the block says why it does not apply, the whole variant is warned
        let lost = parse("### blk\n<<<\n    g(\"misc\\quickchat\");\n===\n    h();\n>>>\n").unwrap();
        let e = apply(func, &lost[0].edit).unwrap_err();
        assert!(e.contains("occurs 0 times") && e.contains("lost a backslash"), "{e}");
        assert_eq!(halved_literals(func, "void f(void)\n{\n    g(\"misc\\quickchat\");\n}"), ["\"misc\\\\quickchat\""]);
        // an old text simply absent: no such hint
        assert!(!apply(func, &Edit::Pairs(vec![("zz\\q".into(), "y".into())])).unwrap_err().contains("backslash"));
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

    /// A block with an empty replacement (a deletion) ends at its `>>>`: the next block is a block of its own, in the
    /// same variant and the next one. A block whose markers are out of order (a deletion written without its `===`,
    /// a block without its `>>>`, two markers on one line) is an error naming it, never another block's text.
    #[test]
    fn empty_replacement_ends_its_block() {
        let v = parse("### del\n<<<\n    x = 1;\n===\n>>>\n<<<\n    y = 2;\n===\n    y = 3;\n>>>\n\n### next\n<<<\n    z;\n===\n\n>>>\n<<<\n    w;\n===\n    v;\n>>>\n").unwrap();
        assert_eq!(v[0].edit, Edit::Pairs(vec![("    x = 1;".into(), "".into()), ("    y = 2;".into(), "    y = 3;".into())]));
        assert_eq!(v[1].edit, Edit::Pairs(vec![("    z;".into(), "".into()), ("    w;".into(), "    v;".into())]));
        assert_eq!(apply("{\n    x = 1;\n    y = 2;\n}", &v[0].edit).unwrap(), "{\n\n    y = 3;\n}");
        let e = |f: &str| parse(f).unwrap_err();
        assert!(e("### a\n<<<\n    x;\n>>>\n<<<\n    y;\n===\n    z;\n>>>\n").contains(">>> without ==="));
        assert!(e("### a\n<<<\n    x;\n<<<\n    y;\n===\n    z;\n>>>\n").contains("<<< inside a block's old text"));
        assert!(e("### a\n<<<\n    x;\n===\n<<<\n    y;\n===\n    z;\n>>>\n").contains("<<< inside a block's new text"));
        assert!(e("### a\n<<<\n    x;\n=== >>>\n<<<\n    y;\n===\n    z;\n>>>\n").contains("on a line of its own"));
        assert!(e("### a\n<<<\n    x;\n===\n    y;\n").contains("its last block has no >>>"));
        assert!(e("### a\nint f(void)\n===\n").contains("whole-function variant"));
        // `=====` in a comment is text
        let v = parse("### c\n<<<\n    /* a\n       ===== */\n===\n    /* b */\n>>>\n").unwrap();
        assert_eq!(v[0].edit, Edit::Pairs(vec![("    /* a\n       ===== */".into(), "    /* b */".into())]));
    }

    /// --apply writes the variant over the function's lines and keeps every other byte: a Latin-1 byte (0xfc) in
    /// another function's string is no U+FFFD after it (gildegold main.c, main_UpdateFigure fell shape -> draft), nor
    /// one in the variant's own text; a CRLF file stays CRLF.
    #[test]
    fn apply_keeps_latin1_bytes() {
        let dir = crate::testkit::scratch("try-latin1");
        let p = dir.join("u.c").to_string_lossy().into_owned();
        let src = b"/* 0x1000, f */\nvoid f(void)\n{\n    g(1);\n}\n\n/* 0x1010, says it */\nvoid h(void)\n{\n    puts(\"MeisterPr\xfc\" \"fung\");\n}\n";
        std::fs::write(&p, src).unwrap();
        let v = parse(&crate::edit::decode(b"### two\n<<<\n    g(1);\n===\n    g(2); /* \xfc */\n>>>\n")).unwrap();
        let (func, new) = apply_to_file(&p, 1, 5, &v[0].edit).unwrap();
        assert_eq!((func.as_str(), new.as_str()), ("/* 0x1000, f */\nvoid f(void)\n{\n    g(1);\n}", "/* 0x1000, f */\nvoid f(void)\n{\n    g(2); /* \u{10fffc} */\n}"));
        let want = b"/* 0x1000, f */\nvoid f(void)\n{\n    g(2); /* \xfc */\n}\n\n/* 0x1010, says it */\nvoid h(void)\n{\n    puts(\"MeisterPr\xfc\" \"fung\");\n}\n";
        assert_eq!(std::fs::read(&p).unwrap(), want.to_vec());
        let mut src_crlf = vec![];
        for &c in src.iter() {
            if c == b'\n' {
                src_crlf.push(b'\r');
            }
            src_crlf.push(c);
        }
        std::fs::write(&p, &src_crlf).unwrap();
        apply_to_file(&p, 1, 5, &v[0].edit).unwrap();
        let mut want_crlf = vec![];
        for &c in want.iter() {
            if c == b'\n' {
                want_crlf.push(b'\r');
            }
            want_crlf.push(c);
        }
        assert_eq!(std::fs::read(&p).unwrap(), want_crlf);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
