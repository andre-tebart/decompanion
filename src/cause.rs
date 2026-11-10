//! The cause candidates of a grade change (many falls share one cause, M1 names it): which inputs of a unit's compile changed since
//! a commit. A unit compiles from its own file and the headers it includes, so a function whose grade moved names
//! one of three things:
//! - its unit's own text changed;
//! - a header of its include closure changed (with the include chain that reaches it from the unit);
//! - nothing it compiles from changed: a rule or prover change, or another object's φ.
//!
//! The changes are read from git once (`git diff --name-only REV` against the working tree, plus the untracked
//! files) and only when a grade moved, so a clean build pays nothing. The include chain follows the quoted
//! `#include` lines, each resolved against the including file's directory, then include/ (VC6's search for a quoted
//! name before the /I directories that hold the system headers, which do not change).

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::LazyLock;

static INCLUDE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r#"(?m)^[ \t]*#[ \t]*include[ \t]+"([^"]+)""#).unwrap());

/// The paths that changed since one commit: project-relative, '/' separated, lower case, each with whether it is
/// uncommitted (differs from HEAD: in a worker's loop almost always the trigger).
pub struct Changes {
    pub since: String,
    rev: String, // the full commit (git show reads the base's texts)
    files: HashMap<String, bool>,
}

/// What changed in one unit's inputs.
#[derive(Debug, PartialEq, Eq)]
pub struct Cause {
    pub unit: Option<(String, bool)>,               // the unit's own file, when it changed (uncommitted)
    pub headers: Vec<(String, Vec<String>, bool)>,  // each changed header of its closure: the chain unit > ... >
                                                    // header, uncommitted; the uncommitted ones first
}

fn git(root: &str, args: &[&str]) -> Option<String> {
    match std::process::Command::new("git").args(args).current_dir(root).output() {
        Ok(o) if o.status.success() => Some(String::from_utf8_lossy(&o.stdout).into_owned()),
        _ => None,
    }
}

fn norm(p: &str) -> String {
    let mut out: Vec<&str> = vec![];
    for part in p.split(['/', '\\']) {
        match part {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            x => out.push(x),
        }
    }
    out.join("/").to_lowercase()
}

impl Changes {
    /// The changes since `rev` (working tree and untracked files included), None outside git or for an unknown rev.
    pub fn since(root: &str, rev: &str) -> Option<Changes> {
        let names = |t: String| -> Vec<String> { t.lines().map(str::trim).filter(|l| !l.is_empty()).map(norm).collect() };
        let diff = names(git(root, &["diff", "--name-only", "--no-renames", rev, "--"])?);
        let untracked = names(git(root, &["ls-files", "--others", "--exclude-standard"]).unwrap_or_default());
        let revs = git(root, &["rev-parse", rev, "HEAD"]).unwrap_or_default();
        let revs: Vec<&str> = revs.split_whitespace().collect();
        let short = revs.first().map(|s| s.chars().take(8).collect()).unwrap_or_else(|| rev.to_string());
        // since HEAD itself every change is uncommitted; else one more diff tells them apart
        let dirty: HashSet<String> = if revs.len() == 2 && revs[0] == revs[1] {
            diff.iter().cloned().collect()
        } else {
            names(git(root, &["diff", "--name-only", "--no-renames", "HEAD", "--"]).unwrap_or_default()).into_iter().collect()
        };
        let mut files: HashMap<String, bool> = diff.into_iter().map(|f| { let u = dirty.contains(&f); (f, u) }).collect();
        files.extend(untracked.into_iter().map(|f| (f, true)));
        Some(Changes { since: short, rev: revs.first().map(|s| s.to_string()).unwrap_or_else(|| rev.to_string()), files })
    }

    /// The changes since the commit that last wrote the baseline ledger/grades.tsv; since HEAD when the baseline
    /// has uncommitted changes (a promote not yet committed: the grades are of the tree at HEAD or later).
    pub fn since_baseline(root: &str) -> Option<Changes> {
        let dirty = !git(root, &["status", "--porcelain", "--", "ledger/grades.tsv"])?.trim().is_empty();
        let rev = if dirty { None } else { git(root, &["log", "-1", "--format=%H", "--", "ledger/grades.tsv"]).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) };
        Changes::since(root, rev.as_deref().unwrap_or("HEAD"))
    }

    #[cfg(test)]
    fn of(since: &str, files: &[(&str, bool)]) -> Changes {
        Changes { since: since.into(), rev: since.into(), files: files.iter().map(|(f, u)| (norm(f), *u)).collect() }
    }

    /// A file's text at the base (project-relative), None when the base has no such file or outside git.
    pub fn text_at(&self, root: &str, file: &str) -> Option<String> {
        git(root, &["show", &format!("{}:{}", self.rev, file.replace('\\', "/"))]).map(|t| t.replace("\r\n", "\n"))
    }

    /// The commits since the base that changed any of `files` (project-relative), newest first: `abc1234 subject`,
    /// at most `max`.
    pub fn commits(&self, root: &str, files: &[String], max: usize) -> Vec<String> {
        if files.is_empty() {
            return vec![];
        }
        let range = format!("{}..HEAD", self.rev);
        let mut args = vec!["log", "--format=%h %s", "--no-renames", &range, "--"];
        args.extend(files.iter().map(|f| f.as_str()));
        git(root, &args).unwrap_or_default().lines().take(max).map(|l| l.chars().take(90).collect()).collect()
    }

    /// What changed of the inputs of the unit compiled from `file` (project-relative).
    pub fn of_unit(&self, root: &str, file: &str) -> Cause {
        let own = norm(file);
        let unit = self.files.get(&own).map(|&u| (file.replace('\\', "/"), u));
        // breadth first: the shortest chain to each header
        let mut parent: HashMap<String, String> = HashMap::new();
        let mut seen: HashSet<String> = HashSet::from([own.clone()]);
        let mut order: Vec<String> = vec![];
        let mut todo: VecDeque<String> = VecDeque::from([own.clone()]);
        while let Some(f) = todo.pop_front() {
            let text = crate::fsmemo::read_text(&crate::project::py_path(&format!("{root}/{f}"))).unwrap_or_default();
            let dir = f.rsplit_once('/').map(|x| x.0.to_string()).unwrap_or_default();
            for c in INCLUDE.captures_iter(&text) {
                let name = &c[1];
                let Some(h) = [norm(&format!("{dir}/{name}")), norm(&format!("include/{name}"))].into_iter()
                    .find(|h| Path::new(&crate::project::py_path(&format!("{root}/{h}"))).exists()) else { continue };
                if seen.insert(h.clone()) {
                    parent.insert(h.clone(), f.clone());
                    order.push(h.clone());
                    todo.push_back(h);
                }
            }
        }
        let mut headers: Vec<(String, Vec<String>, bool)> = order.into_iter().filter_map(|h| {
            let u = *self.files.get(&h)?;
            let mut chain = vec![h.clone()];
            while let Some(p) = parent.get(chain.last().unwrap()) {
                chain.push(p.clone());
            }
            chain.reverse();
            Some((h, chain, u))
        }).collect();
        headers.sort_by_key(|h| !h.2);
        Cause { unit, headers }
    }
}

impl Cause {
    /// The files of the cause: the unit's own and the changed headers.
    pub fn files(&self) -> Vec<String> {
        self.unit.iter().map(|u| u.0.clone()).chain(self.headers.iter().map(|h| h.0.clone())).collect()
    }

    /// `text`, with the commits since the base that made the change (wrap-unexplained-grade-change.md: a raise by a
    /// shared macro fixed for another function, or by a fix committed outside a session, named no edit).
    pub fn text_with_commits(&self, ch: &Changes, root: &str, max: usize) -> String {
        let t = self.text(&ch.since, max);
        let c = ch.commits(root, &self.files(), 3);
        if c.is_empty() { t } else { format!("{t}; by {}", c.join(", ")) }
    }

    /// The cause as one clause: "since abc1234: unit src/a.c changed; header include/t.h (src/a.c > include/a.h >
    /// include/t.h)", at most `max` headers named.
    pub fn text(&self, since: &str, max: usize) -> String {
        let mut parts = vec![];
        let fresh = |u: bool| if u { ", uncommitted" } else { "" };
        if let Some((f, u)) = &self.unit {
            parts.push(format!("its unit {f} changed{}", fresh(*u)));
        }
        for (h, chain, u) in self.headers.iter().take(max) {
            let via = if chain.len() > 2 { format!(" ({})", chain.join(" > ")) } else { String::new() };
            parts.push(format!("{h} changed{}{via}", fresh(*u)));
        }
        if self.headers.len() > max {
            parts.push(format!("{} more headers changed", self.headers.len() - max));
        }
        if parts.is_empty() {
            format!("nothing it compiles from changed since {since}: a rule or prover change, or another object's φ")
        } else {
            format!("since {since}: {}", parts.join("; "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chains_and_text() {
        let dir = crate::testkit::scratch("cause");
        let _ = std::fs::remove_dir_all(&dir);
        let root = dir.to_string_lossy().into_owned();
        for (f, t) in [("src/a.c", "#include \"a.h\"\n#include \"local.h\"\n"), ("src/local.h", ""), ("include/a.h", "#include \"t.h\"\n#include <stdio.h>\n"),
                       ("include/t.h", "#include \"a.h\"\n"), ("include/other.h", "")] {
            std::fs::create_dir_all(dir.join(f).parent().unwrap()).unwrap();
            std::fs::write(dir.join(f), t).unwrap();
        }
        crate::fsmemo::new_epoch();
        let none = Changes::of("abc1234", &[("include/other.h", true)]).of_unit(&root, "src/a.c");
        assert_eq!(none, Cause { unit: None, headers: vec![] });
        assert_eq!(none.text("abc1234", 3), "nothing it compiles from changed since abc1234: a rule or prover change, or another object's φ");
        let c = Changes::of("abc1234", &[("include/T.h", true), ("src/local.h", false), ("src/a.c", false)]).of_unit(&root, "src/a.c");
        assert_eq!(c.text("abc1234", 3), "since abc1234: its unit src/a.c changed; include/t.h changed, uncommitted (src/a.c > include/a.h > include/t.h); src/local.h changed");
        assert_eq!(c.text("abc1234", 1), "since abc1234: its unit src/a.c changed; include/t.h changed, uncommitted (src/a.c > include/a.h > include/t.h); 1 more headers changed");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
