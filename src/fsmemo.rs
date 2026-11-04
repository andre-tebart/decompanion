//! File contents and content hashes, read once: the input hashes, the source scan, the units and the grades all
//! read the same few thousand source files in one refresh, and every command (every request of `dcp serve`)
//! hashes the whole tree again.
//!
//! - A read is memoised by (path, size, modification time) for the life of the process.
//! - A stamp (size, modification time) is taken once per epoch: `walk` lists a tree with the stamps the directory
//!   listing carries (no stat per file), `stamp` stats a path not seen yet. `new_epoch` forgets the stamps; it
//!   runs at the start of every command, refresh and build, and after every write of a source file by dcp itself,
//!   so a file changed between two epochs is always seen.
//! - The content hash of a file is persisted per project (build/cache/stamps.tsv: path, size, modification time,
//!   sha256, when it was hashed), so a new process does not read an unchanged file to hash it. An entry is trusted
//!   only when the stamp is equal and the file was last modified more than RACY_NS before it was hashed (git's
//!   racy-clean rule: a write within the same clock tick as the hash could keep the stamp). DCP_NO_STAMPS=1 turns
//!   the persisted hashes off; `dcp build --force` and `dcp setup --force` drop them (forget_all).
//! - An entry is a fact about one file (its absolute path), whichever project hashed it: the entries of every
//!   attached project are one map. A project's file persists the entries hashed while it was attached (the thread's
//!   project; a thread a command spawned: the project attached last), and only a project with new entries is
//!   written. A process serves one project (the daemon) or several at once (the tests): attaching one never writes
//!   another's file.
//! - The lock guards the memo only: every stat, listing, read and hash runs outside it.
//!
//! The stamps decide nothing on their own beyond "this file did not change": every input hash is still the
//! content hash of the files.

use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const STAMPS_VERSION: &str = "dcp-stamps 3";
const RACY_NS: i128 = 2_000_000_000;
/// The tests that count reads hold it exclusively; the command-line tests hold it shared (their projects share the
/// one memo of the process).
#[cfg(test)]
pub(crate) static EXCLUSIVE: std::sync::RwLock<()> = std::sync::RwLock::new(());
#[cfg(test)]
thread_local!(static READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) });

type Stamp = (u64, i128); // size, modification time (ns since the epoch)

#[derive(Default)]
struct State {
    bytes: HashMap<String, (Stamp, Arc<Vec<u8>>)>,
    sha: HashMap<String, (Stamp, String)>,
    seen: HashMap<String, Stamp>,
    disk: HashMap<String, (Stamp, String, i128)>, // path -> stamp, sha256, hashed at (ns): every attached project's
    roots: HashMap<PathBuf, Persisted>,           // a project's stamps.tsv -> what it persists
    last: Option<PathBuf>,                        // the stamps.tsv attached last
    epoch: u64,                                   // a stamp taken before the current epoch began is not kept
}

/// What one project's stamps.tsv persists: the paths of its entries, and whether it has entries not yet written.
#[derive(Default)]
struct Persisted {
    paths: HashSet<String>,
    dirty: bool,
}

thread_local!(static ATTACHED: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) });

fn state() -> std::sync::MutexGuard<'static, State> {
    static S: OnceLock<Mutex<State>> = OnceLock::new();
    S.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner())
}

fn ns(t: std::io::Result<SystemTime>) -> i128 {
    match t.map(|t| t.duration_since(UNIX_EPOCH)) {
        Ok(Ok(d)) => d.as_nanos() as i128,
        Ok(Err(e)) => -(e.duration().as_nanos() as i128),
        Err(_) => 0,
    }
}

fn now_ns() -> i128 {
    ns(Ok(SystemTime::now()))
}

/// The file's stamp of this epoch (a stat when it has none yet; the stat outside the lock, kept only when no new
/// epoch began meanwhile).
fn stamp_of(path: &str) -> std::io::Result<Stamp> {
    let epoch = {
        let st = state();
        if let Some(s) = st.seen.get(path) {
            return Ok(*s);
        }
        st.epoch
    };
    let m = std::fs::metadata(path)?;
    let s = (m.len(), ns(m.modified()));
    let mut st = state();
    if st.epoch == epoch {
        st.seen.insert(path.to_string(), s);
    }
    Ok(s)
}

/// Forget every stamp taken so far: the next look at a file stats it (or lists its directory) again.
pub fn new_epoch() {
    let mut st = state();
    st.seen.clear();
    st.epoch += 1;
}

/// fnmatch.fnmatchcase of `*`, `?` and literal characters.
pub(crate) fn fnmatch(name: &[u8], pat: &[u8]) -> bool {
    let (mut n, mut p) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while n < name.len() {
        if p < pat.len() && (pat[p] == b'?' || pat[p] == name[n]) {
            n += 1;
            p += 1;
        } else if p < pat.len() && pat[p] == b'*' {
            star = Some(p);
            mark = n;
            p += 1;
        } else if let Some(s) = star {
            p = s + 1;
            mark += 1;
            n = mark;
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == b'*' {
        p += 1;
    }
    p == pat.len()
}

/// The files below base matching any of the name patterns (case-insensitive) as (path relative to base in posix
/// spelling, full path), in the order of sorted(base.rglob(pattern)) per pattern, each pattern's files once; the
/// directory listing's stamps are noted for the epoch.
pub fn walk(base: &str, patterns: &[String]) -> Vec<(String, String)> {
    struct Found {
        parts: Vec<String>,
        rel: String,
        path: String,
    }
    fn rec(d: &Path, parts: &[String], rel: &str, found: &mut Vec<Found>, stamps: &mut Vec<(String, Stamp)>) {
        let Ok(it) = std::fs::read_dir(d) else { return };
        for e in it.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            let name = e.file_name().to_string_lossy().into_owned();
            let path = d.join(&name);
            let mut p = parts.to_vec();
            p.push(name.to_lowercase());
            if ft.is_dir() {
                rec(&path, &p, &format!("{rel}{name}/"), found, stamps);
            } else {
                // a symlink counts when it leads to a file (DirEntry.is_file follows it)
                let m = if ft.is_symlink() { std::fs::metadata(&path) } else { e.metadata() };
                let Ok(m) = m else { continue };
                if !m.is_file() {
                    continue;
                }
                let ps = path.to_string_lossy().into_owned();
                stamps.push((ps.clone(), (m.len(), ns(m.modified()))));
                found.push(Found { parts: p, rel: format!("{rel}{name}"), path: ps });
            }
        }
    }
    let (mut found, mut stamps) = (vec![], vec![]);
    let epoch = state().epoch;
    rec(Path::new(base), &[], "", &mut found, &mut stamps);
    let mut st = state();
    if st.epoch == epoch {
        st.seen.extend(stamps);
    }
    found.sort_by(|a, b| (&a.parts, &a.rel, &a.path).cmp(&(&b.parts, &b.rel, &b.path)));
    let mut out = vec![];
    for pat in patterns {
        let pat = pat.to_lowercase();
        out.extend(found.iter().filter(|f| fnmatch(f.parts.last().unwrap().as_bytes(), pat.as_bytes())).map(|f| (f.rel.clone(), f.path.clone())));
    }
    out
}

pub fn read_bytes(path: &str) -> std::io::Result<Arc<Vec<u8>>> {
    let stamp = stamp_of(path)?;
    if let Some((s, b)) = state().bytes.get(path) {
        if *s == stamp {
            return Ok(b.clone());
        }
    }
    let data = Arc::new(std::fs::read(path)?);
    state().bytes.insert(path.to_string(), (stamp, data.clone()));
    Ok(data)
}

/// The text as Path.read_text(errors="replace") gives it (UTF-8, universal newlines).
pub fn read_text(path: &str) -> std::io::Result<String> {
    let b = read_bytes(path)?;
    let s = String::from_utf8_lossy(&b);
    Ok(if s.contains('\r') { s.replace("\r\n", "\n").replace('\r', "\n") } else { s.into_owned() })
}

/// The hex sha256 of the file's bytes.
pub fn sha256(path: &str) -> std::io::Result<String> {
    let stamp = stamp_of(path)?;
    {
        let mut st = state();
        if let Some((s, h)) = st.sha.get(path) {
            if *s == stamp {
                return Ok(h.clone());
            }
        }
        if let Some((s, h, at)) = st.disk.get(path) {
            if *s == stamp && s.1 < at - RACY_NS {
                let h = h.clone();
                st.sha.insert(path.to_string(), (stamp, h.clone()));
                return Ok(h);
            }
        }
    }
    let h = hex(&Sha256::digest(&*read_bytes(path)?));
    #[cfg(test)]
    READS.with(|r| r.set(r.get() + 1));
    let to = ATTACHED.with(|a| a.borrow().clone());
    let mut st = state();
    st.sha.insert(path.to_string(), (stamp, h.clone()));
    if let Some(root) = to.or_else(|| st.last.clone()).filter(|r| st.roots.contains_key(r)) {
        st.disk.insert(path.to_string(), (stamp, h.clone(), now_ns()));
        let r = st.roots.get_mut(&root).unwrap();
        r.paths.insert(path.to_string());
        r.dirty = true;
    }
    Ok(h)
}

pub fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// The hash of the files below dirs matching the patterns: each existing directory's name, then every file's
/// relative path and content hash (Project.tree_hash).
pub fn tree_hash(dirs: &[String], patterns: &[String]) -> std::io::Result<String> {
    let mut h = Sha256::new();
    for d in dirs {
        let p = Path::new(d);
        if !p.exists() {
            continue;
        }
        h.update(p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default().as_bytes());
        h.update(b"\x01");
        for (rel, path) in walk(d, patterns) {
            h.update(rel.as_bytes());
            h.update(b"\0");
            let s = sha256(&path)?;
            let raw: Vec<u8> = (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect();
            h.update(&raw);
        }
    }
    Ok(hex(&h.finalize()))
}

// ------------------------------------------------------------------------------------------------ the persisted hashes

/// Use the persisted hashes of the project at root: its file is read once per process, and this thread's new
/// hashes are persisted there.
pub fn attach(root: &str) {
    if std::env::var_os("DCP_NO_STAMPS").is_some_and(|v| !v.is_empty()) || std::env::var_os("DCP_NO_SHORTCUTS").is_some_and(|v| !v.is_empty()) {
        return;
    }
    let path = Path::new(root).join("build").join("cache").join("stamps.tsv");
    ATTACHED.with(|a| *a.borrow_mut() = Some(path.clone()));
    {
        let mut st = state();
        st.last = Some(path.clone());
        if st.roots.contains_key(&path) {
            return;
        }
    }
    let mut entries = vec![];
    if let Ok(text) = std::fs::read_to_string(&path) {
        let mut lines = text.lines();
        if lines.next() == Some(STAMPS_VERSION) {
            for l in lines {
                let f: Vec<&str> = l.split('\t').collect();
                if f.len() == 5 {
                    if let (Ok(size), Ok(m), Ok(at)) = (f[1].parse(), f[2].parse(), f[4].parse()) {
                        entries.push((f[0].to_string(), ((size, m), f[3].to_string(), at)));
                    }
                }
            }
        }
    }
    let mut st = state();
    if st.roots.contains_key(&path) {
        return; // another thread read it meanwhile
    }
    let mut r = Persisted::default();
    for (p, e) in entries {
        r.paths.insert(p.clone());
        // the later hash of a file another project's file also holds stays
        if st.disk.get(&p).is_none_or(|d| d.2 < e.2) {
            st.disk.insert(p, e);
        }
    }
    st.roots.insert(path, r);
}

/// Write the persisted hashes of each project with new entries (atomically: another process may read them meanwhile).
pub fn flush() {
    let mut out: Vec<(PathBuf, String)> = vec![];
    {
        let mut st = state();
        let State { roots, disk, .. } = &mut *st;
        for (path, r) in roots.iter_mut().filter(|(_, r)| r.dirty) {
            let mut text = String::from(STAMPS_VERSION);
            text.push('\n');
            let mut rows: Vec<(&String, &(Stamp, String, i128))> = r.paths.iter().filter_map(|p| disk.get(p).map(|e| (p, e))).collect();
            rows.sort_by(|a, b| a.0.cmp(b.0));
            for (p, ((size, m), h, at)) in rows {
                text.push_str(&format!("{p}\t{size}\t{m}\t{h}\t{at}\n"));
            }
            r.dirty = false;
            out.push((path.clone(), text));
        }
    }
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    for (path, text) in out {
        // a temporary file of its own per write: two threads never write one file, a rename moves a whole one
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp = path.with_file_name(format!("stamps.tsv.{}.{n}.tmp", std::process::id()));
        let ok = path.parent().map(|d| std::fs::create_dir_all(d).is_ok()).unwrap_or(false)
            && std::fs::write(&tmp, text).is_ok()
            && std::fs::rename(&tmp, &path).is_ok();
        if !ok {
            if let Some(r) = state().roots.get_mut(&path) {
                r.dirty = true;
            }
        }
    }
}

/// Drop every memo and the persisted hashes (a forced rebuild trusts no stamp).
pub fn forget_all() {
    let mut st = state();
    st.bytes.clear();
    st.sha.clear();
    st.seen.clear();
    st.disk.clear();
    for r in st.roots.values_mut() {
        r.paths.clear();
        r.dirty = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnmatch_forms() {
        assert!(fnmatch(b"a.c", b"*.c"));
        assert!(!fnmatch(b"a.cc", b"*.c"));
        assert!(fnmatch(b"x.dcl", b"*.dcl"));
        assert!(fnmatch(b"ab", b"a?"));
        assert!(fnmatch(b"abc", b"*"));
    }

    #[test]
    fn walk_order_and_reads() {
        let _x = EXCLUSIVE.write().unwrap_or_else(|e| e.into_inner());
        let d = crate::testkit::scratch("fsmemo");
        std::fs::create_dir_all(d.join("Sub")).unwrap();
        std::fs::write(d.join("b.c"), "x\r\ny").unwrap();
        std::fs::write(d.join("A.h"), "").unwrap();
        std::fs::write(d.join("Sub").join("a.c"), "").unwrap();
        std::fs::write(d.join("n.txt"), "").unwrap();
        let base = d.to_string_lossy().into_owned();
        let got: Vec<String> = walk(&base, &["*.c".into(), "*.h".into()]).into_iter().map(|t| t.0).collect();
        assert_eq!(got, ["b.c", "Sub/a.c", "A.h"]);
        let b = d.join("b.c").to_string_lossy().into_owned();
        assert_eq!(read_text(&b).unwrap(), "x\ny");
        assert_eq!(sha256(&b).unwrap(), hex(&Sha256::digest(b"x\r\ny")));
        let _ = std::fs::remove_dir_all(&d);
    }

    fn age(p: &Path, secs: u64) {
        let f = std::fs::File::options().write(true).open(p).unwrap();
        f.set_modified(SystemTime::now() - std::time::Duration::from_secs(secs)).unwrap();
    }

    fn reads() -> usize {
        READS.with(|r| r.get())
    }

    /// One test: the persisted hashes are process state.
    #[test]
    fn persisted_hash_trusted_only_for_an_old_unchanged_stamp_and_racy_entries_hashed_again() {
        let _x = EXCLUSIVE.write().unwrap_or_else(|e| e.into_inner());
        let root = crate::testkit::scratch("stamps");
        std::fs::create_dir_all(root.join("src")).unwrap();
        let f = root.join("src").join("a.c");
        let fs = f.to_string_lossy().into_owned();
        std::fs::write(&f, "int a;\n").unwrap();
        age(&f, 60);
        attach(&root.to_string_lossy());
        let h1 = sha256(&fs).unwrap();
        flush();
        // a new process: the memo is gone, the persisted hash answers without a read
        *state() = State::default();
        attach(&root.to_string_lossy());
        let n = reads();
        assert_eq!(sha256(&fs).unwrap(), h1);
        assert_eq!(reads(), n);
        // same size, other content, other modification time: hashed again
        std::fs::write(&f, "int b;\n").unwrap();
        age(&f, 30);
        new_epoch();
        assert_ne!(sha256(&fs).unwrap(), h1);
        assert!(reads() > n);
        // modified just now: the stamp could hide a second write, the entry is not trusted
        std::fs::write(&f, "int c;\n").unwrap();
        new_epoch();
        sha256(&fs).unwrap();
        state().sha.clear();
        new_epoch();
        let n = reads();
        sha256(&fs).unwrap();
        assert!(reads() > n);
        *state() = State::default();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn walk_lists_like_rglob() {
        let d = crate::testkit::scratch("rglob");
        for rel in ["b/z.c", "a/y.h", "a/x.c", "A2/w.C", "c.txt"] {
            let p = d.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "x").unwrap();
        }
        let got: Vec<String> = walk(&d.to_string_lossy(), &["*.c".into(), "*.h".into()]).into_iter().map(|t| t.0).collect();
        assert_eq!(got, ["a/x.c", "A2/w.C", "b/z.c", "a/y.h"]);
        let _ = std::fs::remove_dir_all(&d);
    }
}
