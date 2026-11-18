//! The unit files dcp itself rewrote (edit::write: dcp try --apply, dcp note, dcp escalate, dcp unit split / move,
//! dcp rename, dcp headers --write ...), so that a build which sees a function of such a unit fall says so loudly: a
//! dcp writer must change only what it names, and a fall elsewhere in the unit is a dcp bug (a lossy read once made
//! a Latin-1 byte of another function's string U+FFFD, and the function fell shape -> draft with nothing but the
//! grade totals to show it).
//!
//! build/dcp-writes.json: {rel: {"pre": sha, "post": sha, "by": [command, ..], "grades": {target: {addr: [name,
//! code, readability]}}}}. A write is remembered only when the target store's last compile of the unit was of the
//! file as dcp found it (its src_hash is the sha before the write): the unit's grades then are the grades before
//! dcp's change, and dcp's change is the only one. A later dcp write of the same file extends the record. The
//! refresh after the unit's next compile (glue::refresh) compares the grades and forgets the record; a file changed
//! since by anyone else is forgotten silently.

use serde_json::{json, Map, Value};
use std::path::Path;
use std::sync::Mutex;

static COMMAND: Mutex<String> = Mutex::new(String::new());

/// The command line being run (cli::run): what a record names as the writer.
pub fn set_command(c: &str) {
    *COMMAND.lock().unwrap() = c.to_string();
}

fn command() -> String {
    let c = COMMAND.lock().unwrap().clone();
    if c.is_empty() { "a dcp command".into() } else { format!("dcp {c}") }
}

const FILE: &str = "build/dcp-writes.json";

fn sha(b: &[u8]) -> String {
    crate::fsmemo::hex(&<sha2::Sha256 as sha2::Digest>::digest(b))
}

/// The project root above a path (the directory holding decompanion.toml) and the path relative to it (posix).
fn locate(path: &str) -> Option<(std::path::PathBuf, String)> {
    let p = std::path::absolute(path).ok()?;
    let root = p.ancestors().skip(1).find(|d| d.join(crate::project::CONFIG_NAME).is_file())?.to_path_buf();
    let rel = p.strip_prefix(&root).ok()?.to_string_lossy().replace('\\', "/");
    Some((root, rel))
}

fn load(root: &Path) -> Map<String, Value> {
    std::fs::read(root.join(FILE)).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| v.as_object().cloned()).unwrap_or_default()
}

fn save(root: &Path, m: &Map<String, Value>) {
    let path = root.join(FILE);
    if m.is_empty() {
        let _ = std::fs::remove_file(&path);
        return;
    }
    let _ = std::fs::write(&path, serde_json::to_string_pretty(&Value::Object(m.clone())).unwrap_or_default());
}

/// The target stores of a project: build/<target>.sqlite.
fn stores(root: &Path) -> Vec<(String, String)> {
    let mut out = vec![];
    for e in std::fs::read_dir(root.join("build")).into_iter().flatten().flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if let Some(t) = n.strip_suffix(".sqlite") {
            out.push((t.to_string(), crate::project::native_path(&e.path().to_string_lossy())));
        }
    }
    out.sort();
    out
}

/// The unit whose file is rel in a store's compile table, and the sha its last compile read.
fn unit_of(db: &str, rel: &str) -> Option<(String, String)> {
    let keys = crate::compile::tu_keys(db).ok()?;
    keys.into_iter().find(|(_, k)| k.amalg == rel).map(|(u, k)| (u, k.src_hash))
}

/// {addr: [name, code, readability]} of a unit's functions in a store.
fn grades(db: &str, unit: &str) -> Map<String, Value> {
    let rows = crate::queues::function_grades(db).map(|r| r.to_vec()).unwrap_or_default();
    let s = |r: &Map<String, Value>, k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    rows.iter().filter(|r| s(r, "unit") == unit)
        .map(|r| (format!("{:#010x}", r["addr"].as_i64().unwrap_or(0)), json!([s(r, "name"), s(r, "code"), s(r, "readability")]))).collect()
}

/// A dcp write of a file: `pre` its bytes before (None: it did not exist), `post` the bytes written.
pub fn note(path: &str, pre: Option<&[u8]>, post: &[u8]) {
    if !(path.ends_with(".c") || path.ends_with(".C")) {
        return;
    }
    let Some((root, rel)) = locate(path) else { return };
    let Some(pre) = pre else { return };
    let (pre, post) = (sha(pre), sha(post));
    if pre == post {
        return;
    }
    let mut m = load(&root);
    let by = command();
    // a later dcp write of a file dcp wrote last: the record grows
    if let Some(r) = m.get_mut(&rel).and_then(|r| r.as_object_mut()).filter(|r| r.get("post").and_then(|v| v.as_str()) == Some(pre.as_str())) {
        r.insert("post".into(), Value::from(post));
        if let Some(Value::Array(b)) = r.get_mut("by") {
            if b.last().and_then(|v| v.as_str()) != Some(by.as_str()) {
                b.push(Value::from(by));
            }
        }
        save(&root, &m);
        return;
    }
    let mut snap = Map::new();
    for (target, db) in stores(&root) {
        if let Some((unit, built)) = unit_of(&db, &rel) {
            if built == pre {
                snap.insert(target, Value::Object(grades(&db, &unit)));
            }
        }
    }
    if snap.is_empty() {
        // the unit was changed since its last compile (or never compiled): dcp's change is not the only one
        m.remove(&rel);
    } else {
        m.insert(rel, json!({"pre": pre, "post": post, "by": [by], "grades": snap}));
    }
    save(&root, &m);
}

/// After a refresh of a target: the falls of the functions of every unit dcp rewrote last whose compile now reads
/// that text, against their grades before the write, as warning lines. The records answered are forgotten.
pub fn falls(root: &Path, target: &str, db: &str) -> Vec<String> {
    let mut m = load(root);
    if m.is_empty() {
        return vec![];
    }
    let mut out = vec![];
    let mut changed = false;
    for rel in m.keys().cloned().collect::<Vec<_>>() {
        let r = m[&rel].clone();
        let post = r["post"].as_str().unwrap_or("").to_string();
        let now = crate::fsmemo::sha256(&crate::project::native_path(&root.join(&rel).to_string_lossy())).unwrap_or_default();
        if now != post {
            // changed since by someone else (or gone): no longer dcp's change alone
            m.remove(&rel);
            changed = true;
            continue;
        }
        let Some(before) = r["grades"].get(target).and_then(|g| g.as_object()) else { continue };
        let Some((unit, built)) = unit_of(db, &rel) else { continue };
        if built != post {
            continue; // not compiled from dcp's text yet
        }
        let after = grades(db, &unit);
        let by = r["by"].as_array().map(|b| b.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", then ")).unwrap_or_default();
        for (addr, b) in before {
            let (name, code, rd) = (b[0].as_str().unwrap_or(""), b[1].as_str().unwrap_or(""), b[2].as_str().unwrap_or(""));
            let (ncode, nrd) = match after.get(addr) {
                Some(a) => (a[1].as_str().unwrap_or("").to_string(), a[2].as_str().unwrap_or("").to_string()),
                None => ("none".to_string(), "none".to_string()),
            };
            if crate::queues::at_least(&ncode, &nrd, &format!("{code}+{rd}")) {
                continue;
            }
            out.push(format!("WARNING: {addr} {name} fell {code}+{rd} -> {ncode}+{nrd} in {rel}, whose only change since its last compile was \
                              made by dcp ({by}): if the command did not name {name}, the dcp writer changed more than it should \
                              (git diff {rel}; a dcp bug to report)"));
        }
        let o = m.get_mut(&rel).and_then(|x| x.as_object_mut()).unwrap();
        if let Some(Value::Object(g)) = o.get_mut("grades") {
            g.remove(target);
            if g.is_empty() {
                m.remove(&rel);
            }
        }
        changed = true;
    }
    if changed {
        save(root, &m);
    }
    out
}
