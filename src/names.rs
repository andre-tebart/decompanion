//! The names the reading and drafting commands spell addresses with (dcp disasm, dump, refs, draft, asmdiff): φ
//! (phi.rs) as a display, one C name per address, chosen by φ's order of origins (source, decl, export, entry, lib,
//! import, analyzer: the first that names an address wins), never guessed. Of a fold `a|b` (library members with
//! identical bytes) the name a lib name of its own names wins (S.crt.refs: the library's relocations call
//! `_memmove`, not `_memcpy`), else the first in sorted order. An import by ordinal has no name; its thunk or slot
//! takes the analyzer's when there is one.

use crate::error::Result;
use crate::phi::{Origin, Phi};
use crate::store::{self, Claim};
use crate::with_db;
use serde_json::Value;
use std::collections::HashMap;
use std::rc::Rc;

/// Whether an analyzer calls a name one of its own placeholders.
pub fn analyzer_placeholder(analyzer: &str, name: &str) -> bool {
    if analyzer != "ghidra" {
        return false;
    }
    let n = name.strip_prefix("thunk_").unwrap_or(name);
    ["FUN_", "LAB_", "SUB_", "DAT_", "PTR_"].iter().any(|p| {
        n.strip_prefix(p).is_some_and(|h| !h.is_empty() && h.chars().all(|c| c.is_ascii_hexdigit()))
    })
}

/// The drafts of a store (main's and the overlay's, by start, the overlay's replacing main's), sorted by start.
pub fn draft_values(db: &rusqlite::Connection, main: &str) -> rusqlite::Result<Vec<Value>> {
    let mut by_start: std::collections::BTreeMap<i64, Value> = std::collections::BTreeMap::new();
    let mut sources = vec![];
    if crate::storedb::ensure_main(db, main)? {
        sources.push("main_store.blob");
    }
    sources.push("blob");
    for s in sources {
        let mut st = db.prepare(&format!("SELECT data FROM {s} WHERE kind='drafts'"))?;
        let rows = st.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        for d in rows {
            let v: Value = serde_json::from_slice(&d?).unwrap_or(Value::Null);
            if let Some(a) = v.get("start").and_then(|x| x.as_i64()) {
                by_start.insert(a, v);
            }
        }
    }
    Ok(by_start.into_values().collect())
}


/// The size from which a data object can be an array or a record a loop runs over to its end (Names::end_label).
const END_MIN: i64 = 0x10;

/// The rules whose `name` claims place a name at an address (the ledger's names): G.grade needs them all, so
/// its binding (equiv::bind by name) reruns when one changes.
pub const NAME_RULES: &[&str] = &["L.decl", "L.src", "S.imports", "S.exports", "S.crt.code", "S.lib.data", "S.crt.refs", "S.crt.data",
                                  "S.thunk", "S.entry.user"];

/// The address each name of `claims` (`name` claims) places at exactly one address: what a relocation's symbol
/// binds to when no aligned site binds it (equiv::bind). G.grade and dcp diffclass bind through the same map.
pub fn unique_addrs(claims: &[Rc<Claim>]) -> HashMap<String, u32> {
    let mut at: HashMap<String, Option<u32>> = HashMap::new();
    for c in claims {
        let Some(n) = c.s("name") else { continue };
        let e = at.entry(n.to_string()).or_insert(Some(c.lo as u32));
        if *e != Some(c.lo as u32) {
            *e = None;
        }
    }
    at.into_iter().filter_map(|(n, a)| Some((n, a?))).collect()
}

/// unique_addrs over the current `name` claims of a store.
pub fn ledger_addrs(db_path: &str) -> Result<HashMap<String, u32>> {
    let rules: Vec<String> = NAME_RULES.iter().map(|r| r.to_string()).collect();
    with_db(db_path, |db| Ok(unique_addrs(&store::claims(db, db_path, "name", &rules, |_| true)?)))
}

/// φ with the symbols, for annotation.
pub struct Names {
    pub phi: Phi,
    /// a shown name -> the addresses φ gives it (any origin, the analyzer's too), sorted
    shown: HashMap<String, Vec<i64>>,
    syms: Vec<Rc<Claim>>,
    image: String,
    db: String,
    /// every data object's (lo, hi) of every rule (the match phase's too), sorted: Names::end_label, loaded on use
    objects: std::cell::OnceCell<Vec<(i64, i64)>>,
}

impl Names {
    pub fn build(db_path: &str, main: &str, image: &str) -> Result<Names> {
        let (names, symbols, drafts) = with_db(db_path, |db| {
            let names = store::claims_of(db, db_path, "name", None, |_| true)?;
            let symbols = store::claims_of(db, db_path, "symbol", None, |f| !f.rule.starts_with("M."))?;
            Ok((names, symbols, draft_values(db, main)?))
        })?;
        let phi = Phi::new(&names, &drafts);
        let mut shown: HashMap<String, Vec<i64>> = HashMap::new();
        for a in phi.addrs() {
            for e in phi.ranked(a) {
                let v = shown.entry(e.name.clone()).or_default();
                if !v.contains(&a) {
                    v.push(a);
                }
            }
        }
        for v in shown.values_mut() {
            v.sort_unstable();
        }
        let mut syms = symbols;
        syms.sort_by_key(|f| (f.lo, f.hi));
        Ok(Names { phi, shown, syms, image: image.to_string(), db: db_path.to_string(), objects: std::cell::OnceCell::new() })
    }

    /// The name a display gives an address.
    pub fn name_of(&self, a: i64) -> Option<&str> {
        self.phi.display(a).map(|e| e.name.as_str())
    }

    /// Where that name comes from.
    pub fn origin_of(&self, a: i64) -> Option<Origin> {
        self.phi.display(a).map(|e| e.origin)
    }

    /// Every name a display could give an address, best first.
    pub fn names_at(&self, a: i64) -> Vec<String> {
        self.phi.ranked(a).into_iter().map(|e| e.name.clone()).collect()
    }

    /// The addresses a name spells (any origin), sorted; empty when it names nothing.
    pub fn addrs_of(&self, name: &str) -> &[i64] {
        self.shown.get(name).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn symbol_at(&self, a: i64) -> Option<&Rc<Claim>> {
        let i = self.syms.partition_point(|f| f.lo <= a) as i64 - 1;
        let mut j = i;
        while j >= 0 && j > i - 4 {
            let f = &self.syms[j as usize];
            if f.lo <= a && a < f.hi {
                return Some(f);
            }
            j -= 1;
        }
        None
    }

    /// The other reading of an address a compare uses as a bound: `obj+off` from the nearest named data object of
    /// END_MIN bytes at least below the one holding it that the same code refers to (`used`: the function's other
    /// image addresses). A loop
    /// runs a pointer from inside an array to its end pointer `&arr[N]` or `&arr[N].field`, which lies at or
    /// inside the next object (a match-base report: `cmp ecx, 0xfb91e4` read as d3s_Lights+0x4, really
    /// &d2_Views[0x30].nwins, and led to wrong code; the loop's start `mov ecx, 0xfb1450` lies in d2_Views). None
    /// when the code refers to no named object below it (within 1 MB).
    pub fn end_label(&self, a: i64, used: &[i64]) -> Option<String> {
        let objs = self.objects.get_or_init(|| {
            let fs = with_db(&self.db, |db| store::claims_of(db, &self.db, "symbol", None, |f| f.s("skind") == Some("global"))).unwrap_or_default();
            let mut v: Vec<(i64, i64)> = fs.iter().map(|f| (f.lo, f.hi)).collect();
            v.sort();
            v.dedup();
            v
        });
        // the data object holding x (any rule's extent)
        let holder = |x: i64| -> Option<(i64, i64)> {
            let k = objs.partition_point(|o| o.0 <= x);
            objs[..k].iter().rev().take(8).find(|o| o.0 <= x && x < o.1).copied()
        };
        let here = holder(a).map(|o| o.0).unwrap_or(a);
        // an array or a record (END_MIN bytes at least: a scalar has no end pointer) the code refers to
        let best = used.iter().filter(|&&r| r < here && here - r <= 0x100000).filter_map(|&r| holder(r))
            .filter(|o| o.0 < here && o.1 - o.0 >= END_MIN && self.name_of(o.0).is_some()).map(|o| o.0).max()?;
        Some(format!("{}+{}", self.name_of(best)?, crate::x86::py_hex(a - best)))
    }

    /// How `dcp disasm` / `dcp dump` spell an address: its name, else `name+off` inside a named symbol (not an
    /// unknown run), else a string's text, else None.
    pub fn label_of(&self, a: i64) -> Result<Option<String>> {
        if let Some(n) = self.name_of(a) {
            return Ok(Some(n.to_string()));
        }
        let Some(f) = self.symbol_at(a) else { return Ok(None) };
        let sk = f.s("skind").unwrap_or("");
        if sk == "unknown.code" || sk == "unknown.data" {
            return Ok(None);
        }
        if let Some(base) = self.name_of(f.lo) {
            if a != f.lo {
                return Ok(Some(format!("{base}+{}", crate::x86::py_hex(a - f.lo))));
            }
        }
        if sk == "string" && a == f.lo {
            let img = crate::image(&self.image)?;
            let s: String = img.cstr(a as u32).iter().take(40).map(|&c| c as char).collect();
            return Ok(Some(format!("\"{}\"", s.replace('\n', "\\n"))));
        }
        Ok(None)
    }
}

impl Names {
    /// The instruction text with ` <label>` after every number the ledger names (label).
    pub(crate) fn annotate(&self, text: &str) -> Result<String> {
        use std::sync::LazyLock;
        static HEX: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"0x([0-9a-f]+)").unwrap());
        let (mut out, mut pos) = (String::new(), 0);
        for m in HEX.captures_iter(text) {
            let e = m.get(0).unwrap().end();
            out.push_str(&text[pos..e]);
            if let Some(v) = i64::from_str_radix(&m[1], 16).ok() {
                if let Some(l) = self.label_of(v)? {
                    out.push_str(&format!(" <{l}>"));
                }
            }
            pos = e;
        }
        out.push_str(&text[pos..]);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders() {
        assert!(analyzer_placeholder("ghidra", "FUN_10001000"));
        assert!(analyzer_placeholder("ghidra", "thunk_FUN_10001000"));
        assert!(!analyzer_placeholder("ghidra", "FUN_"));
        assert!(!analyzer_placeholder("ghidra", "net_Send"));
        assert!(!analyzer_placeholder("none", "FUN_10001000"));
        assert!(crate::phi::is_ident("_f1") && !crate::phi::is_ident("1f") && !crate::phi::is_ident("a-b"));
    }
}
