//! The names the ledger knows for addresses, as the reading and drafting commands spell them (dcp disasm, dump,
//! refs, draft): one C name per address, chosen by a fixed order of origins, never guessed.
//!
//! Order (the first origin that names an address wins):
//!   source   the definition in our sources (L.src: a sourced function, a data definition or extern)
//!   decl     `ADDR name NAME` in decl/*.dcl
//!   export   the export table (proven)
//!   entry    the user entry the start-up code calls (S.entry.user: DllMain, WinMain, main)
//!   lib      a placed library member's symbol (S.crt.code / S.crt.refs / S.crt.data), undecorated by the
//!            toolchain (`_fclose` -> fclose); of `a|b` aliases (members with identical bytes) the one a lib name
//!            of its own names (S.crt.refs: the library's relocations call `_memmove`, not `_memcpy`), else the
//!            first in sorted order
//!   import   an import slot (`KERNEL32.dll!GetTickCount` -> GetTickCount) and the import thunk that jumps through
//!            it (`thunk:WS2_32.dll!#3`: by ordinal, no name)
//!   analyzer the name the analyzer gave a function it found (its drafts, `dcp setup`), unless the analyzer calls
//!            it one of its own placeholders (Ghidra's dialect, Ghidra's drafts: FUN_, thunk_FUN_, LAB_,
//!            SUB_, DAT_, PTR_ and a hex number)
//! A thunk or slot imported by ordinal takes the analyzer's name for it when there is one.

use crate::error::Result;
use crate::store::{self, Claim};
use crate::with_db;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::rc::Rc;

const ORDER: [&str; 7] = ["source", "decl", "export", "entry", "lib", "import", "analyzer"];

fn is_ident(s: &str) -> bool {
    let mut c = s.chars();
    c.next().is_some_and(|f| f.is_ascii_alphabetic() || f == '_') && c.all(|x| x.is_alphanumeric() || x == '_')
}

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

/// address -> (C name, origin), name -> addresses; the symbols for annotation.
pub struct Names {
    pub(crate) at: HashMap<i64, (String, String)>,
    pub(crate) all_at: HashMap<i64, Vec<(String, String)>>,
    pub(crate) by_name: Vec<(String, Vec<i64>)>,
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
        // within an origin, a lib name chosen from an alias set (`_memcpy|_memmove`: members with identical bytes)
        // ranks after a lib name that stands alone (S.crt.refs: the library's own relocations name the member)
        let rank = |o: &str| 2 * ORDER.iter().position(|x| *x == o).unwrap_or(ORDER.len());
        let mut order: Vec<i64> = vec![];
        let mut cands: HashMap<i64, Vec<(usize, String, String)>> = HashMap::new();
        let mut add = |a: i64, c: (usize, String, String)| {
            cands.entry(a).or_insert_with(|| {
                order.push(a);
                vec![]
            }).push(c);
        };
        for f in &names {
            let origin = f.s("origin").unwrap_or("").to_string();
            let raw = f.s("name").unwrap_or("");
            let name = match origin.as_str() {
                "lib" => {
                    let mut ns: Vec<String> = raw.split('|').map(crate::coff::undecorate).collect();
                    ns.sort();
                    Some(ns.swap_remove(0))
                }
                "import" => {
                    let tail = raw.split_once('!').map(|x| x.1).unwrap_or(raw);
                    (!tail.starts_with('#')).then(|| tail.to_string())
                }
                _ => Some(raw.to_string()),
            };
            if let Some(n) = name.filter(|n| is_ident(n)) {
                let chosen = origin == "lib" && raw.contains('|');
                add(f.lo, (rank(&origin) + chosen as usize, n, origin));
            }
        }
        for v in &drafts {
            let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("");
            let az = v.get("analyzer").and_then(|x| x.as_str()).unwrap_or("");
            if !name.is_empty() && !analyzer_placeholder(az, name) && is_ident(name) {
                add(v["start"].as_i64().unwrap_or(0), (rank("analyzer"), name.to_string(), "analyzer".to_string()));
            }
        }
        let mut at = HashMap::new();
        let mut all_at = HashMap::new();
        let mut by_name: Vec<(String, Vec<i64>)> = vec![];
        let mut by_name_ix: HashMap<String, usize> = HashMap::new();
        for a in &order {
            let cs = cands.get_mut(a).unwrap();
            cs.sort();
            at.insert(*a, (cs[0].1.clone(), cs[0].2.clone()));
            for (_, n, _) in cs.iter() {
                let i = *by_name_ix.entry(n.clone()).or_insert_with(|| {
                    by_name.push((n.clone(), vec![]));
                    by_name.len() - 1
                });
                if !by_name[i].1.contains(a) {
                    by_name[i].1.push(*a);
                }
            }
            let set: BTreeSet<(String, String)> = cs.iter().map(|(_, n, o)| (n.clone(), o.clone())).collect();
            all_at.insert(*a, set.into_iter().collect());
        }
        let mut syms = symbols;
        syms.sort_by_key(|f| (f.lo, f.hi));
        Ok(Names { at, all_at, by_name, syms, image: image.to_string(), db: db_path.to_string(), objects: std::cell::OnceCell::new() })
    }

    pub fn name_of(&self, a: i64) -> Option<&str> {
        self.at.get(&a).map(|x| x.0.as_str())
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
        assert!(is_ident("_f1") && !is_ident("1f") && !is_ident("a-b"));
    }
}
