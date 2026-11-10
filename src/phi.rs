//! φ, the correspondence: which object of ours is which address of the original. Its entries come from
//! the `name` claims: our address comments (`source`) and declarations (`decl`) are φ for our own objects, a placed
//! library member's symbols (`lib`) φ for the toolchain's part of ours, the export and import tables (`export`,
//! `import`) and the CRT's user entry (`entry`) names the image itself holds; an analyzer's drafts (`analyzer`) add
//! names for display only, never a correspondence. One index, built from those claims, answers both directions:
//! φ(name) (the addresses an object of ours is at, with their support) and φ⁻¹(address) (the our objects there).
//!
//! φ is many-to-one where the toolchain folds objects (identical library members `a|b`, pooled literals) or an
//! alias is declared; two of our own definitions at one address without such a reason are ill-formed (L.src, N2,
//! C.name.alias).

use crate::store::{Claim, Support, OPEN};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;

/// Where an entry of φ comes from, in the order a display name is chosen (the first origin that names an address
/// wins).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    /// an address comment of our sources (L.src)
    Source,
    /// `ADDR name NAME` in decl/*.dcl (L.decl)
    Decl,
    /// the export table (S.exports)
    Export,
    /// the user entry the start-up code calls (S.entry.user)
    Entry,
    /// a placed library member's symbol (S.crt.code, S.crt.refs, S.crt.data, S.lib.data)
    Lib,
    /// an import address-table slot or its thunk (S.imports, S.thunk)
    Import,
    /// the analyzer's name for a function it found (drafts): display only
    Analyzer,
}

impl Origin {
    pub fn parse(s: &str) -> Option<Origin> {
        Some(match s {
            "source" => Origin::Source,
            "decl" => Origin::Decl,
            "export" => Origin::Export,
            "entry" => Origin::Entry,
            "lib" => Origin::Lib,
            "import" => Origin::Import,
            "analyzer" => Origin::Analyzer,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Origin::Source => "source",
            Origin::Decl => "decl",
            Origin::Export => "export",
            Origin::Entry => "entry",
            Origin::Lib => "lib",
            Origin::Import => "import",
            Origin::Analyzer => "analyzer",
        }
    }
}

/// One entry of φ: the C name of an object of ours at an address of the original.
#[derive(Clone, Debug)]
pub struct Entry {
    /// the C spelling (a library symbol undecorated, an import's symbol without its DLL)
    pub name: String,
    /// the name as the claim spells it (`_memcpy|_memmove`, `KERNEL32.dll!GetTickCount`)
    pub raw: String,
    pub addr: i64,
    pub origin: Origin,
    pub support: Support,
    /// the claim's producer (`src:src/net.c:12`, `rule:S.exports@1`); the analyzer's drafts: `analyzer:<key>`
    pub by: String,
    /// one name of several the toolchain folded into one object (identical library members `a|b`)
    pub folded: bool,
    /// a view (`(*(T *)((char *)&C + OFF))`): the container's name
    pub view: Option<String>,
    /// a data object's declared size (sizeof, the front end's): its extent in our sources
    pub size: Option<i64>,
}

impl Entry {
    /// Whether a display picks it: an identifier (an import by ordinal has none).
    fn shown(&self) -> bool {
        is_ident(&self.name)
    }
}

pub(crate) fn is_ident(s: &str) -> bool {
    let mut c = s.chars();
    c.next().is_some_and(|f| f.is_ascii_alphabetic() || f == '_') && c.all(|x| x.is_alphanumeric() || x == '_')
}

/// The index over φ's entries.
#[derive(Default)]
pub struct Phi {
    pub entries: Vec<Entry>,
    by_name: HashMap<String, BTreeMap<i64, Support>>,
    by_addr: BTreeMap<i64, Vec<usize>>,
    sizes: HashMap<String, i64>,
}

impl Phi {
    /// φ from the `name` claims (and, for display, the analyzer's drafts: `{start, name, analyzer}`).
    pub fn new(names: &[Rc<Claim>], drafts: &[Value]) -> Phi {
        let mut entries: Vec<Entry> = vec![];
        for f in names {
            let Some(origin) = f.s("origin").and_then(Origin::parse) else { continue };
            let raw = f.s("name").unwrap_or("");
            let parts: Vec<&str> = raw.split('|').collect();
            for n in &parts {
                let name = match origin {
                    Origin::Import => n.split_once('!').map(|x| x.1).unwrap_or(n).to_string(),
                    Origin::Lib => crate::coff::undecorate(n),
                    _ => n.to_string(),
                };
                entries.push(Entry { name, raw: raw.to_string(), addr: f.lo, origin, support: f.support, by: f.by.clone(),
                                     folded: parts.len() > 1, view: f.s("view").map(String::from),
                                     size: f.value.get("size").and_then(|v| v.as_i64()).filter(|&n| n > 0) });
            }
        }
        let mut by_name: HashMap<String, BTreeMap<i64, Support>> = HashMap::new();
        for e in &entries {
            let s = by_name.entry(e.name.clone()).or_default().entry(e.addr).or_insert(OPEN);
            *s = (*s).max(e.support);
        }
        for v in drafts {
            let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("");
            let az = v.get("analyzer").and_then(|x| x.as_str()).unwrap_or("");
            if !name.is_empty() && !crate::names::analyzer_placeholder(az, name) {
                entries.push(Entry { name: name.to_string(), raw: name.to_string(), addr: v["start"].as_i64().unwrap_or(0), origin: Origin::Analyzer,
                                     support: crate::store::DECLARED, by: format!("analyzer:{az}"), folded: false, view: None, size: None });
            }
        }
        let mut by_addr: BTreeMap<i64, Vec<usize>> = BTreeMap::new();
        for (i, e) in entries.iter().enumerate() {
            by_addr.entry(e.addr).or_default().push(i);
        }
        let mut sizes: HashMap<String, i64> = HashMap::new();
        for e in &entries {
            if let Some(n) = e.size {
                sizes.entry(e.name.clone()).or_insert(n);
            }
        }
        Phi { entries, by_name, by_addr, sizes }
    }

    /// φ(name): the addresses the object of ours of this C name corresponds to, each at its best support (no
    /// analyzer name: those are no correspondence).
    pub fn of(&self, name: &str) -> Option<&BTreeMap<i64, Support>> {
        self.by_name.get(name)
    }

    /// The declared size of the object of ours of this C name (sizeof, the front end's), when a declaration with an
    /// address gives one: references stay inside [0, size] of it (one past the end allowed).
    pub fn size_of(&self, name: &str) -> Option<i64> {
        self.sizes.get(name).copied()
    }

    /// φ⁻¹(addr): the entries at an address, in claim order.
    pub fn at(&self, addr: i64) -> impl Iterator<Item = &Entry> {
        self.by_addr.get(&addr).into_iter().flatten().map(|&i| &self.entries[i])
    }

    /// The C names of the our objects at an address (no analyzer name), sorted.
    pub fn names_at(&self, addr: i64) -> BTreeSet<String> {
        self.at(addr).filter(|e| e.origin != Origin::Analyzer).map(|e| e.name.clone()).collect()
    }

    /// The addresses φ maps something to, in order.
    pub fn addrs(&self) -> impl Iterator<Item = i64> + '_ {
        self.by_addr.keys().copied()
    }

    /// The entries a display ranks at an address, best first: by origin, a name chosen from a fold after one that
    /// stands alone (S.crt.refs: the library's own relocations name the member), then by name.
    pub fn ranked(&self, addr: i64) -> Vec<&Entry> {
        let mut v: Vec<&Entry> = self.at(addr).filter(|e| e.shown()).collect();
        v.sort_by(|a, b| (a.origin, a.folded, &a.name).cmp(&(b.origin, b.folded, &b.name)));
        v.dedup_by(|a, b| a.name == b.name && a.origin == b.origin);
        v
    }

    /// The name a display gives an address.
    pub fn display(&self, addr: i64) -> Option<&Entry> {
        self.ranked(addr).into_iter().next()
    }

    /// The addresses where φ is many-to-one: several distinct C names of ours (no analyzer's, a view is its own
    /// object), with the entries.
    pub fn many(&self) -> Vec<(i64, Vec<&Entry>)> {
        self.by_addr.keys().filter_map(|&a| {
            let es: Vec<&Entry> = self.at(a).filter(|e| e.origin != Origin::Analyzer && e.view.is_none()).collect();
            let names: BTreeSet<&str> = es.iter().map(|e| e.name.as_str()).collect();
            (names.len() > 1).then_some((a, es))
        }).collect()
    }

    /// Why φ is many-to-one at an address, when the toolchain or the image explains it: the library folds identical
    /// members (`folded`); the image's own spellings of one object (an export and its library symbol, an import
    /// slot and its thunk, the user entry and the CRT's decorated name) are one object.
    pub fn many_reason(es: &[&Entry]) -> Option<&'static str> {
        if es.iter().any(|e| e.folded) {
            return Some("folded: identical library members");
        }
        let ours = es.iter().filter(|e| matches!(e.origin, Origin::Source | Origin::Decl)).map(|e| e.name.as_str()).collect::<BTreeSet<_>>();
        if ours.len() <= 1 {
            return Some("one object, spelled by the image and the toolchain");
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn claim(lo: i64, v: Value, support: Support) -> Rc<Claim> {
        let mut text = String::new();
        crate::store::canon(&mut text, &v);
        Rc::new(Claim { id: lo, rule: Rc::from("T"), lo, hi: lo + 1, text, value: v, support, by: format!("t:{lo:x}"), reason: None })
    }

    #[test]
    fn both_directions_and_display() {
        let names = vec![
            claim(0x100, json!({"name": "_memcpy|_memmove", "origin": "lib"}), crate::store::REPRODUCED),
            claim(0x100, json!({"name": "_memmove", "origin": "lib"}), crate::store::REPRODUCED),
            claim(0x200, json!({"name": "KERNEL32.dll!GetTickCount", "origin": "import"}), crate::store::OBSERVED),
            claim(0x204, json!({"name": "WS2_32.dll!#3", "origin": "import"}), crate::store::OBSERVED),
            claim(0x300, json!({"name": "net_Send", "origin": "source"}), crate::store::DECLARED),
            claim(0x300, json!({"name": "net_Send", "origin": "export"}), crate::store::OBSERVED),
            claim(0x400, json!({"name": "g_a", "origin": "source"}), crate::store::DECLARED),
            claim(0x400, json!({"name": "g_b", "origin": "source"}), crate::store::DECLARED),
        ];
        let drafts = vec![json!({"start": 0x500, "name": "FUN_00000500", "analyzer": "ghidra"}), json!({"start": 0x500, "name": "Tick", "analyzer": "ghidra"})];
        let phi = Phi::new(&names, &drafts);
        assert_eq!(phi.of("memmove").map(|m| m.iter().map(|(a, s)| (*a, *s)).collect::<Vec<_>>()), Some(vec![(0x100, crate::store::REPRODUCED)]));
        assert_eq!(phi.of("net_Send").unwrap()[&0x300], crate::store::OBSERVED); // the best support of the address
        assert!(phi.of("Tick").is_none()); // an analyzer's name is no correspondence
        assert_eq!(phi.names_at(0x100).into_iter().collect::<Vec<_>>(), ["memcpy", "memmove"]);
        // display: the lib name that stands alone over one chosen from a fold; an ordinal import has none
        assert_eq!(phi.display(0x100).map(|e| e.name.as_str()), Some("memmove"));
        assert_eq!(phi.display(0x200).map(|e| e.name.as_str()), Some("GetTickCount"));
        assert!(phi.display(0x204).is_none());
        assert_eq!(phi.display(0x300).map(|e| e.origin), Some(Origin::Source));
        assert_eq!(phi.display(0x500).map(|e| e.name.as_str()), Some("Tick"));
        // many-to-one: the fold is explained, two of our own names at one address are not
        let many: Vec<(i64, Option<&str>)> = phi.many().iter().map(|(a, es)| (*a, Phi::many_reason(es))).collect();
        assert_eq!(many, [(0x100, Some("folded: identical library members")), (0x400, None)]);
    }
}
