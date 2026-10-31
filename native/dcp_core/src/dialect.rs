//! An analyzer's dialect: how a draft reads the pseudocode of an analyzer (analyzers/: the key of a stored entry
//! names it). Ghidra's (and REA's, whose files are Ghidra output):
//!   placeholders   FUN_<hex>, thunk_FUN_<hex>, LAB_, SUB_, DAT_, PTR_ + hex: Ghidra's names for what it does not know
//!   functions      FUN_<hex> / thunk_FUN_<hex>, or a name Ghidra gave an address
//!   data labels    DAT_<hex>, _DAT_<hex>, PTR_..._<hex>, s_..._<hex>, u_..._<hex>, BYTE_ / WORD_ / DWORD_ / QWORD_ /
//!                  FLOAT_ / DOUBLE_ / UNK_..._<hex>, typed by the prefix (else undefined4)
//!   types          undefined1..8, uint, byte, CONCAT / SUB / ZEXT / SEXT ...: the shipped dcp_ghidra.h
//! Any other key reads as no dialect: the body unchanged, no typed labels, `int` for an unknown datum.

use regex::Regex;
use std::collections::BTreeMap;
use std::sync::LazyLock;

static FUN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(?:thunk_)?FUN_([0-9a-fA-F]{8})\b").unwrap());
static FUN_WHOLE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(?:thunk_)?FUN_([0-9a-fA-F]{8})$").unwrap());
static LABEL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(_?DAT|PTR|s|u|BYTE|WORD|DWORD|QWORD|FLOAT|DOUBLE|UNK)_\w*?([0-9a-fA-F]{8})\b").unwrap());

/// The header of Ghidra's type names and macros the drafts use (written to include/ by `dcp draft`).
pub const GHIDRA_HEADER: (&str, &str) = ("dcp_ghidra.h", include_str!("../../../src/decompanion/data/dcp_ghidra.h"));

pub struct Dialect {
    ghidra: bool,
}

/// The dialect of an analyzer key.
pub fn of(key: &str) -> Dialect {
    Dialect { ghidra: matches!(key, "ghidra" | "rea") }
}

/// The file names of every analyzer's types header.
pub fn types_headers() -> Vec<&'static str> {
    vec![GHIDRA_HEADER.0]
}

impl Dialect {
    /// (file name, text) of the shipped header whose type names the drafts use, None when none is needed.
    pub fn types_header(&self) -> Option<(&'static str, &'static str)> {
        self.ghidra.then_some(GHIDRA_HEADER)
    }

    /// The type of a datum the body names without a typed label.
    pub fn unknown_data_type(&self) -> &'static str {
        if self.ghidra { "undefined4" } else { "int" }
    }

    /// The body with the tool's labels replaced: `own` = (the tool's name of the drafted function, ours), `labels` =
    /// {the tool's name: address} of every function it named; func / data spell an address.
    pub fn rewrite(&self, body: &str, own: (&str, &str), func: &dyn Fn(i64) -> String, data: &dyn Fn(i64) -> String, labels: &BTreeMap<String, i64>) -> String {
        if !self.ghidra {
            return body.to_string();
        }
        let (theirs, ours) = own;
        let mut out = body.to_string();
        if !theirs.is_empty() {
            out = Regex::new(&format!(r"\b{}\b", regex::escape(theirs))).unwrap().replace_all(&out, regex::NoExpand(ours)).into_owned();
        }
        out = FUN.replace_all(&out, |c: &regex::Captures| func(i64::from_str_radix(&c[1], 16).unwrap_or(0))).into_owned();
        let named: BTreeMap<&String, i64> = labels.iter().filter(|(n, _)| !FUN_WHOLE.is_match(n) && n.as_str() != theirs).map(|(n, a)| (n, *a)).collect();
        if !named.is_empty() {
            let mut alts: Vec<&&String> = named.keys().collect();
            alts.sort_by_key(|n| std::cmp::Reverse(n.len()));
            let pat = Regex::new(&format!(r"\b({})\b", alts.iter().map(|n| regex::escape(n)).collect::<Vec<_>>().join("|"))).unwrap();
            out = pat.replace_all(&out, |c: &regex::Captures| func(named[&c[1].to_string()])).into_owned();
        }
        LABEL.replace_all(&out, |c: &regex::Captures| data(i64::from_str_radix(&c[2], 16).unwrap_or(0))).into_owned()
    }

    /// {address: C type} of the data labels in a body, typed by the label's spelling.
    pub fn data_labels(&self, body: &str) -> BTreeMap<i64, String> {
        let mut types = BTreeMap::new();
        if !self.ghidra {
            return types;
        }
        for c in LABEL.captures_iter(body) {
            let t = match &c[1] {
                "PTR" => "undefined *",
                "s" | "u" => "char []",
                "BYTE" => "undefined1",
                "WORD" => "undefined2",
                "QWORD" => "undefined8",
                "FLOAT" => "float",
                "DOUBLE" => "double",
                _ => self.unknown_data_type(),
            };
            types.entry(i64::from_str_radix(&c[2], 16).unwrap_or(0)).or_insert_with(|| t.to_string());
        }
        types
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ghidra_names_and_labels() {
        let d = of("ghidra");
        let body = "void FUN_00401000(void)\n{\n  FUN_00402000(DAT_00601000, s_hello_00601010);\n  thunk_FUN_00403000();\n  helper(PTR_x_00601020);\n}\n";
        let labels: BTreeMap<String, i64> = [("helper".to_string(), 0x404000), ("FUN_00402000".to_string(), 0x402000)].into_iter().collect();
        let out = d.rewrite(body, ("FUN_00401000", "mine"), &|a| format!("f_{a:x}"), &|a| format!("d_{a:x}"), &labels);
        assert_eq!(out, "void mine(void)\n{\n  f_402000(d_601000, d_601010);\n  f_403000();\n  f_404000(d_601020);\n}\n");
        let t = d.data_labels(body);
        assert_eq!((t[&0x601000].as_str(), t[&0x601010].as_str(), t[&0x601020].as_str()), ("undefined4", "char []", "undefined *"));
        assert_eq!(of("none").rewrite(body, ("x", "y"), &|_| String::new(), &|_| String::new(), &labels), body);
    }
}
