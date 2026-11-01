//! The rules: what each reads and emits, its version and the highest support its claims may carry, and its criterion (the text
//! `dcp rules --verbose` prints). Registration order is the order `dcp rules` lists them in; the engine orders them
//! by their needs (engine.rs). A rule's code is the core's (rules.rs dispatch).

use crate::store::{Support, DECLARED, DERIVED, OBSERVED, OPEN, REPRODUCED};

/// What a finding is in the model (docs/mental-model.md §5). Each check id has one category.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Category {
    /// two claims answer one question about one byte differently; the one with less support is revised (H or φ),
    /// two at the top rank are a bug in a rule
    Contradiction,
    /// H is no valid program (a unit does not compile, a declaration line is malformed or has no reason) or φ is
    /// no valid mapping (two definitions at one address, a function of an object without its address comment)
    IllFormed,
    /// open where the model expects an answer: bytes nothing explains, a part of H that is missing (an import
    /// library, a library member)
    Gap,
    /// a result older than H (a stale compile or lint): the next build or lint makes it current
    Stale,
    /// a regression of an experiment (a baseline fall): allowed only as declared debt with its witness
    Debt,
}

impl Category {
    pub const ALL: [Category; 5] = [Category::Contradiction, Category::IllFormed, Category::Gap, Category::Stale, Category::Debt];

    pub fn name(self) -> &'static str {
        match self {
            Category::Contradiction => "contradiction",
            Category::IllFormed => "ill-formed",
            Category::Gap => "gap",
            Category::Stale => "stale",
            Category::Debt => "debt",
        }
    }

    pub fn parse(s: &str) -> Option<Category> {
        Category::ALL.iter().copied().find(|c| c.name() == s)
    }
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Every check id the rules report, with its category. A check id not listed is a contradiction (and a test fails
/// for it: tests below list the ids the code emits).
pub static CHECKS: &[(&str, Category)] = &[
    // two answers to one question
    ("C.overlap", Category::Contradiction),      // owner: two objects own one byte
    ("C.ref.target", Category::Contradiction),   // start: a call lands inside a function
    ("C.walk", Category::Contradiction),         // owner: the walk runs into another function's bytes
    ("C.toolchain", Category::Contradiction),    // toolchain: the declaration against the Rich header
    ("S7", Category::Contradiction),             // section: the entry or an export outside code
    ("S.crt.refs", Category::Contradiction),     // ref: one symbol resolves to two addresses
    ("S.crt.data", Category::Contradiction),     // owner: a member's data placed at two bases
    ("L1", Category::Contradiction),             // start: a sourced function inside another function
    ("L3", Category::Contradiction),             // unit: literal order against the units
    ("L4", Category::Contradiction),             // unit / start: a boundary inside a function or fill
    ("L5", Category::Contradiction),             // start: a name spelling an address where no function starts
    ("L6", Category::Contradiction),             // owner / start: a declaration against the walk
    ("L7", Category::Contradiction),             // unit: the unit extents disagree
    ("L8", Category::Contradiction),             // unit: two leaked source files in one unit
    ("L9", Category::Contradiction),             // start: the analyzer's function holds one of our starts
    ("L13", Category::Contradiction),            // owner: a data declaration at code
    ("L14", Category::Contradiction),            // unit: a function outside its unit's extent
    ("A1", Category::Contradiction),             // ref: a hard-coded address where the original refers
    ("M.ref.missing", Category::Contradiction),  // ref: our constant where the original refers
    ("M7", Category::Contradiction),             // the consistency convention: a call without its declaration
    ("M8", Category::Contradiction),             // ref: our reference against the original's target
    ("M9", Category::Contradiction),             // ref: a string literal's bytes
    ("M10", Category::Contradiction),            // ref: a floating constant's bits
    ("M.flags", Category::Contradiction),        // toolchain: a probed flag the declaration lacks
    ("M.data.content", Category::Contradiction), // owner: a datum's bytes found elsewhere
    ("M.bytes.declared", Category::Contradiction), // unit: dead / foreign bytes across a unit boundary
    ("D1", Category::Contradiction),             // owner: a definition reaches into another object
    ("D4", Category::Contradiction),             // unit order: definition order against address order
    ("D5", Category::Contradiction),             // owner: a tentative definition at an initialised address
    ("D6", Category::Contradiction),             // ref: a pointer-table entry's target
    ("D8", Category::Contradiction),             // owner: the object the original proves against the definitions
    // H is no program, φ no mapping
    ("L.decl", Category::IllFormed),
    ("L.src", Category::IllFormed),
    ("L15", Category::IllFormed),
    ("L16", Category::IllFormed),
    ("N2", Category::IllFormed),
    ("C.name.alias", Category::IllFormed),       // φ many-to-one without a reason the toolchain gives
    ("M.gen", Category::IllFormed),
    ("M.compile", Category::IllFormed),
    ("M2", Category::IllFormed),
    ("M5", Category::IllFormed),
    ("M6", Category::IllFormed),
    ("D7", Category::IllFormed),
    // open where an answer is due
    ("L2", Category::Gap),
    ("L10", Category::Gap),
    ("S2", Category::Gap),
    ("S4", Category::Gap),
    ("S5", Category::Gap),
    ("S.crt.ambiguous", Category::Gap),
    ("S.crt.duplicate", Category::Gap),
    // older than H
    ("M.compile.stale", Category::Stale),
    ("M.lint.stale", Category::Stale),
    // regressions
    ("M1", Category::Debt),
    ("M1.debt", Category::Debt),
];

/// The category of a finding's check id.
pub fn category(check: &str) -> Category {
    CHECKS.iter().find(|c| c.0 == check).map(|c| c.1).unwrap_or(Category::Contradiction)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every check id the core reports has its category, once: the ids of the sources' `finding(` calls with a
    /// literal id, and the ones computed (layout's issues, the scan's errors, constant_mismatches, the placement).
    #[test]
    fn every_check_has_a_category() {
        let mut ids: Vec<String> = vec![];
        for f in std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/src")).unwrap() {
            let p = f.unwrap().path();
            if p.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&p).unwrap();
                let re = regex::Regex::new(r#"finding2?\([^,()]+, "([A-Za-z0-9_.]+)""#).unwrap();
                ids.extend(re.captures_iter(&text).map(|c| c[1].to_string()));
            }
        }
        let computed = ["L3", "L4", "L7", "L8", "L14", "L.src", "L15", "L16", "N2", "M5", "M6", "M9", "M10", "S.crt.ambiguous",
                        "S.crt.duplicate", "C.overlap", "C.ref.target"];
        ids.extend(computed.iter().map(|s| s.to_string()));
        ids.sort();
        ids.dedup();
        let missing: Vec<&String> = ids.iter().filter(|id| !CHECKS.iter().any(|c| c.0 == id.as_str())).collect();
        assert!(missing.is_empty(), "check ids without a category: {missing:?}");
        let mut listed: Vec<&str> = CHECKS.iter().map(|c| c.0).collect();
        listed.sort();
        let n = listed.len();
        listed.dedup();
        assert_eq!(n, listed.len(), "a check id listed twice");
    }
}

/// One rule of the registry.
pub struct RuleDef {
    pub id: &'static str,
    pub version: &'static str,
    pub max_support: Support, // the highest support its claims may carry (store.rs Support)
    pub phase: &'static str,
    pub loader: bool, // turns H and φ (address comments, declarations, drafts) into declared claims
    pub needs: &'static [&'static str], // rule ids, or `kind:<kind>` (every other rule that outputs that kind)
    pub outputs: &'static [&'static str],
    pub inputs: &'static [&'static str], // named external inputs (project.rs input_hash)
    pub doc: &'static str,
}

pub static RULES: &[RuleDef] = &[
    RuleDef {
        id: "C.overlap", version: "2", max_support: REPRODUCED, phase: "C", loader: false,
        needs: &["kind:symbol", "kind:region"], outputs: &[], inputs: &[],
        doc: "Two symbol or region facts that overlap contradict each other (every byte has one owner). Severity\nfrom the two levels: proven against proven is a bug in a rule. Overlaps with an open fact are not\nreported (open is replaced, not contradicted), nor two facts that say the same thing (one interval, one\nsymbol kind: a declaration the walk confirms).",
    },
    RuleDef {
        id: "C.ref.target", version: "1", max_support: REPRODUCED, phase: "C", loader: false,
        needs: &["S.codewalk", "S.crt.code", "S.thunk"], outputs: &[], inputs: &[],
        doc: "A direct call whose target lies strictly inside a function (not at its start) contradicts that function's\nextent or the call's decoding.",
    },
    RuleDef {
        id: "C.name.alias", version: "1", max_support: REPRODUCED, phase: "C", loader: false,
        needs: &["L.src"], outputs: &[], inputs: &[],
        doc: "Several source names declared for one data address (the address comments of definitions and externs; a\nview is another object) are one object under several names: a warning listing each name where it is\ndeclared. Native: native/dcp_core/src/setup.rs c_name_alias.",
    },
    RuleDef {
        id: "C.toolchain", version: "2", max_support: REPRODUCED, phase: "C", loader: false,
        needs: &["S.rich"], outputs: &[], inputs: &["toolchain"],
        doc: "The target's toolchain declaration ([[target]] compiler / linker with reason.compiler / reason.linker, or\nthe [toolchain] defaults it inherits; written by `dcp toolchain declare`) against the Rich header's\ncandidates (S.rich): a declared compiler, linker or cflags without a reason is an error; when the Rich\nheader lists compiler entries, the declared compiler must name the build of one of them (the last number of\nthe declaration); the same for the linker and the linker entries. Waits until both are declared (the\nobligations toolchain.compiler / toolchain.linker).",
    },
    RuleDef {
        id: "S2.rich.members", version: "2", max_support: REPRODUCED, phase: "S2", loader: false,
        needs: &["S.rich", "S.crt.code"], outputs: &[], inputs: &["toolchain"],
        doc: "The Rich header counts library objects: the compiler entries whose build is not the declared compiler's.\nThe placed library members should account for them. Fewer placed members than counted objects is a\nwarning (members whose code was not found, or libraries not configured). Without a compiler declaration\nnothing is counted.",
    },
    RuleDef {
        id: "S7.entry.section", version: "1", max_support: REPRODUCED, phase: "S7", loader: false,
        needs: &["S.sections", "S.exports", "S.entry"], outputs: &[], inputs: &[],
        doc: "The entry point and every export must lie in a code section (Section.holds_code: marked as code or as\nexecutable).",
    },
    RuleDef {
        id: "S5.crt.gaps", version: "1", max_support: REPRODUCED, phase: "S5", loader: false,
        needs: &["S.crt.code", "S.unknown", "S.fill"], outputs: &[], inputs: &[],
        doc: "Unknown code between the first and the last placed library section is library code no member explains\n(a member not in the configured archives, or a section too short or ambiguous to place).",
    },
    RuleDef {
        id: "S4.import.libs", version: "1", max_support: REPRODUCED, phase: "S4", loader: false,
        needs: &[], outputs: &[], inputs: &["libs"],
        doc: "Every DLL the image imports needs an import library for the full link: the toolchain's library archives\nor the target's archives must hold the import library the toolchain names for it\n(Toolchain.import_library_name, compared case-insensitively; VC6: <DLL name>.LIB in VC98/Lib); a missing\none is a warning until the link milestone.",
    },
    RuleDef {
        id: "M.compile", version: "2", max_support: REPRODUCED, phase: "M", loader: false,
        needs: &["S.sections"], outputs: &["build"], inputs: &["objects", "src", "decl", "targets", "config", "toolchain"],
        doc: "One `build` fact per translation unit of the current target (build/tu.py: a unit with at least one\nfunction of the target), at its least function address (the image base when it has none): tu, ok, the\nobject's hash, the flags, its errors (the compiler's diagnostics, file and line in the unit's file) and its\nwarning count, and `stale` when the unit's text or flags changed since the compile the tu table records.\nGate errors (check M.compile): a unit that failed to compile (the first errors), a unit never compiled\n(a warning when the toolchain is not installed: nothing can be compiled on this machine); a stale unit is a\nwarning (`dcp build` compiles it; `dcp check` builds first). An override table\n([[toolchain.unit]]) without a reason is an error. M.gen, the object-vs-source cross-check (the first\nattempt's gen.py): every function the unit's object defines has an address comment of the target (or\n`unlinked`) in the unit, and every such function is defined by the object; either side alone is an error.",
    },
    RuleDef {
        id: "M.match", version: "1", max_support: REPRODUCED, phase: "M", loader: false,
        needs: &["L.src", "S.sections", "S.relocs", "S.codewalk", "S.crt.code", "S.thunk", "S.exports", "S.entry"], outputs: &["symbol", "source"], inputs: &["objects"],
        doc: "R1. A sourced function of the current target (an L.src `source` fact: a candidate, its declared level\ndoes not propagate) whose unit's object defines its function is a byte match when (match/compare.py):\nevery byte of the function's section (from its symbol to the next named symbol or the section end) equals\nthe image's byte at the source's address, relocated fields masked; the original does not continue after\nour last byte (the bytes up to the next known start are toolchain fill, or none); and, when the image\ncarries base relocations (a dll: the complete list of its absolute fields), every absolute relocation site\nof ours is a base-relocation site and the extent holds as many base relocations as we have absolute\nrelocations (`relocs 7/7`). A match owns its bytes: a `symbol` func proven (value: name, unit, file,\nrelocs) from its address to the end of its last instruction that is no alignment fill (CL pads a function's\nsection with fill up to the next function's alignment: the fill keeps its own symbol), or to the first jump\nor index table the walk found for it inside the section (VC6 places a switch's tables in the function's\nsection; the tables keep their own symbols); and a `source` fact (what: match) over the whole section,\nproven. Native: native/dcp_core/src/rules.rs m_match.",
    },
    RuleDef {
        id: "M.draft", version: "1", max_support: DERIVED, phase: "M", loader: false,
        needs: &["L.src", "S.sections", "S.relocs", "S.codewalk", "S.crt.code", "S.thunk", "S.exports", "S.entry"], outputs: &["source"], inputs: &["objects"],
        doc: "R2. A sourced function of the current target whose compiled function is no byte match (M.match's\ncriterion fails) owns the bytes the code walk gives its start: a `source` fact (what: draft) over the walk's\nfunction extent (S.codewalk, derived), with why it is no match (differing bytes, the original continuing,\nthe relocation aid). Its level is the lower of the walk's and the address comment's (declared). A function\nwhose start the walk does not know owns nothing. Native: native/dcp_core/src/rules.rs m_draft.",
    },
    RuleDef {
        id: "M8.reloc", version: "2", max_support: REPRODUCED, phase: "M8", loader: false,
        needs: &["L.src", "S.sections", "S.relocs", "S.codewalk", "S.crt.code", "S.thunk", "S.exports", "S.entry", "kind:name"], outputs: &[], inputs: &["objects"],
        doc: "For every compiled function that is a byte match, or whose bytes differ while the DLL aid holds (every\nabsolute site of ours is a base-relocation site and the counts agree), each absolute or relative\nrelocation of ours whose site lines up with the original's code (rules.rs aligned_sites: the same\ninstruction at the same offset, equal outside our relocated fields; the aid alone says nothing about\nrelative sites, and a function without absolute sites passes it trivially) is resolved against the image\n(the address the original's site refers to, Reloc.resolve with our addend). A site that does not line up\nsays nothing: the difference is the function's draft diff (M.draft), not a contradiction.\nM8: the symbol we reference has a registered address (a name fact: export, import slot, library, source,\ndeclaration) and the original's site refers to another address: our object references X where the original\nholds the address registered to Y (severity from the two levels).\nM9: we reference a string literal and the original's bytes at the resolved address differ from our\nliteral's bytes (text or terminator).\nM10: we reference a floating constant and the original's bytes there differ from its bits. Native:\nnative/dcp_core/src/rules.rs m8_reloc.",
    },
    RuleDef {
        id: "M.flags.probe", version: "1", max_support: REPRODUCED, phase: "M", loader: false,
        needs: &[], outputs: &["toolchain"], inputs: &["probe", "toolchain"],
        doc: "From the last `dcp toolchain probe` (build/probe.py): one `toolchain` fact per flag group of the probe\ngrid, over the image, naming the best combination's flag, the user anchors that distinguish it (they match\nunder it and stop matching when only that group takes another value) and their units. Proven when the\ndistinguishing anchors come from at least two units; else declared (the target's declaration stays what\nsays it). A proven flag the target's declared cflags do not contain is an error (M.flags).",
    },
    RuleDef {
        id: "M.lint", version: "2", max_support: REPRODUCED, phase: "M", loader: false,
        needs: &["L.src"], outputs: &[], inputs: &["lint", "src"],
        doc: "The last `dcp lint` (source/lint.py: clang as a C89 type checker with MS compatibility against the\ntoolchain's headers; `@original why` / `@vc6 why` on a line exempt it): M6 an error inside one unit, M5 a\ndeclaration conflict across units (the all-declarations unit), both errors; M7 a call through a K&R\ndeclaration or without a declaration, a warning (the consistency convention: G.grade lists the calls on the
function's experiment). Reported at the address\nof the function whose span holds the diagnostic's line (the image base when none does). A lint run whose units'\ntexts differ from today's units is stale: a warning, M.lint.stale (`dcp lint`; `dcp check` lints first). Native:\nnative/dcp_core/src/rules.rs m_lint.",
    },
    RuleDef {
        id: "G.grade", version: "8", max_support: REPRODUCED, phase: "G", loader: false,
        needs: &["L.src", "M.match", "L.unit.extent", "L.src.extent", "S.sections", "S.relocs", "S.codewalk", "S.crt.code", "S.thunk", "S.exports", "S.entry"], outputs: &["experiment", "readability"], inputs: &["objects", "src", "lint"],
        doc: "The grades of every sourced function of the current target and of every unit (the rules B1..B3, Q1..Q8\nand the unit grades of rules/grade.py's module docstring), as `grade` facts: a function's at its address\n{of: function, name, unit, file, code, readability, level (deep / stuck from the address comment's tag, ''\nfor base), failing (the failing rules with evidence), dist (differing instructions, differing bytes, our\nsize, the original's code size without its switch tables, the extent and the slot the diff read: a report,\nnot a gate; `dcp asmdiff` / `dcp diffclass` read the same extent and slot), hunks}; a unit's over its extent {of: unit, code,\nreadability, functions, named_by}. A function's grade fact is proven when its code is byte (M.match), else\ndeclared (its address comment is the premise). A byte match that references a string literal or a floating\nconstant whose bytes the original does not hold where its site refers to (M9 / M10, rules.rs\nconstant_mismatches) is draft (a meaning difference), B1 failing with the M9 / M10 message and B3 naming the\nmismatch. Q7 is evaluated only for the units whose text the\nlast `dcp lint` parsed (the store meta `lint`). Native:\nnative/dcp_core/src/grade.rs (diffclass.rs, readability.rs, x86.rs).",
    },
    RuleDef {
        id: "M1.baseline", version: "1", max_support: REPRODUCED, phase: "M1", loader: false,
        needs: &["G.grade"], outputs: &[], inputs: &["baseline"],
        doc: "M1: every function of the current target in the grade baseline (ledger/grades.tsv, written only by `dcp\npromote`, lowered for one function only by `dcp accept`) keeps its grades: code byte -> shape / draft and\nshape -> draft are falls, readable -> draft is a fall, and a function the baseline grades that has no\ngrade now fell too. Each fall is an error. A function the baseline does not list cannot fall; an accepted\nfall holds the function at the accepted grade. Native:\nnative/dcp_core/src/layout.rs.",
    },
    RuleDef {
        id: "L.decl", version: "5", max_support: DECLARED, phase: "L", loader: true,
        needs: &[], outputs: &["boundary", "symbol", "name"], inputs: &["decl", "targets", "src"],
        doc: "Every line of decl/*.dcl that belongs to the current target becomes one declared fact, producer\ndecl:<file>:<line>, reason = the text after `--` (grammar: ledger/decl.py). boundary -> boundary fact\n{side, tu, named_by}; bytes dead -> symbol dead; jumptable / idxtable fn= -> symbol of that kind; foreign\nkind= -> symbol foreign; fptr -> symbol fptr; name N -> name (origin decl); start: L.decl.start; file tu= path=\n-> checked only: the image holds the path, NUL-terminated, at the address, one unit has one file name, and\nthe unit's file src/<tu>.c names it in a `#line` directive (its `__FILE__`); writes ptr=aK size=EXPR (the\nfunction writes EXPR bytes, a product of its arguments and numbers such as a1*a2, at its argument K: S.extent\nreads it) -> checked only: K is one argument and the address lies in code.\nErrors (check L.decl, severity error): a malformed line, an unknown kind or key, a missing reason, an\nunknown target prefix, an unsorted file, a duplicate key, an address outside the image or a range across\nsections, a text.dcl line outside a code section or a data.dcl line inside one. An error is reported in\nthe store of the target its line names (a line whose target is unknown: the default target's).",
    },
    RuleDef {
        id: "L.decl.start", version: "1", max_support: DECLARED, phase: "L", loader: true,
        needs: &[], outputs: &["start"], inputs: &["decl", "targets"],
        doc: "The `start` lines of decl/*.dcl for the current target, inside a code section, as declared start facts\n(how decl). Its own loader so that the setup walk, which takes them as roots, reruns only when a start\ndeclaration changes, not on every boundary edit (the run key follows this rule's output). Malformed lines\nare L.decl's errors.",
    },
    RuleDef {
        id: "L.src", version: "5", max_support: DECLARED, phase: "L", loader: true,
        needs: &[], outputs: &["source", "name", "start"], inputs: &["scan", "targets"],
        doc: "The address comments of the sources (grammar: ledger/srcscan.py), for the current target: every function\nwith an address gives a `source` fact {file, line, comment (the address comment's line), end (the\ndefinition's last line), unit, symbol, what: func, deep / stuck / rough tags}, a `name` fact (origin source)\nand a `start` fact (how source); every data definition with an address a `source` fact (what: data) and a\n`name`; every extern with an address a `name`. Producer src:<file>:<line>, reason = the comment's\ndescription. Errors: a parse error of the scan (L.src: a function without its address comment directly\nabove its definition, a function outside a unit file, a stray file), L16 (a function compiled into a target\nits comment does not list, or listed for one whose compile does not hold it), an unknown target prefix, an\naddress outside the image, a function address outside a code section, two definitions at one address\n(L.src), one name at two addresses (N2; a `static` name is compared within its unit only, two units may each\nkeep their own), L15 (a view's address is not its container's plus its offset, or its container has no data\ndeclaration with an address; a view gives a `name` fact {view: container}). Errors of the text itself (the\nscan's, an unknown target prefix) are reported in the default target's store; errors about an address in the\nstore of its target.\nA function or datum whose comment lists another target's address only is no fact of this target. Native:\nnative/dcp_core/src/layout.rs.",
    },
    RuleDef {
        id: "L.analyzer", version: "3", max_support: DECLARED, phase: "L", loader: true,
        needs: &[], outputs: &["start"], inputs: &["drafts"],
        doc: "Every draft of the analyzer (`dcp setup` runs its export; analyzers/) whose entry lies in a code section is\na declared function start (how = the analyzer's key, by decl:analyzer:<key>:<file>, reason \"<key>\nanalysis\"; value: the analyzer's name and, when it reports ranges, its body's size in bytes): an external\ntool's function discovery is a claim, so it is a declaration, never a computed fact. A function the\nanalyzer made at one of our own starts on our request (seeded: Ghidra's export creates one where it has\nnone) is no claim of the analyzer's and gives no start fact.",
    },
    RuleDef {
        id: "L.analyze", version: "1", max_support: REPRODUCED, phase: "L", loader: false,
        needs: &["S.sections", "S.relocs", "S.codewalk", "S.crt.code", "S.thunk", "S.strings", "S.fill"], outputs: &["evidence"], inputs: &[],
        doc: "Boundary evidence, computed once per image.\nlit (B-LIT): for every string symbol reached by a relocation site inside a function, its first user = the\nlowest start among those functions, the number of user functions, and the number of relocation sites in\ndata sections that reach it (then a table, not a function, may be its first user). For a dll the\nrelocations are the complete list of absolute operands, so the users are exact; the containing function\nrests on the walk (derived).\nfill (B-FILL): for every function start, what precedes it: a fill run as the toolchain names its form\n(Toolchain.fill_origin; VC6: `cc` a run of int3, padding the linker puts between section contributions;\n`nop` the compiler's alignment inside one object, proves nothing; `mixed`), `none` (the previous symbol\nends right there) or `unknown` (open bytes).\nleak (B-LEAK): a string whose text holds a path with a .c / .cpp / .h suffix (an __FILE__ of assert or a\nlog call), at every function that references it: the function was compiled from that file (.c / .cpp:\nnames the unit; .h: an inline from a header, names nothing).",
    },
    RuleDef {
        id: "L.unit.extent", version: "3", max_support: DECLARED, phase: "L", loader: false,
        needs: &["L.decl", "L.src", "S.sections", "S.crt.code", "S.thunk", "S.codewalk", "S.unknown"], outputs: &["unit"], inputs: &["decl", "targets"],
        doc: "The units of the game code (compute_units in rules/layout.py: a unit runs from its declared start\nboundary or first source to its declared end, the next unit's start or the end of the game code; the\nfirst library byte ends the game code). Each unit is a `unit` fact over its extent with its boundary\nlevels and producers, the count of function starts inside, how many have a source, its open bytes\n(unknown code: no rule claims them), its declared dead / foreign bytes (`bytes dead`, `foreign`: explained,\nnot open) and the C.walk conflicts inside it (a walk that runs into another function's bytes: one of the\ntwo starts is wrong). Status: separated when both boundaries are at least declared, no open byte and no\nC.walk conflict lies inside, else open. Level: the lower of the two boundary levels (at most declared).\nIssues of the computation are L7 conflicts. A unit declared `libunit` (a library member compiled from source)\nis no game unit: its functions are left out (L14 checks them against the member's range). Native:\nnative/dcp_core/src/layout.rs.",
    },
    RuleDef {
        id: "L1.src.start", version: "1", max_support: REPRODUCED, phase: "L1", loader: false,
        needs: &["L.src", "S.codewalk", "S.crt.code", "S.thunk", "S.fill", "S.sections"], outputs: &[], inputs: &[],
        doc: "L1: the address of a sourced function is the start of a function: the start of a walked or placed\nfunction, or a byte of unknown code (an undrafted start the walk did not find). Strictly inside a function\n(not one of its inner labels), inside fill, an import thunk or a table it is an error: the walk crosses\nthe source's start, one of the two is wrong. Native:\nnative/dcp_core/src/layout.rs.",
    },
    RuleDef {
        id: "L3.lit.order", version: "1", max_support: DERIVED, phase: "L3", loader: false,
        needs: &["L.analyze", "L.unit.extent"], outputs: &[], inputs: &[],
        doc: "L3, B-LIT contradiction (lit_issues in rules/layout.py): in each data section, the units of the literals'\nfirst users never go backwards in address order.",
    },
    RuleDef {
        id: "L4.boundary", version: "1", max_support: REPRODUCED, phase: "L4", loader: false,
        needs: &["L.decl", "kind:start", "S.codewalk", "S.crt.code", "S.thunk", "S.fill"], outputs: &[], inputs: &[],
        doc: "L4 (boundary_issues in rules/layout.py): a declared boundary lies at a function start (or an end\nboundary at the end of the game code), never inside fill or strictly inside a function. Native:\nnative/dcp_core/src/layout.rs.",
    },
    RuleDef {
        id: "L5.placeholder", version: "3", max_support: REPRODUCED, phase: "L5", loader: false,
        needs: &["kind:start", "S.sections", "S.codewalk", "S.crt.code"], outputs: &[], inputs: &["scan", "targets"],
        doc: "L5: an identifier that spells an address (`Unk<hex>`, `FUN_<hex>`, `DAT_<hex>`, `<name>_<6-8 hex with a\ndigit>`, in any .c / .h of src/ and include/) names a real address: on a line of the current target (inside\na function the target holds, or outside every function with an address) a number inside a section of the\ntarget's image must, inside a code section, be a function start (a `start` fact of any producer, or an inner\nlabel). A number inside no section of any target the file belongs to is a dropped or extra digit, reported\nin the default target's store only (at the line that spells it). A function's span ends with its definition\n(line_targets). Native:\nnative/dcp_core/src/layout.rs.",
    },
    RuleDef {
        id: "A1.addr.cast", version: "1", max_support: REPRODUCED, phase: "A1", loader: false,
        needs: &["kind:name", "kind:symbol"], outputs: &[], inputs: &["scan", "targets"],
        doc: "A1: an integer literal cast to a pointer type in the sources (srcscan's PtrCast: `(void (*)(void))0x5de470`,\n`(char *)0x6f242c`, `(T *)(unsigned)0x...`; the cast's type spells its `*`, a typedef'd pointer name is not\nrecognised; comments, strings and `#if 0` / `#else` text do not count, `#define` bodies do) whose value lies in\nthe current target's image [base, end), on a line of the current target (line_targets: inside a function\nthe target holds, or outside every function with an address). Such a pointer is the original's address\nfrozen into the code: the relinked image places that object elsewhere, so the pointer goes wrong. An error;\nthe message names what the facts know at the address (its name, else the symbol containing it, else nothing\nknown) and asks for the symbol by name. The address of a symbol (`(unsigned)&x`, `(char *)&x`) is no literal\nand is not reported. Native:\nnative/dcp_core/src/layout.rs.",
    },
    RuleDef {
        id: "L13.data.code", version: "1", max_support: REPRODUCED, phase: "L13", loader: false,
        needs: &["kind:name", "kind:start", "S.codewalk", "S.crt.code", "S.thunk", "M.match", "L.decl"], outputs: &[], inputs: &["scan", "targets"],
        doc: "L13: a data declaration of the sources (a definition or an `extern` with an address comment, srcscan Data)\nwhose address, for the current target, is a known function start (a `start` fact above declared: the walk,\nthe library placement, the entry, an export; or the start of a function symbol above declared) or lies inside\na known function's extent (a `func` symbol above declared: walked, placed or byte-matched), unless a table\nsymbol covers it (the walk's or a declared jumptable / idxtable, a declared fptr range: data a code section\nholds). The name declares data at code: whatever reads or calls it through that declaration, the relinked\nimage gives it a data object instead of the function. An error naming the function there. Native:\nnative/dcp_core/src/layout.rs.",
    },
    RuleDef {
        id: "L14.unit.outside", version: "2", max_support: DECLARED, phase: "L14", loader: false,
        needs: &["L.unit.extent", "L.src", "L.decl", "S.crt.code", "S.thunk"], outputs: &[], inputs: &["decl", "targets"],
        doc: "L14 (outside_unit_issues in rules/layout.py): a sourced function outside the game code (in the library\ncode after it) whose unit has a declared boundary (`boundary start|end tu=UNIT` in decl/text.dcl) and an\nextent: every function of such a unit lies inside the extent. Inside the game code L7 checks the same.\nAn error: no game unit owns library code, and a unit compiled with that function is not the\nunit's translation unit. Library code with a source belongs to a library unit (`libunit` in decl/text.dcl):\nits functions lie inside the declared member range, which lies outside the game code. Native:\nnative/dcp_core/src/layout.rs.",
    },
    RuleDef {
        id: "L6.declared", version: "1", max_support: REPRODUCED, phase: "L6", loader: false,
        needs: &["L.decl", "S.codewalk", "S.crt.code", "S.thunk", "S.relocs", "S.sections"], outputs: &[], inputs: &[],
        doc: "L6: every declaration is re-checked against the computed facts at every run, never trusted.\nbytes dead / foreign: no walked or placed function covers a byte of the range, and no call, jump, tail call\nor code immediate reaches into it (such bytes are reachable code, not dead).\njumptable / idxtable fn=F: F is a function start; the walk did not walk the range as code; a table the\nwalk found overlapping the range has the same extent and function.\nfptr: every address-wide field of the range (Image.ptr_size) is a relocation site whose target lies in a\ncode section.\nstart: not strictly inside a walked or placed function (unless it is an inner label).",
    },
    RuleDef {
        id: "L8.leak", version: "1", max_support: DERIVED, phase: "L8", loader: false,
        needs: &["L.analyze", "L.unit.extent"], outputs: &[], inputs: &[],
        doc: "L8 (leak_issues in rules/layout.py): one unit, one leaked source file.",
    },
    RuleDef {
        id: "L9.analyzer.span", version: "2", max_support: DECLARED, phase: "L9", loader: false,
        needs: &["L.decl", "L.src", "S.exports", "S.entry", "S.crt.code", "S.crt.refs", "S.codewalk", "S.thunk"], outputs: &[], inputs: &["drafts"],
        doc: "L9 (warning): an analyzer's function of the game code (its entry before the first library byte) whose\nbody (its address ranges, when the analyzer reports them: Ghidra's export does) holds one of our function\nstarts other than its own entry: a start fact of any producer but L.analyzer (export, entry, library, walk,\ndeclaration, source) or the start of a placed or walked function; inner labels of a walked function do\nnot count. The analyzer merged two functions (typically across a call that does not return): its\npseudocode holds both, and a draft from it must stop at our start. A warning, not an error: the body is an\nexternal tool's analysis (a declaration), our starts rest on the bytes and stated conventions. Library code\nis placed by its own members' bytes; the analyzer's view of it is no layout question and is not checked. Native:\nnative/dcp_core/src/layout.rs.",
    },
    RuleDef {
        id: "L.src.extent", version: "1", max_support: DECLARED, phase: "L", loader: false,
        needs: &["L.src", "L.decl", "L.decl.start", "S.sections", "S.codewalk", "S.crt.code", "S.thunk", "S.fill", "M.match", "S.exports", "S.entry"], outputs: &["symbol"], inputs: &[],
        doc: "A sourced function whose start no other function covers (the walk did not reach it: an image without base\nrelocations hides most call-only and pointer-only functions; it does not byte-match) owns its code by the\ncontiguity convention W1 of rules/walk.py: from its start up to the next stop (any known start, the start of\nany claimed symbol or region, a declared unit boundary, the end of the code section), less the alignment fill\nat the end (Toolchain fill forms, at most function_alignment - 1 bytes), as a `func` symbol {extent: source};\nthe trailing fill as a `fill` symbol. Declared: the start is the address comment's (a premise), the extent a\nconvention. Nothing is claimed when the range is only fill. After the end of any claimed code (a function,\nits jump or index table, a match's compared section), a gap of less than function_alignment bytes up to the\nnext stop is claimed too: first a match's padding inside our compiled section (compared equal: `fill`\n{extent: matched}), then alignment fill (`fill` {extent: source}). S.fill cannot see these gaps: it claims\nfill that ends at a claimed byte, and the next function may be one only this rule claims. Native:\nnative/dcp_core/src/layout.rs.",
    },
    RuleDef {
        id: "L.src.refs", version: "1", max_support: DECLARED, phase: "L", loader: false,
        needs: &["L.src.extent", "M.match", "S.codewalk", "S.relocs", "S.sections"], outputs: &["ref"], inputs: &[],
        doc: "The references of a sourced function the walk does not reach (S.codewalk has no function at its start: an\nimage without base relocations hides the functions only a pointer reaches). The function's code is\ndescended inside the extent the ledger gives it (L.src.extent's convention, M.match's comparison): a return\nor an unconditional jump ends a path (W4), a jump out of the extent is a tail call, a jump table's entries\ninside the extent are paths. Its calls, tail calls, code immediates at relocation sites and memory operands\ninto the image are `ref` facts like the walk's, declared (they rest on the address comment's start). Native:\nnative/dcp_core/src/walk.rs l_src_refs.",
    },
    RuleDef {
        id: "L10.unexplained", version: "2", max_support: DECLARED, phase: "L10", loader: false,
        needs: &["L.unit.extent", "L.src", "M.match", "S.codewalk", "L.decl", "L.src.extent"], outputs: &[], inputs: &[],
        doc: "L10 (warning): code inside a game unit's extent that no source, no declaration and no other function\nexplains, though a source claims it. Two cases:\n(a) a source whose start the walk does not know (a declared start in unknown code) and that does not\nbyte-match owns no bytes (M.draft takes the walk's extent, there is none; M.match proves an extent only for\na match) and L.src.extent did not give it the bytes up to the next stop either (a claimed byte right at its\nstart, or only fill): its code stays open (`open_bytes`) until it matches or a convention reaches its start;\n(b) a source that byte-matches (M.match: its compiled section, padding included, ends at m) while the walk\ngives its start a function extent [a, w) with w > m: the bytes [m, w), minus declared dead / foreign bytes,\nare code the walk reached that our function does not contain (a missed start, dead code to declare `bytes\ndead -- why`, or a table read as code). (R1's tail check makes (b) rare: a match already proves that only fill\nfollows its end up to the next start.)\nA non-matching draft with a walked start owns the walk's extent (M.draft), and a walked function without a\nfunction is L2 (informational, `dcp layout next`): neither is L10. Native:\nnative/dcp_core/src/layout.rs.",
    },
    RuleDef {
        id: "M.bytes.declared", version: "1", max_support: DECLARED, phase: "M", loader: false,
        needs: &["L.decl", "L.unit.extent"], outputs: &["source"], inputs: &[],
        doc: "R5: declared dead or foreign bytes (decl/*.dcl `bytes dead`, `foreign kind=`) inside a game unit's extent\nbelong to that unit: a `source` fact {what: dead | foreign, unit} over the range, declared (the declaration\nis the premise), so the byte map gives those bytes the unit and its source, and the unit counts them as\nexplained (L.unit.extent: dead_bytes), not open. A range that crosses a unit boundary is an error\n(M.bytes.declared); a range inside no unit is a warning (no unit owns it yet).",
    },
    RuleDef {
        id: "M.data.site", version: "2", max_support: REPRODUCED, phase: "M", loader: false,
        needs: &["L.src", "S.sections", "S.relocs", "S.codewalk", "S.crt.code", "S.thunk", "S.exports", "S.entry", "M.match"], outputs: &["symbol"], inputs: &["objects"],
        doc: "A data definition with an address comment whose address a byte-matched function's absolute relocation\nto the same symbol confirms (the original's site holds exactly that address, Reloc.resolve with our\naddend) is placed: a `global` symbol proven over [address, address + the object's size of the symbol)\n{name, unit, extent: site}. Native:\nnative/dcp_core/src/rules.rs.",
    },
    RuleDef {
        id: "M.data.content", version: "3", max_support: REPRODUCED, phase: "M", loader: false,
        needs: &["L.src", "S.sections", "S.relocs", "S.codewalk", "S.crt.code", "S.thunk", "S.exports", "S.entry", "M.match"], outputs: &["symbol"], inputs: &["objects"],
        doc: "A data definition with an address comment that M.data.site does not place, defined in an initialised\nsection of its object with at least 4 bytes that are no relocated field, no possible alignment padding\n(padding_masked) and not all zero, whose bytes (relocated fields and possible padding masked) equal the image's at the declared address and occur at no other address of the\nimage's initialised data sections: a `global` symbol proven {extent: content}. Found elsewhere only once\nand not at the declared address: an error (M.data.content): the declaration names another object's place. Native:\nnative/dcp_core/src/rules.rs.",
    },
    RuleDef {
        id: "M.data.draft", version: "2", max_support: DECLARED, phase: "M", loader: false,
        needs: &["L.src", "M.data.site", "M.data.content"], outputs: &["symbol"], inputs: &["objects"],
        doc: "Every data definition with an address comment that neither M.data.site nor M.data.content places owns\nits declared extent: a `global` symbol, declared, over [address, address + the object's size) (one byte\nwhen its unit has no object or the object lacks the symbol) {extent: draft}. Native:\nnative/dcp_core/src/rules.rs.",
    },
    RuleDef {
        id: "D.data", version: "6", max_support: REPRODUCED, phase: "D", loader: false,
        needs: &["L.src", "M.data.site", "M.data.content", "M.data.draft", "S.crt.data", "S.strings", "S.imports", "S.relocs", "S.sections", "kind:name", "S.extent"], outputs: &[], inputs: &["objects", "src", "decl"],
        doc: "D1: a data definition's extent holds the start of another symbol (a data symbol of the sources, a CRT data\nblock, a string, an import slot): an error when even its least size (least_size: the object's size without\nthe alignment padding it may include) reaches it, a warning when only the padding may. D4: in one unit, the\ndefinitions of one section kind (data / rdata / bss) are not in increasing address order in the order the\nunit's file defines them (VC6 places a unit's definitions of a section in definition order). D5: a\ntentative definition (the object holds it as common: the linker allocates it apart from its unit) whose\ndeclared address lies in the image's uninitialised data (no file bytes): write it `= 0`. D6: an absolute\nrelocation inside a definition of ours (a pointer-table entry) whose symbol has a registered address while\nthe original's entry at the same offset holds another one. D7: a view (`(*(T *)((char *)&C + OFF))` with an\naddress comment) whose offset lies at or past its container's object size (padding included): the view reads\nwhatever the linker puts after the container (a view of a view: of the definition the chain ends at). D8:\nthe ranges S.extent proves one object of the original (overlapping ones merged) against the definitions: an\nobject that several definitions overlap, that reaches past its one definition's object size or starts before\nit, is an error naming the definitions inside it (views of it or fields of its type); a warning when they are\npieces of one unit and section kind that tile it without a hole (they link where the original's bytes are:\ndeclare it as one). Native:\nnative/dcp_core/src/rules.rs.",
    },
    RuleDef {
        id: "S.headers", version: "1", max_support: OBSERVED, phase: "S", loader: false,
        needs: &[], outputs: &["region"], inputs: &[],
        doc: "The image format's headers own their bytes, one region each as the format names them\n(Image.header_regions; PE32: [image base, image base + SizeOfHeaders) is DOS header and stub, PE\nsignature, file and optional headers and section table as pe.header, the Rich header where the linker\nwrote one as pe.rich).",
    },
    RuleDef {
        id: "S.sections", version: "1", max_support: OBSERVED, phase: "S", loader: false,
        needs: &[], outputs: &["section", "region"], inputs: &[],
        doc: "One section fact per entry of the section table, over [VirtualAddress, VirtualAddress + max(VirtualSize,\nSizeOfRawData)). File bytes past VirtualSize up to SizeOfRawData are file-alignment padding (region pad).\nThe bytes between one section's end and the next section's start are not mapped (region unmapped).",
    },
    RuleDef {
        id: "S.datadirs", version: "1", max_support: OBSERVED, phase: "S", loader: false,
        needs: &[], outputs: &["region"], inputs: &[],
        doc: "The directories of the image format that are byte ranges of their own inside a section\n(Image.directory_regions; PE32: base relocations, resources, debug, TLS, load config, bound and delay\nimports, the COM descriptor, as pe.<directory>). Import and export tables are walked by S.imports /\nS.exports, which know their exact extents.",
    },
    RuleDef {
        id: "S.imports", version: "1", max_support: OBSERVED, phase: "S", loader: false,
        needs: &[], outputs: &["region", "symbol", "name"], inputs: &[],
        doc: "The import machinery as regions (Image.import_regions; PE32: descriptors pe.import_desc, lookup tables\npe.ilt, hint/name strings and DLL names pe.names, the terminating zero slot of each address table\npe.iat), and one `iat` symbol per address-table slot (an address wide), named DLL!symbol (or\nDLL!#ordinal).",
    },
    RuleDef {
        id: "S.exports", version: "1", max_support: OBSERVED, phase: "S", loader: false,
        needs: &[], outputs: &["region", "start", "name"], inputs: &[],
        doc: "The export machinery as regions (Image.export_regions; PE32: the export directory with its address, name\nand ordinal tables and name strings, pe.export_*, pe.names), and for every exported address a function\nstart plus its name (a forwarder names no start).",
    },
    RuleDef {
        id: "S.entry", version: "1", max_support: OBSERVED, phase: "S", loader: false,
        needs: &[], outputs: &["start"], inputs: &[],
        doc: "AddressOfEntryPoint is a function start.",
    },
    RuleDef {
        id: "S.relocs", version: "1", max_support: OBSERVED, phase: "S", loader: false,
        needs: &[], outputs: &["ref"], inputs: &[],
        doc: "One `reloc` reference per absolute relocation site of the image (Image.relocations; PE32: every HIGHLOW\nentry of the base relocation directory): the address-wide field at the site holds an absolute address of\nthe image (`to`). For a dll this is the complete list of absolute operands in code and data.",
    },
    RuleDef {
        id: "S.rich", version: "2", max_support: DERIVED, phase: "S", loader: false,
        needs: &[], outputs: &["toolchain"], inputs: &["archives"],
        doc: "The Rich header decoded with the toolchain's product table (Toolchain.rich_candidates): every entry with\nits tool, family, language, build and object count, and how many objects of the target's configured\narchives carry the same (prodid, build) in their tool stamp (ObjectFormat.tool_stamps decoded by\nToolchain.archive_tools; COFF / VC6: the @comp.id symbol) (those entries are library objects the archives\nexplain; before the archives are declared every count is 0). The candidates are listed, never picked: every\ncompiler entry is a compiler candidate, every linker entry a linker candidate; which one built the user's\nobjects is the target's declaration ([[target]] compiler / linker), checked by C.toolchain. The fact spans\nthe whole image; its level is derived (the product table is the community's reconstruction of Microsoft's\nids).",
    },
    RuleDef {
        id: "S.crt.code", version: "1", max_support: REPRODUCED, phase: "S", loader: false,
        needs: &["S.relocs"], outputs: &["symbol", "start", "name", "unit"], inputs: &["libs"],
        doc: "A code section of a library member is placed at the one position in a code section of the image where\nits bytes equal the image's with the relocation fields masked (Section.mask: every byte a relocation of\na known kind rewrites; COFF: DIR32 / DIR32NB / REL32, 4 bytes each), every absolute relocation site of\nthe section is a base-relocation site of the image when the image has a relocation directory, and no\nbase-relocation site falls on an unmasked byte. Sections shorter than 8 unmasked bytes are not searched.\nA section found at two or more positions is listed (warn S.crt.ambiguous) and places nothing. The placed\nsection owns its bytes as one `func` symbol named by its first external symbol; every further named\nsymbol of the section (external or file-static) is a start and a name; the unit is lib:<archive>/<member>.\nWaits for the declared archives (`dcp libs declare`).",
    },
    RuleDef {
        id: "S.lib.data", version: "2", max_support: REPRODUCED, phase: "S", loader: false,
        needs: &["S.crt.code", "S.crt.data"], outputs: &["symbol", "name", "unit"], inputs: &["libs"],
        doc: "A data-only member of an archive (no code section; S.crt.data places only the data that placed code\npoints to) is placed by content: an initialised data section without relocations, at least 8 bytes long\nwith at least 8 nonzero bytes, whose bytes occur exactly once in the image's initialised data sections, and\nnot over a section already placed (and no .idata$* section: the PE rules own the import tables), owns\n[that address, + size) as a `crt.data` symbol, its member a `unit`\nfact {tu, lib}, every named symbol a name (a GUID of an interface-id library, a CRT string table). Two\nmembers with the same bytes at one address are one placement (the first member; `candidates` counts them).",
    },
    RuleDef {
        id: "S.crt.refs", version: "1", max_support: REPRODUCED, phase: "S", loader: false,
        needs: &["S.crt.code"], outputs: &["name", "start"], inputs: &["libs"],
        doc: "Every absolute or relative relocation of a placed library section names the address it resolves to\n(Reloc.resolve: an absolute site holds the symbol's address plus the addend the object stores at the\nsite, a relative site the displacement to it; COFF: DIR32 / REL32). Symbols the member defines itself\nare not named again (S.crt.code placed them); symbols it references and another object defines (not\nthrough an import address-table slot) get a name fact at the resolved address: the user's entry\n(_DllMain@12, _main, _WinMain@16), CRT data of other members, and so on; a start too when the symbol is a\nfunction. Two sites that resolve one symbol to two addresses are a conflict.",
    },
    RuleDef {
        id: "S.crt.data", version: "1", max_support: REPRODUCED, phase: "S", loader: false,
        needs: &["S.crt.code"], outputs: &["symbol", "name", "unit"], inputs: &["libs"],
        doc: "A data section of a placed library member sits where that member's own absolute relocations into it\npoint (COFF: DIR32): the address a placed code site resolves to (Reloc.resolve) minus the referenced\nsymbol's offset in its section is the section's base. Every site must give the same base (else a\nconflict and nothing is placed); the placed section owns [base, base + size) as a `crt.data` symbol named\nby its first named symbol (external or file-static), and every named symbol is a name.",
    },
    RuleDef {
        id: "S.thunk", version: "2", max_support: DERIVED, phase: "S", loader: false,
        needs: &["S.imports", "S.crt.code"], outputs: &["symbol", "name"], inputs: &[],
        doc: "An import stub of the toolchain (Toolchain.import_stubs; VC6 / LINK: `FF 25 <slot>`, 6 bytes, `jmp dword\nptr [slot]`) whose slot is an import address-table slot, in a code section, outside every placed library\nsection, is a candidate. The same bytes are what the compiler emits for `return f(...)` when f is a\ndllimport function (VC6 does), as the last instruction of a function or as a whole function, so a\ncandidate is an import thunk (named after the slot) only where the linker's layout makes it a library\ncontribution (Toolchain.stub_placement; VC6 / LINK: library contributions follow the objects of the\ncommand line, the stubs of one import library are packed back to back): it lies at or after the start of\nthe first placed library section, or another candidate lies one stub size (Toolchain.import_stub_size)\nbefore or after it while the stub size is below the function alignment (Toolchain.function_alignment;\nVC6: 16 bytes, so two compiled functions never lie a 6-byte stub apart). Every other candidate is\ncompiled code, which the walk reaches.",
    },
    RuleDef {
        id: "S.entry.user", version: "1", max_support: DERIVED, phase: "S", loader: false,
        needs: &["S.crt.refs", "S.entry", "S.codewalk"], outputs: &["name"], inputs: &[],
        doc: "The user entry: when the CRT names a symbol the CRT start-up calls (through S.crt.refs), that name is the\nuser's entry function, reported as its C spelling for the layout (Toolchain.user_entry_names; VC6:\n_DllMain@12 -> DllMain, _main -> main, _WinMain@16 -> WinMain, _wmain -> wmain, _wWinMain@16 ->\nwWinMain).",
    },
    RuleDef {
        id: "S.strings", version: "3", max_support: DERIVED, phase: "S", loader: false,
        needs: &["S.relocs", "S.sections", "S.crt.data", "S.lib.data"], outputs: &["symbol"], inputs: &[],
        doc: "A relocation target in a data section whose bytes are at least 4 printable ASCII characters (0x20..0x7e,\ntab, CR, LF) followed by NUL is a string literal: the start is where the pointer points (proven), the extent\nruns to the first NUL (convention: C strings are NUL-terminated). A target inside an already claimed\nstring is an inner reference, not a new string; bytes a placed library data section owns are that\nsection's (its strings are named there).",
    },
    RuleDef {
        id: "S.fill", version: "1", max_support: DERIVED, phase: "S", loader: false,
        needs: &["S.sections", "S.crt.code", "S.thunk", "S.codewalk", "S.imports"], outputs: &["symbol"], inputs: &[],
        doc: "An unclaimed run of a code section that decodes entirely into the toolchain's alignment fill forms\n(VC6: 90, CC, 8B FF, 8D 49 00) and ends at a claimed byte or the section's end is fill. One other byte\nmakes the whole run not fill.",
    },
    RuleDef {
        id: "S.unknown", version: "1", max_support: OPEN, phase: "S", loader: false,
        needs: &["kind:symbol", "kind:region", "S.sections"], outputs: &["symbol"], inputs: &[],
        doc: "Every mapped byte of a section that no symbol and no region claims is unknown: unknown.code in a code\nsection, unknown.data elsewhere. This is the catch-all that makes the byte map total; it claims nothing\nabout the bytes.",
    },
    RuleDef {
        id: "S.codewalk", version: "6", max_support: DERIVED, phase: "S", loader: false,
        needs: &["S.sections", "S.exports", "S.entry", "S.crt.code", "S.crt.refs", "S.thunk", "S.relocs", "L.decl.start"], outputs: &["symbol", "start", "ref"], inputs: &[],
        doc: "Recursive descent over the code sections from every known start (exports, the entry point, the symbols\nof placed library sections, the entry the CRT calls), adding the starts the walk reveals (conventions\nW1..W5 in rules/walk.py: call targets, tail-call targets, code immediates at relocation sites, code\npointers stored in data sections) and repeating until the set of starts is stable. A walked\nfunction owns [start, last byte it reached + 1) as a `func` symbol of derived extent (bytes inside it\nthe walk did not reach are counted as holes); its jump tables and byte index tables are `jumptable` /\n`idxtable` symbols; calls (over the call instruction), tail calls, immediates and memory operands pointing\ninto the image are `ref` facts. A walk that runs into bytes another function owns is a conflict (C.walk).\nInstructions come from the target's instruction-set plugin (isa/), fill forms from the toolchain.",
    },
    RuleDef {
        id: "S.extent", version: "2", max_support: DERIVED, phase: "S", loader: false,
        needs: &["S.codewalk", "S.crt.code", "S.crt.refs", "S.sections"], outputs: &["evidence"], inputs: &["decl", "targets"],
        doc: "How far the original's code proves a data object reaches. Every walked function is read once, callees\nbefore callers, tracking what its registers and stack slots hold: a constant, a data address (exact, or\nwalking up from it through an added index or a loop), a stack argument plus an offset. Evidence that a\nrange is one object (C: a pointer stays inside its object): an access [r + disp] through a data address\n(field); `cmp r, END` before an ordering jump with r walking up from B (bound: B .. END is one array);\nrep movs / stos with a constant count (copy); an address passed to a function whose summary reaches\nthrough that argument (call). A summary is per stack argument the range around the pointer the\nfunction's accesses reach, a constant or a product of its arguments; seeds are the library's copiers by\nname (memcpy, memmove, memset, memcmp, strncpy, fread, fwrite, _read, _write) and the `writes ptr=aK\nsize=EXPR` declarations (decl/text.dcl: the function writes EXPR bytes, a product of arguments and numbers,\nat its argument K). Per base address the union of its evidence is one `evidence` fact {ekind: extent,\nbase, site, how, fn} over the proven range, derived. Native: native/dcp_core/src/extent.rs.",
    },
];
