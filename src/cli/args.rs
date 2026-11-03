//! The command line: every command, its arguments and options (clap). The help texts are the commands' one-line
//! descriptions; the semantics of each command are its handler's (cli/commands.rs and the core module it names).

use clap::{Args, Parser, Subcommand, ValueEnum};

/// dcp: the command line. Every command refreshes the rule engine first (nothing changed: nothing runs), then
/// answers from the store.
#[derive(Parser, Debug)]
#[command(name = "dcp", bin_name = "dcp", version = crate::client::BUILD, about = "dcp: the command line. Every command refreshes the rule engine first (nothing changed: nothing runs), then answers from the store.")]
pub struct Cli {
    /// the target project (default: the decompanion.toml above the cwd)
    #[arg(long, global = true)]
    pub root: Option<String>,
    /// the target to work on (default: the first [[target]] of decompanion.toml)
    #[arg(long, global = true)]
    pub target: Option<String>,
    /// run in this process, not in the project's daemon
    #[arg(long, global = true)]
    pub no_daemon: bool,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// run every rule and print the report
    Setup {
        #[arg(short, long)]
        verbose: bool,
        /// rerun every rule
        #[arg(long)]
        force: bool,
        /// every target in config order
        #[arg(long)]
        all_targets: bool,
        /// skip the analyzer's export
        #[arg(long)]
        no_analyzer: bool,
        /// export again although the export key is unchanged
        #[arg(long)]
        analyzer_force: bool,
    },
    /// the setup report (with the analyzer's drafts)
    Report {
        /// every target in config order
        #[arg(long)]
        all_targets: bool,
        /// list every analyzer-only and ours-only start
        #[arg(short, long)]
        verbose: bool,
    },
    /// everything known about an address (or a function / data name)
    Why {
        #[arg(value_name = "ADDR|NAME", required = true, num_args = 1..)]
        addr: Vec<String>,
        #[arg(long)]
        refs: bool,
    },
    /// the claims intersecting a range: each with its question, value, support and producer
    Claims {
        range: String,
        /// the claims answering one question: section, owner, start, unit, ref, toolchain
        #[arg(long, value_parser = parse_question)]
        question: Option<crate::store::Question>,
        /// one stored kind (also the kinds that are no claims: name (φ), grade, build, evidence)
        #[arg(long)]
        kind: Option<String>,
        /// the claims of this support or above: declared, derived, observed, reproduced
        #[arg(long, value_parser = parse_support)]
        support: Option<crate::store::Support>,
        #[arg(long)]
        json: bool,
    },
    /// the answers of a range: per run of bytes the owner at its highest support, its unit and section
    Answers { range: Option<String> },
    /// φ, the correspondence: an address's objects of H, a name's addresses; without either a summary
    Phi {
        #[arg(value_name = "ADDR|NAME")]
        key: Option<String>,
        /// the addresses where φ is many-to-one, each with the reason the toolchain gives (or none)
        #[arg(long)]
        many: bool,
    },
    /// the exceptions: the sources' `@original why` (the original was inconsistent here) and `@vc6 why` (the checker
    /// differs from the toolchain here) markers, each with its reason
    Exceptions,
    /// the findings: contradictions, ill-formed H or φ, gaps, stale results, debt
    Findings {
        /// contradiction, ill-formed, gap, stale, debt
        #[arg(long, value_parser = parse_category)]
        category: Option<crate::registry::Category>,
        #[arg(long)]
        severity: Option<Severity>,
        #[arg(long)]
        json: bool,
    },
    /// the gate: build, no bug or error finding, the link resolves (every target unless --target)
    Check {
        /// warnings fail too
        #[arg(long)]
        strict: bool,
        /// no grade fell against ledger/grades.tsv at this git revision
        #[arg(long, value_name = "REV")]
        against: Option<String>,
    },
    /// the project's daemon: every dcp command of the project runs in it (started on demand)
    Serve {
        /// stop the running daemon
        #[arg(long)]
        stop: bool,
        /// print the running daemon's state
        #[arg(long)]
        status: bool,
        /// run the daemon in this process
        #[arg(long)]
        foreground: bool,
    },
    /// the rule graph and run status
    Rules {
        /// print each rule's criterion
        #[arg(short, long)]
        verbose: bool,
    },
    /// the phase and the open obligations in order, with the next step (every target unless --target)
    Status {
        /// the records of the output contract instead of the guided view
        #[arg(long)]
        json: bool,
    },
    /// the toolchain evidence; `probe`: the flag probe; `declare`: a declaration
    Toolchain {
        #[arg(short, long)]
        verbose: bool,
        #[command(subcommand)]
        sub: Option<ToolchainCmd>,
    },
    /// the static library archives
    Libs {
        #[command(subcommand)]
        sub: LibsCmd,
    },
    /// the third-party analyzer
    Analyzer {
        #[command(subcommand)]
        sub: AnalyzerCmd,
    },
    /// the data tooling: map, fix
    Data {
        #[command(subcommand)]
        sub: DataCmd,
    },
    /// the include checks of a unit's head region
    Headers {
        #[command(subcommand)]
        sub: HeadersCmd,
    },
    /// the grades: matrix and units, or one unit / function with the failing rules
    Grade {
        #[arg(value_name = "NAME|UNIT|ADDR")]
        what: Option<String>,
    },
    /// the next functions of the base (default), deep or names queue
    Next {
        #[arg(long)]
        base: bool,
        #[arg(long)]
        deep: bool,
        #[arg(long)]
        names: bool,
        #[arg(short = 'n', default_value_t = 1)]
        n: usize,
        #[arg(long)]
        unit: Option<String>,
        /// k/N (or off); default: the file .dcp/shard
        #[arg(long)]
        shard: Option<String>,
    },
    /// the instruction diff of one function (ours '-', the original '+')
    Asmdiff {
        name: String,
        /// rename registers on our side: a=b,c=d, or `auto`: the renaming most of the function agrees on
        #[arg(long)]
        regs: Option<String>,
        /// print every equal instruction
        #[arg(long)]
        all: bool,
        /// print the names instead of X (ours: the relocations' symbols, the original's: the ledger's labels); '!' marks
        /// an equal instruction naming another symbol
        #[arg(long)]
        symbols: bool,
        /// diff the texts as they are (else, when the frames differ in size, the stack offsets are aligned as diffclass
        /// aligns them and a line shifted only by the frame counts as equal)
        #[arg(long)]
        plain: bool,
        /// only the differing lines, with --context lines around each
        #[arg(long)]
        changed: bool,
        /// only the lines around this address (the original's, or ours on a '-' line): --context lines each way
        #[arg(long, value_name = "ADDR")]
        at: Option<String>,
        /// the lines around a difference (--changed, default 3) or an address (--at, default 20)
        #[arg(long, value_name = "N")]
        context: Option<usize>,
        /// one side's listing alone, in its own order: ours or original (names with --symbols, renamed with --regs)
        #[arg(long, value_name = "SIDE", value_parser = ["ours", "original"])]
        side: Option<String>,
    },
    /// the hunk classes of one function's instruction diff
    Diffclass {
        name: String,
        /// print every line of every code hunk (else the first 8 of each side)
        #[arg(long)]
        all: bool,
    },
    /// write `@deep why` into a function's address comment (--clear removes the tag)
    Escalate {
        name: String,
        why: Option<String>,
        #[arg(long)]
        clear: bool,
        /// escalate although the instruction count differs from the original's beyond what allocation explains
        /// (max(12, 1/100 of the original's)): why allocation causes it (kept in the reason)
        #[arg(long, value_name = "WHY")]
        size_explained: Option<String>,
        /// escalate although a call or a global store of one side is missing on the other, or a reference of ours
        /// differs from the original's field (dcp diffclass names both): why it is not a meaning difference (kept
        /// in the reason)
        #[arg(long, value_name = "WHY")]
        divergence_explained: Option<String>,
    },
    /// write `@stuck why` into a function's address comment (--clear removes the tag)
    Stuck {
        name: String,
        why: Option<String>,
        #[arg(long)]
        clear: bool,
    },
    /// raise the grade baseline ledger/grades.tsv to the current grades (main checkout only; a fall no dcp debt add
    /// covers is refused)
    Promote {
        /// write the falls too (each noted in the accepted column)
        #[arg(long)]
        accept_falls: bool,
    },
    /// the debt: regressions declared on purpose, each with its last witness; `add` declares one, `list` lists them
    Debt {
        #[command(subcommand)]
        sub: DebtCmd,
    },
    /// the full link of a target with the unresolved externals classified
    Link {
        #[arg(long)]
        all_targets: bool,
    },
    /// clang as the declaration checker (M5 / M6, and M7: the consistency convention)
    Lint {
        #[arg(long)]
        all_targets: bool,
    },
    /// create a target project (declares nothing: dcp setup, then dcp status)
    Init {
        dir: String,
        #[arg(value_name = "TARGET")]
        target_path: String,
        /// the project's name (default: the directory's)
        #[arg(long)]
        name: Option<String>,
        /// the target's name (default: the binary's stem)
        #[arg(long)]
        target_name: Option<String>,
    },
    /// the binaries of the project
    Target {
        #[command(subcommand)]
        sub: TargetCmd,
    },
    /// declarations (decl/*.dcl)
    Decl {
        #[command(subcommand)]
        sub: DeclCmd,
    },
    /// the layout phase
    Layout {
        #[command(subcommand)]
        sub: LayoutCmd,
    },
    /// compile every stale unit, refresh the rules, print the build and grade summary
    Build {
        /// every target in config order
        #[arg(long)]
        all_targets: bool,
        /// compile every unit
        #[arg(long)]
        force: bool,
        /// list every unit's build row, not only the failed ones
        #[arg(long)]
        units: bool,
        /// then compile and link this [[variant]] (build/link/<target>/<variant>/)
        #[arg(long, value_name = "NAME")]
        variant: Option<String>,
    },
    /// units
    Unit {
        #[command(subcommand)]
        sub: UnitCmd,
    },
    /// print one function of the sources (its address comment to the end of its definition)
    Fn {
        /// a function name or an address
        key: String,
    },
    /// the original's instructions with the ledger's names (--ours NAME: our compiled function)
    Disasm {
        #[arg(value_name = "ADDR|NAME")]
        addr: Option<String>,
        #[arg(value_name = "LEN|..END", allow_hyphen_values = true)]
        len: Option<String>,
        /// disassemble our compiled function from its unit's object
        #[arg(long, value_name = "NAME")]
        ours: Option<String>,
        /// leave out the bytes column (`ADDR  instruction`)
        #[arg(long, alias = "compact")]
        no_bytes: bool,
        /// only the instructions from LO to HI; `+N` is an offset from the listing's start (`+0x200..+0x400`)
        #[arg(long, value_name = "LO..HI")]
        range: Option<String>,
    },
    /// the original's bytes: hex and latin-1, strings, dwords, floats, with the symbols of each row
    Dump {
        #[arg(value_name = "ADDR|NAME")]
        addr: String,
        /// bytes (default 0x40)
        #[arg(value_name = "LEN")]
        len: Option<String>,
        /// every NUL-terminated string starting in the range
        #[arg(long)]
        str: bool,
        /// every aligned dword: unsigned, signed, float, name
        #[arg(long)]
        dword: bool,
        /// every aligned float and double
        #[arg(long)]
        float: bool,
    },
    /// definition, facts, references to and from, and source lines of a name or address
    Refs {
        #[arg(value_name = "NAME|ADDR")]
        what: String,
    },
    /// write a function into its unit's file (the analyzer's pseudocode, else a @rough skeleton)
    Draft {
        #[arg(value_name = "ADDR|NAME")]
        addr: Option<String>,
        /// the function `dcp layout next` shows
        #[arg(long)]
        next: bool,
        /// print the analyzer's draft of ADDR, write nothing
        #[arg(long)]
        show: bool,
        /// the unit (default: the unit whose extent holds the address)
        #[arg(long)]
        unit: Option<String>,
    },
    /// rename identifiers over src/ and include/ (names.log); several pairs in one call share one rebuild
    Rename {
        /// pairs of the identifier (or [TARGET:]0xADDR for the ledger's name of the address) and its new name
        #[arg(value_name = "OLD NEW")]
        pairs: Vec<String>,
        /// more pairs, one `OLD NEW [why]` per line
        #[arg(long = "from", value_name = "FILE")]
        from_file: Option<String>,
        /// the evidence (required unless every --from line carries its own)
        #[arg(long)]
        why: Option<String>,
    },
    /// the session protocol
    Session {
        #[command(subcommand)]
        sub: SessionCmd,
    },
    /// the agent skills
    Skills {
        #[command(subcommand)]
        sub: SkillsCmd,
    },
    /// build a [[run]] profile, stage its directory, run its setup steps and start the program
    Run(RunArgs),
    /// worktrees with an overlay store
    Wt {
        #[command(subcommand)]
        sub: WtCmd,
    },
    /// copy this checkout's stores into another checkout (fallback for the overlay)
    Seed { path: String },
    /// dcp itself: `self install` builds this checkout and replaces the installed dcp
    #[command(name = "self")]
    SelfCmd {
        #[command(subcommand)]
        sub: SelfSub,
    },
}

fn parse_question(s: &str) -> Result<crate::store::Question, String> {
    crate::store::Question::parse(s).ok_or_else(|| {
        format!("no question {s:?} (one of {})", crate::store::Question::ALL.map(|q| q.name()).join(", "))
    })
}

fn parse_support(s: &str) -> Result<crate::store::Support, String> {
    crate::store::Support::parse(s).ok_or_else(|| format!("no support {s:?} (one of {})", crate::store::Support::ALL.map(|q| q.name()).join(", ")))
}

fn parse_category(s: &str) -> Result<crate::registry::Category, String> {
    crate::registry::Category::parse(s)
        .ok_or_else(|| format!("no category {s:?} (one of {})", crate::registry::Category::ALL.map(|q| q.name()).join(", ")))
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum Severity {
    Bug,
    Error,
    Warn,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Bug => "bug",
            Severity::Error => "error",
            Severity::Warn => "warn",
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum DebtCmd {
    /// declare a regression: lower one function's baseline entry to the grade it fell to, with the reason, what it
    /// waits for and the last witness commit (main checkout only)
    Add {
        #[arg(value_name = "ADDR|NAME")]
        name: String,
        /// the experiment's outcome the entry falls to
        #[arg(long, value_parser = ["shape", "draft"])]
        to: Option<String>,
        /// the readability falls to draft too
        #[arg(long, value_parser = ["draft"])]
        readability: Option<String>,
        /// the reason (kept in the accepted column)
        #[arg(long, required = true)]
        why: String,
        /// what has to settle before the grade comes back (a prototype, a header, a unit's layout)
        #[arg(long, value_name = "WHAT")]
        waits_for: Option<String>,
    },
    /// every debt item of the baseline: function, the grade before and now, the witness, why, what it waits for
    List,
}

#[derive(Subcommand, Debug)]
pub enum ToolchainCmd {
    /// the flag grid over the byte-matched functions
    Probe {
        #[arg(short, long)]
        verbose: bool,
    },
    /// declare compiler= linker= root= cflags= (any subset) with --why
    Declare {
        /// keys: compiler, linker, root, cflags, plugin
        #[arg(value_name = "KEY=VALUE", required = true, num_args = 1..)]
        pairs: Vec<String>,
        /// the reason (required): the evidence the declaration rests on
        #[arg(long)]
        why: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum LibsCmd {
    /// place every run-time archive of the root on its own
    Candidates {
        /// place again (ignore the cache)
        #[arg(long)]
        force: bool,
        #[arg(short, long)]
        verbose: bool,
    },
    /// declare the target's archives with --why
    Declare {
        /// LIBCMT, LIBCMT.LIB or a path
        #[arg(value_name = "ARCHIVE", required = true, num_args = 1..)]
        archives: Vec<String>,
        /// the reason (required)
        #[arg(long)]
        why: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum AnalyzerCmd {
    /// confirm or change the analyzer with --why
    Declare {
        /// ghidra | none
        #[arg(value_name = "PLUGIN")]
        plugin: String,
        /// root= java_home= timeout=
        #[arg(value_name = "KEY=VALUE")]
        pairs: Vec<String>,
        /// the reason (required)
        #[arg(long)]
        why: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum DataCmd {
    /// a unit's data declarations in address order (no unit: the per-unit summary)
    Map {
        unit: Option<String>,
        /// list the extern declarations too
        #[arg(long)]
        externs: bool,
    },
    /// rewrite sources to answer D5 / D1 / D4 (dry run unless --write)
    Fix {
        /// comma-separated subset of D5,D1,D4 (default: all, in that order)
        #[arg(long)]
        check: Option<String>,
        /// only this unit's fixes
        #[arg(long)]
        unit: Option<String>,
        /// apply, compile, keep only units where no byte or shape function falls (graded as G.grade grades)
        #[arg(long)]
        write: bool,
        /// edits listed per check (default 40)
        #[arg(long, default_value_t = 40)]
        limit: usize,
        /// list every edit
        #[arg(short, long)]
        verbose: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum HeadersCmd {
    /// what including headers into a unit's head region collides with (a trial parse; nothing is written without
    /// --write)
    Conflicts {
        unit: String,
        #[arg(value_name = "HEADER", required = true, num_args = 1..)]
        headers: Vec<String>,
        /// insert the includes and drop the head's duplicates when no other conflict is left
        #[arg(long)]
        write: bool,
        /// compile the unit as --write would leave it (in build/obj/trial/, removed after) and grade each of its
        /// functions: the ones whose code grade would fall (exit 1) or rise; writes nothing
        #[arg(long)]
        trial: bool,
        /// insert the includes before the unit file's line LINE (default: after its last include, or before the
        /// first statement using a name the headers declare when that comes first)
        #[arg(long, value_name = "LINE")]
        at: Option<i64>,
    },
}

#[derive(Subcommand, Debug)]
pub enum TargetCmd {
    /// list the targets
    List {
        #[arg(long)]
        json: bool,
    },
    /// add a target
    Add { name: String, path: String },
}

#[derive(Subcommand, Debug)]
pub enum DeclCmd {
    /// insert a declaration line in address order
    Add {
        /// e.g. "0x10008cb0 boundary start tu=dllmain by=guess -- DllMain, Init, Exit"
        line: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum LayoutCmd {
    /// the first open function of the game code with its evidence
    Next {
        /// show the first N
        #[arg(short = 'n', default_value_t = 1)]
        n: usize,
        /// from this address on
        #[arg(long)]
        start: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// the unit table
    Units {
        #[arg(short, long)]
        verbose: bool,
        #[arg(long)]
        json: bool,
    },
    /// the literal-pool view of a unit or range: first users, blocks, interleaving (B-LIT)
    Literals {
        /// default: the game code
        #[arg(value_name = "UNIT|LO..HI")]
        what: Option<String>,
    },
    /// every function pointer in data (tables of functions) with its unit
    Fptrs {
        /// a unit or code range: the functions pointed to; a data range: the sites; default: all
        #[arg(value_name = "UNIT|LO..HI")]
        what: Option<String>,
    },
    /// every function start in a range with its evidence
    Starts {
        /// LO..HI or LO HI; default: the game code
        #[arg(value_name = "LO..HI")]
        range: Vec<String>,
    },
    /// unit commands
    Unit {
        #[command(subcommand)]
        sub: LayoutUnitCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum LayoutUnitCmd {
    /// check a unit proposal (L3/L4/L7/L8) and write its boundary lines
    Propose(ProposeArgs),
}

#[derive(Args, Debug, Clone)]
pub struct ProposeArgs {
    /// 0xSTART..0xEND (END exclusive) or 0xSTART
    pub range: String,
    #[arg(long, required = true)]
    pub name: String,
    #[arg(long, required = true)]
    pub why: String,
    #[arg(long, value_parser = ["leaked", "tag", "guess"])]
    pub by: Option<String>,
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Subcommand, Debug)]
pub enum UnitCmd {
    /// declare a unit (layout unit propose) and write its skeleton files
    New {
        name: String,
        /// 0xSTART..0xEND (END exclusive) or 0xSTART
        #[arg(long, required = true)]
        range: String,
        /// how the unit got its name
        #[arg(long, required = true, value_parser = ["leaked", "tag", "guess"])]
        by: String,
        #[arg(long, required = true)]
        why: String,
    },
    /// join unit B (directly after A) into unit A
    Join {
        a: String,
        b: String,
        #[arg(long, required = true)]
        why: String,
    },
    /// rename a unit (directory, header, includes, boundaries, placeholders)
    Rename {
        old: String,
        new: String,
        #[arg(long, required = true)]
        why: String,
        /// the new name's origin (the start boundary's by=)
        #[arg(long, value_parser = ["leaked", "tag", "guess"])]
        by: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum SessionCmd {
    /// the session gate (clean tree, built, checked, linked) and the overview
    Start {
        /// the session's kind: the guidance after the gate (layout: the clock; match-base: counted in functions)
        #[arg(long, value_parser = ["layout", "match-base"])]
        kind: Option<String>,
    },
    /// build, link, check, promote, and the computed session report
    Wrap,
    /// the session clock: base, start time, minutes elapsed and left, over
    Status {
        /// the session length (default 30)
        #[arg(long, default_value_t = 30)]
        minutes: i64,
    },
}

#[derive(Subcommand, Debug)]
pub enum SkillsCmd {
    /// install the decompanion skills into .claude/skills/
    Install {
        /// overwrite every skill file
        #[arg(long)]
        force: bool,
    },
}

#[derive(Args, Debug)]
pub struct RunArgs {
    /// the [[run]] profile (none: list the profiles)
    pub name: Option<String>,
    /// extra program arguments, after --
    pub extra: Vec<String>,
    /// list the profiles
    #[arg(long)]
    pub list: bool,
    /// stage and start the last linked program
    #[arg(long)]
    pub no_build: bool,
    /// terminate the program after this many seconds (default: the profile's)
    #[arg(long)]
    pub seconds: Option<f64>,
    /// build and stage, write the launch spec, start nothing
    #[arg(long)]
    pub prepare_only: bool,
    /// run under the debugger: a crash writes build/crash/<run>-<stamp>/ (crash.txt, crash.dmp)
    #[arg(long, overrides_with = "no_debug")]
    pub debug: bool,
    /// a plain run, whatever the profile says
    #[arg(long, overrides_with = "debug")]
    pub no_debug: bool,
    /// the minidump of a crash (default: the profile's dump, else full)
    #[arg(long, value_parser = ["full", "state", "normal", "none"])]
    pub dump: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum WtCmd {
    /// create ../<project>-wt/NAME on branch wt/NAME
    New { name: String },
    /// list the worktrees
    List,
    /// remove a worktree (and its branch when merged)
    Drop {
        name: String,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum SelfSub {
    /// build this checkout (cargo build --release) and replace the installed dcp, also while it runs
    Install,
}
