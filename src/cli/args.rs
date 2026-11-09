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
    Setup(SetupArgs),
    /// the setup report (with the analyzer's drafts)
    Report(ReportArgs),
    /// everything known about an address (or a function / data name)
    Why(WhyArgs),
    /// the claims intersecting a range: each with its question, value, support and producer
    Claims(ClaimsArgs),
    /// the answers of a range: per run of bytes the owner at its highest support, its unit and section
    Answers(AnswersArgs),
    /// φ, the correspondence: an address's objects of H, a name's addresses; without either a summary
    Phi(PhiArgs),
    /// the exceptions: the sources' `@original why` (the original was inconsistent here) and `@vc6 why` (the checker
    /// differs from the toolchain here) markers and the declared `overrun`s (the original's access at an instruction
    /// overruns its object), each with its reason
    Exceptions,
    /// the findings: contradictions, ill-formed H or φ, gaps, stale results, debt
    Findings(FindingsArgs),
    /// the gate: build, no bug or error finding, the link resolves (every target unless --target)
    Check(CheckArgs),
    /// the project's daemon: every dcp command of the project runs in it (started on demand)
    Serve(ServeArgs),
    /// the rule graph and run status
    Rules(RulesArgs),
    /// the phase and the open obligations in order, with the next step (every target unless --target)
    Status(StatusArgs),
    /// the toolchain evidence; `probe`: the flag probe; `declare`: a declaration
    Toolchain(ToolchainArgs),
    /// the static library archives
    Libs(LibsArgs),
    /// the third-party analyzer
    Analyzer(AnalyzerArgs),
    /// the data tooling: map, fix
    Data(DataArgs),
    /// the include checks of a unit's head region
    Headers(HeadersArgs),
    /// the grades: matrix and units, or one unit / function with the failing rules
    Grade(GradeArgs),
    /// the next functions of the base (default), deep or names queue; each with its tier (easy or hard: which
    /// worker it is for, `[queue]` of the configuration)
    Next(NextArgs),
    /// the instruction diff of one function (ours '-', the original '+')
    Asmdiff(AsmdiffArgs),
    /// the hunk classes of one function's instruction diff
    Diffclass(DiffclassArgs),
    /// write `@deep why` into a function's address comment (--clear removes the tag); with --hard, `@hard why`
    Escalate(EscalateArgs),
    /// write `@stuck why` into a function's address comment (--clear removes the tag)
    Stuck(StuckArgs),
    /// raise the grade baseline ledger/grades.tsv to the current grades (main checkout only; a fall no dcp debt add
    /// covers is refused)
    Promote(PromoteArgs),
    /// the debt: regressions declared on purpose, each with its last witness; `add` declares one, `list` lists them
    Debt(DebtArgs),
    /// the full link of a target with the unresolved externals classified
    Link(LinkArgs),
    /// clang as the declaration checker (M5 / M6, and M7: the consistency convention)
    Lint(LintArgs),
    /// create a target project (declares nothing: dcp setup, then dcp status)
    Init(InitArgs),
    /// the binaries of the project
    Target(TargetArgs),
    /// declarations (decl/*.dcl)
    Decl(DeclArgs),
    /// the layout phase
    Layout(LayoutArgs),
    /// compile every stale unit, refresh the rules, print the build and grade summary
    Build(BuildArgs),
    /// units
    Unit(UnitArgs),
    /// print one function of the sources (its address comment to the end of its definition)
    Fn(FnArgs),
    /// the original's instructions with the ledger's names (--ours NAME: our compiled function)
    Disasm(DisasmArgs),
    /// the original's bytes: hex and latin-1, strings, dwords, floats, with the symbols of each row
    Dump(DumpArgs),
    /// definition, facts, references to and from, and source lines of a name or address
    Refs(RefsArgs),
    /// write a function into its unit's file (the analyzer's pseudocode, else a @rough skeleton)
    Draft(DraftArgs),
    /// rename identifiers over src/ and include/ (names.log); several pairs in one call share one rebuild
    Rename(RenameArgs),
    /// the session protocol
    Session(SessionArgs),
    /// the agent skills
    Skills(SkillsArgs),
    /// build a [[run]] profile, stage its directory, run its setup steps and start the program
    Run(RunArgs),
    /// worktrees with an overlay store
    Wt(WtArgs),
    /// copy this checkout's stores into another checkout (fallback for the overlay)
    Seed(SeedArgs),
    /// dcp itself: `self install` builds this checkout and replaces the installed dcp
    #[command(name = "self")]
    SelfCmd(SelfCmdArgs),
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
    Add(DebtAddArgs),
    /// every debt item of the baseline: function, the grade before and now, the witness, why, what it waits for
    List,
}

#[derive(Subcommand, Debug)]
pub enum ToolchainCmd {
    /// the flag grid over the byte-matched functions
    Probe(ToolchainProbeArgs),
    /// declare compiler= linker= root= cflags= (any subset) with --why
    Declare(ToolchainDeclareArgs),
}

#[derive(Subcommand, Debug)]
pub enum LibsCmd {
    /// place every run-time archive of the root on its own
    Candidates(LibsCandidatesArgs),
    /// declare the target's archives with --why
    Declare(LibsDeclareArgs),
}

#[derive(Subcommand, Debug)]
pub enum AnalyzerCmd {
    /// confirm or change the analyzer with --why
    Declare(AnalyzerDeclareArgs),
}

#[derive(Subcommand, Debug)]
pub enum DataCmd {
    /// a unit's data declarations in address order (no unit: the per-unit summary)
    Map(DataMapArgs),
    /// rewrite sources to answer D5 / D1 / D4 (dry run unless --write)
    Fix(DataFixArgs),
}

#[derive(Subcommand, Debug)]
pub enum HeadersCmd {
    /// what including headers into a unit's head region collides with (a trial parse; nothing is written without
    /// --write)
    Conflicts(HeadersConflictsArgs),
    /// which functions VC6's tie-breaks move by the declaration set alone: each unit compiled with unused typedefs
    /// before its text and graded; recorded in ledger/tiebreak.tsv (every unit when none is named)
    Probe(HeadersProbeArgs),
    /// whether the declaration set moves one function: its unit preprocessed and compiled N times with unused
    /// declarations at random file-scope places before it; sensitive or not, the best grade (its source-proven one),
    /// recorded in ledger/tiebreak.tsv
    Sample(HeadersSampleArgs),
}

#[derive(Subcommand, Debug)]
pub enum TargetCmd {
    /// list the targets
    List(TargetListArgs),
    /// add a target
    Add(TargetAddArgs),
}

#[derive(Subcommand, Debug)]
pub enum DeclCmd {
    /// insert a declaration line in address order
    Add(DeclAddArgs),
}

#[derive(Subcommand, Debug)]
pub enum LayoutCmd {
    /// the first open function of the game code with its evidence
    Next(LayoutNextArgs),
    /// the unit table
    Units(LayoutUnitsArgs),
    /// the literal-pool view of a unit or range: first users, blocks, interleaving (B-LIT)
    Literals(LayoutLiteralsArgs),
    /// every function pointer in data (tables of functions) with its unit
    Fptrs(LayoutFptrsArgs),
    /// every function start in a range with its evidence
    Starts(LayoutStartsArgs),
    /// unit commands
    Unit(LayoutUnitArgs),
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
    New(UnitNewArgs),
    /// join unit B (directly after A) into unit A
    Join(UnitJoinArgs),
    /// rename a unit (directory, header, includes, boundaries, placeholders)
    Rename(UnitRenameArgs),
}

#[derive(Subcommand, Debug)]
pub enum SessionCmd {
    /// the session gate (clean tree, built, checked, linked) and the overview
    Start(SessionStartArgs),
    /// build, link, check, promote, and the computed session report
    Wrap,
    /// the session clock: base, start time, minutes elapsed and left, over
    Status(SessionStatusArgs),
}

#[derive(Subcommand, Debug)]
pub enum SkillsCmd {
    /// install the decompanion skills into .claude/skills/
    Install(SkillsInstallArgs),
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
    New(WtNewArgs),
    /// list the worktrees
    List,
    /// remove a worktree (and its branch when merged)
    Drop(WtDropArgs),
}

#[derive(Subcommand, Debug)]
pub enum SelfSub {
    /// build this checkout (cargo build --release) and replace the installed dcp, also while it runs
    Install,
}

/// `Cmd::Setup`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct SetupArgs {
    #[arg(short, long)]
    pub verbose: bool,
    /// rerun every rule
    #[arg(long)]
    pub force: bool,
    /// every target in config order
    #[arg(long)]
    pub all_targets: bool,
    /// skip the analyzer's export
    #[arg(long)]
    pub no_analyzer: bool,
    /// export again although the export key is unchanged
    #[arg(long)]
    pub analyzer_force: bool,
}

/// `Cmd::Report`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct ReportArgs {
    /// every target in config order
    #[arg(long)]
    pub all_targets: bool,
    /// list every analyzer-only and ours-only start
    #[arg(short, long)]
    pub verbose: bool,
}

/// `Cmd::Why`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct WhyArgs {
    #[arg(value_name = "ADDR|NAME", required = true, num_args = 1..)]
    pub addr: Vec<String>,
    #[arg(long)]
    pub refs: bool,
}

/// `Cmd::Claims`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct ClaimsArgs {
    pub range: String,
    /// the claims answering one question: section, owner, start, unit, ref, toolchain
    #[arg(long, value_parser = parse_question)]
    pub question: Option<crate::store::Question>,
    /// one stored kind (also the kinds that are no claims: name (φ), grade, build, evidence)
    #[arg(long)]
    pub kind: Option<String>,
    /// the claims of this support or above: declared, derived, observed, reproduced
    #[arg(long, value_parser = parse_support)]
    pub support: Option<crate::store::Support>,
    #[arg(long)]
    pub json: bool,
}

/// `Cmd::Phi`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct PhiArgs {
    #[arg(value_name = "ADDR|NAME")]
    pub key: Option<String>,
    /// the addresses where φ is many-to-one, each with the reason the toolchain gives (or none)
    #[arg(long)]
    pub many: bool,
}

/// `Cmd::Findings`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct FindingsArgs {
    /// contradiction, ill-formed, gap, stale, debt
    #[arg(long, value_parser = parse_category)]
    pub category: Option<crate::registry::Category>,
    #[arg(long)]
    pub severity: Option<Severity>,
    #[arg(long)]
    pub json: bool,
}

/// `Cmd::Check`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct CheckArgs {
    /// warnings fail too
    #[arg(long)]
    pub strict: bool,
    /// no grade fell against ledger/grades.tsv at this git revision
    #[arg(long, value_name = "REV")]
    pub against: Option<String>,
}

/// `Cmd::Serve`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct ServeArgs {
    /// stop the running daemon
    #[arg(long)]
    pub stop: bool,
    /// print the running daemon's state
    #[arg(long)]
    pub status: bool,
    /// run the daemon in this process
    #[arg(long)]
    pub foreground: bool,
}

/// `Cmd::Rules`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct RulesArgs {
    /// print each rule's criterion
    #[arg(short, long)]
    pub verbose: bool,
}

/// `Cmd::Status`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct StatusArgs {
    /// the records of the output contract instead of the guided view
    #[arg(long)]
    pub json: bool,
}

/// `Cmd::Toolchain`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct ToolchainArgs {
    #[arg(short, long)]
    pub verbose: bool,
    #[command(subcommand)]
    pub sub: Option<ToolchainCmd>,
}

/// `Cmd::Libs`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct LibsArgs {
    #[command(subcommand)]
    pub sub: LibsCmd,
}

/// `Cmd::Analyzer`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct AnalyzerArgs {
    #[command(subcommand)]
    pub sub: AnalyzerCmd,
}

/// `Cmd::Data`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct DataArgs {
    #[command(subcommand)]
    pub sub: DataCmd,
}

/// `Cmd::Headers`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct HeadersArgs {
    #[command(subcommand)]
    pub sub: HeadersCmd,
}

/// `Cmd::Grade`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct GradeArgs {
    #[arg(value_name = "NAME|UNIT|ADDR")]
    pub what: Option<String>,
}

/// `Cmd::Next`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct NextArgs {
    #[arg(long)]
    pub base: bool,
    /// only the base items of this tier (a deep or names item is hard)
    #[arg(long, value_parser = ["easy", "hard"])]
    pub tier: Option<String>,
    #[arg(long)]
    pub deep: bool,
    #[arg(long)]
    pub names: bool,
    #[arg(short = 'n', default_value_t = 1)]
    pub n: usize,
    #[arg(long)]
    pub unit: Option<String>,
    /// k/N (or off); default: the file .dcp/shard
    #[arg(long)]
    pub shard: Option<String>,
}

/// `Cmd::Asmdiff`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct AsmdiffArgs {
    pub name: String,
    /// rename registers on our side: a=b,c=d, or `auto`: the renaming most of the function agrees on
    #[arg(long)]
    pub regs: Option<String>,
    /// print every equal instruction
    #[arg(long)]
    pub all: bool,
    /// print the names instead of X (ours: the relocations' symbols, the original's: the ledger's labels); '!' marks
    /// an equal instruction naming another symbol
    #[arg(long)]
    pub symbols: bool,
    /// diff the texts as they are (else, when the frames differ in size, the stack offsets are aligned as diffclass
    /// aligns them and a line shifted only by the frame counts as equal)
    #[arg(long)]
    pub plain: bool,
    /// only the differing lines, with --context lines around each
    #[arg(long)]
    pub changed: bool,
    /// only the lines around this address (the original's, or ours on a '-' line): --context lines each way
    #[arg(long, value_name = "ADDR")]
    pub at: Option<String>,
    /// the lines around a difference (--changed, default 3) or an address (--at, default 20)
    #[arg(long, value_name = "N")]
    pub context: Option<usize>,
    /// one side's listing alone, in its own order: ours or original (names with --symbols, renamed with --regs)
    #[arg(long, value_name = "SIDE", value_parser = ["ours", "original"])]
    pub side: Option<String>,
}

/// `Cmd::Diffclass`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct DiffclassArgs {
    pub name: String,
    /// print every line of every code hunk (else the first 8 of each side)
    #[arg(long)]
    pub all: bool,
}

/// `Cmd::Escalate`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct EscalateArgs {
    pub name: String,
    pub why: Option<String>,
    #[arg(long)]
    pub clear: bool,
    /// hand base work up to a stronger worker: the function stays in the base queue, in the hard tier (what was
    /// tried and what is left, in the reason); shape + readable clears the tag
    #[arg(long, conflicts_with_all = ["size_explained", "divergence_explained"])]
    pub hard: bool,
    /// escalate although the instruction count differs from the original's beyond what allocation explains
    /// (max(12, 1/100 of the original's)): why allocation causes it (kept in the reason)
    #[arg(long, value_name = "WHY")]
    pub size_explained: Option<String>,
    /// escalate although a call or a global store of one side is missing on the other, or a reference of ours
    /// differs from the original's field (dcp diffclass names both): why it is not a meaning difference (kept
    /// in the reason)
    #[arg(long, value_name = "WHY")]
    pub divergence_explained: Option<String>,
}

/// `Cmd::Stuck`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct StuckArgs {
    pub name: String,
    pub why: Option<String>,
    #[arg(long)]
    pub clear: bool,
}

/// `Cmd::Promote`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct PromoteArgs {
    /// write the falls too (each noted in the accepted column)
    #[arg(long)]
    pub accept_falls: bool,
}

/// `Cmd::Debt`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct DebtArgs {
    #[command(subcommand)]
    pub sub: DebtCmd,
}

/// `Cmd::Link`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct LinkArgs {
    #[arg(long)]
    pub all_targets: bool,
}

/// `Cmd::Lint`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct LintArgs {
    #[arg(long)]
    pub all_targets: bool,
}

/// `Cmd::Init`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct InitArgs {
    pub dir: String,
    #[arg(value_name = "TARGET")]
    pub target_path: String,
    /// the project's name (default: the directory's)
    #[arg(long)]
    pub name: Option<String>,
    /// the target's name (default: the binary's stem)
    #[arg(long)]
    pub target_name: Option<String>,
}

/// `Cmd::Target`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct TargetArgs {
    #[command(subcommand)]
    pub sub: TargetCmd,
}

/// `Cmd::Decl`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct DeclArgs {
    #[command(subcommand)]
    pub sub: DeclCmd,
}

/// `Cmd::Layout`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct LayoutArgs {
    #[command(subcommand)]
    pub sub: LayoutCmd,
}

/// `Cmd::Build`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct BuildArgs {
    /// every target in config order
    #[arg(long)]
    pub all_targets: bool,
    /// compile every unit
    #[arg(long)]
    pub force: bool,
    /// list every unit's build row, not only the failed ones
    #[arg(long)]
    pub units: bool,
    /// then compile and link this [[variant]] (build/link/<target>/<variant>/)
    #[arg(long, value_name = "NAME")]
    pub variant: Option<String>,
}

/// `Cmd::Unit`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct UnitArgs {
    #[command(subcommand)]
    pub sub: UnitCmd,
}

/// `Cmd::Fn`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct FnArgs {
    /// a function name or an address
    pub key: String,
}

/// `Cmd::Disasm`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct DisasmArgs {
    #[arg(value_name = "ADDR|NAME")]
    pub addr: Option<String>,
    #[arg(value_name = "LEN|..END", allow_hyphen_values = true)]
    pub len: Option<String>,
    /// disassemble our compiled function from its unit's object
    #[arg(long, value_name = "NAME")]
    pub ours: Option<String>,
    /// leave out the bytes column (`ADDR  instruction`)
    #[arg(long, alias = "compact")]
    pub no_bytes: bool,
    /// only the instructions from LO to HI; `+N` is an offset from the listing's start (`+0x200..+0x400`)
    #[arg(long, value_name = "LO..HI")]
    pub range: Option<String>,
}

/// `Cmd::Dump`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct DumpArgs {
    #[arg(value_name = "ADDR|NAME")]
    pub addr: String,
    /// bytes (default 0x40)
    #[arg(value_name = "LEN")]
    pub len: Option<String>,
    /// every NUL-terminated string starting in the range
    #[arg(long)]
    pub str: bool,
    /// every aligned dword: unsigned, signed, float, name
    #[arg(long)]
    pub dword: bool,
    /// every aligned float and double
    #[arg(long)]
    pub float: bool,
}

/// `Cmd::Refs`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct RefsArgs {
    #[arg(value_name = "NAME|ADDR")]
    pub what: String,
}

/// `Cmd::Draft`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct DraftArgs {
    #[arg(value_name = "ADDR|NAME")]
    pub addr: Option<String>,
    /// the function `dcp layout next` shows
    #[arg(long)]
    pub next: bool,
    /// print the analyzer's draft of ADDR, write nothing
    #[arg(long)]
    pub show: bool,
    /// the unit (default: the unit whose extent holds the address)
    #[arg(long)]
    pub unit: Option<String>,
}

/// `Cmd::Rename`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct RenameArgs {
    /// pairs of the identifier (or [TARGET:]0xADDR for the ledger's name of the address) and its new name
    #[arg(value_name = "OLD NEW")]
    pub pairs: Vec<String>,
    /// more pairs, one `OLD NEW [why]` per line
    #[arg(long = "from", value_name = "FILE")]
    pub from_file: Option<String>,
    /// the evidence (required unless every --from line carries its own)
    #[arg(long)]
    pub why: Option<String>,
}

/// `Cmd::Session`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct SessionArgs {
    #[command(subcommand)]
    pub sub: SessionCmd,
}

/// `Cmd::Skills`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct SkillsArgs {
    #[command(subcommand)]
    pub sub: SkillsCmd,
}

/// `Cmd::Wt`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct WtArgs {
    #[command(subcommand)]
    pub sub: WtCmd,
}

/// `Cmd::SelfCmd`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct SelfCmdArgs {
    #[command(subcommand)]
    pub sub: SelfSub,
}

/// `DebtCmd::Add`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct DebtAddArgs {
    #[arg(value_name = "ADDR|NAME")]
    pub name: String,
    /// the experiment's outcome the entry falls to
    #[arg(long, value_parser = ["shape", "draft"])]
    pub to: Option<String>,
    /// the readability falls to draft too
    #[arg(long, value_parser = ["draft"])]
    pub readability: Option<String>,
    /// the reason (kept in the accepted column)
    #[arg(long, required = true)]
    pub why: String,
    /// what has to settle before the grade comes back (a prototype, a header, a unit's layout)
    #[arg(long, value_name = "WHAT")]
    pub waits_for: Option<String>,
}

/// `ToolchainCmd::Probe`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct ToolchainProbeArgs {
    #[arg(short, long)]
    pub verbose: bool,
}

/// `ToolchainCmd::Declare`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct ToolchainDeclareArgs {
    /// keys: compiler, linker, root, cflags, plugin
    #[arg(value_name = "KEY=VALUE", required = true, num_args = 1..)]
    pub pairs: Vec<String>,
    /// the reason (required): the evidence the declaration rests on
    #[arg(long)]
    pub why: Option<String>,
}

/// `LibsCmd::Candidates`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct LibsCandidatesArgs {
    /// place again (ignore the cache)
    #[arg(long)]
    pub force: bool,
    #[arg(short, long)]
    pub verbose: bool,
}

/// `LibsCmd::Declare`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct LibsDeclareArgs {
    /// LIBCMT, LIBCMT.LIB or a path
    #[arg(value_name = "ARCHIVE", required = true, num_args = 1..)]
    pub archives: Vec<String>,
    /// the reason (required)
    #[arg(long)]
    pub why: Option<String>,
}

/// `AnalyzerCmd::Declare`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct AnalyzerDeclareArgs {
    /// ghidra | none
    #[arg(value_name = "PLUGIN")]
    pub plugin: String,
    /// root= java_home= timeout=
    #[arg(value_name = "KEY=VALUE")]
    pub pairs: Vec<String>,
    /// the reason (required)
    #[arg(long)]
    pub why: Option<String>,
}

/// `DataCmd::Map`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct DataMapArgs {
    pub unit: Option<String>,
    /// list the extern declarations too
    #[arg(long)]
    pub externs: bool,
}

/// `DataCmd::Fix`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct DataFixArgs {
    /// comma-separated subset of D5,D1,D4 (default: all, in that order)
    #[arg(long)]
    pub check: Option<String>,
    /// only this unit's fixes
    #[arg(long)]
    pub unit: Option<String>,
    /// apply, compile, keep only units where no byte or shape function falls (graded as G.grade grades)
    #[arg(long)]
    pub write: bool,
    /// edits listed per check (default 40)
    #[arg(long, default_value_t = 40)]
    pub limit: usize,
    /// list every edit
    #[arg(short, long)]
    pub verbose: bool,
}

/// `HeadersCmd::Conflicts`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct HeadersConflictsArgs {
    pub unit: String,
    #[arg(value_name = "HEADER", required = true, num_args = 1..)]
    pub headers: Vec<String>,
    /// insert the includes and drop the head's duplicates when no other conflict is left
    #[arg(long)]
    pub write: bool,
    /// compile the unit as --write would leave it (in build/obj/trial/, removed after) and grade each of its
    /// functions: the ones whose code grade would fall (exit 1) or rise; writes nothing
    #[arg(long)]
    pub trial: bool,
    /// insert the includes before the unit file's line LINE (default: after its last include, or before the
    /// first statement using a name the headers declare when that comes first)
    #[arg(long, value_name = "LINE")]
    pub at: Option<i64>,
}

/// `HeadersCmd::Probe`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct HeadersProbeArgs {
    #[arg(value_name = "UNIT")]
    pub units: Vec<String>,
    /// probe and report, write nothing
    #[arg(long)]
    pub dry_run: bool,
}

/// `HeadersCmd::Sample`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct HeadersSampleArgs {
    #[arg(value_name = "NAME")]
    pub name: String,
    /// how many samples (compiles of the unit)
    #[arg(long, default_value_t = 32)]
    pub n: usize,
    /// the seed of the samples (the same seed gives the same samples)
    #[arg(long, default_value_t = 1)]
    pub seed: u64,
    /// sample and report, write nothing
    #[arg(long)]
    pub dry_run: bool,
}

/// `TargetCmd::List`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct TargetListArgs {
    #[arg(long)]
    pub json: bool,
}

/// `DeclCmd::Add`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct DeclAddArgs {
    /// e.g. "0x10008cb0 boundary start tu=dllmain by=guess -- DllMain, Init, Exit"
    pub line: String,
}

/// `LayoutCmd::Next`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct LayoutNextArgs {
    /// show the first N
    #[arg(short = 'n', default_value_t = 1)]
    pub n: usize,
    /// from this address on
    #[arg(long)]
    pub start: Option<String>,
    #[arg(long)]
    pub json: bool,
}

/// `LayoutCmd::Units`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct LayoutUnitsArgs {
    #[arg(short, long)]
    pub verbose: bool,
    #[arg(long)]
    pub json: bool,
}

/// `LayoutCmd::Literals`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct LayoutLiteralsArgs {
    /// default: the game code
    #[arg(value_name = "UNIT|LO..HI")]
    pub what: Option<String>,
}

/// `LayoutCmd::Fptrs`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct LayoutFptrsArgs {
    /// a unit or code range: the functions pointed to; a data range: the sites; default: all
    #[arg(value_name = "UNIT|LO..HI")]
    pub what: Option<String>,
}

/// `LayoutCmd::Starts`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct LayoutStartsArgs {
    /// LO..HI or LO HI; default: the game code
    #[arg(value_name = "LO..HI")]
    pub range: Vec<String>,
}

/// `LayoutCmd::Unit`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct LayoutUnitArgs {
    #[command(subcommand)]
    pub sub: LayoutUnitCmd,
}

/// `UnitCmd::New`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct UnitNewArgs {
    pub name: String,
    /// 0xSTART..0xEND (END exclusive) or 0xSTART
    #[arg(long, required = true)]
    pub range: String,
    /// how the unit got its name
    #[arg(long, required = true, value_parser = ["leaked", "tag", "guess"])]
    pub by: String,
    #[arg(long, required = true)]
    pub why: String,
}

/// `UnitCmd::Join`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct UnitJoinArgs {
    pub a: String,
    pub b: String,
    #[arg(long, required = true)]
    pub why: String,
}

/// `UnitCmd::Rename`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct UnitRenameArgs {
    pub old: String,
    pub new: String,
    #[arg(long, required = true)]
    pub why: String,
    /// the new name's origin (the start boundary's by=)
    #[arg(long, value_parser = ["leaked", "tag", "guess"])]
    pub by: Option<String>,
}

/// `SessionCmd::Start`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct SessionStartArgs {
    /// the session's kind: the guidance after the gate (layout: the clock; match-base: counted in functions)
    #[arg(long, value_parser = ["layout", "match-base"])]
    pub kind: Option<String>,
}

/// `SessionCmd::Status`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct SessionStatusArgs {
    /// the session length (default 30)
    #[arg(long, default_value_t = 30)]
    pub minutes: i64,
}

/// `SkillsCmd::Install`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct SkillsInstallArgs {
    /// overwrite every skill file
    #[arg(long)]
    pub force: bool,
}

/// `WtCmd::Drop`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct WtDropArgs {
    pub name: String,
    #[arg(long)]
    pub force: bool,
}

/// `Cmd::Answers`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct AnswersArgs {
    pub range: Option<String>,
}

/// `Cmd::Seed`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct SeedArgs {
    pub path: String,
}

/// `TargetCmd::Add`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct TargetAddArgs {
    pub name: String,
    pub path: String,
}

/// `WtCmd::New`'s arguments (its own type: clap builds and reads them in a function of their own).
#[derive(Args, Debug)]
pub struct WtNewArgs {
    pub name: String,
}

#[cfg(test)]
mod tests {
    /// The command line builds, renders its help and parses on half the stack of Windows' main thread (1 MiB) in an
    /// unoptimized build. clap's derive builds an enum's variants in one function whose frame, at opt-level 0, holds
    /// every temporary of every variant: with the arguments inline, Cmd's took 914 KiB and `dcp --version`
    /// overflowed. Each variant's arguments are a type of their own, built in a function of their own.
    #[test]
    fn parses_on_half_a_main_thread_stack() {
        let t = std::thread::Builder::new().stack_size(512 << 10).spawn(|| {
            use clap::{CommandFactory, Parser};
            let _ = super::Cli::command().render_long_help();
            matches!(super::Cli::try_parse_from(["dcp", "asmdiff", "f", "--all"]).map(|c| c.cmd), Ok(super::Cmd::Asmdiff(_)))
        }).unwrap();
        assert!(t.join().unwrap());
    }
}
