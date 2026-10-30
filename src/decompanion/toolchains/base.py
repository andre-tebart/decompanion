"""The toolchain seam: everything the rules know about the compiler and linker that produced the image,
behind one class per toolchain family. VC6 is the only implementation (toolchains/vc6).

What a plugin answers (the rules ask, they never know the answers themselves):
  object_format          the objfmt plugin of its objects and archives ("coff")
  fill_forms             the byte forms of alignment fill between functions; fill_origin(bytes) names a run
  function_alignment     the boundary every compiled function starts at
  import_stubs(data)     the import stubs (linker-made `jump through an import slot` thunks) in a code section's
                         bytes, import_stub_size their size, stub_placement the linker's layout convention
  user_entry_names()     the decorated symbols of the user's entry functions -> their C names
  archive_tools(stamps)  the objects' tool stamps (objfmt tool_stamps) decoded to Rich (prodid, build)
  rich_product / rich_candidates / declare / build_name   the Rich header vocabulary
  import_library_name(dll)   the import library a DLL is linked through
  add_library_members(lib, objects)        add compiled objects to an archive (a library unit's object joins the
                         archive whose member it reproduces)
  make_import_library(dll, imports, out)   an import library built from the image's own import directory, for a
                         DLL whose library no installation holds (a commercial SDK that is not archived)
The guided decisions (obligations.py; the plugin hands over evidence, it never declares anything):
  installs()             the installations found on this machine (Install: root, versions, builds)
  install(root)          what one root holds (versions of its tools, the compiler / linker builds they make)
  crt_strings(image)     the run-time library's own strings found in the image (evidence of the CRT)
  library_candidates()   the static run-time archives of the installation (`dcp libs candidates` places each)
  archive_spec(name)     how `dcp libs declare NAME` spells an archive in decompanion.toml
  wizard_cflags()        the flags the toolchain's project wizard writes (evidence for toolchain.cflags)
The match phase (milestone 3) adds the tools themselves:
  compile(src, obj, flags, include_dirs, cwd)   one compiler process for one translation unit -> CompileResult
                         (ok, the full log, the diagnostics with file and line, the flags it refused)
  includes(src, flags, include_dirs, cwd)       the files the preprocessor read for the unit (its include set)
  include_search_dirs(include_dirs)             every directory an include may come from (the unit's own, the
                         project's, the toolchain's): their listing is part of the include-set cache key
  undecorate(symbol)     a linker symbol -> its C name (`_f@12` -> f)
  link(LinkJob)          one linker process -> LinkResult (ok, log, unresolved externals, other errors)
  default_libraries(kind)    the static libraries every link of an image kind (dll / exe) names
  entry_object(kind, dir)    a generated object the start-up code needs (None when the libraries hold it)
  module_definition(name, exports)   the export definition file text of a dll
  probe_grid()           the flag grid of `dcp toolchain probe`: (group, alternatives) pairs
Drafting (milestone 4): declaring_header(name), import_header(dll), the language beyond standard C (keywords,
default_convention, sized_conventions) that `dcp draft` spells declarations with.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class RichProduct:
    prodid: int
    name: str           # the tool, in the usual Rich-header vocabulary (Utc12_2_C, Linker600, Masm613, ...)
    family: str         # compiler | linker | assembler | implib | import | cvtres | alias | unknown
    language: str = ""  # C | C++ | "" for non-compilers


@dataclass(frozen=True)
class Diagnostic:
    """One compiler or linker message: the file and line it names ('' / 0 for the command line), its severity
    (error / warning; a fatal error is an error), the tool's code (C2065, D4002, LNK2001) and the text."""
    file: str
    line: int
    severity: str
    code: str
    message: str

    def text(self) -> str:
        where = f"{self.file}({self.line})" if self.file else "command line"
        return f"{where}: {self.severity} {self.code}: {self.message}"


@dataclass
class CompileResult:
    ok: bool
    log: str
    diagnostics: list = field(default_factory=list)
    refused_flags: list = field(default_factory=list)     # flags the compiler ignored or rejected

    @property
    def errors(self):
        return [d for d in self.diagnostics if d.severity == "error"]

    @property
    def warnings(self):
        return [d for d in self.diagnostics if d.severity == "warning"]


@dataclass(frozen=True)
class Install:
    """One installation of a toolchain: its root, the versions of its tools ({tool: version}), the compiler and
    linker builds it makes (what a Rich entry and a declaration name; None when unknown), and whether the
    plugin can run it."""
    root: Path
    versions: dict
    compiler_build: int | None
    linker_build: int | None
    ok: bool


@dataclass
class LinkJob:
    """What one link reads and writes. Paths relative to `cwd` (the project root), objects in link order."""
    cwd: Path
    out: Path
    objects: list
    libraries: list
    dll: bool
    base: int
    map_file: Path
    def_file: Path | None = None
    includes: list = field(default_factory=list)       # linker symbols kept under /OPT:REF
    entry: str | None = None                            # the entry symbol (None: the toolchain's default)
    subsystem: str = ""                                  # gui / console ('' : the toolchain's default)
    rsp: Path | None = None                              # the response file to write the arguments into


@dataclass
class LinkResult:
    ok: bool
    log: str
    unresolved: list = field(default_factory=list)     # linker symbols no object or library defines
    errors: list = field(default_factory=list)         # the other error lines
    args: list = field(default_factory=list)


class Toolchain:
    key = "base"
    object_format = ""              # the objfmt plugin key of the toolchain's objects and archives
    function_alignment = 1          # every compiled function starts at a multiple of this
    import_stub_size = 0            # bytes of one import stub (0: the toolchain makes none)
    stub_placement = ""             # the linker's placement convention for import stubs, as prose (S.thunk cites it)

    def __init__(self, root: Path | None, config: dict):
        self.root = Path(root) if root else None
        self.config = config

    # -------------------------------------------------------------- facts about the output
    @property
    def fill_forms(self) -> tuple[bytes, ...]:
        """The byte forms the linker / compiler leave as alignment fill between functions."""
        raise NotImplementedError

    def fill_origin(self, run: bytes) -> str:
        """What a fill run before a function start says about the boundary (L.analyze B-FILL): a short word
        naming the form, e.g. linker padding between contributions vs compiler alignment inside one object."""
        raise NotImplementedError

    def import_stubs(self, data: bytes):
        """(offset, slot) of every import stub in `data` (the raw bytes of a code section): the bytes of a stub
        whose jump goes through the import address-table slot `slot` (a VA). Candidates only: the same bytes
        may be compiled code; S.thunk decides by stub_placement."""
        return iter(())

    def rich_product(self, prodid: int) -> RichProduct:
        raise NotImplementedError

    def build_name(self, family: str, build: int) -> str:
        """A human name for a tool build, e.g. 9044 -> 'VC6 SP5 / Processor Pack'. '' when unknown."""
        return ""

    def declare(self, entry: dict) -> str:
        """The declaration spelling of a Rich compiler or linker entry ('cl 12.00.9044', 'link 6.00.8447')."""
        return f"{entry['tool']} {entry['build']}"

    def archive_tools(self, stamps: dict[int, int]) -> dict[tuple[int, int], int]:
        """(Rich prodid, build) -> objects, from the archives' tool stamps (ObjectFormat.tool_stamps: raw stamp
        value -> objects)."""
        return {}

    def rich_candidates(self, entries, comp_ids=None) -> dict:
        """The decoded Rich header: every entry with its tool, family, language, build, object count and the
        number of configured archive objects whose tool stamp (archive_tools) names the same (prodid, build);
        the compiler candidates (every compiler entry) and the linker candidates (every linker entry). Nothing
        is picked: which candidate built the user's objects is a declaration ([[target]] compiler / linker)."""
        comp_ids = comp_ids or {}
        decoded = []
        for prodid, build, count in entries:
            p = self.rich_product(prodid)
            decoded.append({"prodid": prodid, "tool": p.name, "family": p.family, "language": p.language,
                            "build": build, "count": count, "archive_objects": comp_ids.get((prodid, build), 0)})
        order = sorted(decoded, key=lambda e: (-e["count"], -e["build"], e["prodid"]))
        return {"entries": decoded,
                "compilers": [e for e in order if e["family"] == "compiler"],
                "linkers": [e for e in order if e["family"] == "linker"]}

    def crt_entry_symbols(self) -> dict[str, str]:
        """CRT entry symbols -> what they start: {'_DllMainCRTStartup@12': 'dll', '_WinMainCRTStartup': 'gui', ...}."""
        return {}

    def crt_user_entry(self, entry_symbol: str) -> str:
        """The decorated user entry the CRT entry calls or ''."""
        return ""

    def user_entry_names(self) -> dict[str, str]:
        """The decorated symbols of the user's entry functions (what the CRT start-up calls) -> their C names."""
        return {}

    # -------------------------------------------------------------- the toolchain on disk
    def library_archives(self) -> list[Path]:
        """Every library archive of the toolchain installation."""
        return []

    # -------------------------------------------------------------- evidence for the guided decisions
    def installs(self) -> list["Install"]:
        """Every installation of the toolchain found on this machine (the plugin knows its usual places)."""
        return []

    def install(self, root: Path) -> "Install":
        """What one installation root holds: the versions its tools report and the builds they make."""
        return Install(Path(root), {}, None, None, False)

    def crt_strings(self, image) -> list[tuple[int, str]]:
        """(address, text) of the run-time library's own strings found in the image's sections."""
        return []

    def library_candidates(self) -> list[Path]:
        """The static run-time archives of the installation at `root` that `dcp libs candidates` places, one
        by one (no import libraries: they hold no code to place)."""
        return []

    def archive_spec(self, name: str) -> str:
        """The decompanion.toml spelling of an archive a human names (`dcp libs declare NAME`): a path stays a
        path, a bare name is the toolchain's archive of that name under `{toolchain.root}`."""
        return name

    def wizard_cflags(self) -> list[str]:
        """The flags the toolchain's project wizard writes for a release build: evidence for the obligation
        toolchain.cflags, never written by the tool."""
        return []

    def import_library_name(self, dll: str) -> str:
        """The file name (lower case) of the import library a DLL is linked through."""
        raise NotImplementedError

    # -------------------------------------------------------------- drafting (milestone 4)
    def declaring_header(self, name: str) -> str | None:
        """The system header (as `#include <...>` names it) that declares the C library function `name`, None when
        no header of the toolchain does (`dcp draft` includes it instead of writing a declaration)."""
        return None

    def import_header(self, dll: str) -> str | None:
        """The system header that declares the functions an imported DLL exports, None when unknown."""
        return None

    # the language the compiler reads beyond standard C (`dcp draft` spells declarations with them)
    keywords: frozenset = frozenset()       # the compiler's own keywords (calling conventions, extended types)
    default_convention = ""                 # the calling convention a skeleton prototype spells ('' : none)
    sized_conventions: tuple = ()           # conventions whose decorated name carries the parameters' size: a
                                            # declaration of such a function needs its full prototype

    # -------------------------------------------------------------- the tools (milestone 3)
    def available(self) -> bool:
        """The compiler and linker are installed (else nothing compiles: the match rules say so as warnings)."""
        return False

    def compile(self, src: Path, obj: Path, flags: list[str], include_dirs: list[Path], cwd: Path) -> CompileResult:
        """Compile one translation unit `src` into `obj` (one process; paths relative to cwd or absolute)."""
        raise NotImplementedError

    def define_flag(self, macro: str) -> str:
        """The compiler flag that defines a macro (a target's DCP_TARGET_<name>)."""
        raise NotImplementedError

    def includes(self, src: Path, flags: list[str], include_dirs: list[Path], cwd: Path) -> tuple[list[Path], str]:
        """(every file the preprocessor read for `src` other than src itself, the log): the unit's include set,
        absolute paths. An empty list and the log when the preprocessor fails."""
        raise NotImplementedError

    def syntax_check(self, src: Path, flags: list[str], include_dirs: list[Path], cwd: Path) -> CompileResult | None:
        """The compiler's front end over `src` without an object (what it rejects that clang accepts), or None
        when the toolchain has no such mode."""
        return None

    def include_search_dirs(self, include_dirs: list[Path]) -> list[Path]:
        """The directories an include of a unit compiled with these include dirs may resolve to: the given ones
        and the toolchain's own header directories."""
        return list(include_dirs)

    def undecorate(self, symbol: str) -> str:
        """The C name of a linker symbol."""
        return symbol

    def data_symbol(self, cname: str) -> str:
        """The linker symbol of a C data object named cname."""
        return cname

    def link(self, job: LinkJob) -> LinkResult:
        raise NotImplementedError

    def make_import_library(self, dll: str, imports: list, out: Path) -> str | None:
        """Write an import library for `dll` to `out` that imports exactly `imports` (image Import records:
        the names and hints of the image's import directory); None when written, else why not."""
        return f"the {self.key} toolchain cannot build import libraries"

    def add_library_members(self, lib: Path, objects: list) -> str | None:
        """Add the objects to the archive `lib` (rewritten in place); None when done, else why not."""
        return f"the {self.key} toolchain cannot add archive members"

    def library_search_dirs(self) -> list[Path]:
        """The directories the linker finds a library named by its file name in."""
        return []

    def default_libraries(self, kind: str) -> list[str]:
        """The static libraries every link of an image of this kind (`dll` / `exe`) names, as file names the
        linker finds on its library path."""
        return []

    def entry_object(self, kind: str, out_dir: Path, user_entry: str | None = None) -> Path | None:
        """A generated object the start-up code needs for an image of this kind (None: the libraries hold
        everything)."""
        return None

    def module_definition(self, name: str, exports) -> str:
        """The text of the module definition (export) file of a dll named `name` with these exports
        (image Export records: ordinal, name)."""
        raise NotImplementedError

    def probe_grid(self) -> list[tuple[str, tuple[str, ...]]]:
        """(group, alternatives) of the compiler flags `dcp toolchain probe` varies."""
        return []

    def probe_defaults(self) -> list[str]:
        """The grid values the compiler uses when the command line names none of a group (a tie-break)."""
        return []
