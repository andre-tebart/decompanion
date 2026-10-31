"""The full link of a target (lifted from the first attempt's link/link.py full_link): every object of the
target through the toolchain's linker, the unresolved externals classified.

What goes in (Toolchain.link, LinkJob):
  objects      every compiled unit of the target, in the order of their least function address (LINK lays
               the objects out in command-line order), plus a generated entry object when the start-up code
               calls an entry the sources name otherwise (Toolchain.entry_object), plus the alias object
  /INCLUDE     every external function symbol the objects define (so /OPT:REF keeps it and its references are
               checked)
  a dll        /DLL /BASE:<image base> and a module definition file from the image's exports with their
               ordinals (Toolchain.module_definition); an export whose address has no source yet is left out
               of it and listed as undrafted (open layout work: LINK cannot build an export nothing defines)
  libraries    the target's archives (the static CRT), the import library of every DLL the image imports
               (Toolchain.import_library_name, found in the toolchain's library directories or the project's
               libs/), the toolchain's default libraries
  lib order    the libraries in the order the image shows (library_order: per section, the first contributions of
               placed archive members, import thunks and library units in address order; a topological sort
               keeps the given order where the image says nothing), since LINK places library contributions in
               the order it searches the libraries
  lib units    the object of a unit declared `libunit tu=UNIT lib=ARCHIVE` (a library member compiled from source)
               is no command-line object: it becomes a member of that archive (a copy under build/link/<target>/
               when the archive is the toolchain's, Toolchain.add_library_members), so LINK places it among the
               library contributions where the original has it
  aliases      one weak external per extra name of a data address: when the sources give one address several
               names (`extern` views of one object under another type), the name an object defines is the
               canonical one and every other resolves to it
Output under build/link/<target>/: the image, the map, the response file, link.log and the unresolved
externals in one file per class (unresolved-<class>.txt), classified as in the first attempt plus `library`:
  data      a data name of the sources (a definition or an `extern` with an address) nothing defines: define it
  renames   a stale name: it spells (placeholder) or is registered at the address of a function whose source
            defines another name
  aliases   a name declared at the address of a data object defined under another name
  undrafted a placeholder (or a name the ledger registers) whose address has no definition in the sources yet: a
            function start without a source, or a data address no definition names; open layout work, not a link
            error (the link is ok when nothing else is unresolved)
  library   a name no class above takes that the symbol table of an archive the target does not declare defines
            (an archive directly in the project's libs/ or the toolchain's library directories, [toolchain] lib_dirs
            first): the line names the archive(s) and the `dcp libs declare` that adds it; the archives' symbol
            tables are indexed by content hash in the store (archive_symbols), read only when such names remain
  other     everything else (a real name without an address, a CRT internal, ...)
The link is skipped when its inputs (the arguments, every object and library by content hash) are those of the
last successful-or-not link and its log is on disk: the result is read back.

The link and its classes are the core's (native/dcp_core/src/link.rs; vc6.rs runs LINK and LIB); this module is its
face.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .. import native


@dataclass
class LinkReport:
    target: str
    ok: bool = False
    skipped: str = ""
    objects: int = 0
    includes: int = 0
    unresolved: dict = field(default_factory=dict)     # class -> [lines]
    errors: list = field(default_factory=list)
    notes: list = field(default_factory=list)       # what the link did beyond the plain call (built import libraries)
    out: str = ""
    cached: bool = False
    ms: int = 0

    @property
    def n_unresolved(self):
        return sum(len(v) for v in self.unresolved.values())


def full_link(project, log=None) -> LinkReport:
    """The full link of the current target (module docstring)."""
    return LinkReport(**native.core().link_full(project.core))


def classify(project, unresolved: list[str]) -> dict[str, list[str]]:
    """The six classes of the module docstring, one line per symbol (`symbol  ->  hint`)."""
    return native.core().link_classify(project.core, list(unresolved))
