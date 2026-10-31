"""The C compiler of today as the declaration checker of the sources (lifted from the first attempt's
decomp/decl/lint.py). clang parses every translation unit the way VC6 sees it (src/<unit>.c with the target's
DCP_TARGET_<name> defined, MS compatibility, C89 so that `T f();` is a K&R declaration, the toolchain's own headers as
system headers) and reports what VC6 does not. Nothing here changes a byte: clang only reads.

  M6  errors inside one unit: two declarations of one function that disagree, a call with the wrong number of
      arguments, a type VC6 silently accepted
  M5  across units: a generated all-declarations unit (build/lint/<target>/alldecls.c, `alldecls`) includes the
      system headers the sources include, every header of include/ (a header after the headers that define
      the names it uses, and after its includer), repeats every source's file-scope prototypes and extern data
      declarations behind `#line` (with the macros of its unit that they use: `GAPDATA`), then every
      non-static definition of the sources (a function's head as a prototype, a K&R definition with an empty
      body, a data definition as an extern declaration). One M5 line per symbol:
        - with a definition: every other spelling of the symbol is renamed (`__dcp_<n>`, pseudo file
          @dcp-copy) and compared with the renamed definition by `__builtin_types_compatible_p` on their
          addresses (@dcp-check): each declaration's file:line agrees or disagrees with the definition (or is
          unknown: it uses a type of its unit), whatever order clang would see them in
        - without one (or with a definition that uses a type of its unit): clang's own pairs, each
          redeclaration against the first declaration seen
        - a struct, union, enum or typedef two headers define differently (`redefinition`)
        - a header that does not compile there (its declarations are not compared: their conflicts hidden)
      Errors that are no conflict are clang's business elsewhere (a unit-local type, a macro the unit does not
      have), and a pair whose two sides read the same, or one side of which has an error of its own, is
      clang's error recovery, not a disagreement. An `@original` / `@vc6` exemption applies to a declaration
      in src/ only: a header is included into many units and repeats the definition's spelling; a unit's own
      view goes into that unit (a cast macro in its head region). A header marked `@private UNIT[,..]` in its first
      20 lines (the original only included it into those units) is left out of the unit, and a file outside
      those units that includes it is an M5 error
  M7  a call through a K&R declaration (-Wdeprecated-non-prototype: every float argument widened, the count
      unchecked) or without any declaration (-Wimplicit-function-declaration); the readability rule Q7 reads
      the calls inside each function's span
Exemptions, one per line, in the line clang points at or the line of a note it attaches: `@original why` (the
original binary has this mismatch) and `@vc6 why` (VC6 accepts what clang does not). Nothing else silences a
diagnostic.

Cache: per unit in the store's blob table, keyed by the unit's text, the clang arguments and the unit's
include hash (the compile's: every file of its include set by content), so a unit is parsed again exactly when
it would be compiled again; the all-declarations unit by its text and the contents of include/. The result of a
run is the store meta `lint` (the input `lint` of M.lint and G.grade).

clang: the LLVM installation's libclang in process (the core's frontend.rs: `[lint] libclang = "<path>"` in
decompanion.toml, else beside `clang` on PATH, else the LLVM default install path); the units a lint parses at
once parse on threads; a unit alone stays live (the scan's parse of an edit serves its lint).
"""
from __future__ import annotations

from pathlib import Path

from .. import native

NOT_FOUND = ("libclang not found ([lint] libclang = ... in decompanion.toml, or an LLVM installation: clang on PATH "
             "or C:/Program Files/LLVM)")


def available(project) -> bool:
    """Whether the project's libclang is there (the core's frontend::library)."""
    return native.core().lint_available(project.core)


def private_headers(root: Path) -> dict[str, set[str]]:
    """header name -> the units it is private to (`@private UNIT[,UNIT..]` in its first 20 lines)."""
    return native.core().lint_private_headers(str(root))


def stale(project) -> list[str] | None:
    """The units whose source or include set changed since the last lint (by the compile's hashes), None when
    there was no lint run: the lint result (Q7, M5..M7) is current exactly when this is empty."""
    return native.core().lint_stale(project.core)


def lint(project, log=None) -> dict:
    """Lint every unit of the current target and the all-declarations unit; store and return the result
    {units: {unit: text hash}, errors: [M6 lines], cross: [M5 lines], calls: {file: [[line, callee (kind)]]}}
    with `parsed` and `cached` (the core's: native/dcp_core/src/lintrun.rs)."""
    res = native.core().lint_run(project.core)
    project.forget_input("lint")
    return res
