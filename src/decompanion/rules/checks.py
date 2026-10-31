"""Check rules (C.* and the numbered setup checks): they read facts and emit conflicts only. A conflict never
removes a fact; it makes `dcp check` fail (error, bug) or `dcp conflicts` list it (warn)."""
from __future__ import annotations

import re

from ..ledger.fact import Level
from .engine import RuleContext, rule


@rule("C.overlap", version="2", ceiling=Level.proven, needs=("kind:symbol", "kind:region"), native=True)
def overlap(ctx: RuleContext):
    """Two symbol or region facts that overlap contradict each other (every byte has one owner). Severity
    from the two levels: proven against proven is a bug in a rule. Overlaps with an open fact are not
    reported (open is replaced, not contradicted), nor two facts that say the same thing (one interval, one
    symbol kind: a declaration the walk confirms)."""
    return ()                                      # native: native/dcp_core/src/setup.rs


@rule("C.ref.target", version="1", ceiling=Level.proven, needs=("S.codewalk", "S.crt.code", "S.thunk"), native=True)
def ref_target(ctx: RuleContext):
    """A direct call whose target lies strictly inside a function (not at its start) contradicts that function's
    extent or the call's decoding."""
    return ()                                      # native: native/dcp_core/src/setup.rs


def declared_build(decl: str) -> int | None:
    """The build number a declaration names: its last run of digits ('cl 12.00.9044' -> 9044)."""
    m = re.search(r"(\d+)\D*$", decl or "")
    return int(m.group(1)) if m else None


def toolchain_inputs(p) -> dict:
    """C.toolchain's and S2's: the toolchain's key, the target's toolchain declaration and name."""
    return {"toolchain": p.toolchain.key, "decl": p.input("toolchain"), "target": p.target_name}


@rule("C.toolchain", version="2", ceiling=Level.proven, needs=("S.rich",), inputs=("toolchain",), helpers=(declared_build,), native=True,
      native_inputs=toolchain_inputs)
def toolchain(ctx: RuleContext):
    """The target's toolchain declaration ([[target]] compiler / linker with reason.compiler / reason.linker, or
    the [toolchain] defaults it inherits; written by `dcp toolchain declare`) against the Rich header's
    candidates (S.rich): a declared compiler, linker or cflags without a reason is an error; when the Rich
    header lists compiler entries, the declared compiler must name the build of one of them (the last number of
    the declaration); the same for the linker and the linker entries. Waits until both are declared (the
    obligations toolchain.compiler / toolchain.linker)."""
    return ()                                      # native: native/dcp_core/src/crt.rs


@rule("S2.rich.members", version="2", ceiling=Level.proven, needs=("S.rich", "S.crt.code"), inputs=("toolchain",),
      helpers=(declared_build,), native=True,
      native_inputs=toolchain_inputs)
def rich_members(ctx: RuleContext):
    """The Rich header counts library objects: the compiler entries whose build is not the declared compiler's.
    The placed library members should account for them. Fewer placed members than counted objects is a
    warning (members whose code was not found, or libraries not configured). Without a compiler declaration
    nothing is counted."""
    return ()                                      # native: native/dcp_core/src/crt.rs


@rule("S7.entry.section", version="1", ceiling=Level.proven, needs=("S.sections", "S.exports", "S.entry"), native=True)
def entry_section(ctx: RuleContext):
    """The entry point and every export must lie in a code section (Section.holds_code: marked as code or as
    executable)."""
    return ()                                      # native: native/dcp_core/src/setup.rs


@rule("S5.crt.gaps", version="1", ceiling=Level.proven, needs=("S.crt.code", "S.unknown", "S.fill"), native=True)
def crt_gaps(ctx: RuleContext):
    """Unknown code between the first and the last placed library section is library code no member explains
    (a member not in the configured archives, or a section too short or ambiguous to place)."""
    return ()                                      # native: native/dcp_core/src/setup.rs


def import_libs_inputs(p) -> dict:
    """What S4 reads of the configuration: the toolchain's key and root, the target's archives."""
    tc = p.toolchain
    return {"toolchain": tc.key, "root": str(tc.root) if tc.root is not None else None,
            "libs": [str(x) for x in p.input("libs")]}


@rule("S4.import.libs", version="1", ceiling=Level.proven, inputs=("libs",), native=True,
      native_inputs=import_libs_inputs)
def import_libs(ctx: RuleContext):
    """Every DLL the image imports needs an import library for the full link: the toolchain's library archives
    or the target's archives must hold the import library the toolchain names for it
    (Toolchain.import_library_name, compared case-insensitively; VC6: <DLL name>.LIB in VC98/Lib); a missing
    one is a warning until the link milestone."""
    return ()                                      # native: native/dcp_core/src/setup.rs
