"""The analyzer seam: a third-party tool that reads the image and hands back opinions about it (function
starts, names, a pseudocode body per function), behind one class per tool. Ghidra (analyzers/ghidra.py), a
saved REA batch_decompile file (analyzers/rea.py) and no analyzer at all (analyzers/none.py) are the plugins.

An analyzer's output is never a computed fact: its function starts are declared `start` facts (L.analyzer,
reason "<key> analysis"), its pseudocode is draft text for `dcp draft`, its function bodies are checked against
our starts (L9). The rules read the stored entries (input `drafts`, ledger/drafts.py), never the plugin.

What a plugin answers:
  key                    "ghidra" | "rea" | "none": the [analyzer] plugin value, the `how` of its start facts
  available()            Install: where the tool is (or the file it reads), or the reason it is not there;
                         a note setup prints as a warning (none: no drafts)
  script_hash()          the hash of what makes the export besides the image and our starts (the shipped
                         post-script, the file read): part of the export key, so a changed script exports again
  export(install, image, isa_key, starts, out_dir)   Export: one Entry per function the tool knows (start, end,
                         ranges, name, body, seeded), the items that failed, the analysed binary's sha256
  is_placeholder(name)   a name of the tool's own that says nothing (the ledger never adopts it)
  rewrite(body, own, names, labels)   the tool's pseudocode with its labels replaced by our names (the dialect
                         in; draft.py composes it with the toolchain's language out)
  data_labels(body)      {address: C type} of the data labels in a body, typed by the label's spelling
  unknown_data_type      the type of a datum the body names without a typed label
  types_header           the shipped header whose type names and macros the drafts use (None: none needed)
The plugin is constructed with its configuration table ([analyzer]) and the project's path expansion, like a
Toolchain with its [toolchain] table.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


class AnalyzerError(RuntimeError):
    pass


@dataclass(frozen=True)
class Entry:
    """One function as an analyzer sees it."""
    start: int                    # the function's entry
    name: str                     # the tool's name for it ('' when none)
    body: str                     # the pseudocode ('' when the tool gave none)
    end: int | None = None        # the end of its highest address range (exclusive), when the tool reports ranges
    size: int | None = None       # bytes in its ranges
    ranges: tuple = ()            # ((lo, hi), ...)
    seeded: bool = False          # made by the tool at one of our starts on our request: no claim of the tool's
    requested: int | None = None  # the address it was asked for (None: its start)
    source: str = ""              # the file the entry came from (its name)
    analyzer: str = ""            # the plugin key


@dataclass
class Install:
    """What `available()` found: `where` (printed) and the plugin's own details, or the reason it is missing;
    `note`: a warning `dcp setup` prints although the analyzer is there."""
    where: str = ""
    reason: str | None = None
    detail: dict = field(default_factory=dict)
    note: str = ""

    @property
    def ok(self) -> bool:
        return self.reason is None


@dataclass
class Export:
    entries: list = field(default_factory=list)
    failed: list = field(default_factory=list)      # one message per item the tool could not decompile
    digest: str = ""                                # the analysed binary's sha256 ('' when the output names none)
    ms: int = 0
    out: Path | None = None                         # the tool's output file
    log: Path | None = None
    skipped: list = field(default_factory=list)     # (file, digest) of output files about another binary


@dataclass(frozen=True)
class Names:
    """How a draft spells what a body names: `func(addr)` a function, `data(addr)` a datum."""
    func: Callable[[int], str]
    data: Callable[[int], str]


class Analyzer:
    key = "base"
    types_header: Path | None = None
    unknown_data_type = "int"

    def __init__(self, config: dict | None, expand: Callable[[str], Path] | None):
        self.config = dict(config or {})
        self.expand = expand or (lambda s: Path(s))

    def available(self) -> Install:
        return Install(reason="no analyzer")

    def script_hash(self) -> str:
        return ""

    def export(self, install: Install, image, isa_key: str, starts: list[int], out_dir: Path, fresh: bool = False) -> Export:
        return Export()

    def is_placeholder(self, name: str) -> bool:
        return False

    def rewrite(self, body: str, own: tuple[str, str], names: Names, labels: dict[str, int]) -> str:
        """The body with the tool's labels replaced: `own` = (the tool's name of the drafted function, ours),
        `labels` = {the tool's name: address} of every function it named."""
        return body

    def data_labels(self, body: str) -> dict[int, str]:
        return {}
