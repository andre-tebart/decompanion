"""The analyzer seam: a third-party tool that reads the image and hands back opinions about it (function starts,
names, a pseudocode body per function). The analyzers are the core's (native/dcp_core/src/analyzers.rs: Ghidra
headless with its post-script data/ghidra/DcpExport.java, the default; none); `[analyzer] plugin = "<key>"` selects
one. This module is their face: the keys and what `available()` found."""
from __future__ import annotations

from dataclasses import dataclass

from .. import native

DEFAULT = "ghidra"
ANALYZERS = tuple(native.core().analyzer_keys())


@dataclass(frozen=True)
class Install:
    """What `available()` found: `where` the tool is, or the `reason` it is not there; `note`: a warning `dcp setup`
    prints although the analyzer is there; `root` / `java_home` of a Ghidra installation."""
    key: str
    ok: bool
    where: str
    reason: str | None
    note: str
    root: str | None
    java_home: str | None


class Analyzer:
    """The configured analyzer of a project."""

    def __init__(self, project, key: str):
        self.project, self.key = project, key

    def available(self) -> Install:
        return Install(**native.core().analyzer_available(self.project.core))


def default_install() -> Install:
    """The default analyzer without configuration and what it finds (`dcp init`)."""
    return Install(**native.core().analyzer_default())
