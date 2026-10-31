"""What `dcp layout next|units|unit propose` print, computed from the current facts of one target's store: the
core's (native/dcp_core/src/layoutview.rs); this module is its face.

Nothing here decides anything new: the units are L.unit.extent's facts, the evidence L.analyze's, the checks are
layout.rs's pure functions (run again on the units as a proposal would make them).
"""
from __future__ import annotations

from dataclasses import dataclass

from .. import native
from ..rules import layout as L  # noqa: F401  (L.container for the commands)


class View:
    @staticmethod
    def load(project, store):
        """The layout-relevant facts of one store, indexed (game, funcs, syms, starts, sources, units, fills,
        bounds; items(), unit_at(a))."""
        return native.core().View(store._p, store._main, str(project.image_path))


def fmt(a):
    return f"{a:#010x}"


def fmt_range(lo, hi):
    return f"{lo:#010x}..{hi:#010x}"


def next_records(v, count: int = 1, start: int | None = None):
    """The first `count` open items of the game code from `start`, one record (a dict) each, with its evidence."""
    return v.next_records(count, start)


def undrafted(v):
    """L2: function starts inside game units without a source (informational)."""
    return v.undrafted()


def unit_rows(v):
    return v.unit_rows()


@dataclass
class Proposal:
    lo: int
    hi: int | None
    name: str
    lines: list          # decl lines (addr, side) to write
    table: list          # evidence rows per function
    new_issues: list
    old_issues: list


def propose(v, lo: int, hi: int | None, name: str) -> Proposal:
    """A unit lo..hi named `name` evaluated against the current units: the issues it would add."""
    return Proposal(*v.propose(lo, hi, name))
