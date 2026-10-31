"""The fact model's checks. (The engine's order, run keys and output checks are tested in the core: engine.rs.)"""
import pytest

from decompanion.ledger.fact import Fact, Kind, Level


def test_declared_fact_needs_reason():
    with pytest.raises(ValueError):
        Fact(0x1000, 0x1001, Kind.name, {"name": "x"}, Level.declared, "decl:decl/text.dcl:3")
    f = Fact(0x1000, 0x1001, Kind.name, {"name": "x"}, Level.declared, "decl:decl/text.dcl:3", "a leaked path")
    assert f.level is Level.declared
