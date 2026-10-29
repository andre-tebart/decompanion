"""The rule engine on toy rules: memoisation by input hash, dependency order, level enforcement."""
import hashlib
from pathlib import Path

import pytest

from decompanion.ledger.fact import Fact, Kind, Level
from decompanion.ledger.store import Store
from decompanion.rules import engine as eng
from decompanion.rules.engine import Engine, RuleError, rule


class FakeImage:
    base, end = 0x1000, 0x2000
    sha256 = "0" * 64

    def in_image(self, a):
        return self.base <= a < self.end


class FakeProject:
    def __init__(self, tmp):
        self.image = FakeImage()
        self.store = Store(tmp / "s.sqlite")
        self.counter = {"n": 0}
        self.cfg_hash = "cfg1"
        self.x = 1
        self.toolchain = None

    def input_hash(self, name):
        return {"image": "img", "config": self.cfg_hash}[name]

    def input(self, name):
        return {"config": {"x": self.x}}[name]


@pytest.fixture
def toy(tmp_path, monkeypatch):
    saved = dict(eng.RULES)
    eng.RULES.clear()
    calls = []

    @rule("T.a", version="1", ceiling=Level.proven, outputs=("section",))
    def a(ctx):
        calls.append("a")
        yield ctx.fact(0x1000, 0x1100, Kind.section, {"name": ".t"}, Level.proven)

    @rule("T.b", version="1", ceiling=Level.derived, outputs=("symbol",), needs=("T.a",), inputs=("config",))
    def b(ctx):
        calls.append("b")
        secs = ctx.facts(Kind.section)
        yield ctx.fact(secs[0].lo, secs[0].hi, Kind.symbol, {"skind": "fill", "cfg": ctx.input("config")["x"]}, Level.derived)

    @rule("T.c", version="1", ceiling=Level.open, outputs=("symbol",), needs=("kind:symbol",))
    def c(ctx):
        calls.append("c")
        yield ctx.fact(0x1100, 0x1200, Kind.symbol, {"skind": "unknown.code"}, Level.open)

    p = FakeProject(tmp_path)
    yield p, calls
    eng.RULES.clear()
    eng.RULES.update(saved)


def test_order_and_memo(toy):
    p, calls = toy
    e = Engine(p, p.store)
    assert [r.id for r in e.order()] == ["T.a", "T.b", "T.c"]
    res = e.run()
    assert calls == ["a", "b", "c"]
    assert all(r.ran for r in res)
    res = e.run()
    assert calls == ["a", "b", "c"]           # nothing reran
    assert not any(r.ran for r in res)
    p.cfg_hash = "cfg2"                      # an input of T.b changed but its output did not: T.c stays
    res = e.run()
    assert calls == ["a", "b", "c", "b"]
    assert [r.rule for r in res if r.ran] == ["T.b"]
    p.cfg_hash, p.x = "cfg3", 2              # now T.b's output changes: T.c reruns, T.a not
    res = e.run()
    assert calls == ["a", "b", "c", "b", "b", "c"]
    assert [r.rule for r in res if r.ran] == ["T.b", "T.c"]
    facts = p.store.facts(Kind.symbol)
    assert [f.value["skind"] for f in facts] == ["fill", "unknown.code"]


def test_level_ceiling(toy, tmp_path):
    p, calls = toy

    @rule("T.bad", version="1", ceiling=Level.derived, outputs=("name",))
    def bad(ctx):
        yield ctx.fact(0x1000, 0x1001, Kind.name, {"name": "x"}, Level.proven)

    e = Engine(p, p.store)
    with pytest.raises(RuleError):
        e.run(["T.bad"])


def test_undeclared_output(toy):
    p, calls = toy

    @rule("T.out", version="1", ceiling=Level.proven, outputs=("name",))
    def out(ctx):
        yield ctx.fact(0x1000, 0x1001, Kind.unit, {"tu": "x"}, Level.proven)

    e = Engine(p, p.store)
    with pytest.raises(RuleError):
        e.run(["T.out"])


def test_declared_fact_needs_reason():
    with pytest.raises(ValueError):
        Fact(0x1000, 0x1001, Kind.name, {"name": "x"}, Level.declared, "decl:decl/text.dcl:3")
    f = Fact(0x1000, 0x1001, Kind.name, {"name": "x"}, Level.declared, "decl:decl/text.dcl:3", "a leaked path")
    assert f.level is Level.declared
