"""The setup rules on the first real target, server.dll (skipped when the GOG install is absent)."""
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import declare_vc6

SERVER = Path("C:/Program Files/GOG Galaxy/Games/The Guild Gold/server/server.dll")
TOOLCHAIN = Path("C:/Tools/MSVC600-SP5PP")

pytestmark = pytest.mark.skipif(not (SERVER.exists() and TOOLCHAIN.exists()), reason="server.dll or VC6 not installed")


@pytest.fixture(scope="module")
def project(tmp_path_factory):
    from decompanion.config import Project
    from decompanion.init import init_project
    d = tmp_path_factory.mktemp("guild-server")
    init_project(d, SERVER)
    declare_vc6(d)
    return Project(d)


def test_pe_facts(project):
    img = project.image
    assert img.is_dll and img.base == 0x10000000
    assert {e.name for e in img.exports()} == {"Init", "Exit"}
    assert len(img.relocations()) == 3099
    assert (48, 9044, 37) in img.rich()


def test_setup_total_map(project):
    from decompanion.ledger import query
    from decompanion.ledger.fact import Kind, Level
    from decompanion.rules.engine import Engine
    import decompanion.rules  # noqa: F401
    e = Engine(project, project.store)
    e.run()
    query.ensure_bytemap(project.store)
    rows = project.store.bytemap_rows()
    img = project.image
    # total and non-overlapping over the mapped image
    assert rows[0][0] == img.base and rows[-1][1] == img.end
    for (a_lo, a_hi, *_), (b_lo, *_rest) in zip(rows, rows[1:]):
        assert a_hi == b_lo, f"gap or overlap at {a_hi:#x}"
    names = {f.value["name"]: f.lo for f in project.store.facts(Kind.name)}
    assert names["Init"] == 0x10008cc0 and names["Exit"] == 0x10008cf0
    assert names["_DllMain@12"] == 0x10008cb0 and names["DllMain"] == 0x10008cb0
    assert names["_malloc"] and names["__DllMainCRTStartup@12"] == img.entry
    bad = [c for c in project.store.conflicts() if c.severity.value in ("bug", "error")]
    assert not bad, [c.line() for c in bad][:5]
    tc = project.store.facts(Kind.toolchain)[0].value
    comps = {(c["tool"], c["build"]): c for c in tc["compilers"]}
    assert comps[("Utc12_2_C", 9044)]["count"] == 37 and comps[("Utc12_2_C", 9044)]["archive_objects"] == 0
    assert comps[("Utc12_C", 8047)]["archive_objects"] > 0          # the static CRT's objects carry @comp.id 8047
    assert 8447 in {k["build"] for k in tc["linkers"]}
    # the declarations of `dcp toolchain declare`, one reason per key
    decl = project.toolchain_decl
    assert decl["compiler"] == "cl 12.00.9044" and decl["linker"] == "link 6.00.8447" and decl["reasons"]["compiler"].startswith("test:")
    # a second run runs nothing
    res = e.run()
    assert not any(r.ran for r in res)
