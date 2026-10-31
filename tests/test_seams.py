"""The plugin seams: the registries, the format-neutral relocation view of objfmt, the toolchain's import stubs,
user entries and defaults, the instruction-set decoder the walk reads, and `dcp init` naming its plugins."""
import pytest

from conftest import build_pe, dcp

from decompanion.config import ConfigError, Project


# ------------------------------------------------------------------------------------------------ registries
def test_project_plugins(tiny):
    p = Project(tiny)
    assert p.image.key == "pe32" and p.image.default_isa == "x86"
    assert p.isa == "x86" and p.core.toolchain_key() == "vc6"


def test_declared_isa(tiny):
    cfg = tiny / "decompanion.toml"
    cfg.write_text(cfg.read_text().replace('image = "pe32"\n', 'image = "pe32"\nisa = "x86"\n', 1), newline="\n")
    assert Project(tiny).isa == "x86"
    cfg.write_text(cfg.read_text().replace('isa = "x86"', 'isa = "z80"', 1), newline="\n")
    with pytest.raises(ConfigError, match="unknown instruction set 'z80'"):
        Project(tiny).isa


# ------------------------------------------------------------------------------------------------ init
def test_init_names_plugins(tmp_path):
    pe = build_pe(tmp_path / "t.dll")
    from decompanion.cli import main
    assert main(["init", str(tmp_path / "proj"), str(pe)]) == 0
    text = (tmp_path / "proj" / "decompanion.toml").read_text()
    assert 'image = "pe32"\nisa = "x86"\n' in text          # computed from the file; nothing is declared
    p = Project(tmp_path / "proj")
    assert p.core.toolchain_key() == "vc6"                  # the only registered plugin, without a [toolchain] table
    assert p.target().isa == "x86" and p.isa == "x86"
    code, out = dcp(tmp_path / "proj", "target", "list")
    assert "isa=x86" in out
