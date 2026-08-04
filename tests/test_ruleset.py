import pytest

from gatekeeper_cli.ruleset import Ruleset, default_ruleset
from gatekeeper_cli.tiers import Tier


def test_set_shell_rule_refuses_to_loosen_below_t3():
    rs = default_ruleset()
    with pytest.raises(ValueError):
        rs.set_shell_rule("rm", Tier.T1, "trying to loosen")


def test_set_shell_rule_allows_tightening():
    rs = default_ruleset()
    rs.set_shell_rule("ls", Tier.T3, "tightened for this project")
    assert any(r.pattern == "ls" and r.tier == Tier.T3 for r in rs.shell_rules)


def test_set_shell_rule_allows_loosen_when_forced():
    rs = default_ruleset()
    rs.set_shell_rule("rm", Tier.T1, "forced", allow_loosen=True)
    assert any(r.pattern == "rm" and r.tier == Tier.T1 for r in rs.shell_rules)


def test_roundtrip_save_and_load(tmp_path):
    rs = default_ruleset()
    path = tmp_path / "ruleset.yaml"
    rs.save(path)
    loaded = Ruleset.load(path)
    assert loaded.version == rs.version
    assert len(loaded.shell_rules) == len(rs.shell_rules)
    assert len(loaded.mcp_rules) == len(rs.mcp_rules)


def test_load_missing_path_returns_default(tmp_path):
    path = tmp_path / "does_not_exist.yaml"
    rs = Ruleset.load(path)
    assert rs.version == 1
    assert len(rs.shell_rules) > 0
