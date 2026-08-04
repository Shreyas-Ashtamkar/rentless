from rentless_cli.classifier import classify_mcp_call, classify_shell_command
from rentless_cli.ruleset import default_ruleset
from rentless_cli.tiers import Tier


def test_readonly_commands_are_tier1():
    rs = default_ruleset()
    assert classify_shell_command("ls -la", rs).tier == Tier.T1
    assert classify_shell_command("git status", rs).tier == Tier.T1


def test_unmapped_command_defaults_to_tier4():
    rs = default_ruleset()
    result = classify_shell_command("totallyunknowncmd --flag", rs)
    assert result.tier == Tier.T4
    assert "default-deny" in result.matched_rule


def test_rm_rf_is_tier4():
    rs = default_ruleset()
    result = classify_shell_command("rm -rf /tmp/scratch", rs)
    assert result.tier == Tier.T4


def test_plain_rm_is_tier3():
    rs = default_ruleset()
    result = classify_shell_command("rm file.txt", rs)
    assert result.tier == Tier.T3


def test_sudo_is_tier5():
    rs = default_ruleset()
    result = classify_shell_command("sudo apt-get update", rs)
    assert result.tier == Tier.T5


def test_pipeline_takes_highest_tier():
    rs = default_ruleset()
    result = classify_shell_command("ls | sudo tee /etc/hosts", rs)
    assert result.tier == Tier.T5
    assert len(result.sub_commands) == 2


def test_chained_commands_take_highest_tier():
    rs = default_ruleset()
    result = classify_shell_command("cat file.txt && rm -rf /", rs)
    assert result.tier == Tier.T4


def test_obfuscated_command_still_parsed_by_grammar():
    rs = default_ruleset()
    # Command substitution / variable tricks still get parsed structurally.
    result = classify_shell_command('echo hi; rm -rf /tmp/x', rs)
    assert result.tier == Tier.T4


def test_unparsable_command_fails_closed_to_tier5():
    rs = default_ruleset()
    result = classify_shell_command("((( unbalanced", rs)
    assert result.tier == Tier.T5
    assert result.parse_error


def test_mcp_unmapped_tool_defaults_to_tier4():
    rs = default_ruleset()
    result = classify_mcp_call("filesystem", "delete_everything", rs)
    assert result.tier == Tier.T4


def test_mcp_mapped_readonly_tool_is_tier1():
    rs = default_ruleset()
    result = classify_mcp_call("filesystem", "read_file", rs)
    assert result.tier == Tier.T1


def test_mcp_write_tool_is_tier2():
    rs = default_ruleset()
    result = classify_mcp_call("filesystem", "write_file", rs)
    assert result.tier == Tier.T2
