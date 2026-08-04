import json

from rentless_cli.audit import AuditLog, redact


def test_audit_log_appends_and_reads(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.log_proposal(action="ls -la", tier=1, matched_rule="shell_rule:ls", decision="auto")
    log.log_proposal(action="rm file.txt", tier=3, matched_rule="argv_rule:rm", decision="approved")

    entries = log.read_all()
    assert len(entries) == 2
    assert entries[0]["action"] == "ls -la"
    assert entries[1]["decision"] == "approved"


def test_audit_log_query_filters_by_tier_and_decision(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.log_proposal(action="ls", tier=1, matched_rule="r1", decision="auto")
    log.log_proposal(action="rm x", tier=3, matched_rule="r2", decision="denied")
    log.log_proposal(action="rm -rf x", tier=4, matched_rule="r3", decision="denied")

    denied = log.query(decision="denied")
    assert len(denied) == 2
    tier4 = log.query(tier=4)
    assert len(tier4) == 1
    assert tier4[0]["action"] == "rm -rf x"


def test_audit_log_is_append_only_never_truncated(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.log_proposal(action="a", tier=1, matched_rule="r", decision="auto")
    size_after_one = path.stat().st_size
    log.log_proposal(action="b", tier=1, matched_rule="r", decision="auto")
    assert path.stat().st_size > size_after_one


def test_secrets_are_redacted_before_logging(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.log_proposal(
        action="curl -H 'Authorization: token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345'",
        tier=3,
        matched_rule="r",
        decision="approved",
    )
    raw = (tmp_path / "audit.jsonl").read_text()
    assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345" not in raw
    assert "REDACTED" in raw


def test_redact_helper_handles_multiple_patterns():
    text = "api_key=abcd1234 password: hunter2 done"
    redacted = redact(text)
    assert "abcd1234" not in redacted
    assert "hunter2" not in redacted
