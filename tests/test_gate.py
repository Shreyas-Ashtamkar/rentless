from gatekeeper_cli.classifier import classify_shell_command
from gatekeeper_cli.gate import ConfirmationGate
from gatekeeper_cli.ruleset import default_ruleset


def test_t1_auto_approved_no_prompt():
    rs = default_ruleset()
    result = classify_shell_command("ls", rs)
    gate = ConfirmationGate(input_fn=lambda _: (_ for _ in ()).throw(AssertionError("should not prompt")))
    decision = gate.decide(result)
    assert decision.approved


def test_t3_requires_yn_confirmation_yes():
    rs = default_ruleset()
    result = classify_shell_command("rm file.txt", rs)
    gate = ConfirmationGate(input_fn=lambda _: "y", print_fn=lambda _: None)
    decision = gate.decide(result)
    assert decision.approved


def test_t3_requires_yn_confirmation_no():
    rs = default_ruleset()
    result = classify_shell_command("rm file.txt", rs)
    gate = ConfirmationGate(input_fn=lambda _: "n", print_fn=lambda _: None)
    decision = gate.decide(result)
    assert not decision.approved


def test_t4_requires_typed_phrase_not_yn():
    rs = default_ruleset()
    result = classify_shell_command("rm -rf /tmp/x", rs)
    # Answering "y" should NOT be sufficient for T4.
    gate = ConfirmationGate(input_fn=lambda _: "y", print_fn=lambda _: None)
    decision = gate.decide(result)
    assert not decision.approved


def test_t5_denied_without_override_flag():
    rs = default_ruleset()
    result = classify_shell_command("sudo rm -rf /", rs)
    gate = ConfirmationGate(allow_tier5=False, print_fn=lambda _: None)
    decision = gate.decide(result)
    assert not decision.approved
    assert "denied by default" in decision.reason


def test_t5_allowed_with_override_still_requires_typed_phrase():
    rs = default_ruleset()
    result = classify_shell_command("sudo systemctl restart nginx", rs)
    gate = ConfirmationGate(allow_tier5=True, input_fn=lambda _: "y", print_fn=lambda _: None)
    decision = gate.decide(result)
    # plain "y" must not satisfy typed-phrase requirement even with override
    assert not decision.approved
