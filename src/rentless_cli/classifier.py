"""Deterministic risk classifier (FR-2.1 .. FR-2.4).

Classification is entirely rule-based and never asks the LLM to self-rate.
Shell commands are parsed with a real shell grammar (bashlex) so pipelines,
chains (`&&`, `;`, `|`), and command substitutions are decomposed into
individual commands rather than pattern-matched as one opaque string.

Fail-closed (§4.1): any parse failure or ambiguity yields the *higher* of the
candidate tiers, never the lower, and unmapped commands/tools default to
Tier 4 (FR-2.3).
"""

from __future__ import annotations

from dataclasses import dataclass, field

import bashlex

from .ruleset import Ruleset
from .tiers import DEFAULT_UNMAPPED_TIER, Tier


@dataclass
class ClassificationResult:
    tier: Tier
    matched_rule: str
    explanation_seed: str
    raw: str
    sub_commands: list[str] = field(default_factory=list)
    parse_error: bool = False


def _extract_simple_commands(node) -> list[list[str]]:
    """Recursively walk a bashlex AST and return argv lists for every
    simple command found (covers pipelines, lists, and-or, subshells)."""
    commands: list[list[str]] = []

    def visit(n):
        kind = getattr(n, "kind", None)
        if kind == "command":
            words = [
                part.word
                for part in n.parts
                if getattr(part, "kind", None) == "word"
            ]
            if words:
                commands.append(words)
        for part in getattr(n, "parts", []) or []:
            visit(part)

    visit(node)
    return commands


def classify_shell_command(command: str, ruleset: Ruleset) -> ClassificationResult:
    """Classify a raw shell command string.

    Splits on shell grammar via bashlex; every discrete sub-command found is
    classified independently and the overall result is the *highest* (most
    restrictive) tier among them, so `ls && rm -rf /` is gated as the rm, not
    the ls.
    """
    try:
        trees = bashlex.parse(command)
    except Exception:
        # Fail closed: unparsable input is treated as maximally risky.
        return ClassificationResult(
            tier=Tier.T5,
            matched_rule="parse-error:fail-closed",
            explanation_seed=(
                "This command could not be parsed by the shell-grammar parser, "
                "so it is treated as the highest risk tier for safety."
            ),
            raw=command,
            parse_error=True,
        )

    all_argvs: list[list[str]] = []
    for tree in trees:
        all_argvs.extend(_extract_simple_commands(tree))

    if not all_argvs:
        return ClassificationResult(
            tier=DEFAULT_UNMAPPED_TIER,
            matched_rule="empty-or-unrecognized",
            explanation_seed="No recognizable command was found in the input.",
            raw=command,
        )

    best_tier = Tier.T1
    best_rule = ""
    best_seed = ""
    for argv in all_argvs:
        sub_tier, sub_rule, sub_seed = _classify_single_argv(argv, ruleset)
        if sub_tier >= best_tier:
            best_tier, best_rule, best_seed = sub_tier, sub_rule, sub_seed

    return ClassificationResult(
        tier=best_tier,
        matched_rule=best_rule,
        explanation_seed=best_seed,
        raw=command,
        sub_commands=[" ".join(a) for a in all_argvs],
    )


def _classify_single_argv(argv: list[str], ruleset: Ruleset) -> tuple[Tier, str, str]:
    argv_str = " ".join(argv)
    command_name = argv[0] if argv else ""

    # argv-level rules (full-command regex, e.g. `rm -rf`) take precedence
    # since they are more specific than a bare command-name match.
    best_tier = None
    best_rule = None
    best_desc = None
    for rule in ruleset.argv_rules:
        if rule.matches(argv_str):
            if best_tier is None or rule.tier > best_tier:
                best_tier = rule.tier
                best_rule = f"argv_rule:{rule.pattern}"
                best_desc = rule.description

    for rule in ruleset.shell_rules:
        if rule.matches(command_name):
            if best_tier is None or rule.tier > best_tier:
                best_tier = rule.tier
                best_rule = f"shell_rule:{rule.pattern}"
                best_desc = rule.description

    if best_tier is None:
        return (
            DEFAULT_UNMAPPED_TIER,
            f"default-deny:unmapped-command:{command_name}",
            f"'{command_name}' has no explicit ruleset entry; unmapped "
            f"commands default to {DEFAULT_UNMAPPED_TIER.name}.",
        )

    return best_tier, best_rule, best_desc or ""


def classify_mcp_call(server: str, tool: str, ruleset: Ruleset) -> ClassificationResult:
    """Classify an MCP tool call by (server, tool) tuple (FR-2.3, FR-6.3).

    Unmapped tools default to Tier 4 minimum — never auto-approved.
    """
    best_tier = None
    best_rule = None
    best_desc = None
    for rule in ruleset.mcp_rules:
        if rule.matches(server, tool):
            if best_tier is None or rule.tier > best_tier:
                best_tier = rule.tier
                best_rule = f"mcp_rule:{rule.server}/{rule.tool}"
                best_desc = rule.description

    raw = f"mcp://{server}/{tool}"
    if best_tier is None:
        return ClassificationResult(
            tier=DEFAULT_UNMAPPED_TIER,
            matched_rule=f"default-deny:unmapped-mcp-tool:{server}/{tool}",
            explanation_seed=(
                f"MCP tool '{tool}' on server '{server}' has no explicit ruleset "
                f"entry; unmapped tools default to {DEFAULT_UNMAPPED_TIER.name}."
            ),
            raw=raw,
        )

    return ClassificationResult(
        tier=best_tier,
        matched_rule=best_rule,
        explanation_seed=best_desc or "",
        raw=raw,
    )
