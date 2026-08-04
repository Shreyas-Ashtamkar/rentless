"""MCP Host stub (FR-6.1 .. FR-6.4).

The Agent is the MCP Host: it owns tool-call dispatch and is the single
point where the permission gate is enforced (§2.1). This module models
server registration and per-server scoping; it does not implement the full
MCP wire protocol (out of scope to hand-roll for v1 — a real implementation
should use an official MCP client SDK), but establishes the contract the
rest of the Agent (classifier, gate) relies on: every registered tool must
be mapped into the ruleset, and unmapped tools default to Tier 4.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .ruleset import Ruleset
from .tiers import DEFAULT_UNMAPPED_TIER, Tier


@dataclass
class McpServerConfig:
    name: str
    transport: str  # "stdio" | "url"
    location: str  # command for stdio, URL for remote
    scope_root: str | None = None  # e.g. restrict a filesystem server to a directory
    tools: list[str] = field(default_factory=list)  # declared tool names


class McpHost:
    """Registers MCP servers and maps their declared tools into the ruleset."""

    def __init__(self, ruleset: Ruleset) -> None:
        self.ruleset = ruleset
        self.servers: dict[str, McpServerConfig] = {}

    def register_server(self, config: McpServerConfig) -> None:
        self.servers[config.name] = config

    def tool_tier(self, server: str, tool: str) -> Tier:
        for rule in self.ruleset.mcp_rules:
            if rule.matches(server, tool):
                return rule.tier
        # FR-6.3 / FR-2.3: unmapped tools default to Tier 4, never auto-approved.
        return DEFAULT_UNMAPPED_TIER

    def is_in_scope(self, server: str, path: str) -> bool:
        """Check a filesystem-style path argument against the server's
        declared scope root (FR-6.2). Servers without a scope_root are
        considered unscoped (caller should treat conservatively)."""
        cfg = self.servers.get(server)
        if cfg is None or cfg.scope_root is None:
            return False
        from pathlib import Path

        try:
            Path(path).resolve().relative_to(Path(cfg.scope_root).resolve())
            return True
        except ValueError:
            return False
