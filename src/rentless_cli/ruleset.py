"""Ruleset loading and representation (FR-2.4, FR-2.5).

The ruleset is a versioned, human-editable YAML file mapping:
  - shell command patterns (regex/glob on the command name, and optionally
    full-argv patterns) to tiers
  - MCP (server, tool) tuples (exact or wildcard) to tiers

It is intentionally a pure data + lookup layer with no execution or LLM
involvement, per the deterministic-classifier constraint (§2.5, FR-2.1).
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .tiers import MIN_LOOSENABLE_TIER, Tier

DEFAULT_RULESET_PATH = Path.home() / ".config" / "rentless-cli" / "ruleset.yaml"


@dataclass
class ShellRule:
    """A rule matching a shell command by its executable name (regex/glob)."""

    pattern: str
    tier: Tier
    description: str = ""
    match_type: str = "glob"  # "glob" or "regex"

    def matches(self, command_name: str) -> bool:
        if self.match_type == "regex":
            return re.fullmatch(self.pattern, command_name) is not None
        return fnmatch.fnmatch(command_name, self.pattern)


@dataclass
class ArgvRule:
    """A rule matching a full command argv against a regex, e.g. `rm -rf`."""

    pattern: str
    tier: Tier
    description: str = ""

    def matches(self, argv_str: str) -> bool:
        return re.search(self.pattern, argv_str) is not None


@dataclass
class McpRule:
    """A rule matching an MCP (server, tool) tuple. `*` is a wildcard."""

    server: str
    tool: str
    tier: Tier
    description: str = ""

    def matches(self, server: str, tool: str) -> bool:
        return fnmatch.fnmatch(server, self.server) and fnmatch.fnmatch(tool, self.tool)


@dataclass
class Ruleset:
    version: int
    shell_rules: list[ShellRule] = field(default_factory=list)
    argv_rules: list[ArgvRule] = field(default_factory=list)
    mcp_rules: list[McpRule] = field(default_factory=list)
    path: Path | None = None

    @classmethod
    def load(cls, path: Path | None = None) -> "Ruleset":
        path = path or DEFAULT_RULESET_PATH
        if not path.exists():
            return default_ruleset(path=path)
        data = yaml.safe_load(path.read_text()) or {}
        return cls.from_dict(data, path=path)

    @classmethod
    def from_dict(cls, data: dict[str, Any], path: Path | None = None) -> "Ruleset":
        version = int(data.get("version", 1))
        shell_rules = [
            ShellRule(
                pattern=r["pattern"],
                tier=Tier(int(r["tier"])),
                description=r.get("description", ""),
                match_type=r.get("match_type", "glob"),
            )
            for r in data.get("shell_rules", [])
        ]
        argv_rules = [
            ArgvRule(
                pattern=r["pattern"],
                tier=Tier(int(r["tier"])),
                description=r.get("description", ""),
            )
            for r in data.get("argv_rules", [])
        ]
        mcp_rules = [
            McpRule(
                server=r.get("server", "*"),
                tool=r["tool"],
                tier=Tier(int(r["tier"])),
                description=r.get("description", ""),
            )
            for r in data.get("mcp_rules", [])
        ]
        return cls(
            version=version,
            shell_rules=shell_rules,
            argv_rules=argv_rules,
            mcp_rules=mcp_rules,
            path=path,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "shell_rules": [
                {
                    "pattern": r.pattern,
                    "tier": int(r.tier),
                    "description": r.description,
                    "match_type": r.match_type,
                }
                for r in self.shell_rules
            ],
            "argv_rules": [
                {"pattern": r.pattern, "tier": int(r.tier), "description": r.description}
                for r in self.argv_rules
            ],
            "mcp_rules": [
                {
                    "server": r.server,
                    "tool": r.tool,
                    "tier": int(r.tier),
                    "description": r.description,
                }
                for r in self.mcp_rules
            ],
        }

    def save(self, path: Path | None = None) -> None:
        target = path or self.path or DEFAULT_RULESET_PATH
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(yaml.safe_dump(self.to_dict(), sort_keys=False))

    def set_shell_rule(self, pattern: str, tier: Tier, description: str = "",
                        match_type: str = "glob", *, allow_loosen: bool = False) -> None:
        """Add/override a shell rule. Refuses to loosen below MIN_LOOSENABLE_TIER
        unless explicitly forced (FR-2.5)."""
        if tier < MIN_LOOSENABLE_TIER and not allow_loosen:
            raise ValueError(
                f"Refusing to set tier below {MIN_LOOSENABLE_TIER.name} "
                f"without allow_loosen=True (would silently loosen policy)."
            )
        self.shell_rules = [r for r in self.shell_rules if r.pattern != pattern]
        self.shell_rules.append(ShellRule(pattern, tier, description, match_type))

    def set_mcp_rule(self, server: str, tool: str, tier: Tier, description: str = "",
                      *, allow_loosen: bool = False) -> None:
        if tier < MIN_LOOSENABLE_TIER and not allow_loosen:
            raise ValueError(
                f"Refusing to set tier below {MIN_LOOSENABLE_TIER.name} "
                f"without allow_loosen=True (would silently loosen policy)."
            )
        self.mcp_rules = [
            r for r in self.mcp_rules if not (r.server == server and r.tool == tool)
        ]
        self.mcp_rules.append(McpRule(server, tool, tier, description))


def default_ruleset(path: Path | None = None) -> Ruleset:
    """Built-in seed ruleset covering the SRS §3.2 examples."""
    return Ruleset(
        version=1,
        path=path,
        shell_rules=[
            ShellRule("ls", Tier.T1, "Read-only directory listing"),
            ShellRule("cat", Tier.T1, "Read-only file view"),
            ShellRule("git", Tier.T1, "git read/status commands", match_type="glob"),
            ShellRule("echo", Tier.T1, "Read-only output"),
            ShellRule("pwd", Tier.T1, "Read-only cwd"),
            ShellRule("grep", Tier.T1, "Read-only search"),
            ShellRule("find", Tier.T1, "Read-only search"),
            ShellRule("touch", Tier.T2, "Safe file creation"),
            ShellRule("mkdir", Tier.T2, "Safe directory creation"),
            ShellRule("cp", Tier.T2, "Safe copy within scope"),
            ShellRule("pip", Tier.T3, "Package install (scoped venv)"),
            ShellRule("npm", Tier.T3, "Package install"),
            ShellRule("curl", Tier.T3, "External API call"),
            ShellRule("wget", Tier.T3, "External network fetch"),
            ShellRule("chmod", Tier.T4, "Permission change, potentially recursive"),
            ShellRule("kill", Tier.T4, "Process termination"),
            ShellRule("dd", Tier.T4, "Low-level disk write"),
            ShellRule("sudo", Tier.T5, "Privilege escalation"),
            ShellRule("systemctl", Tier.T5, "System-level service control"),
            ShellRule("iptables", Tier.T5, "Network/firewall config"),
            ShellRule("shutdown", Tier.T5, "System power control"),
            ShellRule("reboot", Tier.T5, "System power control"),
        ],
        argv_rules=[
            ArgvRule(r"\brm\b.*(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)", Tier.T4,
                      "Recursive forced delete"),
            ArgvRule(r"\brm\b", Tier.T3, "File delete"),
            ArgvRule(r"\bchmod\b.*-R", Tier.T4, "Recursive permission change"),
            ArgvRule(r"\bgit\b.*\bpush\b.*--force", Tier.T4, "Force-push, hard to reverse"),
            ArgvRule(r"\bgit\b.*\bpush\b", Tier.T3, "git push (remote mutation)"),
            ArgvRule(r"\bgit\b.*\bdiff\b", Tier.T1, "Read-only diff"),
            ArgvRule(r"\bgit\b.*\bstatus\b", Tier.T1, "Read-only status"),
            ArgvRule(r"\bgit\b.*\bcommit\b", Tier.T2, "Local commit, safe write"),
            ArgvRule(r"\bDROP\b|\bTRUNCATE\b", Tier.T5, "Irreversible DB schema/data loss"),
        ],
        mcp_rules=[
            McpRule("*", "list_resources", Tier.T1, "Read-only MCP listing"),
            McpRule("*", "read_*", Tier.T1, "Read-only MCP read"),
            McpRule("*", "write_*", Tier.T2, "Scoped MCP write"),
        ],
    )
