"""LLM planning interface (FR-1.x).

The Agent decomposes an LLM's plan into discrete, individually-classifiable
actions rather than executing an opaque multi-step blob (FR-1.3). This
module defines the pluggable `Planner` protocol and a deterministic
`NullPlanner` fallback used when no LLM provider is configured, so the rest
of the system (classifier, gate, executor, audit) is fully testable and
usable without any network/API dependency.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass
class PlannedAction:
    """A single discrete action proposed by the planner."""

    kind: str  # "shell" | "mcp"
    command: str | None = None  # for kind == "shell"
    server: str | None = None  # for kind == "mcp"
    tool: str | None = None  # for kind == "mcp"
    arguments: dict | None = None  # for kind == "mcp"


class Planner(Protocol):
    def plan(self, task: str, *, context: dict) -> list[PlannedAction]:
        ...

    def explain(self, action: PlannedAction, tier_name: str, matched_rule: str) -> str:
        ...

    def notify_denied(self, action: PlannedAction, reason: str) -> None:
        ...

    def notify_failed(self, action: PlannedAction, error: str) -> None:
        ...


class NullPlanner:
    """No-op planner: treats the whole task string as a single shell command.

    Useful for offline/local-only operation and as the default until a real
    LLM-backed planner is configured (see §2.6: local-only mode possible).
    """

    def plan(self, task: str, *, context: dict) -> list[PlannedAction]:
        return [PlannedAction(kind="shell", command=task)]

    def explain(self, action: PlannedAction, tier_name: str, matched_rule: str) -> str:
        return f"No LLM configured; showing raw command classified as {tier_name} ({matched_rule})."

    def notify_denied(self, action: PlannedAction, reason: str) -> None:
        # FR-3.6: report denial back into the planning loop so it can
        # propose an alternative. NullPlanner has no loop, so this is a no-op.
        return None

    def notify_failed(self, action: PlannedAction, error: str) -> None:
        # FR-4.4: surface failures to the planning loop for re-planning.
        return None
