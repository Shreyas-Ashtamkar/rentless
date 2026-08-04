"""Append-only JSONL audit log (FR-5.1 .. FR-5.3, §4.1, §4.2).

* Synchronous, durable writes (fsync) so a crash mid-action leaves an
  accurate record (§4.2).
* Known secret patterns are redacted before logging (§4.1).
* Never silently truncated/rotated (FR-5.2) — this module only ever appends.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_LOG_PATH = Path.home() / ".local" / "share" / "rentless-cli" / "audit.jsonl"

# Best-effort redaction of common secret shapes before they ever hit disk.
_SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key\s*[:=]\s*)([^\s'\"]+)"),
    re.compile(r"(?i)(secret\s*[:=]\s*)([^\s'\"]+)"),
    re.compile(r"(?i)(token\s*[:=]\s*)([^\s'\"]+)"),
    re.compile(r"(?i)(password\s*[:=]\s*)([^\s'\"]+)"),
    re.compile(r"sk-[A-Za-z0-9]{16,}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
]


def redact(text: str) -> str:
    if not text:
        return text
    redacted = text
    for pattern in _SECRET_PATTERNS:
        if pattern.groups >= 2:
            redacted = pattern.sub(lambda m: m.group(1) + "***REDACTED***", redacted)
        else:
            redacted = pattern.sub("***REDACTED***", redacted)
    return redacted


def _redact_any(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {k: _redact_any(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_any(v) for v in value]
    return value


@dataclass
class AuditEntry:
    timestamp: str
    event: str  # "proposal" | "ruleset_change"
    action: str
    tier: int | None = None
    matched_rule: str | None = None
    decision: str | None = None  # "auto" | "approved" | "denied"
    result: dict[str, Any] | None = field(default=None)
    detail: dict[str, Any] | None = field(default=None)

    def to_json_line(self) -> str:
        data = _redact_any(asdict(self))
        return json.dumps(data, sort_keys=False)


class AuditLog:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or DEFAULT_LOG_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _append(self, entry: AuditEntry) -> None:
        line = entry.to_json_line() + "\n"
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())

    def log_proposal(
        self,
        *,
        action: str,
        tier: int,
        matched_rule: str,
        decision: str,
        result: dict[str, Any] | None = None,
    ) -> None:
        self._append(
            AuditEntry(
                timestamp=_now(),
                event="proposal",
                action=action,
                tier=tier,
                matched_rule=matched_rule,
                decision=decision,
                result=result,
            )
        )

    def log_ruleset_change(self, *, who: str, change: dict[str, Any]) -> None:
        self._append(
            AuditEntry(
                timestamp=_now(),
                event="ruleset_change",
                action=f"ruleset change by {who}",
                detail=change,
            )
        )

    def read_all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        entries = []
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                entries.append(json.loads(line))
        return entries

    def query(
        self,
        *,
        tier: int | None = None,
        decision: str | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> list[dict[str, Any]]:
        results = self.read_all()
        if tier is not None:
            results = [r for r in results if r.get("tier") == tier]
        if decision is not None:
            results = [r for r in results if r.get("decision") == decision]
        if since is not None:
            results = [r for r in results if r.get("timestamp", "") >= since]
        if until is not None:
            results = [r for r in results if r.get("timestamp", "") <= until]
        return results


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
