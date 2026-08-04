"""Subprocess execution wrapper (FR-4.1 .. FR-4.4)."""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass

from .tiers import DEFAULT_TIER_TIMEOUTS_SECONDS, Tier


@dataclass
class ExecutionResult:
    stdout: str
    stderr: str
    exit_code: int
    duration_seconds: float
    timed_out: bool = False


def execute_shell_command(
    command: str,
    tier: Tier,
    *,
    timeout_seconds: int | None = None,
    cwd: str | None = None,
) -> ExecutionResult:
    """Run an approved shell command, capturing stdout/stderr/exit code and
    wall-clock duration. Timeout defaults per-tier (lower for higher tiers).
    """
    timeout = timeout_seconds or DEFAULT_TIER_TIMEOUTS_SECONDS[tier]
    start = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            shell=True,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        duration = time.monotonic() - start
        return ExecutionResult(
            stdout=proc.stdout,
            stderr=proc.stderr,
            exit_code=proc.returncode,
            duration_seconds=duration,
        )
    except subprocess.TimeoutExpired as exc:
        duration = time.monotonic() - start
        return ExecutionResult(
            stdout=exc.stdout or "" if isinstance(exc.stdout, str) else "",
            stderr=(exc.stderr or "") if isinstance(exc.stderr, str) else "",
            exit_code=-1,
            duration_seconds=duration,
            timed_out=True,
        )
