"""CLI entry point (FR-1.4, FR-7.1, FR-7.2, FR-5.3)."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from .audit import AuditLog
from .classifier import classify_mcp_call, classify_shell_command
from .executor import execute_shell_command
from .gate import ConfirmationGate
from .planner import NullPlanner, PlannedAction
from .ruleset import Ruleset

app = typer.Typer(help="rentless-cli: Tiered-Permission CLI AI Agent")
console = Console()


def _load_ruleset(ruleset_path: Optional[str]) -> Ruleset:
    return Ruleset.load(Path(ruleset_path) if ruleset_path else None)


@app.command()
def run(
    task: str = typer.Argument(..., help="Natural-language task, or a raw shell command in offline mode."),
    allow_tier5: bool = typer.Option(False, "--allow-tier5", help="Permit Tier 5 actions (still requires typed confirmation each time)."),
    ruleset_path: Optional[str] = typer.Option(None, "--ruleset", help="Path to ruleset YAML."),
    log_path: Optional[str] = typer.Option(None, "--log", help="Path to audit log JSONL."),
    batch: bool = typer.Option(False, "--batch", help="Plan-then-review batch mode instead of step-by-step."),
):
    """Plan a task (via the configured/offline planner) and execute its
    actions through the permission gate, one classified action at a time."""
    ruleset = _load_ruleset(ruleset_path)
    audit = AuditLog(Path(log_path) if log_path else None)
    planner = NullPlanner()
    gate = ConfirmationGate(allow_tier5=allow_tier5)

    actions = planner.plan(task, context={"cwd": str(Path.cwd())})

    if batch:
        console.print("[bold]Planned actions:[/bold]")
        for i, action in enumerate(actions, 1):
            console.print(f"  {i}. {action.kind}: {action.command or f'{action.server}/{action.tool}'}")
        if not typer.confirm("Proceed to review each action?", default=True):
            raise typer.Exit(code=1)

    for action in actions:
        _handle_action(action, ruleset, gate, audit, planner)


def _handle_action(action: PlannedAction, ruleset: Ruleset, gate: ConfirmationGate,
                    audit: AuditLog, planner: NullPlanner) -> None:
    if action.kind == "shell":
        result = classify_shell_command(action.command or "", ruleset)
    else:
        result = classify_mcp_call(action.server or "", action.tool or "", ruleset)

    decision = gate.decide(result)

    if not decision.approved:
        audit.log_proposal(
            action=result.raw, tier=int(result.tier), matched_rule=result.matched_rule,
            decision="denied",
        )
        console.print(f"[red]Denied:[/red] {decision.reason}")
        planner.notify_denied(action, decision.reason)
        return

    exec_result = None
    if action.kind == "shell":
        exec_result = execute_shell_command(action.command or "", result.tier)
        console.print(exec_result.stdout)
        if exec_result.stderr:
            console.print(f"[yellow]{exec_result.stderr}[/yellow]")
        if exec_result.exit_code != 0:
            planner.notify_failed(action, exec_result.stderr or f"exit code {exec_result.exit_code}")

    decision_label = "auto" if not result.tier.requires_confirmation else "approved"
    audit.log_proposal(
        action=result.raw,
        tier=int(result.tier),
        matched_rule=result.matched_rule,
        decision=decision_label,
        result=(
            {
                "exit_code": exec_result.exit_code,
                "duration_seconds": exec_result.duration_seconds,
            }
            if exec_result
            else None
        ),
    )


@app.command()
def classify(
    command: str = typer.Argument(..., help="Shell command to classify."),
    ruleset_path: Optional[str] = typer.Option(None, "--ruleset"),
):
    """Dry-run: classify a command/tool call and show its tier and matched
    rule without executing it (FR-7.2)."""
    ruleset = _load_ruleset(ruleset_path)
    result = classify_shell_command(command, ruleset)
    console.print(f"Command: {result.raw}")
    console.print(f"Tier: [bold]{result.tier.name}[/bold] ({result.tier.label})")
    console.print(f"Matched rule: {result.matched_rule}")
    if result.explanation_seed:
        console.print(f"Why: {result.explanation_seed}")


rules_app = typer.Typer(help="Ruleset management commands.")
app.add_typer(rules_app, name="rules")


@rules_app.command("list")
def rules_list(ruleset_path: Optional[str] = typer.Option(None, "--ruleset")):
    """List current tier mappings (FR-7.1)."""
    ruleset = _load_ruleset(ruleset_path)

    table = Table(title="Shell rules")
    table.add_column("Pattern")
    table.add_column("Tier")
    table.add_column("Description")
    for rule in ruleset.shell_rules:
        table.add_row(rule.pattern, rule.tier.name, rule.description)
    console.print(table)

    table = Table(title="Argv rules")
    table.add_column("Pattern")
    table.add_column("Tier")
    table.add_column("Description")
    for rule in ruleset.argv_rules:
        table.add_row(rule.pattern, rule.tier.name, rule.description)
    console.print(table)

    table = Table(title="MCP rules")
    table.add_column("Server")
    table.add_column("Tool")
    table.add_column("Tier")
    table.add_column("Description")
    for rule in ruleset.mcp_rules:
        table.add_row(rule.server, rule.tool, rule.tier.name, rule.description)
    console.print(table)


logs_app = typer.Typer(help="Audit log query commands.")
app.add_typer(logs_app, name="logs")


@logs_app.command("query")
def logs_query(
    tier: Optional[int] = typer.Option(None, help="Filter by tier (1-5)."),
    decision: Optional[str] = typer.Option(None, help="Filter by decision: auto, approved, denied."),
    since: Optional[str] = typer.Option(None, help="ISO timestamp lower bound."),
    until: Optional[str] = typer.Option(None, help="ISO timestamp upper bound."),
    log_path: Optional[str] = typer.Option(None, "--log"),
):
    """Query the audit log filtered by tier, date range, or outcome (FR-5.3)."""
    audit = AuditLog(Path(log_path) if log_path else None)
    entries = audit.query(tier=tier, decision=decision, since=since, until=until)
    for entry in entries:
        console.print(entry)
    console.print(f"[bold]{len(entries)} entries[/bold]")


if __name__ == "__main__":
    app()
