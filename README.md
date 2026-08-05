# rentless

**rentless-cli** — a Tiered-Permission CLI AI Agent.

Implements the SRS in `SRS_Tiered_Permission_CLI_Agent-1.pdf`: a command-line agent
that plans tasks with an LLM but gates every proposed shell command or MCP tool
call behind a deterministic, five-tier risk classifier before it can run.

- **T1** Read-only — auto-approved, logged.
- **T2** Safe write — auto-approved, logged with detail.
- **T3** Moderate risk — y/n confirmation with a plain-language explanation.
- **T4** Destructive / hard-to-reverse — typed confirmation phrase required.
- **T5** Irreversible / high blast radius — denied unless launched with
  `--allow-tier5`, and still requires a typed confirmation phrase per action.

Unmapped shell commands and MCP tools default to Tier 4 (fail-closed,
default-deny). Shell commands are parsed with a real shell grammar
(`bashlex`), not naive substring matching, so pipelines and command chains
are decomposed and classified sub-command by sub-command.

## Project layout

- `src/rentless_cli/tiers.py` — tier definitions and defaults.
- `src/rentless_cli/ruleset.py` — versioned, human-editable YAML ruleset.
- `src/rentless_cli/classifier.py` — deterministic classifier (bashlex-based).
- `src/rentless_cli/gate.py` — confirmation flow (y/n, typed phrase, deny-by-default).
- `src/rentless_cli/audit.py` — append-only JSONL audit log with secret redaction.
- `src/rentless_cli/executor.py` — subprocess execution wrapper with per-tier timeouts.
- `src/rentless_cli/planner.py` — pluggable LLM planner interface (`NullPlanner` offline default).
- `src/rentless_cli/mcp_host.py` — MCP server registration and per-server scoping stub.
- `src/rentless_cli/cli.py` — CLI commands: `run`, `classify`, `rules list`, `logs query`.
- `tests/` — pytest suite covering classification, ruleset editing, audit logging, and the gate.

## Usage

```bash
pip install -e ".[dev]"

# Classify a command without executing it (dry-run)
rentless classify "rm -rf /tmp/foo"

# List current tier mappings
rentless rules list

# Run a task through the planner + gate (offline mode treats the task as a raw shell command)
rentless run "ls -la"

# Query the audit log
rentless logs query --decision denied
```

## Running tests

```bash
python -m pytest
```

## What's not implemented (v1 scope, per SRS)

- A real LLM-backed `Planner`/`Explainer` (only the offline `NullPlanner` /
  `StaticExplainer` fallbacks are provided; the interfaces are designed to be
  swapped for an LLM provider).
- Full MCP wire-protocol client (only server registration/scoping data model).
- Container/VM sandboxed execution mode.
- Multi-user/team permission delegation, remote/headless approval, fine-grained
  per-file ACLs (explicitly out of scope for v1 per the SRS).
