# OpenCode Webview — Benchmark Demos

Six end-to-end demos that exercise different capability dimensions of the framework.
Each is a self-contained bash script you can run directly from the repo root.

```bash
bash benchmarks/<name>.sh
```

| # | Script | App | Pattern | Use Case |
|---|--------|-----|---------|----------|
| 1 | `01_deployment_wizard.sh` | `dynamic` | Multi-step form wizard | DevOps / CI–CD |
| 2 | `02_code_review_hitl.sh` | `approval-review` | Diff review + feedback | Code review agent |
| 3 | `03_pr_batch_triage.sh` | `dynamic` | Item list batch decisions | PR triage assistant |
| 4 | `04_security_findings_qa.sh` | `security-qa` | Tabbed finding review | Pentest / SecEng |
| 5 | `05_db_schema_migration.sh` | `dynamic` | Progressive status + confirm | DBA / migrations |
| 6 | `06_data_pipeline_config.sh` | `dynamic` | Multi-section dashboard | Data engineering |

## What each demo tests

- **01** — Dynamic app form wizard, `submit` value collection, multi-step state transitions, processing→completed lifecycle
- **02** — Custom app (approval-review), unified diff rendering, inline feedback capture, approve/reject/feedback action combo
- **03** — Items section with per-item actions, batch state, async-style non-blocking polling pattern
- **04** — Custom app (security-qa), complex data shape, multi-finding tabbed UI, analyst annotation, bulk submit action
- **05** — Text + actions sections, progressive UI updates (show analysis results before asking for confirm), error status path
- **06** — Two-column form, select fields, static display fields, textarea, multi-section layout, checkbox

## Running interactively vs. in simulation mode

Each script detects a `--simulate` flag that auto-answers with synthetic responses
(useful for CI or automated benchmarking without human interaction):

```bash
bash benchmarks/01_deployment_wizard.sh --simulate
```

The simulation injects pre-cooked `actions.json` payloads so the full agent-side
script logic runs without waiting for a human.
