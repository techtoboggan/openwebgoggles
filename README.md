# OpenWebGoggles

AI coding agents are good at writing code. They are not good at showing you things. An agent can generate a 200-line diff, but it has no way to pull up a side-by-side review UI, highlight the parts that matter, and wait for you to say "approved" or "try again with fewer abstractions."

OpenWebGoggles fixes that. It gives any agent — Claude Code, a shell script, anything that can write JSON — the ability to open a browser-based UI and get structured decisions back from a human.

Not a chat interface. Not a terminal dump. A real interactive panel: forms, approval flows, dashboards, multi-step wizards. The kind of thing you'd build if you had a few days and a frontend team. Except the agent builds it on the fly from a JSON schema, and the whole round-trip takes seconds.

```
Agent ←→ OpenWebGoggles Server ←→ Browser UI ←→ Human
```

*"The goggles — they do everything."*

## The Big Use Case: Review Before You Commit

Your agent just finished a round of work — refactored the auth module, updated three API endpoints, added tests. Before it commits, it opens a review UI in your browser that groups the changes by category and shows you what changed and why:

```json
{
  "title": "Pre-Commit Review",
  "message": "### 3 categories of changes across 8 files\nReview each category and approve or request changes.",
  "message_format": "markdown",
  "status": "pending_review",
  "data": {
    "sections": [
      { "type": "text", "title": "Auth Refactor (4 files)", "format": "markdown",
        "content": "Replaced session-based auth with JWT tokens.\n\n- `auth.py` — new `create_token()` / `verify_token()` functions\n- `middleware.py` — swapped session lookup for token validation\n- `login.py` / `logout.py` — updated to issue/revoke JWTs" },
      { "type": "text", "title": "API Updates (2 files)", "format": "markdown",
        "content": "Updated `/users` and `/settings` to use new auth middleware.\n\n- Response codes unchanged, no breaking changes" },
      { "type": "text", "title": "Tests (2 files)", "format": "markdown",
        "content": "Added 14 tests for token lifecycle. All passing." },
      { "type": "form", "fields": [
        { "key": "feedback", "label": "Notes (optional)", "type": "textarea",
          "placeholder": "Anything you want changed before committing?" }
      ]}
    ]
  },
  "actions_requested": [
    { "id": "approve", "type": "approve", "label": "Commit & Push" },
    { "id": "revise", "type": "reject", "label": "Request Changes" }
  ]
}
```

You see the summary, scan the categories, and either approve or type "the logout endpoint should also clear the cookie" and hit Request Changes. The agent gets your structured response and acts on it. No scrolling through `git diff` in a terminal.

This pattern works as a pre-commit checkpoint, a PR summary review, or any time an agent wants sign-off before taking an irreversible action.

## More Examples

### Dependency Update Review

Your agent ran `npm outdated` and found 8 packages to update. Instead of listing them in the terminal, it opens a table with selection checkboxes and a form for configuration:

```json
{
  "title": "Dependency Updates",
  "status": "pending_review",
  "data": {
    "sections": [
      { "type": "table", "title": "Available Updates",
        "columns": [
          { "key": "name", "label": "Package" },
          { "key": "current", "label": "Current" },
          { "key": "latest", "label": "Latest" },
          { "key": "type", "label": "Type" }
        ],
        "rows": [
          { "name": "react", "current": "18.2.0", "latest": "19.1.0", "type": "major" },
          { "name": "typescript", "current": "5.3.2", "latest": "5.7.3", "type": "minor" },
          { "name": "eslint", "current": "8.55.0", "latest": "9.18.0", "type": "major" }
        ]
      },
      { "type": "form", "fields": [
        { "key": "strategy", "label": "Update Strategy", "type": "select",
          "options": ["All updates", "Minor + patch only", "Patch only", "Let me choose"] },
        { "key": "run_tests", "label": "Run tests after update", "type": "checkbox", "value": true }
      ]}
    ]
  },
  "actions_requested": [
    { "id": "proceed", "type": "approve", "label": "Update Selected" },
    { "id": "skip", "type": "reject", "label": "Skip All" }
  ]
}
```

The agent gets back structured data — which strategy, whether to run tests, which button was clicked — and acts on it:

```json
{
  "actions": [{
    "action_id": "proceed",
    "type": "approve",
    "value": { "strategy": "Minor + patch only", "run_tests": true }
  }]
}
```

### Live Build Dashboard

While your agent runs a multi-step build, it streams progress to the browser in real time using `webview_update(merge=True)`:

```json
{
  "title": "Build Pipeline",
  "status": "processing",
  "data": {
    "sections": [
      { "type": "progress", "title": "Pipeline Status", "percentage": 60,
        "tasks": [
          { "label": "Install dependencies", "status": "completed" },
          { "label": "Run linter", "status": "completed" },
          { "label": "Run tests", "status": "in_progress" },
          { "label": "Build artifacts", "status": "pending" },
          { "label": "Deploy to staging", "status": "pending" }
        ]},
      { "type": "log", "title": "Test Output",
        "lines": [
          "\u001b[32m✓\u001b[0m auth.test.js (12 tests, 0.8s)",
          "\u001b[32m✓\u001b[0m api.test.js (24 tests, 1.2s)",
          "\u001b[33m⚠\u001b[0m db.test.js — running..."
        ]}
    ]
  }
}
```

No action buttons needed yet — the agent keeps pushing updates until the build finishes, then swaps in an approval step.

### Configuration Wizard

The agent needs you to configure a deployment. It uses tabs, conditional fields, and validation:

```json
{
  "title": "Deploy Configuration",
  "status": "waiting_input",
  "data": {
    "sections": [
      { "type": "tabs", "tabs": [
        { "id": "general", "label": "General", "sections": [
          { "type": "form", "fields": [
            { "key": "env", "label": "Environment", "type": "select",
              "options": ["staging", "production"], "value": "staging" },
            { "key": "branch", "label": "Branch", "type": "text", "value": "main",
              "required": true, "pattern": "^[a-zA-Z0-9/_-]+$",
              "errorMessage": "Invalid branch name" }
          ]}
        ]},
        { "id": "advanced", "label": "Advanced", "sections": [
          { "type": "form", "fields": [
            { "key": "replicas", "label": "Replicas", "type": "number", "value": 2 },
            { "key": "notify", "label": "Send notifications", "type": "checkbox", "value": true },
            { "key": "channel", "label": "Notify Channel", "type": "text",
              "placeholder": "#deployments" }
          ]}
        ]}
      ]}
    ]
  },
  "behaviors": [
    { "when": { "field": "notify", "checked": true }, "show": ["channel"] },
    { "when": { "field": "env", "equals": "production" }, "enable": ["replicas"] }
  ],
  "actions_requested": [
    { "id": "deploy", "type": "approve", "label": "Deploy" },
    { "id": "cancel", "type": "reject", "label": "Cancel" }
  ]
}
```

### Sidebar Layout

For navigation-heavy interfaces, use a multi-panel layout with a sidebar:

```json
{
  "title": "Migration Plan",
  "layout": { "type": "sidebar", "sidebarWidth": "260px" },
  "panels": {
    "sidebar": { "sections": [
      { "type": "items", "title": "Steps", "items": [
        { "title": "1. Backup database", "subtitle": "~5 min" },
        { "title": "2. Run migrations", "subtitle": "~2 min" },
        { "title": "3. Verify data", "subtitle": "~1 min" },
        { "title": "4. Switch traffic", "subtitle": "~30 sec" }
      ]}
    ]},
    "main": { "sections": [
      { "type": "diff", "title": "Migration: add_users_table",
        "content": "--- a/db/schema.sql\n+++ b/db/schema.sql\n@@ -12,0 +13,6 @@\n+CREATE TABLE users (\n+  id SERIAL PRIMARY KEY,\n+  email TEXT NOT NULL UNIQUE,\n+  created_at TIMESTAMPTZ DEFAULT NOW()\n+);" },
      { "type": "form", "fields": [
        { "key": "confirm", "label": "I've reviewed the migration", "type": "checkbox" }
      ]}
    ]}
  },
  "actions_requested": [
    { "id": "run", "type": "approve", "label": "Run Migration" }
  ]
}
```

The agent doesn't need to know HTML. It writes a JSON object describing what it wants to show, and the built-in dynamic renderer handles the rest. Structured data in, structured data out — the browser is just the rendering layer in between.

## Quick Start

Install from PyPI:

```bash
# Recommended — isolates dependencies, puts binary on PATH
pipx install openwebgoggles

# Alternative — works fine, but shares dependencies with your Python environment
pip install openwebgoggles
```

<details>
<summary><strong>Don't have pipx?</strong></summary>

pipx installs Python CLI tools in isolated environments. Install it once:

```bash
# macOS (Homebrew)
brew install pipx && pipx ensurepath

# Linux / macOS (without Homebrew)
python3 -m pip install --user pipx && pipx ensurepath

# Then restart your terminal
```

See [pipx.pypa.io](https://pipx.pypa.io) for more options.
</details>

Then bootstrap for your editor:

### Claude Code

```bash
cd your-project
openwebgoggles init claude
```

Creates `.mcp.json` and `.claude/settings.json` in your project. Restart Claude Code and you're live. Run this in each project where you want the tools available.

### OpenCode

```bash
openwebgoggles init opencode
```

Adds to `~/.config/opencode/opencode.json` (global config) — available in every project. Restart OpenCode and you're live.

> To set up a specific project instead: `openwebgoggles init opencode /path/to/project`

### Try It

Tell your agent:

> *"Show me a review UI for these changes and wait for my approval."*

> *"Create a dashboard showing the build progress with live updates."*

> *"Walk me through these dependency updates one at a time so I can decide which to apply."*

The agent figures out the JSON schema, calls `webview`, and a panel opens in your browser. You make your decisions, click approve, and the agent continues with your structured response.

### Lifecycle Commands

Once installed, three CLI commands help you manage the server:

```bash
openwebgoggles restart       # seamless restart (same PID, editor never notices)
openwebgoggles status        # check what's running, ports, uptime
openwebgoggles doctor        # diagnose setup problems
```

See the [Restart & Lifecycle Guide](references/restart-guide.md) for details on automatic recovery, manual restart, and troubleshooting.

### What Gets Installed

Five MCP tools — that's the entire API surface:

| Tool | What it does |
|------|-------------|
| `webview(state)` | Show a UI and block until the human responds |
| `webview_update(state)` | Push live updates without blocking (progress, logs, status) |
| `webview_read()` | Poll for actions without blocking |
| `webview_status()` | Check if a session is active |
| `webview_close()` | Close the session |

### Manual Setup

The `init` command is recommended — it resolves the absolute path to the binary so editors don't depend on PATH. But if you'd rather configure by hand, use the full path to the binary in your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "openwebgoggles": {
      "command": "/full/path/to/openwebgoggles"
    }
  }
}
```

Or for OpenCode, add to `opencode.json`:

```json
{
  "mcp": {
    "openwebgoggles": {
      "type": "local",
      "command": ["/full/path/to/openwebgoggles"],
      "enabled": true
    }
  }
}
```

> **Tip:** Find your binary path with `which openwebgoggles` or `pipx list`.

### Bash Scripts (for shell-based agents)

If your agent orchestrates via shell scripts — or if you just want to understand the mechanics — the bash interface exposes the same capabilities:

```bash
# Start a session
bash scripts/start_webview.sh --app dynamic

# Push state to the browser
bash scripts/write_state.sh '{"version":1, "status":"pending_review", "title":"Review Changes", ...}'

# Block until the human responds (up to 5 minutes)
ACTIONS=$(bash scripts/wait_for_action.sh --timeout 300)

# Clean up
bash scripts/stop_webview.sh
```

| Script | Purpose |
|--------|---------|
| `start_webview.sh --app <name> [--port N]` | Launch server and open browser |
| `write_state.sh '<json>'` | Atomic state write |
| `wait_for_action.sh [--timeout N]` | Block until human acts |
| `read_actions.sh [--clear]` | Read actions, optionally clear |
| `stop_webview.sh` | Graceful shutdown |
| `init_webview_app.sh <name>` | Scaffold a custom app |

## How It Works Under the Hood

The architecture is deliberately simple. Three JSON files in a `.openwebgoggles/` directory are the entire interface between the agent and the browser.

| File | Direction | Purpose |
|------|-----------|---------|
| `state.json` | Agent → Browser | What to show: data, UI schema, requested actions |
| `actions.json` | Browser → Agent | What the human decided |
| `manifest.json` | Shared | Session config: ports, app name, auth token |

The Python server watches these files and pushes updates to the browser over WebSocket in real time. The browser renders the UI and writes responses back. The agent reads the response file and continues.

This means you can debug the entire system by looking at three JSON files. No hidden state, no message queues, no databases. If something looks wrong in the browser, `cat .openwebgoggles/state.json` and you'll see exactly what the agent sent.

## The Dynamic Renderer

Most use cases don't require custom HTML. The built-in `dynamic` app takes a JSON schema and renders a complete, styled interface.

**Section types:** `text`, `items`, `form`, `actions`, `progress`, `log`, `diff`, `table`, `tabs`

**Form field types:** `text`, `textarea`, `number`, `select`, `checkbox`, `email`, `url`, `static`

**Action styles:** `primary`, `success`, `danger`, `warning`, `ghost`, `approve`, `reject`, `submit`, `delete`

You can combine these to build approval flows, configuration wizards, data entry forms, triage interfaces — really any structured interaction that runs on fields, selections, and decisions. For 80% of use cases, you never touch HTML.

### Rich Section Types

Beyond basic forms and text, the renderer supports content types purpose-built for developer workflows:

- **`progress`** — Task checklist with status icons and percentage bar. Pair with `webview_update(merge=True)` to stream live progress as your agent works.
- **`log`** — Scrolling terminal output with ANSI color support. Great for build output, test results, or any streaming text.
- **`diff`** — Unified diff viewer with line numbers, green/red coloring, and hunk headers. Show code changes without forcing the human to read raw patches.
- **`table`** — Sortable data table with optional row selection. Good for test results, dependency lists, or any tabular data.
- **`tabs`** — Client-side tabbed panels. Nest any other section types inside each tab. No server round-trip on tab switch.

### Live Updates

`webview_update()` pushes state changes to the browser without blocking. The agent can continue working while the UI updates in real time:

```json
webview_update({"status": "processing", "message": "Running tests..."}, merge=True)
```

Use `merge=True` to update specific fields without replacing the entire state. Or use presets for common patterns:

```json
webview_update({"tasks": [...], "percentage": 75}, preset="progress")
```

### Field Validation

Fields support client-side validation that blocks form submission until resolved:

```json
{"key": "email", "type": "email", "label": "Email", "required": true,
 "pattern": "^[^@]+@[^@]+$", "errorMessage": "Enter a valid email"}
```

Available validators: `required`, `pattern` (regex), `minLength`, `maxLength`.

### Conditional Fields

Show or hide fields based on other field values using behaviors:

```json
{
  "data": {"sections": [...]},
  "behaviors": [
    {"when": {"field": "type", "equals": "custom"}, "show": ["custom_name"]},
    {"when": {"field": "confirm", "checked": true}, "enable": ["submit"]}
  ]
}
```

Conditions: `equals`, `notEquals`, `in`, `notIn`, `checked`, `unchecked`, `empty`, `notEmpty`, `matches`.

### Multi-Panel Layouts

Use `layout` + `panels` for side-by-side content:

```json
{
  "layout": {"type": "sidebar", "sidebarWidth": "280px"},
  "panels": {
    "sidebar": {"sections": [{"type": "items", "items": [...]}]},
    "main": {"sections": [{"type": "text", "content": "..."}]}
  }
}
```

Layout types: `sidebar` (main + nav), `split` (equal columns). Both collapse to single-column on mobile.

## Custom Apps

When the dynamic renderer isn't enough — complex visualizations, custom layouts, domain-specific interactions — you can build a custom app:

```bash
bash scripts/init_webview_app.sh my-dashboard
```

This scaffolds `index.html`, `app.js`, and `style.css` with the SDK already wired up. The client SDK is vanilla JavaScript with zero dependencies:

```javascript
const wv = new OpenWebGoggles();
await wv.connect();

// Listen for state updates from the agent
wv.onStateUpdate((state) => {
  // Render however you want
});

// Send structured responses back
await wv.approve("action-id", { comment: "Looks good" });
await wv.reject("action-id");
await wv.submitInput("field-id", "user input");
await wv.sendAction("custom-id", "custom", { any: "data" });
```

Two working examples are included in `examples/`:

- **approval-review** — Code review UI with unified diffs, per-file toggles, approve/reject with comments
- **item-triage** — Step-by-step item review with editable fields, priority dropdowns, and a progress bar. Works for dependency updates, config reviews, PR triage — any list of items needing individual decisions

These aren't toy demos. They're functional interfaces that handle real workflows. Start by reading their source if you're building something custom.

## Patterns That Work Well

**Single approval.** Agent shows a summary, human clicks approve or reject. The simplest case, and probably the most common.

**Pre-commit change review.** This is the killer use case. Your agent finishes a round of changes — refactoring, feature work, security hardening — and before it commits, it opens a review UI that summarizes *what changed and why*, grouped by category. You see the diffs, the rationale, and approve or ask questions right in the browser. Think of it as a pre-commit checklist where the agent is the one presenting and you're the one signing off. Way faster than scrolling through a terminal dump of `git diff`, and you get structured feedback back to the agent if something needs to change.

**Multi-step wizard.** For N items that need review, show one at a time. The agent calls `webview` in a loop, advancing to the next item after each response. This avoids overwhelming the user with a wall of decisions.

**Live dashboard.** Agent calls `webview` to display initial state, then uses `webview_update(merge=True)` to stream progress, logs, and status changes in real time. The human sees a live-updating UI and can act when ready. Pair with `progress` and `log` sections for build pipelines, test runs, or deployment workflows.

**Batch triage.** Show all items at once with per-item actions — tabs, cards, or a list with inline controls. Works well when the total count is under 10 or so.

## Security

The trust model is straightforward: the agent and the browser are on the same machine, and nobody else should be able to read or tamper with the communication between them.

Nine defense layers enforce this, all enabled by default:

- **Localhost-only binding** — the server only listens on 127.0.0.1
- **Bearer token auth** — 32-byte session token, constant-time comparison
- **WebSocket first-message auth** — token verified before any data flows
- **Ed25519 signatures** — server signs every state update (cryptographic proof of origin)
- **HMAC-SHA256** — browser signs every action (tamper detection)
- **Nonce replay prevention** — each action can only be submitted once
- **Content Security Policy** — per-request nonce blocks inline script injection
- **SecurityGate** — 22 XSS patterns, zero-width character detection, schema validation
- **Rate limiting** — 30 actions per minute per session

All cryptographic keys are ephemeral — generated in memory at session start, zeroed on shutdown, never written to disk in plaintext. The test suite covers OWASP Top 10, MITRE ATT&CK techniques, and LLM-specific attack vectors across 1025+ tests.

The tradeoff is real, though. This level of defense adds complexity to the codebase. If you're running in a fully trusted local environment and want to understand what each layer does, the [security tests](scripts/tests/) are the best documentation.

## Development

```bash
# Run the full test suite
python -m pytest -v

# Lint
ruff check scripts/
```

Python 3.11+ required. Core dependencies: `websockets`, `PyNaCl`, `mcp`.

## Reference Documentation

For the full details:

- [Data Contract](references/data-contract.md) — JSON file formats, state lifecycle, status values
- [SDK API](references/sdk-api.md) — Complete client SDK reference
- [Integration Guide](references/integration-guide.md) — Step-by-step patterns for connecting from other tools
- [Restart & Lifecycle Guide](references/restart-guide.md) — Automatic recovery, manual restart, diagnostics

## License

Apache License 2.0 — see [LICENSE](LICENSE).

---

Built by [Techtoboggan](https://techtoboggan.com).
