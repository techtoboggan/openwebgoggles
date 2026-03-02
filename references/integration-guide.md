# Integration Guide

How to integrate OpenWebGoggles into your agent or workflow.

## Installation

```bash
pipx install openwebgoggles
```

> **Don't have pipx?** `brew install pipx && pipx ensurepath` (macOS) or `pip install --user pipx && pipx ensurepath` (Linux). Or use plain `pip install openwebgoggles` if you prefer.

Then bootstrap for your editor:

```bash
openwebgoggles init claude      # Claude Code — project-level (.mcp.json in cwd)
openwebgoggles init opencode    # OpenCode — global (~/.config/opencode/opencode.json)
```

The init command resolves the absolute path to the binary and embeds it in the editor config, so editors don't depend on PATH. For OpenCode, the default is the global config so the tools are available in every project.

## MCP Tools (Claude Code / OpenCode)

Once installed, your agent gets four MCP tools:

| Tool | What it does |
|------|-------------|
| `webview_ask(state)` | Show a UI and block until the human responds |
| `webview_show(state)` | Show a UI without blocking (dashboards, progress) |
| `webview_read()` | Poll for actions without blocking |
| `webview_close()` | Close the session |

The agent just calls these tools with a JSON state object. No HTML, no frontend code. See the [Data Contract](data-contract.md) for the full state schema.

## Bash Scripts (Shell-based Agents)

If your agent orchestrates via shell scripts, the bash interface exposes the same capabilities. The scripts live in the installed package:

```bash
SCRIPTS_DIR="$(python3 -c 'import scripts; import pathlib; print(pathlib.Path(scripts.__file__).parent)')"

# 1. Start webview with the approval-review app
bash "$SCRIPTS_DIR/start_webview.sh" --app approval-review

# 2. Write state for the user to review
bash "$SCRIPTS_DIR/write_state.sh" '{
  "version": 1,
  "status": "pending_review",
  "updated_at": "2026-02-19T10:00:00Z",
  "title": "Review Proposed Changes",
  "message": "Please review the following changes and approve or reject.",
  "data": {
    "files_changed": [
      {
        "path": "src/main.py",
        "diff": "--- a/src/main.py\n+++ b/src/main.py\n@@ -10,3 +10,5 @@\n+def new_helper():\n+    return True",
        "summary": "Added new_helper function"
      }
    ],
    "total_lines_added": 2,
    "total_lines_removed": 0
  },
  "actions_requested": [
    {"id": "approve", "type": "approve", "label": "Approve All"},
    {"id": "reject", "type": "reject", "label": "Reject All"},
    {"id": "feedback", "type": "input", "label": "Feedback", "required": false}
  ]
}'

# 3. Wait for user decision (blocks up to 5 minutes)
ACTIONS=$(bash "$SCRIPTS_DIR/wait_for_action.sh" --timeout 300 --clear)

# 4. Parse the response
echo "$ACTIONS" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for action in data['actions']:
    print(f'{action[\"type\"]}: {action[\"value\"]}')
"

# 5. Stop webview
bash "$SCRIPTS_DIR/stop_webview.sh"
```

## Multi-Step Workflows

Update state repeatedly for multi-step interactions:

```bash
# Step 1: Show configuration options
bash "$SCRIPTS_DIR/write_state.sh" '{
  "version": 1,
  "status": "waiting_input",
  "title": "Configure Settings",
  "data": {"current_config": {"debug": false, "log_level": "info"}},
  "actions_requested": [
    {"id": "log-level", "type": "select", "label": "Log Level",
     "options": [{"value": "debug"}, {"value": "info"}, {"value": "warn"}]},
    {"id": "save", "type": "confirm", "label": "Save Configuration"}
  ]
}'

# Wait for step 1
ACTIONS=$(bash "$SCRIPTS_DIR/wait_for_action.sh" --clear)

# Step 2: Show confirmation
bash "$SCRIPTS_DIR/write_state.sh" '{
  "version": 2,
  "status": "pending_review",
  "title": "Confirm Changes",
  "message": "The following settings will be applied:",
  "data": {"new_config": {"debug": false, "log_level": "debug"}},
  "actions_requested": [
    {"id": "confirm", "type": "confirm", "label": "Apply"},
    {"id": "cancel", "type": "reject", "label": "Cancel"}
  ]
}'

# Wait for step 2
ACTIONS=$(bash "$SCRIPTS_DIR/wait_for_action.sh" --clear)
```

## Custom Webview Apps

### 1. Scaffold

```bash
bash "$SCRIPTS_DIR/init_webview_app.sh" my-dashboard
```

### 2. Develop

Edit `index.html`, `app.js`, `style.css`. The SDK is included automatically.

### 3. Launch

```bash
bash "$SCRIPTS_DIR/start_webview.sh" --app ./my-dashboard
```

## Non-Blocking Pattern

Instead of `wait_for_action.sh`, poll periodically:

```bash
# Start webview and write state...

# Check every 5 seconds without blocking
while true; do
    COUNT=$(bash "$SCRIPTS_DIR/read_actions.sh" --count)
    if [[ "$COUNT" -gt 0 ]]; then
        ACTIONS=$(bash "$SCRIPTS_DIR/read_actions.sh" --clear)
        break
    fi
    # Do other work while waiting...
    sleep 5
done
```

## Data Payload Conventions

The `data` field in state.json is freeform, but the built-in apps expect these shapes:

### approval-review app

```json
{
  "files_changed": [
    {"path": "string", "diff": "unified diff string", "summary": "string"}
  ],
  "total_files": 3,
  "total_lines_added": 42,
  "total_lines_removed": 7
}
```

### Custom apps

Define your own `data` shape. Document it in your project's references.

## Dynamic Renderer Examples

The dynamic renderer (`assets/apps/dynamic/`) interprets JSON state directly — no custom HTML needed. Below are three examples demonstrating dashboard features.

### 1. Metric Cards with Sparklines

```json
{
  "title": "Application Metrics",
  "data": {
    "sections": [
      {
        "type": "metric",
        "title": "Key Performance Indicators",
        "columns": 3,
        "cards": [
          {
            "label": "Response Time",
            "value": "142",
            "unit": "ms",
            "change": "-18ms",
            "changeDirection": "down",
            "sparkline": [180, 165, 158, 150, 145, 142]
          },
          {
            "label": "Throughput",
            "value": "3,420",
            "unit": "req/s",
            "change": "+12%",
            "changeDirection": "up",
            "sparkline": [2800, 2950, 3100, 3250, 3350, 3420]
          },
          {
            "label": "Error Rate",
            "value": "0.2%",
            "change": "-0.1%",
            "changeDirection": "down"
          }
        ]
      }
    ]
  }
}
```

Metric cards support sparklines (inline SVG charts), change indicators, and units. The `columns` property (1-6) controls the grid layout.

### 2. Multi-Page SPA with Hidden Detail Pages

```json
{
  "title": "Project Dashboard",
  "showNav": false,
  "pages": {
    "home": {
      "label": "Home",
      "data": {
        "sections": [
          {
            "type": "items",
            "title": "Projects",
            "items": [
              {"title": "Auth Service", "subtitle": "3 issues", "navigateTo": "auth-detail"},
              {"title": "API Gateway", "subtitle": "1 issue", "navigateTo": "api-detail"}
            ]
          }
        ]
      }
    },
    "auth-detail": {
      "label": "Auth Service",
      "hidden": true,
      "data": {
        "sections": [
          {"type": "text", "title": "Auth Service", "content": "Detailed view..."},
          {"type": "table", "title": "Issues", "columns": [{"key": "id", "label": "ID"}, {"key": "title", "label": "Title"}], "rows": [{"id": "AUTH-1", "title": "Token expiry too short"}]}
        ]
      },
      "actions_requested": [
        {"id": "back", "label": "Back to Projects", "type": "ghost", "navigateTo": "home"}
      ]
    },
    "api-detail": {
      "label": "API Gateway",
      "hidden": true,
      "data": {
        "sections": [
          {"type": "text", "title": "API Gateway", "content": "Detailed view..."}
        ]
      },
      "actions_requested": [
        {"id": "back", "label": "Back to Projects", "type": "ghost", "navigateTo": "home"}
      ]
    }
  },
  "activePage": "home"
}
```

Setting `showNav: false` hides the tab bar. Hidden pages are excluded from nav but remain reachable via `navigateTo` on items and actions. Navigation is instant (client-side, no server round-trip).

### 3. Clickable Table with NavigateTo Drill-Down

```json
{
  "title": "Server Fleet",
  "pages": {
    "overview": {
      "label": "Overview",
      "data": {
        "sections": [
          {
            "type": "table",
            "title": "Servers",
            "clickable": true,
            "navigateToField": "detail_page",
            "columns": [
              {"key": "name", "label": "Server"},
              {"key": "status", "label": "Status"},
              {"key": "cpu", "label": "CPU"}
            ],
            "rows": [
              {"name": "web-01", "status": "healthy", "cpu": "34%", "detail_page": "web01"},
              {"name": "web-02", "status": "warning", "cpu": "89%", "detail_page": "web02"}
            ]
          }
        ]
      }
    },
    "web01": {
      "label": "web-01",
      "hidden": true,
      "data": {
        "sections": [
          {"type": "metric", "cards": [{"label": "CPU", "value": "34%"}, {"label": "Memory", "value": "2.1 GB"}]}
        ]
      },
      "actions_requested": [
        {"id": "back", "label": "Back", "type": "ghost", "navigateTo": "overview"}
      ]
    },
    "web02": {
      "label": "web-02",
      "hidden": true,
      "data": {
        "sections": [
          {"type": "metric", "cards": [{"label": "CPU", "value": "89%"}, {"label": "Memory", "value": "5.8 GB"}]}
        ]
      },
      "actions_requested": [
        {"id": "back", "label": "Back", "type": "ghost", "navigateTo": "overview"}
      ]
    }
  },
  "activePage": "overview"
}
```

Setting `navigateToField` on a clickable table makes row clicks navigate to the page specified in that field -- no action is emitted to the agent. Combine with hidden pages for master-detail drill-down patterns.
