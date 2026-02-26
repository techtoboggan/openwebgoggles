# Integration Guide

How to integrate OpenWebGoggles into your agent or workflow.

## Installation

```bash
pipx install openwebgoggles
```

> **Don't have pipx?** `brew install pipx && pipx ensurepath` (macOS) or `pip install --user pipx && pipx ensurepath` (Linux). Or use plain `pip install openwebgoggles` if you prefer.

Then bootstrap for your editor:

```bash
openwebgoggles init claude      # Claude Code
openwebgoggles init opencode    # OpenCode
```

The init command resolves the absolute path to the binary and embeds it in the editor config, so editors don't depend on PATH.

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
