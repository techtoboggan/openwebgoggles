# Integration Guide

How to use opencode-webview from other OpenCode skills.

## Basic HITL Pattern

```bash
SKILL_DIR="$HOME/.config/opencode/skills/opencode-webview"

# 1. Start webview with the approval-review app
bash "$SKILL_DIR/scripts/start_webview.sh" --app approval-review

# 2. Write state for the user to review
bash "$SKILL_DIR/scripts/write_state.sh" '{
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
ACTIONS=$(bash "$SKILL_DIR/scripts/wait_for_action.sh" --timeout 300 --clear)

# 4. Parse the response
echo "$ACTIONS" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for action in data['actions']:
    print(f'{action[\"type\"]}: {action[\"value\"]}')
"

# 5. Stop webview
bash "$SKILL_DIR/scripts/stop_webview.sh"
```

## Multi-Step Workflows

Update state repeatedly for multi-step interactions:

```bash
# Step 1: Show configuration options
bash "$SKILL_DIR/scripts/write_state.sh" '{
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
ACTIONS=$(bash "$SKILL_DIR/scripts/wait_for_action.sh" --clear)

# Step 2: Show confirmation
bash "$SKILL_DIR/scripts/write_state.sh" '{
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
ACTIONS=$(bash "$SKILL_DIR/scripts/wait_for_action.sh" --clear)
```

## Custom Webview Apps

### 1. Scaffold

```bash
bash "$SKILL_DIR/scripts/init_webview_app.sh" my-dashboard --dest ./my-skill/assets/my-dashboard
```

### 2. Develop

Edit `index.html`, `app.js`, `style.css`. The SDK is included automatically.

### 3. Launch from your skill

```bash
bash "$SKILL_DIR/scripts/start_webview.sh" --app ./my-skill/assets/my-dashboard
```

## Non-Blocking Pattern

Instead of `wait_for_action.sh`, poll periodically:

```bash
# Start webview and write state...

# Check every 5 seconds without blocking
while true; do
    COUNT=$(bash "$SKILL_DIR/scripts/read_actions.sh" --count)
    if [[ "$COUNT" -gt 0 ]]; then
        ACTIONS=$(bash "$SKILL_DIR/scripts/read_actions.sh" --clear)
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

Define your own `data` shape. Document it in your skill's references.
