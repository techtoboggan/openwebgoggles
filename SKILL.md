---
name: opencode-webview
description: >
  Runtime framework for launching interactive browser-based webview UIs that communicate
  bidirectionally with the CLI agent via structured JSON data contracts. Use when:
  (1) The agent needs human-in-the-loop approval or review of proposed changes,
  (2) Displaying rich interactive dashboards, visualizations, or architecture diagrams,
  (3) Collecting structured user input via forms, wizards, or configuration panels,
  (4) Any task requiring a browser-based UI that exchanges data with the CLI agent.
  Provides a local HTTP+WebSocket server, file-based JSON data contract in the CWD,
  a client-side SDK, and bash helper scripts for agent integration.
---

# OpenCode Webview

Launch browser-based interactive UIs from OpenCode skills with bidirectional agent communication.

## Quick Start

### 1. Start the webview server with a built-in or custom app

```bash
bash scripts/start_webview.sh --app approval-review
```

This creates `.opencode/webview/` in the CWD, starts the server, and opens the browser.

### 2. Write state for the webview to render

```bash
bash scripts/write_state.sh '{"version":1,"status":"pending_review","updated_at":"2026-02-19T10:00:00Z","title":"Review Changes","data":{"files":[{"path":"src/main.py","summary":"Added error handling"}]},"actions_requested":[{"id":"approve","type":"approve","label":"Approve"},{"id":"reject","type":"reject","label":"Reject"}]}'
```

### 3. Wait for the user's decision

```bash
ACTIONS=$(bash scripts/wait_for_action.sh --timeout 300)
echo "$ACTIONS"  # JSON with user's approve/reject/input responses
```

### 4. Stop the webview when done

```bash
bash scripts/stop_webview.sh
```

## Architecture

```
Agent (bash) ←→ .opencode/webview/*.json ←→ Server (Python) ←→ Browser (SDK + App)
```

- **Files are the source of truth**: `state.json` (agent→webview), `actions.json` (webview→agent), `manifest.json` (session metadata)
- **Server**: HTTP for static files + REST API, WebSocket for real-time push
- **SDK**: Vanilla JS client library that handles WS connection, state caching, HTTP fallback
- **Shell scripts**: Agent-side helpers for reading/writing the data contract

## Data Contract

All files live in `.opencode/webview/` within the current working directory.

| File | Direction | Purpose |
|------|-----------|---------|
| `manifest.json` | Bidirectional | Session config: which app, ports, session token |
| `state.json` | Agent → Webview | Current state, data payload, requested actions |
| `actions.json` | Webview → Agent | User decisions and input responses |

### State Status Values

- `initializing` — Server starting up
- `ready` — Webview loaded, waiting for agent to send data
- `pending_review` — Agent has data for user to review
- `waiting_input` — Agent needs user input to continue
- `processing` — Agent is working on user's response
- `completed` — Workflow finished
- `error` — Something went wrong

## Scripts Reference

| Script | Usage |
|--------|-------|
| `start_webview.sh --app <name> [--port <N>] [--no-browser]` | Start server and open browser |
| `stop_webview.sh` | Graceful shutdown via PID file |
| `write_state.sh '<json>'` or `write_state.sh --file <path>` | Atomic write to state.json |
| `read_actions.sh [--clear]` | Read actions.json, optionally clear after reading |
| `wait_for_action.sh [--timeout <secs>] [--action-type <type>]` | Block until user acts |
| `init_webview_app.sh <name> [--dest <dir>]` | Scaffold a new webview app from template |

## Built-in `dynamic` App — No Custom Code Needed

**Use `--app dynamic` for any HITL UI.** Write a UI schema into `state.json` and the dynamic renderer builds the interface automatically. No HTML/JS required.

```bash
bash scripts/start_webview.sh --app dynamic
bash scripts/write_state.sh "$(cat <<'EOF'
{
  "version": 1,
  "status": "waiting_input",
  "title": "Deploy Configuration",
  "message": "Review and confirm the deployment settings.",
  "data": {
    "ui": {
      "sections": [
        {
          "type": "form",
          "title": "Settings",
          "columns": 2,
          "fields": [
            { "key": "environment", "label": "Environment", "type": "select",
              "options": ["staging", "production"], "value": "staging" },
            { "key": "replicas", "label": "Replicas", "type": "number",
              "value": 2, "min": 1, "max": 10 },
            { "key": "tag", "label": "Docker Tag", "type": "text",
              "value": "v1.4.2", "placeholder": "e.g. v1.2.3" },
            { "key": "notes", "label": "Release Notes", "type": "textarea",
              "placeholder": "Optional notes..." }
          ],
          "actions": [
            { "id": "deploy", "type": "submit", "label": "Deploy", "style": "success" },
            { "id": "cancel", "type": "reject", "label": "Cancel" }
          ]
        }
      ]
    }
  },
  "actions_requested": []
}
EOF
)"
RESULT=$(bash scripts/wait_for_action.sh --timeout 120)
# $RESULT contains { action_id, type, value: { environment, replicas, tag, notes } }
```

### Dynamic UI Schema Reference

**Section types:**

| type | Purpose |
|------|---------|
| `form` | Input fields with submit actions. Collected values sent as action value. |
| `items` | List of items, each with per-item action buttons (e.g. approve/reject each). |
| `text` | Static message/info block. |
| `actions` | Standalone action buttons only. |

**Field types:** `text`, `textarea`, `number`, `select`, `checkbox`, `email`, `url`, `static`

**Field properties:**
- `key` — identifier returned in action value
- `label` — display label
- `type` — input type
- `value` / `default` — initial value
- `placeholder` — hint text
- `options` — for select: array of strings or `[{value, label}]` objects
- `description` — helper text shown below field
- `rows` — for textarea height
- `mono` — for static fields: monospace font

**Action button styles:** `primary`, `success`, `danger`, `warning`, `ghost`
(also accepts semantic types: `approve`, `reject`, `confirm`, `submit`, `delete`)

**Items section example:**
```json
{
  "type": "items",
  "title": "Pending PRs",
  "items": [
    { "id": "pr-42", "title": "Fix auth bug", "subtitle": "#42 · main ← feat/auth",
      "actions": [
        { "id": "merge", "type": "approve", "label": "Merge", "style": "success" },
        { "id": "close", "type": "reject",  "label": "Close", "style": "danger" }
      ]
    }
  ]
}
```

## Creating Custom Webview Apps

1. Scaffold: `bash scripts/init_webview_app.sh my-dashboard`
2. Edit `index.html`, `app.js`, `style.css` in the generated directory
3. Use the SDK in your app:

```html
<script src="/sdk/opencode-webview-sdk.js"></script>
<script>
  const wv = new OpenCodeWebview();
  wv.connect().then(() => {
    wv.onStateUpdate((state) => {
      // Render your UI based on state.data
      // Show actions from state.actions_requested
    });
  });

  function handleApprove() {
    wv.approve('approve-all', { comment: 'Looks good' });
  }
</script>
```

4. Launch with: `bash scripts/start_webview.sh --app my-dashboard`

## Integration from Other Skills

See `references/integration-guide.md` for detailed patterns. The basic flow:

1. Start the webview with your app
2. Write state with your data payload and requested actions
3. Wait for user response (blocking or polling)
4. Parse the actions JSON and continue your workflow
5. Stop the webview when done

## SDK API Reference

See `references/sdk-api.md` for the full client SDK API.
