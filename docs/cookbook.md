# OpenWebGoggles Cookbook

Copy-paste recipes for common human-in-the-loop patterns. Each recipe shows both the **SDK helper** (recommended) and the **raw state dict** approach.

## Quick Start

```python
from scripts.sdk import confirm, show_form, show_table, show_progress, show_log
from scripts.sdk import show_dashboard, show_diff, show_chart
from scripts.sdk import Field, Action, unwrap_action, was_confirmed, get_form_values
```

---

## 1. Ask for Confirmation

The most common pattern — block until the user approves or cancels.

```python
# SDK helper
state = confirm(
    "Deploy to production?",
    "This will deploy v2.3.1 to all 12 servers.",
    details="**Changes:**\n- Fix auth timeout\n- Update rate limits\n- New health endpoint",
)
result = openwebgoggles(state)

if was_confirmed(result):
    deploy()
else:
    print("Deployment cancelled")
```

<details>
<summary>Raw state dict</summary>

```python
result = openwebgoggles({
    "title": "Deploy to production?",
    "message": "This will deploy v2.3.1 to all 12 servers.",
    "status": "pending_review",
    "data": {"sections": [
        {"type": "text", "content": "**Changes:**\n- Fix auth timeout", "format": "markdown"}
    ]},
    "actions_requested": [
        {"id": "confirm", "label": "Confirm", "type": "approve"},
        {"id": "cancel", "label": "Cancel", "type": "reject"},
    ]
})
```
</details>

---

## 2. Collect Form Input

Present a form and get structured values back.

```python
state = show_form("New User", [
    Field("name", "Full Name", required=True),
    Field("email", "Email", "email", required=True),
    Field("role", "Role", "select", options=["Admin", "Editor", "Viewer"]),
    Field("notes", "Notes", "textarea", placeholder="Optional context..."),
], message="Fill in the details for the new team member.")

result = openwebgoggles(state)
values = get_form_values(result)
print(f"Creating user: {values['name']} ({values['email']})")
```

---

## 3. Display a Data Table

Show tabular data with optional action buttons.

```python
state = show_table(
    "Open Pull Requests",
    columns=["PR", "Author", "Status", "Files"],
    rows=[
        {"PR": "#42 Fix auth", "Author": "alice", "Status": "Ready", "Files": "3"},
        {"PR": "#43 Add dark mode", "Author": "bob", "Status": "Draft", "Files": "8"},
        {"PR": "#44 Bump deps", "Author": "dependabot", "Status": "Ready", "Files": "1"},
    ],
    actions=[
        Action("merge_all", "Merge Ready", "approve"),
        Action("skip", "Skip", "ghost"),
    ],
)
result = openwebgoggles(state)
action_id, _ = unwrap_action(result)
```

---

## 4. Show Progress

Track multi-step operations with a progress bar.

```python
# Initial state
state = show_progress("Building Project", [
    {"label": "Install dependencies", "status": "complete"},
    {"label": "Compile TypeScript", "status": "running"},
    {"label": "Run tests", "status": "pending"},
    {"label": "Bundle assets", "status": "pending"},
], percentage=35)

openwebgoggles(state)

# Update progress as work completes
openwebgoggles_update(show_progress("Building Project", [
    {"label": "Install dependencies", "status": "complete"},
    {"label": "Compile TypeScript", "status": "complete"},
    {"label": "Run tests", "status": "running"},
    {"label": "Bundle assets", "status": "pending"},
], percentage=65))
```

---

## 5. Stream Log Output

Display live-updating log output.

```python
state = show_log("Build Output", [
    "$ npm install",
    "\033[32m✓\033[0m 847 packages installed",
    "$ npm run build",
    "Compiling 42 files...",
])
openwebgoggles(state)

# Append new lines via update
openwebgoggles_update({
    "data": {"sections": [{"type": "log", "lines": [
        "$ npm install",
        "\033[32m✓\033[0m 847 packages installed",
        "$ npm run build",
        "Compiling 42 files...",
        "\033[32m✓\033[0m Build complete (2.3s)",
    ]}]}
}, merge=True)
```

---

## 6. Metric Dashboard

Show key metrics with trends and sparklines.

```python
state = show_dashboard("API Health", [
    {"label": "Requests/s", "value": "1,234", "delta": "+12%", "trend": "up"},
    {"label": "Error Rate", "value": "0.3%", "delta": "-0.1%", "trend": "down"},
    {"label": "P99 Latency", "value": "142ms", "delta": "+8ms", "trend": "up"},
    {"label": "Uptime", "value": "99.97%"},
], columns=4)
openwebgoggles(state)
```

---

## 7. Code Review with Diff

Show a diff and collect approval.

```python
diff_content = """--- a/auth.py
+++ b/auth.py
@@ -42,7 +42,7 @@
 def verify_token(token: str) -> bool:
-    return token == SECRET
+    return hmac.compare_digest(token, SECRET)
"""

state = show_diff("Review: Fix timing attack", diff_content,
    message="Replaces `==` with constant-time comparison.",
    actions=[
        Action("approve", "Approve", "approve"),
        Action("request_changes", "Request Changes", "reject"),
    ],
)
result = openwebgoggles(state)
```

---

## 8. Charts

Render data visualizations.

```python
state = show_chart("Monthly Revenue", "line",
    labels=["Jan", "Feb", "Mar", "Apr", "May", "Jun"],
    datasets=[
        {"label": "2025", "data": [100, 120, 115, 140, 155, 170]},
        {"label": "2024", "data": [80, 95, 90, 105, 110, 125]},
    ],
)
openwebgoggles(state)
```

---

## 9. Light Mode

Any state can use the light theme.

```python
state = confirm("Review complete", theme="light")

# Or use system preference
state = show_table("Results", ["Name", "Score"], rows, theme="system")
```

---

## 10. Multi-Page SPA

Build tabbed interfaces for complex workflows.

```python
result = openwebgoggles({
    "title": "Project Setup",
    "pages": {
        "config": {
            "label": "Configuration",
            "data": {"sections": [
                {"type": "form", "fields": [
                    {"key": "name", "label": "Project Name", "type": "text", "required": True},
                    {"key": "lang", "label": "Language", "type": "select",
                     "options": ["Python", "TypeScript", "Go"]},
                ]}
            ]},
        },
        "review": {
            "label": "Review",
            "data": {"sections": [
                {"type": "text", "content": "Review your settings before creating.", "format": "markdown"}
            ]},
            "actions_requested": [
                {"id": "create", "label": "Create Project", "type": "approve"},
            ],
        },
    },
})
```

---

## 11. Delta Streaming (Append Mode)

Stream new data incrementally without replacing the entire state. Ideal for logs, table rows, and real-time feeds.

```python
# Initial state with a log section
openwebgoggles({
    "title": "Build Output",
    "data": {"sections": [
        {"type": "log", "title": "Output", "lines": ["$ npm install"]}
    ]}
})

# Append new lines — only the new data is sent over WebSocket
openwebgoggles_update({
    "data": {"sections": [{"lines": [
        "\033[32m✓\033[0m 847 packages installed",
        "$ npm run build",
    ]}]}
}, append=True)

# Append more lines later
openwebgoggles_update({
    "data": {"sections": [{"lines": [
        "\033[32m✓\033[0m Build complete (2.3s)",
    ]}]}
}, append=True)
```

Unlike `merge=True` which replaces lists, `append=True` **adds to** existing lists. The browser receives a compact patch (`{"op": "append", "path": "data.sections.0.lines", "value": [...]}`) and updates incrementally.

---

## 12. Multi-Session (Side-by-Side Panels)

Run multiple concurrent UI panels. Each named session gets its own browser tab.

```python
# Open a build dashboard in one tab
openwebgoggles({
    "title": "Build Pipeline",
    "data": {"sections": [
        {"type": "progress", "tasks": [...], "percentage": 0}
    ]}
}, session_name="build")

# Open a test results panel in another tab
openwebgoggles({
    "title": "Test Results",
    "data": {"sections": [
        {"type": "table", "columns": [...], "rows": [...]}
    ]}
}, session_name="tests")

# Update each independently
openwebgoggles_update({"percentage": 50}, merge=True, session_name="build")
openwebgoggles_update({"data": {"sections": [{"rows": [new_row]}]}}, append=True, session_name="tests")

# Close one without affecting the other
openwebgoggles_close(session_name="build")
```

---

## 13. Save & Restore Sessions

Persist session state across restarts. Useful for long-running workflows.

```python
# Save current session state
openwebgoggles_save(name="deployment-review")

# ... restart, crash, or come back later ...

# Restore the saved session (re-opens browser tab with previous state)
openwebgoggles_restore(name="deployment-review")
```

---

## 14. Tree / Hierarchy View

Show hierarchical data with expand/collapse.

```python
openwebgoggles({
    "title": "Project Structure",
    "data": {"sections": [{
        "type": "tree",
        "title": "Changed Files",
        "nodes": [
            {"label": "src/", "children": [
                {"label": "auth.py", "badge": "modified"},
                {"label": "utils.py", "badge": "added"},
                {"label": "api/", "children": [
                    {"label": "routes.py", "badge": "modified"},
                ]}
            ]},
            {"label": "tests/", "children": [
                {"label": "test_auth.py", "badge": "added"},
            ]}
        ],
        "expandAll": False,
    }]}
})
```

---

## 15. Timeline / Gantt View

Visualize time-based data.

```python
openwebgoggles({
    "title": "Sprint Plan",
    "data": {"sections": [{
        "type": "timeline",
        "title": "Q1 Milestones",
        "items": [
            {"label": "Auth Refactor", "start": "2026-03-01", "end": "2026-03-10", "color": "blue"},
            {"label": "API v2", "start": "2026-03-05", "end": "2026-03-20", "color": "green"},
            {"label": "Load Testing", "start": "2026-03-15", "end": "2026-03-25", "color": "orange"},
        ]
    }]}
})
```

---

## 16. Heatmap

Show matrix data with color-coded cells.

```python
openwebgoggles({
    "title": "Error Rate by Hour/Day",
    "data": {"sections": [{
        "type": "heatmap",
        "xLabels": ["Mon", "Tue", "Wed", "Thu", "Fri"],
        "yLabels": ["00:00", "06:00", "12:00", "18:00"],
        "values": [
            [0.1, 0.2, 0.3, 0.1, 0.05],
            [0.05, 0.1, 0.15, 0.1, 0.05],
            [0.3, 0.5, 0.8, 0.4, 0.2],
            [0.2, 0.3, 0.4, 0.3, 0.15],
        ],
        "colorScale": ["#eaffea", "#ff4444"],
    }]}
})
```

---

## 17. Network Diagram

Visualize relationships between services or components.

```python
openwebgoggles({
    "title": "Service Dependencies",
    "data": {"sections": [{
        "type": "network",
        "nodes": [
            {"id": "api", "label": "API Gateway"},
            {"id": "auth", "label": "Auth Service"},
            {"id": "db", "label": "PostgreSQL"},
            {"id": "cache", "label": "Redis"},
        ],
        "edges": [
            {"from": "api", "to": "auth", "label": "validates"},
            {"from": "api", "to": "cache", "label": "reads"},
            {"from": "auth", "to": "db", "label": "queries"},
            {"from": "cache", "to": "db", "label": "populates"},
        ]
    }]}
})
```

---

## Result Helpers

```python
from scripts.sdk import unwrap_action, was_confirmed, get_form_values

# Check if confirmed
if was_confirmed(result):
    print("User approved")

# Get the action ID and value
action_id, value = unwrap_action(result)

# Extract form values as a dict
values = get_form_values(result)
```

---

## CI Approval Gate (GitHub Actions)

Use OpenWebGoggles as a human approval step in your deployment pipeline.

### Reusable Workflow

```yaml
# .github/workflows/deploy.yml
jobs:
  approve:
    uses: techtoboggan/openwebgoggles/.github/workflows/approval-gate.yml@main
    with:
      title: "Deploy v2.3.1 to production"
      message: "Release includes auth fix and health endpoint."
      details: |
        ### Changes
        - Fix: token refresh race condition
        - Feat: /health endpoint
      confirm-label: "Deploy"
      cancel-label: "Abort"
    secrets:
      webhook-url: ${{ secrets.OWG_WEBHOOK_URL }}

  deploy:
    needs: approve
    runs-on: ubuntu-latest
    steps:
      - run: echo "Deploying..."
```

### Webhook Notifications

Set `OWG_WEBHOOK_URL` as a repository secret to get Slack/Discord notifications when approval is pending:

- **Slack**: `https://hooks.slack.com/services/T00/B00/xxx`
- **Discord**: `https://discord.com/api/webhooks/123/abc`
- **Generic**: Any HTTPS endpoint accepting JSON POST

See [`examples/ci-approval-gate.yml`](../examples/ci-approval-gate.yml) for a complete example.
