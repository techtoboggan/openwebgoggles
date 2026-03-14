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
