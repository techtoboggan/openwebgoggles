"""
OpenWebGoggles Python SDK — high-level helpers for common HITL patterns.

Instead of constructing raw state dicts, use these helpers:

    from openwebgoggles.sdk import confirm, show_form, show_table, show_progress, show_log

Each function returns a state dict ready to pass to the ``openwebgoggles()`` MCP tool.
Use ``to_state()`` to get the dict, or pass directly to the tool.

These helpers are sugar — they produce the same state schemas that the raw tool
accepts, validated identically by SecurityGate.
"""

from __future__ import annotations

import json
from typing import Any

# ---------------------------------------------------------------------------
# Field builder
# ---------------------------------------------------------------------------


class Field:
    """Build a form field descriptor with validation.

    Examples::

        Field("name", "Full Name", "text", required=True)
        Field("role", "Role", "select", options=["Admin", "User"])
        Field("notes", "Notes", "textarea", placeholder="Optional...")
        Field("age", "Age", "number", min_value=0, max_value=150)
    """

    VALID_TYPES = frozenset(
        {
            "text",
            "textarea",
            "number",
            "select",
            "checkbox",
            "email",
            "url",
            "static",
            "slider",
            "date",
            "datetime",
            "autocomplete",
            "file",
        }
    )

    def __init__(
        self,
        key: str,
        label: str,
        field_type: str = "text",
        *,
        value: Any = None,
        default: Any = None,
        placeholder: str | None = None,
        description: str | None = None,
        options: list[str] | None = None,
        required: bool = False,
        pattern: str | None = None,
        min_length: int | None = None,
        max_length: int | None = None,
        min_value: int | float | None = None,
        max_value: int | float | None = None,
        error_message: str | None = None,
        format: str | None = None,  # noqa: A002
        class_name: str | None = None,
    ):
        if field_type not in self.VALID_TYPES:
            msg = f"Invalid field type: {field_type!r}. Valid types: {', '.join(sorted(self.VALID_TYPES))}"
            raise ValueError(msg)
        self._data: dict[str, Any] = {"key": key, "label": label, "type": field_type}
        if required:
            self._data["required"] = True
        # Map keyword args to their camelCase dict keys (None = omit)
        _optional: dict[str, tuple[str, Any]] = {
            "value": ("value", value),
            "default": ("default", default),
            "placeholder": ("placeholder", placeholder),
            "description": ("description", description),
            "options": ("options", options),
            "pattern": ("pattern", pattern),
            "min_length": ("minLength", min_length),
            "max_length": ("maxLength", max_length),
            "min_value": ("min", min_value),
            "max_value": ("max", max_value),
            "error_message": ("errorMessage", error_message),
            "format": ("format", format),
            "class_name": ("className", class_name),
        }
        for dict_key, val in _optional.values():
            if val is not None:
                self._data[dict_key] = val

    def to_dict(self) -> dict[str, Any]:
        """Return the field descriptor as a plain dict."""
        return dict(self._data)


# ---------------------------------------------------------------------------
# Action builder
# ---------------------------------------------------------------------------


class Action:
    """Build an action button descriptor.

    Examples::

        Action("approve", "Approve", "approve")
        Action("reject", "Reject", "reject")
        Action("submit", "Submit", "primary")
    """

    def __init__(
        self,
        action_id: str,
        label: str,
        action_type: str = "primary",
        *,
        navigate_to: str | None = None,
    ):
        self._data: dict[str, Any] = {"id": action_id, "label": label, "type": action_type}
        if navigate_to is not None:
            self._data["navigateTo"] = navigate_to

    def to_dict(self) -> dict[str, Any]:
        """Return the action descriptor as a plain dict."""
        return dict(self._data)


# ---------------------------------------------------------------------------
# Helper: normalize fields/actions from mixed input
# ---------------------------------------------------------------------------


def _normalize_fields(fields: list[Field | dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert a list of Field objects or dicts to plain dicts."""
    return [f.to_dict() if isinstance(f, Field) else f for f in fields]


def _normalize_actions(actions: list[Action | dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert a list of Action objects or dicts to plain dicts."""
    return [a.to_dict() if isinstance(a, Action) else a for a in actions]


# ---------------------------------------------------------------------------
# State builders
# ---------------------------------------------------------------------------


def confirm(
    title: str = "Confirm",
    message: str = "",
    *,
    details: str | None = None,
    confirm_label: str = "Confirm",
    cancel_label: str = "Cancel",
    theme: str | None = None,
) -> dict[str, Any]:
    """Build a confirmation dialog state.

    Returns a state dict with approve/cancel buttons and optional details.

    Example::

        state = confirm("Deploy to prod?", "This will deploy v2.3.1 to production.")
    """
    state: dict[str, Any] = {
        "title": title,
        "message": message,
        "status": "pending_review",
        "data": {"sections": []},
        "actions_requested": [
            {"id": "confirm", "label": confirm_label, "type": "approve"},
            {"id": "cancel", "label": cancel_label, "type": "reject"},
        ],
    }
    if details:
        state["data"]["sections"].append({"type": "text", "content": details, "format": "markdown"})
    if theme:
        state["theme"] = theme
    return state


def show_form(
    title: str = "Form",
    fields: list[Field | dict[str, Any]] | None = None,
    *,
    message: str | None = None,
    submit_label: str = "Submit",
    cancel_label: str | None = None,
    form_title: str | None = None,
    theme: str | None = None,
) -> dict[str, Any]:
    """Build a form input state.

    Example::

        state = show_form("User Info", [
            Field("name", "Name", required=True),
            Field("email", "Email", "email"),
            Field("role", "Role", "select", options=["Admin", "Editor", "Viewer"]),
        ])
    """
    normalized = _normalize_fields(fields or [])
    actions: list[dict[str, Any]] = [{"id": "submit", "label": submit_label, "type": "approve"}]
    if cancel_label:
        actions.append({"id": "cancel", "label": cancel_label, "type": "reject"})

    state: dict[str, Any] = {
        "title": title,
        "status": "waiting_input",
        "data": {"sections": [{"type": "form", "title": form_title or "", "fields": normalized}]},
        "actions_requested": actions,
    }
    if message:
        state["message"] = message
    if theme:
        state["theme"] = theme
    return state


def show_table(
    title: str = "Table",
    columns: list[dict[str, str]] | list[str] | None = None,
    rows: list[dict[str, Any]] | None = None,
    *,
    message: str | None = None,
    clickable: bool = False,
    click_action_id: str | None = None,
    actions: list[Action | dict[str, Any]] | None = None,
    theme: str | None = None,
) -> dict[str, Any]:
    """Build a table display state.

    Columns can be dicts ``{"key": "col_key", "label": "Col Label"}`` or
    plain strings (used as both key and label).

    Example::

        state = show_table("Users", ["Name", "Email", "Role"], [
            {"Name": "Alice", "Email": "alice@co.com", "Role": "Admin"},
            {"Name": "Bob", "Email": "bob@co.com", "Role": "Editor"},
        ])
    """
    # Normalize string columns to dicts
    normalized_cols = []
    for c in columns or []:
        if isinstance(c, str):
            normalized_cols.append({"key": c, "label": c})
        else:
            normalized_cols.append(c)

    section: dict[str, Any] = {"type": "table", "columns": normalized_cols, "rows": rows or []}
    if clickable:
        section["clickable"] = True
    if click_action_id:
        section["clickActionId"] = click_action_id

    state: dict[str, Any] = {
        "title": title,
        "status": "complete",
        "data": {"sections": [section]},
    }
    if message:
        state["message"] = message
    if actions:
        state["actions_requested"] = _normalize_actions(actions)
    if theme:
        state["theme"] = theme
    return state


def show_progress(
    title: str = "Progress",
    tasks: list[dict[str, str]] | None = None,
    *,
    percentage: int | float | None = None,
    message: str | None = None,
    theme: str | None = None,
) -> dict[str, Any]:
    """Build a progress tracker state.

    Example::

        state = show_progress("Building", [
            {"label": "Install deps", "status": "complete"},
            {"label": "Compile", "status": "running"},
            {"label": "Test", "status": "pending"},
        ], percentage=45)
    """
    section: dict[str, Any] = {"type": "progress", "title": "", "tasks": tasks or []}
    if percentage is not None:
        section["percentage"] = percentage

    state: dict[str, Any] = {
        "title": title,
        "status": "processing",
        "data": {"sections": [section]},
    }
    if message:
        state["message"] = message
    if theme:
        state["theme"] = theme
    return state


def show_log(
    title: str = "Log",
    lines: list[str] | None = None,
    *,
    max_lines: int = 500,
    message: str | None = None,
    theme: str | None = None,
) -> dict[str, Any]:
    """Build a log viewer state.

    Example::

        state = show_log("Build Output", [
            "Installing dependencies...",
            "\\033[32m✓\\033[0m All packages installed",
            "Running tests...",
        ])
    """
    state: dict[str, Any] = {
        "title": title,
        "status": "processing",
        "data": {
            "sections": [
                {
                    "type": "log",
                    "title": "",
                    "lines": lines or [],
                    "autoScroll": True,
                    "maxLines": max_lines,
                }
            ]
        },
    }
    if message:
        state["message"] = message
    if theme:
        state["theme"] = theme
    return state


def show_dashboard(
    title: str = "Dashboard",
    metrics: list[dict[str, Any]] | None = None,
    *,
    columns: int | None = None,
    message: str | None = None,
    theme: str | None = None,
) -> dict[str, Any]:
    """Build a metric dashboard state.

    Example::

        state = show_dashboard("API Health", [
            {"label": "Requests/s", "value": "1,234", "delta": "+12%", "trend": "up"},
            {"label": "Error Rate", "value": "0.3%", "delta": "-0.1%", "trend": "down"},
            {"label": "P99 Latency", "value": "142ms"},
        ])
    """
    cards = []
    for m in metrics or []:
        card: dict[str, Any] = {"label": m.get("label", ""), "value": m.get("value", "")}
        if "delta" in m:
            card["delta"] = m["delta"]
        if "trend" in m:
            card["trend"] = m["trend"]
        if "unit" in m:
            card["unit"] = m["unit"]
        if "sparkline" in m:
            card["sparkline"] = m["sparkline"]
        cards.append(card)

    cols = columns or min(len(cards), 4) or 4
    state: dict[str, Any] = {
        "title": title,
        "status": "complete",
        "data": {"sections": [{"type": "metric", "columns": cols, "cards": cards}]},
    }
    if message:
        state["message"] = message
    if theme:
        state["theme"] = theme
    return state


def show_diff(
    title: str = "Diff",
    content: str = "",
    *,
    message: str | None = None,
    actions: list[Action | dict[str, Any]] | None = None,
    theme: str | None = None,
) -> dict[str, Any]:
    """Build a diff viewer state.

    Example::

        state = show_diff("Changes", diff_string, actions=[
            Action("approve", "Approve", "approve"),
            Action("reject", "Reject", "reject"),
        ])
    """
    state: dict[str, Any] = {
        "title": title,
        "status": "pending_review",
        "data": {"sections": [{"type": "diff", "content": content}]},
    }
    if message:
        state["message"] = message
    if actions:
        state["actions_requested"] = _normalize_actions(actions)
    if theme:
        state["theme"] = theme
    return state


def show_chart(
    title: str = "Chart",
    chart_type: str = "bar",
    labels: list[str] | None = None,
    datasets: list[dict[str, Any]] | None = None,
    *,
    message: str | None = None,
    theme: str | None = None,
) -> dict[str, Any]:
    """Build a chart display state.

    Example::

        state = show_chart("Revenue", "line",
            labels=["Jan", "Feb", "Mar", "Apr"],
            datasets=[{"label": "2025", "data": [100, 120, 115, 140]}],
        )
    """
    state: dict[str, Any] = {
        "title": title,
        "status": "complete",
        "data": {
            "sections": [
                {
                    "type": "chart",
                    "chartType": chart_type,
                    "data": {"labels": labels or [], "datasets": datasets or []},
                }
            ]
        },
    }
    if message:
        state["message"] = message
    if theme:
        state["theme"] = theme
    return state


# ---------------------------------------------------------------------------
# Result unwrapping
# ---------------------------------------------------------------------------


def unwrap_action(result: dict[str, Any]) -> tuple[str, Any]:
    """Extract the action_id and value from an openwebgoggles() result.

    Returns:
        (action_id, value) — the first action's ID and its value.

    Raises:
        ValueError: if the result contains an error or no actions.

    Example::

        result = openwebgoggles(confirm("Deploy?"))
        action_id, value = unwrap_action(result)
        if action_id == "confirm":
            deploy()
    """
    if "error" in result:
        raise ValueError(f"Tool returned error: {result['error']}")
    actions = result.get("actions", [])
    if not actions:
        raise ValueError("No actions in result")
    first = actions[0]
    return first.get("action_id", ""), first.get("value")


def was_confirmed(result: dict[str, Any]) -> bool:
    """Check if the user confirmed (clicked approve) in a confirm dialog.

    Example::

        result = openwebgoggles(confirm("Proceed?"))
        if was_confirmed(result):
            do_the_thing()
    """
    try:
        action_id, _ = unwrap_action(result)
        return action_id == "confirm"
    except ValueError:
        return False


def get_form_values(result: dict[str, Any]) -> dict[str, Any]:
    """Extract form field values from an openwebgoggles() result.

    Returns the value dict if the user submitted, empty dict otherwise.

    Example::

        result = openwebgoggles(show_form("Settings", [
            Field("name", "Name"),
            Field("email", "Email", "email"),
        ]))
        values = get_form_values(result)
        print(values["name"], values["email"])
    """
    try:
        _, value = unwrap_action(result)
        if isinstance(value, dict):
            return value
        return {}
    except ValueError:
        return {}


# ---------------------------------------------------------------------------
# Convenience: serialize to JSON for direct use with SecurityGate
# ---------------------------------------------------------------------------


def to_json(state: dict[str, Any]) -> str:
    """Serialize a state dict to compact JSON (for SecurityGate validation)."""
    return json.dumps(state, separators=(",", ":"))
