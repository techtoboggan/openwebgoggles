"""
Tests for the Python SDK helpers (scripts/sdk.py).

Covers: Field/Action builders, state generators, result unwrapping, theme support.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sdk import (
    Action,
    Field,
    confirm,
    get_form_values,
    show_chart,
    show_dashboard,
    show_diff,
    show_form,
    show_log,
    show_progress,
    show_table,
    to_json,
    unwrap_action,
    was_confirmed,
)
from security_gate import SecurityGate


# ═══════════════════════════════════════════════════════════════════════════════
# 1. FIELD BUILDER
# ═══════════════════════════════════════════════════════════════════════════════


class TestField:
    def test_basic_field(self):
        f = Field("name", "Name")
        d = f.to_dict()
        assert d == {"key": "name", "label": "Name", "type": "text"}

    def test_all_options(self):
        f = Field(
            "age",
            "Age",
            "number",
            value=25,
            default=18,
            placeholder="Enter age",
            description="Your age",
            required=True,
            min_value=0,
            max_value=150,
            error_message="Invalid age",
        )
        d = f.to_dict()
        assert d["type"] == "number"
        assert d["value"] == 25
        assert d["default"] == 18
        assert d["required"] is True
        assert d["min"] == 0
        assert d["max"] == 150
        assert d["errorMessage"] == "Invalid age"

    def test_select_with_options(self):
        f = Field("role", "Role", "select", options=["Admin", "User"])
        d = f.to_dict()
        assert d["options"] == ["Admin", "User"]

    def test_invalid_type_raises(self):
        with pytest.raises(ValueError, match="Invalid field type"):
            Field("x", "X", "invalid_type")

    def test_all_valid_types_accepted(self):
        for ft in Field.VALID_TYPES:
            f = Field("k", "L", ft)
            assert f.to_dict()["type"] == ft

    def test_class_name(self):
        f = Field("x", "X", class_name="owg-mono")
        assert f.to_dict()["className"] == "owg-mono"

    def test_format(self):
        f = Field("x", "X", "static", format="markdown")
        assert f.to_dict()["format"] == "markdown"


# ═══════════════════════════════════════════════════════════════════════════════
# 2. ACTION BUILDER
# ═══════════════════════════════════════════════════════════════════════════════


class TestAction:
    def test_basic_action(self):
        a = Action("ok", "OK")
        d = a.to_dict()
        assert d == {"id": "ok", "label": "OK", "type": "primary"}

    def test_action_with_type(self):
        a = Action("approve", "Approve", "approve")
        assert a.to_dict()["type"] == "approve"

    def test_action_with_navigate(self):
        a = Action("next", "Next", navigate_to="step_2")
        assert a.to_dict()["navigateTo"] == "step_2"


# ═══════════════════════════════════════════════════════════════════════════════
# 3. STATE BUILDERS — confirm()
# ═══════════════════════════════════════════════════════════════════════════════


class TestConfirm:
    def test_minimal(self):
        s = confirm()
        assert s["title"] == "Confirm"
        assert s["status"] == "pending_review"
        assert len(s["actions_requested"]) == 2
        assert s["actions_requested"][0]["id"] == "confirm"
        assert s["actions_requested"][1]["id"] == "cancel"

    def test_with_details(self):
        s = confirm("Deploy?", details="## Important\nThis is irreversible.")
        assert len(s["data"]["sections"]) == 1
        assert s["data"]["sections"][0]["type"] == "text"
        assert s["data"]["sections"][0]["format"] == "markdown"

    def test_custom_labels(self):
        s = confirm(confirm_label="Yes", cancel_label="No")
        assert s["actions_requested"][0]["label"] == "Yes"
        assert s["actions_requested"][1]["label"] == "No"

    def test_with_theme(self):
        s = confirm(theme="light")
        assert s["theme"] == "light"

    def test_passes_security_gate(self):
        gate = SecurityGate()
        s = confirm("Test", "msg", details="details")
        ok, err, _ = gate.validate_state(to_json(s))
        assert ok, err


# ═══════════════════════════════════════════════════════════════════════════════
# 4. STATE BUILDERS — show_form()
# ═══════════════════════════════════════════════════════════════════════════════


class TestShowForm:
    def test_minimal(self):
        s = show_form()
        assert s["title"] == "Form"
        assert s["status"] == "waiting_input"
        assert s["data"]["sections"][0]["type"] == "form"

    def test_with_fields(self):
        s = show_form("User", [Field("name", "Name", required=True)])
        fields = s["data"]["sections"][0]["fields"]
        assert len(fields) == 1
        assert fields[0]["key"] == "name"
        assert fields[0]["required"] is True

    def test_with_dict_fields(self):
        s = show_form("F", [{"key": "k", "label": "L", "type": "text"}])
        assert s["data"]["sections"][0]["fields"][0]["key"] == "k"

    def test_with_cancel(self):
        s = show_form(cancel_label="Cancel")
        assert len(s["actions_requested"]) == 2

    def test_with_message(self):
        s = show_form(message="Fill this out")
        assert s["message"] == "Fill this out"

    def test_passes_security_gate(self):
        gate = SecurityGate()
        s = show_form("Test", [Field("name", "Name"), Field("email", "Email", "email")])
        ok, err, _ = gate.validate_state(to_json(s))
        assert ok, err


# ═══════════════════════════════════════════════════════════════════════════════
# 5. STATE BUILDERS — show_table()
# ═══════════════════════════════════════════════════════════════════════════════


class TestShowTable:
    def test_string_columns(self):
        s = show_table("T", ["A", "B"], [{"A": "1", "B": "2"}])
        cols = s["data"]["sections"][0]["columns"]
        assert cols[0] == {"key": "A", "label": "A"}

    def test_dict_columns(self):
        s = show_table("T", [{"key": "a", "label": "Col A"}], [])
        assert s["data"]["sections"][0]["columns"][0]["label"] == "Col A"

    def test_clickable(self):
        s = show_table("T", ["A"], [], clickable=True, click_action_id="row_click")
        sec = s["data"]["sections"][0]
        assert sec["clickable"] is True
        assert sec["clickActionId"] == "row_click"

    def test_with_actions(self):
        s = show_table("T", ["A"], [], actions=[Action("ok", "OK")])
        assert s["actions_requested"][0]["id"] == "ok"

    def test_passes_security_gate(self):
        gate = SecurityGate()
        s = show_table("T", ["Name", "Value"], [{"Name": "x", "Value": "y"}])
        ok, err, _ = gate.validate_state(to_json(s))
        assert ok, err


# ═══════════════════════════════════════════════════════════════════════════════
# 6. STATE BUILDERS — show_progress, show_log, show_dashboard
# ═══════════════════════════════════════════════════════════════════════════════


class TestShowProgress:
    def test_basic(self):
        s = show_progress("Build", [{"label": "Step 1", "status": "complete"}], percentage=50)
        sec = s["data"]["sections"][0]
        assert sec["type"] == "progress"
        assert sec["percentage"] == 50
        assert s["status"] == "processing"

    def test_passes_security_gate(self):
        gate = SecurityGate()
        s = show_progress("P", [{"label": "A", "status": "pending"}])
        ok, err, _ = gate.validate_state(to_json(s))
        assert ok, err


class TestShowLog:
    def test_basic(self):
        s = show_log("Log", ["line1", "line2"], max_lines=100)
        sec = s["data"]["sections"][0]
        assert sec["type"] == "log"
        assert sec["maxLines"] == 100
        assert len(sec["lines"]) == 2

    def test_passes_security_gate(self):
        gate = SecurityGate()
        s = show_log("L", ["hello"])
        ok, err, _ = gate.validate_state(to_json(s))
        assert ok, err


class TestShowDashboard:
    def test_basic(self):
        s = show_dashboard(
            "D",
            [
                {"label": "Metric", "value": "42", "delta": "+5%", "trend": "up"},
            ],
        )
        cards = s["data"]["sections"][0]["cards"]
        assert len(cards) == 1
        assert cards[0]["label"] == "Metric"
        assert cards[0]["delta"] == "+5%"

    def test_passes_security_gate(self):
        gate = SecurityGate()
        s = show_dashboard("D", [{"label": "X", "value": "1"}])
        ok, err, _ = gate.validate_state(to_json(s))
        assert ok, err


class TestShowDiff:
    def test_basic(self):
        s = show_diff("Changes", "--- a\n+++ b\n@@ -1 +1 @@\n-old\n+new")
        assert s["data"]["sections"][0]["type"] == "diff"

    def test_with_actions(self):
        s = show_diff("D", "diff", actions=[Action("ok", "OK", "approve")])
        assert s["actions_requested"][0]["id"] == "ok"

    def test_passes_security_gate(self):
        gate = SecurityGate()
        s = show_diff("D", "content")
        ok, err, _ = gate.validate_state(to_json(s))
        assert ok, err


class TestShowChart:
    def test_basic(self):
        s = show_chart("Revenue", "bar", ["Jan", "Feb"], [{"label": "2025", "data": [100, 200]}])
        sec = s["data"]["sections"][0]
        assert sec["chartType"] == "bar"
        assert sec["data"]["labels"] == ["Jan", "Feb"]

    def test_passes_security_gate(self):
        gate = SecurityGate()
        s = show_chart("C", "line", ["A"], [{"label": "D", "data": [1]}])
        ok, err, _ = gate.validate_state(to_json(s))
        assert ok, err


# ═══════════════════════════════════════════════════════════════════════════════
# 7. THEME SUPPORT
# ═══════════════════════════════════════════════════════════════════════════════


class TestThemeSupport:
    def test_dark_theme_valid(self):
        gate = SecurityGate()
        s = confirm(theme="dark")
        ok, err, _ = gate.validate_state(to_json(s))
        assert ok, err

    def test_light_theme_valid(self):
        gate = SecurityGate()
        s = confirm(theme="light")
        ok, err, _ = gate.validate_state(to_json(s))
        assert ok, err

    def test_system_theme_valid(self):
        gate = SecurityGate()
        s = confirm(theme="system")
        ok, err, _ = gate.validate_state(to_json(s))
        assert ok, err

    def test_invalid_theme_rejected(self):
        gate = SecurityGate()
        state = {"status": "ready", "theme": "neon"}
        ok, err, _ = gate.validate_state(json.dumps(state))
        assert not ok
        assert "Invalid theme" in err
        assert "neon" in err

    def test_theme_type_must_be_string(self):
        gate = SecurityGate()
        state = {"status": "ready", "theme": 42}
        ok, err, _ = gate.validate_state(json.dumps(state))
        assert not ok
        assert "Invalid theme" in err

    def test_no_theme_passes(self):
        gate = SecurityGate()
        state = {"status": "ready"}
        ok, err, _ = gate.validate_state(json.dumps(state))
        assert ok, err


# ═══════════════════════════════════════════════════════════════════════════════
# 8. RESULT UNWRAPPING
# ═══════════════════════════════════════════════════════════════════════════════


class TestResultUnwrapping:
    def test_unwrap_action(self):
        result = {"actions": [{"action_id": "approve", "type": "approve", "value": True}]}
        action_id, value = unwrap_action(result)
        assert action_id == "approve"
        assert value is True

    def test_unwrap_error(self):
        with pytest.raises(ValueError, match="error"):
            unwrap_action({"error": "timeout"})

    def test_unwrap_no_actions(self):
        with pytest.raises(ValueError, match="No actions"):
            unwrap_action({"actions": []})

    def test_was_confirmed_true(self):
        result = {"actions": [{"action_id": "confirm", "value": True}]}
        assert was_confirmed(result) is True

    def test_was_confirmed_false(self):
        result = {"actions": [{"action_id": "cancel", "value": False}]}
        assert was_confirmed(result) is False

    def test_was_confirmed_error(self):
        assert was_confirmed({"error": "timeout"}) is False

    def test_get_form_values(self):
        result = {"actions": [{"action_id": "submit", "value": {"name": "Alice", "age": 30}}]}
        values = get_form_values(result)
        assert values == {"name": "Alice", "age": 30}

    def test_get_form_values_boolean(self):
        result = {"actions": [{"action_id": "approve", "value": True}]}
        values = get_form_values(result)
        assert values == {}

    def test_get_form_values_error(self):
        assert get_form_values({"error": "x"}) == {}


# ═══════════════════════════════════════════════════════════════════════════════
# 9. IMPROVED ERROR MESSAGES
# ═══════════════════════════════════════════════════════════════════════════════


class TestImprovedErrors:
    def test_unknown_top_key_shows_valid_keys(self):
        gate = SecurityGate()
        state = {"status": "ready", "titl": "oops"}
        ok, err, _ = gate.validate_state(json.dumps(state))
        assert not ok
        assert "titl" in err
        assert "title" in err  # suggestion
        assert "Valid keys:" in err

    def test_invalid_section_type_suggests(self):
        gate = SecurityGate()
        state = {"data": {"sections": [{"type": "frm"}]}}
        ok, err, _ = gate.validate_state(json.dumps(state))
        assert not ok
        assert "frm" in err
        assert "form" in err  # suggestion

    def test_invalid_field_type_suggests(self):
        gate = SecurityGate()
        state = {"data": {"sections": [{"type": "form", "fields": [{"key": "x", "type": "txet", "label": "X"}]}]}}
        ok, err, _ = gate.validate_state(json.dumps(state))
        assert not ok
        assert "txet" in err
        assert "text" in err  # suggestion

    def test_invalid_action_type_suggests(self):
        gate = SecurityGate()
        state = {"actions_requested": [{"id": "ok", "type": "aprove", "label": "OK"}]}
        ok, err, _ = gate.validate_state(json.dumps(state))
        assert not ok
        assert "aprove" in err
        assert "approve" in err  # suggestion


# ═══════════════════════════════════════════════════════════════════════════════
# 10. to_json
# ═══════════════════════════════════════════════════════════════════════════════


class TestToJson:
    def test_compact(self):
        s = confirm("Test")
        j = to_json(s)
        assert " " not in j or ":" not in j  # compact separators
        parsed = json.loads(j)
        assert parsed["title"] == "Test"
