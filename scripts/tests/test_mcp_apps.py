"""
Tests for MCP Apps dual-mode support (in-memory state, structuredContent, _owg_action).
"""

from __future__ import annotations

import asyncio
import os
import sys
import threading
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import mcp_server
from mcp_server import (
    AppModeState,
    _get_app_state,
    _is_app_mode,
    _make_merge_validator,
    _owg_action,
    webview,
    webview_close,
    webview_read,
    webview_status,
    webview_update,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_app_mode():
    """Reset app mode globals before each test."""
    old_host = mcp_server._host_fetched_ui_resource
    old_state = mcp_server._app_mode_state
    old_pending = mcp_server._reload_pending
    old_active = mcp_server._active_tool_calls
    old_gate = mcp_server._security_gate

    mcp_server._host_fetched_ui_resource = False
    mcp_server._app_mode_state = None
    mcp_server._reload_pending = False
    mcp_server._active_tool_calls = 0

    yield

    mcp_server._host_fetched_ui_resource = old_host
    mcp_server._app_mode_state = old_state
    mcp_server._reload_pending = old_pending
    mcp_server._active_tool_calls = old_active
    mcp_server._security_gate = old_gate


def _enable_app_mode():
    """Enable MCP Apps mode by setting the host-fetched flag."""
    mcp_server._host_fetched_ui_resource = True


# ---------------------------------------------------------------------------
# AppModeState
# ---------------------------------------------------------------------------


class TestAppModeState:
    def test_write_state_increments_version(self):
        """write_state increments state_version on each call."""
        ams = AppModeState()
        ams.write_state({"title": "A"})
        v1 = ams.state_version
        ams.write_state({"title": "B"})
        v2 = ams.state_version
        assert v2 == v1 + 1

    def test_write_state_stores_data(self):
        """write_state stores the state dict and stamps version into it."""
        ams = AppModeState()
        ams.write_state({"title": "Hello"})
        assert ams.state["title"] == "Hello"
        assert ams.state["version"] == ams.state_version

    def test_merge_state_deep_merges(self):
        """merge_state deep-merges a partial dict into existing state."""
        ams = AppModeState()
        ams.write_state({"title": "Root", "data": {"sections": [], "meta": {"a": 1, "b": 2}}})
        merged = ams.merge_state({"data": {"meta": {"b": 99, "c": 3}}})
        assert merged["title"] == "Root"
        assert merged["data"]["meta"]["a"] == 1
        assert merged["data"]["meta"]["b"] == 99
        assert merged["data"]["meta"]["c"] == 3

    def test_merge_state_with_validator(self):
        """merge_state calls the validator with the merged result."""
        ams = AppModeState()
        ams.write_state({"title": "Root"})
        validator = mock.MagicMock()
        ams.merge_state({"status": "ok"}, validator=validator)
        validator.assert_called_once()
        call_arg = validator.call_args[0][0]
        assert call_arg["title"] == "Root"
        assert call_arg["status"] == "ok"

    def test_merge_state_validator_rejects(self):
        """merge_state propagates ValueError from validator."""
        ams = AppModeState()
        ams.write_state({"title": "Root"})

        def bad_validator(merged):
            raise ValueError("Nope")

        with pytest.raises(ValueError, match="Nope"):
            ams.merge_state({"bad": True}, validator=bad_validator)

    def test_add_and_read_actions(self):
        """add_action stores actions, read_actions returns them."""
        ams = AppModeState()
        ams.add_action({"action_id": "a", "type": "approve"})
        ams.add_action({"action_id": "b", "type": "reject"})
        actions = ams.read_actions()
        assert len(actions) == 2
        assert actions[0]["action_id"] == "a"
        assert actions[1]["action_id"] == "b"

    def test_clear_actions(self):
        """clear_actions empties the action queue."""
        ams = AppModeState()
        ams.add_action({"action_id": "x"})
        ams.clear_actions()
        assert ams.read_actions() == []

    def test_clear_resets_everything(self):
        """clear() resets state, version, and actions."""
        ams = AppModeState()
        ams.write_state({"title": "T"})
        ams.add_action({"action_id": "x"})
        ams.clear()
        assert ams.state == {}
        assert ams.state_version == 0
        assert ams.read_actions() == []

    def test_concurrent_action_adds(self):
        """Concurrent add_action calls from multiple threads are safe."""
        ams = AppModeState()
        errors = []

        def add_many(n):
            try:
                for i in range(n):
                    ams.add_action({"action_id": f"t-{threading.current_thread().name}-{i}"})
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=add_many, args=(10,)) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(ams.read_actions()) == 100


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


class TestAppModeHelpers:
    def test_is_app_mode_false_by_default(self):
        """_is_app_mode() returns False when host has not fetched the UI resource."""
        assert _is_app_mode() is False

    def test_is_app_mode_true_after_flag(self):
        """_is_app_mode() returns True after the host-fetched flag is set."""
        _enable_app_mode()
        assert _is_app_mode() is True

    def test_get_app_state_creates_singleton(self):
        """_get_app_state() returns the same object on repeated calls."""
        s1 = _get_app_state()
        s2 = _get_app_state()
        assert s1 is s2

    def test_make_merge_validator_none_without_gate(self):
        """_make_merge_validator() returns None when _security_gate is None."""
        mcp_server._security_gate = None
        assert _make_merge_validator() is None

    def test_make_merge_validator_returns_callable(self):
        """_make_merge_validator() returns a callable when _security_gate is present."""
        gate = mock.MagicMock()
        gate.validate_state.return_value = (True, None, {})
        mcp_server._security_gate = gate
        validator = _make_merge_validator()
        assert callable(validator)
        # Calling it should not raise when gate says valid
        validator({"title": "OK"})
        gate.validate_state.assert_called_once()


# ---------------------------------------------------------------------------
# _owg_action tool
# ---------------------------------------------------------------------------


class TestOwgAction:
    async def test_not_in_app_mode(self):
        """_owg_action returns error when not in app mode."""
        mcp_server._security_gate = None
        result = await _owg_action("approve", "approve", True)
        assert "error" in result
        assert "Not in MCP Apps mode" in result["error"]

    async def test_stores_action(self):
        """_owg_action stores the action in the in-memory queue."""
        _enable_app_mode()
        mcp_server._security_gate = None
        result = await _owg_action("approve", "approve", True)
        assert result == {"received": True}
        actions = _get_app_state().read_actions()
        assert len(actions) == 1
        assert actions[0]["action_id"] == "approve"

    async def test_action_has_required_fields(self):
        """Stored action contains action_id, type, value, id, and timestamp."""
        _enable_app_mode()
        mcp_server._security_gate = None
        await _owg_action("submit", "submit", {"key": "val"})
        action = _get_app_state().read_actions()[0]
        assert "action_id" in action
        assert "type" in action
        assert "value" in action
        assert "id" in action
        assert "timestamp" in action
        assert action["action_id"] == "submit"
        assert action["type"] == "submit"
        assert action["value"] == {"key": "val"}

    async def test_action_with_context(self):
        """_owg_action stores context when provided."""
        _enable_app_mode()
        mcp_server._security_gate = None
        ctx = {"item_index": 0, "section_id": "items"}
        await _owg_action("click", "click", True, context=ctx)
        action = _get_app_state().read_actions()[0]
        assert action["context"] == ctx

    async def test_security_gate_rejects(self):
        """_owg_action returns error when security gate rejects the action."""
        _enable_app_mode()
        gate = mock.MagicMock()
        gate.validate_state.return_value = (False, "bad payload", {})
        mcp_server._security_gate = gate
        result = await _owg_action("approve", "approve", True)
        assert "error" in result
        assert "security gate" in result["error"]
        # Action should NOT be stored
        assert _get_app_state().read_actions() == []


# ---------------------------------------------------------------------------
# webview tool — app mode
# ---------------------------------------------------------------------------


class TestWebviewAppMode:
    async def test_returns_structured_content(self):
        """webview returns structuredContent immediately in app mode."""
        _enable_app_mode()
        mcp_server._security_gate = None
        result = await webview(state={"title": "Test"})
        assert "structuredContent" in result
        assert result["structuredContent"]["title"] == "Test"

    async def test_clears_actions_on_new_webview(self):
        """webview clears pending actions when called in app mode."""
        _enable_app_mode()
        mcp_server._security_gate = None
        app_state = _get_app_state()
        app_state.add_action({"action_id": "old"})
        await webview(state={"title": "Fresh"})
        assert app_state.read_actions() == []

    async def test_does_not_block(self):
        """webview returns immediately in app mode (no timeout/blocking)."""
        _enable_app_mode()
        mcp_server._security_gate = None
        # If this blocks, the test will time out
        result = await asyncio.wait_for(
            webview(state={"title": "Quick"}),
            timeout=2.0,
        )
        assert "structuredContent" in result

    async def test_state_stored_in_memory(self):
        """webview stores state in the AppModeState singleton."""
        _enable_app_mode()
        mcp_server._security_gate = None
        await webview(state={"title": "Stored", "data": {"sections": []}})
        app_state = _get_app_state()
        assert app_state.state["title"] == "Stored"
        assert app_state.state_version >= 1


# ---------------------------------------------------------------------------
# webview_read tool — app mode
# ---------------------------------------------------------------------------


class TestWebviewReadAppMode:
    async def test_reads_from_memory(self):
        """webview_read returns actions from the in-memory queue."""
        _enable_app_mode()
        mcp_server._security_gate = None
        app_state = _get_app_state()
        app_state.add_action({"action_id": "btn", "type": "approve", "value": True})
        result = await webview_read()
        assert len(result["actions"]) == 1
        assert result["actions"][0]["action_id"] == "btn"

    async def test_clear_drains_queue(self):
        """webview_read(clear=True) drains the queue so next read is empty."""
        _enable_app_mode()
        mcp_server._security_gate = None
        app_state = _get_app_state()
        app_state.add_action({"action_id": "a"})
        result1 = await webview_read(clear=True)
        assert len(result1["actions"]) == 1
        result2 = await webview_read()
        assert result2["actions"] == []

    async def test_empty_when_no_actions(self):
        """webview_read returns empty actions when queue is empty."""
        _enable_app_mode()
        mcp_server._security_gate = None
        # Ensure singleton exists but has no actions
        _get_app_state()
        result = await webview_read()
        assert result["actions"] == []


# ---------------------------------------------------------------------------
# webview_update tool — app mode
# ---------------------------------------------------------------------------


class TestWebviewUpdateAppMode:
    async def test_update_replaces_state(self):
        """webview_update replaces state and returns structuredContent."""
        _enable_app_mode()
        mcp_server._security_gate = None
        app_state = _get_app_state()
        app_state.write_state({"title": "Old"})
        result = await webview_update(state={"title": "New"})
        assert result["updated"] is True
        assert result["structuredContent"]["title"] == "New"
        assert app_state.state["title"] == "New"

    async def test_update_merge_mode(self):
        """webview_update(merge=True) deep-merges into existing state."""
        _enable_app_mode()
        mcp_server._security_gate = None
        app_state = _get_app_state()
        app_state.write_state({"title": "Base", "data": {"meta": {"a": 1}}})
        result = await webview_update(state={"data": {"meta": {"b": 2}}}, merge=True)
        assert result["updated"] is True
        merged = result["structuredContent"]
        assert merged["title"] == "Base"
        assert merged["data"]["meta"]["a"] == 1
        assert merged["data"]["meta"]["b"] == 2

    async def test_preset_expansion(self):
        """webview_update with preset="confirm" expands state."""
        _enable_app_mode()
        mcp_server._security_gate = None
        _get_app_state()
        result = await webview_update(
            state={"title": "Sure?", "message": "Do it?"},
            preset="confirm",
        )
        assert result["updated"] is True
        sc = result["structuredContent"]
        assert "actions_requested" in sc
        assert sc["status"] == "pending_review"


# ---------------------------------------------------------------------------
# webview_close tool — app mode
# ---------------------------------------------------------------------------


class TestWebviewCloseAppMode:
    async def test_clears_state(self):
        """webview_close clears in-memory state in app mode."""
        _enable_app_mode()
        mcp_server._security_gate = None
        app_state = _get_app_state()
        app_state.write_state({"title": "Active"})
        app_state.add_action({"action_id": "x"})
        result = await webview_close()
        assert result["status"] == "ok"
        assert app_state.state == {}
        assert app_state.state_version == 0
        assert app_state.read_actions() == []


# ---------------------------------------------------------------------------
# webview_status tool — app mode
# ---------------------------------------------------------------------------


class TestWebviewStatusAppMode:
    async def test_active_when_state_exists(self):
        """webview_status reports active=True when state is non-empty."""
        _enable_app_mode()
        mcp_server._security_gate = None
        app_state = _get_app_state()
        app_state.write_state({"title": "Live"})
        result = await webview_status()
        assert result["active"] is True
        assert result["mode"] == "mcp_apps"
        assert result["version"] >= 1

    async def test_inactive_when_empty(self):
        """webview_status reports active=False when no state has been written."""
        _enable_app_mode()
        mcp_server._security_gate = None
        _get_app_state()  # create singleton but don't write state
        result = await webview_status()
        assert result["active"] is False
        assert result["mode"] == "mcp_apps"
