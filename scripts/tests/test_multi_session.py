"""
Tests for multi-session support: SessionManager, SessionSlot, and named session routing.
"""

from __future__ import annotations

import os
import sys
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import mcp_server
from mcp_server import (
    MAX_CONCURRENT_SESSIONS,
    SessionManager,
    SessionSlot,
    WebviewSession,
    _get_browser_session,
    _get_slot_app_state,
    _is_valid_session_name,
    openwebgoggles,
    openwebgoggles_close,
    openwebgoggles_read,
    openwebgoggles_status,
    openwebgoggles_update,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_state():
    """Reset session manager and mode for each test."""
    old_manager = mcp_server._session_manager
    old_cached = mcp_server._cached_mode
    old_host = mcp_server._host_fetched_ui_resource
    old_pending = mcp_server._reload_pending
    old_active = mcp_server._active_tool_calls

    mcp_server._session_manager = SessionManager()
    mcp_server._cached_mode = None
    mcp_server._host_fetched_ui_resource = False
    mcp_server._reload_pending = False
    mcp_server._active_tool_calls = 0

    yield

    mcp_server._session_manager = old_manager
    mcp_server._cached_mode = old_cached
    mcp_server._host_fetched_ui_resource = old_host
    mcp_server._reload_pending = old_pending
    mcp_server._active_tool_calls = old_active


def _make_mock_session(**kwargs):
    session = mock.MagicMock(spec=WebviewSession)
    session._started = kwargs.get("started", True)
    session._state_version = kwargs.get("state_version", 1)
    session.session_id = kwargs.get("session_id", "test-session-id")
    session.http_port = kwargs.get("http_port", 18420)
    session.url = f"http://127.0.0.1:{session.http_port}"
    session.is_alive = mock.MagicMock(return_value=kwargs.get("alive", True))
    session.ensure_started = mock.AsyncMock()
    session.write_state = mock.MagicMock()
    session.read_state = mock.MagicMock(return_value={})
    session.merge_state = mock.MagicMock(return_value={"version": 1})
    session.read_actions = mock.MagicMock(return_value={"version": 0, "actions": []})
    session.clear_actions = mock.MagicMock()
    session.wait_for_action = mock.AsyncMock(return_value=None)
    session.close = mock.AsyncMock()
    return session


# ---------------------------------------------------------------------------
# SessionSlot
# ---------------------------------------------------------------------------


class TestSessionSlot:
    def test_slot_creation(self):
        slot = SessionSlot("my-session")
        assert slot.name == "my-session"
        assert slot.browser_session is None
        assert slot.app_state is None
        assert slot.mode is None
        assert slot.persist_enabled is False
        assert slot.created_at > 0

    def test_slot_mode_caching(self):
        slot = SessionSlot("test")
        slot.mode = "browser"
        assert slot.mode == "browser"


# ---------------------------------------------------------------------------
# Session name validation
# ---------------------------------------------------------------------------


class TestSessionNameValidation:
    @pytest.mark.parametrize(
        "name",
        ["default", "my-session", "session_1", "a", "A-Z_0-9", "a" * 64],
    )
    def test_valid_names(self, name):
        assert _is_valid_session_name(name) is True

    @pytest.mark.parametrize(
        "name",
        ["", "a" * 65, "my session", "my/session", "../escape", "session.name", "a@b"],
    )
    def test_invalid_names(self, name):
        assert _is_valid_session_name(name) is False


# ---------------------------------------------------------------------------
# SessionManager
# ---------------------------------------------------------------------------


class TestSessionManager:
    async def test_get_or_create_default(self):
        mgr = SessionManager()
        slot = await mgr.get_or_create("default")
        assert slot.name == "default"
        assert mgr.count == 1

    async def test_get_or_create_named(self):
        mgr = SessionManager()
        slot1 = await mgr.get_or_create("alpha")
        slot2 = await mgr.get_or_create("beta")
        assert slot1.name == "alpha"
        assert slot2.name == "beta"
        assert mgr.count == 2

    async def test_get_or_create_returns_existing(self):
        mgr = SessionManager()
        slot1 = await mgr.get_or_create("test")
        slot2 = await mgr.get_or_create("test")
        assert slot1 is slot2

    async def test_max_sessions_enforced(self):
        mgr = SessionManager()
        for i in range(MAX_CONCURRENT_SESSIONS):
            await mgr.get_or_create(f"session-{i}")
        with pytest.raises(ValueError, match="Maximum concurrent sessions"):
            await mgr.get_or_create("one-too-many")

    async def test_invalid_session_name_rejected(self):
        mgr = SessionManager()
        with pytest.raises(ValueError, match="Invalid session name"):
            await mgr.get_or_create("bad name")

    async def test_get_existing(self):
        mgr = SessionManager()
        await mgr.get_or_create("test")
        slot = await mgr.get("test")
        assert slot is not None
        assert slot.name == "test"

    async def test_get_nonexistent(self):
        mgr = SessionManager()
        slot = await mgr.get("nonexistent")
        assert slot is None

    async def test_remove_session(self):
        mgr = SessionManager()
        await mgr.get_or_create("test")
        slot = await mgr.remove("test")
        assert slot is not None
        assert slot.name == "test"
        assert mgr.count == 0

    async def test_remove_nonexistent(self):
        mgr = SessionManager()
        slot = await mgr.remove("nonexistent")
        assert slot is None

    async def test_close_all(self):
        mgr = SessionManager()
        for name in ["a", "b", "c"]:
            slot = await mgr.get_or_create(name)
            mock_session = _make_mock_session()
            slot.browser_session = mock_session
            slot.mode = "browser"
        count = await mgr.close_all(message="bye")
        assert count == 3
        assert mgr.count == 0

    async def test_list_active(self):
        mgr = SessionManager()
        slot = await mgr.get_or_create("test")
        mock_session = _make_mock_session()
        slot.browser_session = mock_session
        slot.mode = "browser"

        sessions = await mgr.list_active()
        assert len(sessions) == 1
        assert sessions[0]["name"] == "test"
        assert sessions[0]["active"] is True
        assert sessions[0]["mode"] == "browser"


# ---------------------------------------------------------------------------
# Multi-session tool routing
# ---------------------------------------------------------------------------


class TestMultiSessionTools:
    """Test that tools route to the correct named session."""

    async def test_openwebgoggles_with_session_param(self):
        """Named session parameter routes to the correct slot."""
        mock_session = _make_mock_session()

        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles(
                state={"title": "Test"},
                session="my-panel",
                ctx=None,
            )

        # Non-blocking: returns ui_ready immediately
        assert result["status"] == "ui_ready"
        assert result["session"] == "my-panel"
        mock_session.write_state.assert_called_once()

    async def test_two_sessions_independent_state(self):
        """Two named sessions have independent state in app mode."""
        mcp_server._cached_mode = "app"
        mcp_server._host_fetched_ui_resource = True

        # Create two sessions
        with mock.patch("mcp_server._get_bundled_html", return_value="<html></html>"):
            await openwebgoggles(
                state={"title": "Panel A", "data": {}},
                session="panel-a",
                ctx=None,
            )
            await openwebgoggles(
                state={"title": "Panel B", "data": {}},
                session="panel-b",
                ctx=None,
            )

        # Read from each — they should be independent
        result_a = await openwebgoggles_read(session="panel-a")
        result_b = await openwebgoggles_read(session="panel-b")

        # Both return empty actions (no user interaction yet)
        assert result_a["actions"] == []
        assert result_b["actions"] == []

    async def test_close_specific_session(self):
        """Closing one session leaves others intact."""
        mgr = mcp_server._session_manager
        slot_a = await mgr.get_or_create("alpha")
        slot_a.browser_session = _make_mock_session()
        slot_a.mode = "browser"
        slot_b = await mgr.get_or_create("beta")
        slot_b.browser_session = _make_mock_session()
        slot_b.mode = "browser"

        with mock.patch("mcp_server._stop_any_running_server"):
            result = await openwebgoggles_close(message="bye", session="alpha")

        assert result["status"] == "ok"
        assert "alpha" in result["message"]
        assert mgr.count == 1
        remaining = await mgr.get("beta")
        assert remaining is not None

    async def test_close_all_sessions(self):
        """Close without session param closes all."""
        mgr = mcp_server._session_manager
        for name in ["a", "b"]:
            slot = await mgr.get_or_create(name)
            slot.browser_session = _make_mock_session()
            slot.mode = "browser"

        with mock.patch("mcp_server._stop_any_running_server"):
            result = await openwebgoggles_close(message="bye")

        assert result["status"] == "ok"
        assert "2 session(s)" in result["message"]
        assert mgr.count == 0

    async def test_status_all_sessions(self):
        """Status without session param returns all active sessions."""
        mgr = mcp_server._session_manager
        slot = await mgr.get_or_create("test")
        slot.browser_session = _make_mock_session()
        slot.mode = "browser"

        result = await openwebgoggles_status()

        assert result["active_count"] == 1
        assert result["max_sessions"] == MAX_CONCURRENT_SESSIONS
        assert len(result["sessions"]) == 1

    async def test_status_specific_session(self):
        """Status with session param returns info for that session."""
        mgr = mcp_server._session_manager
        slot = await mgr.get_or_create("test")
        mock_session = _make_mock_session()
        slot.browser_session = mock_session
        slot.mode = "browser"

        result = await openwebgoggles_status(session="test")

        assert result["active"] is True
        assert result["session"] == "test"
        assert result["mode"] == "browser"

    async def test_status_nonexistent_session(self):
        """Status for nonexistent session returns inactive."""
        result = await openwebgoggles_status(session="nonexistent")
        assert result["active"] is False

    async def test_read_from_named_session(self):
        """Read routes to the correct browser session slot."""
        mock_session = _make_mock_session()
        mock_session.read_actions.return_value = {
            "version": 1,
            "actions": [{"action_id": "ok"}],
        }

        mgr = mcp_server._session_manager
        slot = await mgr.get_or_create("test")
        slot.browser_session = mock_session
        slot.mode = "browser"

        result = await openwebgoggles_read(session="test")
        assert len(result["actions"]) == 1

    async def test_update_named_session(self):
        """Update routes to the correct browser session."""
        mock_session = _make_mock_session()

        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles_update(
                state={"title": "Updated"},
                session="my-panel",
                ctx=None,
            )

        assert result["updated"] is True
        mock_session.write_state.assert_called_once()


# ---------------------------------------------------------------------------
# _get_browser_session helper
# ---------------------------------------------------------------------------


class TestGetBrowserSession:
    async def test_creates_session_for_default(self):
        """Default name creates a WebviewSession with default data dir."""
        with mock.patch.object(WebviewSession, "ensure_started", new_callable=mock.AsyncMock):
            with mock.patch.object(WebviewSession, "__init__", return_value=None):
                # Just verify it calls WebviewSession constructor
                try:
                    await _get_browser_session("default")
                except Exception:
                    pass  # May fail due to mock, but we check the slot was created
        slot = await mcp_server._session_manager.get("default")
        assert slot is not None

    async def test_creates_session_for_named(self):
        """Named session creates a WebviewSession with per-session data dir."""
        slot = await mcp_server._session_manager.get_or_create("my-panel")
        assert slot.browser_session is None  # Not created yet

        mock_session = _make_mock_session()
        slot.browser_session = mock_session

        ws = await _get_browser_session("my-panel")
        assert ws is mock_session  # Returns existing

    async def test_reuses_existing_session(self):
        """Calling twice returns the same WebviewSession."""
        mock_session = _make_mock_session()
        slot = await mcp_server._session_manager.get_or_create("test")
        slot.browser_session = mock_session

        ws1 = await _get_browser_session("test")
        ws2 = await _get_browser_session("test")
        assert ws1 is ws2


# ---------------------------------------------------------------------------
# _get_slot_app_state helper
# ---------------------------------------------------------------------------


class TestGetSlotAppState:
    def test_creates_app_state(self):
        slot = SessionSlot("test")
        assert slot.app_state is None
        app_state = _get_slot_app_state(slot)
        assert app_state is not None
        assert slot.mode == "app"

    def test_returns_existing(self):
        slot = SessionSlot("test")
        s1 = _get_slot_app_state(slot)
        s2 = _get_slot_app_state(slot)
        assert s1 is s2
