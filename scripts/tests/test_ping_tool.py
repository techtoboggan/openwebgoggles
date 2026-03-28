"""
Tests for openwebgoggles_ping tool and _hint in return values.

Covers:
  - App mode: pings write_state and return ok with _hint
  - Browser mode: pings active session, returns ok
  - Browser mode, no active session: returns error
  - SecurityGate rejection of malicious message
  - openwebgoggles_status returns _hint for all-sessions view
"""

from __future__ import annotations

import os
import sys
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import mcp_server
from mcp_server import (
    AppModeState,
    SessionManager,
    SessionSlot,
    WebviewSession,
    openwebgoggles_ping,
    openwebgoggles_status,
)


# ---------------------------------------------------------------------------
# Fixtures — reset globals before each test
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_globals():
    """Restore mcp_server globals after each test."""
    old_cached_mode = mcp_server._cached_mode
    old_host_fetched = mcp_server._host_fetched_ui_resource
    old_manager = mcp_server._session_manager
    old_gate = mcp_server._security_gate

    mcp_server._cached_mode = None
    mcp_server._host_fetched_ui_resource = False
    mcp_server._session_manager = SessionManager()

    yield

    mcp_server._cached_mode = old_cached_mode
    mcp_server._host_fetched_ui_resource = old_host_fetched
    mcp_server._session_manager = old_manager
    mcp_server._security_gate = old_gate


def _enable_app_mode():
    """Force app mode."""
    mcp_server._cached_mode = "app"
    mcp_server._host_fetched_ui_resource = True


def _make_mock_browser_session(alive: bool = True) -> mock.MagicMock:
    session = mock.MagicMock(spec=WebviewSession)
    session._started = True
    session.is_alive = mock.MagicMock(return_value=alive)
    session.write_state = mock.MagicMock()
    return session


def _inject_browser_slot(mock_session, name: str = "default") -> SessionSlot:
    slot = SessionSlot(name)
    slot.browser_session = mock_session
    slot.mode = "browser"
    mcp_server._session_manager._slots[name] = slot
    return slot


# ---------------------------------------------------------------------------
# openwebgoggles_ping — app mode
# ---------------------------------------------------------------------------


class TestPingToolAppMode:
    async def test_app_mode_calls_write_state(self):
        """In app mode, ping calls write_state on the AppModeState with a processing dict."""
        _enable_app_mode()
        app_state = _make_app_state_mock()
        with mock.patch("mcp_server._get_app_state", return_value=app_state):
            await openwebgoggles_ping("Analyzing files...")

        app_state.write_state.assert_called_once()
        call_arg = app_state.write_state.call_args[0][0]
        assert "message" in call_arg
        assert call_arg["status"] == "processing"

    async def test_app_mode_returns_ok_with_hint(self):
        """In app mode, ping returns ok=True and includes a _hint key."""
        _enable_app_mode()
        app_state = _make_app_state_mock()
        with mock.patch("mcp_server._get_app_state", return_value=app_state):
            result = await openwebgoggles_ping("Running tests...")

        assert result.get("ok") is True
        assert "_hint" in result
        assert isinstance(result["_hint"], str)
        assert len(result["_hint"]) > 0

    async def test_app_mode_message_passed_through(self):
        """In app mode, ping includes the message text in the state written."""
        _enable_app_mode()
        msg = "Step 3 of 5: compiling"
        app_state = _make_app_state_mock()
        with mock.patch("mcp_server._get_app_state", return_value=app_state):
            await openwebgoggles_ping(msg)

        call_arg = app_state.write_state.call_args[0][0]
        assert call_arg["message"] == msg


# ---------------------------------------------------------------------------
# openwebgoggles_ping — browser mode
# ---------------------------------------------------------------------------


class TestPingToolBrowserMode:
    async def test_browser_mode_updates_state(self):
        """In browser mode, ping calls write_state on the active browser session."""
        mcp_server._cached_mode = "browser"
        mock_session = _make_mock_browser_session(alive=True)
        _inject_browser_slot(mock_session)

        result = await openwebgoggles_ping("Scanning...")

        mock_session.write_state.assert_called_once()
        assert result.get("ok") is True

    async def test_browser_mode_returns_hint(self):
        """Browser mode ping result includes a _hint key."""
        mcp_server._cached_mode = "browser"
        mock_session = _make_mock_browser_session(alive=True)
        _inject_browser_slot(mock_session)

        result = await openwebgoggles_ping("Processing...")

        assert "_hint" in result

    async def test_browser_mode_no_active_session_returns_error(self):
        """When no active session exists, ping returns an error dict."""
        mcp_server._cached_mode = "browser"
        # Don't inject any slot

        result = await openwebgoggles_ping("Hello")

        assert "error" in result

    async def test_browser_mode_dead_session_returns_error(self):
        """When the browser session is not alive, ping returns an error."""
        mcp_server._cached_mode = "browser"
        mock_session = _make_mock_browser_session(alive=False)
        _inject_browser_slot(mock_session)

        result = await openwebgoggles_ping("Hello")

        assert "error" in result


# ---------------------------------------------------------------------------
# openwebgoggles_ping — security gate rejection
# ---------------------------------------------------------------------------


class TestPingSecurityGate:
    async def test_xss_message_rejected(self):
        """Ping with an XSS payload in the message is rejected by the security gate."""
        mcp_server._cached_mode = "browser"
        # The security gate is already set up globally; just call with XSS payload
        result = await openwebgoggles_ping("<script>alert(1)</script>")

        assert "error" in result

    async def test_no_security_gate_returns_error(self):
        """When _security_gate is None, ping returns an error."""
        mcp_server._security_gate = None

        result = await openwebgoggles_ping("some message")

        assert "error" in result


# ---------------------------------------------------------------------------
# openwebgoggles_status — _hint in all-sessions view
# ---------------------------------------------------------------------------


class TestStatusHint:
    async def test_all_sessions_view_has_hint(self):
        """openwebgoggles_status() with no session arg returns dict with _hint key."""
        mcp_server._cached_mode = "browser"

        result = await openwebgoggles_status(session=None)

        assert "_hint" in result, f"Expected '_hint' in status result, got: {list(result.keys())}"

    async def test_hint_mentions_close(self):
        """The _hint value for all-sessions view mentions 'openwebgoggles_close'."""
        mcp_server._cached_mode = "browser"

        result = await openwebgoggles_status(session=None)

        assert "openwebgoggles_close" in result["_hint"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_app_state_mock() -> mock.MagicMock:
    """Create a mock AppModeState that accepts write_state calls."""
    app_state = mock.MagicMock(spec=AppModeState)
    app_state.write_state = mock.MagicMock()
    app_state.state = {"status": "ready"}
    app_state.state_version = 1
    return app_state
