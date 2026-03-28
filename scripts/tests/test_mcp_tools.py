"""
Tests for MCP tool functions: webview, webview_read, webview_update,
webview_status, webview_close, plus the _version_monitor main loop,
_signal_reload_monitor drain/exec, and lifespan session cleanup.

Targets the uncovered MCP tool paths and auto-reload inner loops.
"""

from __future__ import annotations

import asyncio
import os
import signal
import sys
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import mcp_server
from exceptions import MergeError
from mcp_server import (
    WebviewSession,
    _expand_preset,
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
def _ensure_browser_mode():
    """Ensure browser mode for all tests in this file."""
    old_cached_mode = mcp_server._cached_mode
    old_host_fetched = mcp_server._host_fetched_ui_resource
    old_manager = mcp_server._session_manager
    mcp_server._cached_mode = None
    mcp_server._host_fetched_ui_resource = False
    mcp_server._session_manager = mcp_server.SessionManager()
    yield
    mcp_server._cached_mode = old_cached_mode
    mcp_server._host_fetched_ui_resource = old_host_fetched
    mcp_server._session_manager = old_manager


# ---------------------------------------------------------------------------
# Helper: create a mock session
# ---------------------------------------------------------------------------


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


def _inject_slot(mock_session, name="default"):
    """Inject a mock session into the session manager for testing."""
    slot = mcp_server.SessionSlot(name)
    slot.browser_session = mock_session
    slot.mode = "browser"
    mcp_server._session_manager._slots[name] = slot
    return slot


# ---------------------------------------------------------------------------
# webview tool
# ---------------------------------------------------------------------------


class TestWebviewTool:
    async def test_browser_mode_blocks_and_returns_actions(self):
        """webview in browser mode blocks via wait_for_action and returns result."""
        mock_session = _make_mock_session()
        mock_session.wait_for_action.return_value = {
            "actions": [{"action_id": "ok", "type": "approve"}],
        }

        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles(state={"title": "Test"}, ctx=None)

        # Browser mode returns the wait_for_action result directly (plain dict)
        assert isinstance(result, dict)
        assert "actions" in result
        mock_session.ensure_started.assert_called_once()
        mock_session.write_state.assert_called_once()
        mock_session.wait_for_action.assert_called_once()

    async def test_browser_mode_timeout(self):
        """webview returns timeout error when no user action arrives."""
        mock_session = _make_mock_session()
        mock_session.wait_for_action.return_value = None  # timeout

        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles(state={"title": "Test"}, ctx=None)

        assert "error" in result
        assert "Timed out" in result["error"]

    async def test_browser_mode_starts_session(self):
        """webview starts browser subprocess and clears actions."""
        mock_session = _make_mock_session()
        mock_session.wait_for_action.return_value = {"actions": []}

        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            await openwebgoggles(state={"title": "Test"}, ctx=None)

        mock_session.ensure_started.assert_called_once()
        mock_session.clear_actions.assert_called_once()

    async def test_preset_expansion(self):
        """webview expands preset before writing state."""
        mock_session = _make_mock_session()
        mock_session.wait_for_action.return_value = {"actions": [{"id": "confirm"}]}

        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            await openwebgoggles(
                state={"title": "Confirm?", "message": "Are you sure?"},
                preset="confirm",
                ctx=None,
            )

        # write_state should have been called with expanded state
        call_args = mock_session.write_state.call_args[0][0]
        assert "actions_requested" in call_args

    async def test_preset_error(self):
        """webview returns error when preset expansion fails."""
        with mock.patch("mcp_server._get_browser_session"):
            result = await openwebgoggles(
                state={"title": "Test"},
                preset="nonexistent_preset",
                ctx=None,
            )

        assert "error" in result
        assert "Unknown preset" in result["error"]

    async def test_security_gate_validation_failure(self):
        """webview returns error when state fails security validation."""
        mock_session = _make_mock_session()
        old_gate = mcp_server._security_gate
        mock_gate = mock.MagicMock()
        mock_gate.validate_state.return_value = (False, "XSS detected", [])
        mcp_server._security_gate = mock_gate
        try:
            with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
                result = await openwebgoggles(state={"title": "<script>alert(1)</script>"}, ctx=None)
            assert "error" in result
            assert "validation failed" in result["error"]
        finally:
            mcp_server._security_gate = old_gate

    async def test_ensure_started_failure_raises(self):
        """webview propagates RuntimeError when browser start fails."""
        mock_session = _make_mock_session()
        mock_session.ensure_started = mock.AsyncMock(side_effect=RuntimeError("bind failed"))

        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            with pytest.raises(RuntimeError, match="bind failed"):
                await openwebgoggles(state={"title": "Test"}, ctx=None)


# ---------------------------------------------------------------------------
# webview_read tool
# ---------------------------------------------------------------------------


class TestWebviewReadTool:
    async def test_not_started(self):
        """Returns empty actions when session not started."""
        mock_session = _make_mock_session(started=False)
        _inject_slot(mock_session)
        result = await openwebgoggles_read()
        assert result == {"version": 0, "actions": []}

    async def test_read_actions(self):
        """Returns current actions."""
        mock_session = _make_mock_session()
        mock_session.read_actions.return_value = {
            "version": 1,
            "actions": [{"id": "submit", "type": "approve"}],
        }
        _inject_slot(mock_session)
        result = await openwebgoggles_read()
        assert result["actions"][0]["id"] == "submit"
        mock_session.clear_actions.assert_not_called()

    async def test_read_with_clear(self):
        """Clears actions after reading when clear=True."""
        mock_session = _make_mock_session()
        mock_session.read_actions.return_value = {
            "version": 1,
            "actions": [{"id": "submit"}],
        }
        _inject_slot(mock_session)
        await openwebgoggles_read(clear=True)
        mock_session.clear_actions.assert_called_once()

    async def test_clear_no_actions(self):
        """Does not clear when clear=True but no actions."""
        mock_session = _make_mock_session()
        _inject_slot(mock_session)
        await openwebgoggles_read(clear=True)
        mock_session.clear_actions.assert_not_called()


# ---------------------------------------------------------------------------
# webview_update tool
# ---------------------------------------------------------------------------


class TestWebviewUpdateTool:
    async def test_simple_update(self):
        """Basic non-merge update writes state."""
        mock_session = _make_mock_session()
        mock_session._state_version = 2

        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles_update(state={"title": "Updated"})

        assert result["updated"] is True
        mock_session.write_state.assert_called_once()

    async def test_merge_update(self):
        """Merge update calls merge_state."""
        mock_session = _make_mock_session()
        mock_session.merge_state.return_value = {"version": 3, "title": "Merged"}

        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles_update(state={"data": {"new": True}}, merge=True)

        assert result["updated"] is True
        mock_session.merge_state.assert_called_once()

    async def test_merge_validation_error(self):
        """Merge returns error on ValueError from validator."""
        mock_session = _make_mock_session()
        mock_session.merge_state.side_effect = ValueError("Merged state validation failed")

        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles_update(state={"data": {}}, merge=True)

        assert "error" in result

    async def test_preset_expansion(self):
        """Update expands preset."""
        mock_session = _make_mock_session()

        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles_update(
                state={"tasks": [], "percentage": 50},
                preset="progress",
            )

        assert result["updated"] is True

    async def test_preset_error(self):
        """Update returns error for unknown preset."""
        result = await openwebgoggles_update(state={}, preset="nonexistent")
        assert "error" in result

    async def test_security_gate_failure(self):
        """Update returns error when state fails security validation."""
        mock_session = _make_mock_session()
        old_gate = mcp_server._security_gate
        mock_gate = mock.MagicMock()
        mock_gate.validate_state.return_value = (False, "XSS detected", [])
        mcp_server._security_gate = mock_gate
        try:
            with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
                result = await openwebgoggles_update(state={"title": "bad"})
            assert "error" in result
        finally:
            mcp_server._security_gate = old_gate

    async def test_ensure_started_failure(self):
        """Update returns error when start fails."""
        mock_session = _make_mock_session()
        mock_session.ensure_started = mock.AsyncMock(side_effect=RuntimeError("fail"))

        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles_update(state={"title": "Test"})

        assert "error" in result
        assert "Failed to start" in result["error"]


# ---------------------------------------------------------------------------
# webview_status tool
# ---------------------------------------------------------------------------


class TestWebviewStatusTool:
    async def test_no_session(self):
        """Returns inactive when no session."""
        # Session manager starts empty from fixture — no slot exists
        result = await openwebgoggles_status(session="default")
        assert result["active"] is False
        assert result["mode"] == "browser"

    async def test_session_not_started(self):
        """Returns inactive when session exists but not started."""
        mock_session = _make_mock_session(started=False)
        slot = mcp_server.SessionSlot("default")
        slot.browser_session = mock_session
        slot.mode = "browser"
        mcp_server._session_manager._slots["default"] = slot
        result = await openwebgoggles_status(session="default")
        assert result["active"] is False
        assert result["mode"] == "browser"

    async def test_active_session(self):
        """Returns active session info."""
        mock_session = _make_mock_session()
        slot = mcp_server.SessionSlot("default")
        slot.browser_session = mock_session
        slot.mode = "browser"
        mcp_server._session_manager._slots["default"] = slot
        result = await openwebgoggles_status(session="default")
        assert result["active"] is True
        assert result["mode"] == "browser"
        assert result["alive"] is True
        assert "url" in result
        assert "session_id" in result


# ---------------------------------------------------------------------------
# webview_close tool
# ---------------------------------------------------------------------------


class TestWebviewCloseTool:
    async def test_no_session(self):
        """Returns ok when no active session."""
        # Session manager starts empty from fixture — no slot exists
        result = await openwebgoggles_close()
        assert result["status"] == "ok"
        assert "0 session(s)" in result["message"]

    async def test_close_active_session(self):
        """Closes active session and clears slot."""
        mock_session = _make_mock_session()
        _inject_slot(mock_session)
        result = await openwebgoggles_close(message="Goodbye", session="default")
        assert result["status"] == "ok"
        assert "default" not in mcp_server._session_manager._slots
        mock_session.close.assert_called_once_with(message="Goodbye")

    async def test_close_error_gracefully_handled(self):
        """Close handles error in session close gracefully."""
        mock_session = _make_mock_session()
        mock_session.close = mock.AsyncMock(side_effect=Exception("close failed"))
        _inject_slot(mock_session)
        result = await openwebgoggles_close(session="default")
        # _close_slot catches exceptions and logs, doesn't return error
        assert result["status"] == "ok"

    async def test_close_not_started(self):
        """Returns ok when session exists but not started."""
        mock_session = _make_mock_session(started=False)
        slot = mcp_server.SessionSlot("default")
        slot.browser_session = mock_session
        slot.mode = "browser"
        mcp_server._session_manager._slots["default"] = slot
        result = await openwebgoggles_close()
        assert result["status"] == "ok"


# ---------------------------------------------------------------------------
# _stop_any_running_server
# ---------------------------------------------------------------------------


class TestStopAnyRunningServer:
    """_stop_any_running_server kills processes found via PID files."""

    def test_kills_process_from_pid_file(self, tmp_path):
        """Sends SIGTERM then waits; probe raises ProcessLookupError → no SIGKILL needed."""
        data_dir = tmp_path / ".openwebgoggles"
        data_dir.mkdir()
        pid_file = data_dir / ".server.pid"
        pid = os.getpid()
        pid_file.write_text(str(pid))

        # First call: SIGTERM (no-op). Second call: probe(0) → process dead.
        call_count = {"n": 0}

        def kill_se(p, sig):
            call_count["n"] += 1
            if sig == 0:
                raise ProcessLookupError("dead")

        with (
            mock.patch("mcp_server.Path.cwd", return_value=tmp_path),
            mock.patch("mcp_server.os.kill", side_effect=kill_se) as mock_kill,
            mock.patch("mcp_server.time.sleep"),
        ):
            mcp_server._stop_any_running_server()

        assert mock_kill.call_args_list[0] == mock.call(pid, signal.SIGTERM)
        assert not pid_file.exists(), "PID file must be removed after stop"

    def test_no_pid_file_is_noop(self, tmp_path):
        """Does nothing when no PID file exists."""
        with (
            mock.patch("mcp_server.Path.cwd", return_value=tmp_path),
            mock.patch("mcp_server.os.kill") as mock_kill,
        ):
            mcp_server._stop_any_running_server()

        mock_kill.assert_not_called()

    def test_dead_process_is_silently_ignored(self, tmp_path):
        """ProcessLookupError (process already dead) is swallowed and PID file removed."""
        data_dir = tmp_path / ".openwebgoggles"
        data_dir.mkdir()
        pid_file = data_dir / ".server.pid"
        pid_file.write_text("99999")

        with (
            mock.patch("mcp_server.Path.cwd", return_value=tmp_path),
            mock.patch("mcp_server.os.kill", side_effect=ProcessLookupError),
        ):
            mcp_server._stop_any_running_server()  # must not raise

        assert not pid_file.exists(), "Stale PID file must be cleaned up"

    def test_invalid_pid_content_is_skipped(self, tmp_path):
        """Non-numeric PID file content does not call kill and leaves file intact."""
        data_dir = tmp_path / ".openwebgoggles"
        data_dir.mkdir()
        pid_file = data_dir / ".server.pid"
        pid_file.write_text("not-a-pid")

        with (
            mock.patch("mcp_server.Path.cwd", return_value=tmp_path),
            mock.patch("mcp_server.os.kill") as mock_kill,
        ):
            mcp_server._stop_any_running_server()

        mock_kill.assert_not_called()
        assert pid_file.exists(), "Invalid PID file must not be removed"

    async def test_close_app_mode_calls_stop_server(self):
        """openwebgoggles_close in app mode calls _stop_any_running_server."""
        old_mode = mcp_server._cached_mode
        mcp_server._cached_mode = "app"
        try:
            with mock.patch("mcp_server._stop_any_running_server") as mock_stop:
                await openwebgoggles_close()
            mock_stop.assert_called_once()
        finally:
            mcp_server._cached_mode = old_mode

    async def test_close_browser_mode_calls_stop_server(self):
        """openwebgoggles_close in browser mode calls _stop_any_running_server."""
        old_mode = mcp_server._cached_mode
        mcp_server._cached_mode = "browser"
        # Session manager starts empty from fixture — no slot exists
        try:
            with mock.patch("mcp_server._stop_any_running_server") as mock_stop:
                await openwebgoggles_close()
            mock_stop.assert_called_once()
        finally:
            mcp_server._cached_mode = old_mode


# ---------------------------------------------------------------------------
# _version_monitor main loop
# ---------------------------------------------------------------------------


class TestVersionMonitorLoop:
    async def test_mtime_change_triggers_version_check(self):
        """When mtime changes and version changes, triggers reload."""
        mock_dist_path = mock.MagicMock()
        mock_dist_path.is_dir.return_value = True
        mock_stat1 = mock.MagicMock()
        mock_stat1.st_mtime = 100.0
        mock_stat2 = mock.MagicMock()
        mock_stat2.st_mtime = 200.0
        mock_dist_path.stat.side_effect = [mock_stat1, mock_stat2]

        with mock.patch("mcp_server._RELOAD_CHECK_INTERVAL", 0.2):
            with mock.patch("mcp_server._get_installed_version_info", return_value=("1.0.0", mock_dist_path)):
                with mock.patch("mcp_server._read_version_fresh", return_value="2.0.0"):
                    with mock.patch("mcp_server._mark_stale") as mock_stale:
                        old_pending = mcp_server._reload_pending
                        old_active = mcp_server._active_tool_calls
                        mcp_server._reload_pending = False
                        mcp_server._active_tool_calls = 0
                        # Session manager starts empty from fixture
                        try:
                            task = asyncio.create_task(mcp_server._version_monitor())
                            await asyncio.sleep(1.0)
                            task.cancel()
                            try:
                                await task
                            except asyncio.CancelledError:
                                pass

                            assert mock_stale.called
                        finally:
                            mcp_server._reload_pending = old_pending
                            mcp_server._active_tool_calls = old_active

    async def test_mtime_unchanged_skips_version_read(self):
        """When mtime doesn't change, skips version read."""
        mock_dist_path = mock.MagicMock()
        mock_dist_path.is_dir.return_value = True
        mock_stat = mock.MagicMock()
        mock_stat.st_mtime = 100.0
        mock_dist_path.stat.return_value = mock_stat

        with mock.patch("mcp_server._RELOAD_CHECK_INTERVAL", 0.2):
            with mock.patch("mcp_server._get_installed_version_info", return_value=("1.0.0", mock_dist_path)):
                with mock.patch("mcp_server._read_version_fresh") as mock_read_fresh:
                    task = asyncio.create_task(mcp_server._version_monitor())
                    await asyncio.sleep(1.0)
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass

                    # Should not have read fresh version since mtime didn't change
                    mock_read_fresh.assert_not_called()

    async def test_same_version_after_mtime_change(self):
        """When mtime changes but version is the same, should not reload."""
        mock_dist_path = mock.MagicMock()
        mock_dist_path.is_dir.return_value = True
        mock_dist_path.stat.side_effect = [mock.MagicMock(st_mtime=100.0), mock.MagicMock(st_mtime=200.0)]

        new_dist_path = mock.MagicMock()
        new_dist_path.is_dir.return_value = True
        new_dist_path.stat.return_value = mock.MagicMock(st_mtime=200.0)

        with mock.patch("mcp_server._RELOAD_CHECK_INTERVAL", 0.2):
            with mock.patch(
                "mcp_server._get_installed_version_info",
                side_effect=[
                    ("1.0.0", mock_dist_path),
                    ("1.0.0", new_dist_path),
                ]
                + [("1.0.0", new_dist_path)] * 20,
            ):
                with mock.patch("mcp_server._read_version_fresh", return_value="1.0.0"):
                    with mock.patch("mcp_server._mark_stale") as mock_stale:
                        task = asyncio.create_task(mcp_server._version_monitor())
                        await asyncio.sleep(1.0)
                        task.cancel()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass

                        mock_stale.assert_not_called()

    async def test_unknown_version_during_upgrade(self):
        """When version becomes 'unknown' during upgrade, should retry."""
        mock_dist_path = mock.MagicMock()
        mock_dist_path.is_dir.return_value = True
        mock_dist_path.stat.side_effect = OSError("gone")

        with mock.patch("mcp_server._RELOAD_CHECK_INTERVAL", 0.2):
            with mock.patch("mcp_server._get_installed_version_info", return_value=("1.0.0", mock_dist_path)):
                with mock.patch("mcp_server._read_version_fresh", return_value="unknown"):
                    with mock.patch("mcp_server._mark_stale") as mock_stale:
                        task = asyncio.create_task(mcp_server._version_monitor())
                        await asyncio.sleep(1.0)
                        task.cancel()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass

                        mock_stale.assert_not_called()

    async def test_marks_stale_even_with_active_tool_calls(self):
        """Version monitor marks stale immediately regardless of active tool calls."""
        mock_dist_path = mock.MagicMock()
        mock_dist_path.is_dir.return_value = True
        mock_dist_path.stat.side_effect = [
            mock.MagicMock(st_mtime=100.0),
            mock.MagicMock(st_mtime=200.0),
        ]

        old_active = mcp_server._active_tool_calls
        old_pending = mcp_server._reload_pending
        mcp_server._active_tool_calls = 1
        mcp_server._reload_pending = False
        # Session manager starts empty from fixture

        try:
            with mock.patch("mcp_server._RELOAD_CHECK_INTERVAL", 0.2):
                with mock.patch("mcp_server._get_installed_version_info", return_value=("1.0.0", mock_dist_path)):
                    with mock.patch("mcp_server._read_version_fresh", return_value="2.0.0"):
                        with mock.patch("mcp_server._mark_stale") as mock_stale:
                            task = asyncio.create_task(mcp_server._version_monitor())
                            await asyncio.sleep(1.5)
                            task.cancel()
                            try:
                                await task
                            except asyncio.CancelledError:
                                pass

                            # _mark_stale is called immediately without draining
                            assert mock_stale.called
                            assert mcp_server._reload_pending
        finally:
            mcp_server._active_tool_calls = old_active
            mcp_server._reload_pending = old_pending

    async def test_closes_session_before_reload(self):
        """Version monitor closes webview session before reloading."""
        mock_dist_path = mock.MagicMock()
        mock_dist_path.is_dir.return_value = True
        mock_dist_path.stat.side_effect = [
            mock.MagicMock(st_mtime=100.0),
            mock.MagicMock(st_mtime=200.0),
        ]

        mock_session = _make_mock_session()
        old_pending = mcp_server._reload_pending
        old_active = mcp_server._active_tool_calls
        slot = mcp_server.SessionSlot("default")
        slot.browser_session = mock_session
        slot.mode = "browser"
        mcp_server._session_manager._slots["default"] = slot
        mcp_server._reload_pending = False
        mcp_server._active_tool_calls = 0

        try:
            with mock.patch("mcp_server._RELOAD_CHECK_INTERVAL", 0.2):
                with mock.patch("mcp_server._get_installed_version_info", return_value=("1.0.0", mock_dist_path)):
                    with mock.patch("mcp_server._read_version_fresh", return_value="2.0.0"):
                        with mock.patch("mcp_server._mark_stale"):
                            task = asyncio.create_task(mcp_server._version_monitor())
                            await asyncio.sleep(1.0)
                            task.cancel()
                            try:
                                await task
                            except asyncio.CancelledError:
                                pass

                            mock_session.close.assert_called()
        finally:
            mcp_server._reload_pending = old_pending
            mcp_server._active_tool_calls = old_active

    async def test_exception_in_loop_retries(self):
        """General exceptions in version monitor are logged and retried."""
        mock_dist_path = mock.MagicMock()
        mock_dist_path.is_dir.return_value = True
        call_count = [0]

        def stat_effect():
            call_count[0] += 1
            if call_count[0] == 1:
                return mock.MagicMock(st_mtime=100.0)
            raise RuntimeError("unexpected error")

        mock_dist_path.stat = stat_effect

        with mock.patch("mcp_server._RELOAD_CHECK_INTERVAL", 0.2):
            with mock.patch("mcp_server._get_installed_version_info", return_value=("1.0.0", mock_dist_path)):
                task = asyncio.create_task(mcp_server._version_monitor())
                await asyncio.sleep(1.5)
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                # Should have survived the error


# ---------------------------------------------------------------------------
# _signal_reload_monitor drain and exec
# ---------------------------------------------------------------------------


class TestSignalReloadMonitorDrain:
    async def test_drains_and_reloads(self):
        """Signal monitor drains tool calls then reloads."""
        old_flag = mcp_server._signal_reload_requested
        old_pending = mcp_server._reload_pending
        old_active = mcp_server._active_tool_calls

        mcp_server._signal_reload_requested = True
        mcp_server._reload_pending = False
        mcp_server._active_tool_calls = 0
        # Session manager starts empty from fixture

        try:
            with mock.patch("mcp_server._mark_stale") as mock_stale:
                task = asyncio.create_task(mcp_server._signal_reload_monitor())
                await asyncio.sleep(1.5)
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

                assert mock_stale.called
        finally:
            mcp_server._signal_reload_requested = old_flag
            mcp_server._reload_pending = old_pending
            mcp_server._active_tool_calls = old_active

    async def test_closes_session_before_mark_stale(self):
        """Signal monitor closes session before marking stale."""
        mock_session = _make_mock_session()
        old_flag = mcp_server._signal_reload_requested
        old_pending = mcp_server._reload_pending
        old_active = mcp_server._active_tool_calls

        mcp_server._signal_reload_requested = True
        mcp_server._reload_pending = False
        mcp_server._active_tool_calls = 0
        slot = mcp_server.SessionSlot("default")
        slot.browser_session = mock_session
        slot.mode = "browser"
        mcp_server._session_manager._slots["default"] = slot

        try:
            with mock.patch("mcp_server._mark_stale"):
                task = asyncio.create_task(mcp_server._signal_reload_monitor())
                await asyncio.sleep(1.5)
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

                mock_session.close.assert_called()
        finally:
            mcp_server._signal_reload_requested = old_flag
            mcp_server._reload_pending = old_pending
            mcp_server._active_tool_calls = old_active


# ---------------------------------------------------------------------------
# lifespan session cleanup
# ---------------------------------------------------------------------------


class TestLifespanSessionCleanup:
    async def test_closes_session_on_shutdown(self):
        """Lifespan cleans up active session on MCP server shutdown."""
        mock_session = _make_mock_session()

        async def fake_version_monitor():
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                return

        async def fake_signal_monitor():
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                return

        with mock.patch("mcp_server._write_mcp_pid"):
            with mock.patch("mcp_server._cleanup_mcp_pid"):
                with mock.patch("mcp_server._version_monitor", side_effect=fake_version_monitor):
                    with mock.patch("mcp_server._signal_reload_monitor", side_effect=fake_signal_monitor):
                        slot = mcp_server.SessionSlot("default")
                        slot.browser_session = mock_session
                        slot.mode = "browser"
                        mcp_server._session_manager._slots["default"] = slot
                        fake_server = mock.MagicMock()
                        async with mcp_server.lifespan(fake_server):
                            pass
                        mock_session.close.assert_called_once()
                        assert "default" not in mcp_server._session_manager._slots

    async def test_session_close_exception_suppressed(self):
        """Lifespan suppresses exceptions during session close."""
        mock_session = _make_mock_session()
        mock_session.close = mock.AsyncMock(side_effect=RuntimeError("cleanup fail"))

        async def fake_version_monitor():
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                return

        async def fake_signal_monitor():
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                return

        with mock.patch("mcp_server._write_mcp_pid"):
            with mock.patch("mcp_server._cleanup_mcp_pid"):
                with mock.patch("mcp_server._version_monitor", side_effect=fake_version_monitor):
                    with mock.patch("mcp_server._signal_reload_monitor", side_effect=fake_signal_monitor):
                        slot = mcp_server.SessionSlot("default")
                        slot.browser_session = mock_session
                        slot.mode = "browser"
                        mcp_server._session_manager._slots["default"] = slot
                        fake_server = mock.MagicMock()
                        async with mcp_server.lifespan(fake_server):
                            pass
                        # Should not raise
                        assert "default" not in mcp_server._session_manager._slots


# ---------------------------------------------------------------------------
# _expand_preset
# ---------------------------------------------------------------------------


class TestExpandPreset:
    def test_progress_preset(self):
        state = _expand_preset("progress", {"title": "Building", "tasks": [{"label": "Build"}], "percentage": 42})
        assert state["data"]["sections"][0]["type"] == "progress"
        assert state["data"]["sections"][0]["percentage"] == 42

    def test_confirm_preset(self):
        state = _expand_preset("confirm", {"title": "OK?", "message": "Sure?", "details": "More info"})
        assert state["status"] == "pending_review"
        assert state["actions_requested"][0]["type"] == "approve"
        assert state["data"]["sections"][0]["content"] == "More info"

    def test_log_preset(self):
        state = _expand_preset("log", {"title": "Log", "lines": ["line1", "line2"]})
        assert state["data"]["sections"][0]["type"] == "log"
        assert state["data"]["sections"][0]["lines"] == ["line1", "line2"]

    def test_unknown_preset_raises(self):
        with pytest.raises(ValueError, match="Unknown preset"):
            _expand_preset("invalid", {})

    def test_form_wizard_preset(self):
        steps = [
            {"title": "Name", "fields": [{"key": "name", "label": "Name", "type": "text"}]},
            {"title": "Confirm", "fields": [{"key": "ok", "label": "OK?", "type": "checkbox"}]},
        ]
        state = _expand_preset("form-wizard", {"title": "Setup", "steps": steps, "step": 0})
        assert "pages" in state
        assert "step_0" in state["pages"]
        assert "step_1" in state["pages"]
        assert state["active_page"] == "step_0"
        assert state["message"] == "Step 1 of 2"
        # Step 0 has Next but no Previous
        actions_0 = state["pages"]["step_0"]["actions_requested"]
        assert any(a["id"] == "next_0" for a in actions_0)
        assert not any(a["id"].startswith("prev") for a in actions_0)
        # Step 1 (last) has Previous + Submit
        actions_1 = state["pages"]["step_1"]["actions_requested"]
        assert any(a["id"].startswith("prev") for a in actions_1)
        assert any(a["id"] == "submit" for a in actions_1)

    def test_form_wizard_step_index(self):
        steps = [{"title": "A"}, {"title": "B"}, {"title": "C"}]
        state = _expand_preset("form-wizard", {"steps": steps, "step": 1})
        assert state["active_page"] == "step_1"
        assert state["message"] == "Step 2 of 3"

    def test_triage_preset(self):
        items = [
            {"title": "Bug #1", "subtitle": "High", "description": "Crash on login"},
            {"title": "Bug #2", "subtitle": "Low"},
        ]
        state = _expand_preset("triage", {"title": "Bug Triage", "items": items, "current": 0})
        assert state["status"] == "pending_review"
        assert state["message"] == "Item 1 of 2"
        action_ids = {a["id"] for a in state["actions_requested"]}
        assert "approve" in action_ids
        assert "reject" in action_ids
        assert "skip" in action_ids
        # Description becomes a text section
        sections = state["data"]["sections"]
        text_secs = [s for s in sections if s["type"] == "text"]
        assert any("Crash on login" in s["content"] for s in text_secs)

    def test_triage_preset_second_item(self):
        items = [{"title": "X"}, {"title": "Y"}]
        state = _expand_preset("triage", {"items": items, "current": 1})
        assert state["message"] == "Item 2 of 2"

    def test_dashboard_preset(self):
        metrics = [
            {"label": "Revenue", "value": "$1.2M", "delta": "+5%", "trend": "up"},
            {"label": "Users", "value": "42K"},
        ]
        state = _expand_preset("dashboard", {"title": "KPIs", "metrics": metrics})
        assert state["status"] == "complete"
        sec = state["data"]["sections"][0]
        assert sec["type"] == "metric"
        assert len(sec["cards"]) == 2
        assert sec["cards"][0]["label"] == "Revenue"
        assert sec["cards"][0]["delta"] == "+5%"
        assert "delta" not in sec["cards"][1]  # not provided

    def test_dashboard_preset_columns_default(self):
        metrics = [{"label": "A", "value": "1"}, {"label": "B", "value": "2"}]
        state = _expand_preset("dashboard", {"metrics": metrics})
        assert state["data"]["sections"][0]["columns"] == 2  # min(len, 4)

    def test_table_actions_preset(self):
        columns = [{"key": "name", "label": "Name"}, {"key": "status", "label": "Status"}]
        rows = [{"name": "Alice", "status": "active"}]
        state = _expand_preset("table-actions", {"columns": columns, "rows": rows, "title": "Users"})
        assert state["status"] == "pending_review"
        assert state["data"]["sections"][0]["type"] == "table"
        assert state["data"]["sections"][0]["rows"] == rows
        assert len(state["actions_requested"]) == 2
        assert state["actions_requested"][0]["id"] == "confirm"

    def test_table_actions_preset_custom_actions(self):
        custom = [{"id": "delete", "label": "Delete", "type": "reject"}]
        state = _expand_preset("table-actions", {"columns": [], "rows": [], "actions": custom})
        assert state["actions_requested"] == custom

    def test_stepper_preset(self):
        steps = [
            {"label": "Fetch", "status": "completed"},
            {"label": "Build", "status": "in_progress"},
            {"label": "Deploy", "status": "pending"},
        ]
        state = _expand_preset("stepper", {"title": "CI/CD", "steps": steps, "percentage": 60})
        assert state["status"] == "processing"
        sec = state["data"]["sections"][0]
        assert sec["type"] == "progress"
        assert len(sec["tasks"]) == 3
        assert sec["tasks"][0]["status"] == "completed"
        assert sec["percentage"] == 60

    def test_stepper_preset_message(self):
        state = _expand_preset("stepper", {"steps": [], "message": "Running..."})
        assert state["message"] == "Running..."

    def test_stepper_preset_no_percentage_when_omitted(self):
        state = _expand_preset("stepper", {"steps": []})
        assert "percentage" not in state["data"]["sections"][0]


# ---------------------------------------------------------------------------
# End-to-end integration: metric / chart / clickable table / pages
# through webview() and webview_update() (SecurityGate + session)
# ---------------------------------------------------------------------------


class TestWebviewMetricIntegration:
    """End-to-end: metric card states through webview() + SecurityGate."""

    async def test_metric_cards_basic(self):
        """Full metric card state passes SecurityGate and reaches session."""
        mock_session = _make_mock_session()
        mock_session.wait_for_action.return_value = {"actions": [{"id": "ok"}]}

        state = {
            "title": "Dashboard",
            "data": {
                "sections": [
                    {
                        "type": "metric",
                        "title": "KPIs",
                        "columns": 3,
                        "cards": [
                            {"label": "Users", "value": 1205},
                            {"label": "Revenue", "value": "$12.3k", "change": "+8%", "changeDirection": "up"},
                            {"label": "Errors", "value": "0.3%", "changeDirection": "down"},
                        ],
                    }
                ]
            },
        }
        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles(state=state, ctx=None)

        assert "error" not in result
        # State should have been written to the session
        mock_session.write_state.assert_called_once()
        written = mock_session.write_state.call_args[0][0]
        assert written["data"]["sections"][0]["type"] == "metric"

    async def test_metric_with_sparkline(self):
        """Metric cards with sparkline arrays pass end-to-end."""
        mock_session = _make_mock_session()
        mock_session.wait_for_action.return_value = {"actions": []}

        state = {
            "title": "Metrics",
            "data": {
                "sections": [
                    {
                        "type": "metric",
                        "cards": [
                            {
                                "label": "Latency",
                                "value": "142ms",
                                "sparkline": [180, 165, 155, 148, 145, 143, 142, 142],
                            }
                        ],
                    }
                ]
            },
        }
        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles(state=state, ctx=None)

        assert "error" not in result

    async def test_metric_xss_in_label_rejected(self):
        """XSS in metric card label is caught by SecurityGate."""
        state = {
            "title": "Dashboard",
            "data": {
                "sections": [
                    {
                        "type": "metric",
                        "cards": [{"label": '<img src=x onerror="alert(1)">', "value": 100}],
                    }
                ]
            },
        }
        mock_session = _make_mock_session()
        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles(state=state, ctx=None)

        assert "error" in result
        assert "validation failed" in result["error"]


class TestWebviewChartIntegration:
    """End-to-end: chart states through webview() + SecurityGate."""

    async def test_bar_chart(self):
        """Bar chart state passes SecurityGate end-to-end."""
        mock_session = _make_mock_session()
        mock_session.wait_for_action.return_value = {"actions": [{"id": "ok"}]}

        state = {
            "title": "Sales",
            "data": {
                "sections": [
                    {
                        "type": "chart",
                        "chartType": "bar",
                        "title": "Monthly Revenue",
                        "data": {
                            "labels": ["Jan", "Feb", "Mar", "Apr"],
                            "datasets": [{"label": "Revenue", "values": [1200, 1900, 3000, 5000], "color": "blue"}],
                        },
                        "options": {"width": 600, "height": 300, "showLegend": True, "showGrid": True},
                    }
                ]
            },
        }
        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles(state=state, ctx=None)

        assert "error" not in result

    async def test_line_chart_with_multiple_datasets(self):
        """Line chart with multiple datasets passes end-to-end."""
        mock_session = _make_mock_session()
        mock_session.wait_for_action.return_value = {"actions": []}

        state = {
            "title": "Trends",
            "data": {
                "sections": [
                    {
                        "type": "chart",
                        "chartType": "line",
                        "data": {
                            "labels": ["Mon", "Tue", "Wed", "Thu", "Fri"],
                            "datasets": [
                                {"label": "Requests", "values": [800, 1200, 2800, 3200, 2100], "color": "#58a6ff"},
                                {"label": "Errors", "values": [2, 5, 12, 8, 4], "color": "red"},
                            ],
                        },
                    }
                ]
            },
        }
        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles(state=state, ctx=None)

        assert "error" not in result

    async def test_pie_chart(self):
        """Pie chart with theme-aliased colors passes end-to-end."""
        mock_session = _make_mock_session()
        mock_session.wait_for_action.return_value = {"actions": []}

        state = {
            "title": "Distribution",
            "data": {
                "sections": [
                    {
                        "type": "chart",
                        "chartType": "pie",
                        "data": {
                            "labels": ["Healthy", "Warning", "Critical"],
                            "datasets": [{"values": [5, 1, 0], "colors": ["green", "yellow", "red"]}],
                        },
                        "options": {"width": 300, "height": 300},
                    }
                ]
            },
        }
        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles(state=state, ctx=None)

        assert "error" not in result

    async def test_area_chart(self):
        """Area chart type passes end-to-end."""
        mock_session = _make_mock_session()
        mock_session.wait_for_action.return_value = {"actions": []}

        state = {
            "title": "Area",
            "data": {
                "sections": [
                    {
                        "type": "chart",
                        "chartType": "area",
                        "data": {
                            "labels": ["A", "B", "C"],
                            "datasets": [{"values": [10, 20, 15], "color": "cyan"}],
                        },
                    }
                ]
            },
        }
        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles(state=state, ctx=None)

        assert "error" not in result

    async def test_donut_chart(self):
        """Donut chart type passes end-to-end."""
        mock_session = _make_mock_session()
        mock_session.wait_for_action.return_value = {"actions": []}

        state = {
            "title": "Donut",
            "data": {
                "sections": [
                    {
                        "type": "chart",
                        "chartType": "donut",
                        "data": {
                            "labels": ["A", "B"],
                            "datasets": [{"values": [60, 40], "colors": ["purple", "orange"]}],
                        },
                    }
                ]
            },
        }
        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles(state=state, ctx=None)

        assert "error" not in result

    async def test_sparkline_chart(self):
        """Sparkline chart type passes end-to-end."""
        mock_session = _make_mock_session()
        mock_session.wait_for_action.return_value = {"actions": []}

        state = {
            "title": "Spark",
            "data": {
                "sections": [
                    {
                        "type": "chart",
                        "chartType": "sparkline",
                        "data": {"datasets": [{"values": [1, 3, 2, 5, 4, 6]}]},
                    }
                ]
            },
        }
        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles(state=state, ctx=None)

        assert "error" not in result

    async def test_chart_xss_in_color_rejected(self):
        """XSS in chart color is caught by SecurityGate."""
        state = {
            "title": "XSS",
            "data": {
                "sections": [
                    {
                        "type": "chart",
                        "chartType": "bar",
                        "data": {
                            "labels": ["A"],
                            "datasets": [{"values": [1], "color": "javascript:alert(1)"}],
                        },
                    }
                ]
            },
        }
        mock_session = _make_mock_session()
        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles(state=state, ctx=None)

        assert "error" in result

    async def test_chart_invalid_type_rejected(self):
        """Invalid chart type is caught by SecurityGate."""
        state = {
            "title": "Bad",
            "data": {
                "sections": [
                    {
                        "type": "chart",
                        "chartType": "histogram",
                        "data": {"labels": ["A"], "datasets": [{"values": [1]}]},
                    }
                ]
            },
        }
        mock_session = _make_mock_session()
        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles(state=state, ctx=None)

        assert "error" in result


class TestWebviewClickableTableIntegration:
    """End-to-end: clickable table states through webview() + SecurityGate."""

    async def test_clickable_table_passes(self):
        """Clickable table with actionId passes SecurityGate end-to-end."""
        mock_session = _make_mock_session()
        mock_session.wait_for_action.return_value = {"actions": []}

        state = {
            "title": "Servers",
            "data": {
                "sections": [
                    {
                        "type": "table",
                        "columns": [{"key": "name", "label": "Server"}, {"key": "status", "label": "Status"}],
                        "rows": [
                            {"name": "web-01", "status": "healthy"},
                            {"name": "api-01", "status": "warning"},
                        ],
                        "clickable": True,
                        "clickActionId": "server_detail",
                    }
                ]
            },
        }
        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles(state=state, ctx=None)

        assert "error" not in result

    async def test_clickable_plus_selectable(self):
        """Clickable + selectable table coexist end-to-end."""
        mock_session = _make_mock_session()
        mock_session.wait_for_action.return_value = {"actions": []}

        state = {
            "title": "Fleet",
            "data": {
                "sections": [
                    {
                        "type": "table",
                        "columns": [{"key": "name", "label": "Name"}],
                        "rows": [{"name": "srv-1"}],
                        "clickable": True,
                        "clickActionId": "detail",
                        "selectable": True,
                    }
                ]
            },
        }
        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles(state=state, ctx=None)

        assert "error" not in result


class TestWebviewPagesIntegration:
    """End-to-end: multi-page SPA states through webview() + SecurityGate."""

    async def test_basic_pages(self):
        """Multi-page dashboard state passes SecurityGate end-to-end."""
        mock_session = _make_mock_session()
        mock_session.wait_for_action.return_value = {"actions": []}

        state = {
            "title": "Dashboard",
            "pages": {
                "overview": {
                    "label": "Overview",
                    "data": {
                        "sections": [
                            {
                                "type": "metric",
                                "cards": [{"label": "Users", "value": 1205}],
                            }
                        ]
                    },
                },
                "charts": {
                    "label": "Charts",
                    "data": {
                        "sections": [
                            {
                                "type": "chart",
                                "chartType": "bar",
                                "data": {"labels": ["A", "B"], "datasets": [{"values": [10, 20]}]},
                            }
                        ]
                    },
                },
            },
            "activePage": "overview",
        }
        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles(state=state, ctx=None)

        assert "error" not in result

    async def test_pages_with_clickable_table(self):
        """Pages containing clickable table + chart sections pass end-to-end."""
        mock_session = _make_mock_session()
        mock_session.wait_for_action.return_value = {"actions": []}

        state = {
            "title": "Server Dashboard",
            "pages": {
                "servers": {
                    "label": "Servers",
                    "data": {
                        "sections": [
                            {
                                "type": "table",
                                "columns": [{"key": "name", "label": "Server"}],
                                "rows": [{"name": "web-01"}],
                                "clickable": True,
                                "clickActionId": "srv_detail",
                            }
                        ]
                    },
                },
                "health": {
                    "label": "Health",
                    "data": {
                        "sections": [
                            {
                                "type": "chart",
                                "chartType": "pie",
                                "data": {
                                    "labels": ["OK", "Warn"],
                                    "datasets": [{"values": [5, 1], "colors": ["green", "yellow"]}],
                                },
                            }
                        ]
                    },
                },
            },
            "activePage": "servers",
        }
        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles(state=state, ctx=None)

        assert "error" not in result

    async def test_pages_with_actions_and_log(self):
        """Pages can include page-level actions_requested and log sections."""
        mock_session = _make_mock_session()
        mock_session.wait_for_action.return_value = {"actions": []}

        state = {
            "title": "Dash",
            "pages": {
                "logs": {
                    "label": "Logs",
                    "data": {
                        "sections": [
                            {
                                "type": "log",
                                "lines": ["[INFO] server started", "[WARN] high CPU"],
                            }
                        ]
                    },
                    "actions_requested": [{"id": "refresh", "label": "Refresh", "type": "primary"}],
                }
            },
            "activePage": "logs",
        }
        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles(state=state, ctx=None)

        assert "error" not in result

    async def test_pages_invalid_active_page_rejected(self):
        """activePage not in pages dict is caught by SecurityGate."""
        state = {
            "title": "Bad",
            "pages": {
                "overview": {
                    "label": "Overview",
                    "data": {"sections": [{"type": "text", "content": "hi"}]},
                }
            },
            "activePage": "nonexistent",
        }
        mock_session = _make_mock_session()
        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles(state=state, ctx=None)

        assert "error" in result

    async def test_full_dashboard_example(self):
        """The examples/dashboard/state.json passes SecurityGate end-to-end."""
        import json
        from pathlib import Path

        example = Path(__file__).resolve().parent.parent.parent / "examples" / "dashboard" / "state.json"
        if not example.exists():
            pytest.skip("Dashboard example not found")

        state = json.loads(example.read_text())
        mock_session = _make_mock_session()
        mock_session.wait_for_action.return_value = {"actions": []}

        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles(state=state, ctx=None)

        assert "error" not in result
        mock_session.write_state.assert_called_once()


class TestWebviewUpdatePagesIntegration:
    """End-to-end: webview_update with merge=True on pages states."""

    async def test_merge_add_new_page(self):
        """webview_update(merge=True) can add a new page to existing pages."""
        mock_session = _make_mock_session()
        # merge_state should be called for merge updates
        mock_session.merge_state.return_value = {"version": 2}

        state = {
            "pages": {
                "new_page": {
                    "label": "New",
                    "data": {"sections": [{"type": "text", "content": "hello"}]},
                }
            }
        }
        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles_update(state=state, merge=True)

        assert result["updated"] is True
        mock_session.merge_state.assert_called_once()

    async def test_merge_update_page_data(self):
        """webview_update(merge=True) can update sections in an existing page."""
        mock_session = _make_mock_session()
        mock_session.merge_state.return_value = {"version": 3}

        state = {
            "pages": {
                "overview": {
                    "data": {
                        "sections": [
                            {
                                "type": "metric",
                                "cards": [{"label": "Users", "value": 1500}],
                            }
                        ]
                    }
                }
            }
        }
        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles_update(state=state, merge=True)

        assert result["updated"] is True

    async def test_merge_change_active_page(self):
        """webview_update(merge=True) can change activePage."""
        mock_session = _make_mock_session()
        mock_session.merge_state.return_value = {"version": 4}

        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles_update(state={"activePage": "servers"}, merge=True)

        assert result["updated"] is True

    async def test_non_merge_full_pages_state(self):
        """webview_update without merge replaces entire state including pages."""
        mock_session = _make_mock_session()

        state = {
            "title": "New Dashboard",
            "pages": {
                "main": {
                    "label": "Main",
                    "data": {
                        "sections": [
                            {
                                "type": "chart",
                                "chartType": "line",
                                "data": {"labels": ["A"], "datasets": [{"values": [1]}]},
                            }
                        ]
                    },
                }
            },
            "activePage": "main",
        }
        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles_update(state=state)

        assert result["updated"] is True
        mock_session.write_state.assert_called_once()

    async def test_mixed_metric_chart_update(self):
        """Non-merge update with mixed metric + chart sections passes."""
        mock_session = _make_mock_session()

        state = {
            "title": "Real-time",
            "data": {
                "sections": [
                    {
                        "type": "metric",
                        "cards": [
                            {"label": "RPS", "value": "2,847", "change": "+12%", "changeDirection": "up"},
                            {"label": "P95", "value": "142", "unit": "ms"},
                        ],
                    },
                    {
                        "type": "chart",
                        "chartType": "line",
                        "data": {
                            "labels": ["00:00", "04:00", "08:00", "12:00"],
                            "datasets": [{"label": "Requests", "values": [800, 420, 1200, 2800], "color": "blue"}],
                        },
                        "options": {"showGrid": True, "showLegend": True},
                    },
                ]
            },
        }
        with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
            result = await openwebgoggles_update(state=state)

        assert result["updated"] is True


# ---------------------------------------------------------------------------
# main() entry point -- MCP server mode
# ---------------------------------------------------------------------------


class TestMainMCPMode:
    def test_default_mcp_server_mode(self):
        """When no subcommand, runs MCP server with stdio transport."""
        with mock.patch("sys.argv", ["openwebgoggles"]):
            with mock.patch("mcp_server._mcp_import_error", None):
                with mock.patch("platform.system", return_value="Linux"):
                    with mock.patch("signal.signal"):
                        with mock.patch("logging.basicConfig"):
                            with mock.patch("mcp_server.mcp") as mock_mcp:
                                mcp_server.main()
                                mock_mcp.run.assert_called_once_with(transport="stdio")

    def test_init_default_dir(self, tmp_path):
        """Init without explicit dir uses default."""
        with mock.patch("sys.argv", ["openwebgoggles", "init", "claude"]):
            with mock.patch("mcp_server._EDITOR_DEFAULT_DIRS", {"claude": tmp_path}):
                with mock.patch("mcp_server.shutil.which", return_value="/usr/bin/openwebgoggles"):
                    mcp_server.main()
        assert (tmp_path / ".mcp.json").exists()


# ---------------------------------------------------------------------------
# Regression: TR-2 — _deep_merge must reject __proto__/constructor/prototype
# ---------------------------------------------------------------------------


class TestDeepMergePrototypePollution:
    """Regression tests for blocking prototype pollution keys in _deep_merge."""

    def test_proto_key_rejected(self):
        """__proto__ key in merge should raise MergeError."""
        from mcp_server import _deep_merge

        base = {"title": "test"}
        with pytest.raises(MergeError, match="dangerous key"):
            _deep_merge(base, {"__proto__": {"polluted": True}})

    def test_constructor_key_rejected(self):
        """constructor key in merge should raise MergeError."""
        from mcp_server import _deep_merge

        base = {"title": "test"}
        with pytest.raises(MergeError, match="dangerous key"):
            _deep_merge(base, {"constructor": {"polluted": True}})

    def test_prototype_key_rejected(self):
        """prototype key in merge should raise MergeError."""
        from mcp_server import _deep_merge

        base = {"title": "test"}
        with pytest.raises(MergeError, match="dangerous key"):
            _deep_merge(base, {"prototype": {"polluted": True}})

    def test_normal_keys_still_merge(self):
        """Normal keys should still merge fine."""
        from mcp_server import _deep_merge

        base = {"title": "old", "data": {"x": 1}}
        _deep_merge(base, {"title": "new", "data": {"y": 2}})
        assert base["title"] == "new"
        assert base["data"]["x"] == 1
        assert base["data"]["y"] == 2

    def test_nested_proto_key_rejected(self):
        """Nested __proto__ key should also be rejected."""
        from mcp_server import _deep_merge

        base = {"data": {"inner": {}}}
        with pytest.raises(MergeError, match="dangerous key"):
            _deep_merge(base, {"data": {"inner": {"__proto__": {"bad": True}}}})


# ═══════════════════════════════════════════════════════════════════════════════
# H8: _notify_host_stale real-path coverage
# ═══════════════════════════════════════════════════════════════════════════════


class TestNotifyHostStaleReal:
    """Exercise the real _notify_host_stale coroutine."""

    def test_sends_log_when_server_available(self):
        """When the MCP server exposes send_log_message, it should be called."""
        mock_server = mock.MagicMock()
        mock_server.send_log_message = mock.AsyncMock()

        loop = asyncio.new_event_loop()
        try:

            async def _test():
                with mock.patch.object(mcp_server, "mcp") as mock_mcp:
                    mock_mcp._mcp_server = mock_server
                    await mcp_server._notify_host_stale("Server is stale")
                    mock_server.send_log_message.assert_called_once_with(level="error", data="Server is stale")

            loop.run_until_complete(_test())
        finally:
            loop.close()

    def test_no_server_available(self):
        """When no MCP server is available, _notify_host_stale should not crash."""
        loop = asyncio.new_event_loop()
        try:

            async def _test():
                with mock.patch.object(mcp_server, "mcp") as mock_mcp:
                    mock_mcp._mcp_server = None
                    mock_mcp.server = None
                    await mcp_server._notify_host_stale("No server")

            loop.run_until_complete(_test())
        finally:
            loop.close()

    def test_exception_suppressed(self):
        """If send_log_message raises, the exception should be suppressed."""
        mock_server = mock.MagicMock()
        mock_server.send_log_message = mock.AsyncMock(side_effect=RuntimeError("network down"))

        loop = asyncio.new_event_loop()
        try:

            async def _test():
                with mock.patch.object(mcp_server, "mcp") as mock_mcp:
                    mock_mcp._mcp_server = mock_server
                    # Should NOT raise
                    await mcp_server._notify_host_stale("Stale with error")

            loop.run_until_complete(_test())
        finally:
            loop.close()


# ═══════════════════════════════════════════════════════════════════════════════
# M15: webview_close XSS rejection
# ═══════════════════════════════════════════════════════════════════════════════


class TestWebviewCloseXSS:
    """Verify webview_close rejects XSS payloads in the close message."""

    def test_script_tag_rejected(self):
        """A <script> tag in close message should be rejected."""
        loop = asyncio.new_event_loop()
        try:

            async def _test():
                result = await openwebgoggles_close(message="<script>alert(1)</script>")
                return result

            result = loop.run_until_complete(_test())
        finally:
            loop.close()

        assert "error" in result
        assert "security gate" in result["error"].lower() or "rejected" in result["error"].lower()

    def test_event_handler_rejected(self):
        """An event handler in the close message should be rejected."""
        loop = asyncio.new_event_loop()
        try:

            async def _test():
                result = await openwebgoggles_close(message='<img onerror="alert(1)" src=x>')
                return result

            result = loop.run_until_complete(_test())
        finally:
            loop.close()

        assert "error" in result

    def test_clean_message_accepted(self):
        """A clean message should be accepted (no error)."""
        loop = asyncio.new_event_loop()
        try:

            async def _test():
                # Session manager starts empty from fixture — no slot exists
                result = await openwebgoggles_close(message="Goodbye!")
                return result

            result = loop.run_until_complete(_test())
        finally:
            loop.close()

        assert result.get("status") == "ok"


# ═══════════════════════════════════════════════════════════════════════════════
# monitor.py helper functions — direct unit tests
# _version_monitor tests above always mock these; test the implementations here.
# ═══════════════════════════════════════════════════════════════════════════════


class TestMonitorHelpers:
    """Unit tests for monitor.py helper functions."""

    def test_get_installed_version_info_returns_tuple(self):
        """Always returns a (str, Path|None) tuple — never raises."""
        from monitor import _get_installed_version_info

        version, path = _get_installed_version_info()
        assert isinstance(version, str)
        assert path is None or hasattr(path, "name")

    def test_get_installed_version_info_not_installed(self):
        """Returns ('unknown', None) when package is not found."""
        import importlib.metadata

        from monitor import _get_installed_version_info

        with mock.patch(
            "importlib.metadata.distribution",
            side_effect=importlib.metadata.PackageNotFoundError,
        ):
            version, path = _get_installed_version_info()

        assert version == "unknown"
        assert path is None

    def test_get_site_packages_dirs_returns_list(self):
        """Always returns a list (possibly empty)."""
        from monitor import _get_site_packages_dirs

        dirs = _get_site_packages_dirs()
        assert isinstance(dirs, list)

    def test_get_site_packages_dirs_filters_correctly(self, tmp_path):
        """Only paths named 'site-packages' that exist are included."""
        import sys

        from monitor import _get_site_packages_dirs

        site_dir = tmp_path / "site-packages"
        site_dir.mkdir()
        other_dir = tmp_path / "lib"
        other_dir.mkdir()
        nonexistent = tmp_path / "site-packages-nope"

        with mock.patch.object(sys, "path", [str(site_dir), str(other_dir), str(nonexistent)]):
            dirs = _get_site_packages_dirs()

        assert site_dir in dirs
        assert other_dir not in dirs

    def test_read_version_fresh_from_dist_info_hint(self, tmp_path):
        """Reads version from METADATA file at the hint path."""
        from monitor import _read_version_fresh

        dist_info = tmp_path / "openwebgoggles-1.2.3.dist-info"
        dist_info.mkdir()
        (dist_info / "METADATA").write_text("Metadata-Version: 2.1\nVersion: 1.2.3\nName: openwebgoggles\n")

        assert _read_version_fresh(dist_info) == "1.2.3"

    def test_read_version_fresh_hint_missing_falls_to_scan(self, tmp_path):
        """Falls through to site-packages scan when hint METADATA doesn't exist."""
        import sys

        from monitor import _read_version_fresh

        hint = tmp_path / "missing-dist-info"  # does not exist

        site_dir = tmp_path / "site-packages"
        site_dir.mkdir()
        dist_info = site_dir / "openwebgoggles-7.7.7.dist-info"
        dist_info.mkdir()
        (dist_info / "METADATA").write_text("Version: 7.7.7\n")

        with mock.patch.object(sys, "path", [str(site_dir)]):
            assert _read_version_fresh(hint) == "7.7.7"

    def test_read_version_fresh_scans_site_packages(self, tmp_path):
        """Finds version by scanning site-packages when hint is None."""
        import sys

        from monitor import _read_version_fresh

        site_dir = tmp_path / "site-packages"
        site_dir.mkdir()
        dist_info = site_dir / "openwebgoggles-9.9.9.dist-info"
        dist_info.mkdir()
        (dist_info / "METADATA").write_text("Version: 9.9.9\n")

        with mock.patch.object(sys, "path", [str(site_dir)]):
            assert _read_version_fresh(None) == "9.9.9"

    def test_read_version_fresh_fallback_importlib(self, tmp_path):
        """Falls back to importlib when no dist-info files found on disk."""
        import sys

        from monitor import _read_version_fresh

        with mock.patch.object(sys, "path", []):
            with mock.patch("importlib.metadata.distribution") as mock_dist:
                mock_dist.return_value.metadata = {"Version": "3.3.3"}
                result = _read_version_fresh(None)

        assert result == "3.3.3"

    def test_read_version_fresh_unknown_when_all_fail(self):
        """Returns 'unknown' when every strategy fails."""
        import importlib.metadata
        import sys

        from monitor import _read_version_fresh

        with mock.patch.object(sys, "path", []):
            with mock.patch(
                "importlib.metadata.distribution",
                side_effect=importlib.metadata.PackageNotFoundError,
            ):
                result = _read_version_fresh(None)

        assert result == "unknown"

    def test_task_done_callback_logs_exception(self):
        """Background task crashes are logged, not silently swallowed."""
        from monitor import _task_done_callback

        task = mock.MagicMock()
        task.cancelled.return_value = False
        exc = ValueError("test crash")
        task.exception.return_value = exc
        task.get_name.return_value = "test_task"

        with mock.patch("monitor.logger") as mock_log:
            _task_done_callback(task)

        mock_log.error.assert_called_once()

    def test_task_done_callback_ignores_cancelled(self):
        """Cancelled tasks produce no log output."""
        from monitor import _task_done_callback

        task = mock.MagicMock()
        task.cancelled.return_value = True

        with mock.patch("monitor.logger") as mock_log:
            _task_done_callback(task)

        mock_log.error.assert_not_called()

    def test_read_version_fresh_skips_unreadable_metadata(self, tmp_path):
        """OSError reading a METADATA file does not crash — moves to next."""
        import importlib.metadata
        import sys

        from monitor import _read_version_fresh

        site_dir = tmp_path / "site-packages"
        site_dir.mkdir()
        dist_info = site_dir / "openwebgoggles-2.0.0.dist-info"
        dist_info.mkdir()
        # METADATA exists but is unreadable
        metadata = dist_info / "METADATA"
        metadata.write_text("Version: 2.0.0\n")

        with mock.patch("pathlib.Path.read_text", side_effect=OSError("permission denied")):
            with mock.patch.object(sys, "path", [str(site_dir)]):
                with mock.patch(
                    "importlib.metadata.distribution",
                    side_effect=importlib.metadata.PackageNotFoundError,
                ):
                    result = _read_version_fresh(None)

        assert result == "unknown"  # all strategies failed gracefully
