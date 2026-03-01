"""
Tests for MCP tool functions: webview, webview_read, webview_update,
webview_status, webview_close, plus the _version_monitor main loop,
_signal_reload_monitor drain/exec, and lifespan session cleanup.

Targets the uncovered MCP tool paths and auto-reload inner loops.
"""

from __future__ import annotations

import asyncio
import os
import sys
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import mcp_server
from mcp_server import (
    WebviewSession,
    _expand_preset,
    webview,
    webview_close,
    webview_read,
    webview_status,
    webview_update,
)


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


# ---------------------------------------------------------------------------
# webview tool
# ---------------------------------------------------------------------------


class TestWebviewTool:
    async def test_basic_timeout(self):
        """webview returns timeout error when no action is received."""
        mock_session = _make_mock_session()
        mock_session.wait_for_action.return_value = None

        with mock.patch("mcp_server._get_session", return_value=mock_session):
            result = await webview(state={"title": "Test"}, timeout=1, ctx=None)

        assert "error" in result
        assert "Timeout" in result["error"]
        mock_session.ensure_started.assert_called_once()
        mock_session.write_state.assert_called_once()
        mock_session.clear_actions.assert_called_once()

    async def test_basic_success(self):
        """webview returns the action result when user responds."""
        mock_session = _make_mock_session()
        action_result = {"version": 1, "actions": [{"id": "ok", "type": "approve"}]}
        mock_session.wait_for_action.return_value = action_result

        with mock.patch("mcp_server._get_session", return_value=mock_session):
            result = await webview(state={"title": "Test"}, timeout=30, ctx=None)

        assert result == action_result

    async def test_preset_expansion(self):
        """webview expands preset before writing state."""
        mock_session = _make_mock_session()
        mock_session.wait_for_action.return_value = {"actions": [{"id": "confirm"}]}

        with mock.patch("mcp_server._get_session", return_value=mock_session):
            await webview(
                state={"title": "Confirm?", "message": "Are you sure?"},
                preset="confirm",
                timeout=1,
                ctx=None,
            )

        # write_state should have been called with expanded state
        call_args = mock_session.write_state.call_args[0][0]
        assert "actions_requested" in call_args

    async def test_preset_error(self):
        """webview returns error when preset expansion fails."""
        with mock.patch("mcp_server._get_session"):
            result = await webview(
                state={"title": "Test"},
                preset="nonexistent_preset",
                timeout=1,
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
            with mock.patch("mcp_server._get_session", return_value=mock_session):
                result = await webview(state={"title": "<script>alert(1)</script>"}, timeout=1, ctx=None)
            assert "error" in result
            assert "validation failed" in result["error"]
        finally:
            mcp_server._security_gate = old_gate

    async def test_ensure_started_failure(self):
        """webview returns error when server fails to start."""
        mock_session = _make_mock_session()
        mock_session.ensure_started = mock.AsyncMock(side_effect=RuntimeError("bind failed"))

        with mock.patch("mcp_server._get_session", return_value=mock_session):
            result = await webview(state={"title": "Test"}, timeout=1, ctx=None)

        assert "error" in result
        assert "Failed to start" in result["error"]


# ---------------------------------------------------------------------------
# webview_read tool
# ---------------------------------------------------------------------------


class TestWebviewReadTool:
    async def test_not_started(self):
        """Returns empty actions when session not started."""
        mock_session = _make_mock_session(started=False)

        with mock.patch("mcp_server._get_session", return_value=mock_session):
            result = await webview_read()

        assert result == {"version": 0, "actions": []}

    async def test_read_actions(self):
        """Returns current actions."""
        mock_session = _make_mock_session()
        mock_session.read_actions.return_value = {
            "version": 1,
            "actions": [{"id": "submit", "type": "approve"}],
        }

        with mock.patch("mcp_server._get_session", return_value=mock_session):
            result = await webview_read()

        assert result["actions"][0]["id"] == "submit"
        mock_session.clear_actions.assert_not_called()

    async def test_read_with_clear(self):
        """Clears actions after reading when clear=True."""
        mock_session = _make_mock_session()
        mock_session.read_actions.return_value = {
            "version": 1,
            "actions": [{"id": "submit"}],
        }

        with mock.patch("mcp_server._get_session", return_value=mock_session):
            await webview_read(clear=True)

        mock_session.clear_actions.assert_called_once()

    async def test_clear_no_actions(self):
        """Does not clear when clear=True but no actions."""
        mock_session = _make_mock_session()

        with mock.patch("mcp_server._get_session", return_value=mock_session):
            await webview_read(clear=True)

        mock_session.clear_actions.assert_not_called()


# ---------------------------------------------------------------------------
# webview_update tool
# ---------------------------------------------------------------------------


class TestWebviewUpdateTool:
    async def test_simple_update(self):
        """Basic non-merge update writes state."""
        mock_session = _make_mock_session()
        mock_session._state_version = 2

        with mock.patch("mcp_server._get_session", return_value=mock_session):
            result = await webview_update(state={"title": "Updated"})

        assert result["updated"] is True
        mock_session.write_state.assert_called_once()

    async def test_merge_update(self):
        """Merge update calls merge_state."""
        mock_session = _make_mock_session()
        mock_session.merge_state.return_value = {"version": 3, "title": "Merged"}

        with mock.patch("mcp_server._get_session", return_value=mock_session):
            result = await webview_update(state={"data": {"new": True}}, merge=True)

        assert result["updated"] is True
        mock_session.merge_state.assert_called_once()

    async def test_merge_validation_error(self):
        """Merge returns error on ValueError from validator."""
        mock_session = _make_mock_session()
        mock_session.merge_state.side_effect = ValueError("Merged state validation failed")

        with mock.patch("mcp_server._get_session", return_value=mock_session):
            result = await webview_update(state={"data": {}}, merge=True)

        assert "error" in result

    async def test_preset_expansion(self):
        """Update expands preset."""
        mock_session = _make_mock_session()

        with mock.patch("mcp_server._get_session", return_value=mock_session):
            result = await webview_update(
                state={"tasks": [], "percentage": 50},
                preset="progress",
            )

        assert result["updated"] is True

    async def test_preset_error(self):
        """Update returns error for unknown preset."""
        result = await webview_update(state={}, preset="nonexistent")
        assert "error" in result

    async def test_security_gate_failure(self):
        """Update returns error when state fails security validation."""
        mock_session = _make_mock_session()
        old_gate = mcp_server._security_gate
        mock_gate = mock.MagicMock()
        mock_gate.validate_state.return_value = (False, "XSS detected", [])
        mcp_server._security_gate = mock_gate
        try:
            with mock.patch("mcp_server._get_session", return_value=mock_session):
                result = await webview_update(state={"title": "bad"})
            assert "error" in result
        finally:
            mcp_server._security_gate = old_gate

    async def test_ensure_started_failure(self):
        """Update returns error when start fails."""
        mock_session = _make_mock_session()
        mock_session.ensure_started = mock.AsyncMock(side_effect=RuntimeError("fail"))

        with mock.patch("mcp_server._get_session", return_value=mock_session):
            result = await webview_update(state={"title": "Test"})

        assert "error" in result
        assert "Failed to start" in result["error"]


# ---------------------------------------------------------------------------
# webview_status tool
# ---------------------------------------------------------------------------


class TestWebviewStatusTool:
    async def test_no_session(self):
        """Returns inactive when no session."""
        old = mcp_server._session
        mcp_server._session = None
        try:
            result = await webview_status()
            assert result["active"] is False
        finally:
            mcp_server._session = old

    async def test_session_not_started(self):
        """Returns inactive when session exists but not started."""
        old = mcp_server._session
        mock_session = _make_mock_session(started=False)
        mcp_server._session = mock_session
        try:
            result = await webview_status()
            assert result["active"] is False
        finally:
            mcp_server._session = old

    async def test_active_session(self):
        """Returns active session info."""
        old = mcp_server._session
        mock_session = _make_mock_session()
        mcp_server._session = mock_session
        try:
            result = await webview_status()
            assert result["active"] is True
            assert result["alive"] is True
            assert "url" in result
            assert "session_id" in result
        finally:
            mcp_server._session = old


# ---------------------------------------------------------------------------
# webview_close tool
# ---------------------------------------------------------------------------


class TestWebviewCloseTool:
    async def test_no_session(self):
        """Returns ok when no active session."""
        old = mcp_server._session
        mcp_server._session = None
        try:
            result = await webview_close()
            assert result["status"] == "ok"
            assert "No active session" in result["message"]
        finally:
            mcp_server._session = old

    async def test_close_active_session(self):
        """Closes active session and sets to None."""
        old = mcp_server._session
        mock_session = _make_mock_session()
        mcp_server._session = mock_session
        try:
            result = await webview_close(message="Goodbye")
            assert result["status"] == "ok"
            assert mcp_server._session is None
            mock_session.close.assert_called_once_with(message="Goodbye")
        finally:
            mcp_server._session = old

    async def test_close_error_returns_error(self):
        """Returns error dict when close raises."""
        old = mcp_server._session
        mock_session = _make_mock_session()
        mock_session.close = mock.AsyncMock(side_effect=Exception("close failed"))
        mcp_server._session = mock_session
        try:
            result = await webview_close()
            assert "error" in result
            assert "close failed" in result["error"]
        finally:
            mcp_server._session = old

    async def test_close_not_started(self):
        """Returns ok when session exists but not started."""
        old = mcp_server._session
        mock_session = _make_mock_session(started=False)
        mcp_server._session = mock_session
        try:
            result = await webview_close()
            assert result["status"] == "ok"
        finally:
            mcp_server._session = old


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
                    with mock.patch("mcp_server._exec_reload") as mock_reload:
                        old_pending = mcp_server._reload_pending
                        old_active = mcp_server._active_tool_calls
                        old_session = mcp_server._session
                        mcp_server._reload_pending = False
                        mcp_server._active_tool_calls = 0
                        mcp_server._session = None
                        try:
                            task = asyncio.create_task(mcp_server._version_monitor())
                            await asyncio.sleep(1.0)
                            task.cancel()
                            try:
                                await task
                            except asyncio.CancelledError:
                                pass

                            assert mock_reload.called
                        finally:
                            mcp_server._reload_pending = old_pending
                            mcp_server._active_tool_calls = old_active
                            mcp_server._session = old_session

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
                ],
            ):
                with mock.patch("mcp_server._read_version_fresh", return_value="1.0.0"):
                    with mock.patch("mcp_server._exec_reload") as mock_reload:
                        task = asyncio.create_task(mcp_server._version_monitor())
                        await asyncio.sleep(1.0)
                        task.cancel()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass

                        mock_reload.assert_not_called()

    async def test_unknown_version_during_upgrade(self):
        """When version becomes 'unknown' during upgrade, should retry."""
        mock_dist_path = mock.MagicMock()
        mock_dist_path.is_dir.return_value = True
        mock_dist_path.stat.side_effect = OSError("gone")

        with mock.patch("mcp_server._RELOAD_CHECK_INTERVAL", 0.2):
            with mock.patch("mcp_server._get_installed_version_info", return_value=("1.0.0", mock_dist_path)):
                with mock.patch("mcp_server._read_version_fresh", return_value="unknown"):
                    with mock.patch("mcp_server._exec_reload") as mock_reload:
                        task = asyncio.create_task(mcp_server._version_monitor())
                        await asyncio.sleep(1.0)
                        task.cancel()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass

                        mock_reload.assert_not_called()

    async def test_drains_active_tool_calls(self):
        """Version monitor waits for active tool calls to drain."""
        mock_dist_path = mock.MagicMock()
        mock_dist_path.is_dir.return_value = True
        mock_dist_path.stat.side_effect = [
            mock.MagicMock(st_mtime=100.0),
            mock.MagicMock(st_mtime=200.0),
        ]

        old_active = mcp_server._active_tool_calls
        old_pending = mcp_server._reload_pending
        old_session = mcp_server._session
        mcp_server._active_tool_calls = 1
        mcp_server._reload_pending = False
        mcp_server._session = None

        try:
            with mock.patch("mcp_server._RELOAD_CHECK_INTERVAL", 0.2):
                with mock.patch("mcp_server._get_installed_version_info", return_value=("1.0.0", mock_dist_path)):
                    with mock.patch("mcp_server._read_version_fresh", return_value="2.0.0"):
                        with mock.patch("mcp_server._exec_reload") as mock_reload:
                            task = asyncio.create_task(mcp_server._version_monitor())
                            await asyncio.sleep(1.0)
                            # Set active to 0 so it can proceed
                            mcp_server._active_tool_calls = 0
                            await asyncio.sleep(1.5)
                            task.cancel()
                            try:
                                await task
                            except asyncio.CancelledError:
                                pass

                            assert mock_reload.called
        finally:
            mcp_server._active_tool_calls = old_active
            mcp_server._reload_pending = old_pending
            mcp_server._session = old_session

    async def test_closes_session_before_reload(self):
        """Version monitor closes webview session before reloading."""
        mock_dist_path = mock.MagicMock()
        mock_dist_path.is_dir.return_value = True
        mock_dist_path.stat.side_effect = [
            mock.MagicMock(st_mtime=100.0),
            mock.MagicMock(st_mtime=200.0),
        ]

        mock_session = _make_mock_session()
        old_session = mcp_server._session
        old_pending = mcp_server._reload_pending
        old_active = mcp_server._active_tool_calls
        mcp_server._session = mock_session
        mcp_server._reload_pending = False
        mcp_server._active_tool_calls = 0

        try:
            with mock.patch("mcp_server._RELOAD_CHECK_INTERVAL", 0.2):
                with mock.patch("mcp_server._get_installed_version_info", return_value=("1.0.0", mock_dist_path)):
                    with mock.patch("mcp_server._read_version_fresh", return_value="2.0.0"):
                        with mock.patch("mcp_server._exec_reload"):
                            task = asyncio.create_task(mcp_server._version_monitor())
                            await asyncio.sleep(1.0)
                            task.cancel()
                            try:
                                await task
                            except asyncio.CancelledError:
                                pass

                            mock_session.close.assert_called()
        finally:
            mcp_server._session = old_session
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
        old_session = mcp_server._session

        mcp_server._signal_reload_requested = True
        mcp_server._reload_pending = False
        mcp_server._active_tool_calls = 0
        mcp_server._session = None

        try:
            with mock.patch("mcp_server._exec_reload") as mock_reload:
                task = asyncio.create_task(mcp_server._signal_reload_monitor())
                await asyncio.sleep(1.5)
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

                assert mock_reload.called
        finally:
            mcp_server._signal_reload_requested = old_flag
            mcp_server._reload_pending = old_pending
            mcp_server._active_tool_calls = old_active
            mcp_server._session = old_session

    async def test_closes_session_before_exec(self):
        """Signal monitor closes session before exec_reload."""
        mock_session = _make_mock_session()
        old_flag = mcp_server._signal_reload_requested
        old_pending = mcp_server._reload_pending
        old_active = mcp_server._active_tool_calls
        old_session = mcp_server._session

        mcp_server._signal_reload_requested = True
        mcp_server._reload_pending = False
        mcp_server._active_tool_calls = 0
        mcp_server._session = mock_session

        try:
            with mock.patch("mcp_server._exec_reload"):
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
            mcp_server._session = old_session


# ---------------------------------------------------------------------------
# lifespan session cleanup
# ---------------------------------------------------------------------------


class TestLifespanSessionCleanup:
    async def test_closes_session_on_shutdown(self):
        """Lifespan cleans up active session on MCP server shutdown."""
        mock_session = _make_mock_session()
        old_session = mcp_server._session

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
                        mcp_server._session = mock_session
                        try:
                            fake_server = mock.MagicMock()
                            async with mcp_server.lifespan(fake_server):
                                pass
                            mock_session.close.assert_called_once()
                            assert mcp_server._session is None
                        finally:
                            mcp_server._session = old_session

    async def test_session_close_exception_suppressed(self):
        """Lifespan suppresses exceptions during session close."""
        mock_session = _make_mock_session()
        mock_session.close = mock.AsyncMock(side_effect=RuntimeError("cleanup fail"))
        old_session = mcp_server._session

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
                        mcp_server._session = mock_session
                        try:
                            fake_server = mock.MagicMock()
                            async with mcp_server.lifespan(fake_server):
                                pass
                            # Should not raise
                            assert mcp_server._session is None
                        finally:
                            mcp_server._session = old_session


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
