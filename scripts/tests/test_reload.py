"""
Tests for auto-reload, signal handling, version monitoring, and MCP PID management.

Covers _get_installed_version_info, _read_version_fresh, _mark_stale,
_sigusr1_handler, _write_mcp_pid, _cleanup_mcp_pid, _signal_reload_monitor,
_version_monitor, _track_tool_call, and lifespan.
"""

from __future__ import annotations

import asyncio
import importlib.metadata
import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import mcp_server
from mcp_server import (
    _cleanup_mcp_pid,
    _get_installed_version_info,
    _mark_stale,
    _read_version_fresh,
    _sigusr1_handler,
    _track_tool_call,
    _write_mcp_pid,
)


# ---------------------------------------------------------------------------
# _get_installed_version_info
# ---------------------------------------------------------------------------


class TestGetInstalledVersionInfo:
    def test_returns_unknown_when_not_installed(self):
        with mock.patch(
            "importlib.metadata.distribution",
            side_effect=importlib.metadata.PackageNotFoundError("openwebgoggles"),
        ):
            version, path = _get_installed_version_info()
            assert version == "unknown"
            assert path is None

    def test_returns_version_when_installed(self):
        mock_dist = mock.MagicMock()
        mock_dist.metadata = {"Version": "1.2.3"}
        mock_dist._path = "/fake/path/openwebgoggles-1.2.3.dist-info"

        with mock.patch("importlib.metadata.distribution", return_value=mock_dist):
            version, path = _get_installed_version_info()
            assert version == "1.2.3"
            assert path == Path("/fake/path/openwebgoggles-1.2.3.dist-info")

    def test_handles_missing_path_attr(self):
        mock_dist = mock.MagicMock(spec=[])
        mock_dist.metadata = {"Version": "1.0.0"}

        with mock.patch("importlib.metadata.distribution", return_value=mock_dist):
            version, path = _get_installed_version_info()
            assert version == "1.0.0"
            assert path is None


# ---------------------------------------------------------------------------
# _read_version_fresh
# ---------------------------------------------------------------------------


class TestReadVersionFresh:
    def test_returns_unknown_when_not_installed(self):
        with mock.patch(
            "importlib.metadata.distribution",
            side_effect=importlib.metadata.PackageNotFoundError("openwebgoggles"),
        ):
            assert _read_version_fresh() == "unknown"

    def test_returns_fresh_version(self):
        mock_dist = mock.MagicMock()
        mock_dist.metadata = {"Version": "2.0.0"}

        with mock.patch("importlib.metadata.distribution", return_value=mock_dist):
            with mock.patch("importlib.invalidate_caches"):
                assert _read_version_fresh() == "2.0.0"


# ---------------------------------------------------------------------------
# _mark_stale
# ---------------------------------------------------------------------------


class TestMarkStale:
    def test_sets_stale_message(self):
        old_msg = mcp_server._stale_version_msg
        try:
            _mark_stale("1.0.0", "2.0.0")
            assert mcp_server._stale_version_msg is not None
            assert "1.0.0" in mcp_server._stale_version_msg
            assert "2.0.0" in mcp_server._stale_version_msg
        finally:
            mcp_server._stale_version_msg = old_msg


# ---------------------------------------------------------------------------
# _sigusr1_handler
# ---------------------------------------------------------------------------


class TestSigusr1Handler:
    def test_sets_flag(self):
        mcp_server._signal_reload_requested = False
        _sigusr1_handler(10, None)
        assert mcp_server._signal_reload_requested is True
        # Reset
        mcp_server._signal_reload_requested = False


# ---------------------------------------------------------------------------
# _write_mcp_pid / _cleanup_mcp_pid
# ---------------------------------------------------------------------------


class TestMcpPidFile:
    def test_write_creates_pid_file(self, tmp_path):
        with mock.patch("mcp_server.Path.cwd", return_value=tmp_path):
            _write_mcp_pid()

        pid_file = tmp_path / ".opencode" / "webview" / ".mcp.pid"
        assert pid_file.exists()
        assert pid_file.read_text() == str(os.getpid())

    def test_cleanup_removes_own_pid(self, tmp_path):
        with mock.patch("mcp_server.Path.cwd", return_value=tmp_path):
            _write_mcp_pid()

        pid_file = tmp_path / ".opencode" / "webview" / ".mcp.pid"
        assert pid_file.exists()

        _cleanup_mcp_pid()
        assert not pid_file.exists()

    def test_cleanup_preserves_other_pid(self, tmp_path):
        with mock.patch("mcp_server.Path.cwd", return_value=tmp_path):
            _write_mcp_pid()

        pid_file = tmp_path / ".opencode" / "webview" / ".mcp.pid"
        # Overwrite with a different PID
        pid_file.write_text("99999999")

        _cleanup_mcp_pid()
        # Should NOT have been removed (not our PID)
        assert pid_file.exists()

    def test_cleanup_when_no_dir(self):
        old_dir = mcp_server._MCP_PID_DIR
        mcp_server._MCP_PID_DIR = None
        _cleanup_mcp_pid()  # Should not raise
        mcp_server._MCP_PID_DIR = old_dir


# ---------------------------------------------------------------------------
# _track_tool_call decorator
# ---------------------------------------------------------------------------


class TestTrackToolCall:
    async def test_increments_and_decrements(self):
        mcp_server._active_tool_calls = 0
        mcp_server._reload_pending = False

        @_track_tool_call
        async def dummy():
            assert mcp_server._active_tool_calls == 1
            return "ok"

        result = await dummy()
        assert result == "ok"
        assert mcp_server._active_tool_calls == 0

    async def test_decrements_on_exception(self):
        mcp_server._active_tool_calls = 0
        mcp_server._reload_pending = False

        @_track_tool_call
        async def dummy():
            raise ValueError("boom")

        with pytest.raises(ValueError):
            await dummy()
        assert mcp_server._active_tool_calls == 0

    async def test_rejects_during_reload(self):
        mcp_server._reload_pending = True

        @_track_tool_call
        async def dummy():
            return "should not run"

        result = await dummy()
        assert "error" in result
        assert "restart" in result["error"]

        mcp_server._reload_pending = False


# ---------------------------------------------------------------------------
# _signal_reload_monitor
# ---------------------------------------------------------------------------


class TestSignalReloadMonitor:
    async def test_detects_signal_flag(self):
        """Monitor should detect the flag and call _mark_stale."""
        mcp_server._signal_reload_requested = True
        mcp_server._reload_pending = False
        mcp_server._active_tool_calls = 0
        mcp_server._session = None

        with mock.patch("mcp_server._mark_stale") as mock_stale:
            task = asyncio.create_task(mcp_server._signal_reload_monitor())
            await asyncio.sleep(1.5)  # Let the monitor run a cycle
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

            assert mock_stale.called

        mcp_server._signal_reload_requested = False
        mcp_server._reload_pending = False


# ---------------------------------------------------------------------------
# _version_monitor
# ---------------------------------------------------------------------------


class TestVersionMonitor:
    async def test_exits_when_not_installed(self):
        """Monitor should return immediately if package is not installed."""
        with mock.patch(
            "mcp_server._get_installed_version_info",
            return_value=("unknown", None),
        ):
            # Should complete quickly without looping
            task = asyncio.create_task(mcp_server._version_monitor())
            await asyncio.sleep(0.5)
            assert task.done()

    async def test_starts_with_known_version(self):
        """Monitor should start and loop when version is known."""
        mock_dist_path = mock.MagicMock()
        mock_dist_path.is_dir.return_value = True
        mock_stat = mock.MagicMock()
        mock_stat.st_mtime = 12345.0
        mock_dist_path.stat.return_value = mock_stat

        with mock.patch(
            "mcp_server._get_installed_version_info",
            return_value=("1.0.0", mock_dist_path),
        ):
            task = asyncio.create_task(mcp_server._version_monitor())
            await asyncio.sleep(0.5)
            # Should still be running (sleeping between checks)
            assert not task.done()
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


# ---------------------------------------------------------------------------
# lifespan
# ---------------------------------------------------------------------------


class TestLifespan:
    async def test_lifespan_starts_and_stops(self):
        """Lifespan should create tasks and clean up on exit."""

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

        with mock.patch("mcp_server._write_mcp_pid") as mock_write:
            with mock.patch("mcp_server._cleanup_mcp_pid") as mock_cleanup:
                with mock.patch("mcp_server._version_monitor", side_effect=fake_version_monitor):
                    with mock.patch("mcp_server._signal_reload_monitor", side_effect=fake_signal_monitor):
                        fake_server = mock.MagicMock()
                        async with mcp_server.lifespan(fake_server):
                            mock_write.assert_called_once()
                        mock_cleanup.assert_called_once()
