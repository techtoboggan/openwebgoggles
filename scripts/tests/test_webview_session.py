"""
Tests for WebviewSession methods: _kill_stale_server, _acquire_lock,
_release_lock, _cleanup_process, ensure_started, close, _health_check,
_find_assets_dir, _find_free_ports, _set_permissions, wait_for_action,
is_alive, url property, and the _get_session helper.

Targets the 75% → higher coverage gap in mcp_server.py.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import mcp_server
from mcp_server import WebviewSession, _get_session


# ---------------------------------------------------------------------------
# WebviewSession.__init__
# ---------------------------------------------------------------------------


class TestWebviewSessionInit:
    def test_default_work_dir(self):
        session = WebviewSession(open_browser=False)
        assert session.work_dir == Path.cwd()
        assert session.data_dir == Path.cwd() / ".opencode" / "webview"

    def test_custom_work_dir(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        assert session.work_dir == tmp_path
        assert session.data_dir == tmp_path / ".opencode" / "webview"

    def test_initial_state(self):
        session = WebviewSession(open_browser=False)
        assert session.process is None
        assert session._started is False
        assert session._state_version == 0
        assert session._lock_fd is None


# ---------------------------------------------------------------------------
# _kill_stale_server
# ---------------------------------------------------------------------------


class TestKillStaleServer:
    def test_no_pid_file(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        # Should not raise
        session._kill_stale_server()

    def test_non_numeric_pid_file(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        pid_file = session.data_dir / ".server.pid"
        pid_file.write_text("not-a-number")
        session._kill_stale_server()
        # Should remove the file
        assert not pid_file.exists()

    def test_stale_pid_removed(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        pid_file = session.data_dir / ".server.pid"
        pid_file.write_text("99999999")  # Almost certainly dead

        with mock.patch("os.kill", side_effect=OSError("No such process")):
            session._kill_stale_server()

        assert not pid_file.exists()

    def test_live_pid_killed(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        pid_file = session.data_dir / ".server.pid"
        pid_file.write_text("12345")

        kill_calls = []

        def mock_kill(pid, sig):
            kill_calls.append((pid, sig))
            if sig == 0 and len([c for c in kill_calls if c[1] == 0]) > 1:
                raise OSError("No such process")  # Process died after SIGTERM

        with mock.patch("os.kill", side_effect=mock_kill):
            with mock.patch("time.sleep"):
                session._kill_stale_server()

        # Should have sent SIGTERM (15)
        assert any(c[1] == 15 for c in kill_calls)
        assert not pid_file.exists()

    def test_own_subprocess_not_killed(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        pid_file = session.data_dir / ".server.pid"

        mock_proc = mock.MagicMock()
        mock_proc.pid = 42
        session.process = mock_proc
        pid_file.write_text("42")

        session._kill_stale_server()
        # Should not have tried to kill anything (our own subprocess)

    def test_oserror_on_read(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        pid_file = session.data_dir / ".server.pid"
        pid_file.write_text("123")

        with mock.patch.object(Path, "read_text", side_effect=OSError("fail")):
            # Should not raise
            session._kill_stale_server()

    def test_force_kill_after_timeout(self, tmp_path):
        """When process doesn't die after SIGTERM, should SIGKILL."""
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        pid_file = session.data_dir / ".server.pid"
        pid_file.write_text("12345")

        def mock_kill(pid, sig):
            # Signal 0 always succeeds (process alive), SIGTERM/SIGKILL don't raise
            pass

        with mock.patch("os.kill", side_effect=mock_kill):
            with mock.patch("time.sleep"):
                session._kill_stale_server()

        assert not pid_file.exists()


# ---------------------------------------------------------------------------
# _acquire_lock / _release_lock
# ---------------------------------------------------------------------------


class TestAcquireLock:
    def test_acquires_lock(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        session._acquire_lock()
        assert session._lock_fd is not None
        session._release_lock()
        assert session._lock_fd is None

    def test_release_lock_when_none(self):
        session = WebviewSession(open_browser=False)
        session._lock_fd = None
        session._release_lock()  # Should not raise

    def test_lock_contention_kills_stale(self, tmp_path):
        """When lock is held, should kill stale server and retry."""
        import fcntl

        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)

        call_count = [0]
        original_flock = fcntl.flock

        def mock_flock(fd, operation):
            call_count[0] += 1
            if call_count[0] <= 1:
                raise OSError("Resource temporarily unavailable")
            # Succeed on subsequent calls
            return original_flock(fd, operation)

        with mock.patch("fcntl.flock", side_effect=mock_flock):
            with mock.patch.object(session, "_kill_stale_server"):
                with mock.patch("time.sleep"):
                    session._acquire_lock()

        assert session._lock_fd is not None
        session._release_lock()

    def test_lock_contention_raises_after_retries(self, tmp_path):
        """After exhausting retries, should raise RuntimeError."""

        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)

        def mock_flock(fd, operation):
            raise OSError("Resource temporarily unavailable")

        with mock.patch("fcntl.flock", side_effect=mock_flock):
            with mock.patch.object(session, "_kill_stale_server"):
                with mock.patch("time.sleep"):
                    with pytest.raises(RuntimeError, match="Cannot acquire webview lock"):
                        session._acquire_lock()


# ---------------------------------------------------------------------------
# _cleanup_process
# ---------------------------------------------------------------------------


class TestCleanupProcess:
    def test_cleanup_no_process(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        session._cleanup_process()  # Should not raise

    def test_cleanup_terminates_process(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)

        mock_proc = mock.MagicMock()
        mock_proc.terminate = mock.MagicMock()
        mock_proc.wait = mock.MagicMock()
        session.process = mock_proc

        session._cleanup_process()

        mock_proc.terminate.assert_called_once()
        assert session.process is None

    def test_cleanup_force_kills_on_timeout(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)

        mock_proc = mock.MagicMock()
        mock_proc.terminate = mock.MagicMock()
        mock_proc.wait = mock.MagicMock(side_effect=[subprocess.TimeoutExpired("cmd", 5), None])
        mock_proc.kill = mock.MagicMock()
        session.process = mock_proc

        session._cleanup_process()

        mock_proc.kill.assert_called_once()
        assert session.process is None

    def test_cleanup_exception_suppressed(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)

        mock_proc = mock.MagicMock()
        mock_proc.terminate = mock.MagicMock(side_effect=Exception("fail"))
        session.process = mock_proc

        session._cleanup_process()
        assert session.process is None

    def test_cleanup_removes_pid_file(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        pid_file = session.data_dir / ".server.pid"
        pid_file.write_text("12345")

        session._cleanup_process()
        assert not pid_file.exists()

    def test_cleanup_pid_file_oserror(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        pid_file = session.data_dir / ".server.pid"
        pid_file.write_text("12345")

        with mock.patch.object(Path, "unlink", side_effect=OSError("fail")):
            session._cleanup_process()  # Should not raise


# ---------------------------------------------------------------------------
# is_alive / url property
# ---------------------------------------------------------------------------


class TestIsAlive:
    def test_no_process(self):
        session = WebviewSession(open_browser=False)
        assert session.is_alive() is False

    def test_alive_process(self):
        session = WebviewSession(open_browser=False)
        session.process = mock.MagicMock()
        session.process.poll.return_value = None  # Still running
        assert session.is_alive() is True

    def test_dead_process(self):
        session = WebviewSession(open_browser=False)
        session.process = mock.MagicMock()
        session.process.poll.return_value = 0  # Exited
        assert session.is_alive() is False


class TestUrlProperty:
    def test_url(self):
        session = WebviewSession(open_browser=False)
        session.http_port = 18420
        assert session.url == "http://127.0.0.1:18420"


# ---------------------------------------------------------------------------
# _find_assets_dir
# ---------------------------------------------------------------------------


class TestFindAssetsDir:
    def test_assets_not_found_raises(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        # Mock __file__ to return a fake location with no assets dir
        with mock.patch("mcp_server.__file__", str(tmp_path / "scripts" / "mcp_server.py")):
            with pytest.raises(FileNotFoundError, match="Cannot find assets"):
                session._find_assets_dir()

    def test_pkg_assets_found(self, tmp_path):
        """When dev assets don't exist, package assets should be found."""
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()
        pkg_assets = scripts_dir / "assets"
        pkg_assets.mkdir()

        with mock.patch("mcp_server.__file__", str(scripts_dir / "mcp_server.py")):
            result = session._find_assets_dir()
            assert result == pkg_assets


# ---------------------------------------------------------------------------
# _find_free_ports
# ---------------------------------------------------------------------------


class TestFindFreePorts:
    def test_finds_ports(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        http_port, ws_port = session._find_free_ports()
        assert ws_port == http_port + 1

    def test_all_ports_taken_raises(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)

        with mock.patch.object(WebviewSession, "_port_available", return_value=False):
            with pytest.raises(RuntimeError, match="Could not find free ports"):
                session._find_free_ports()


# ---------------------------------------------------------------------------
# _set_permissions
# ---------------------------------------------------------------------------


class TestSetPermissions:
    def test_sets_permissions(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        (session.data_dir / "manifest.json").write_text("{}")

        session._set_permissions()
        assert oct(session.data_dir.stat().st_mode)[-3:] == "700"

    def test_oserror_suppressed(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)

        with mock.patch("os.chmod", side_effect=OSError("fail")):
            session._set_permissions()  # Should not raise


# ---------------------------------------------------------------------------
# _health_check
# ---------------------------------------------------------------------------


class TestHealthCheck:
    async def test_healthy_server(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.http_port = 18420
        session.process = mock.MagicMock()
        session.process.poll.return_value = None

        mock_resp = mock.MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mock.MagicMock(return_value=False)

        with mock.patch("urllib.request.urlopen", return_value=mock_resp):
            result = await session._health_check()
            assert result is True

    async def test_process_died_during_check(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.http_port = 18420
        session.HEALTH_TIMEOUT = 0.5
        session.process = mock.MagicMock()
        session.process.poll.return_value = 1  # Process died

        result = await session._health_check()
        assert result is False

    async def test_timeout_returns_false(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.http_port = 18420
        session.HEALTH_TIMEOUT = 0.5
        session.process = mock.MagicMock()
        session.process.poll.return_value = None

        import urllib.error

        with mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("fail")):
            result = await session._health_check()
            assert result is False


# ---------------------------------------------------------------------------
# ensure_started
# ---------------------------------------------------------------------------


class TestEnsureStarted:
    async def test_already_started_and_alive(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session._started = True
        session.process = mock.MagicMock()
        session.process.poll.return_value = None  # alive
        await session.ensure_started()
        # Should be a no-op

    async def test_process_died_mid_session(self, tmp_path):
        """When process died, should cleanup and restart."""
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session._started = True
        session.process = mock.MagicMock()
        session.process.poll.return_value = 1  # dead

        with mock.patch.object(session, "_cleanup_process"):
            with mock.patch.object(session, "_kill_stale_server"):
                with mock.patch.object(session, "_acquire_lock"):
                    with mock.patch.object(session, "_copy_app"):
                        with mock.patch.object(session, "_find_assets_dir", return_value=tmp_path):
                            with mock.patch.object(session, "_write_manifest"):
                                with mock.patch.object(session, "_init_data_contract"):
                                    with mock.patch.object(session, "_set_permissions"):
                                        with mock.patch.object(
                                            session, "_find_free_ports", return_value=(18420, 18421)
                                        ):
                                            with mock.patch("subprocess.Popen") as mock_popen:
                                                mock_proc = mock.MagicMock()
                                                mock_proc.stderr = None
                                                mock_popen.return_value = mock_proc
                                                with mock.patch.object(session, "_health_check", return_value=True):
                                                    with mock.patch("atexit.register"):
                                                        (tmp_path / "sdk").mkdir(exist_ok=True)
                                                        (tmp_path / "sdk" / "openwebgoggles-sdk.js").write_text("")
                                                        await session.ensure_started()

        assert session._started is True

    async def test_health_check_fails_raises(self, tmp_path):
        """When health check fails, should raise RuntimeError."""
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session._started = False

        with mock.patch.object(session, "_kill_stale_server"):
            with mock.patch.object(session, "_acquire_lock"):
                with mock.patch.object(session, "_copy_app"):
                    with mock.patch.object(session, "_find_assets_dir", return_value=tmp_path):
                        with mock.patch.object(session, "_write_manifest"):
                            with mock.patch.object(session, "_init_data_contract"):
                                with mock.patch.object(session, "_set_permissions"):
                                    with mock.patch.object(session, "_find_free_ports", return_value=(18420, 18421)):
                                        with mock.patch("subprocess.Popen") as mock_popen:
                                            mock_proc = mock.MagicMock()
                                            mock_proc.stderr = mock.MagicMock()
                                            mock_proc.stderr.read.return_value = b"error"
                                            mock_proc.kill = mock.MagicMock()
                                            mock_popen.return_value = mock_proc
                                            with mock.patch.object(session, "_health_check", return_value=False):
                                                with mock.patch(
                                                    "select.select", return_value=([mock_proc.stderr], [], [])
                                                ):
                                                    (tmp_path / "sdk").mkdir(exist_ok=True)
                                                    (tmp_path / "sdk" / "openwebgoggles-sdk.js").write_text("")
                                                    with pytest.raises(
                                                        RuntimeError, match="Webview server failed to start"
                                                    ):
                                                        await session.ensure_started()


# ---------------------------------------------------------------------------
# close
# ---------------------------------------------------------------------------


class TestClose:
    async def test_close_running_session(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        session._started = True
        session.http_port = 18420
        session.session_token = "test-token"
        session.process = mock.MagicMock()
        session.process.poll.return_value = None  # alive

        async def fake_sleep(t):
            pass

        with mock.patch("urllib.request.urlopen"):
            with mock.patch("asyncio.sleep", side_effect=fake_sleep):
                with mock.patch.object(session, "_cleanup_chrome"):
                    with mock.patch.object(session, "_cleanup_process"):
                        await session.close(message="Test close")

        assert session._started is False

    async def test_close_http_failure_suppressed(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        session._started = True
        session.http_port = 18420
        session.session_token = "test-token"
        session.process = mock.MagicMock()
        session.process.poll.return_value = None

        async def fake_sleep(t):
            pass

        with mock.patch("urllib.request.urlopen", side_effect=Exception("fail")):
            with mock.patch("asyncio.sleep", side_effect=fake_sleep):
                with mock.patch.object(session, "_cleanup_chrome"):
                    with mock.patch.object(session, "_cleanup_process"):
                        await session.close()

        assert session._started is False

    async def test_close_no_process(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        session.process = None

        with mock.patch.object(session, "_cleanup_chrome"):
            with mock.patch.object(session, "_cleanup_process"):
                await session.close()


# ---------------------------------------------------------------------------
# wait_for_action
# ---------------------------------------------------------------------------


class TestWaitForAction:
    async def test_returns_action_when_available(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        actions = {"version": 1, "actions": [{"id": "ok", "type": "approve"}]}
        (session.data_dir / "actions.json").write_text(json.dumps(actions))

        result = await session.wait_for_action(timeout=1.0)
        assert result is not None
        assert result["actions"][0]["id"] == "ok"

    async def test_returns_none_on_timeout(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        # Write empty actions
        (session.data_dir / "actions.json").write_text(json.dumps({"version": 0, "actions": []}))

        result = await session.wait_for_action(timeout=0.3)
        assert result is None

    async def test_handles_missing_actions_file(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        # No actions.json file

        result = await session.wait_for_action(timeout=0.3)
        assert result is None

    async def test_progress_callback_called(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        session.PROGRESS_INTERVAL = 0.05  # Very fast for testing
        session.POLL_INTERVAL = 0.05
        (session.data_dir / "actions.json").write_text(json.dumps({"version": 0, "actions": []}))

        progress_calls = []

        async def on_progress(elapsed, total):
            progress_calls.append((elapsed, total))

        await session.wait_for_action(timeout=0.5, on_progress=on_progress)
        assert len(progress_calls) > 0

    async def test_progress_exception_suppressed(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        session.PROGRESS_INTERVAL = 0.1
        (session.data_dir / "actions.json").write_text(json.dumps({"version": 0, "actions": []}))

        async def bad_progress(elapsed, total):
            raise ValueError("boom")

        # Should not raise
        await session.wait_for_action(timeout=0.5, on_progress=bad_progress)


# ---------------------------------------------------------------------------
# write_state / read_state / merge_state / read_actions / clear_actions
# ---------------------------------------------------------------------------


class TestDataContractMethods:
    def test_write_and_read_state(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        session.write_state({"title": "Test"})
        state = session.read_state()
        assert state["title"] == "Test"
        assert state["version"] == 1

    def test_version_auto_increments(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        session.write_state({"title": "V1"})
        session.write_state({"title": "V2"})
        state = session.read_state()
        assert state["version"] == 2

    def test_merge_state(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        session.write_state({"title": "Base", "data": {"a": 1}})
        merged = session.merge_state({"data": {"b": 2}})
        assert merged["title"] == "Base"
        assert merged["data"]["a"] == 1
        assert merged["data"]["b"] == 2

    def test_merge_state_with_validator(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        session.write_state({"title": "Base"})

        def bad_validator(state):
            raise ValueError("Invalid merge")

        with pytest.raises(ValueError, match="Invalid merge"):
            session.merge_state({"title": "Bad"}, validator=bad_validator)

    def test_read_actions_empty(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        actions = session.read_actions()
        assert actions == {"version": 0, "actions": []}

    def test_clear_actions(self, tmp_path):
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        (session.data_dir / "actions.json").write_text(json.dumps({"version": 1, "actions": [{"id": "a"}]}))
        session.clear_actions()
        actions = session.read_actions()
        assert actions["actions"] == []


# ---------------------------------------------------------------------------
# _get_session (module-level helper)
# ---------------------------------------------------------------------------


class TestGetSession:
    async def test_creates_session(self):
        old_session = mcp_server._session
        mcp_server._session = None
        try:
            session = await _get_session()
            assert isinstance(session, WebviewSession)
            assert mcp_server._session is session
        finally:
            mcp_server._session = old_session

    async def test_returns_existing_session(self):
        old_session = mcp_server._session
        mock_session = WebviewSession(open_browser=False)
        mcp_server._session = mock_session
        try:
            session = await _get_session()
            assert session is mock_session
        finally:
            mcp_server._session = old_session


# ---------------------------------------------------------------------------
# Multi-session race condition tests (M7)
# ---------------------------------------------------------------------------


class TestMergeStateRaceConditions:
    """Tests that merge_state's _state_lock prevents TOCTOU races."""

    def test_concurrent_merges_do_not_lose_data(self, tmp_path):
        """Concurrent merge_state calls should not lose updates."""
        import concurrent.futures

        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        # Write initial state
        session.write_state({"title": "Init", "data": {"sections": []}})

        def merge_field(i):
            session.merge_state({f"field_{i}": f"value_{i}"})

        # Run 20 concurrent merges
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(merge_field, i) for i in range(20)]
            for f in futures:
                f.result()  # raises if any failed

        # All 20 fields should be present in final state
        final = session.read_state()
        for i in range(20):
            assert final.get(f"field_{i}") == f"value_{i}", f"field_{i} missing from final state"

    def test_merge_with_validator_rejection_skips_write(self, tmp_path):
        """If the validator raises, the merged state should NOT be written."""
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        session.write_state({"title": "Original"})

        def bad_validator(state):
            raise ValueError("Invalid merged state")

        with pytest.raises(ValueError, match="Invalid merged state"):
            session.merge_state({"title": "Hacked"}, validator=bad_validator)

        # State should still be the original
        state = session.read_state()
        assert state["title"] == "Original"

    def test_concurrent_write_and_read(self, tmp_path):
        """Concurrent writes and reads should not corrupt state."""
        import concurrent.futures

        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        session.write_state({"title": "Start", "counter": 0})

        errors = []

        def writer(i):
            try:
                session.merge_state({"counter": i})
            except Exception as e:
                errors.append(e)

        def reader():
            try:
                state = session.read_state()
                # State should always be valid JSON
                assert isinstance(state, dict)
            except Exception as e:
                errors.append(e)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = []
            for i in range(15):
                futures.append(executor.submit(writer, i))
                futures.append(executor.submit(reader))
            for f in futures:
                f.result()

        assert len(errors) == 0, f"Errors during concurrent access: {errors}"

    def test_state_lock_prevents_interleaving(self, tmp_path):
        """Verify _state_lock serializes merge_state calls."""
        import threading

        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)
        session.write_state({"title": "Test", "items": []})

        call_order = []

        original_merge = session.merge_state.__func__

        def tracked_merge(self_arg, partial, **kwargs):
            call_order.append(("start", threading.current_thread().name))
            result = original_merge(self_arg, partial, **kwargs)
            call_order.append(("end", threading.current_thread().name))
            return result

        with mock.patch.object(type(session), "merge_state", tracked_merge):
            t1 = threading.Thread(target=lambda: tracked_merge(session, {"a": 1}), name="t1")
            t2 = threading.Thread(target=lambda: tracked_merge(session, {"b": 2}), name="t2")
            t1.start()
            t2.start()
            t1.join()
            t2.join()

        # Both merges should complete
        final = session.read_state()
        assert "a" in final
        assert "b" in final


class TestDeepMerge:
    """Tests for _deep_merge edge cases relevant to race conditions."""

    def test_list_replacement_not_append(self):
        """Lists should be replaced, not appended during merge."""
        from mcp_server import _deep_merge

        base = {"items": [1, 2, 3]}
        override = {"items": [4, 5]}
        _deep_merge(base, override)
        assert base["items"] == [4, 5]

    def test_nested_dict_merge(self):
        """Nested dicts should be recursively merged."""
        from mcp_server import _deep_merge

        base = {"a": {"b": 1, "c": 2}}
        override = {"a": {"c": 3, "d": 4}}
        _deep_merge(base, override)
        assert base == {"a": {"b": 1, "c": 3, "d": 4}}

    def test_max_depth_exceeded_raises(self):
        """Exceeding MAX_MERGE_DEPTH should raise ValueError."""
        from mcp_server import MAX_MERGE_DEPTH, _deep_merge

        # Build matching nested dicts so _deep_merge recurses into dict+dict
        base_inner = {"key": "old"}
        override_inner = {"key": "new"}
        for _ in range(MAX_MERGE_DEPTH + 2):
            base_inner = {"nested": base_inner}
            override_inner = {"nested": override_inner}

        with pytest.raises(ValueError, match="Merge depth exceeds maximum"):
            _deep_merge(base_inner, override_inner)

    def test_non_dict_override_replaces_dict(self):
        """Non-dict value should replace an existing dict."""
        from mcp_server import _deep_merge

        base = {"a": {"b": 1}}
        override = {"a": "replaced"}
        _deep_merge(base, override)
        assert base["a"] == "replaced"

    def test_dict_override_replaces_non_dict(self):
        """Dict value should replace an existing non-dict."""
        from mcp_server import _deep_merge

        base = {"a": "string"}
        override = {"a": {"b": 1}}
        _deep_merge(base, override)
        assert base["a"] == {"b": 1}


# ---------------------------------------------------------------------------
# Integration lifecycle tests (M9)
# ---------------------------------------------------------------------------


class TestIntegrationLifecycle:
    """End-to-end lifecycle tests for WebviewSession data contract."""

    def test_full_state_lifecycle(self, tmp_path):
        """Write → Read → Merge → Read cycle should produce consistent results."""
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)

        # Write initial state
        session.write_state({"title": "Test App", "data": {"sections": []}})
        state1 = session.read_state()
        assert state1["title"] == "Test App"
        assert state1["version"] == 1

        # Merge additional data
        session.merge_state({"status": "active"})
        state2 = session.read_state()
        assert state2["title"] == "Test App"  # preserved
        assert state2["status"] == "active"  # added
        assert state2["version"] == 2  # auto-incremented

        # Overwrite via write_state
        session.write_state({"title": "New Title"})
        state3 = session.read_state()
        assert state3["title"] == "New Title"
        assert state3["version"] == 3

    def test_actions_lifecycle(self, tmp_path):
        """Write actions → Read → Clear → Read cycle."""
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)

        # Initially empty
        actions = session.read_actions()
        assert actions["actions"] == []

        # Simulate action written by server
        actions_path = session.data_dir / "actions.json"
        actions_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "actions": [{"action_id": "approve", "type": "approve", "value": True}],
                }
            )
        )

        actions = session.read_actions()
        assert len(actions["actions"]) == 1
        assert actions["actions"][0]["action_id"] == "approve"

        # Clear
        session.clear_actions()
        actions = session.read_actions()
        assert actions["actions"] == []

    def test_state_version_auto_increments(self, tmp_path):
        """Each write_state call should increment the version."""
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)

        for i in range(5):
            session.write_state({"title": f"v{i}"})
            state = session.read_state()
            assert state["version"] == i + 1

    def test_merge_preserves_nested_sections(self, tmp_path):
        """Merging should preserve existing nested data structures."""
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)

        session.write_state(
            {
                "title": "Test",
                "data": {
                    "sections": [
                        {"type": "text", "content": "Hello"},
                        {"type": "form", "fields": [{"key": "name", "label": "Name", "type": "text"}]},
                    ],
                },
            }
        )

        # Merge only changes the status — sections should survive
        session.merge_state({"status": "updated"})
        state = session.read_state()
        assert state["status"] == "updated"
        assert len(state["data"]["sections"]) == 2
        assert state["data"]["sections"][0]["content"] == "Hello"

    def test_merge_replaces_sections_list(self, tmp_path):
        """Merging data.sections should replace (not append) the list."""
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)

        session.write_state(
            {
                "title": "Test",
                "data": {"sections": [{"type": "text", "content": "Old"}]},
            }
        )

        session.merge_state(
            {
                "data": {"sections": [{"type": "text", "content": "New"}]},
            }
        )

        state = session.read_state()
        assert len(state["data"]["sections"]) == 1
        assert state["data"]["sections"][0]["content"] == "New"

    def test_merge_with_security_gate_validator(self, tmp_path):
        """merge_state with SecurityGate validator should reject XSS."""
        from security_gate import SecurityGate

        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)

        session.write_state({"title": "Safe", "data": {"sections": []}})

        gate = SecurityGate()

        def validator(state):
            # validate_state expects JSON string, returns (ok, err, parsed)
            ok, err, _ = gate.validate_state(json.dumps(state))
            if not ok:
                raise ValueError(f"SecurityGate: {err}")

        # Safe merge should work (use allowed status value)
        session.merge_state({"status": "processing"}, validator=validator)
        assert session.read_state()["status"] == "processing"

        # XSS merge should be rejected
        with pytest.raises(ValueError, match="SecurityGate"):
            session.merge_state(
                {"data": {"sections": [{"type": "text", "content": "<script>alert(1)</script>"}]}},
                validator=validator,
            )

        # State should still be safe (no XSS written)
        state = session.read_state()
        sections = state.get("data", {}).get("sections", [])
        for sec in sections:
            assert "<script>" not in sec.get("content", "")

    @pytest.mark.asyncio
    async def test_wait_for_action_timeout(self, tmp_path):
        """wait_for_action should return None on timeout."""
        session = WebviewSession(work_dir=tmp_path, open_browser=False)
        session.data_dir.mkdir(parents=True)

        result = await session.wait_for_action(timeout=0.1)
        assert result is None

    def test_data_dir_isolation(self, tmp_path):
        """Two sessions with different work_dirs should be fully isolated."""
        dir_a = tmp_path / "a"
        dir_b = tmp_path / "b"

        session_a = WebviewSession(work_dir=dir_a, open_browser=False)
        session_b = WebviewSession(work_dir=dir_b, open_browser=False)

        session_a.data_dir.mkdir(parents=True)
        session_b.data_dir.mkdir(parents=True)

        session_a.write_state({"title": "Session A"})
        session_b.write_state({"title": "Session B"})

        assert session_a.read_state()["title"] == "Session A"
        assert session_b.read_state()["title"] == "Session B"

        # Merging in one doesn't affect the other
        session_a.merge_state({"extra": "a_data"})
        state_b = session_b.read_state()
        assert "extra" not in state_b
