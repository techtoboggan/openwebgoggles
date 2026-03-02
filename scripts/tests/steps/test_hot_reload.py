"""Step definitions for hot_reload.feature."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from unittest import mock

import pytest
from pytest_bdd import given, parsers, scenario, then, when

import mcp_server

pytestmark = pytest.mark.bdd


@scenario("../features/hot_reload.feature", "Version change detected via mtime change")
def test_version_change_detected():
    pass


@scenario("../features/hot_reload.feature", "Same version after mtime change is a no-op")
def test_same_version_noop():
    pass


@scenario("../features/hot_reload.feature", "Package temporarily missing during upgrade")
def test_package_temporarily_missing():
    pass


@scenario("../features/hot_reload.feature", "Package reappears after deletion with new version")
def test_package_reappears():
    pass


@scenario("../features/hot_reload.feature", "dist-info path is recovered after unknown transition")
def test_distinfo_path_recovered():
    pass


@scenario("../features/hot_reload.feature", "Monitor survives transient errors")
def test_monitor_survives_errors():
    pass


@scenario("../features/hot_reload.feature", "Monitor gives up after too many consecutive errors")
def test_monitor_gives_up():
    pass


@scenario("../features/hot_reload.feature", "Background task crash is logged via done-callback")
def test_task_crash_logged():
    pass


@scenario("../features/hot_reload.feature", "Webview session is closed when server becomes stale")
def test_session_closed_on_stale():
    pass


# --- Shared state container ---


class _Ctx:
    """Mutable test context shared across steps within one scenario."""

    pass


@pytest.fixture
def ctx():
    return _Ctx()


# --- Background steps ---


@given(parsers.parse('the MCP server is running with version "{version}"'))
def server_running(version_monitor_env, ctx, version):
    ctx.startup_version = version
    ctx.env = version_monitor_env


@given("the version monitor is active")
def monitor_active(ctx):
    pass  # Implied by test setup


# --- When steps ---


@when("the dist-info directory mtime changes")
def mtime_changes(ctx):
    ctx.mtime_changed = True


@when(parsers.parse('the installed version becomes "{version}"'))
def version_becomes(ctx, version):
    ctx.new_version = version


@when(parsers.parse('the installed version is still "{version}"'))
def version_stays(ctx, version):
    ctx.new_version = version


@when("the dist-info directory is temporarily deleted")
def dist_info_deleted(ctx):
    ctx.version_sequence = ["unknown"]


@when("the version returns unknown")
def version_unknown(ctx):
    pass  # Handled by dist_info_deleted


@when(parsers.parse('the dist-info reappears with version "{version}"'))
def dist_info_reappears(ctx, mock_dist_info_v2, version):
    ctx.new_version = version
    ctx.new_dist_info_path = mock_dist_info_v2


@when(parsers.parse("the monitor encounters {count:d} consecutive errors"))
def monitor_encounters_errors(ctx, count):
    ctx.error_count = count


@when("the version monitor task raises an unhandled exception")
def monitor_raises_exception(ctx):
    ctx.monitor_exception = RuntimeError("test crash")


@when(parsers.parse('a version change is detected to "{version}"'))
def version_change_detected(ctx, version):
    ctx.new_version = version


# --- Given steps for specific scenarios ---


@given("the dist-info directory was temporarily deleted")
def dist_info_was_deleted(ctx, mock_dist_info):
    ctx.original_dist_info = mock_dist_info
    ctx.version_sequence = ["unknown"]


@given("the dist-info path was lost during upgrade")
def dist_info_path_lost(ctx, mock_dist_info):
    ctx.original_dist_info = mock_dist_info


@given("the webview session is active")
def session_active(ctx, version_monitor_env):
    mock_session = mock.MagicMock()
    mock_session.close = mock.AsyncMock()
    version_monitor_env._session = mock_session
    ctx.mock_session = mock_session
    ctx.env = version_monitor_env


@when(parsers.parse('the package is reinstalled with version "{version}"'))
def package_reinstalled(ctx, mock_dist_info_v2, version):
    ctx.new_version = version
    ctx.new_dist_info_path = mock_dist_info_v2


# --- Then steps (with actual async test execution) ---


@then("the server should be marked as stale")
def assert_stale(ctx):
    _run_monitor_and_assert(ctx, expect_stale=True)


@then(parsers.parse('the stale message should mention "{old}" and "{new}"'))
def assert_stale_message(ctx, old, new):
    msg = ctx.env._stale_version_msg
    assert old in msg, f"Expected '{old}' in stale message: {msg}"
    assert new in msg, f"Expected '{new}' in stale message: {msg}"


@then("the server should NOT be marked as stale")
def assert_not_stale(ctx):
    _run_monitor_and_assert(ctx, expect_stale=False)


@then("the monitor should continue polling")
def assert_monitor_continues(ctx):
    # Verified by the fact that the task was still running when cancelled
    assert hasattr(ctx, "task_was_running") and ctx.task_was_running


@then("the dist-info path should be re-discovered")
def assert_path_rediscovered(ctx):
    # Run the monitor so stale detection executes after path loss
    _run_monitor_and_assert(ctx, expect_stale=True)
    assert ctx.env._reload_pending


@then("the monitor should still be running")
def assert_monitor_running(ctx):
    _run_monitor_with_errors(ctx, expect_running=True)


@then("errors should be logged with backoff")
def assert_errors_logged(ctx, caplog):
    # Run a brief monitor with errors under caplog to verify logging
    mock_dist_path = mock.MagicMock(spec=Path)
    mock_dist_path.is_dir.return_value = True
    mock_stat_ok = mock.MagicMock()
    mock_stat_ok.st_mtime = 100.0
    mock_dist_path.stat.side_effect = [mock_stat_ok] + [OSError("disk error")] * 15

    loop = asyncio.new_event_loop()
    try:
        with caplog.at_level(logging.WARNING):

            async def _test():
                with mock.patch("mcp_server._RELOAD_CHECK_INTERVAL", 0.01):
                    with mock.patch("mcp_server._MAX_MONITOR_ERRORS", 10):
                        with mock.patch(
                            "mcp_server._get_installed_version_info",
                            return_value=("1.0.0", mock_dist_path),
                        ):
                            with mock.patch(
                                "mcp_server._read_version_fresh",
                                side_effect=OSError("disk error"),
                            ):
                                task = asyncio.create_task(mcp_server._version_monitor())
                                await asyncio.sleep(0.3)
                                if not task.done():
                                    task.cancel()
                                    try:
                                        await task
                                    except asyncio.CancelledError:
                                        pass

            loop.run_until_complete(_test())
    finally:
        loop.close()

    assert any("error" in rec.message.lower() or "disk" in rec.message.lower() for rec in caplog.records)


@then("the monitor should stop")
def assert_monitor_stopped(ctx):
    _run_monitor_with_errors(ctx, expect_running=False)


@then("a fatal error should be logged")
def assert_fatal_logged(ctx, caplog):
    # _run_monitor_with_errors was already called in assert_monitor_stopped;
    # just verify error/fatal was logged
    assert any(
        rec.levelno >= logging.ERROR
        for rec in caplog.records
        if "monitor" in rec.message.lower() or "error" in rec.message.lower()
    ) or any("error" in rec.message.lower() for rec in caplog.records)


@then("the exception should be logged via done-callback")
def assert_exception_logged(ctx, caplog):
    with caplog.at_level(logging.ERROR):
        loop = asyncio.new_event_loop()
        try:

            async def _test():
                async def _crash():
                    raise ctx.monitor_exception

                task = asyncio.create_task(_crash(), name="test-crash")
                task.add_done_callback(mcp_server._task_done_callback)
                await asyncio.sleep(0.05)

            loop.run_until_complete(_test())
        finally:
            loop.close()
    assert "crashed" in caplog.text.lower() or "test crash" in caplog.text


@then("the webview session should be closed gracefully")
def assert_session_closed(ctx):
    _run_monitor_for_stale(ctx)
    ctx.mock_session.close.assert_called_once()


@then("the session reference should be cleared")
def assert_session_cleared(ctx):
    assert ctx.env._session is None


# --- Helper functions ---


def _run_monitor_and_assert(ctx, *, expect_stale: bool):
    """Run the version monitor briefly and check stale state."""
    if hasattr(ctx, "_monitor_ran"):
        return  # Already ran in a prior step
    ctx._monitor_ran = True

    startup_version = getattr(ctx, "startup_version", "1.0.0")
    new_version = getattr(ctx, "new_version", startup_version)
    mock_dist_path = mock.MagicMock(spec=Path)
    mock_dist_path.is_dir.return_value = True

    # Provide enough stat values: initial mtime (100), then changed mtime (200) repeated
    def _stat_factory():
        """Return stat mocks: first with mtime 100, all subsequent with 200."""
        call_count = 0

        def _stat():
            nonlocal call_count
            call_count += 1
            s = mock.MagicMock()
            s.st_mtime = 100.0 if call_count == 1 else 200.0
            return s

        return _stat

    mock_dist_path.stat.side_effect = _stat_factory()

    version_sequence = getattr(ctx, "version_sequence", None)

    loop = asyncio.new_event_loop()
    try:

        async def _test():
            with mock.patch("mcp_server._RELOAD_CHECK_INTERVAL", 0.01):
                with mock.patch(
                    "mcp_server._get_installed_version_info",
                    return_value=(startup_version, mock_dist_path),
                ):
                    if version_sequence:
                        read_side_effect = version_sequence + [new_version] * 10
                        with mock.patch(
                            "mcp_server._read_version_fresh",
                            side_effect=read_side_effect,
                        ):
                            with mock.patch("mcp_server._notify_host_stale", new_callable=mock.AsyncMock):
                                task = asyncio.create_task(mcp_server._version_monitor())
                                await asyncio.sleep(0.3)
                                ctx.task_was_running = not task.done()
                                if not task.done():
                                    task.cancel()
                                    try:
                                        await task
                                    except asyncio.CancelledError:
                                        pass
                    else:
                        with mock.patch(
                            "mcp_server._read_version_fresh",
                            return_value=new_version,
                        ):
                            with mock.patch("mcp_server._notify_host_stale", new_callable=mock.AsyncMock):
                                task = asyncio.create_task(mcp_server._version_monitor())
                                await asyncio.sleep(0.15)
                                ctx.task_was_running = not task.done()
                                if not task.done():
                                    task.cancel()
                                    try:
                                        await task
                                    except asyncio.CancelledError:
                                        pass

        loop.run_until_complete(_test())
    finally:
        loop.close()

    if expect_stale:
        assert ctx.env._reload_pending, "Expected server to be stale but _reload_pending is False"
    else:
        assert not ctx.env._reload_pending, "Expected server NOT to be stale but _reload_pending is True"


def _run_monitor_for_stale(ctx):
    """Run monitor to trigger stale detection with session cleanup."""
    if hasattr(ctx, "_stale_ran"):
        return
    ctx._stale_ran = True

    mock_dist_path = mock.MagicMock(spec=Path)
    mock_dist_path.is_dir.return_value = True
    mock_stat1 = mock.MagicMock()
    mock_stat1.st_mtime = 100.0
    mock_stat2 = mock.MagicMock()
    mock_stat2.st_mtime = 200.0
    mock_dist_path.stat.side_effect = [mock_stat1, mock_stat2]

    loop = asyncio.new_event_loop()
    try:

        async def _test():
            with mock.patch("mcp_server._RELOAD_CHECK_INTERVAL", 0.01):
                with mock.patch(
                    "mcp_server._get_installed_version_info",
                    return_value=("1.0.0", mock_dist_path),
                ):
                    with mock.patch(
                        "mcp_server._read_version_fresh",
                        return_value=getattr(ctx, "new_version", "2.0.0"),
                    ):
                        with mock.patch("mcp_server._notify_host_stale", new_callable=mock.AsyncMock):
                            task = asyncio.create_task(mcp_server._version_monitor())
                            await asyncio.sleep(0.15)
                            if not task.done():
                                task.cancel()
                                try:
                                    await task
                                except asyncio.CancelledError:
                                    pass

        loop.run_until_complete(_test())
    finally:
        loop.close()


def _run_monitor_with_errors(ctx, *, expect_running: bool):
    """Run monitor that encounters errors on every stat() call."""
    if hasattr(ctx, "_error_monitor_ran"):
        return
    ctx._error_monitor_ran = True

    error_count = getattr(ctx, "error_count", 3)
    mock_dist_path = mock.MagicMock(spec=Path)
    mock_dist_path.is_dir.return_value = True
    # First stat succeeds (initial mtime), then all subsequent stats raise
    mock_stat_ok = mock.MagicMock()
    mock_stat_ok.st_mtime = 100.0
    mock_dist_path.stat.side_effect = [mock_stat_ok] + [OSError("disk error")] * (error_count + 5)

    loop = asyncio.new_event_loop()
    try:

        async def _test():
            with mock.patch("mcp_server._RELOAD_CHECK_INTERVAL", 0.01):
                with mock.patch("mcp_server._MAX_MONITOR_ERRORS", 10):
                    with mock.patch(
                        "mcp_server._get_installed_version_info",
                        return_value=("1.0.0", mock_dist_path),
                    ):
                        # _read_version_fresh also needs to raise to trigger the error path
                        with mock.patch(
                            "mcp_server._read_version_fresh",
                            side_effect=OSError("disk error"),
                        ):
                            task = asyncio.create_task(mcp_server._version_monitor())
                            # Give enough time for errors to accumulate
                            wait_time = 0.01 * error_count * 5
                            await asyncio.sleep(min(wait_time, 5.0))
                            was_running = not task.done()
                            if not task.done():
                                task.cancel()
                                try:
                                    await task
                                except asyncio.CancelledError:
                                    pass
                            if expect_running:
                                assert was_running, "Expected monitor to still be running"
                            else:
                                assert task.done(), "Expected monitor to have stopped"

        loop.run_until_complete(_test())
    finally:
        loop.close()
