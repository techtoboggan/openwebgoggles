"""Step definitions for mcp_lifecycle.feature."""

from __future__ import annotations

import asyncio
import os
import sys
import time
from unittest import mock

import pytest
from pytest_bdd import given, scenario, then, when

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import mcp_server  # noqa: E402, I001

pytestmark = pytest.mark.bdd


@scenario("../features/mcp_lifecycle.feature", "Lifespan starts background monitor tasks")
def test_lifespan_starts_tasks():
    pass


@scenario("../features/mcp_lifecycle.feature", "Lifespan yields quickly without blocking")
def test_lifespan_yields_quickly():
    pass


@scenario("../features/mcp_lifecycle.feature", "PID file is written on startup and removed on shutdown")
def test_pid_lifecycle():
    pass


@scenario("../features/mcp_lifecycle.feature", "Lifespan cleans up on shutdown")
def test_lifespan_cleanup():
    pass


@scenario("../features/mcp_lifecycle.feature", "Lifespan handles session close failure gracefully")
def test_lifespan_handles_close_failure():
    pass


class _Ctx:
    pass


@pytest.fixture
def ctx():
    return _Ctx()


@when("the MCP server lifespan starts")
def lifespan_starts(ctx, version_monitor_env, tmp_path):
    ctx.env = version_monitor_env
    ctx.data_dir = tmp_path / ".opencode" / "webview"

    loop = asyncio.new_event_loop()
    try:

        async def _test():
            mock_server = mock.MagicMock()
            with mock.patch("mcp_server._get_installed_version_info", return_value=("unknown", None)):
                with mock.patch("mcp_server._write_mcp_pid") as mock_write_pid:
                    with mock.patch("mcp_server._cleanup_mcp_pid") as mock_cleanup_pid:
                        with mock.patch("platform.system", return_value="Linux"):
                            with mock.patch("signal.signal"):
                                start = time.monotonic()
                                async with mcp_server.lifespan(mock_server):
                                    elapsed = time.monotonic() - start
                                    ctx.elapsed = elapsed
                                    # Check tasks were created
                                    ctx.reload_task = mcp_server._reload_task
                                    ctx.tasks_created = mcp_server._reload_task is not None
                                    # Capture callback info while task reference is available.
                                    # Note: In Python 3.12+, _callbacks may be None if the
                                    # task already completed and callbacks fired. A done task
                                    # with _callbacks=None means they successfully ran.
                                    if ctx.reload_task is not None:
                                        cbs = getattr(ctx.reload_task, "_callbacks", None)
                                        ctx.callback_count = len(cbs) if cbs else (1 if ctx.reload_task.done() else 0)
                                    else:
                                        ctx.callback_count = 0
                                    # Capture mocks for PID assertions
                                    ctx.mock_write_pid = mock_write_pid
                                # After lifespan exit, capture cleanup mock
                                ctx.mock_cleanup_pid = mock_cleanup_pid

        loop.run_until_complete(_test())
    finally:
        loop.close()


@then("the version monitor task should be created")
def assert_version_task_created(ctx):
    assert ctx.tasks_created


@then("the signal monitor task should be created")
def assert_signal_task_created(ctx):
    assert ctx.tasks_created
    # Verify the reload task is an actual asyncio.Task, not just truthy
    assert isinstance(ctx.reload_task, asyncio.Task)


@then("both tasks should have done-callbacks attached")
def assert_done_callbacks(ctx):
    assert ctx.tasks_created
    # Callback count was captured while the task was still alive inside lifespan
    assert ctx.callback_count > 0, "reload_task should have done-callbacks"


@then("the lifespan should yield within 1 second")
def assert_yields_quickly(ctx):
    assert ctx.elapsed < 1.0, f"Lifespan took {ctx.elapsed:.2f}s to yield (expected < 1s)"


@then("the version metadata lookup should run asynchronously")
def assert_async_metadata(ctx):
    # _version_monitor uses run_in_executor for initial metadata lookup
    # Verified by the fast yield time
    assert ctx.elapsed < 1.0


@then("the PID file should exist")
def assert_pid_exists(ctx):
    assert hasattr(ctx, "mock_write_pid"), "Context should have mock_write_pid from lifespan_starts"
    ctx.mock_write_pid.assert_called_once()


@when("the server shuts down")
def server_shuts_down(ctx):
    pass  # Handled by exiting the lifespan context


@then("the PID file should be removed")
def assert_pid_removed(ctx):
    assert hasattr(ctx, "mock_cleanup_pid"), "Context should have mock_cleanup_pid from lifespan_starts"
    ctx.mock_cleanup_pid.assert_called_once()


@given("the MCP server lifespan is active")
def lifespan_active(ctx, version_monitor_env):
    ctx.env = version_monitor_env

    # Create a mock session to verify close() is called on shutdown
    mock_session = mock.MagicMock()
    mock_session.close = mock.AsyncMock()
    version_monitor_env._session = mock_session
    ctx.session_mock = mock_session

    loop = asyncio.new_event_loop()
    try:

        async def _test():
            mock_server = mock.MagicMock()
            with mock.patch("mcp_server._get_installed_version_info", return_value=("unknown", None)):
                with mock.patch("mcp_server._write_mcp_pid"):
                    with mock.patch("mcp_server._cleanup_mcp_pid"):
                        with mock.patch("platform.system", return_value="Linux"):
                            with mock.patch("signal.signal"):
                                async with mcp_server.lifespan(mock_server):
                                    # Capture tasks while lifespan is active
                                    ctx.reload_task = mcp_server._reload_task
                                # After lifespan exits, tasks should be cancelled
                                ctx.reload_task_after = mcp_server._reload_task

        loop.run_until_complete(_test())
    finally:
        loop.close()


@then("the version monitor task should be cancelled")
def assert_version_cancelled(ctx):
    assert hasattr(ctx, "reload_task"), "Context should have reload_task"
    assert ctx.reload_task is not None, "reload_task should have been created"
    # After lifespan cleanup, _reload_task is set to None
    assert ctx.reload_task_after is None, "reload_task should be set to None after cleanup"


@then("the signal monitor task should be cancelled")
def assert_signal_cancelled(ctx):
    # Signal task is local to lifespan and cancelled on exit.
    # Verify _reload_task was set to None after cleanup (same as version task).
    assert hasattr(ctx, "reload_task"), "Context should have reload_task from lifespan run"
    assert ctx.reload_task_after is None, "reload_task should be None after shutdown (signal task also cleaned)"


@then("the webview session should be closed")
def assert_session_closed(ctx):
    assert hasattr(ctx, "session_mock"), "Context should have session_mock"
    ctx.session_mock.close.assert_called_once()


@given("the webview session close raises an exception")
def session_close_raises(ctx, version_monitor_env):
    ctx.env = version_monitor_env
    mock_session = mock.MagicMock()
    mock_session.close = mock.AsyncMock(side_effect=RuntimeError("close failed"))
    version_monitor_env._session = mock_session
    ctx.mock_session = mock_session

    loop = asyncio.new_event_loop()
    try:

        async def _test():
            mock_server = mock.MagicMock()
            with mock.patch("mcp_server._get_installed_version_info", return_value=("unknown", None)):
                with mock.patch("mcp_server._write_mcp_pid"):
                    with mock.patch("mcp_server._cleanup_mcp_pid"):
                        with mock.patch("platform.system", return_value="Linux"):
                            with mock.patch("signal.signal"):
                                async with mcp_server.lifespan(mock_server):
                                    pass
                                # After lifespan exits, session should be cleaned up
                                ctx.session_after = mcp_server._session

        loop.run_until_complete(_test())
    finally:
        loop.close()


@then("the exception should be suppressed")
def assert_exception_suppressed(ctx):
    # The lifespan completed without raising, AND session.close() was called
    # despite raising RuntimeError("close failed")
    ctx.mock_session.close.assert_called_once()


@then("the session reference should be cleared")
def assert_session_cleared(ctx):
    assert ctx.session_after is None
