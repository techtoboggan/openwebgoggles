"""Step definitions for stale_server.feature."""

from __future__ import annotations

import asyncio
import os
import sys
from unittest import mock

import pytest
from pytest_bdd import given, scenario, then, when

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import mcp_server  # noqa: E402, I001

pytestmark = pytest.mark.bdd


@scenario("../features/stale_server.feature", "Tool call rejected when server is stale")
def test_stale_rejection():
    pass


@scenario("../features/stale_server.feature", "Stale flag persists across multiple tool calls")
def test_stale_persists():
    pass


@scenario("../features/stale_server.feature", "Active tool call count decrements on exception")
def test_decrement_on_exception():
    pass


@scenario("../features/stale_server.feature", "Proactive host notification sent on staleness")
def test_proactive_notification():
    pass


@scenario("../features/stale_server.feature", "Proactive notification fails gracefully")
def test_notification_fails_gracefully():
    pass


class _Ctx:
    pass


@pytest.fixture
def ctx():
    return _Ctx()


@given("the server has been marked as stale")
def server_stale(version_monitor_env, ctx):
    ctx.env = version_monitor_env
    version_monitor_env._reload_pending = True
    version_monitor_env._stale_version_msg = "Server needs restart"


@when("a tool call is made")
def make_tool_call(ctx):
    @mcp_server._track_tool_call
    async def _dummy():
        return "should not execute"

    loop = asyncio.new_event_loop()
    try:
        ctx.result = loop.run_until_complete(_dummy())
    finally:
        loop.close()


@then("the response should contain an error message")
def assert_error_response(ctx):
    assert "error" in ctx.result


@then("the error should mention restart")
def assert_mentions_restart(ctx):
    assert "restart" in ctx.result.get("error", "").lower() or "restart" in str(ctx.result).lower()


@when("multiple tool calls are made")
def make_multiple_calls(ctx):
    @mcp_server._track_tool_call
    async def _dummy():
        ctx.executed = True
        return "should not execute"

    ctx.executed = False
    ctx.results = []
    loop = asyncio.new_event_loop()
    try:
        for _ in range(3):
            result = loop.run_until_complete(_dummy())
            ctx.results.append(result)
    finally:
        loop.close()


@then("all should return the stale error")
def assert_all_stale(ctx):
    for r in ctx.results:
        assert "error" in r


@then("none should execute the tool function")
def assert_none_executed(ctx):
    assert not ctx.executed


@given("a tool call is in progress")
def tool_in_progress(version_monitor_env, ctx):
    ctx.env = version_monitor_env


@when("the tool function raises an exception")
def tool_raises(ctx):
    @mcp_server._track_tool_call
    async def _crash():
        raise ValueError("tool error")

    loop = asyncio.new_event_loop()
    try:
        try:
            loop.run_until_complete(_crash())
        except ValueError:
            pass
        ctx.active_after = mcp_server._active_tool_calls
    finally:
        loop.close()


@then("the active tool call count should decrement to zero")
def assert_count_zero(ctx):
    assert ctx.active_after == 0


@given("the MCP server session is active")
def mcp_session_active(version_monitor_env, ctx):
    ctx.env = version_monitor_env


@when("the server is marked as stale")
def mark_stale(ctx):
    loop = asyncio.new_event_loop()
    try:

        async def _test():
            with mock.patch("mcp_server._notify_host_stale", new_callable=mock.AsyncMock) as mock_notify:
                mcp_server._mark_stale("1.0.0", "2.0.0")
                # Let the scheduled task run
                await asyncio.sleep(0.05)
                ctx.notify_called = mock_notify.called

        loop.run_until_complete(_test())
    finally:
        loop.close()


@then("a log notification should be attempted to the host")
def assert_notification_attempted(ctx):
    assert ctx.notify_called


@given("the MCP server session is not available")
def no_mcp_session(version_monitor_env, ctx):
    ctx.env = version_monitor_env


@then("the notification attempt should not raise")
def assert_no_raise(ctx):
    # _mark_stale uses try/except around the notification
    loop = asyncio.new_event_loop()
    try:

        async def _test():
            # Mock mcp object with no server attribute
            with mock.patch("mcp_server.mcp", create=True) as mock_mcp:
                mock_mcp._mcp_server = None
                mock_mcp.server = None
                mcp_server._mark_stale("1.0.0", "2.0.0")
                await asyncio.sleep(0.05)

        loop.run_until_complete(_test())
    finally:
        loop.close()
    # If we get here without exception, the test passes


@then("the stale flag should still be set")
def assert_stale_set(ctx):
    assert mcp_server._stale_version_msg != ""
