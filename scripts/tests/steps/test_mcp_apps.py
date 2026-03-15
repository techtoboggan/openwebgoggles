"""Step definitions for mcp_apps.feature."""

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


# ---------------------------------------------------------------------------
# Scenario wiring
# ---------------------------------------------------------------------------


@scenario(
    "../features/mcp_apps.feature",
    "App mode returns structuredContent without launching browser",
)
def test_app_mode_structured_content():
    pass


@scenario(
    "../features/mcp_apps.feature",
    "Browser fallback when host lacks MCP Apps",
)
def test_browser_fallback():
    pass


@scenario(
    "../features/mcp_apps.feature",
    "User action received via _owg_action",
)
def test_owg_action_received():
    pass


@scenario(
    "../features/mcp_apps.feature",
    "App mode state is cleared on webview_close",
)
def test_app_mode_state_cleared():
    pass


# ---------------------------------------------------------------------------
# Shared state container
# ---------------------------------------------------------------------------


class _Ctx:
    pass


@pytest.fixture
def ctx():
    return _Ctx()


@pytest.fixture(autouse=True)
def _reset_app_mode_state():
    """Reset MCP Apps globals before each scenario."""
    old_fetched = mcp_server._host_fetched_ui_resource
    old_manager = mcp_server._session_manager
    old_security_gate = mcp_server._security_gate
    old_cached_mode = mcp_server._cached_mode

    mcp_server._host_fetched_ui_resource = False
    mcp_server._session_manager = mcp_server.SessionManager()
    mcp_server._cached_mode = None
    # Disable security gate to avoid side effects in unit tests
    mcp_server._security_gate = None

    yield

    mcp_server._host_fetched_ui_resource = old_fetched
    mcp_server._session_manager = old_manager
    mcp_server._security_gate = old_security_gate
    mcp_server._cached_mode = old_cached_mode


# ---------------------------------------------------------------------------
# Given steps
# ---------------------------------------------------------------------------


@given("the host has fetched the UI resource")
def host_fetched_resource(ctx):
    mcp_server._host_fetched_ui_resource = True
    mcp_server._cached_mode = "app"


@given("the host has not fetched the UI resource")
def host_not_fetched_resource(ctx):
    mcp_server._host_fetched_ui_resource = False
    mcp_server._cached_mode = None


@given("the agent has displayed a webview")
def agent_displayed_webview(ctx):
    loop = asyncio.new_event_loop()
    try:

        async def _display():
            result = await mcp_server.openwebgoggles(
                state={"title": "Active UI", "data": {"sections": []}},
            )
            return result

        ctx.webview_result = loop.run_until_complete(_display())
    finally:
        loop.close()

    # Verify the webview was displayed in app mode (CallToolResult)
    assert hasattr(ctx.webview_result, "structuredContent")


# ---------------------------------------------------------------------------
# When steps
# ---------------------------------------------------------------------------


@when('the agent calls webview with title "Test UI"')
def call_webview_test_ui(ctx):
    loop = asyncio.new_event_loop()
    try:

        async def _call():
            return await mcp_server.openwebgoggles(
                state={"title": "Test UI", "data": {"sections": []}},
            )

        ctx.result = loop.run_until_complete(_call())
    finally:
        loop.close()


@when('the agent calls webview with title "Fallback UI"')
def call_webview_fallback_ui(ctx):
    mock_session = mock.AsyncMock()
    mock_session.ensure_started = mock.AsyncMock()
    mock_session.clear_actions = mock.MagicMock()
    mock_session.write_state = mock.MagicMock()
    mock_session.wait_for_action = mock.AsyncMock(
        return_value={"actions": [{"action_id": "ok", "type": "click"}]},
    )

    loop = asyncio.new_event_loop()
    try:

        async def _call():
            with mock.patch("mcp_server._get_browser_session", return_value=mock_session):
                return await mcp_server.openwebgoggles(
                    state={"title": "Fallback UI", "data": {"sections": []}},
                    timeout=30,
                )

        ctx.result = loop.run_until_complete(_call())
        ctx.mock_session = mock_session
    finally:
        loop.close()


@when('the user clicks a button with action_id "approve"')
def user_clicks_approve(ctx):
    loop = asyncio.new_event_loop()
    try:

        async def _action():
            return await mcp_server._owg_action(
                action_id="approve",
                action_type="click",
                value=True,
            )

        ctx.action_result = loop.run_until_complete(_action())
    finally:
        loop.close()


@when("the agent calls webview_close")
def call_webview_close(ctx):
    loop = asyncio.new_event_loop()
    try:

        async def _close():
            return await mcp_server.openwebgoggles_close(message="Done.")

        ctx.close_result = loop.run_until_complete(_close())
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# Then steps
# ---------------------------------------------------------------------------


@then("the result should contain structuredContent")
def assert_structured_content(ctx):
    assert hasattr(ctx.result, "structuredContent"), (
        f"Expected CallToolResult with structuredContent, got: {type(ctx.result).__name__}"
    )
    assert ctx.result.structuredContent["title"] == "Test UI"


@then("no browser subprocess should be launched")
def assert_no_browser_launched(ctx):
    # In app mode, webview returns structuredContent directly — no session
    # is created. Verify that _session was NOT touched.
    slot = mcp_server._session_manager._slots.get("default")
    assert slot is None or slot.browser_session is None, "Browser session should not have been created in app mode"


@then("the browser fallback should be used")
def assert_browser_fallback(ctx):
    # The mock session's ensure_started should have been called
    ctx.mock_session.ensure_started.assert_called_once()
    ctx.mock_session.write_state.assert_called_once()
    ctx.mock_session.wait_for_action.assert_called_once()
    # Browser mode returns plain dict from wait_for_action (not CallToolResult)
    assert isinstance(ctx.result, dict), f"Browser fallback should return plain dict, got: {type(ctx.result).__name__}"
    assert "actions" in ctx.result


@then("webview_read should return the action")
def assert_webview_read_returns_action(ctx):
    loop = asyncio.new_event_loop()
    try:

        async def _read():
            return await mcp_server.openwebgoggles_read(clear=False)

        ctx.read_result = loop.run_until_complete(_read())
    finally:
        loop.close()

    assert "actions" in ctx.read_result, f"Expected 'actions' key, got: {ctx.read_result}"
    assert len(ctx.read_result["actions"]) > 0, "Expected at least one action"


@then('the action should have action_id "approve"')
def assert_action_id_approve(ctx):
    actions = ctx.read_result["actions"]
    action_ids = [a["action_id"] for a in actions]
    assert "approve" in action_ids, f"Expected 'approve' in action_ids, got: {action_ids}"


@then("the app mode state should be empty")
def assert_app_mode_cleared(ctx):
    assert ctx.close_result["status"] == "ok", f"Expected status 'ok', got: {ctx.close_result}"
    # After webview_close, app_mode_state should be cleared
    app_state = mcp_server._get_app_state()
    assert app_state.state == {}, f"Expected empty state, got: {app_state.state}"
    assert app_state.state_version > 0, f"Expected epoch-ms baseline version, got: {app_state.state_version}"
    assert app_state.read_actions() == [], f"Expected empty actions, got: {app_state.read_actions()}"
