"""Step definitions for anti_zombification.feature.

These scenarios validate the guardrails that prevent coding agents from
"forgetting" they have an open browser session: _hint fields, ping tool,
status hints, and the workflow MCP prompt.
"""

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
    "../features/anti_zombification.feature",
    "openwebgoggles tool returns a _hint reminding agent to continue",
)
def test_openwebgoggles_returns_hint():
    pass


@scenario(
    "../features/anti_zombification.feature",
    "openwebgoggles_ping updates the display in app mode",
)
def test_ping_updates_app_mode():
    pass


@scenario(
    "../features/anti_zombification.feature",
    "openwebgoggles_ping works in browser mode",
)
def test_ping_browser_mode():
    pass


@scenario(
    "../features/anti_zombification.feature",
    "openwebgoggles_status includes hint about open sessions",
)
def test_status_includes_hint():
    pass


@scenario(
    "../features/anti_zombification.feature",
    "Workflow prompt is registered and contains key guidance",
)
def test_workflow_prompt_content():
    pass


@scenario(
    "../features/anti_zombification.feature",
    "openwebgoggles_ping is rejected by SecurityGate if message is too long",
)
def test_ping_long_message():
    pass


# ---------------------------------------------------------------------------
# Shared state container
# ---------------------------------------------------------------------------


class _Ctx:
    result = None
    app_state = None
    session_slot = None
    prompt_text = None
    mock_session = None


@pytest.fixture
def ctx():
    return _Ctx()


@pytest.fixture(autouse=True)
def _reset_globals():
    """Reset MCP globals before each scenario."""
    old_fetched = mcp_server._host_fetched_ui_resource
    old_manager = mcp_server._session_manager
    old_cached_mode = mcp_server._cached_mode

    mcp_server._host_fetched_ui_resource = False
    mcp_server._session_manager = mcp_server.SessionManager()
    mcp_server._cached_mode = None

    yield

    mcp_server._host_fetched_ui_resource = old_fetched
    mcp_server._session_manager = old_manager
    mcp_server._cached_mode = old_cached_mode


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_app_state_mock():
    m = mock.MagicMock()
    m.write_state = mock.MagicMock()
    return m


def _make_live_browser_session():
    """Return a mock WebviewSession that appears alive."""
    s = mock.MagicMock()
    s.is_alive.return_value = True
    s.write_state = mock.MagicMock()
    return s


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# Given steps
# ---------------------------------------------------------------------------


@given("the agent calls openwebgoggles with a simple state")
def agent_calls_openwebgoggles(ctx):
    """Set up app mode and call openwebgoggles() — stores result on ctx."""
    mcp_server._host_fetched_ui_resource = True
    mcp_server._cached_mode = "app"
    app_state = _make_app_state_mock()
    ctx.app_state = app_state

    async def _call():
        with mock.patch("mcp_server._get_app_state", return_value=app_state):
            raw = await mcp_server.openwebgoggles(
                state={"title": "Test", "data": {"sections": []}},
            )
            # In app mode openwebgoggles() returns a CallToolResult whose
            # structuredContent carries the state dict (including _hint).
            # Normalise to a plain dict so Then steps can use the same path.
            if hasattr(raw, "structuredContent"):
                return dict(raw.structuredContent)
            return raw

    ctx.result = _run(_call())


@given("the host has fetched the UI resource")
def host_fetched(ctx):
    mcp_server._host_fetched_ui_resource = True
    mcp_server._cached_mode = "app"


@given("the host has not fetched the UI resource")
def host_not_fetched(ctx):
    mcp_server._host_fetched_ui_resource = False
    mcp_server._cached_mode = None


@given("a browser session is open")
def browser_session_open(ctx):
    ctx.mock_session = _make_live_browser_session()


@given('a named session "work" is open')
def named_session_open(ctx):
    # Inject a mock slot into the session manager
    slot = mock.MagicMock()
    slot.mode = "browser"
    slot.name = "work"
    slot.browser_session = _make_live_browser_session()

    async def _get(name):
        return slot

    mcp_server._session_manager.get = _get
    ctx.session_slot = slot


# ---------------------------------------------------------------------------
# When steps
# ---------------------------------------------------------------------------


@when("the tool returns")
def tool_returns(ctx):
    # Result already set in Given step
    pass


@when('the agent calls openwebgoggles_ping with message "Analyzing files"')
def ping_app_mode(ctx):
    app_state = _make_app_state_mock()
    ctx.app_state = app_state

    async def _call():
        with mock.patch("mcp_server._get_app_state", return_value=app_state):
            return await mcp_server.openwebgoggles_ping("Analyzing files")

    ctx.result = _run(_call())


@when('the agent calls openwebgoggles_ping with message "Running tests"')
def ping_browser_mode(ctx):
    mock_session = ctx.mock_session or _make_live_browser_session()
    ctx.mock_session = mock_session

    slot = mock.MagicMock()
    slot.browser_session = mock_session

    async def _get(name):
        return slot

    mcp_server._session_manager.get = _get

    async def _call():
        return await mcp_server.openwebgoggles_ping("Running tests")

    ctx.result = _run(_call())


@when("the agent calls openwebgoggles_status")
def call_status(ctx):
    async def _call():
        return await mcp_server.openwebgoggles_status()

    ctx.result = _run(_call())


@when("the agent host fetches the openwebgoggles_workflow prompt")
def fetch_workflow_prompt(ctx):
    ctx.prompt_text = mcp_server.openwebgoggles_workflow()


@when("the agent calls openwebgoggles_ping with a 1000-character message")
def ping_long_message(ctx):
    long_msg = "x" * 1000
    app_state = _make_app_state_mock()
    ctx.app_state = app_state
    mcp_server._host_fetched_ui_resource = True
    mcp_server._cached_mode = "app"

    async def _call():
        with mock.patch("mcp_server._get_app_state", return_value=app_state):
            return await mcp_server.openwebgoggles_ping(long_msg)

    ctx.result = _run(_call())


# ---------------------------------------------------------------------------
# Then steps
# ---------------------------------------------------------------------------


@then('the result should contain a "_hint" key')
def result_has_hint(ctx):
    assert "_hint" in ctx.result, f"Expected '_hint' in result, got keys: {list(ctx.result.keys())}"


@then("the hint text should be non-empty")
def hint_nonempty(ctx):
    assert ctx.result["_hint"], "Expected non-empty _hint text"


@then("the hint should mention the session is still open")
def hint_mentions_open(ctx):
    hint = ctx.result["_hint"].lower()
    # Hint should convey that the window is still open and agent should continue
    assert any(word in hint for word in ["open", "window", "session", "continue", "close"]), (
        f"Hint doesn't mention session state: {ctx.result['_hint']}"
    )


@then('the app state should be updated with status "processing"')
def app_state_updated_processing(ctx):
    ctx.app_state.write_state.assert_called_once()
    call_arg = ctx.app_state.write_state.call_args[0][0]
    assert call_arg.get("status") == "processing", f"Expected status='processing', got: {call_arg}"


@then("the state should include the message text")
def state_includes_message(ctx):
    call_arg = ctx.app_state.write_state.call_args[0][0]
    assert "message" in call_arg, f"Expected 'message' key in state: {call_arg}"
    assert call_arg["message"], "Expected non-empty message"


@then("the session state should be updated with a processing indicator")
def browser_state_updated(ctx):
    ctx.mock_session.write_state.assert_called_once()
    call_arg = ctx.mock_session.write_state.call_args[0][0]
    assert call_arg.get("status") == "processing", f"Expected processing state, got: {call_arg}"


@then("the hint should mention closing the session when done")
def hint_mentions_close(ctx):
    hint = ctx.result.get("_hint", "").lower()
    assert any(word in hint for word in ["close", "done", "session"]), (
        f"Expected close/done mention in hint: {ctx.result.get('_hint')}"
    )


@then("the prompt text should be non-empty")
def prompt_nonempty(ctx):
    assert ctx.prompt_text, "Expected non-empty workflow prompt"
    assert len(ctx.prompt_text.strip()) > 50, "Prompt seems too short"


@then("the prompt should mention openwebgoggles_read")
def prompt_mentions_read(ctx):
    assert "openwebgoggles_read" in ctx.prompt_text, "Workflow prompt should mention openwebgoggles_read"


@then("the prompt should mention openwebgoggles_close")
def prompt_mentions_close(ctx):
    assert "openwebgoggles_close" in ctx.prompt_text, "Workflow prompt should mention openwebgoggles_close"


@then("the prompt should mention the attention action type")
def prompt_mentions_attention(ctx):
    assert "attention" in ctx.prompt_text, "Workflow prompt should mention the attention action type"


@then("the call should succeed with a truncated or validated message")
def ping_long_message_ok(ctx):
    # SecurityGate validates the state — 1000-char message in a string field
    # is within the max value limit, so it should succeed (not error).
    # The ping may succeed or return an ok result.
    assert "error" not in ctx.result or ctx.result.get("ok") is True, (
        f"Unexpected hard error on long message: {ctx.result}"
    )
