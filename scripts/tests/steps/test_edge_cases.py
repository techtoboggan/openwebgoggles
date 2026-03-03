"""Step definitions for edge_cases.feature."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import threading

import pytest
from pytest_bdd import given, scenario, then, when

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import mcp_server  # noqa: E402, I001
from mcp_server import WebviewSession, _expand_preset  # noqa: E402

pytestmark = pytest.mark.bdd


# ---------------------------------------------------------------------------
# Scenario wiring
# ---------------------------------------------------------------------------


@scenario(
    "../features/edge_cases.feature",
    "Internal actions filtered from wait_for_action",
)
def test_internal_actions_filtered():
    pass


@scenario(
    "../features/edge_cases.feature",
    "Corrupted state.json on disk",
)
def test_corrupted_state_json():
    pass


@scenario(
    "../features/edge_cases.feature",
    "SecurityGate rejection during merge_state",
)
def test_security_gate_merge_rejection():
    pass


@scenario(
    "../features/edge_cases.feature",
    "Unknown preset in webview_update",
)
def test_unknown_preset():
    pass


@scenario(
    "../features/edge_cases.feature",
    "webview_close XSS in message parameter",
)
def test_webview_close_xss():
    pass


# ---------------------------------------------------------------------------
# Shared state container
# ---------------------------------------------------------------------------


class _Ctx:
    pass


@pytest.fixture
def ctx():
    return _Ctx()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_session(tmp_path):
    """Create a WebviewSession pointing at tmp_path without spawning a subprocess."""
    session = WebviewSession.__new__(WebviewSession)
    session.work_dir = tmp_path
    session.data_dir = tmp_path
    session.data_dir.mkdir(parents=True, exist_ok=True)
    session.process = None
    session.session_token = "test-token"
    session.session_id = "test-session"
    session.http_port = 0
    session.ws_port = 0
    session._started = True
    session._state_version = 0
    session._state_lock = threading.Lock()
    session._open_browser_on_start = False
    session._chrome_process = None
    session._chrome_profile = None
    session._lock_fd = None
    return session


# ---------------------------------------------------------------------------
# Scenario 1: Internal actions filtered from wait_for_action
# ---------------------------------------------------------------------------


@given("a webview session is active")
def session_active(ctx, tmp_path):
    ctx.session = _make_session(tmp_path)


@when('an action with id "_page_switch" is submitted')
def submit_internal_action(ctx):
    actions_data = {
        "version": 1,
        "actions": [
            {"action_id": "_page_switch", "type": "internal", "value": "page2"},
        ],
    }
    WebviewSession._write_json(ctx.session.data_dir / "actions.json", actions_data)


@when("wait_for_action is called")
def call_wait_for_action(ctx):
    loop = asyncio.new_event_loop()
    try:
        # Use a very short timeout so we don't block; internal actions should be
        # filtered, causing wait_for_action to time out.
        result = loop.run_until_complete(ctx.session.wait_for_action(timeout=1.0))
        ctx.wait_result = result
    finally:
        loop.close()


@then("the internal action should be filtered out")
def assert_internal_filtered(ctx):
    # wait_for_action should have returned None (timed out) because only
    # internal actions were present — they are filtered from the wait.
    assert ctx.wait_result is None, f"Expected None (timeout) but got {ctx.wait_result}"


@then("wait_for_action should continue polling")
def assert_continued_polling(ctx):
    # The fact that wait_for_action returned None (timed out) proves it
    # kept polling rather than returning the internal action.
    assert ctx.wait_result is None


# ---------------------------------------------------------------------------
# Scenario 2: Corrupted state.json on disk
# ---------------------------------------------------------------------------


@given("a webview session has written state")
def session_with_state(ctx, tmp_path):
    ctx.session = _make_session(tmp_path)
    ctx.session.write_state({"title": "Test", "data": {}})
    # Verify state is valid before corruption
    state = ctx.session.read_state()
    assert state.get("title") == "Test"


@when("the state.json file is corrupted with invalid JSON")
def corrupt_state_file(ctx):
    state_path = ctx.session.data_dir / "state.json"
    state_path.write_text("{invalid json!!! <<<")


@then("reading state should return a safe default")
def assert_safe_default(ctx):
    result = ctx.session.read_state()
    # _read_json returns None on JSONDecodeError, and read_state returns {} on None
    assert isinstance(result, dict), f"Expected dict, got {type(result)}"
    assert result == {}, f"Expected empty dict default, got {result}"


@then("no exception should propagate")
def assert_no_exception(ctx):
    # The fact that we reached this step without an exception proves this.
    # Verify once more that reading does not raise.
    result = ctx.session.read_state()
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Scenario 3: SecurityGate rejection during merge_state
# ---------------------------------------------------------------------------


@given("a webview session with a security gate")
def session_with_security_gate(ctx, tmp_path):
    ctx.session = _make_session(tmp_path)
    # Write a valid initial state
    ctx.session.write_state({"title": "Original", "data": {"sections": []}})
    ctx.original_state = ctx.session.read_state()


@when("webview_update is called with merge containing dangerous CSS")
def call_merge_with_dangerous_css(ctx):
    old_session = mcp_server._session
    old_gate = mcp_server._security_gate

    try:
        mcp_server._session = ctx.session

        # Ensure security gate is active for this test
        try:
            try:
                from scripts.security_gate import SecurityGate  # noqa: I001
            except ImportError:
                from security_gate import SecurityGate  # noqa: I001
            mcp_server._security_gate = SecurityGate()
        except ImportError:
            pytest.skip("SecurityGate not available")

        loop = asyncio.new_event_loop()
        try:

            async def _test():
                result = await mcp_server.openwebgoggles_update(
                    state={"custom_css": "body { background: url(javascript:alert(1)) }"},
                    merge=True,
                )
                return result

            ctx.update_result = loop.run_until_complete(_test())
        finally:
            loop.close()
    finally:
        mcp_server._session = old_session
        mcp_server._security_gate = old_gate


@then("the update should be rejected")
def assert_update_rejected(ctx):
    assert "error" in ctx.update_result, f"Expected error in response, got {ctx.update_result}"


@then("the original state should be preserved")
def assert_original_preserved(ctx):
    current = ctx.session.read_state()
    assert current.get("title") == ctx.original_state.get("title"), (
        f"Expected original title {ctx.original_state.get('title')!r}, got {current.get('title')!r}"
    )


# ---------------------------------------------------------------------------
# Scenario 4: Unknown preset in webview_update
# ---------------------------------------------------------------------------

# "a webview session is active" is already defined above


@when('webview is called with preset "nonexistent"')
def call_with_unknown_preset(ctx):
    try:
        _expand_preset("nonexistent", {})
        ctx.raised = False
        ctx.error = None
    except ValueError as exc:
        ctx.raised = True
        ctx.error = str(exc)


@then("it should raise a ValueError")
def assert_value_error_raised(ctx):
    assert ctx.raised, "Expected _expand_preset to raise ValueError"


@then("the error should name the invalid preset")
def assert_error_names_preset(ctx):
    assert "nonexistent" in ctx.error, f"Expected 'nonexistent' in error message, got {ctx.error!r}"


# ---------------------------------------------------------------------------
# Scenario 5: webview_close XSS in message parameter
# ---------------------------------------------------------------------------

# "a webview session is active" is already defined above


@when("webview_close is called with a script tag in the message")
def call_close_with_xss(ctx):
    old_session = mcp_server._session
    old_gate = mcp_server._security_gate

    try:
        mcp_server._session = ctx.session
        mcp_server._session._started = True

        try:
            try:
                from scripts.security_gate import SecurityGate  # noqa: I001
            except ImportError:
                from security_gate import SecurityGate  # noqa: I001
            mcp_server._security_gate = SecurityGate()
        except ImportError:
            pytest.skip("SecurityGate not available")

        loop = asyncio.new_event_loop()
        try:

            async def _test():
                return await mcp_server.openwebgoggles_close(
                    message="<script>alert(1)</script>",
                )

            ctx.close_result = loop.run_until_complete(_test())
        finally:
            loop.close()
    finally:
        mcp_server._session = old_session
        mcp_server._security_gate = old_gate


@then("the script should be escaped or rejected")
def assert_xss_rejected(ctx):
    assert "error" in ctx.close_result, f"Expected XSS to be rejected, got {ctx.close_result}"
    assert "security" in ctx.close_result["error"].lower() or "rejected" in ctx.close_result["error"].lower(), (
        f"Error should mention security/rejection: {ctx.close_result['error']}"
    )


@then("no raw HTML should reach the client")
def assert_no_raw_html(ctx):
    # The error response should not contain the raw script tag
    error_str = json.dumps(ctx.close_result)
    assert "<script>" not in error_str.lower() or "rejected" in error_str.lower(), (
        "Raw script tag should not pass through to client unescaped"
    )
