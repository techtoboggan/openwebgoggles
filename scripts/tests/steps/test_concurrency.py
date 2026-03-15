"""Step definitions for concurrency.feature."""

from __future__ import annotations

import asyncio
import os
import sys
import threading
from unittest import mock

import pytest
from pytest_bdd import given, scenario, then, when

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import mcp_server  # noqa: E402, I001
from mcp_server import WebviewSession  # noqa: E402

pytestmark = pytest.mark.bdd


# ---------------------------------------------------------------------------
# Scenario wiring
# ---------------------------------------------------------------------------


@scenario(
    "../features/concurrency.feature",
    "Concurrent webview_close during active tool call",
)
def test_concurrent_close():
    pass


@scenario(
    "../features/concurrency.feature",
    "Multiple rapid state updates",
)
def test_rapid_updates():
    pass


@scenario(
    "../features/concurrency.feature",
    "webview_status during session teardown",
)
def test_status_during_teardown():
    pass


@scenario(
    "../features/concurrency.feature",
    "Lock acquisition under contention",
)
def test_lock_contention():
    pass


@scenario(
    "../features/concurrency.feature",
    "Crypto fallback when NaCl unavailable",
)
def test_crypto_fallback():
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
    session._remote = False
    session._bind_host = "127.0.0.1"
    session._display_host = "127.0.0.1"
    return session


# ---------------------------------------------------------------------------
# Scenario 1: Concurrent webview_close during active tool call
# ---------------------------------------------------------------------------


@given("a webview session is active")
def session_active(ctx, tmp_path):
    ctx.session = _make_session(tmp_path)


@given("a tool call is in progress")
def tool_call_in_progress(ctx, version_monitor_env):
    ctx.env = version_monitor_env
    # Simulate an active tool call by incrementing the counter
    mcp_server._active_tool_calls = 1


@when("webview_close is called concurrently")
def close_called_concurrently(ctx):
    old_manager = mcp_server._session_manager
    try:
        mcp_server._session_manager = mcp_server.SessionManager()
        slot = mcp_server.SessionSlot("default")
        slot.browser_session = ctx.session
        slot.mode = "browser"
        mcp_server._session_manager._slots["default"] = slot

        loop = asyncio.new_event_loop()
        try:

            async def _test():
                # Run a tracked tool call and webview_close concurrently
                @mcp_server._track_tool_call
                async def _dummy_tool():
                    await asyncio.sleep(0.05)
                    return {"result": "ok"}

                close_task = asyncio.create_task(mcp_server.openwebgoggles_close(message="closing"))
                tool_task = asyncio.create_task(_dummy_tool())

                results = await asyncio.gather(close_task, tool_task, return_exceptions=True)
                ctx.close_result = results[0]
                ctx.tool_result = results[1]

            loop.run_until_complete(_test())
        finally:
            loop.close()
    finally:
        mcp_server._session_manager = old_manager
        mcp_server._active_tool_calls = 0


@then("the tool call should complete or fail gracefully")
def assert_tool_completed(ctx):
    # The tool call should have returned a result or a caught exception,
    # not an unhandled crash.
    assert not isinstance(ctx.tool_result, BaseException) or isinstance(ctx.tool_result, Exception), (
        f"Tool call had an unexpected error type: {type(ctx.tool_result)}"
    )


@then("the session should be properly cleaned up")
def assert_session_cleaned(ctx):
    # After close, session should report as closed
    close_result = ctx.close_result
    if isinstance(close_result, dict):
        assert "error" not in close_result or close_result.get("status") == "ok", (
            f"Close should succeed or report no active session, got {close_result}"
        )
    # No unhandled exception
    assert not isinstance(close_result, BaseException), f"webview_close raised an unexpected exception: {close_result}"


# ---------------------------------------------------------------------------
# Scenario 2: Multiple rapid state updates
# ---------------------------------------------------------------------------

# "a webview session is active" already defined


@when("three webview_update calls are made in rapid succession")
def rapid_state_updates(ctx):
    session = ctx.session
    # Write initial state
    session.write_state({"title": "Initial", "data": {}, "counter": 0})

    # Three rapid updates using merge_state to exercise the lock
    for i in range(1, 4):
        session.merge_state({"title": f"Update {i}", "counter": i})

    ctx.final_state = session.read_state()


@then("all updates should be applied")
def assert_all_updates_applied(ctx):
    # The counter should have been updated three times
    assert ctx.final_state.get("counter") == 3, f"Expected counter=3, got {ctx.final_state.get('counter')}"


@then("the final state should reflect the last update")
def assert_final_state(ctx):
    assert ctx.final_state.get("title") == "Update 3", (
        f"Expected title='Update 3', got {ctx.final_state.get('title')!r}"
    )


# ---------------------------------------------------------------------------
# Scenario 3: webview_status during session teardown
# ---------------------------------------------------------------------------

# "a webview session is active" already defined


@when("webview_close and webview_status race")
def close_and_status_race(ctx):
    old_manager = mcp_server._session_manager
    try:
        mcp_server._session_manager = mcp_server.SessionManager()
        slot = mcp_server.SessionSlot("default")
        slot.browser_session = ctx.session
        slot.mode = "browser"
        mcp_server._session_manager._slots["default"] = slot

        loop = asyncio.new_event_loop()
        try:

            async def _test():
                status_task = asyncio.create_task(mcp_server.openwebgoggles_status())
                close_task = asyncio.create_task(mcp_server.openwebgoggles_close(message="teardown"))
                results = await asyncio.gather(status_task, close_task, return_exceptions=True)
                ctx.status_result = results[0]
                ctx.close_result = results[1]

            loop.run_until_complete(_test())
        finally:
            loop.close()
    finally:
        mcp_server._session_manager = old_manager


@then("webview_status should return no active session or active session")
def assert_status_valid(ctx):
    result = ctx.status_result
    if isinstance(result, Exception):
        pytest.fail(f"webview_status raised: {result}")
    assert isinstance(result, dict), f"Expected dict, got {type(result)}"
    # Multi-session format: {active_count: N, sessions: [...]}
    assert "active_count" in result, f"Expected 'active_count' key in {result}"
    assert isinstance(result["active_count"], int), (
        f"Expected int for 'active_count', got {type(result['active_count'])}"
    )


# Reuse "no exception should propagate" — define with a unique function name
@then("no exception should propagate")
def assert_no_exception_concurrency(ctx):
    # Verify neither result is an unhandled exception
    for name, result in [("status", ctx.status_result), ("close", ctx.close_result)]:
        assert not isinstance(result, BaseException), f"{name} raised an unexpected exception: {result}"


# ---------------------------------------------------------------------------
# Scenario 4: Lock acquisition under contention
# ---------------------------------------------------------------------------

# "a webview session is active" already defined


@when("two tool calls try to acquire the session lock simultaneously")
def concurrent_lock_acquisition(ctx):
    session = ctx.session
    session.write_state({"title": "Start", "data": {}, "value": 0})

    results = []
    errors = []

    def _writer(val):
        """Thread function that acquires the state lock and writes."""
        try:
            session.merge_state({"value": val})
            results.append(val)
        except Exception as exc:
            errors.append(exc)

    t1 = threading.Thread(target=_writer, args=(1,))
    t2 = threading.Thread(target=_writer, args=(2,))
    t1.start()
    t2.start()
    t1.join(timeout=5)
    t2.join(timeout=5)

    ctx.writer_results = results
    ctx.writer_errors = errors
    ctx.final_state = session.read_state()


@then("both should eventually succeed")
def assert_both_succeed(ctx):
    assert len(ctx.writer_results) == 2, f"Expected 2 successful writes, got {len(ctx.writer_results)}"
    assert len(ctx.writer_errors) == 0, f"Expected no errors, got {ctx.writer_errors}"


@then("state should remain consistent")
def assert_state_consistent(ctx):
    state = ctx.final_state
    # The final value should be one of the written values (whichever ran last)
    assert state.get("value") in (1, 2), f"Expected value to be 1 or 2, got {state.get('value')}"
    # State version should have been incremented for each write
    # (initial write + 3 merges from rapid test + 1 initial + 2 concurrent)
    # Just verify it's a positive integer
    assert isinstance(state.get("version"), int), "version should be an int"
    assert state["version"] > 0, "version should be positive"


# ---------------------------------------------------------------------------
# Scenario 5: Crypto fallback when NaCl unavailable
# ---------------------------------------------------------------------------


@given("PyNaCl is not installed")
def no_pynacl(ctx):
    ctx.nacl_patched = True


@when("HMAC signing is attempted")
def attempt_hmac_signing(ctx):
    import crypto_utils

    # Patch _lazy_nacl to return None (simulates PyNaCl not installed)
    with mock.patch.object(crypto_utils, "_lazy_nacl", return_value=None):
        seed, pub_hex, verify_hex = crypto_utils.generate_session_keys()
        ctx.seed = seed
        ctx.pub_hex = pub_hex
        ctx.verify_hex = verify_hex

        # Try signing a message — should use HMAC fallback
        ctx.signature = crypto_utils.sign_message(seed, "test payload", "test-nonce")


@then("it should succeed with symmetric key only")
def assert_symmetric_success(ctx):
    assert ctx.seed is not None, "Seed should be generated"
    assert len(ctx.seed) == 32, f"Expected 32-byte seed, got {len(ctx.seed)}"
    assert ctx.signature is not None, "Signature should be produced"
    assert len(ctx.signature) > 0, "Signature should not be empty"


@then("Ed25519 operations should gracefully degrade")
def assert_ed25519_degraded(ctx):
    # When NaCl is unavailable, public/verify keys should be empty strings
    assert ctx.pub_hex == "", f"Expected empty pub_hex in fallback mode, got {ctx.pub_hex!r}"
    assert ctx.verify_hex == "", f"Expected empty verify_hex in fallback mode, got {ctx.verify_hex!r}"
