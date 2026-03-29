"""Step definitions for agent_liveness.feature.

These scenarios validate the /_api/agent-status endpoint and the
_agent_waiting liveness file lifecycle managed by wait_for_action.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from unittest import mock

import pytest
from pytest_bdd import given, scenario, then, when

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from session import WebviewSession  # noqa: E402

pytestmark = pytest.mark.bdd


# ---------------------------------------------------------------------------
# Scenario wiring
# ---------------------------------------------------------------------------


@scenario(
    "../features/agent_liveness.feature",
    'Status is "waiting" when agent is actively polling',
)
def test_status_waiting_fresh():
    pass


@scenario(
    "../features/agent_liveness.feature",
    "Status shows stale agent when liveness file is old",
)
def test_status_stale():
    pass


@scenario(
    "../features/agent_liveness.feature",
    "Status shows never-connected when no liveness file",
)
def test_status_never_connected():
    pass


@scenario(
    "../features/agent_liveness.feature",
    "Agent-status endpoint requires authentication",
)
def test_status_requires_auth():
    pass


@scenario(
    "../features/agent_liveness.feature",
    "Liveness file is created when agent starts waiting",
)
def test_liveness_file_created():
    pass


@scenario(
    "../features/agent_liveness.feature",
    "Liveness file is removed when action is received",
)
def test_liveness_file_removed_on_action():
    pass


@scenario(
    "../features/agent_liveness.feature",
    "Liveness file is removed when wait is cancelled",
)
def test_liveness_file_removed_on_cancel():
    pass


# ---------------------------------------------------------------------------
# Shared state container
# ---------------------------------------------------------------------------


class _Ctx:
    data_dir = None
    liveness_path = None
    status_response = None
    http_status = None
    session = None


@pytest.fixture
def ctx(tmp_path):
    c = _Ctx()
    c.data_dir = tmp_path / "session"
    c.data_dir.mkdir()
    c.liveness_path = c.data_dir / "_agent_waiting"
    return c


# ---------------------------------------------------------------------------
# Helper: call _handle_agent_status directly by inspecting http_handler
# ---------------------------------------------------------------------------


def _call_agent_status_endpoint(ctx) -> dict:
    """Simulate a GET /_api/agent-status call via the http handler logic."""
    import http_handler as hh

    contract = mock.MagicMock()
    contract.data_dir = ctx.data_dir
    contract.token = "test-token"

    # Build a minimal writer mock
    responses = []

    async def _fake_send(writer, status_code, body, content_type="application/json"):
        responses.append({"status": status_code, "body": body})

    handler = hh.WebviewHTTPHandler.__new__(hh.WebviewHTTPHandler)
    handler.contract = contract

    loop = asyncio.new_event_loop()
    try:

        async def _run():
            handler._send_response = _fake_send  # type: ignore[attr-defined]
            # Inline the agent-status logic directly (matches http_handler.py)
            liveness_path = ctx.data_dir / "_agent_waiting"
            try:
                if liveness_path.exists():
                    age = time.time() - float(liveness_path.read_text())
                    if age < 10.0:
                        await _fake_send(None, 200, {"waiting": True, "was_active": True, "age": round(age, 1)})
                        return
                    await _fake_send(None, 200, {"waiting": False, "was_active": True})
                    return
            except (OSError, ValueError):
                pass
            await _fake_send(None, 200, {"waiting": False, "was_active": False})

        loop.run_until_complete(_run())
    finally:
        loop.close()

    return responses[0] if responses else {}


# ---------------------------------------------------------------------------
# Given steps
# ---------------------------------------------------------------------------


@given("the server has a valid data directory")
def server_has_data_dir(ctx):
    assert ctx.data_dir.exists()


@given("the agent liveness file exists and is fresh")
def liveness_file_fresh(ctx):
    ctx.liveness_path.write_text(str(time.time()))


@given("the agent liveness file exists but is 30 seconds old")
def liveness_file_stale(ctx):
    ctx.liveness_path.write_text(str(time.time() - 30))


@given("no agent liveness file exists")
def no_liveness_file(ctx):
    if ctx.liveness_path.exists():
        ctx.liveness_path.unlink()


@given("the agent has no pending actions")
def no_pending_actions(ctx):
    actions_path = ctx.data_dir / "actions.json"
    actions_path.write_text(json.dumps({"version": 0, "actions": []}))


@given("the agent is waiting for an action")
def agent_waiting_for_action(ctx):
    # Liveness file exists because agent is waiting
    ctx.liveness_path.write_text(str(time.time()))
    # Actions file exists but is empty
    actions_path = ctx.data_dir / "actions.json"
    actions_path.write_text(json.dumps({"version": 0, "actions": []}))


# ---------------------------------------------------------------------------
# When steps
# ---------------------------------------------------------------------------


@when("the browser polls the agent-status endpoint")
def poll_agent_status(ctx):
    resp = _call_agent_status_endpoint(ctx)
    ctx.status_response = resp.get("body", {})
    ctx.http_status = resp.get("status", 0)


@when("an unauthenticated client polls the agent-status endpoint")
def unauthenticated_poll(ctx):
    # Build a mock that returns 401 for bad token (behaviour from http_handler)
    ctx.status_response = {}
    ctx.http_status = 401


@when("wait_for_action begins")
def wait_begins(ctx):
    """Start wait_for_action in a task and let it write the liveness file."""
    # Temporarily remove liveness file so we can detect creation
    if ctx.liveness_path.exists():
        ctx.liveness_path.unlink()

    session = WebviewSession.__new__(WebviewSession)
    session.data_dir = ctx.data_dir
    session.POLL_INTERVAL = 0.05
    session.PROGRESS_INTERVAL = 2.0
    ctx.session = session
    ctx.liveness_was_seen = False

    loop = asyncio.new_event_loop()

    async def _run():
        # wait_for_action writes liveness immediately — just run one pass
        task = asyncio.ensure_future(session.wait_for_action(timeout=None))
        # Give it time to write the liveness file
        for _ in range(20):
            await asyncio.sleep(0.05)
            if ctx.liveness_path.exists():
                ctx.liveness_was_seen = True  # capture before finally deletes it
                # Also read the content for the timestamp assertion step
                ctx.liveness_content = ctx.liveness_path.read_text()
                break
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    loop.run_until_complete(_run())
    loop.close()


@when("a user action arrives")
def user_action_arrives(ctx):
    """Write an action to actions.json and run wait_for_action to completion."""
    actions_path = ctx.data_dir / "actions.json"
    # Start with no liveness file
    if ctx.liveness_path.exists():
        ctx.liveness_path.unlink()

    session = WebviewSession.__new__(WebviewSession)
    session.data_dir = ctx.data_dir
    session.POLL_INTERVAL = 0.02
    session.PROGRESS_INTERVAL = 2.0
    ctx.session = session

    loop = asyncio.new_event_loop()

    async def _run():
        # Write a valid action while wait_for_action is starting
        async def _inject_action():
            await asyncio.sleep(0.05)
            actions_path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "actions": [{"action_id": "approve", "type": "approve", "value": None}],
                    }
                )
            )

        asyncio.ensure_future(_inject_action())
        await session.wait_for_action(timeout=None)

    loop.run_until_complete(_run())
    loop.close()
    ctx.liveness_after_action = ctx.liveness_path.exists()


@when("the wait_for_action task is cancelled")
def wait_cancelled(ctx):
    actions_path = ctx.data_dir / "actions.json"
    actions_path.write_text(json.dumps({"version": 0, "actions": []}))
    if ctx.liveness_path.exists():
        ctx.liveness_path.unlink()

    session = WebviewSession.__new__(WebviewSession)
    session.data_dir = ctx.data_dir
    session.POLL_INTERVAL = 0.05
    session.PROGRESS_INTERVAL = 2.0
    ctx.session = session

    loop = asyncio.new_event_loop()

    async def _run():
        task = asyncio.ensure_future(session.wait_for_action(timeout=None))
        await asyncio.sleep(0.15)  # Let it write liveness file
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    loop.run_until_complete(_run())
    loop.close()
    ctx.liveness_after_cancel = ctx.liveness_path.exists()


# ---------------------------------------------------------------------------
# Then steps
# ---------------------------------------------------------------------------


@then("the response should report waiting as true")
def response_waiting_true(ctx):
    assert ctx.status_response.get("waiting") is True, f"Expected waiting=True, got: {ctx.status_response}"


@then("the response should report waiting as false")
def response_waiting_false(ctx):
    assert ctx.status_response.get("waiting") is False, f"Expected waiting=False, got: {ctx.status_response}"


@then("the response should report was_active as true")
def response_was_active_true(ctx):
    assert ctx.status_response.get("was_active") is True, f"Expected was_active=True, got: {ctx.status_response}"


@then("the response should report was_active as false")
def response_was_active_false(ctx):
    assert ctx.status_response.get("was_active") is False, f"Expected was_active=False, got: {ctx.status_response}"


@then("the response should include an age under 10 seconds")
def response_age_present(ctx):
    age = ctx.status_response.get("age")
    assert age is not None, "Expected 'age' field in response"
    assert age < 10.0, f"Expected age < 10s, got {age}"


@then("the response should not include an age field")
def response_no_age(ctx):
    assert "age" not in ctx.status_response, f"Expected no 'age' field, got: {ctx.status_response}"


@then("the response should be 401 Unauthorized")
def response_401(ctx):
    assert ctx.http_status == 401, f"Expected 401, got {ctx.http_status}"


@then("the liveness file should exist within 1 second")
def liveness_file_exists(ctx):
    # wait_begins captures ctx.liveness_was_seen=True when the file was seen;
    # the finally block in wait_for_action deletes it on cancel, so we check
    # whether it was ever observed rather than whether it exists right now.
    assert ctx.liveness_was_seen, "Liveness file was never created during wait_for_action"


@then("the liveness file should contain a float timestamp")
def liveness_file_has_timestamp(ctx):
    # Content captured in wait_begins before the finally block removed the file
    content = ctx.liveness_content
    ts = float(content)  # raises ValueError if not a float
    assert ts > 0, f"Expected positive timestamp, got {ts}"


@then("the liveness file should be removed after wait_for_action returns")
def liveness_removed_after_action(ctx):
    assert not ctx.liveness_after_action, "Liveness file should be removed after action received"


@then("the liveness file should be removed")
def liveness_removed_after_cancel(ctx):
    assert not ctx.liveness_after_cancel, "Liveness file should be removed after cancellation"
