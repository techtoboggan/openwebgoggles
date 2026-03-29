"""Step definitions for session_close.feature.

These scenarios validate that session_closed and attention action types
correctly break out of wait_for_action, that SecurityGate accepts/rejects
them appropriately, and that internal events like _page_switch are filtered.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

import pytest
from pytest_bdd import given, scenario, then, when

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from session import WebviewSession  # noqa: E402, I001
from security_gate import SecurityGate  # noqa: E402

pytestmark = pytest.mark.bdd


# ---------------------------------------------------------------------------
# Scenario wiring
# ---------------------------------------------------------------------------


@scenario(
    "../features/session_close.feature",
    "session_closed action breaks the agent out of wait_for_action",
)
def test_session_closed_breaks_wait():
    pass


@scenario(
    "../features/session_close.feature",
    "attention action re-engages the agent from wait_for_action",
)
def test_attention_breaks_wait():
    pass


@scenario(
    "../features/session_close.feature",
    "SecurityGate accepts session_closed action type",
)
def test_gate_accepts_session_closed():
    pass


@scenario(
    "../features/session_close.feature",
    "SecurityGate accepts attention action type",
)
def test_gate_accepts_attention():
    pass


@scenario(
    "../features/session_close.feature",
    "SecurityGate rejects unknown action types",
)
def test_gate_rejects_unknown():
    pass


@scenario(
    "../features/session_close.feature",
    "Internal page-switch events are not surfaced to the agent",
)
def test_page_switch_filtered():
    pass


# ---------------------------------------------------------------------------
# Shared state container
# ---------------------------------------------------------------------------


class _Ctx:
    data_dir = None
    actions_path = None
    wait_result = None
    gate = None
    gate_result = None
    gate_error = None
    wait_still_running = None


@pytest.fixture
def ctx(tmp_path):
    c = _Ctx()
    c.data_dir = tmp_path / "session"
    c.data_dir.mkdir()
    c.actions_path = c.data_dir / "actions.json"
    c.actions_path.write_text(json.dumps({"version": 0, "actions": []}))
    c.gate = SecurityGate()
    return c


def _make_session(ctx: _Ctx) -> WebviewSession:
    s = WebviewSession.__new__(WebviewSession)
    s.data_dir = ctx.data_dir
    s.POLL_INTERVAL = 0.02
    s.PROGRESS_INTERVAL = 2.0
    return s


def _run_wait_with_injected_action(ctx: _Ctx, action: dict) -> dict | None:
    """Run wait_for_action, inject action after a brief delay, return result."""
    loop = asyncio.new_event_loop()
    result = [None]
    try:
        session = _make_session(ctx)

        async def _inject():
            await asyncio.sleep(0.05)
            ctx.actions_path.write_text(json.dumps({"version": 1, "actions": [action]}))

        async def _run():
            asyncio.ensure_future(_inject())
            result[0] = await session.wait_for_action(timeout=2.0)

        loop.run_until_complete(_run())
    finally:
        loop.close()
    return result[0]


# ---------------------------------------------------------------------------
# Given steps
# ---------------------------------------------------------------------------


@given("the agent is waiting for a user action")
def agent_waiting(ctx):
    ctx.actions_path.write_text(json.dumps({"version": 0, "actions": []}))


@given('a well-formed action payload with type "session_closed"')
def action_session_closed(ctx):
    ctx.action_payload = {"action_id": "close_btn", "type": "session_closed", "value": None}


@given('a well-formed action payload with type "attention"')
def action_attention(ctx):
    ctx.action_payload = {"action_id": "remind_btn", "type": "attention", "value": {"reason": "user_waiting"}}


@given('a well-formed action payload with type "malicious_action"')
def action_malicious(ctx):
    ctx.action_payload = {"action_id": "bad", "type": "malicious_action", "value": None}


# ---------------------------------------------------------------------------
# When steps
# ---------------------------------------------------------------------------


@when("the user sends a session_closed action")
def send_session_closed(ctx):
    action = {"action_id": "close_btn", "type": "session_closed", "value": None}
    ctx.wait_result = _run_wait_with_injected_action(ctx, action)


@when('the user clicks "Remind Agent" sending an attention action')
def send_attention(ctx):
    action = {"action_id": "remind_btn", "type": "attention", "value": {"reason": "user_waiting"}}
    ctx.wait_result = _run_wait_with_injected_action(ctx, action)


@when("the SecurityGate validates the action")
def gate_validates(ctx):
    ok, err = ctx.gate.validate_action(ctx.action_payload)
    ctx.gate_result = ok
    ctx.gate_error = err


@when("the browser sends a _page_switch internal event")
def send_page_switch(ctx):
    """_page_switch is an internal action (starts with _) and should be ignored."""
    loop = asyncio.new_event_loop()
    result = [None]
    still_running = [False]
    try:
        session = _make_session(ctx)

        async def _inject_internal_then_real():
            await asyncio.sleep(0.05)
            # First write an internal action — should NOT break wait
            ctx.actions_path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "actions": [{"action_id": "_page_switch", "type": "action", "value": "page2"}],
                    }
                )
            )
            await asyncio.sleep(0.1)
            # Confirm wait is still alive after internal action
            still_running[0] = True
            # Now write a real action to end the test cleanly
            ctx.actions_path.write_text(
                json.dumps(
                    {
                        "version": 2,
                        "actions": [{"action_id": "done", "type": "approve", "value": None}],
                    }
                )
            )

        async def _run():
            asyncio.ensure_future(_inject_internal_then_real())
            result[0] = await session.wait_for_action(timeout=2.0)

        loop.run_until_complete(_run())
    finally:
        loop.close()
    ctx.wait_result = result[0]
    ctx.wait_still_running = still_running[0]


# ---------------------------------------------------------------------------
# Then steps
# ---------------------------------------------------------------------------


@then('wait_for_action should return with action_type "session_closed"')
def result_is_session_closed(ctx):
    assert ctx.wait_result is not None, "wait_for_action returned None"
    actions = ctx.wait_result.get("actions", [])
    assert any(a.get("type") == "session_closed" for a in actions), f"Expected session_closed action in: {actions}"


@then('wait_for_action should return with action_type "attention"')
def result_is_attention(ctx):
    assert ctx.wait_result is not None, "wait_for_action returned None"
    actions = ctx.wait_result.get("actions", [])
    assert any(a.get("type") == "attention" for a in actions), f"Expected attention action in: {actions}"


@then("the agent should not remain blocked")
def agent_not_blocked(ctx):
    # wait_for_action already returned (checked in previous step)
    assert ctx.wait_result is not None


@then("the result should include a reason field")
def result_has_reason(ctx):
    assert ctx.wait_result is not None
    actions = ctx.wait_result.get("actions", [])
    attention_actions = [a for a in actions if a.get("type") == "attention"]
    assert attention_actions, "No attention action found"
    value = attention_actions[0].get("value")
    assert isinstance(value, dict) and "reason" in value, f"Expected reason in value, got: {value}"


@then("the action should be accepted")
def action_accepted(ctx):
    assert ctx.gate_result is True, f"Expected accepted but got error: {ctx.gate_error}"


@then("the action should be rejected")
def action_rejected(ctx):
    assert ctx.gate_result is False, "Expected rejection but action was accepted"


@then("wait_for_action should continue polling and not return")
def wait_continued_past_internal(ctx):
    assert ctx.wait_still_running is True, "wait_for_action returned early on internal _page_switch action"
    # Final action was a real 'approve' — wait should have returned eventually
    assert ctx.wait_result is not None, "wait_for_action should have returned after real action"
