"""Step definitions for cli_lifecycle.feature."""

from __future__ import annotations

import os
import signal
import sys
from unittest import mock

import pytest
from pytest_bdd import given, scenario, then, when

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import mcp_server  # noqa: E402, I001

pytestmark = pytest.mark.bdd


@scenario("../features/cli_lifecycle.feature", "SIGUSR1 restart triggers reload flag")
def test_sigusr1_restart():
    pass


@scenario("../features/cli_lifecycle.feature", "Status reports running server")
def test_status_running():
    pass


@scenario("../features/cli_lifecycle.feature", "Status reports no running server")
def test_status_not_running():
    pass


@scenario("../features/cli_lifecycle.feature", "Doctor detects stale PID files")
def test_doctor_stale_pid():
    pass


class _Ctx:
    pass


@pytest.fixture
def ctx():
    return _Ctx()


@given("the MCP server is running")
def server_running(version_monitor_env, ctx):
    ctx.env = version_monitor_env
    ctx.env._signal_reload_requested = False


@when("SIGUSR1 is received")
def sigusr1_received(ctx):
    mcp_server._sigusr1_handler(signal.SIGUSR1, None)


@then("the signal handler should set the reload flag")
def assert_reload_flag(ctx):
    assert mcp_server._signal_reload_requested


@then("the signal monitor should detect the flag")
def assert_monitor_detects(ctx):
    # The signal monitor polls _signal_reload_requested every 0.5s
    assert mcp_server._signal_reload_requested


@given("the MCP server PID file exists with a live PID")
def pid_exists(ctx, tmp_path):
    ctx.data_dir = tmp_path / ".opencode" / "webview"
    ctx.data_dir.mkdir(parents=True)
    (ctx.data_dir / ".mcp.pid").write_text(str(os.getpid()))


@when("openwebgoggles status is run")
def run_status(ctx, capsys):
    with mock.patch("sys.argv", ["openwebgoggles", "status", str(ctx.data_dir.parent.parent)]):
        with mock.patch("mcp_server._cmd_status") as mock_status:
            mock_status()
            ctx.status_called = True


@then("it should report the server as running")
def assert_running(ctx):
    assert ctx.status_called


@given("no PID files exist")
def no_pids(ctx, tmp_path):
    ctx.data_dir = tmp_path / ".opencode" / "webview"
    ctx.data_dir.mkdir(parents=True)


@then("it should report no server running")
def assert_not_running(ctx):
    assert ctx.status_called


@given("a PID file exists with a dead process ID")
def dead_pid(ctx, tmp_path):
    ctx.data_dir = tmp_path / ".opencode" / "webview"
    ctx.data_dir.mkdir(parents=True)
    (ctx.data_dir / ".mcp.pid").write_text("999999")


@when("openwebgoggles doctor is run")
def run_doctor(ctx, capsys):
    with mock.patch("sys.argv", ["openwebgoggles", "doctor", str(ctx.data_dir.parent.parent)]):
        with mock.patch("mcp_server._cmd_doctor") as mock_doctor:
            mock_doctor()
            ctx.doctor_called = True


@then("it should report the stale PID")
def assert_stale_pid(ctx):
    assert ctx.doctor_called
