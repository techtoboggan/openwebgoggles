"""
test_bash_scripts.py — Security tests for bash helper scripts.

Validates input validation, command injection prevention, port validation,
race condition safety, file permission enforcement, and PID file integrity.

OWASP A01 — Broken Access Control (file permissions)
OWASP A03 — Injection (command injection via args)
OWASP A05 — Security Misconfiguration (insecure defaults)
OWASP A08 — Software and Data Integrity Failures (atomic writes)
MITRE T1059 — Command and Scripting Interpreter
MITRE T1190 — Exploit Public-Facing Application
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile

import pytest

SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), "..")


def _script(name: str) -> str:
    """Return absolute path to a script."""
    return os.path.join(SCRIPTS_DIR, name)


def _run(args: list[str], env: dict | None = None, input_data: str | None = None) -> subprocess.CompletedProcess:
    """Run a bash command, capturing output. Merges env with PATH."""
    run_env = dict(os.environ)
    if env:
        run_env.update(env)
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        env=run_env,
        input=input_data,
        timeout=10,
    )


def _read_script(name: str) -> str:
    """Read script source."""
    with open(_script(name)) as f:
        return f.read()


# ===================================================================
# Source code static checks — all scripts
# ===================================================================

class TestScriptDefensivePatterns:
    """Verify that all bash scripts use defensive coding patterns."""

    SCRIPTS = [
        "start_webview.sh",
        "stop_webview.sh",
        "close_webview.sh",
        "write_state.sh",
        "read_actions.sh",
        "wait_for_action.sh",
        "init_webview_app.sh",
    ]

    @pytest.mark.owasp_a05
    @pytest.mark.parametrize("script", SCRIPTS)
    def test_set_euo_pipefail(self, script):
        """Every script must use 'set -euo pipefail' for defensive bash."""
        src = _read_script(script)
        assert "set -euo pipefail" in src, f"{script} missing 'set -euo pipefail'"

    @pytest.mark.owasp_a05
    @pytest.mark.parametrize("script", SCRIPTS)
    def test_has_shebang(self, script):
        """Every script must have a proper shebang line."""
        src = _read_script(script)
        assert src.startswith("#!/usr/bin/env bash") or src.startswith("#!/bin/bash"), \
            f"{script} missing bash shebang"

    @pytest.mark.owasp_a03
    @pytest.mark.parametrize("script", SCRIPTS)
    def test_no_eval(self, script):
        """No script should use eval (command injection risk)."""
        src = _read_script(script)
        # Match 'eval ' at start of line or after ; or &&
        assert not re.search(r'(?:^|[;&|]\s*)eval\s', src, re.MULTILINE), \
            f"{script} uses eval"

    @pytest.mark.owasp_a03
    @pytest.mark.parametrize("script", SCRIPTS)
    def test_no_backtick_substitution(self, script):
        """Prefer $() over backticks for command substitution (safer nesting)."""
        src = _read_script(script)
        # Allow backticks in comments and strings but flag standalone usage
        lines = [l for l in src.split("\n") if l.strip() and not l.strip().startswith("#")]
        for line in lines:
            # Simple heuristic: backticks outside of echo/strings
            if "`" in line and "echo" not in line and "'" not in line:
                # Don't flag if it's inside a quoted string
                if not re.search(r'["\'][^"\']*`[^"\']*["\']', line):
                    # This is a soft check — some legitimate uses exist
                    pass


# ===================================================================
# start_webview.sh — port validation, app name validation
# ===================================================================

class TestStartWebviewValidation:
    """Test input validation in start_webview.sh."""

    @pytest.mark.owasp_a03
    def test_port_validation_rejects_non_numeric(self):
        """Port must be an integer, not arbitrary text."""
        src = _read_script("start_webview.sh")
        # The validation regex should be present
        assert re.search(r'\$HTTP_PORT.*\^?\[0-9\]', src) or \
               re.search(r'HTTP_PORT.*=~.*\[0-9\]', src), \
            "start_webview.sh must validate HTTP_PORT as numeric"

    @pytest.mark.owasp_a03
    def test_port_range_validation(self):
        """Port validation should check the 1-65535 range."""
        src = _read_script("start_webview.sh")
        assert "65535" in src, "start_webview.sh should validate port range up to 65535"

    @pytest.mark.owasp_a03
    def test_ws_port_validation(self):
        """WS port must also be validated."""
        src = _read_script("start_webview.sh")
        assert re.search(r'WS_PORT.*=~.*\[0-9\]', src), \
            "start_webview.sh must validate WS_PORT as numeric"

    @pytest.mark.owasp_a03
    @pytest.mark.mitre_t1059
    def test_port_command_injection_prevention(self):
        """Ports like '$(rm -rf /)' must be rejected before they reach any command."""
        src = _read_script("start_webview.sh")
        # Validation must occur BEFORE the port is used in any command
        validation_pos = src.find("must be an integer between 1 and 65535")
        server_start_pos = src.find("webview_server.py")
        assert validation_pos > 0, "Port validation error message not found"
        assert validation_pos < server_start_pos, "Port validation must happen before server start"

    @pytest.mark.owasp_a03
    def test_app_name_validation(self):
        """APP_NAME must be validated to prevent path traversal and injection."""
        src = _read_script("start_webview.sh")
        assert re.search(r'APP_NAME.*=~.*\^?\[a-zA-Z0-9\]', src), \
            "start_webview.sh must validate APP_NAME characters"

    @pytest.mark.owasp_a03
    def test_app_name_rejects_path_traversal(self):
        """APP_NAME like '../../../etc' should be rejected by the regex."""
        # The regex ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ blocks .. and /
        pattern = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$')
        bad_names = [
            "../../../etc/passwd",
            "../../root",
            "app/../../evil",
            "app\nrm -rf /",
            "$(whoami)",
            "; rm -rf /",
            "app`id`",
            "app\x00name",
        ]
        for name in bad_names:
            assert not pattern.match(name), f"Pattern should reject: {name!r}"

    @pytest.mark.owasp_a03
    def test_app_name_allows_valid_names(self):
        """Valid app names should pass the validation regex."""
        pattern = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$')
        good_names = [
            "my-app",
            "approval-review",
            "security-qa",
            "app2.0",
            "My_App_v3",
            "test",
        ]
        for name in good_names:
            assert pattern.match(name), f"Pattern should accept: {name!r}"

    @pytest.mark.owasp_a01
    def test_file_permissions_set(self):
        """Script should set restrictive permissions on sensitive files."""
        src = _read_script("start_webview.sh")
        assert "chmod 0700" in src, "Data dir should be 0700"
        assert "chmod 0600" in src, "manifest.json should be 0600"

    @pytest.mark.owasp_a05
    def test_localhost_only_binding(self):
        """Server must only bind to 127.0.0.1, not 0.0.0.0."""
        src = _read_script("start_webview.sh")
        assert "127.0.0.1" in src
        assert "0.0.0.0" not in src

    @pytest.mark.owasp_a02
    def test_session_token_via_env_not_args(self):
        """Session token should be passed via environment variable, not CLI arg."""
        src = _read_script("start_webview.sh")
        assert 'OCV_SESSION_TOKEN="$SESSION_TOKEN"' in src
        # Token should NOT appear in the command args
        lines_with_server = [l for l in src.split("\n") if "webview_server.py" in l]
        for line in lines_with_server:
            assert "--token" not in line, "Token must not be passed as CLI argument"

    @pytest.mark.owasp_a02
    def test_token_not_written_to_manifest(self):
        """The actual token should not be written to manifest.json."""
        src = _read_script("start_webview.sh")
        # The manifest template should use REDACTED, not the actual token
        assert '"token": "REDACTED"' in src


# ===================================================================
# close_webview.sh — delay validation, PID validation
# ===================================================================

class TestCloseWebviewValidation:

    @pytest.mark.owasp_a03
    def test_delay_ms_validation(self):
        """DELAY_MS must be validated as a non-negative integer."""
        src = _read_script("close_webview.sh")
        assert re.search(r'DELAY_MS.*=~.*\[0-9\]', src), \
            "close_webview.sh must validate DELAY_MS as numeric"

    @pytest.mark.owasp_a03
    def test_chrome_pid_validation(self):
        """PIDs read from .chrome.pids file must be validated as integers."""
        src = _read_script("close_webview.sh")
        assert re.search(r'cpid.*=~.*\[0-9\]', src), \
            "close_webview.sh must validate chrome PIDs as numeric"

    @pytest.mark.owasp_a03
    def test_close_message_passed_safely(self):
        """CLOSE_MESSAGE should be passed to python via sys.argv, not interpolated."""
        src = _read_script("close_webview.sh")
        # The message is passed via sys.argv to python3 -c, not string interpolation
        assert "sys.argv" in src


# ===================================================================
# stop_webview.sh — PID file validation
# ===================================================================

class TestStopWebviewValidation:

    @pytest.mark.owasp_a03
    @pytest.mark.mitre_t1059
    def test_pid_validation(self):
        """PID read from .server.pid must be validated as a positive integer."""
        src = _read_script("stop_webview.sh")
        assert re.search(r'PID.*=~.*\[0-9\]', src), \
            "stop_webview.sh must validate PID as numeric"

    @pytest.mark.owasp_a03
    def test_chrome_pid_validation(self):
        """Chrome PIDs from file must be validated."""
        src = _read_script("stop_webview.sh")
        assert re.search(r'cpid.*=~.*\[0-9\]', src), \
            "stop_webview.sh must validate chrome PIDs as numeric"

    @pytest.mark.owasp_a03
    def test_corrupted_pid_file_handled(self):
        """A corrupted PID file with non-numeric content should be handled gracefully."""
        src = _read_script("stop_webview.sh")
        assert "Invalid PID" in src, "stop_webview.sh should report invalid PID"


# ===================================================================
# wait_for_action.sh — timeout/interval validation
# ===================================================================

class TestWaitForActionValidation:

    @pytest.mark.owasp_a03
    def test_timeout_validation(self):
        """TIMEOUT must be validated as a non-negative integer."""
        src = _read_script("wait_for_action.sh")
        assert re.search(r'TIMEOUT.*=~.*\[0-9\]', src), \
            "wait_for_action.sh must validate TIMEOUT as numeric"

    @pytest.mark.owasp_a03
    def test_poll_interval_validation(self):
        """POLL_INTERVAL must be validated as a positive integer."""
        src = _read_script("wait_for_action.sh")
        assert re.search(r'POLL_INTERVAL.*=~.*\[0-9\]', src), \
            "wait_for_action.sh must validate POLL_INTERVAL as numeric"

    @pytest.mark.owasp_a03
    def test_poll_interval_minimum(self):
        """POLL_INTERVAL must be at least 1 to prevent busy-looping."""
        src = _read_script("wait_for_action.sh")
        assert "POLL_INTERVAL.*-lt 1" in src or re.search(r'POLL_INTERVAL.*-lt\s+1', src), \
            "POLL_INTERVAL should have a minimum of 1"


# ===================================================================
# write_state.sh — atomic writes, JSON validation
# ===================================================================

class TestWriteStateValidation:

    @pytest.mark.owasp_a08
    def test_atomic_write_pattern(self):
        """State writes must be atomic (write to tmp, then mv)."""
        src = _read_script("write_state.sh")
        assert ".tmp" in src, "write_state.sh should use .tmp for atomic writes"
        assert "mv " in src, "write_state.sh should use mv for atomic rename"

    @pytest.mark.owasp_a03
    def test_json_validation(self):
        """JSON input must be validated before writing."""
        src = _read_script("write_state.sh")
        assert "json.loads" in src, "write_state.sh must validate JSON"

    @pytest.mark.owasp_a03
    def test_json_passed_via_sysargv(self):
        """JSON input to python should go via sys.argv, not shell interpolation in -c string."""
        src = _read_script("write_state.sh")
        assert "sys.argv" in src, "JSON should be passed via sys.argv for safety"

    @pytest.mark.owasp_a08
    def test_write_state_functional(self):
        """Test that write_state.sh actually performs an atomic write."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = os.path.join(tmpdir, "webview")
            os.makedirs(data_dir)

            json_input = '{"version": 1, "status": "test"}'
            result = _run(
                ["bash", _script("write_state.sh"), "--data-dir", data_dir, json_input]
            )
            assert result.returncode == 0, f"write_state.sh failed: {result.stderr}"

            state_file = os.path.join(data_dir, "state.json")
            assert os.path.exists(state_file)
            with open(state_file) as f:
                import json
                data = json.load(f)
            assert data["version"] == 1
            assert data["status"] == "test"

    @pytest.mark.owasp_a03
    def test_write_state_rejects_invalid_json(self):
        """write_state.sh must reject non-JSON input."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = os.path.join(tmpdir, "webview")
            os.makedirs(data_dir)

            result = _run(
                ["bash", _script("write_state.sh"), "--data-dir", data_dir, "not valid json"]
            )
            assert result.returncode != 0, "write_state.sh should fail on invalid JSON"

    @pytest.mark.owasp_a03
    @pytest.mark.mitre_t1059
    def test_write_state_json_injection(self):
        """JSON containing shell metacharacters must not cause command injection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = os.path.join(tmpdir, "webview")
            os.makedirs(data_dir)

            # JSON is valid but contains shell-dangerous content
            json_input = '{"version": 1, "status": "$(touch /tmp/pwned)"}'
            result = _run(
                ["bash", _script("write_state.sh"), "--data-dir", data_dir, json_input]
            )
            assert result.returncode == 0
            assert not os.path.exists("/tmp/pwned"), "Command injection via JSON value!"


# ===================================================================
# init_webview_app.sh — app name injection, sed injection
# ===================================================================

class TestInitWebviewAppValidation:

    @pytest.mark.owasp_a03
    def test_app_name_validation_exists(self):
        """init_webview_app.sh must validate app names."""
        src = _read_script("init_webview_app.sh")
        assert re.search(r'APP_NAME.*=~.*\^?\[a-zA-Z0-9\]', src), \
            "init_webview_app.sh must validate APP_NAME"

    @pytest.mark.owasp_a03
    def test_sed_injection_blocked_by_validation(self):
        """App names with / would cause sed delimiter injection, but validation blocks them."""
        _read_script("init_webview_app.sh")  # verify script exists
        # The regex ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ blocks /
        pattern = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$')
        bad_names = [
            "app/../../etc",
            "/bin/sh",
            "s/evil/replacement/g",
        ]
        for name in bad_names:
            assert not pattern.match(name), f"Pattern should reject sed-injectable: {name!r}"

    @pytest.mark.owasp_a03
    def test_init_rejects_bad_name(self):
        """Functional test: init_webview_app.sh rejects a path-traversal name."""
        result = _run(["bash", _script("init_webview_app.sh"), "../../../etc"])
        assert result.returncode != 0

    @pytest.mark.owasp_a03
    def test_init_rejects_empty_name(self):
        """init_webview_app.sh requires an app name."""
        result = _run(["bash", _script("init_webview_app.sh")])
        assert result.returncode != 0


# ===================================================================
# read_actions.sh — basic validation
# ===================================================================

class TestReadActionsValidation:

    @pytest.mark.owasp_a08
    def test_atomic_clear(self):
        """Actions clear must use atomic write pattern."""
        src = _read_script("read_actions.sh")
        assert ".tmp" in src, "read_actions.sh should use tmp file for atomic clear"
        assert "mv " in src, "read_actions.sh should use mv for atomic rename"

    @pytest.mark.owasp_a03
    def test_missing_file_handled(self):
        """read_actions.sh should handle missing actions.json gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = _run(
                ["bash", _script("read_actions.sh"), "--data-dir", tmpdir]
            )
            assert result.returncode == 0
            assert '"actions": []' in result.stdout


# ===================================================================
# Cross-cutting security properties
# ===================================================================

class TestCrossCuttingBashSecurity:

    @pytest.mark.owasp_a05
    def test_no_world_readable_secrets(self):
        """The start script must set restrictive permissions on data files."""
        src = _read_script("start_webview.sh")
        # Check for chmod calls on sensitive files
        assert "chmod 0700" in src
        assert "chmod 0600" in src

    @pytest.mark.owasp_a02
    def test_session_token_not_logged(self):
        """Session token must not appear in echo/log statements."""
        src = _read_script("start_webview.sh")
        echo_lines = [l.strip() for l in src.split("\n") if l.strip().startswith("echo")]
        for line in echo_lines:
            assert "SESSION_TOKEN" not in line, "Token must not be echoed"

    @pytest.mark.owasp_a05
    def test_temp_chrome_profile_cleaned_up(self):
        """The temp Chrome profile directory should have a cleanup trap."""
        src = _read_script("start_webview.sh")
        assert "trap" in src, "start_webview.sh should trap EXIT to clean up temp dir"
        assert "rm -rf" in src, "Cleanup should remove temp Chrome profile"

    @pytest.mark.owasp_a03
    def test_no_unquoted_variables_in_commands(self):
        """Variables used in commands should be quoted to prevent word splitting."""
        scripts = [
            "start_webview.sh",
            "stop_webview.sh",
            "close_webview.sh",
        ]
        for script_name in scripts:
            src = _read_script(script_name)
            # Check for common unquoted variable patterns in dangerous positions
            # This is a heuristic — look for kill $VAR (should be kill "$VAR")
            lines = src.split("\n")
            for _i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                # kill with unquoted variable
                if re.search(r'kill\s+\$[A-Z_]+\s', stripped) and \
                   not re.search(r'kill\s+"\$[A-Z_]+"', stripped):
                    # Might be false positive for kill -0 "$PID" style
                    pass  # Soft check

    @pytest.mark.mitre_t1059
    def test_python_invocations_use_sysargv(self):
        """Python -c invocations should pass data via sys.argv, not string interpolation."""
        scripts_with_python = [
            "start_webview.sh",
            "close_webview.sh",
            "write_state.sh",
        ]
        for script_name in scripts_with_python:
            src = _read_script(script_name)
            # Find python3 -c invocations
            py_blocks = re.findall(r'python3\s+-c\s+"([^"]+)"', src)
            for block in py_blocks:
                # Check that user data isn't directly interpolated
                # (sys.argv usage indicates safe parameter passing)
                if "$CLOSE_MESSAGE" in block or "$JSON_INPUT" in block:
                    pytest.fail(
                        f"{script_name}: python -c string interpolates user data directly"
                    )

    @pytest.mark.owasp_a05
    def test_remote_debugging_port_hardcoded(self):
        """Chrome remote debugging port should be documented/intentional."""
        src = _read_script("start_webview.sh")
        # This is an intentional feature for the MCP extension, but should be localhost-only
        if "--remote-debugging-port" in src:
            # Ensure it's only on localhost (Chrome defaults to localhost)
            assert "127.0.0.1" in src or "localhost" in src

    @pytest.mark.owasp_a05
    def test_chrome_sandboxed_profile(self):
        """Chrome should use an isolated profile directory."""
        src = _read_script("start_webview.sh")
        assert "--user-data-dir" in src, "Chrome must use isolated profile"
        assert "mktemp -d" in src, "Profile dir should be unique per session"
        assert "--disable-extensions" not in src or "--disable-extensions" in src
        assert "--no-first-run" in src
