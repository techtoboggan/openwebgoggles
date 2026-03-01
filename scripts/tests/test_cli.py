"""
Tests for CLI subcommands: restart, status, doctor, init, and helpers.

Covers main() dispatch, _cmd_restart, _cmd_status, _cmd_doctor,
_init_claude, _init_opencode, _strip_jsonc_comments, _resolve_binary,
_find_data_dir, _read_pid_file, _print_usage, _init_usage.
"""

from __future__ import annotations

import json
import os
import signal
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mcp_server import (
    _cmd_doctor,
    _cmd_restart,
    _cmd_status,
    _find_data_dir,
    _init_claude,
    _init_opencode,
    _init_usage,
    _print_usage,
    _read_pid_file,
    _resolve_binary,
    _strip_jsonc_comments,
    main,
)


# ---------------------------------------------------------------------------
# _find_data_dir
# ---------------------------------------------------------------------------


class TestFindDataDir:
    def test_default_uses_cwd(self):
        result = _find_data_dir(None)
        assert result == Path.cwd() / ".opencode" / "webview"

    def test_explicit_path(self, tmp_path):
        result = _find_data_dir(tmp_path)
        assert result == tmp_path / ".opencode" / "webview"


# ---------------------------------------------------------------------------
# _read_pid_file
# ---------------------------------------------------------------------------


class TestReadPidFile:
    def test_file_does_not_exist(self, tmp_path):
        assert _read_pid_file(tmp_path / "nope.pid") is None

    def test_non_numeric_content(self, tmp_path):
        pid_file = tmp_path / "test.pid"
        pid_file.write_text("not-a-number")
        assert _read_pid_file(pid_file) is None

    def test_empty_file(self, tmp_path):
        pid_file = tmp_path / "test.pid"
        pid_file.write_text("")
        assert _read_pid_file(pid_file) is None

    def test_pid_of_current_process(self, tmp_path):
        pid_file = tmp_path / "test.pid"
        pid_file.write_text(str(os.getpid()))
        assert _read_pid_file(pid_file) == os.getpid()

    def test_dead_pid(self, tmp_path):
        pid_file = tmp_path / "test.pid"
        # PID 99999999 is almost certainly not running
        pid_file.write_text("99999999")
        assert _read_pid_file(pid_file) is None


# ---------------------------------------------------------------------------
# _strip_jsonc_comments
# ---------------------------------------------------------------------------


class TestStripJsoncComments:
    def test_no_comments(self):
        text = '{"key": "value"}'
        assert _strip_jsonc_comments(text) == text

    def test_line_comment(self):
        text = '{"key": "value"} // this is a comment\n{"key2": "value2"}'
        result = _strip_jsonc_comments(text)
        parsed = None
        # Should remove the comment
        assert "// this is a comment" not in result

    def test_block_comment(self):
        text = '{"key": /* block */ "value"}'
        result = _strip_jsonc_comments(text)
        assert "/* block */" not in result
        assert '"value"' in result

    def test_url_inside_string_preserved(self):
        text = '{"url": "https://example.com"}'
        result = _strip_jsonc_comments(text)
        assert result == text

    def test_escaped_quotes_in_string(self):
        text = r'{"key": "val\"ue"}'
        result = _strip_jsonc_comments(text)
        assert result == text

    def test_line_comment_at_eof(self):
        text = '{"key": "value"} // comment at end'
        result = _strip_jsonc_comments(text)
        assert "//" not in result

    def test_valid_json_after_stripping(self):
        text = """{
  // Database settings
  "host": "localhost", /* inline */
  "port": 5432
}"""
        result = _strip_jsonc_comments(text)
        parsed = json.loads(result)
        assert parsed["host"] == "localhost"
        assert parsed["port"] == 5432


# ---------------------------------------------------------------------------
# _resolve_binary
# ---------------------------------------------------------------------------


class TestResolveBinary:
    def test_found_via_which(self):
        with mock.patch("shutil.which", return_value="/usr/local/bin/openwebgoggles"):
            result = _resolve_binary()
            assert "openwebgoggles" in result

    def test_fallback_to_argv0(self, tmp_path):
        fake_bin = tmp_path / "openwebgoggles"
        fake_bin.write_text("#!/bin/sh")
        with mock.patch("shutil.which", return_value=None):
            with mock.patch("sys.argv", [str(fake_bin)]):
                result = _resolve_binary()
                assert "openwebgoggles" in result

    def test_last_resort_bare_name(self):
        with mock.patch("shutil.which", return_value=None):
            with mock.patch("sys.argv", ["/nonexistent/openwebgoggles"]):
                result = _resolve_binary()
                assert result == "openwebgoggles"


# ---------------------------------------------------------------------------
# _init_claude
# ---------------------------------------------------------------------------


class TestInitClaude:
    def test_creates_mcp_json_and_settings(self, tmp_path, capsys):
        with mock.patch("mcp_server.shutil.which", return_value="/usr/bin/openwebgoggles"):
            _init_claude(tmp_path)

        # .mcp.json created
        mcp_json = tmp_path / ".mcp.json"
        assert mcp_json.exists()
        cfg = json.loads(mcp_json.read_text())
        assert "openwebgoggles" in cfg["mcpServers"]

        # .claude/settings.json created
        settings = tmp_path / ".claude" / "settings.json"
        assert settings.exists()
        scfg = json.loads(settings.read_text())
        assert "mcp__openwebgoggles__webview" in scfg["permissions"]["allow"]

        output = capsys.readouterr().out
        assert "created" in output.lower() or "Done" in output

    def test_idempotent_skips_existing(self, tmp_path, capsys):
        with mock.patch("mcp_server.shutil.which", return_value="/usr/bin/openwebgoggles"):
            _init_claude(tmp_path)
            _init_claude(tmp_path)

        output = capsys.readouterr().out
        assert "skipping" in output.lower()

    def test_merges_into_existing_mcp_json(self, tmp_path, capsys):
        mcp_json = tmp_path / ".mcp.json"
        mcp_json.write_text(json.dumps({"mcpServers": {"other": {"command": "other"}}}) + "\n")

        with mock.patch("mcp_server.shutil.which", return_value="/usr/bin/openwebgoggles"):
            _init_claude(tmp_path)

        cfg = json.loads(mcp_json.read_text())
        assert "openwebgoggles" in cfg["mcpServers"]
        assert "other" in cfg["mcpServers"]

    def test_adds_missing_permissions(self, tmp_path, capsys):
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings = claude_dir / "settings.json"
        settings.write_text(json.dumps({"permissions": {"allow": ["some_other_tool"]}}) + "\n")

        with mock.patch("mcp_server.shutil.which", return_value="/usr/bin/openwebgoggles"):
            _init_claude(tmp_path)

        scfg = json.loads(settings.read_text())
        allow = scfg["permissions"]["allow"]
        assert "some_other_tool" in allow
        assert "mcp__openwebgoggles__webview" in allow


# ---------------------------------------------------------------------------
# _init_opencode
# ---------------------------------------------------------------------------


class TestInitOpencode:
    def test_creates_opencode_json(self, tmp_path, capsys):
        with mock.patch("mcp_server.shutil.which", return_value="/usr/bin/openwebgoggles"):
            _init_opencode(tmp_path)

        cfg_path = tmp_path / "opencode.json"
        assert cfg_path.exists()
        cfg = json.loads(cfg_path.read_text())
        assert "openwebgoggles" in cfg["mcp"]

    def test_idempotent_skips_existing(self, tmp_path, capsys):
        with mock.patch("mcp_server.shutil.which", return_value="/usr/bin/openwebgoggles"):
            _init_opencode(tmp_path)
            _init_opencode(tmp_path)

        output = capsys.readouterr().out
        assert "skipping" in output.lower()

    def test_merges_into_existing_config(self, tmp_path, capsys):
        cfg_path = tmp_path / "opencode.json"
        cfg_path.write_text(json.dumps({"mcp": {"other": {"command": ["other"]}}}) + "\n")

        with mock.patch("mcp_server.shutil.which", return_value="/usr/bin/openwebgoggles"):
            _init_opencode(tmp_path)

        cfg = json.loads(cfg_path.read_text())
        assert "openwebgoggles" in cfg["mcp"]
        assert "other" in cfg["mcp"]

    def test_reads_jsonc_file(self, tmp_path, capsys):
        jsonc_path = tmp_path / "opencode.jsonc"
        jsonc_path.write_text('{\n  // MCP servers\n  "mcp": {}\n}\n')

        with mock.patch("mcp_server.shutil.which", return_value="/usr/bin/openwebgoggles"):
            _init_opencode(tmp_path)

        # Should have added to the jsonc file (rewritten as json)
        cfg = json.loads(jsonc_path.read_text())
        assert "openwebgoggles" in cfg["mcp"]

    def test_global_config_message(self, tmp_path, capsys):
        global_dir = Path.home() / ".config" / "opencode"
        with mock.patch("mcp_server.shutil.which", return_value="/usr/bin/openwebgoggles"):
            # Patch Path.home resolution to match tmp_path
            with mock.patch.object(Path, "resolve", return_value=global_dir.resolve()):
                _init_opencode(tmp_path)

        output = capsys.readouterr().out
        # Just check it prints something about the config
        assert "Done" in output


# ---------------------------------------------------------------------------
# _init_usage / _print_usage
# ---------------------------------------------------------------------------


class TestUsage:
    def test_init_usage_prints(self, capsys):
        _init_usage()
        output = capsys.readouterr().out
        assert "claude" in output
        assert "opencode" in output
        assert "Usage:" in output

    def test_print_usage_prints(self, capsys):
        _print_usage()
        output = capsys.readouterr().out
        assert "restart" in output
        assert "status" in output
        assert "doctor" in output


# ---------------------------------------------------------------------------
# _cmd_restart
# ---------------------------------------------------------------------------


class TestCmdRestart:
    def test_no_running_server(self, tmp_path, capsys):
        data_dir = tmp_path / ".opencode" / "webview"
        data_dir.mkdir(parents=True)

        with mock.patch("sys.argv", ["openwebgoggles", "restart", str(tmp_path)]):
            with pytest.raises(SystemExit) as exc_info:
                _cmd_restart()
            assert exc_info.value.code == 1

        output = capsys.readouterr().out
        assert "No running MCP server found" in output

    def test_fallback_webview_pid_hint(self, tmp_path, capsys):
        data_dir = tmp_path / ".opencode" / "webview"
        data_dir.mkdir(parents=True)
        # Write a webview PID that's alive (our own PID)
        (data_dir / ".server.pid").write_text(str(os.getpid()))

        with mock.patch("sys.argv", ["openwebgoggles", "restart", str(tmp_path)]):
            with pytest.raises(SystemExit):
                _cmd_restart()

        output = capsys.readouterr().out
        assert "webview server" in output.lower()

    def test_sends_sigusr1_on_unix(self, tmp_path, capsys):
        data_dir = tmp_path / ".opencode" / "webview"
        data_dir.mkdir(parents=True)
        (data_dir / ".mcp.pid").write_text(str(os.getpid()))

        with mock.patch("sys.argv", ["openwebgoggles", "restart", str(tmp_path)]):
            with mock.patch("os.kill") as mock_kill:
                mock_kill.return_value = None  # succeed for all calls
                with mock.patch("platform.system", return_value="Linux"):
                    with mock.patch("time.sleep"):
                        _cmd_restart()

        # Should have sent SIGUSR1
        mock_kill.assert_any_call(os.getpid(), signal.SIGUSR1)

        output = capsys.readouterr().out
        assert "restart" in output.lower()

    def test_signal_send_fails(self, tmp_path, capsys):
        data_dir = tmp_path / ".opencode" / "webview"
        data_dir.mkdir(parents=True)
        (data_dir / ".mcp.pid").write_text(str(os.getpid()))

        with mock.patch("sys.argv", ["openwebgoggles", "restart", str(tmp_path)]):
            with mock.patch("platform.system", return_value="Linux"):
                with mock.patch("os.kill", side_effect=OSError("Permission denied")):
                    with pytest.raises(SystemExit) as exc_info:
                        _cmd_restart()
                    assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# _cmd_status
# ---------------------------------------------------------------------------


class TestCmdStatus:
    def test_nothing_running(self, tmp_path, capsys):
        data_dir = tmp_path / ".opencode" / "webview"
        data_dir.mkdir(parents=True)

        with mock.patch("sys.argv", ["openwebgoggles", "status", str(tmp_path)]):
            _cmd_status()

        output = capsys.readouterr().out
        assert "not running" in output
        assert "OpenWebGoggles Status" in output

    def test_mcp_server_running(self, tmp_path, capsys):
        data_dir = tmp_path / ".opencode" / "webview"
        data_dir.mkdir(parents=True)
        (data_dir / ".mcp.pid").write_text(str(os.getpid()))

        with mock.patch("sys.argv", ["openwebgoggles", "status", str(tmp_path)]):
            _cmd_status()

        output = capsys.readouterr().out
        assert f"PID {os.getpid()}" in output
        assert "running" in output

    def test_webview_with_manifest(self, tmp_path, capsys):
        data_dir = tmp_path / ".opencode" / "webview"
        data_dir.mkdir(parents=True)
        (data_dir / ".mcp.pid").write_text(str(os.getpid()))
        (data_dir / ".server.pid").write_text(str(os.getpid()))
        manifest = {
            "version": "1.0",
            "app": {"name": "dynamic"},
            "session": {"id": "test-1234-5678"},
            "server": {"http_port": 18420, "ws_port": 18421, "host": "127.0.0.1"},
        }
        (data_dir / "manifest.json").write_text(json.dumps(manifest))

        with mock.patch("sys.argv", ["openwebgoggles", "status", str(tmp_path)]):
            # Health endpoint won't be reachable, that's fine
            _cmd_status()

        output = capsys.readouterr().out
        assert "18420" in output
        assert "test-123" in output  # truncated session id
        assert "dynamic" in output

    def test_webview_running_no_manifest(self, tmp_path, capsys):
        data_dir = tmp_path / ".opencode" / "webview"
        data_dir.mkdir(parents=True)
        (data_dir / ".server.pid").write_text(str(os.getpid()))

        with mock.patch("sys.argv", ["openwebgoggles", "status", str(tmp_path)]):
            _cmd_status()

        output = capsys.readouterr().out
        assert f"PID {os.getpid()}" in output

    def test_default_data_dir(self, capsys):
        """status without explicit dir uses cwd."""
        with mock.patch("sys.argv", ["openwebgoggles", "status"]):
            _cmd_status()

        output = capsys.readouterr().out
        assert "OpenWebGoggles Status" in output


# ---------------------------------------------------------------------------
# _cmd_doctor
# ---------------------------------------------------------------------------


class TestCmdDoctor:
    def test_basic_checks_pass(self, tmp_path, capsys):
        # Create a valid .mcp.json so the config check passes
        binary = "/usr/bin/openwebgoggles"
        mcp_json = tmp_path / ".mcp.json"
        mcp_json.write_text(json.dumps({
            "mcpServers": {"openwebgoggles": {"command": binary}}
        }))

        with mock.patch("sys.argv", ["openwebgoggles", "doctor", str(tmp_path)]):
            with mock.patch("shutil.which", return_value=binary):
                _cmd_doctor()

        output = capsys.readouterr().out
        assert "OpenWebGoggles Doctor" in output
        assert "[ok]" in output
        assert "Python" in output

    def test_missing_dependency_warns(self, tmp_path, capsys):
        import importlib.metadata

        original_dist = importlib.metadata.distribution

        def mock_dist(name):
            if name == "mcp":
                raise importlib.metadata.PackageNotFoundError(name)
            return original_dist(name)

        with mock.patch("sys.argv", ["openwebgoggles", "doctor", str(tmp_path)]):
            with mock.patch("importlib.metadata.distribution", side_effect=mock_dist):
                with mock.patch("shutil.which", return_value=None):
                    _cmd_doctor()

        output = capsys.readouterr().out
        assert "[!!]" in output
        assert "mcp" in output

    def test_stale_pid_cleaned(self, tmp_path, capsys):
        data_dir = tmp_path / ".opencode" / "webview"
        data_dir.mkdir(parents=True)
        # Write a dead PID
        (data_dir / ".mcp.pid").write_text("99999999")

        with mock.patch("sys.argv", ["openwebgoggles", "doctor", str(tmp_path)]):
            with mock.patch("shutil.which", return_value=None):
                _cmd_doctor()

        output = capsys.readouterr().out
        assert "Stale" in output or "cleaned" in output
        # PID file should be removed
        assert not (data_dir / ".mcp.pid").exists()

    def test_no_config_warns(self, tmp_path, capsys):
        with mock.patch("sys.argv", ["openwebgoggles", "doctor", str(tmp_path)]):
            with mock.patch("shutil.which", return_value=None):
                _cmd_doctor()

        output = capsys.readouterr().out
        assert "No editor config found" in output

    def test_invalid_mcp_json_warns(self, tmp_path, capsys):
        mcp_json = tmp_path / ".mcp.json"
        mcp_json.write_text("not valid json{{{")

        with mock.patch("sys.argv", ["openwebgoggles", "doctor", str(tmp_path)]):
            with mock.patch("shutil.which", return_value=None):
                _cmd_doctor()

        output = capsys.readouterr().out
        assert "invalid JSON" in output

    def test_mcp_json_without_openwebgoggles(self, tmp_path, capsys):
        mcp_json = tmp_path / ".mcp.json"
        mcp_json.write_text(json.dumps({"mcpServers": {"other": {}}}))

        with mock.patch("sys.argv", ["openwebgoggles", "doctor", str(tmp_path)]):
            with mock.patch("shutil.which", return_value=None):
                _cmd_doctor()

        output = capsys.readouterr().out
        assert "not configured" in output

    def test_binary_path_mismatch(self, tmp_path, capsys):
        mcp_json = tmp_path / ".mcp.json"
        mcp_json.write_text(json.dumps({
            "mcpServers": {"openwebgoggles": {"command": "/old/path/openwebgoggles"}}
        }))

        with mock.patch("sys.argv", ["openwebgoggles", "doctor", str(tmp_path)]):
            with mock.patch("shutil.which", return_value="/new/path/openwebgoggles"):
                _cmd_doctor()

        output = capsys.readouterr().out
        assert "differs" in output

    def test_lock_file_not_held(self, tmp_path, capsys):
        data_dir = tmp_path / ".opencode" / "webview"
        data_dir.mkdir(parents=True)
        (data_dir / ".server.lock").write_text("")

        with mock.patch("sys.argv", ["openwebgoggles", "doctor", str(tmp_path)]):
            with mock.patch("shutil.which", return_value=None):
                _cmd_doctor()

        output = capsys.readouterr().out
        assert "[ok]" in output

    def test_default_data_dir(self, capsys):
        with mock.patch("sys.argv", ["openwebgoggles", "doctor"]):
            with mock.patch("shutil.which", return_value=None):
                _cmd_doctor()

        output = capsys.readouterr().out
        assert "OpenWebGoggles Doctor" in output

    def test_opencode_config_detected(self, tmp_path, capsys):
        # No .mcp.json, but opencode.json exists
        oc_json = tmp_path / "opencode.json"
        oc_json.write_text(json.dumps({"mcp": {"openwebgoggles": {"command": ["owg"]}}}))

        with mock.patch("sys.argv", ["openwebgoggles", "doctor", str(tmp_path)]):
            with mock.patch("shutil.which", return_value=None):
                _cmd_doctor()

        output = capsys.readouterr().out
        assert "opencode.json" in output
        assert "configured" in output


# ---------------------------------------------------------------------------
# main() dispatch
# ---------------------------------------------------------------------------


class TestMainDispatch:
    def test_help_flag(self, capsys):
        with mock.patch("sys.argv", ["openwebgoggles", "--help"]):
            main()
        output = capsys.readouterr().out
        assert "restart" in output

    def test_help_command(self, capsys):
        with mock.patch("sys.argv", ["openwebgoggles", "help"]):
            main()
        output = capsys.readouterr().out
        assert "Commands:" in output

    def test_h_flag(self, capsys):
        with mock.patch("sys.argv", ["openwebgoggles", "-h"]):
            main()
        output = capsys.readouterr().out
        assert "restart" in output

    def test_unknown_flag(self, capsys):
        with mock.patch("sys.argv", ["openwebgoggles", "--unknown"]):
            main()
        output = capsys.readouterr().out
        assert "Usage:" in output

    def test_init_without_editor(self, capsys):
        with mock.patch("sys.argv", ["openwebgoggles", "init"]):
            main()
        output = capsys.readouterr().out
        assert "Usage:" in output

    def test_init_invalid_editor(self, capsys):
        with mock.patch("sys.argv", ["openwebgoggles", "init", "vscode"]):
            main()
        output = capsys.readouterr().out
        assert "Usage:" in output

    def test_init_claude_dispatch(self, tmp_path):
        with mock.patch("sys.argv", ["openwebgoggles", "init", "claude", str(tmp_path)]):
            with mock.patch("mcp_server.shutil.which", return_value="/usr/bin/openwebgoggles"):
                main()
        assert (tmp_path / ".mcp.json").exists()

    def test_init_opencode_dispatch(self, tmp_path):
        with mock.patch("sys.argv", ["openwebgoggles", "init", "opencode", str(tmp_path)]):
            with mock.patch("mcp_server.shutil.which", return_value="/usr/bin/openwebgoggles"):
                main()
        assert (tmp_path / "opencode.json").exists()

    def test_restart_dispatch(self, tmp_path):
        data_dir = tmp_path / ".opencode" / "webview"
        data_dir.mkdir(parents=True)

        with mock.patch("sys.argv", ["openwebgoggles", "restart", str(tmp_path)]):
            with pytest.raises(SystemExit):
                main()

    def test_status_dispatch(self, tmp_path, capsys):
        with mock.patch("sys.argv", ["openwebgoggles", "status", str(tmp_path)]):
            main()
        output = capsys.readouterr().out
        assert "OpenWebGoggles Status" in output

    def test_doctor_dispatch(self, tmp_path, capsys):
        with mock.patch("sys.argv", ["openwebgoggles", "doctor", str(tmp_path)]):
            with mock.patch("shutil.which", return_value=None):
                main()
        output = capsys.readouterr().out
        assert "OpenWebGoggles Doctor" in output

    def test_mcp_server_mode_fails_without_mcp(self, capsys):
        """When no subcommand is given and mcp import failed, should exit with error."""
        with mock.patch("sys.argv", ["openwebgoggles"]):
            with mock.patch("mcp_server._mcp_import_error", ImportError("test")):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 1

        output = capsys.readouterr().err
        assert "failed to load mcp library" in output
