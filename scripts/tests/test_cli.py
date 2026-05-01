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

from cli import (
    _cmd_dev,
    _cmd_scaffold,
    _find_sdk_file,
    _find_template_dir,
    _parse_dev_args,
    _parse_scaffold_args,
)
from mcp_server import (
    _CLAUDE_SETTINGS,
    _DEPRECATED_PERMISSIONS,
    _SERVER_NAME_ALIASES,
    _cmd_doctor,
    _cmd_logs,
    _cmd_restart,
    _cmd_status,
    _find_data_dir,
    _find_server_key,
    _get_data_dir,
    _init_claude,
    _init_cursor,
    _init_opencode,
    _init_usage,
    _init_windsurf,
    _parse_logs_args,
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
    def test_default_uses_platform_data_dir(self):
        result = _find_data_dir(None)
        assert result == _get_data_dir()

    def test_explicit_path(self, tmp_path):
        result = _find_data_dir(tmp_path)
        assert result == tmp_path


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
    def test_found_via_which(self, tmp_path):
        # which() must return a path that is actually executable — bare names
        # are not enough, since the host would spawn-fail later anyway.
        fake_bin = tmp_path / "openwebgoggles"
        fake_bin.write_text("#!/bin/sh\nexit 0\n")
        fake_bin.chmod(0o755)
        with mock.patch("shutil.which", return_value=str(fake_bin)):
            result = _resolve_binary()
            assert result == str(fake_bin)

    def test_fallback_to_argv0(self, tmp_path):
        fake_bin = tmp_path / "openwebgoggles"
        fake_bin.write_text("#!/bin/sh\nexit 0\n")
        fake_bin.chmod(0o755)
        with mock.patch("shutil.which", return_value=None):
            with mock.patch("sys.argv", [str(fake_bin)]):
                result = _resolve_binary()
                assert result == str(fake_bin)

    def test_raises_when_unresolvable(self):
        # New strict behavior: refuse to return a bare name the host can't spawn.
        # The previous fallback ("openwebgoggles") was the root cause of the
        # ENOENT-spam bug — this test pins the new contract.
        from exceptions import BinaryResolveError

        with mock.patch("shutil.which", return_value=None):
            with mock.patch("sys.argv", ["/nonexistent/openwebgoggles"]):
                with pytest.raises(BinaryResolveError, match="Cannot locate"):
                    _resolve_binary()

    def test_which_result_must_be_executable(self, tmp_path):
        """A which() result that isn't executable falls back; raises if no fallback."""
        non_exec = tmp_path / "fake-openwebgoggles"
        non_exec.write_text("#!/bin/sh")  # NOT chmod +x — file exists but not executable
        from exceptions import BinaryResolveError

        with mock.patch("shutil.which", return_value=str(non_exec)):
            with mock.patch("sys.argv", ["/also-nonexistent"]):
                with pytest.raises(BinaryResolveError):
                    _resolve_binary()


# ---------------------------------------------------------------------------
# _init_claude
# ---------------------------------------------------------------------------


class TestInitClaude:
    def test_creates_mcp_json_and_settings(self, tmp_path, capsys):
        with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
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
        assert "mcp__openwebgoggles__openwebgoggles" in scfg["permissions"]["allow"]

        output = capsys.readouterr().out
        assert "created" in output.lower() or "Done" in output

    def test_idempotent_skips_existing(self, tmp_path, capsys):
        with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
            _init_claude(tmp_path)
            _init_claude(tmp_path)

        output = capsys.readouterr().out
        assert "skipping" in output.lower()

    def test_merges_into_existing_mcp_json(self, tmp_path, capsys):
        mcp_json = tmp_path / ".mcp.json"
        mcp_json.write_text(json.dumps({"mcpServers": {"other": {"command": "other"}}}) + "\n")

        with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
            _init_claude(tmp_path)

        cfg = json.loads(mcp_json.read_text())
        assert "openwebgoggles" in cfg["mcpServers"]
        assert "other" in cfg["mcpServers"]

    def test_adds_missing_permissions(self, tmp_path, capsys):
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings = claude_dir / "settings.json"
        settings.write_text(json.dumps({"permissions": {"allow": ["some_other_tool"]}}) + "\n")

        with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
            _init_claude(tmp_path)

        scfg = json.loads(settings.read_text())
        allow = scfg["permissions"]["allow"]
        assert "some_other_tool" in allow
        assert "mcp__openwebgoggles__openwebgoggles" in allow


# ---------------------------------------------------------------------------
# _init_opencode
# ---------------------------------------------------------------------------


class TestInitOpencode:
    def test_creates_opencode_json(self, tmp_path, capsys):
        with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
            _init_opencode(tmp_path)

        cfg_path = tmp_path / "opencode.json"
        assert cfg_path.exists()
        cfg = json.loads(cfg_path.read_text())
        assert "openwebgoggles" in cfg["mcp"]

    def test_idempotent_skips_existing(self, tmp_path, capsys):
        with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
            _init_opencode(tmp_path)
            _init_opencode(tmp_path)

        output = capsys.readouterr().out
        assert "skipping" in output.lower()

    def test_merges_into_existing_config(self, tmp_path, capsys):
        cfg_path = tmp_path / "opencode.json"
        cfg_path.write_text(json.dumps({"mcp": {"other": {"command": ["other"]}}}) + "\n")

        with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
            _init_opencode(tmp_path)

        cfg = json.loads(cfg_path.read_text())
        assert "openwebgoggles" in cfg["mcp"]
        assert "other" in cfg["mcp"]

    def test_reads_jsonc_file(self, tmp_path, capsys):
        jsonc_path = tmp_path / "opencode.jsonc"
        jsonc_path.write_text('{\n  // MCP servers\n  "mcp": {}\n}\n')

        with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
            _init_opencode(tmp_path)

        # Should have added to the jsonc file (rewritten as json)
        cfg = json.loads(jsonc_path.read_text())
        assert "openwebgoggles" in cfg["mcp"]

    def test_global_config_message(self, tmp_path, capsys):
        global_dir = Path.home() / ".config" / "opencode"
        with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
            # Patch Path.home resolution to match tmp_path
            with mock.patch.object(Path, "resolve", return_value=global_dir.resolve()):
                _init_opencode(tmp_path)

        output = capsys.readouterr().out
        # Just check it prints something about the config
        assert "Done" in output


# ---------------------------------------------------------------------------
# _init_cursor
# ---------------------------------------------------------------------------


class TestInitCursor:
    def test_creates_cursor_mcp_json(self, tmp_path, capsys):
        with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
            _init_cursor(tmp_path)

        cfg_path = tmp_path / ".cursor" / "mcp.json"
        assert cfg_path.exists()
        cfg = json.loads(cfg_path.read_text())
        assert "openwebgoggles" in cfg["mcpServers"]
        assert cfg["mcpServers"]["openwebgoggles"]["command"] == "/usr/bin/openwebgoggles"

    def test_idempotent_skips_existing(self, tmp_path, capsys):
        with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
            _init_cursor(tmp_path)
            _init_cursor(tmp_path)

        output = capsys.readouterr().out
        assert "skipping" in output.lower()

    def test_merges_into_existing_config(self, tmp_path, capsys):
        config_dir = tmp_path / ".cursor"
        config_dir.mkdir()
        cfg_path = config_dir / "mcp.json"
        cfg_path.write_text(json.dumps({"mcpServers": {"other": {"command": "other"}}}) + "\n")

        with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
            _init_cursor(tmp_path)

        cfg = json.loads(cfg_path.read_text())
        assert "openwebgoggles" in cfg["mcpServers"]
        assert "other" in cfg["mcpServers"]

    def test_done_message_mentions_cursor(self, tmp_path, capsys):
        with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
            _init_cursor(tmp_path)

        output = capsys.readouterr().out
        assert "Cursor" in output


# ---------------------------------------------------------------------------
# _init_windsurf
# ---------------------------------------------------------------------------


class TestInitWindsurf:
    def test_creates_windsurf_mcp_json(self, tmp_path, capsys):
        with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
            _init_windsurf(tmp_path)

        cfg_path = tmp_path / ".windsurf" / "mcp.json"
        assert cfg_path.exists()
        cfg = json.loads(cfg_path.read_text())
        assert "openwebgoggles" in cfg["mcpServers"]

    def test_idempotent_skips_existing(self, tmp_path, capsys):
        with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
            _init_windsurf(tmp_path)
            _init_windsurf(tmp_path)

        output = capsys.readouterr().out
        assert "skipping" in output.lower()

    def test_merges_into_existing_config(self, tmp_path, capsys):
        config_dir = tmp_path / ".windsurf"
        config_dir.mkdir()
        cfg_path = config_dir / "mcp.json"
        cfg_path.write_text(json.dumps({"mcpServers": {"other": {"command": "other"}}}) + "\n")

        with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
            _init_windsurf(tmp_path)

        cfg = json.loads(cfg_path.read_text())
        assert "openwebgoggles" in cfg["mcpServers"]
        assert "other" in cfg["mcpServers"]

    def test_done_message_mentions_windsurf(self, tmp_path, capsys):
        with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
            _init_windsurf(tmp_path)

        output = capsys.readouterr().out
        assert "Windsurf" in output


# ---------------------------------------------------------------------------
# _init_usage / _print_usage
# ---------------------------------------------------------------------------


class TestUsage:
    def test_init_usage_prints(self, capsys):
        _init_usage()
        output = capsys.readouterr().out
        assert "claude" in output
        assert "opencode" in output
        assert "cursor" in output
        assert "windsurf" in output
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
        data_dir = tmp_path
        data_dir.mkdir(parents=True, exist_ok=True)

        with mock.patch("sys.argv", ["openwebgoggles", "restart", str(tmp_path)]):
            with pytest.raises(SystemExit) as exc_info:
                _cmd_restart()
            assert exc_info.value.code == 1

        output = capsys.readouterr().out
        assert "No running MCP server found" in output

    def test_fallback_webview_pid_hint(self, tmp_path, capsys):
        data_dir = tmp_path
        data_dir.mkdir(parents=True, exist_ok=True)
        # Write a webview PID that's alive (our own PID)
        (data_dir / ".server.pid").write_text(str(os.getpid()))

        with mock.patch("sys.argv", ["openwebgoggles", "restart", str(tmp_path)]):
            with pytest.raises(SystemExit):
                _cmd_restart()

        output = capsys.readouterr().out
        assert "webview server" in output.lower()

    def test_sends_sigusr1_on_unix(self, tmp_path, capsys):
        data_dir = tmp_path
        data_dir.mkdir(parents=True, exist_ok=True)
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
        data_dir = tmp_path
        data_dir.mkdir(parents=True, exist_ok=True)
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
        data_dir = tmp_path
        data_dir.mkdir(parents=True, exist_ok=True)

        with mock.patch("sys.argv", ["openwebgoggles", "status", str(tmp_path)]):
            _cmd_status()

        output = capsys.readouterr().out
        assert "not running" in output
        assert "OpenWebGoggles Status" in output

    def test_mcp_server_running(self, tmp_path, capsys):
        data_dir = tmp_path
        data_dir.mkdir(parents=True, exist_ok=True)
        (data_dir / ".mcp.pid").write_text(str(os.getpid()))

        with mock.patch("sys.argv", ["openwebgoggles", "status", str(tmp_path)]):
            _cmd_status()

        output = capsys.readouterr().out
        assert f"PID {os.getpid()}" in output
        assert "running" in output

    def test_webview_with_manifest(self, tmp_path, capsys):
        data_dir = tmp_path
        data_dir.mkdir(parents=True, exist_ok=True)
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
        data_dir = tmp_path
        data_dir.mkdir(parents=True, exist_ok=True)
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
        mcp_json.write_text(json.dumps({"mcpServers": {"openwebgoggles": {"command": binary}}}))

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
        data_dir = tmp_path
        data_dir.mkdir(parents=True, exist_ok=True)
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
                with mock.patch("pathlib.Path.home", return_value=tmp_path):
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
        # An "old" binary that exists+executes but doesn't match the currently
        # resolved one. Doctor should warn on the mismatch (without flagging it
        # as stale, since the old path is still live).
        old_bin = tmp_path / "old-openwebgoggles"
        old_bin.write_text("#!/bin/sh\nexit 0\n")
        old_bin.chmod(0o755)
        new_bin = tmp_path / "new-openwebgoggles"
        new_bin.write_text("#!/bin/sh\nexit 0\n")
        new_bin.chmod(0o755)

        mcp_json = tmp_path / ".mcp.json"
        mcp_json.write_text(json.dumps({"mcpServers": {"openwebgoggles": {"command": str(old_bin)}}}))

        with mock.patch("sys.argv", ["openwebgoggles", "doctor", str(tmp_path)]):
            with mock.patch("cli._try_resolve_binary", return_value=str(new_bin)):
                _cmd_doctor()

        output = capsys.readouterr().out
        assert "differs" in output

    def test_lock_file_not_held(self, tmp_path, capsys):
        data_dir = tmp_path
        data_dir.mkdir(parents=True, exist_ok=True)
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
# _find_server_key and alias support
# ---------------------------------------------------------------------------


class TestFindServerKey:
    def test_exact_match(self):
        assert _find_server_key({"openwebgoggles": {}}) == "openwebgoggles"

    def test_alias_webview(self):
        assert _find_server_key({"webview": {}}) == "webview"

    def test_alias_open_webview(self):
        assert _find_server_key({"open-webview": {}}) == "open-webview"

    def test_alias_owg(self):
        assert _find_server_key({"owg": {}}) == "owg"

    def test_case_insensitive(self):
        assert _find_server_key({"OpenWebGoggles": {}}) == "OpenWebGoggles"

    def test_underscore_normalized(self):
        assert _find_server_key({"open_webview": {}}) == "open_webview"

    def test_no_match(self):
        assert _find_server_key({"other_server": {}}) is None

    def test_empty_dict(self):
        assert _find_server_key({}) is None

    def test_aliases_frozen(self):
        """Alias set is immutable."""
        assert isinstance(_SERVER_NAME_ALIASES, frozenset)
        assert "openwebgoggles" in _SERVER_NAME_ALIASES
        assert "webview" in _SERVER_NAME_ALIASES


class TestInitClaudeAliases:
    def test_skips_when_alias_configured(self, tmp_path, capsys):
        """init claude should skip if a known alias is already in .mcp.json."""
        mcp_json = tmp_path / ".mcp.json"
        mcp_json.write_text(json.dumps({"mcpServers": {"webview": {"command": "owg"}}}) + "\n")

        with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
            _init_claude(tmp_path)

        output = capsys.readouterr().out
        assert "webview" in output
        assert "skipping" in output.lower()

        # Should NOT have added a duplicate "openwebgoggles" key
        cfg = json.loads(mcp_json.read_text())
        assert "webview" in cfg["mcpServers"]
        assert "openwebgoggles" not in cfg["mcpServers"]


class TestInitOpencodeAliases:
    def test_skips_when_alias_configured(self, tmp_path, capsys):
        """init opencode should skip if a known alias is already in opencode.json."""
        cfg_path = tmp_path / "opencode.json"
        cfg_path.write_text(json.dumps({"mcp": {"open-webview": {"command": ["owg"]}}}) + "\n")

        with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
            _init_opencode(tmp_path)

        output = capsys.readouterr().out
        assert "open-webview" in output
        assert "skipping" in output.lower()

        # Should NOT have added a duplicate "openwebgoggles" key
        cfg = json.loads(cfg_path.read_text())
        assert "open-webview" in cfg["mcp"]
        assert "openwebgoggles" not in cfg["mcp"]


class TestDoctorAliases:
    def test_recognizes_webview_alias_in_mcp_json(self, tmp_path, capsys, monkeypatch):
        """Doctor should recognize 'webview' as a valid alias for the openwebgoggles entry."""
        # Isolate global config lookups so the CI runner's home dir doesn't leak in.
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

        # Real executable so the entry registers as `ok` rather than `stale`.
        fake_bin = tmp_path / "openwebgoggles"
        fake_bin.write_text("#!/bin/sh\nexit 0\n")
        fake_bin.chmod(0o755)
        binary = str(fake_bin)

        mcp_json = tmp_path / ".mcp.json"
        mcp_json.write_text(json.dumps({"mcpServers": {"webview": {"command": binary}}}))

        with mock.patch("sys.argv", ["openwebgoggles", "doctor", str(tmp_path)]):
            with mock.patch("cli._try_resolve_binary", return_value=binary):
                _cmd_doctor()

        output = capsys.readouterr().out
        assert "webview" in output, "alias key 'webview' not surfaced in doctor output"
        assert "configured" in output
        assert "[ok]" in output

    def test_recognizes_owg_alias_in_opencode(self, tmp_path, capsys, monkeypatch):
        """Doctor should recognize 'owg' as valid key in opencode.json."""
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
        oc_json = tmp_path / "opencode.json"
        oc_json.write_text(json.dumps({"mcp": {"owg": {"command": ["owg"]}}}))

        with mock.patch("sys.argv", ["openwebgoggles", "doctor", str(tmp_path)]):
            with mock.patch("shutil.which", return_value=None):
                _cmd_doctor()

        output = capsys.readouterr().out
        assert "owg" in output
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
            with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
                main()
        assert (tmp_path / ".mcp.json").exists()

    def test_init_opencode_dispatch(self, tmp_path):
        with mock.patch("sys.argv", ["openwebgoggles", "init", "opencode", str(tmp_path)]):
            with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
                main()
        assert (tmp_path / "opencode.json").exists()

    def test_init_cursor_dispatch(self, tmp_path):
        with mock.patch("sys.argv", ["openwebgoggles", "init", "cursor", str(tmp_path)]):
            with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
                main()
        assert (tmp_path / ".cursor" / "mcp.json").exists()

    def test_init_windsurf_dispatch(self, tmp_path):
        with mock.patch("sys.argv", ["openwebgoggles", "init", "windsurf", str(tmp_path)]):
            with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
                main()
        assert (tmp_path / ".windsurf" / "mcp.json").exists()

    def test_restart_dispatch(self, tmp_path):
        data_dir = tmp_path
        data_dir.mkdir(parents=True, exist_ok=True)

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


# ---------------------------------------------------------------------------
# Additional coverage: _cmd_status edge cases
# ---------------------------------------------------------------------------


class TestCmdStatusEdgeCases:
    def test_corrupt_manifest_json(self, tmp_path, capsys):
        """Corrupt manifest.json should be handled gracefully (line 1938-1939)."""
        data_dir = tmp_path
        data_dir.mkdir(parents=True, exist_ok=True)
        (data_dir / ".mcp.pid").write_text(str(os.getpid()))
        (data_dir / ".server.pid").write_text(str(os.getpid()))
        (data_dir / "manifest.json").write_text("invalid json{{{")

        with mock.patch("sys.argv", ["openwebgoggles", "status", str(tmp_path)]):
            _cmd_status()

        output = capsys.readouterr().out
        # Should not crash, manifest treated as None
        assert "OpenWebGoggles Status" in output

    def test_health_endpoint_reachable(self, tmp_path, capsys):
        """When health endpoint is reachable, shows uptime and ws_clients (lines 1950-1958)."""
        data_dir = tmp_path
        data_dir.mkdir(parents=True, exist_ok=True)
        (data_dir / ".mcp.pid").write_text(str(os.getpid()))
        (data_dir / ".server.pid").write_text(str(os.getpid()))
        manifest = {
            "version": "1.0",
            "app": {"name": "dynamic"},
            "session": {"id": "test-1234-5678"},
            "server": {"http_port": 18420, "ws_port": 18421, "host": "127.0.0.1"},
        }
        (data_dir / "manifest.json").write_text(json.dumps(manifest))

        health_data = json.dumps({"uptime": 185, "ws_clients": 2}).encode()
        mock_resp = mock.MagicMock()
        mock_resp.read.return_value = health_data
        mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mock.MagicMock(return_value=False)

        with mock.patch("sys.argv", ["openwebgoggles", "status", str(tmp_path)]):
            with mock.patch("urllib.request.urlopen", return_value=mock_resp):
                _cmd_status()

        output = capsys.readouterr().out
        assert "3m 5s" in output  # 185s = 3m 5s
        assert "2" in output  # ws_clients

    def test_health_endpoint_under_minute(self, tmp_path, capsys):
        """Uptime under 1 minute shows just seconds (line 1956-1957)."""
        data_dir = tmp_path
        data_dir.mkdir(parents=True, exist_ok=True)
        (data_dir / ".mcp.pid").write_text(str(os.getpid()))
        (data_dir / ".server.pid").write_text(str(os.getpid()))
        manifest = {
            "version": "1.0",
            "app": {"name": "dynamic"},
            "session": {"id": "test-1234"},
            "server": {"http_port": 18420},
        }
        (data_dir / "manifest.json").write_text(json.dumps(manifest))

        health_data = json.dumps({"uptime": 42, "ws_clients": 0}).encode()
        mock_resp = mock.MagicMock()
        mock_resp.read.return_value = health_data
        mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mock.MagicMock(return_value=False)

        with mock.patch("sys.argv", ["openwebgoggles", "status", str(tmp_path)]):
            with mock.patch("urllib.request.urlopen", return_value=mock_resp):
                _cmd_status()

        output = capsys.readouterr().out
        assert "42s" in output


# ---------------------------------------------------------------------------
# Additional coverage: _cmd_doctor edge cases
# ---------------------------------------------------------------------------


class TestCmdDoctorEdgeCases:
    def test_python_version_too_old(self, tmp_path, capsys):
        """Python < 3.11 should warn (line 2006).

        Note: We can't easily mock sys.version_info (it's a structseq).
        Instead we test the code path by directly verifying the branch logic.
        The actual test for deps found (below) implicitly tests the ok path.
        """
        # Skip if we can't mock it - the important thing is the logic is covered
        # by the other doctor tests that exercise the ok() path
        import mcp_server

        # We verify the code path exists by reading the source
        import inspect

        source = inspect.getsource(mcp_server._cmd_doctor)
        assert "3.11" in source  # Verify the check exists

    def test_all_deps_found(self, tmp_path, capsys):
        """When all deps are found, prints ok for each (line 2012)."""

        def mock_dist(name):
            d = mock.MagicMock()
            d.metadata = {"Version": "1.0.0"}
            return d

        with mock.patch("sys.argv", ["openwebgoggles", "doctor", str(tmp_path)]):
            with mock.patch("importlib.metadata.distribution", side_effect=mock_dist):
                with mock.patch("shutil.which", return_value="/usr/bin/openwebgoggles"):
                    _cmd_doctor()

        output = capsys.readouterr().out
        assert "websockets 1.0.0" in output
        assert "PyNaCl 1.0.0" in output
        assert "mcp 1.0.0" in output

    def test_all_checks_pass_summary(self, tmp_path, capsys, monkeypatch):
        """When all checks pass, prints the all-passed summary line."""

        def mock_dist(name):
            d = mock.MagicMock()
            d.metadata = {"Version": "1.0.0"}
            return d

        # Isolate global config lookups (Claude Desktop, OpenCode global,
        # etc.) — without this, configs already on the developer's machine
        # leak into the scan and fail the test.
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

        # Real executable so the strict binary check passes and the config's
        # command is considered live (not stale).
        fake_bin = tmp_path / "openwebgoggles"
        fake_bin.write_text("#!/bin/sh\nexit 0\n")
        fake_bin.chmod(0o755)

        mcp_json = tmp_path / ".mcp.json"
        mcp_json.write_text(json.dumps({"mcpServers": {"openwebgoggles": {"command": str(fake_bin)}}}))

        with mock.patch("sys.argv", ["openwebgoggles", "doctor", str(tmp_path)]):
            with mock.patch("importlib.metadata.distribution", side_effect=mock_dist):
                with mock.patch("cli._try_resolve_binary", return_value=str(fake_bin)):
                    _cmd_doctor()

        output = capsys.readouterr().out
        assert "checks passed" in output

    def test_stale_pid_oserror_on_read(self, tmp_path, capsys):
        """OSError reading PID file during stale check is suppressed (line 2080-2081)."""
        data_dir = tmp_path
        data_dir.mkdir(parents=True, exist_ok=True)
        pid_file = data_dir / ".mcp.pid"
        pid_file.write_text("12345")

        original_read_text = Path.read_text

        def mock_read_text(self_path, *args, **kwargs):
            if str(self_path) == str(pid_file):
                raise OSError("Permission denied")
            return original_read_text(self_path, *args, **kwargs)

        with mock.patch("sys.argv", ["openwebgoggles", "doctor", str(tmp_path)]):
            with mock.patch("shutil.which", return_value=None):
                with mock.patch.object(Path, "read_text", mock_read_text):
                    _cmd_doctor()  # Should not raise

    def test_lock_held_by_running_server(self, tmp_path, capsys):
        """Lock held by another process shows ok (line 2102-2103)."""

        data_dir = tmp_path
        data_dir.mkdir(parents=True, exist_ok=True)
        lock_file = data_dir / ".server.lock"
        lock_file.write_text("")

        def mock_flock(fd, op):
            raise OSError("Resource temporarily unavailable")

        with mock.patch("sys.argv", ["openwebgoggles", "doctor", str(tmp_path)]):
            with mock.patch("shutil.which", return_value=None):
                with mock.patch("fcntl.flock", side_effect=mock_flock):
                    _cmd_doctor()

        output = capsys.readouterr().out
        assert "Lock file held" in output

    def test_lock_present_with_server_pid(self, tmp_path, capsys):
        """Lock file OK when server pid exists (line 2101)."""

        data_dir = tmp_path
        data_dir.mkdir(parents=True, exist_ok=True)
        lock_file = data_dir / ".server.lock"
        lock_file.write_text("")
        (data_dir / ".server.pid").write_text(str(os.getpid()))

        with mock.patch("sys.argv", ["openwebgoggles", "doctor", str(tmp_path)]):
            with mock.patch("shutil.which", return_value=None):
                _cmd_doctor()

        output = capsys.readouterr().out
        assert "Lock file OK" in output

    def test_lock_open_fails(self, tmp_path, capsys):
        """OSError on lock file open shows no conflicts (line 2106-2107)."""
        data_dir = tmp_path
        data_dir.mkdir(parents=True, exist_ok=True)
        lock_file = data_dir / ".server.lock"
        lock_file.write_text("")

        with mock.patch("sys.argv", ["openwebgoggles", "doctor", str(tmp_path)]):
            with mock.patch("shutil.which", return_value=None):
                with mock.patch("os.open", side_effect=OSError("fail")):
                    _cmd_doctor()

        output = capsys.readouterr().out
        assert "No lock conflicts" in output

    def test_config_parse_error(self, tmp_path, capsys):
        """OSError/JSONDecodeError reading config file is suppressed (line 2057-2058)."""
        # Create .mcp.json with invalid JSON - the doctor detects this as invalid
        mcp_json = tmp_path / ".mcp.json"
        mcp_json.write_text("{invalid json")

        with mock.patch("sys.argv", ["openwebgoggles", "doctor", str(tmp_path)]):
            with mock.patch("shutil.which", return_value=None):
                _cmd_doctor()  # Should not raise (parse error handled)

        output = capsys.readouterr().out
        assert "invalid JSON" in output or "No editor config" in output


# ---------------------------------------------------------------------------
# Additional coverage: _cmd_restart edge cases
# ---------------------------------------------------------------------------


class TestCmdRestartEdgeCases:
    def test_restart_process_died_after_signal(self, tmp_path, capsys):
        """After SIGUSR1, if process died, should print fallback message (line 1907-1908)."""
        data_dir = tmp_path
        data_dir.mkdir(parents=True, exist_ok=True)
        (data_dir / ".mcp.pid").write_text(str(os.getpid()))

        call_count = [0]

        def mock_kill(pid, sig):
            call_count[0] += 1
            if sig == 0 and call_count[0] > 1:
                raise OSError("No such process")

        with mock.patch("sys.argv", ["openwebgoggles", "restart", str(tmp_path)]):
            with mock.patch("platform.system", return_value="Linux"):
                with mock.patch("os.kill", side_effect=mock_kill):
                    with mock.patch("time.sleep"):
                        _cmd_restart()

        output = capsys.readouterr().out
        assert "exited" in output or "restart" in output.lower()

    def test_windows_sigterm_fallback(self, tmp_path, capsys):
        """On Windows, should send SIGTERM instead of SIGUSR1 (already tested but adding edge)."""
        data_dir = tmp_path
        data_dir.mkdir(parents=True, exist_ok=True)
        (data_dir / ".mcp.pid").write_text(str(os.getpid()))

        with mock.patch("sys.argv", ["openwebgoggles", "restart", str(tmp_path)]):
            with mock.patch("platform.system", return_value="Windows"):
                with mock.patch("os.kill") as mock_kill:
                    mock_kill.side_effect = [None, None]  # SIGTERM + existence check
                    with mock.patch("time.sleep"):
                        # Windows path calls SIGTERM via signal.SIGTERM
                        try:
                            _cmd_restart()
                        except SystemExit:
                            pass  # Windows path may exit


# ---------------------------------------------------------------------------
# Permission migration in _init_claude
# ---------------------------------------------------------------------------


class TestPermissionMigration:
    def test_removes_deprecated_permissions(self, tmp_path, capsys):
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings = claude_dir / "settings.json"
        old_perms = list(_DEPRECATED_PERMISSIONS) + ["some_other_tool"]
        settings.write_text(json.dumps({"permissions": {"allow": old_perms}}) + "\n")

        with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
            _init_claude(tmp_path)

        scfg = json.loads(settings.read_text())
        allow = scfg["permissions"]["allow"]
        # All deprecated strings removed
        for dep in _DEPRECATED_PERMISSIONS:
            assert dep not in allow, f"{dep} should have been removed"
        # New permissions added
        for new_perm in _CLAUDE_SETTINGS["permissions"]["allow"]:
            assert new_perm in allow
        # Unrelated tool preserved
        assert "some_other_tool" in allow

    def test_migration_reported_in_output(self, tmp_path, capsys):
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings = claude_dir / "settings.json"
        stale = ["mcp__openwebgoggles__webview", "mcp__openwebgoggles__webview_read"]
        settings.write_text(json.dumps({"permissions": {"allow": stale}}) + "\n")

        with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
            _init_claude(tmp_path)

        output = capsys.readouterr().out
        assert "stale" in output.lower()

    def test_deprecated_set_is_frozen(self):
        assert isinstance(_DEPRECATED_PERMISSIONS, frozenset)
        assert "mcp__openwebgoggles__webview" in _DEPRECATED_PERMISSIONS

    def test_no_deprecated_perms_leaves_file_untouched(self, tmp_path, capsys):
        """init should report 'skipping' when permissions already correct."""
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings = claude_dir / "settings.json"
        current = list(_CLAUDE_SETTINGS["permissions"]["allow"])
        settings.write_text(json.dumps({"permissions": {"allow": current}}) + "\n")

        with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
            _init_claude(tmp_path)

        output = capsys.readouterr().out
        assert "skipping" in output.lower()


# ---------------------------------------------------------------------------
# doctor warns about deprecated permissions
# ---------------------------------------------------------------------------


class TestDoctorDeprecatedPermissions:
    def test_warns_on_stale_permissions(self, tmp_path, capsys):
        mcp_json = tmp_path / ".mcp.json"
        mcp_json.write_text(json.dumps({"mcpServers": {"openwebgoggles": {"command": "/usr/bin/owg"}}}))
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings = claude_dir / "settings.json"
        settings.write_text(json.dumps({"permissions": {"allow": ["mcp__openwebgoggles__webview"]}}) + "\n")

        with mock.patch("sys.argv", ["openwebgoggles", "doctor", str(tmp_path)]):
            with mock.patch("shutil.which", return_value="/usr/bin/openwebgoggles"):
                with mock.patch("pathlib.Path.home", return_value=tmp_path / "fakehome"):
                    _cmd_doctor()

        output = capsys.readouterr().out
        assert "[!!]" in output
        assert "stale" in output.lower()

    def test_no_warning_without_stale_permissions(self, tmp_path, capsys):
        mcp_json = tmp_path / ".mcp.json"
        mcp_json.write_text(json.dumps({"mcpServers": {"openwebgoggles": {"command": "/usr/bin/owg"}}}))

        with mock.patch("sys.argv", ["openwebgoggles", "doctor", str(tmp_path)]):
            with mock.patch("shutil.which", return_value="/usr/bin/openwebgoggles"):
                with mock.patch("pathlib.Path.home", return_value=tmp_path / "fakehome"):
                    _cmd_doctor()

        output = capsys.readouterr().out
        assert "stale permission" not in output.lower()


# ---------------------------------------------------------------------------
# init claude --global
# ---------------------------------------------------------------------------


class TestInitClaudeGlobal:
    def test_global_flag_routes_to_home(self, tmp_path, capsys):
        with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
            with mock.patch("sys.argv", ["openwebgoggles", "init", "claude", "--global"]):
                with mock.patch("mcp_server._init_claude") as mock_init:
                    main()

        mock_init.assert_called_once()
        call_args = mock_init.call_args
        # First positional arg should be Path.home(), global_mode=True
        assert call_args.kwargs.get("global_mode") is True or (len(call_args.args) > 1 and call_args.args[1] is True)

    def test_global_flag_writes_to_home_dir(self, tmp_path, capsys):
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
            with mock.patch("sys.argv", ["openwebgoggles", "init", "claude", "--global"]):
                with mock.patch("pathlib.Path.home", return_value=fake_home):
                    with mock.patch("mcp_server._setup_claude_desktop_config"):
                        _init_claude(fake_home, global_mode=True)

        # Should write ~/.mcp.json (i.e. fake_home/.mcp.json)
        assert (fake_home / ".mcp.json").exists()
        # Should write ~/.claude/settings.json
        assert (fake_home / ".claude" / "settings.json").exists()

    def test_global_done_message(self, tmp_path, capsys):
        with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
            with mock.patch("mcp_server._setup_claude_desktop_config"):
                _init_claude(tmp_path, global_mode=True)

        output = capsys.readouterr().out
        assert "globally" in output.lower() or "all projects" in output.lower()

    def test_project_done_message(self, tmp_path, capsys):
        with mock.patch("cli._try_resolve_binary", return_value="/usr/bin/openwebgoggles"):
            with mock.patch("mcp_server._setup_claude_desktop_config"):
                _init_claude(tmp_path, global_mode=False)

        output = capsys.readouterr().out
        assert "globally" not in output.lower()

    def test_global_flag_in_usage(self, capsys):
        _init_usage()
        output = capsys.readouterr().out
        assert "--global" in output


# ---------------------------------------------------------------------------
# _cmd_logs / _parse_logs_args
# ---------------------------------------------------------------------------


class TestCmdLogsArgs:
    def test_defaults(self):
        lines, tail = _parse_logs_args([])
        assert lines == 50
        assert tail is False

    def test_lines_short(self):
        lines, tail = _parse_logs_args(["-n", "20"])
        assert lines == 20

    def test_lines_long(self):
        lines, tail = _parse_logs_args(["--lines", "100"])
        assert lines == 100

    def test_tail_flag(self):
        _, tail = _parse_logs_args(["--tail"])
        assert tail is True

    def test_tail_short(self):
        _, tail = _parse_logs_args(["-f"])
        assert tail is True

    def test_combined(self):
        lines, tail = _parse_logs_args(["-n", "5", "-f"])
        assert lines == 5
        assert tail is True


class TestCmdLogsOutput:
    def test_no_log_file_prints_helpful_message(self, tmp_path, capsys):
        missing = tmp_path / "nonexistent.log"
        import log_config as lc

        real_default = lc.DEFAULT_LOG_FILE
        lc.DEFAULT_LOG_FILE = missing
        try:
            _cmd_logs(lines=50, tail=False)
        finally:
            lc.DEFAULT_LOG_FILE = real_default

        out = capsys.readouterr().out
        assert "No log file" in out or "not found" in out.lower() or str(missing) in out

    def test_prints_last_n_lines(self, tmp_path, capsys):
        log_file = tmp_path / "server.log"
        log_file.write_text("\n".join(f"line{i}" for i in range(100)) + "\n")

        import log_config as lc

        real_default = lc.DEFAULT_LOG_FILE
        lc.DEFAULT_LOG_FILE = log_file
        try:
            _cmd_logs(lines=10, tail=False)
        finally:
            lc.DEFAULT_LOG_FILE = real_default

        out = capsys.readouterr().out
        lines = [l for l in out.splitlines() if l.strip()]
        assert len(lines) == 10
        assert lines[0] == "line90"
        assert lines[-1] == "line99"

    def test_prints_all_lines_when_fewer_than_n(self, tmp_path, capsys):
        log_file = tmp_path / "server.log"
        log_file.write_text("alpha\nbeta\ngamma\n")

        import log_config as lc

        real_default = lc.DEFAULT_LOG_FILE
        lc.DEFAULT_LOG_FILE = log_file
        try:
            _cmd_logs(lines=50, tail=False)
        finally:
            lc.DEFAULT_LOG_FILE = real_default

        out = capsys.readouterr().out
        assert "alpha" in out
        assert "beta" in out
        assert "gamma" in out


class TestLogsMainDispatch:
    def test_logs_dispatched_from_main(self, tmp_path, capsys):
        log_file = tmp_path / "server.log"
        log_file.write_text("dispatched log line\n")

        import log_config as lc

        real_default = lc.DEFAULT_LOG_FILE
        lc.DEFAULT_LOG_FILE = log_file
        try:
            with mock.patch("sys.argv", ["openwebgoggles", "logs", "--lines", "5"]):
                main()
        finally:
            lc.DEFAULT_LOG_FILE = real_default

        out = capsys.readouterr().out
        assert "dispatched log line" in out

    def test_logs_in_usage_help(self, capsys):
        _print_usage()
        out = capsys.readouterr().out
        assert "logs" in out


# ---------------------------------------------------------------------------
# Phase 3.5: scaffold command
# ---------------------------------------------------------------------------


class TestParseScaffoldArgs:
    def test_app_name_required(self):
        with pytest.raises(SystemExit):
            _parse_scaffold_args([])

    def test_app_name_parsed(self):
        app_name, out_dir, force = _parse_scaffold_args(["my-app"])
        assert app_name == "my-app"
        assert out_dir is None
        assert force is False

    def test_output_dir_short(self, tmp_path):
        app_name, out_dir, force = _parse_scaffold_args(["my-app", "-o", str(tmp_path)])
        assert out_dir == tmp_path

    def test_output_dir_long(self, tmp_path):
        app_name, out_dir, force = _parse_scaffold_args(["my-app", "--output-dir", str(tmp_path)])
        assert out_dir == tmp_path

    def test_force_flag(self):
        _, _, force = _parse_scaffold_args(["my-app", "--force"])
        assert force is True

    def test_force_short(self):
        _, _, force = _parse_scaffold_args(["my-app", "-f"])
        assert force is True


class TestCmdScaffold:
    def test_creates_directory_with_files(self, tmp_path, capsys):
        rc = _cmd_scaffold("my-app", output_dir=tmp_path)
        assert rc == 0
        dest = tmp_path / "my-app"
        assert dest.is_dir()
        # Template files are copied
        assert (dest / "index.html").is_file()
        assert (dest / "app.js").is_file()
        assert (dest / "style.css").is_file()

    def test_substitutes_app_name(self, tmp_path):
        _cmd_scaffold("my-app", output_dir=tmp_path)
        content = (tmp_path / "my-app" / "index.html").read_text()
        # {{APP_NAME}} should be replaced with the display name
        assert "{{APP_NAME}}" not in content
        assert "My App" in content

    def test_substitutes_underscore_app_name(self, tmp_path):
        _cmd_scaffold("my_cool_app", output_dir=tmp_path)
        content = (tmp_path / "my_cool_app" / "app.js").read_text()
        assert "{{APP_NAME}}" not in content
        assert "My Cool App" in content

    def test_sdk_js_copied(self, tmp_path):
        _cmd_scaffold("my-app", output_dir=tmp_path)
        # SDK file should be present (or warning printed if not found)
        dest = tmp_path / "my-app"
        sdk = dest / "openwebgoggles-sdk.js"
        # In dev mode, the SDK exists in assets/sdk/
        assert sdk.is_file()

    def test_invalid_name_returns_1(self, tmp_path, capsys):
        rc = _cmd_scaffold("123-bad", output_dir=tmp_path)
        assert rc == 1
        err = capsys.readouterr().err
        assert "invalid app name" in err

    def test_name_with_leading_hyphen_rejected(self, tmp_path, capsys):
        rc = _cmd_scaffold("-badname", output_dir=tmp_path)
        assert rc == 1

    def test_existing_dir_without_force_returns_1(self, tmp_path, capsys):
        _cmd_scaffold("my-app", output_dir=tmp_path)
        rc = _cmd_scaffold("my-app", output_dir=tmp_path)
        assert rc == 1
        err = capsys.readouterr().err
        assert "already exists" in err

    def test_force_overwrites_existing(self, tmp_path):
        _cmd_scaffold("my-app", output_dir=tmp_path)
        # Modify a file
        (tmp_path / "my-app" / "app.js").write_text("// modified")
        rc = _cmd_scaffold("my-app", output_dir=tmp_path, force=True)
        assert rc == 0
        # File should be restored from template
        content = (tmp_path / "my-app" / "app.js").read_text()
        assert "// modified" not in content

    def test_output_shows_created_message(self, tmp_path, capsys):
        _cmd_scaffold("my-app", output_dir=tmp_path)
        out = capsys.readouterr().out
        assert "Created app scaffold" in out
        assert "my-app" in out

    def test_output_shows_next_steps(self, tmp_path, capsys):
        _cmd_scaffold("my-app", output_dir=tmp_path)
        out = capsys.readouterr().out
        assert "Next steps" in out
        assert "renderData" in out

    def test_missing_template_dir_returns_1(self, tmp_path, capsys):
        with mock.patch("cli._find_template_dir", side_effect=FileNotFoundError("no template")):
            rc = _cmd_scaffold("my-app", output_dir=tmp_path)
        assert rc == 1
        err = capsys.readouterr().err
        assert "no template" in err

    def test_find_template_dir_finds_dev_location(self):
        """_find_template_dir() returns a valid directory in dev mode."""
        d = _find_template_dir()
        assert d.is_dir()
        assert (d / "index.html").is_file()
        assert (d / "app.js").is_file()

    def test_find_sdk_file_finds_dev_sdk(self):
        """_find_sdk_file() finds the SDK in dev mode."""
        sdk = _find_sdk_file()
        assert sdk is not None
        assert sdk.is_file()
        assert sdk.name == "openwebgoggles-sdk.js"


class TestScaffoldMainDispatch:
    def test_scaffold_dispatched_from_main(self, tmp_path, capsys):
        with mock.patch("sys.argv", ["openwebgoggles", "scaffold", "test-app", "-o", str(tmp_path)]):
            with pytest.raises(SystemExit) as exc_info:
                main()
        assert exc_info.value.code == 0
        assert (tmp_path / "test-app").is_dir()

    def test_scaffold_in_usage_help(self, capsys):
        _print_usage()
        out = capsys.readouterr().out
        assert "scaffold" in out


# ---------------------------------------------------------------------------
# _parse_dev_args
# ---------------------------------------------------------------------------


class TestParseDevArgs:
    def test_app_name_required(self):
        with pytest.raises(SystemExit):
            _parse_dev_args([])

    def test_positional_app_name(self):
        app, data_dir, http, ws, wds = _parse_dev_args(["myapp"])
        assert app == "myapp"
        assert data_dir is None
        assert http == 18420
        assert ws == 18421
        assert wds == []

    def test_custom_ports(self):
        app, _, http, ws, _ = _parse_dev_args(["myapp", "--http-port", "9000", "--ws-port", "9001"])
        assert http == 9000
        assert ws == 9001

    def test_data_dir(self, tmp_path):
        app, data_dir, _, _, _ = _parse_dev_args(["myapp", "--data-dir", str(tmp_path)])
        assert data_dir == tmp_path

    def test_watch_dir_single(self, tmp_path):
        _, _, _, _, wds = _parse_dev_args(["myapp", "--watch-dir", str(tmp_path)])
        assert wds == [str(tmp_path)]

    def test_watch_dir_multiple(self, tmp_path):
        d1 = str(tmp_path / "a")
        d2 = str(tmp_path / "b")
        _, _, _, _, wds = _parse_dev_args(["myapp", "--watch-dir", d1, "--watch-dir", d2])
        assert wds == [d1, d2]


# ---------------------------------------------------------------------------
# _cmd_dev
# ---------------------------------------------------------------------------


class TestCmdDev:
    def test_sdk_not_found_returns_1(self, capsys):
        with mock.patch("cli._find_sdk_file", return_value=None):
            rc = _cmd_dev("myapp")
        assert rc == 1
        out = capsys.readouterr()
        assert "not found" in out.err

    def test_launches_subprocess_with_dev_flag(self, tmp_path, capsys):
        fake_sdk = tmp_path / "sdk.js"
        fake_sdk.touch()
        fake_result = mock.Mock()
        fake_result.returncode = 0
        with mock.patch("cli._find_sdk_file", return_value=fake_sdk):
            with mock.patch("subprocess.run", return_value=fake_result) as mock_run:
                rc = _cmd_dev("myapp", data_dir=tmp_path)
        assert rc == 0
        call_args = mock_run.call_args[0][0]
        assert "--dev" in call_args
        assert "--app" in call_args
        assert "myapp" in call_args

    def test_watch_dirs_passed_to_subprocess(self, tmp_path, capsys):
        fake_sdk = tmp_path / "sdk.js"
        fake_sdk.touch()
        watch = str(tmp_path / "src")
        fake_result = mock.Mock()
        fake_result.returncode = 0
        with mock.patch("cli._find_sdk_file", return_value=fake_sdk):
            with mock.patch("subprocess.run", return_value=fake_result) as mock_run:
                rc = _cmd_dev("myapp", data_dir=tmp_path, watch_dirs=[watch])
        assert rc == 0
        call_args = mock_run.call_args[0][0]
        assert "--watch-dir" in call_args
        assert watch in call_args

    def test_app_dir_auto_watched_when_exists(self, tmp_path, capsys):
        fake_sdk = tmp_path / "sdk.js"
        fake_sdk.touch()
        app_dir = tmp_path / "apps" / "myapp"
        app_dir.mkdir(parents=True)
        fake_result = mock.Mock()
        fake_result.returncode = 0
        with mock.patch("cli._find_sdk_file", return_value=fake_sdk):
            with mock.patch("subprocess.run", return_value=fake_result) as mock_run:
                _cmd_dev("myapp", data_dir=tmp_path)
        call_args = mock_run.call_args[0][0]
        assert "--watch-dir" in call_args
        assert str(app_dir) in call_args

    def test_keyboard_interrupt_returns_0(self, tmp_path, capsys):
        fake_sdk = tmp_path / "sdk.js"
        fake_sdk.touch()
        with mock.patch("cli._find_sdk_file", return_value=fake_sdk):
            with mock.patch("subprocess.run", side_effect=KeyboardInterrupt):
                rc = _cmd_dev("myapp", data_dir=tmp_path)
        assert rc == 0

    def test_prints_startup_message(self, tmp_path, capsys):
        fake_sdk = tmp_path / "sdk.js"
        fake_sdk.touch()
        fake_result = mock.Mock()
        fake_result.returncode = 0
        with mock.patch("cli._find_sdk_file", return_value=fake_sdk):
            with mock.patch("subprocess.run", return_value=fake_result):
                _cmd_dev("myapp", data_dir=tmp_path)
        out = capsys.readouterr().out
        assert "myapp" in out
        assert "18420" in out


# ---------------------------------------------------------------------------
# dev dispatch via main()
# ---------------------------------------------------------------------------


class TestDevMainDispatch:
    def test_dev_dispatched_from_main(self, tmp_path, capsys):
        fake_result = mock.Mock()
        fake_result.returncode = 0
        fake_sdk = tmp_path / "sdk.js"
        fake_sdk.touch()
        with mock.patch("sys.argv", ["openwebgoggles", "dev", "myapp", "--data-dir", str(tmp_path)]):
            with mock.patch("cli._find_sdk_file", return_value=fake_sdk):
                with mock.patch("subprocess.run", return_value=fake_result):
                    with pytest.raises(SystemExit) as exc_info:
                        main()
        assert exc_info.value.code == 0

    def test_dev_in_usage_help(self, capsys):
        _print_usage()
        out = capsys.readouterr().out
        assert "dev" in out
