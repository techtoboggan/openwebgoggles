"""Tests for the data-driven editor registry and config repair.

Covers:
  * scripts/editors.py — EditorSpec entries, all_known_locations()
  * scripts/cli.py — _scan_configs(), _repair_configs(), strict _resolve_binary()

The repair flow is the user-visible payoff of this refactor — when the
``command`` path in an MCP config goes stale (binary moved, package
uninstalled), ``openwebgoggles doctor --fix`` should rewrite it to the
currently-resolved binary across every known editor config in one shot.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cli import (  # noqa: E402, I001
    _entry_command_path,
    _is_stale_path,
    _repair_configs,
    _scan_configs,
    _set_entry_command,
)
from editors import EDITORS, ConfigSchema, all_known_locations  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    """Redirect Path.home() to tmp_path so global config lookups stay isolated."""
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    return tmp_path


@pytest.fixture
def fake_binary(tmp_path):
    """Create a real executable for tests that need the strict resolver to succeed."""
    fake = tmp_path / "openwebgoggles"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    return str(fake)


# ---------------------------------------------------------------------------
# Registry sanity
# ---------------------------------------------------------------------------


class TestEditorRegistry:
    def test_every_editor_has_required_fields(self):
        for name, spec in EDITORS.items():
            assert spec.name == name, f"{name}: name field doesn't match registry key"
            assert spec.display_name, f"{name}: missing display_name"
            assert spec.summary, f"{name}: missing summary"
            assert callable(spec.config_locations), f"{name}: config_locations not callable"

    def test_all_known_locations_dedupes(self, isolated_home):
        # Claude Desktop's path appears under both `claude` and `claude-desktop`
        # entries — all_known_locations() should yield it once, not twice.
        seen: list[Path] = []
        for loc in all_known_locations(isolated_home):
            seen.append(loc.path)
        assert len(seen) == len(set(seen)), f"duplicate paths: {seen}"

    @pytest.mark.parametrize("editor_name", list(EDITORS.keys()))
    def test_config_locations_yields_at_least_one(self, editor_name, isolated_home):
        spec = EDITORS[editor_name]
        locations = list(spec.config_locations(isolated_home))
        assert locations, f"{editor_name}: no config locations"
        for loc in locations:
            assert isinstance(loc.schema, ConfigSchema)
            assert loc.description


# ---------------------------------------------------------------------------
# Schema-aware command extraction
# ---------------------------------------------------------------------------


class TestCommandExtraction:
    def test_mcp_servers_string_command(self):
        entry = {"command": "/usr/bin/owg"}
        assert _entry_command_path(entry, ConfigSchema.MCP_SERVERS) == "/usr/bin/owg"

    def test_opencode_list_command(self):
        entry = {"command": ["/usr/bin/owg", "--flag"], "type": "local"}
        assert _entry_command_path(entry, ConfigSchema.OPENCODE) == "/usr/bin/owg"

    def test_opencode_empty_list_returns_none(self):
        entry = {"command": [], "type": "local"}
        assert _entry_command_path(entry, ConfigSchema.OPENCODE) is None

    def test_set_entry_command_preserves_opencode_list_shape(self):
        entry = {"command": ["/old", "--flag"], "type": "local"}
        _set_entry_command(entry, "/new", ConfigSchema.OPENCODE)
        assert entry["command"] == ["/new", "--flag"]

    def test_set_entry_command_mcp_servers_shape(self):
        entry = {"command": "/old"}
        _set_entry_command(entry, "/new", ConfigSchema.MCP_SERVERS)
        assert entry["command"] == "/new"


# ---------------------------------------------------------------------------
# Stale-path detection
# ---------------------------------------------------------------------------


class TestStalePathDetection:
    def test_missing_command_is_stale(self):
        assert _is_stale_path(None) is True
        assert _is_stale_path("") is True

    def test_bare_name_is_not_stale(self):
        # Bare names (no path separator) are deferred to the host's PATH at
        # spawn time — we can't tell from disk whether they'll resolve.
        assert _is_stale_path("openwebgoggles") is False

    def test_absolute_nonexistent_is_stale(self):
        assert _is_stale_path("/definitely/does/not/exist/openwebgoggles") is True

    def test_absolute_executable_is_not_stale(self, fake_binary):
        assert _is_stale_path(fake_binary) is False

    def test_absolute_non_executable_is_stale(self, tmp_path):
        non_exec = tmp_path / "owg"
        non_exec.write_text("#!/bin/sh")  # NOT chmod +x
        assert _is_stale_path(str(non_exec)) is True


# ---------------------------------------------------------------------------
# Scan — finds entries across every known editor
# ---------------------------------------------------------------------------


class TestScanConfigs:
    def test_scan_picks_up_mcp_servers_entry(self, tmp_path, isolated_home):
        # Create a project-level Claude Code config
        (tmp_path / ".mcp.json").write_text(
            json.dumps({"mcpServers": {"openwebgoggles": {"command": "/some/path/owg"}}})
        )
        results = _scan_configs(tmp_path)
        assert any(r["status"] == "stale" and r["command"] == "/some/path/owg" for r in results)

    def test_scan_picks_up_opencode_entry(self, tmp_path, isolated_home):
        # OpenCode global config (in isolated_home/.config/opencode/opencode.json)
        opencode_dir = isolated_home / ".config" / "opencode"
        opencode_dir.mkdir(parents=True)
        (opencode_dir / "opencode.json").write_text(
            json.dumps({"mcp": {"openwebgoggles": {"type": "local", "command": ["/x/owg"]}}})
        )
        results = _scan_configs(tmp_path)
        opencode_results = [r for r in results if "OpenCode" in r["location"].description]
        assert opencode_results, "OpenCode config not found by scan"
        assert opencode_results[0]["command"] == "/x/owg"
        assert opencode_results[0]["status"] == "stale"

    def test_scan_recognizes_aliases(self, tmp_path, isolated_home):
        """_find_server_key handles 'webview', 'open-webgoggles', etc."""
        (tmp_path / ".mcp.json").write_text(
            json.dumps({"mcpServers": {"webview": {"command": "/x/owg"}}})
        )
        results = _scan_configs(tmp_path)
        assert any(r.get("key") == "webview" for r in results)

    def test_scan_reports_parse_error(self, tmp_path, isolated_home):
        (tmp_path / ".mcp.json").write_text("not valid json{{{")
        results = _scan_configs(tmp_path)
        assert any(r["status"] == "parse-error" for r in results)

    def test_scan_reports_no_entry(self, tmp_path, isolated_home):
        (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"other-server": {}}}))
        results = _scan_configs(tmp_path)
        assert any(r["status"] == "no-entry" for r in results)

    def test_scan_reports_ok_for_live_entry(self, tmp_path, isolated_home, fake_binary):
        (tmp_path / ".mcp.json").write_text(
            json.dumps({"mcpServers": {"openwebgoggles": {"command": fake_binary}}})
        )
        results = _scan_configs(tmp_path)
        ok_entries = [r for r in results if r["status"] == "ok"]
        assert ok_entries, "live config not detected as ok"


# ---------------------------------------------------------------------------
# Repair — rewrite stale paths or remove on uninstall
# ---------------------------------------------------------------------------


class TestRepairConfigs:
    def test_rewrites_stale_mcp_servers_path(self, tmp_path, isolated_home, fake_binary):
        cfg_path = tmp_path / ".mcp.json"
        cfg_path.write_text(
            json.dumps({"mcpServers": {"openwebgoggles": {"command": "/usr/bin/old-owg"}}})
        )
        with mock.patch("cli._try_resolve_binary", return_value=fake_binary):
            fixed, removed = _repair_configs(tmp_path)
        assert fixed == 1 and removed == 0
        rewritten = json.loads(cfg_path.read_text())
        assert rewritten["mcpServers"]["openwebgoggles"]["command"] == fake_binary

    def test_rewrites_stale_opencode_list_command(self, tmp_path, isolated_home, fake_binary):
        cfg_path = tmp_path / "opencode.json"
        cfg_path.write_text(
            json.dumps({"mcp": {"openwebgoggles": {"type": "local", "command": ["/usr/bin/old", "--flag"]}}})
        )
        with mock.patch("cli._try_resolve_binary", return_value=fake_binary):
            fixed, _ = _repair_configs(tmp_path)
        assert fixed == 1
        rewritten = json.loads(cfg_path.read_text())
        # Preserves args after the command (--flag) — only the executable changes.
        assert rewritten["mcp"]["openwebgoggles"]["command"] == [fake_binary, "--flag"]

    def test_leaves_live_entries_alone(self, tmp_path, isolated_home, fake_binary):
        cfg_path = tmp_path / ".mcp.json"
        cfg_path.write_text(
            json.dumps({"mcpServers": {"openwebgoggles": {"command": fake_binary}}})
        )
        before = cfg_path.read_text()
        with mock.patch("cli._try_resolve_binary", return_value=fake_binary):
            fixed, removed = _repair_configs(tmp_path)
        assert fixed == 0 and removed == 0
        assert cfg_path.read_text() == before  # untouched

    def test_removes_entry_when_binary_unresolvable_and_remove_flag(self, tmp_path, isolated_home):
        cfg_path = tmp_path / ".mcp.json"
        cfg_path.write_text(
            json.dumps(
                {"mcpServers": {"openwebgoggles": {"command": "/gone"}, "other": {"command": "/x"}}}
            )
        )
        with mock.patch("cli._try_resolve_binary", return_value=None):
            fixed, removed = _repair_configs(tmp_path, remove_if_unresolvable=True)
        assert removed == 1 and fixed == 0
        rewritten = json.loads(cfg_path.read_text())
        # openwebgoggles entry is gone; other servers remain untouched.
        assert "openwebgoggles" not in rewritten["mcpServers"]
        assert "other" in rewritten["mcpServers"]

    def test_keeps_entry_when_binary_unresolvable_without_remove_flag(self, tmp_path, isolated_home):
        cfg_path = tmp_path / ".mcp.json"
        cfg_path.write_text(
            json.dumps({"mcpServers": {"openwebgoggles": {"command": "/gone"}}})
        )
        with mock.patch("cli._try_resolve_binary", return_value=None):
            fixed, removed = _repair_configs(tmp_path, remove_if_unresolvable=False)
        assert fixed == 0 and removed == 0
        # Entry preserved — user gets to decide whether to nuke it.
        assert "openwebgoggles" in json.loads(cfg_path.read_text())["mcpServers"]


# ---------------------------------------------------------------------------
# End-to-end: doctor --fix repairs the bug-report scenario
# ---------------------------------------------------------------------------


class TestDoctorFixEndToEnd:
    """The exact scenario from the bug report:

      - Claude Desktop config points at /usr/bin/openwebgoggles
      - That path doesn't exist anymore
      - User runs `openwebgoggles doctor --fix`
      - Config is rewritten to point at the live binary
      - No more ENOENT spam on next Claude Desktop launch
    """

    def test_repairs_stale_claude_desktop_entry(self, tmp_path, isolated_home, fake_binary, capsys):
        from cli import _cmd_doctor

        # Reproduce the user's situation: claude_desktop_config.json with a stale path
        claude_dir = isolated_home / ".config" / "Claude"
        claude_dir.mkdir(parents=True)
        cfg_path = claude_dir / "claude_desktop_config.json"
        cfg_path.write_text(
            json.dumps({"mcpServers": {"openwebgoggles": {"command": "/usr/bin/openwebgoggles"}}})
        )

        with mock.patch("sys.argv", ["openwebgoggles", "doctor", str(tmp_path), "--fix"]):
            with mock.patch("cli._try_resolve_binary", return_value=fake_binary):
                _cmd_doctor()

        rewritten = json.loads(cfg_path.read_text())
        assert rewritten["mcpServers"]["openwebgoggles"]["command"] == fake_binary
        assert "Fixed 1 stale entry" in capsys.readouterr().out
