"""
Cross-client compatibility matrix tests for OpenWebGoggles.

Tests that mode detection (_check_host_supports_ui / _resolve_mode) produces
the expected result (app vs browser) for every known MCP client, based on the
capabilities each client advertises in the initialize handshake.

Client matrix (as of v0.15.0):
  ┌─────────────────────┬──────────────────────────┬───────────┐
  │ Client              │ Detection signal          │ Mode      │
  ├─────────────────────┼──────────────────────────┼───────────┤
  │ Claude Code (agent) │ clientInfo.name           │ app       │
  │                     │   "local-agent-mode-*"    │           │
  │ Claude Desktop      │ caps.extensions           │ app       │
  │                     │   "io.modelcontextprotocol│           │
  │                     │   /ui"                    │           │
  │ Claude Desktop      │ caps.experimental         │ app       │
  │   (experimental)    │   "io.modelcontextprotocol│           │
  │                     │   /ui"                    │           │
  │ OpenCode            │ (none — no UI ext)        │ browser   │
  │ Cursor              │ (none — no UI ext)        │ browser   │
  │ Zed                 │ (none — no UI ext)        │ browser   │
  │ Cline (VS Code)     │ (none — no UI ext)        │ browser   │
  │ Continue (VS Code)  │ (none — no UI ext)        │ browser   │
  │ Unknown client      │ (none — no UI ext)        │ browser   │
  │ Fallback (no ctx)   │ _host_fetched_ui_resource │ browser   │
  │ Fallback (flag set) │ _host_fetched_ui_resource │ app       │
  └─────────────────────┴──────────────────────────┴───────────┘
"""

from __future__ import annotations

import os
import sys
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import mcp_server
from mcp_server import _check_host_supports_ui, _resolve_mode


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_UI_EXT = "io.modelcontextprotocol/ui"


def _make_ctx(
    client_name: str | None = None,
    extensions: dict | None = None,
    experimental: dict | None = None,
    caps_raises: bool = False,
) -> mock.MagicMock:
    """Build a mock Context with the given client capabilities."""
    ctx = mock.MagicMock()

    if caps_raises:
        type(ctx.session.client_params).capabilities = mock.PropertyMock(side_effect=AttributeError("no caps"))
        return ctx

    caps = mock.MagicMock()
    caps.experimental = experimental

    if extensions is not None:
        caps.extensions = extensions
    else:
        # Make attribute access raise AttributeError (no extensions field)
        del caps.extensions

    client_info = mock.MagicMock()
    client_info.name = client_name or ""
    ctx.session.client_params.clientInfo = client_info
    ctx.session.client_params.capabilities = caps
    return ctx


@pytest.fixture(autouse=True)
def _reset():
    """Reset global state before each test."""
    old_host = mcp_server._host_fetched_ui_resource
    old_cached = mcp_server._cached_mode

    mcp_server._host_fetched_ui_resource = False
    mcp_server._cached_mode = None

    yield

    mcp_server._host_fetched_ui_resource = old_host
    mcp_server._cached_mode = old_cached


# ---------------------------------------------------------------------------
# Claude Code (agent bridge)
# ---------------------------------------------------------------------------


class TestClaudeCodeAgent:
    """Claude Code uses clientInfo.name = 'local-agent-mode-*' (strategy 3)."""

    def test_detects_app_mode(self):
        ctx = _make_ctx(client_name="local-agent-mode-abc123")
        assert _check_host_supports_ui(ctx) is True

    def test_resolves_app(self):
        ctx = _make_ctx(client_name="local-agent-mode-xyz")
        assert _resolve_mode(ctx) == "app"

    def test_different_suffix_still_matches(self):
        """Prefix match — any suffix after 'local-agent-mode-' qualifies."""
        for name in ("local-agent-mode-1", "local-agent-mode-session-42", "local-agent-mode-"):
            mcp_server._cached_mode = None
            ctx = _make_ctx(client_name=name)
            assert _check_host_supports_ui(ctx) is True, f"Expected app mode for {name!r}"

    def test_prefix_mismatch_does_not_match(self):
        """Other clientInfo names don't trigger app mode."""
        for name in ("local-agent", "agent-mode-x", "", "Claude Code", "cursor"):
            mcp_server._cached_mode = None
            ctx = _make_ctx(client_name=name)
            # These names alone don't match — result depends on other caps
            result = _check_host_supports_ui(ctx)
            assert result is False, f"Expected browser mode for {name!r}"


# ---------------------------------------------------------------------------
# Claude Desktop (direct extensions field)
# ---------------------------------------------------------------------------


class TestClaudeDesktopExtensions:
    """Claude Desktop advertises ui extension via caps.extensions dict."""

    def test_detects_app_mode(self):
        ctx = _make_ctx(extensions={_UI_EXT: {}})
        assert _check_host_supports_ui(ctx) is True

    def test_resolves_app(self):
        ctx = _make_ctx(extensions={_UI_EXT: {}})
        assert _resolve_mode(ctx) == "app"

    def test_extra_extensions_also_match(self):
        ctx = _make_ctx(extensions={_UI_EXT: {"version": "1"}, "other.ext": True})
        assert _check_host_supports_ui(ctx) is True

    def test_wrong_extension_key_is_browser(self):
        ctx = _make_ctx(extensions={"io.modelcontextprotocol/other": {}})
        assert _check_host_supports_ui(ctx) is False

    def test_empty_extensions_is_browser(self):
        ctx = _make_ctx(extensions={})
        assert _check_host_supports_ui(ctx) is False


# ---------------------------------------------------------------------------
# Claude Desktop (experimental capabilities field)
# ---------------------------------------------------------------------------


class TestClaudeDesktopExperimental:
    """Some Claude Desktop versions use caps.experimental instead."""

    def test_detects_app_mode(self):
        ctx = _make_ctx(experimental={_UI_EXT: {}})
        assert _check_host_supports_ui(ctx) is True

    def test_resolves_app(self):
        ctx = _make_ctx(experimental={_UI_EXT: {}})
        assert _resolve_mode(ctx) == "app"

    def test_none_experimental_is_browser(self):
        ctx = _make_ctx(experimental=None)
        assert _check_host_supports_ui(ctx) is False

    def test_wrong_experimental_key_is_browser(self):
        ctx = _make_ctx(experimental={"some.other.capability": {}})
        assert _check_host_supports_ui(ctx) is False


# ---------------------------------------------------------------------------
# Browser-fallback clients (no UI extension)
# ---------------------------------------------------------------------------


class TestBrowserFallbackClients:
    """All these clients lack the ui extension — must use browser mode."""

    _CLIENTS = [
        ("OpenCode", "OpenCode"),
        ("Cursor", "Cursor"),
        ("Zed", "Zed"),
        ("Cline", "cline"),
        ("Continue", "continue"),
        ("Sourcegraph Cody", "Cody"),
        ("Unknown", "unknown-client"),
        ("Empty name", ""),
    ]

    @pytest.mark.parametrize("label,client_name", _CLIENTS)
    def test_is_browser_mode(self, label, client_name):
        ctx = _make_ctx(client_name=client_name)
        result = _check_host_supports_ui(ctx)
        assert result is False, f"{label}: expected browser mode, got app mode"

    @pytest.mark.parametrize("label,client_name", _CLIENTS)
    def test_resolve_mode_is_browser(self, label, client_name):
        ctx = _make_ctx(client_name=client_name)
        result = _resolve_mode(ctx)
        assert result == "browser", f"{label}: expected browser, got {result!r}"


# ---------------------------------------------------------------------------
# Fallback: no ctx (resource-fetch flag)
# ---------------------------------------------------------------------------


class TestFallbackNoCtx:
    """When ctx is None, mode falls back to _host_fetched_ui_resource."""

    def test_no_ctx_no_flag_is_browser(self):
        assert _check_host_supports_ui(None) is False

    def test_no_ctx_flag_set_is_app(self):
        mcp_server._host_fetched_ui_resource = True
        assert _check_host_supports_ui(None) is True

    def test_resolve_none_ctx_defaults_browser(self):
        assert _resolve_mode(None) == "browser"

    def test_resolve_none_ctx_flag_set_is_app(self):
        mcp_server._host_fetched_ui_resource = True
        assert _resolve_mode(None) == "app"


# ---------------------------------------------------------------------------
# Error resilience
# ---------------------------------------------------------------------------


class TestErrorResilience:
    """Detection must not crash on malformed or partial capabilities."""

    def test_caps_attribute_error_falls_back_to_flag(self):
        ctx = _make_ctx(caps_raises=True)
        assert _check_host_supports_ui(ctx) is False

    def test_caps_attribute_error_with_flag_is_app(self):
        ctx = _make_ctx(caps_raises=True)
        mcp_server._host_fetched_ui_resource = True
        assert _check_host_supports_ui(ctx) is True

    def test_none_extensions_dict_is_browser(self):
        """extensions=None (not missing, but None) should not match."""
        ctx = _make_ctx(extensions=None)
        # None is falsy; isinstance(None, dict) is False — expect browser
        assert _check_host_supports_ui(ctx) is False

    def test_ctx_session_raises(self):
        """Exceptions from ctx.session are caught gracefully."""
        ctx = mock.MagicMock()
        ctx.session.client_params = mock.PropertyMock(side_effect=RuntimeError("dead"))
        # Should not raise
        result = _check_host_supports_ui(ctx)
        assert result is False

    def test_experimental_is_not_dict(self):
        """If experimental is a non-dict truthy value, it shouldn't match."""
        ctx = _make_ctx(experimental="enabled")  # type: ignore[arg-type]
        # "io.modelcontextprotocol/ui" in "enabled" is False
        assert _check_host_supports_ui(ctx) is False


# ---------------------------------------------------------------------------
# Mode caching
# ---------------------------------------------------------------------------


class TestModeCaching:
    """Once resolved, mode should be cached for the session lifetime."""

    def test_app_mode_cached_after_first_call(self):
        ctx = _make_ctx(extensions={_UI_EXT: {}})
        _resolve_mode(ctx)
        assert mcp_server._cached_mode == "app"

    def test_browser_mode_cached_after_first_call(self):
        ctx = _make_ctx(client_name="opencode")
        _resolve_mode(ctx)
        assert mcp_server._cached_mode == "browser"

    def test_cached_mode_not_re_evaluated(self):
        """Subsequent calls use cached mode even if ctx changes."""
        mcp_server._cached_mode = "app"
        # Provide a ctx that would normally be browser-mode — but cache wins
        ctx = _make_ctx(client_name="opencode")
        assert _resolve_mode(ctx) == "app"

    def test_reset_mode_clears_cache(self):
        from mcp_server import _reset_mode

        mcp_server._cached_mode = "app"
        _reset_mode()
        assert mcp_server._cached_mode is None

    def test_after_reset_re_evaluates(self):
        from mcp_server import _reset_mode

        mcp_server._cached_mode = "browser"
        _reset_mode()
        ctx = _make_ctx(extensions={_UI_EXT: {}})
        assert _resolve_mode(ctx) == "app"
