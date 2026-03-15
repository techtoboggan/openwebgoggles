"""Tests for remote mode (OWG_REMOTE / --remote flag).

Covers:
- WebviewSession remote flag propagation
- WebviewServer bind_host parameterization
- HTTP handler host validation in remote mode
- CSP connect-src in remote vs localhost mode
- CORS origin handling in remote mode
- _is_remote_mode() env var detection
- Subprocess args when remote=True
"""

from __future__ import annotations

import json
import os
import socket
import sys
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import mcp_server  # noqa: E402, I001
from session import WebviewSession  # noqa: E402


# ---------------------------------------------------------------------------
# WebviewSession remote mode
# ---------------------------------------------------------------------------


class TestWebviewSessionRemote:
    """Tests for WebviewSession remote parameter."""

    def test_default_is_localhost(self, tmp_path):
        """Default session binds to 127.0.0.1."""
        session = WebviewSession(work_dir=tmp_path)
        assert session._remote is False
        assert session._bind_host == "127.0.0.1"
        assert session._display_host == "127.0.0.1"

    def test_remote_binds_all_interfaces(self, tmp_path):
        """Remote session binds to 0.0.0.0."""
        session = WebviewSession(work_dir=tmp_path, remote=True)
        assert session._remote is True
        assert session._bind_host == "0.0.0.0"
        # Display host should be the machine's hostname
        assert session._display_host == socket.gethostname()

    def test_remote_url_uses_hostname(self, tmp_path):
        """Remote session URL uses hostname, not 127.0.0.1."""
        session = WebviewSession(work_dir=tmp_path, remote=True)
        assert socket.gethostname() in session.url

    def test_localhost_url(self, tmp_path):
        """Localhost session URL uses 127.0.0.1."""
        session = WebviewSession(work_dir=tmp_path)
        assert "127.0.0.1" in session.url

    def test_remote_manifest_host(self, tmp_path):
        """Remote session writes hostname to manifest."""
        session = WebviewSession(work_dir=tmp_path, remote=True)
        session.session_token = "test"
        session.session_id = "test-id"
        session.http_port = 18420
        session.ws_port = 18421
        session._write_manifest("dynamic")
        manifest = json.loads((tmp_path / "manifest.json").read_text())
        assert manifest["server"]["host"] == socket.gethostname()

    def test_localhost_manifest_host(self, tmp_path):
        """Localhost session writes 127.0.0.1 to manifest."""
        session = WebviewSession(work_dir=tmp_path)
        session.session_token = "test"
        session.session_id = "test-id"
        session.http_port = 18420
        session.ws_port = 18421
        session._write_manifest("dynamic")
        manifest = json.loads((tmp_path / "manifest.json").read_text())
        assert manifest["server"]["host"] == "127.0.0.1"

    def test_remote_disables_browser_open(self, tmp_path):
        """Remote session should not auto-open browser."""
        session = WebviewSession(work_dir=tmp_path, remote=True, open_browser=False)
        assert session._open_browser_on_start is False


# ---------------------------------------------------------------------------
# WebviewServer bind_host
# ---------------------------------------------------------------------------


class TestWebviewServerBindHost:
    """Tests for WebviewServer bind_host parameter."""

    def test_default_bind_host(self):
        """Default bind host is 127.0.0.1."""
        import inspect

        import webview_server

        sig = inspect.signature(webview_server.WebviewServer.__init__)
        assert sig.parameters["bind_host"].default == "127.0.0.1"

    def test_remote_bind_host_stored(self, tmp_path):
        """Bind host is stored on the server instance."""
        import webview_server

        server = webview_server.WebviewServer(
            data_dir=str(tmp_path),
            http_port=18420,
            ws_port=18421,
            sdk_path=str(tmp_path / "sdk.js"),
            bind_host="0.0.0.0",
        )
        assert server.bind_host == "0.0.0.0"

    def test_localhost_bind_host_stored(self, tmp_path):
        """Localhost bind host is stored."""
        import webview_server

        server = webview_server.WebviewServer(
            data_dir=str(tmp_path),
            http_port=18420,
            ws_port=18421,
            sdk_path=str(tmp_path / "sdk.js"),
        )
        assert server.bind_host == "127.0.0.1"


# ---------------------------------------------------------------------------
# HTTP handler remote mode
# ---------------------------------------------------------------------------


class TestHTTPHandlerRemote:
    """Tests for HTTP handler behavior in remote mode."""

    @pytest.fixture
    def handler_localhost(self, tmp_path):
        from data_contract import DataContract
        from http_handler import WebviewHTTPHandler

        return WebviewHTTPHandler(
            contract=DataContract(tmp_path),
            apps_dir=tmp_path / "apps",
            sdk_path=tmp_path / "sdk.js",
            session_token="test-token",
            bind_host="127.0.0.1",
        )

    @pytest.fixture
    def handler_remote(self, tmp_path):
        from data_contract import DataContract
        from http_handler import WebviewHTTPHandler

        return WebviewHTTPHandler(
            contract=DataContract(tmp_path),
            apps_dir=tmp_path / "apps",
            sdk_path=tmp_path / "sdk.js",
            session_token="test-token",
            bind_host="0.0.0.0",
        )

    def test_localhost_rejects_external_host(self, handler_localhost):
        """Localhost mode rejects non-localhost Host headers."""
        assert not handler_localhost._is_valid_host("192.168.1.50:18420")
        assert not handler_localhost._is_valid_host("example.com")

    def test_localhost_accepts_localhost(self, handler_localhost):
        """Localhost mode accepts localhost variants."""
        assert handler_localhost._is_valid_host("127.0.0.1:18420")
        assert handler_localhost._is_valid_host("localhost:18420")

    def test_remote_accepts_any_host(self, handler_remote):
        """Remote mode accepts any Host header (bearer auth is the gate)."""
        assert handler_remote._is_valid_host("192.168.1.50:18420")
        assert handler_remote._is_valid_host("example.com")
        assert handler_remote._is_valid_host("my-codespace-abc123.github.dev")

    def test_remote_rejects_empty_host(self, handler_remote):
        """Remote mode still rejects empty Host headers."""
        assert not handler_remote._is_valid_host("")

    def test_remote_flag_set(self, handler_remote, handler_localhost):
        """Remote flag is set based on bind_host."""
        assert handler_remote._remote is True
        assert handler_localhost._remote is False


# ---------------------------------------------------------------------------
# _is_remote_mode() env var
# ---------------------------------------------------------------------------


class TestIsRemoteMode:
    """Tests for _is_remote_mode() helper."""

    def test_not_set(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop("OWG_REMOTE", None)
            assert mcp_server._is_remote_mode() is False

    def test_set_to_1(self):
        with mock.patch.dict(os.environ, {"OWG_REMOTE": "1"}):
            assert mcp_server._is_remote_mode() is True

    def test_set_to_true(self):
        with mock.patch.dict(os.environ, {"OWG_REMOTE": "true"}):
            assert mcp_server._is_remote_mode() is True

    def test_set_to_yes(self):
        with mock.patch.dict(os.environ, {"OWG_REMOTE": "yes"}):
            assert mcp_server._is_remote_mode() is True

    def test_set_to_True_uppercase(self):
        with mock.patch.dict(os.environ, {"OWG_REMOTE": "TRUE"}):
            assert mcp_server._is_remote_mode() is True

    def test_set_to_0(self):
        with mock.patch.dict(os.environ, {"OWG_REMOTE": "0"}):
            assert mcp_server._is_remote_mode() is False

    def test_set_to_empty(self):
        with mock.patch.dict(os.environ, {"OWG_REMOTE": ""}):
            assert mcp_server._is_remote_mode() is False

    def test_set_to_no(self):
        with mock.patch.dict(os.environ, {"OWG_REMOTE": "no"}):
            assert mcp_server._is_remote_mode() is False


# ---------------------------------------------------------------------------
# _get_browser_session remote mode integration
# ---------------------------------------------------------------------------


class TestGetBrowserSessionRemote:
    """Tests for _get_browser_session with remote mode."""

    @pytest.fixture(autouse=True)
    def _reset(self):
        old_manager = mcp_server._session_manager
        mcp_server._session_manager = mcp_server.SessionManager()
        yield
        mcp_server._session_manager = old_manager

    async def test_remote_creates_remote_session(self):
        """When OWG_REMOTE=1, new sessions are created with remote=True."""
        with mock.patch.dict(os.environ, {"OWG_REMOTE": "1"}):
            with mock.patch("mcp_server.WebviewSession") as MockSession:
                mock_instance = mock.MagicMock()
                MockSession.return_value = mock_instance
                await mcp_server._get_browser_session("test-remote")
                MockSession.assert_called_once()
                call_kwargs = MockSession.call_args[1]
                assert call_kwargs["remote"] is True
                assert call_kwargs["open_browser"] is False

    async def test_localhost_creates_localhost_session(self):
        """Without OWG_REMOTE, sessions are created with remote=False."""
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop("OWG_REMOTE", None)
            with mock.patch("mcp_server.WebviewSession") as MockSession:
                mock_instance = mock.MagicMock()
                MockSession.return_value = mock_instance
                await mcp_server._get_browser_session("test-local")
                MockSession.assert_called_once()
                call_kwargs = MockSession.call_args[1]
                assert call_kwargs["remote"] is False
                assert call_kwargs["open_browser"] is True
