"""Tests for delta streaming / append mode.

Covers:
- WebviewSession.append_state() — list append + patch op generation
- AppModeState.append_state() — in-memory list append + patch ops
- openwebgoggles_update(append=True) — browser + app mode paths
- _broadcast_patch() — HTTP POST to webview server
- SDK _applyPatch() logic (tested indirectly via patch op structure)
- HTTP /_api/patch endpoint
"""

from __future__ import annotations

import json
import os
import sys
import threading
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import mcp_server  # noqa: E402, I001
from mcp_server import AppModeState, SessionSlot, WebviewSession  # noqa: E402
from session import MergeError  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_session(**kwargs):
    session = mock.MagicMock(spec=WebviewSession)
    session._started = kwargs.get("started", True)
    session._state_version = kwargs.get("state_version", 1)
    session.session_id = kwargs.get("session_id", "test-session-id")
    session.http_port = kwargs.get("http_port", 18420)
    session.session_token = kwargs.get("session_token", "test-token")
    session.url = f"http://127.0.0.1:{session.http_port}"
    session.is_alive = mock.MagicMock(return_value=kwargs.get("alive", True))
    session.ensure_started = mock.AsyncMock()
    session.write_state = mock.MagicMock()
    session.read_state = mock.MagicMock(return_value={})
    session.merge_state = mock.MagicMock(return_value={"version": 1})
    session.append_state = mock.MagicMock(
        return_value=(
            {"version": 2, "data": {"lines": [1, 2, 3]}},
            [{"op": "append", "path": "data.lines", "value": [3]}],
        )
    )
    session.read_actions = mock.MagicMock(return_value={"version": 0, "actions": []})
    session.clear_actions = mock.MagicMock()
    session.wait_for_action = mock.AsyncMock(return_value=None)
    session.close = mock.AsyncMock()
    return session


def _inject_slot(mock_session, name="default"):
    slot = SessionSlot(name)
    slot.browser_session = mock_session
    slot.mode = "browser"
    mcp_server._session_manager._slots[name] = slot
    return slot


@pytest.fixture(autouse=True)
def _reset_session_manager():
    old_manager = mcp_server._session_manager
    mcp_server._session_manager = mcp_server.SessionManager()
    yield
    mcp_server._session_manager = old_manager


# ---------------------------------------------------------------------------
# WebviewSession.append_state
# ---------------------------------------------------------------------------


class TestWebviewSessionAppend:
    """Tests for WebviewSession.append_state()."""

    def test_append_lists(self, tmp_path):
        """List values in partial are appended, not replaced."""
        session = WebviewSession.__new__(WebviewSession)
        session.data_dir = tmp_path
        session._state_version = 0
        session._state_lock = threading.Lock()
        # Write initial state with a list
        state_file = tmp_path / "state.json"
        initial = {"title": "Test", "data": {"lines": ["line1", "line2"]}, "version": 0}
        state_file.write_text(json.dumps(initial))

        full, ops = session.append_state({"data": {"lines": ["line3", "line4"]}})

        assert full["data"]["lines"] == ["line1", "line2", "line3", "line4"]
        assert len(ops) == 1
        assert ops[0]["op"] == "append"
        assert ops[0]["path"] == "data.lines"
        assert ops[0]["value"] == ["line3", "line4"]

    def test_set_scalar_values(self, tmp_path):
        """Non-list values generate set ops."""
        session = WebviewSession.__new__(WebviewSession)
        session.data_dir = tmp_path
        session._state_version = 0
        session._state_lock = threading.Lock()
        state_file = tmp_path / "state.json"
        initial = {"title": "Old", "counter": 1, "version": 0}
        state_file.write_text(json.dumps(initial))

        full, ops = session.append_state({"title": "New", "counter": 5})

        assert full["title"] == "New"
        assert full["counter"] == 5
        assert len(ops) == 2
        set_ops = {op["path"]: op for op in ops}
        assert set_ops["title"]["op"] == "set"
        assert set_ops["counter"]["op"] == "set"

    def test_mixed_append_and_set(self, tmp_path):
        """Mixed list append + scalar set in same update."""
        session = WebviewSession.__new__(WebviewSession)
        session.data_dir = tmp_path
        session._state_version = 0
        session._state_lock = threading.Lock()
        state_file = tmp_path / "state.json"
        initial = {"title": "Log", "data": {"sections": [{"type": "log", "lines": ["a"]}]}, "version": 0}
        state_file.write_text(json.dumps(initial))

        full, ops = session.append_state(
            {
                "title": "Updated Log",
                "data": {"sections": [{"type": "log", "lines": ["b", "c"]}]},
            }
        )

        # title is set, sections[0] is replaced (list items are non-dict so no recursion)
        assert full["title"] == "Updated Log"
        # sections is a list replaced (not appended — only lists at matching paths append)
        # Actually the top-level "sections" is list+list so it appends
        assert len(full["data"]["sections"]) == 2  # appended

    def test_nested_dict_recursion(self, tmp_path):
        """Nested dicts are recursed into to find lists."""
        session = WebviewSession.__new__(WebviewSession)
        session.data_dir = tmp_path
        session._state_version = 0
        session._state_lock = threading.Lock()
        state_file = tmp_path / "state.json"
        initial = {"data": {"metrics": {"values": [1, 2]}, "label": "x"}, "version": 0}
        state_file.write_text(json.dumps(initial))

        full, ops = session.append_state({"data": {"metrics": {"values": [3]}, "label": "y"}})

        assert full["data"]["metrics"]["values"] == [1, 2, 3]
        assert full["data"]["label"] == "y"
        ops_by_path = {op["path"]: op for op in ops}
        assert ops_by_path["data.metrics.values"]["op"] == "append"
        assert ops_by_path["data.label"]["op"] == "set"

    def test_version_incremented(self, tmp_path):
        """State version is incremented after append."""
        session = WebviewSession.__new__(WebviewSession)
        session.data_dir = tmp_path
        session._state_version = 5
        session._state_lock = threading.Lock()
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"items": [1], "version": 5}))

        full, ops = session.append_state({"items": [2]})

        assert full["version"] == 6
        assert session._state_version == 6

    def test_dangerous_keys_rejected(self, tmp_path):
        """Prototype pollution keys are rejected."""
        session = WebviewSession.__new__(WebviewSession)
        session.data_dir = tmp_path
        session._state_version = 0
        session._state_lock = threading.Lock()
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"version": 0}))

        with pytest.raises(MergeError, match="dangerous key"):
            session.append_state({"__proto__": {"pwned": True}})

    def test_validator_called(self, tmp_path):
        """Validator is called before writing state."""
        session = WebviewSession.__new__(WebviewSession)
        session.data_dir = tmp_path
        session._state_version = 0
        session._state_lock = threading.Lock()
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"items": [], "version": 0}))

        def bad_validator(state):
            raise ValueError("bad state")

        with pytest.raises(ValueError, match="bad state"):
            session.append_state({"items": [1]}, validator=bad_validator)

    def test_empty_list_append_no_op(self, tmp_path):
        """Appending empty list produces an append op with empty value."""
        session = WebviewSession.__new__(WebviewSession)
        session.data_dir = tmp_path
        session._state_version = 0
        session._state_lock = threading.Lock()
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"items": [1, 2], "version": 0}))

        full, ops = session.append_state({"items": []})

        assert full["items"] == [1, 2]  # unchanged
        assert len(ops) == 1
        assert ops[0]["op"] == "append"
        assert ops[0]["value"] == []

    def test_new_key_creates_set_op(self, tmp_path):
        """Keys not in existing state create set ops."""
        session = WebviewSession.__new__(WebviewSession)
        session.data_dir = tmp_path
        session._state_version = 0
        session._state_lock = threading.Lock()
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"version": 0}))

        full, ops = session.append_state({"new_key": "new_value"})

        assert full["new_key"] == "new_value"
        assert ops[0]["op"] == "set"
        assert ops[0]["path"] == "new_key"


# ---------------------------------------------------------------------------
# AppModeState.append_state
# ---------------------------------------------------------------------------


class TestAppModeStateAppend:
    """Tests for AppModeState.append_state()."""

    def test_append_lists(self):
        """List values in partial are appended."""
        ams = AppModeState()
        ams.write_state({"title": "Test", "data": {"lines": ["a", "b"]}})

        full, ops = ams.append_state({"data": {"lines": ["c"]}})

        assert full["data"]["lines"] == ["a", "b", "c"]
        assert len(ops) == 1
        assert ops[0]["op"] == "append"
        assert ops[0]["path"] == "data.lines"

    def test_set_scalars(self):
        """Non-list values create set ops."""
        ams = AppModeState()
        ams.write_state({"title": "Old", "count": 0})

        full, ops = ams.append_state({"title": "New"})

        assert full["title"] == "New"
        assert ops[0]["op"] == "set"

    def test_version_incremented(self):
        """Version is incremented on append."""
        ams = AppModeState()
        ams.write_state({"items": [1]})
        v1 = ams.state_version

        full, ops = ams.append_state({"items": [2]})

        assert full["version"] == v1 + 1
        assert ams.state_version == v1 + 1

    def test_dangerous_keys_rejected(self):
        """Prototype pollution keys raise ValueError."""
        ams = AppModeState()
        ams.write_state({"data": {}})

        with pytest.raises(ValueError, match="dangerous key"):
            ams.append_state({"constructor": "evil"})

    def test_validator_called(self):
        """Validator runs before committing state."""
        ams = AppModeState()
        ams.write_state({"items": []})

        def bad_validator(state):
            raise ValueError("nope")

        with pytest.raises(ValueError, match="nope"):
            ams.append_state({"items": [1]}, validator=bad_validator)


# ---------------------------------------------------------------------------
# openwebgoggles_update(append=True) — browser mode
# ---------------------------------------------------------------------------


class TestUpdateAppendBrowser:
    """Tests for openwebgoggles_update with append=True in browser mode."""

    async def test_append_calls_session_append_state(self):
        """append=True calls ws.append_state and returns version + patch_ops count."""
        mock_session = _make_mock_session()
        with mock.patch("mcp_server._get_browser_session", new_callable=mock.AsyncMock, return_value=mock_session):
            with mock.patch("mcp_server._broadcast_patch", new_callable=mock.AsyncMock) as mock_bcast:
                result = await mcp_server.openwebgoggles_update(
                    state={"data": {"lines": ["new"]}},
                    append=True,
                )
        assert result["updated"] is True
        assert result["version"] == 2
        assert result["patch_ops"] == 1
        mock_session.append_state.assert_called_once()
        mock_bcast.assert_called_once()

    async def test_append_error_returns_error(self):
        """ValueError from append_state is caught and returned."""
        mock_session = _make_mock_session()
        mock_session.append_state.side_effect = ValueError("bad merge")
        with mock.patch("mcp_server._get_browser_session", new_callable=mock.AsyncMock, return_value=mock_session):
            result = await mcp_server.openwebgoggles_update(
                state={"__proto__": {}},
                append=True,
            )
        assert "error" in result

    async def test_append_broadcasts_patch(self):
        """append=True sends patch ops via _broadcast_patch."""
        mock_session = _make_mock_session()
        expected_ops = [{"op": "append", "path": "data.lines", "value": [3]}]
        mock_session.append_state.return_value = ({"version": 5}, expected_ops)
        with mock.patch("mcp_server._get_browser_session", new_callable=mock.AsyncMock, return_value=mock_session):
            with mock.patch("mcp_server._broadcast_patch", new_callable=mock.AsyncMock) as mock_bcast:
                await mcp_server.openwebgoggles_update(
                    state={"data": {"lines": [3]}},
                    append=True,
                )
        mock_bcast.assert_called_once_with(mock_session, 5, expected_ops)

    async def test_append_takes_priority_over_merge(self):
        """When both append=True and merge=True, append wins."""
        mock_session = _make_mock_session()
        with mock.patch("mcp_server._get_browser_session", new_callable=mock.AsyncMock, return_value=mock_session):
            with mock.patch("mcp_server._broadcast_patch", new_callable=mock.AsyncMock):
                result = await mcp_server.openwebgoggles_update(
                    state={"data": {"lines": ["x"]}},
                    append=True,
                    merge=True,
                )
        # append should be called, not merge
        mock_session.append_state.assert_called_once()
        mock_session.merge_state.assert_not_called()
        assert result["updated"] is True


# ---------------------------------------------------------------------------
# openwebgoggles_update(append=True) — app mode
# ---------------------------------------------------------------------------


class TestUpdateAppendApp:
    """Tests for openwebgoggles_update with append=True in MCP Apps mode."""

    async def test_app_mode_append(self):
        """append=True in app mode uses AppModeState.append_state."""
        with mock.patch("mcp_server._resolve_mode", return_value="app"):
            with mock.patch("mcp_server._get_app_state") as mock_get:
                mock_app = mock.MagicMock()
                mock_app.state_version = 10
                mock_app.append_state.return_value = ({"title": "Log", "version": 10}, [])
                mock_get.return_value = mock_app
                result = await mcp_server.openwebgoggles_update(
                    state={"data": {"lines": ["new"]}},
                    append=True,
                )
        mock_app.append_state.assert_called_once()
        # In app mode, returns CallToolResult
        assert hasattr(result, "structuredContent")

    async def test_app_mode_append_error(self):
        """ValueError from app mode append is returned as error dict."""
        with mock.patch("mcp_server._resolve_mode", return_value="app"):
            with mock.patch("mcp_server._get_app_state") as mock_get:
                mock_app = mock.MagicMock()
                mock_app.append_state.side_effect = ValueError("bad")
                mock_get.return_value = mock_app
                result = await mcp_server.openwebgoggles_update(
                    state={"bad": "data"},
                    append=True,
                )
        assert "error" in result


# ---------------------------------------------------------------------------
# _broadcast_patch
# ---------------------------------------------------------------------------


class TestBroadcastPatch:
    """Tests for _broadcast_patch helper."""

    async def test_skips_when_not_started(self):
        """No HTTP call when session not started."""
        ws = mock.MagicMock()
        ws._started = False
        ws.is_alive.return_value = False
        with mock.patch("urllib.request.urlopen") as mock_open:
            await mcp_server._broadcast_patch(ws, 1, [])
        mock_open.assert_not_called()

    async def test_skips_when_not_alive(self):
        """No HTTP call when process not alive."""
        ws = mock.MagicMock()
        ws._started = True
        ws.is_alive.return_value = False
        with mock.patch("urllib.request.urlopen") as mock_open:
            await mcp_server._broadcast_patch(ws, 1, [])
        mock_open.assert_not_called()

    async def test_sends_patch_via_http(self):
        """Sends state_patch JSON to /_api/patch endpoint."""
        ws = mock.MagicMock()
        ws._started = True
        ws.is_alive.return_value = True
        ws.http_port = 18420
        ws.session_token = "test-token"
        ops = [{"op": "append", "path": "lines", "value": ["x"]}]
        with mock.patch("urllib.request.urlopen") as mock_open:
            await mcp_server._broadcast_patch(ws, 5, ops)
        mock_open.assert_called_once()
        call_args = mock_open.call_args
        req = call_args[0][0]
        assert "/_api/patch" in req.full_url
        body = json.loads(req.data)
        assert body["type"] == "state_patch"
        assert body["version"] == 5
        assert body["ops"] == ops

    async def test_catches_errors_gracefully(self):
        """Network errors are caught and logged, not raised."""
        ws = mock.MagicMock()
        ws._started = True
        ws.is_alive.return_value = True
        ws.http_port = 18420
        ws.session_token = "test-token"
        with mock.patch("urllib.request.urlopen", side_effect=Exception("connection refused")):
            # Should not raise
            await mcp_server._broadcast_patch(ws, 1, [])


# ---------------------------------------------------------------------------
# Patch op structure validation
# ---------------------------------------------------------------------------


class TestPatchOpStructure:
    """Verify patch ops have the correct structure for SDK consumption."""

    def test_append_op_structure(self, tmp_path):
        """Append op has correct fields."""
        session = WebviewSession.__new__(WebviewSession)
        session.data_dir = tmp_path
        session._state_version = 0
        session._state_lock = threading.Lock()
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"items": [1], "version": 0}))

        _, ops = session.append_state({"items": [2, 3]})

        assert len(ops) == 1
        op = ops[0]
        assert op["op"] == "append"
        assert op["path"] == "items"
        assert op["value"] == [2, 3]
        # All ops must be JSON-serializable
        json.dumps(ops)

    def test_set_op_structure(self, tmp_path):
        """Set op has correct fields."""
        session = WebviewSession.__new__(WebviewSession)
        session.data_dir = tmp_path
        session._state_version = 0
        session._state_lock = threading.Lock()
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"title": "x", "version": 0}))

        _, ops = session.append_state({"title": "y"})

        assert len(ops) == 1
        op = ops[0]
        assert op["op"] == "set"
        assert op["path"] == "title"
        assert op["value"] == "y"

    def test_deeply_nested_path(self, tmp_path):
        """Ops for deeply nested values use dot-separated paths."""
        session = WebviewSession.__new__(WebviewSession)
        session.data_dir = tmp_path
        session._state_version = 0
        session._state_lock = threading.Lock()
        state_file = tmp_path / "state.json"
        state_file.write_text(
            json.dumps(
                {
                    "data": {"sections": [{"lines": ["a"]}]},
                    "version": 0,
                }
            )
        )

        _, ops = session.append_state({"data": {"sections": [{"lines": ["b"]}]}})

        # sections is list+list → appended
        # Find the append op for sections
        paths = {op["path"]: op for op in ops}
        assert "data.sections" in paths
        assert paths["data.sections"]["op"] == "append"


# ---------------------------------------------------------------------------
# HTTP handler /_api/patch endpoint
# ---------------------------------------------------------------------------


class TestHTTPPatchEndpoint:
    """Tests for the /_api/patch endpoint in http_handler.py."""

    @pytest.fixture
    def handler(self, tmp_path):
        """Create a handler with mocked contract."""
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from http_handler import WebviewHTTPHandler
        from data_contract import DataContract

        contract = DataContract(tmp_path)
        h = WebviewHTTPHandler(
            contract=contract,
            apps_dir=tmp_path / "apps",
            sdk_path=tmp_path / "sdk.js",
            session_token="test-token",
        )
        h._broadcast_fn = mock.AsyncMock()
        return h

    async def test_patch_broadcasts_ops(self, handler):
        """Valid patch message is broadcast to WS clients."""
        writer = mock.MagicMock()
        writer.write = mock.MagicMock()
        writer.drain = mock.AsyncMock()
        writer.close = mock.MagicMock()
        writer.wait_closed = mock.AsyncMock()

        patch = {
            "type": "state_patch",
            "version": 5,
            "ops": [{"op": "append", "path": "lines", "value": ["x"]}],
        }
        body = json.dumps(patch).encode()

        await handler._handle_api("POST", "/_api/patch", {}, body, writer)

        handler._broadcast_fn.assert_called_once_with(patch, exclude=None)

    async def test_patch_rejects_non_post(self, handler):
        """Only POST is allowed."""
        writer = mock.MagicMock()
        writer.write = mock.MagicMock()
        writer.drain = mock.AsyncMock()
        writer.close = mock.MagicMock()
        writer.wait_closed = mock.AsyncMock()

        await handler._handle_api("GET", "/_api/patch", {}, b"", writer)

        handler._broadcast_fn.assert_not_called()

    async def test_patch_rejects_invalid_json(self, handler):
        """Invalid JSON body is rejected."""
        writer = mock.MagicMock()
        writer.write = mock.MagicMock()
        writer.drain = mock.AsyncMock()
        writer.close = mock.MagicMock()
        writer.wait_closed = mock.AsyncMock()

        await handler._handle_api("POST", "/_api/patch", {}, b"not json", writer)

        handler._broadcast_fn.assert_not_called()

    async def test_patch_rejects_wrong_type(self, handler):
        """Patch with wrong type field is rejected."""
        writer = mock.MagicMock()
        writer.write = mock.MagicMock()
        writer.drain = mock.AsyncMock()
        writer.close = mock.MagicMock()
        writer.wait_closed = mock.AsyncMock()

        patch = {"type": "not_a_patch", "ops": []}
        await handler._handle_api("POST", "/_api/patch", {}, json.dumps(patch).encode(), writer)

        handler._broadcast_fn.assert_not_called()

    async def test_patch_rejects_non_list_ops(self, handler):
        """ops must be a list."""
        writer = mock.MagicMock()
        writer.write = mock.MagicMock()
        writer.drain = mock.AsyncMock()
        writer.close = mock.MagicMock()
        writer.wait_closed = mock.AsyncMock()

        patch = {"type": "state_patch", "ops": "not-a-list"}
        await handler._handle_api("POST", "/_api/patch", {}, json.dumps(patch).encode(), writer)

        handler._broadcast_fn.assert_not_called()
