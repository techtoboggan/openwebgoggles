"""
Tests for the MCP server (scripts/mcp_server.py).

Covers WebviewSession lifecycle, file I/O, port finding, and MCP tool logic.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path

import pytest

# Ensure scripts/ is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mcp_server import WebviewSession


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def work_dir(tmp_path):
    """Temporary working directory for a test session."""
    return tmp_path


@pytest.fixture
def session(work_dir):
    """WebviewSession pointed at a temp directory (browser disabled for tests)."""
    return WebviewSession(work_dir=work_dir, open_browser=False)


def inject_action(data_dir: Path, action_id: str = "approve", action_type: str = "approve", value=True):
    """Write a fake action to actions.json (simulates a user click in the browser)."""
    actions = {
        "version": 1,
        "actions": [
            {
                "id": "test-uuid",
                "action_id": action_id,
                "type": action_type,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "value": value,
            }
        ],
    }
    actions_path = data_dir / "actions.json"
    tmp = actions_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(actions, indent=2))
    tmp.replace(actions_path)


# ---------------------------------------------------------------------------
# WebviewSession — path resolution
# ---------------------------------------------------------------------------


class TestSessionPaths:
    def test_data_dir_under_work_dir(self, session, work_dir):
        assert session.data_dir == work_dir / ".opencode" / "webview"

    def test_default_ports(self, session):
        assert session.http_port == 18420
        assert session.ws_port == 18421

    def test_not_started_initially(self, session):
        assert not session._started
        assert not session.is_alive()


# ---------------------------------------------------------------------------
# Asset discovery
# ---------------------------------------------------------------------------


class TestAssetDiscovery:
    def test_find_assets_dir(self, session):
        assets = session._find_assets_dir()
        assert assets.is_dir()
        assert (assets / "sdk" / "openwebgoggles-sdk.js").is_file()
        assert (assets / "apps" / "dynamic" / "app.js").is_file()


# ---------------------------------------------------------------------------
# App copy
# ---------------------------------------------------------------------------


class TestAppCopy:
    def test_copy_dynamic_app(self, session):
        session.data_dir.mkdir(parents=True, exist_ok=True)
        (session.data_dir / "apps").mkdir(exist_ok=True)

        session._copy_app("dynamic")

        app_dir = session.data_dir / "apps" / "dynamic"
        assert app_dir.is_dir()
        assert (app_dir / "index.html").is_file()
        assert (app_dir / "app.js").is_file()
        assert (app_dir / "openwebgoggles-sdk.js").is_file()

    def test_unknown_app_raises(self, session):
        session.data_dir.mkdir(parents=True, exist_ok=True)
        (session.data_dir / "apps").mkdir(exist_ok=True)

        with pytest.raises(FileNotFoundError, match="not found"):
            session._copy_app("nonexistent-app-xyz")


# ---------------------------------------------------------------------------
# Manifest generation
# ---------------------------------------------------------------------------


class TestManifest:
    def test_manifest_structure(self, session):
        session.data_dir.mkdir(parents=True, exist_ok=True)
        session.session_id = "test-session-id"
        session.http_port = 18420
        session.ws_port = 18421

        session._write_manifest("dynamic")

        manifest = json.loads((session.data_dir / "manifest.json").read_text())
        assert manifest["version"] == "1.0"
        assert manifest["app"]["name"] == "dynamic"
        assert manifest["session"]["id"] == "test-session-id"
        assert manifest["server"]["http_port"] == 18420
        assert manifest["server"]["ws_port"] == 18421

    def test_manifest_token_redacted(self, session):
        session.data_dir.mkdir(parents=True, exist_ok=True)
        session.session_token = "supersecret"

        session._write_manifest("dynamic")

        manifest = json.loads((session.data_dir / "manifest.json").read_text())
        assert manifest["session"]["token"] == "REDACTED"
        assert "supersecret" not in (session.data_dir / "manifest.json").read_text()


# ---------------------------------------------------------------------------
# Data contract initialization
# ---------------------------------------------------------------------------


class TestDataContract:
    def test_init_creates_state_and_actions(self, session):
        session.data_dir.mkdir(parents=True, exist_ok=True)

        session._init_data_contract()

        state = json.loads((session.data_dir / "state.json").read_text())
        assert state["version"] == 0
        assert state["status"] == "initializing"
        assert "updated_at" in state

        actions = json.loads((session.data_dir / "actions.json").read_text())
        assert actions["version"] == 0
        assert actions["actions"] == []

    def test_state_version_resets_on_init(self, session):
        session.data_dir.mkdir(parents=True, exist_ok=True)
        session._state_version = 42

        session._init_data_contract()

        assert session._state_version == 0


# ---------------------------------------------------------------------------
# State write / read
# ---------------------------------------------------------------------------


class TestStateIO:
    def test_write_state_creates_valid_json(self, session):
        session.data_dir.mkdir(parents=True, exist_ok=True)
        session._init_data_contract()

        session.write_state({"title": "Test", "data": {}})

        state = json.loads((session.data_dir / "state.json").read_text())
        assert state["title"] == "Test"
        assert state["version"] == 1
        assert "updated_at" in state
        assert state["status"] == "waiting_input"

    def test_write_state_increments_version(self, session):
        session.data_dir.mkdir(parents=True, exist_ok=True)
        session._init_data_contract()

        session.write_state({"title": "V1"})
        session.write_state({"title": "V2"})
        session.write_state({"title": "V3"})

        state = json.loads((session.data_dir / "state.json").read_text())
        assert state["version"] == 3
        assert state["title"] == "V3"

    def test_write_state_preserves_explicit_status(self, session):
        session.data_dir.mkdir(parents=True, exist_ok=True)
        session._init_data_contract()

        session.write_state({"title": "Test", "status": "pending_review"})

        state = json.loads((session.data_dir / "state.json").read_text())
        assert state["status"] == "pending_review"


# ---------------------------------------------------------------------------
# Actions read / clear
# ---------------------------------------------------------------------------


class TestActionsIO:
    def test_read_actions_empty(self, session):
        session.data_dir.mkdir(parents=True, exist_ok=True)
        session._init_data_contract()

        actions = session.read_actions()
        assert actions["actions"] == []

    def test_read_actions_after_inject(self, session):
        session.data_dir.mkdir(parents=True, exist_ok=True)
        session._init_data_contract()

        inject_action(session.data_dir, "approve", "approve", True)

        actions = session.read_actions()
        assert len(actions["actions"]) == 1
        assert actions["actions"][0]["action_id"] == "approve"

    def test_clear_actions(self, session):
        session.data_dir.mkdir(parents=True, exist_ok=True)
        session._init_data_contract()

        inject_action(session.data_dir, "approve", "approve", True)
        session.clear_actions()

        actions = session.read_actions()
        assert actions["actions"] == []

    def test_read_actions_no_file(self, session):
        session.data_dir.mkdir(parents=True, exist_ok=True)
        actions = session.read_actions()
        assert actions == {"version": 0, "actions": []}


# ---------------------------------------------------------------------------
# Wait for action (async polling)
# ---------------------------------------------------------------------------


class TestWaitForAction:
    async def test_returns_on_action(self, session):
        session.data_dir.mkdir(parents=True, exist_ok=True)
        session._init_data_contract()

        # Inject action after a short delay
        async def delayed_inject():
            await asyncio.sleep(0.3)
            inject_action(session.data_dir, "submit", "submit", {"name": "test"})

        task = asyncio.create_task(delayed_inject())
        result = await session.wait_for_action(timeout=5.0)
        await task

        assert result is not None
        assert len(result["actions"]) == 1
        assert result["actions"][0]["action_id"] == "submit"

    async def test_returns_none_on_timeout(self, session):
        session.data_dir.mkdir(parents=True, exist_ok=True)
        session._init_data_contract()

        result = await session.wait_for_action(timeout=0.5)
        assert result is None


# ---------------------------------------------------------------------------
# Port finding
# ---------------------------------------------------------------------------


class TestPortFinding:
    def test_finds_ports(self, session):
        http_port, ws_port = session._find_free_ports()
        assert 1 <= http_port <= 65535
        assert ws_port == http_port + 1

    def test_port_available_check(self):
        # Port 0 is special but a high random port should be available
        import socket

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        # Port is in use
        assert not WebviewSession._port_available(port)
        s.close()
        # Port should now be free
        assert WebviewSession._port_available(port)


# ---------------------------------------------------------------------------
# File permissions
# ---------------------------------------------------------------------------


class TestPermissions:
    @pytest.mark.skipif(sys.platform == "win32", reason="Unix permissions only")
    def test_set_permissions(self, session):
        session.data_dir.mkdir(parents=True, exist_ok=True)
        session._init_data_contract()
        session._write_manifest("dynamic")

        session._set_permissions()

        assert oct(session.data_dir.stat().st_mode & 0o777) == oct(0o700)
        assert oct((session.data_dir / "manifest.json").stat().st_mode & 0o777) == oct(0o600)
        assert oct((session.data_dir / "state.json").stat().st_mode & 0o777) == oct(0o600)


# ---------------------------------------------------------------------------
# Chrome detection
# ---------------------------------------------------------------------------


class TestChromeDetection:
    def test_find_chrome_returns_string_or_none(self):
        result = WebviewSession._find_chrome()
        assert result is None or isinstance(result, str)


# ---------------------------------------------------------------------------
# Integration: full server lifecycle (requires subprocess)
# ---------------------------------------------------------------------------


@pytest.mark.slow
class TestServerLifecycle:
    async def test_ensure_started_and_health(self, session):
        """Start the server, verify health, and clean up."""
        try:
            await session.ensure_started("dynamic")

            assert session._started
            assert session.is_alive()
            assert session.http_port > 0

            # Verify health endpoint responds
            import urllib.request

            with urllib.request.urlopen(f"http://127.0.0.1:{session.http_port}/_health", timeout=5) as resp:
                assert resp.status == 200
                data = json.loads(resp.read())
                assert data["status"] == "ok"
        finally:
            await session.close()
            assert not session.is_alive()

    async def test_write_state_reflected_via_api(self, session):
        """Write state via file, read back via HTTP API."""
        try:
            await session.ensure_started("dynamic")

            session.write_state(
                {
                    "title": "Integration Test",
                    "message": "Hello from test",
                    "data": {},
                    "actions_requested": [],
                }
            )

            # Give the file watcher time to pick it up
            await asyncio.sleep(1.0)

            import urllib.request

            req = urllib.request.Request(
                f"http://127.0.0.1:{session.http_port}/_api/state",
                headers={"Authorization": f"Bearer {session.session_token}"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                state = json.loads(resp.read())
                assert state["title"] == "Integration Test"
        finally:
            await session.close()

    async def test_ask_flow_with_injected_action(self, session):
        """Simulate the webview_ask flow: write state, inject action, read back."""
        try:
            await session.ensure_started("dynamic")

            session.clear_actions()
            session.write_state(
                {
                    "title": "Review",
                    "message": "Please review",
                    "data": {},
                    "actions_requested": [
                        {"id": "approve", "label": "Approve", "type": "approve"},
                    ],
                }
            )

            # Inject an action after a delay (simulating user click)
            async def delayed_action():
                await asyncio.sleep(0.5)
                inject_action(session.data_dir, "approve", "approve", True)

            task = asyncio.create_task(delayed_action())
            result = await session.wait_for_action(timeout=5.0)
            await task

            assert result is not None
            assert result["actions"][0]["action_id"] == "approve"
        finally:
            await session.close()

    async def test_close_is_idempotent(self, session):
        """Closing twice should not raise."""
        await session.ensure_started("dynamic")
        await session.close()
        await session.close()  # Should not raise


# ---------------------------------------------------------------------------
# App name security — path traversal prevention
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# webview_show action stripping
# ---------------------------------------------------------------------------


class TestWebviewShowActionStripping:
    """webview_show must strip action buttons since it's non-blocking.

    Only webview_ask (which blocks) should present interactive buttons.
    This prevents the 'orphaned button' bug where a user clicks a button
    but the agent has already exited and nobody is polling for the response.
    """

    def test_strips_actions_requested(self, session):
        """actions_requested should be removed from state before writing."""
        session.data_dir.mkdir(parents=True, exist_ok=True)
        session._init_data_contract()

        state = {
            "title": "Test",
            "actions_requested": [
                {"id": "approve", "label": "Approve", "type": "approve"},
            ],
        }
        # Simulate what webview_show does: pop actions, then write
        had_actions = bool(state.pop("actions_requested", None))
        session.write_state(state)

        assert had_actions is True
        written = json.loads((session.data_dir / "state.json").read_text())
        assert "actions_requested" not in written

    def test_strips_data_actions(self, session):
        """data.actions (alternate location) should also be stripped."""
        session.data_dir.mkdir(parents=True, exist_ok=True)
        session._init_data_contract()

        state = {
            "title": "Test",
            "data": {
                "sections": [{"type": "text", "content": "Hello"}],
                "actions": [
                    {"id": "ok", "label": "OK", "type": "approve"},
                ],
            },
        }
        had_actions = bool(state.pop("actions_requested", None))
        data = state.get("data")
        if isinstance(data, dict):
            had_actions = bool(data.pop("actions", None)) or had_actions
        session.write_state(state)

        assert had_actions is True
        written = json.loads((session.data_dir / "state.json").read_text())
        assert "actions" not in written.get("data", {})
        # Sections should be preserved
        assert len(written["data"]["sections"]) == 1

    def test_no_warning_without_actions(self, session):
        """State without actions should write normally with no stripping."""
        session.data_dir.mkdir(parents=True, exist_ok=True)
        session._init_data_contract()

        state = {"title": "Progress", "message": "Step 1 of 3"}
        had_actions = bool(state.pop("actions_requested", None))
        session.write_state(state)

        assert had_actions is False
        written = json.loads((session.data_dir / "state.json").read_text())
        assert written["title"] == "Progress"
        assert written["message"] == "Step 1 of 3"

    def test_ask_preserves_actions(self, session):
        """webview_ask should NOT strip actions (it blocks and waits)."""
        session.data_dir.mkdir(parents=True, exist_ok=True)
        session._init_data_contract()

        state = {
            "title": "Review",
            "actions_requested": [
                {"id": "approve", "label": "Approve", "type": "approve"},
            ],
        }
        # webview_ask writes state directly without stripping
        session.write_state(state)

        written = json.loads((session.data_dir / "state.json").read_text())
        assert "actions_requested" in written
        assert len(written["actions_requested"]) == 1


# ---------------------------------------------------------------------------
# App name security — path traversal prevention
# ---------------------------------------------------------------------------


class TestAppNameSecurity:
    """App names must not be usable as path traversal vectors.

    _copy_app builds a candidate list from known directories; names containing
    '..' or absolute paths simply won't match any candidate and raise
    FileNotFoundError rather than escaping the assets directory.
    """

    def test_dotdot_app_name_raises_not_found(self, session):
        """'../../../etc' must not traverse out of assets dir."""
        session.data_dir.mkdir(parents=True, exist_ok=True)
        (session.data_dir / "apps").mkdir(exist_ok=True)

        with pytest.raises(FileNotFoundError, match="not found"):
            session._copy_app("../../../etc")

    def test_absolute_path_app_name_raises_not_found(self, session):
        """/tmp must be rejected immediately — absolute paths bypass candidate allowlist.

        Pathlib resolves Path(base) / '/abs' to '/abs' on Unix, so without this guard an
        absolute app_name would silently escape the assets directory.
        """
        session.data_dir.mkdir(parents=True, exist_ok=True)
        (session.data_dir / "apps").mkdir(exist_ok=True)

        with pytest.raises(FileNotFoundError, match="not found"):
            session._copy_app("/tmp")

    def test_null_byte_app_name_raises_not_found(self, session):
        """Null-byte injection in app name must not bypass path checks."""
        session.data_dir.mkdir(parents=True, exist_ok=True)
        (session.data_dir / "apps").mkdir(exist_ok=True)

        with pytest.raises((FileNotFoundError, ValueError)):
            session._copy_app("dynamic\x00../../etc")

    def test_valid_app_name_succeeds(self, session):
        """A legitimate app name (dynamic) must copy successfully."""
        session.data_dir.mkdir(parents=True, exist_ok=True)
        (session.data_dir / "apps").mkdir(exist_ok=True)

        session._copy_app("dynamic")  # Should not raise
        assert (session.data_dir / "apps" / "dynamic" / "index.html").is_file()
